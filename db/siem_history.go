package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/wazuh"
)

// How much history is kept. Prompts carry alert timelines, so judgments are
// the larger table.
const (
	analysisRunsKept = 500
	judgementsKept   = 5000
)

// ErrHistoryNotFound: no such run or judgment.
var ErrHistoryNotFound = errors.New("기록을 찾을 수 없습니다")

// AnalysisRun is one stored manual analysis. Detail is the run as the panel
// showed it; the list leaves it out and carries the counts instead.
type AnalysisRun struct {
	ID         string          `json:"id"`
	SourceID   int64           `json:"-"`
	SourceName string          `json:"source_name"`
	Label      string          `json:"label"`
	State      string          `json:"state"`
	StartedAt  time.Time       `json:"started_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Hosts      int             `json:"hosts"`
	Alerts     int             `json:"alerts"`
	Cases      int             `json:"cases"`
	Judged     int             `json:"judged"`
	Model      string          `json:"model"`
	Detail     json.RawMessage `json:"detail,omitempty"`
}

// SaveAnalysisRun stores a run or replaces its state and detail.
func (d *DB) SaveAnalysisRun(ctx context.Context, id string, sourceID int64, sourceName, label, state string, started time.Time, detail []byte) error {
	_, err := d.ExecContext(ctx, `INSERT INTO siem_analysis_runs(id,source_id,source_name,label,state,detail,started_at) VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET state=EXCLUDED.state, detail=EXCLUDED.detail, updated_at=clock_timestamp()`,
		id, sourceID, sourceName, label, state, detail, started)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `DELETE FROM siem_analysis_runs WHERE id IN (SELECT id FROM siem_analysis_runs ORDER BY started_at DESC OFFSET $1)`, analysisRunsKept)
	return err
}

const analysisRunColumns = `id,source_id,source_name,label,state,started_at,updated_at,
	COALESCE(jsonb_array_length(detail->'hosts'),0), COALESCE((detail->>'alerts')::int,0),
	COALESCE(jsonb_array_length(detail->'cases'),0), COALESCE((detail->>'judge_done')::int,0), COALESCE(detail->>'model','')`

func scanAnalysisRun(row interface{ Scan(...any) error }, extra ...any) (*AnalysisRun, error) {
	r := &AnalysisRun{}
	dest := append([]any{&r.ID, &r.SourceID, &r.SourceName, &r.Label, &r.State, &r.StartedAt, &r.UpdatedAt,
		&r.Hosts, &r.Alerts, &r.Cases, &r.Judged, &r.Model}, extra...)
	return r, row.Scan(dest...)
}

// ListAnalysisRuns returns the newest runs without their detail.
func (d *DB) ListAnalysisRuns(ctx context.Context, limit int) ([]*AnalysisRun, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+analysisRunColumns+` FROM siem_analysis_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AnalysisRun{}
	for rows.Next() {
		r, err := scanAnalysisRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAnalysisRun returns one run with its detail.
func (d *DB) GetAnalysisRun(ctx context.Context, id string) (*AnalysisRun, error) {
	var detail []byte
	r, err := scanAnalysisRun(d.QueryRowContext(ctx, `SELECT `+analysisRunColumns+`,detail FROM siem_analysis_runs WHERE id=$1`, id), &detail)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrHistoryNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Detail = detail
	return r, nil
}

// JudgeAttempt is one request to the model inside a judgment: what was sent
// and what came back. A later attempt's prompt lists the rules the previous
// answer broke.
type JudgeAttempt struct {
	Prompt   string `json:"prompt"`
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
	Ms       int64  `json:"ms"`
}

// Judgement is one LLM judgment of a case candidate.
type Judgement struct {
	ID       int64  `json:"id"`
	SourceID int64  `json:"-"`
	RunID    string `json:"run_id"`
	CaseKey  string `json:"case_key"`
	// The case as it was judged, without its timeline (the prompt holds it).
	Case     wazuh.Case     `json:"case"`
	Model    string         `json:"model"`
	System   string         `json:"system_prompt,omitempty"`
	Attempts []JudgeAttempt `json:"attempts,omitempty"`
	// Number of attempts, set on list rows where Attempts is left out.
	Tries    int            `json:"tries"`
	Verdict  *wazuh.Verdict `json:"verdict,omitempty"`
	Error    string         `json:"error,omitempty"`
	Ms       int64          `json:"ms"`
	JudgedAt time.Time      `json:"judged_at"`
}

// SaveJudgement records one judgment, successful or not.
func (d *DB) SaveJudgement(ctx context.Context, j Judgement) error {
	j.Case.Timeline = nil
	caseData, err := json.Marshal(j.Case)
	if err != nil {
		return err
	}
	if j.Attempts == nil {
		j.Attempts = []JudgeAttempt{}
	}
	attempts, err := json.Marshal(j.Attempts)
	if err != nil {
		return err
	}
	var verdict any
	if j.Verdict != nil {
		raw, err := json.Marshal(j.Verdict)
		if err != nil {
			return err
		}
		verdict = raw
	}
	if _, err = d.ExecContext(ctx, `INSERT INTO siem_judgements(source_id,run_id,case_key,case_data,model,system_prompt,attempts,verdict,error,ms)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		j.SourceID, j.RunID, CaseKey(j.Case), caseData, j.Model, j.System, attempts, verdict, j.Error, j.Ms); err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `DELETE FROM siem_judgements WHERE id IN (SELECT id FROM siem_judgements ORDER BY id DESC OFFSET $1)`, judgementsKept)
	return err
}

func scanJudgement(row interface{ Scan(...any) error }, full bool) (*Judgement, error) {
	j := &Judgement{}
	var caseData, attempts, verdict []byte
	dest := []any{&j.ID, &j.SourceID, &j.RunID, &j.CaseKey, &caseData, &j.Model, &verdict, &j.Error, &j.Ms, &j.JudgedAt, &j.Tries}
	if full {
		dest = append(dest, &j.System, &attempts)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(caseData, &j.Case); err != nil {
		return nil, err
	}
	if verdict != nil {
		j.Verdict = &wazuh.Verdict{}
		if err := json.Unmarshal(verdict, j.Verdict); err != nil {
			return nil, err
		}
	}
	if full {
		if err := json.Unmarshal(attempts, &j.Attempts); err != nil {
			return nil, err
		}
	}
	return j, nil
}

const judgementColumns = `id,source_id,run_id,case_key,case_data,model,verdict,error,ms,judged_at,jsonb_array_length(attempts)`

// ListJudgements returns judgments newest first, without prompts. runID
// narrows to one run; "" lists every judgment.
func (d *DB) ListJudgements(ctx context.Context, runID string, limit int) ([]*Judgement, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+judgementColumns+` FROM siem_judgements
		WHERE ($1='' OR run_id=$1) ORDER BY id DESC LIMIT $2`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Judgement{}
	for rows.Next() {
		j, err := scanJudgement(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ListSourceJudgements returns one connection's judgments newest first,
// without prompts.
func (d *DB) ListSourceJudgements(ctx context.Context, sourceID int64, limit int) ([]*Judgement, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+judgementColumns+` FROM siem_judgements
		WHERE source_id=$1 ORDER BY id DESC LIMIT $2`, sourceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Judgement{}
	for rows.Next() {
		j, err := scanJudgement(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// GetJudgement returns one judgment with its prompts and answers.
func (d *DB) GetJudgement(ctx context.Context, id int64) (*Judgement, error) {
	j, err := scanJudgement(d.QueryRowContext(ctx, `SELECT `+judgementColumns+`,system_prompt,attempts FROM siem_judgements WHERE id=$1`, id), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrHistoryNotFound
	}
	return j, err
}

// Alert storage limits: alerts are the bulk of a run, so they are kept for
// the newest runs only and capped per run.
const (
	RunAlertsMax     = 50000
	runAlertsRuns    = 20
	runAlertsBatch   = 500
	runAlertsLogSize = 4000
)

// RunAlert is one alert a run collected.
type RunAlert struct {
	Seq     int       `json:"seq"`
	T       time.Time `json:"t"`
	Host    string    `json:"host"`
	Rule    string    `json:"rule"`
	Level   int       `json:"level"`
	Desc    string    `json:"desc"`
	Actor   string    `json:"actor"`
	Src     string    `json:"src"`
	Object  string    `json:"object"`
	FullLog string    `json:"full_log"`
}

// SaveRunAlerts stores the alerts a run collected, newest first when the run
// collected more than RunAlertsMax, and drops the alerts of runs older than
// the newest few. It returns how many were stored.
func (d *DB) SaveRunAlerts(ctx context.Context, runID string, alerts []*wazuh.Alert) (int, error) {
	if len(alerts) > RunAlertsMax {
		alerts = alerts[len(alerts)-RunAlertsMax:] // timestamp order: keep the latest
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM siem_analysis_alerts WHERE run_id=$1`, runID); err != nil {
		return 0, err
	}
	const cols = 11
	for start := 0; start < len(alerts); start += runAlertsBatch {
		batch := alerts[start:min(start+runAlertsBatch, len(alerts))]
		query := strings.Builder{}
		query.WriteString(`INSERT INTO siem_analysis_alerts(run_id,seq,t,host,rule_id,level,descr,actor,src,object,full_log) VALUES`)
		args := make([]any, 0, len(batch)*cols)
		for i, a := range batch {
			if i > 0 {
				query.WriteByte(',')
			}
			query.WriteByte('(')
			for c := 0; c < cols; c++ {
				if c > 0 {
					query.WriteByte(',')
				}
				query.WriteByte('$')
				query.WriteString(strconv.Itoa(i*cols + c + 1))
			}
			query.WriteByte(')')
			log := a.FullLog
			if len(log) > runAlertsLogSize {
				log = strings.ToValidUTF8(log[:runAlertsLogSize], "")
			}
			args = append(args, runID, start+i, a.T, a.Host, a.RuleID, a.Level, a.Desc, a.Actor, a.Src, a.Object, strings.ReplaceAll(log, "\x00", ""))
		}
		if _, err := d.ExecContext(ctx, query.String(), args...); err != nil {
			return start, err
		}
	}
	_, err := d.ExecContext(ctx, `DELETE FROM siem_analysis_alerts WHERE run_id NOT IN
		(SELECT id FROM siem_analysis_runs ORDER BY started_at DESC LIMIT $1)`, runAlertsRuns)
	return len(alerts), err
}

// RunAlertFilter narrows a run's alerts. Empty fields match everything.
type RunAlertFilter struct {
	Rule, Host, Query string
}

// ListRunAlerts returns a page of a run's alerts in time order and how many
// match the filter in all.
func (d *DB) ListRunAlerts(ctx context.Context, runID string, f RunAlertFilter, offset, limit int) (int, []RunAlert, error) {
	const where = ` FROM siem_analysis_alerts WHERE run_id=$1 AND ($2='' OR rule_id=$2) AND ($3='' OR host=$3)
		AND ($4='' OR descr ILIKE $4 OR actor ILIKE $4 OR src ILIKE $4 OR object ILIKE $4 OR full_log ILIKE $4)`
	like := ""
	if f.Query != "" {
		like = "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(f.Query) + "%"
	}
	total := 0
	if err := d.QueryRowContext(ctx, `SELECT count(*)`+where, runID, f.Rule, f.Host, like).Scan(&total); err != nil {
		return 0, nil, err
	}
	rows, err := d.QueryContext(ctx, `SELECT seq,t,host,rule_id,level,descr,actor,src,object,full_log`+where+
		` ORDER BY seq LIMIT $5 OFFSET $6`, runID, f.Rule, f.Host, like, limit, offset)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	out := []RunAlert{}
	for rows.Next() {
		a := RunAlert{}
		if err = rows.Scan(&a.Seq, &a.T, &a.Host, &a.Rule, &a.Level, &a.Desc, &a.Actor, &a.Src, &a.Object, &a.FullLog); err != nil {
			return 0, nil, err
		}
		out = append(out, a)
	}
	return total, out, rows.Err()
}
