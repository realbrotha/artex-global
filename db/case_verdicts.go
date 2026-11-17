package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Autumn-27/artex/wazuh"
)

// CaseVerdict is a stored LLM verdict and the case activity it judged.
type CaseVerdict struct {
	wazuh.Verdict
	Model    string    `json:"model"`
	JudgedAt time.Time `json:"judged_at"`
	CaseLast time.Time `json:"case_last"`
	CaseN    int       `json:"case_n"`
}

// CaseKey is the stable identity of a case: one criterion on one subject.
func CaseKey(c wazuh.Case) string { return c.Criterion + "|" + c.Actor }

// SaveCaseVerdict stores (or replaces) the verdict of one case.
func (d *DB) SaveCaseVerdict(ctx context.Context, sourceID int64, c wazuh.Case, v wazuh.Verdict, model string) (*CaseVerdict, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := &CaseVerdict{Verdict: v, Model: model, CaseLast: c.Last, CaseN: c.N}
	err = d.QueryRowContext(ctx, `INSERT INTO case_verdicts(source_id,case_key,verdict,case_last,case_n,model) VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (source_id,case_key) DO UPDATE SET verdict=EXCLUDED.verdict, case_last=EXCLUDED.case_last, case_n=EXCLUDED.case_n,
			model=EXCLUDED.model, judged_at=clock_timestamp()
		RETURNING judged_at`, sourceID, CaseKey(c), raw, c.Last, c.N, model).Scan(&out.JudgedAt)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CaseVerdicts returns the stored verdicts of one connection by case key.
func (d *DB) CaseVerdicts(ctx context.Context, sourceID int64) (map[string]*CaseVerdict, error) {
	rows, err := d.QueryContext(ctx, `SELECT case_key,verdict,case_last,case_n,model,judged_at FROM case_verdicts WHERE source_id=$1`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*CaseVerdict{}
	for rows.Next() {
		var key string
		var raw []byte
		v := &CaseVerdict{}
		if err = rows.Scan(&key, &raw, &v.CaseLast, &v.CaseN, &v.Model, &v.JudgedAt); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &v.Verdict); err != nil {
			return nil, err
		}
		out[key] = v
	}
	return out, rows.Err()
}
