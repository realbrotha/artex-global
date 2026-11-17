package db

import (
	"context"
	"time"

	"github.com/Autumn-27/artex/wazuh"
)

// Correction is one verdict a person changed.
type Correction struct {
	ID        int64     `json:"id"`
	CaseKey   string    `json:"case_key"`
	Criterion string    `json:"criterion"`
	Actor     string    `json:"actor"`
	Summary   string    `json:"summary"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// SaveCorrection records a person's verdict and stores it as the case's
// current verdict, in one transaction.
func (d *DB) SaveCorrection(ctx context.Context, sourceID int64, c wazuh.Case, from string, v wazuh.Verdict, reason string) (*CaseVerdict, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO siem_corrections(source_id,case_key,criterion,actor,summary,from_verdict,to_verdict,reason)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, sourceID, CaseKey(c), c.Criterion, c.Actor, c.Summary, from, v.Verdict, reason); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d.SaveCaseVerdict(ctx, sourceID, c, v, "사람")
}

// ListCorrections returns a connection's corrections newest first.
func (d *DB) ListCorrections(ctx context.Context, sourceID int64, limit int) ([]Correction, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,case_key,criterion,actor,summary,from_verdict,to_verdict,reason,created_at
		FROM siem_corrections WHERE source_id=$1 ORDER BY id DESC LIMIT $2`, sourceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Correction{}
	for rows.Next() {
		var c Correction
		if err = rows.Scan(&c.ID, &c.CaseKey, &c.Criterion, &c.Actor, &c.Summary, &c.From, &c.To, &c.Reason, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Precedents returns the latest correction of each case of a criterion, newest
// first, as precedents for judging another case of that criterion.
func (d *DB) Precedents(ctx context.Context, sourceID int64, criterion string, limit int) ([]wazuh.Precedent, error) {
	rows, err := d.QueryContext(ctx, `SELECT actor,summary,from_verdict,to_verdict,reason FROM (
		SELECT DISTINCT ON (case_key) case_key,actor,summary,from_verdict,to_verdict,reason,id
		FROM siem_corrections WHERE source_id=$1 AND criterion=$2 ORDER BY case_key, id DESC) latest
		ORDER BY id DESC LIMIT $3`, sourceID, criterion, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []wazuh.Precedent{}
	for rows.Next() {
		var p wazuh.Precedent
		if err = rows.Scan(&p.Actor, &p.Summary, &p.From, &p.Verdict, &p.Reason); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FeedbackJudgements returns the model judgments of a connection within the
// window, as the feedback summary reads them.
func (d *DB) FeedbackJudgements(ctx context.Context, sourceID int64, since time.Time) ([]wazuh.FeedbackJudgement, error) {
	rows, err := d.QueryContext(ctx, `SELECT case_key, COALESCE(verdict->>'verdict',''), COALESCE(verdict->>'method','')
		FROM siem_judgements WHERE source_id=$1 AND judged_at >= $2`, sourceID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []wazuh.FeedbackJudgement{}
	for rows.Next() {
		var j wazuh.FeedbackJudgement
		if err = rows.Scan(&j.CaseKey, &j.Verdict, &j.Method); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
