package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/wazuh"
)

// Review is one re-reading of a stored verdict.
type Review struct {
	ID         int64     `json:"id"`
	RunID      string    `json:"run_id"`
	CaseKey    string    `json:"case_key"`
	Title      string    `json:"title"`
	Prev       string    `json:"prev"`
	New        string    `json:"new"`
	Agreed     bool      `json:"agreed"`
	Changed    bool      `json:"changed"`
	PickReason string    `json:"pick_reason"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
}

// SaveReview records one re-reading.
func (d *DB) SaveReview(ctx context.Context, sourceID int64, r Review) error {
	_, err := d.ExecContext(ctx, `INSERT INTO siem_reviews(source_id,run_id,case_key,title,prev_verdict,new_verdict,agreed,changed,pick_reason,reason)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, sourceID, r.RunID, r.CaseKey, r.Title, r.Prev, r.New, r.Agreed, r.Changed, r.PickReason, r.Reason)
	return err
}

// ListReviews returns a connection's re-readings newest first.
func (d *DB) ListReviews(ctx context.Context, sourceID int64, limit int) ([]Review, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,run_id,case_key,title,prev_verdict,new_verdict,agreed,changed,pick_reason,reason,created_at
		FROM siem_reviews WHERE source_id=$1 ORDER BY id DESC LIMIT $2`, sourceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Review{}
	for rows.Next() {
		var r Review
		if err = rows.Scan(&r.ID, &r.RunID, &r.CaseKey, &r.Title, &r.Prev, &r.New, &r.Agreed, &r.Changed, &r.PickReason, &r.Reason, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastReviewed returns when each case of a connection was last re-read.
func (d *DB) LastReviewed(ctx context.Context, sourceID int64) (map[string]time.Time, error) {
	rows, err := d.QueryContext(ctx, `SELECT case_key, max(created_at) FROM siem_reviews WHERE source_id=$1 GROUP BY case_key`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var key string
		var at time.Time
		if err = rows.Scan(&key, &at); err != nil {
			return nil, err
		}
		out[key] = at
	}
	return out, rows.Err()
}

// QualityWeek is one week of judging quality numbers.
type QualityWeek struct {
	Week      string `json:"week"` // Monday, YYYY-MM-DD
	Judged    int    `json:"judged"`
	Debated   int    `json:"debated"`
	Fallback  int    `json:"fallback"`
	Failed    int    `json:"failed"`
	Reviews   int    `json:"reviews"`
	Agreed    int    `json:"agreed"`
	Changed   int    `json:"changed"`
	Corrected int    `json:"corrected"`
}

// QualityWeeks returns the last weeks' numbers for a connection, oldest first.
func (d *DB) QualityWeeks(ctx context.Context, sourceID int64, weeks int) ([]QualityWeek, error) {
	rows, err := d.QueryContext(ctx, `
WITH w AS (SELECT generate_series(date_trunc('week', now()) - ($2 - 1) * interval '1 week', date_trunc('week', now()), interval '1 week') AS wk),
j AS (SELECT date_trunc('week', judged_at) wk, count(*) n,
        count(*) FILTER (WHERE verdict->>'method'='debate') deb,
        count(*) FILTER (WHERE verdict->>'method'='fallback') fb,
        count(*) FILTER (WHERE verdict IS NULL) failed
      FROM siem_judgements WHERE source_id=$1 GROUP BY 1),
r AS (SELECT date_trunc('week', created_at) wk, count(*) n, count(*) FILTER (WHERE agreed) ag, count(*) FILTER (WHERE changed) ch
      FROM siem_reviews WHERE source_id=$1 GROUP BY 1),
c AS (SELECT date_trunc('week', created_at) wk, count(*) n FROM siem_corrections WHERE source_id=$1 GROUP BY 1)
SELECT to_char(w.wk,'YYYY-MM-DD'), COALESCE(j.n,0), COALESCE(j.deb,0), COALESCE(j.fb,0), COALESCE(j.failed,0),
       COALESCE(r.n,0), COALESCE(r.ag,0), COALESCE(r.ch,0), COALESCE(c.n,0)
FROM w LEFT JOIN j ON j.wk=w.wk LEFT JOIN r ON r.wk=w.wk LEFT JOIN c ON c.wk=w.wk ORDER BY w.wk`, sourceID, weeks)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QualityWeek{}
	for rows.Next() {
		var q QualityWeek
		if err = rows.Scan(&q.Week, &q.Judged, &q.Debated, &q.Fallback, &q.Failed, &q.Reviews, &q.Agreed, &q.Changed, &q.Corrected); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// WatchItem is a stored near miss and how many scheduled runs saw it.
type WatchItem struct {
	wazuh.NearMiss
	SeenRuns  int       `json:"seen_runs"`
	FirstSeen time.Time `json:"first_seen"`
}

// SaveWatch records the near misses of a scheduled run: a subject seen again
// counts one more run. Subjects not seen for two weeks are dropped.
func (d *DB) SaveWatch(ctx context.Context, sourceID int64, items []wazuh.NearMiss) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, n := range items {
		if _, err = tx.ExecContext(ctx, `INSERT INTO siem_watch(source_id,pattern,kind,subject,host,count,threshold,last_at,note)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (source_id,pattern,kind,subject) DO UPDATE SET host=EXCLUDED.host, count=EXCLUDED.count,
				threshold=EXCLUDED.threshold, last_at=EXCLUDED.last_at, note=EXCLUDED.note,
				seen_runs=siem_watch.seen_runs+1, updated_at=clock_timestamp()`,
			sourceID, n.Pattern, n.Kind, n.Subject, n.Host, n.Count, n.Threshold, n.Last, n.Note); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM siem_watch WHERE source_id=$1 AND updated_at < now() - interval '14 days'`, sourceID); err != nil {
		return err
	}
	return tx.Commit()
}

// ListWatch returns a connection's near misses, most often seen first.
func (d *DB) ListWatch(ctx context.Context, sourceID int64, limit int) ([]WatchItem, error) {
	rows, err := d.QueryContext(ctx, `SELECT pattern,kind,subject,host,count,threshold,last_at,note,seen_runs,first_seen
		FROM siem_watch WHERE source_id=$1 ORDER BY (kind='slow') DESC, seen_runs DESC, count::float/GREATEST(threshold,1) DESC, subject LIMIT $2`, sourceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WatchItem{}
	for rows.Next() {
		var w WatchItem
		if err = rows.Scan(&w.Pattern, &w.Kind, &w.Subject, &w.Host, &w.Count, &w.Threshold, &w.Last, &w.Note, &w.SeenRuns, &w.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// StoredProposal is a gap-review suggestion and what a person decided.
type StoredProposal struct {
	ID int64 `json:"id"`
	wazuh.Proposal
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	DecidedAt *time.Time `json:"decided_at"`
}

// SaveProposals stores new suggestions; one with a title already stored
// (open, accepted or dismissed) is not stored again.
func (d *DB) SaveProposals(ctx context.Context, sourceID int64, items []wazuh.Proposal) (int, error) {
	added := 0
	for _, p := range items {
		res, err := d.ExecContext(ctx, `INSERT INTO siem_proposals(source_id,kind,title,why,how,origin) VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT (source_id,title) DO NOTHING`, sourceID, p.Kind, p.Title, p.Why, p.How, p.Source)
		if err != nil {
			return added, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	return added, nil
}

// ListProposals returns a connection's suggestions, open ones first.
func (d *DB) ListProposals(ctx context.Context, sourceID int64) ([]StoredProposal, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,kind,title,why,how,origin,status,created_at,decided_at FROM siem_proposals
		WHERE source_id=$1 ORDER BY (status='open') DESC, id DESC LIMIT 200`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredProposal{}
	for rows.Next() {
		var p StoredProposal
		if err = rows.Scan(&p.ID, &p.Kind, &p.Title, &p.Why, &p.How, &p.Source, &p.Status, &p.CreatedAt, &p.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DecideProposal records a person's decision on a suggestion.
func (d *DB) DecideProposal(ctx context.Context, id int64, status string) error {
	res, err := d.ExecContext(ctx, `UPDATE siem_proposals SET status=$2, decided_at=clock_timestamp() WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrHistoryNotFound
	}
	return nil
}

// Knowledge is a cached piece of outside knowledge.
type Knowledge struct {
	Key, Title, Body, URL string
	FetchedAt             time.Time
}

// GetKnowledge returns a cached entry, or nil when there is none.
func (d *DB) GetKnowledge(ctx context.Context, key string) (*Knowledge, error) {
	k := &Knowledge{Key: key}
	err := d.QueryRowContext(ctx, `SELECT title,body,url,fetched_at FROM siem_knowledge WHERE key=$1`, key).Scan(&k.Title, &k.Body, &k.URL, &k.FetchedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

// SaveKnowledge stores or refreshes a cached entry.
func (d *DB) SaveKnowledge(ctx context.Context, k Knowledge) error {
	_, err := d.ExecContext(ctx, `INSERT INTO siem_knowledge(key,title,body,url) VALUES($1,$2,$3,$4)
		ON CONFLICT (key) DO UPDATE SET title=EXCLUDED.title, body=EXCLUDED.body, url=EXCLUDED.url, fetched_at=clock_timestamp()`,
		k.Key, k.Title, k.Body, k.URL)
	return err
}

// GoldenCase is a case a person corrected, kept with its timeline as an
// answer the judging can be replayed against.
type GoldenCase struct {
	CaseKey  string
	Expected string
	Case     wazuh.Case
}

// GoldenCases returns the latest correction of each case that was stored
// with its case data, newest first.
func (d *DB) GoldenCases(ctx context.Context, sourceID int64, limit int) ([]GoldenCase, error) {
	rows, err := d.QueryContext(ctx, `SELECT case_key,to_verdict,case_data FROM (
		SELECT DISTINCT ON (case_key) case_key,to_verdict,case_data,id FROM siem_corrections
		WHERE source_id=$1 AND case_data IS NOT NULL ORDER BY case_key, id DESC) latest ORDER BY id DESC LIMIT $2`, sourceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GoldenCase{}
	for rows.Next() {
		var g GoldenCase
		var raw []byte
		if err = rows.Scan(&g.CaseKey, &g.Expected, &raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &g.Case); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// PrecedentsExcept is Precedents without the corrections of one case: a
// case must not be replayed against its own answer.
func (d *DB) PrecedentsExcept(ctx context.Context, sourceID int64, criterion, exceptKey string, limit int) ([]wazuh.Precedent, error) {
	rows, err := d.QueryContext(ctx, `SELECT actor,summary,from_verdict,to_verdict,reason FROM (
		SELECT DISTINCT ON (case_key) case_key,actor,summary,from_verdict,to_verdict,reason,id
		FROM siem_corrections WHERE source_id=$1 AND criterion=$2 AND case_key<>$3 ORDER BY case_key, id DESC) latest
		ORDER BY id DESC LIMIT $4`, sourceID, criterion, exceptKey, limit)
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
