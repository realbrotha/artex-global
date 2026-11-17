package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/wazuh"
)

// CaseMeta describes one case-extraction run.
type CaseMeta struct {
	Alerts     int    `json:"alerts"`
	Capped     bool   `json:"capped"` // the alert limit was reached; older alerts were not read
	WindowDays int    `json:"window_days"`
	Rules      int    `json:"rules"` // analysed catalog rules
	SeenNote   string `json:"seen_note"`
}

// WazuhCaseSet is the stored extraction result of one connection.
type WazuhCaseSet struct {
	SourceID int64
	Name     string
	CasesAt  *time.Time
	Error    string
	Meta     CaseMeta
	Cases    []wazuh.Case
}

func (d *DB) GetSiemSettings(ctx context.Context) (map[string]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT key,value FROM siem_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err = rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetSiemSettings upserts every given key in one transaction.
func (d *DB) SetSiemSettings(ctx context.Context, values map[string]string) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range values {
		if _, err = tx.ExecContext(ctx, `INSERT INTO siem_settings(key,value) VALUES($1,$2)
			ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=clock_timestamp()`, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WazuhCasesAt returns when cases were last extracted for a connection.
func (d *DB) WazuhCasesAt(ctx context.Context, id int64) (*time.Time, error) {
	var at sql.NullTime
	err := d.QueryRowContext(ctx, `SELECT cases_at FROM wazuh_sources WHERE id=$1`, id).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrWazuhSourceNotFound
	}
	if err != nil || !at.Valid {
		return nil, err
	}
	return &at.Time, nil
}

// SaveWazuhCases records an extraction result. A failure keeps the previous
// cases and only stores the reason.
func (d *DB) SaveWazuhCases(ctx context.Context, id, revision int64, cases []wazuh.Case, meta CaseMeta, failure string) error {
	if failure != "" {
		_, err := d.ExecContext(ctx, `UPDATE wazuh_sources SET cases_error=$3, cases_at=clock_timestamp() WHERE id=$1 AND revision=$2`, id, revision, failure)
		return err
	}
	if cases == nil {
		cases = []wazuh.Case{}
	}
	raw, err := json.Marshal(cases)
	if err != nil {
		return err
	}
	rawMeta, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `UPDATE wazuh_sources SET cases=$3, cases_meta=$4, cases_at=clock_timestamp(), cases_error='' WHERE id=$1 AND revision=$2`,
		id, revision, raw, rawMeta)
	return err
}

func scanWazuhCaseSet(row interface{ Scan(...any) error }) (*WazuhCaseSet, error) {
	s := &WazuhCaseSet{}
	var cases, meta []byte
	var at sql.NullTime
	if err := row.Scan(&s.SourceID, &s.Name, &cases, &meta, &at, &s.Error); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrWazuhSourceNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(cases, &s.Cases); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(meta, &s.Meta); err != nil {
		return nil, err
	}
	if s.Cases == nil {
		s.Cases = []wazuh.Case{}
	}
	if at.Valid {
		s.CasesAt = &at.Time
	}
	return s, nil
}

const wazuhCaseColumns = `id,name,cases,cases_meta,cases_at,cases_error`

// ListWazuhCases returns the stored cases of every enabled connection.
func (d *DB) ListWazuhCases(ctx context.Context) ([]*WazuhCaseSet, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+wazuhCaseColumns+` FROM wazuh_sources WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*WazuhCaseSet{}
	for rows.Next() {
		s, err := scanWazuhCaseSet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) GetWazuhCases(ctx context.Context, id int64) (*WazuhCaseSet, error) {
	return scanWazuhCaseSet(d.QueryRowContext(ctx, `SELECT `+wazuhCaseColumns+` FROM wazuh_sources WHERE id=$1`, id))
}
