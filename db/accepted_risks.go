package db

import (
	"context"

	"github.com/Autumn-27/artex/wazuh"
)

// ListAcceptedRisks returns the whole accepted-risk registry.
func (d *DB) ListAcceptedRisks(ctx context.Context) ([]wazuh.AcceptedRisk, error) {
	rows, err := d.QueryContext(ctx, `SELECT code,host,reason,approved_by,until FROM accepted_risks ORDER BY code,host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []wazuh.AcceptedRisk{}
	for rows.Next() {
		var r wazuh.AcceptedRisk
		if err = rows.Scan(&r.Code, &r.Host, &r.Reason, &r.ApprovedBy, &r.Until); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReplaceAcceptedRisks swaps the registry for rows in one transaction, so a
// partially applied import is never visible.
func (d *DB) ReplaceAcceptedRisks(ctx context.Context, rows []wazuh.AcceptedRisk) error {
	clean := make([]wazuh.AcceptedRisk, 0, len(rows))
	for _, r := range rows {
		v, err := wazuh.ValidateAcceptedRisk(r)
		if err != nil {
			return err
		}
		clean = append(clean, v)
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM accepted_risks`); err != nil {
		return err
	}
	for _, r := range clean {
		if _, err = tx.ExecContext(ctx, `INSERT INTO accepted_risks(code,host,reason,approved_by,until) VALUES($1,$2,$3,$4,$5)`,
			r.Code, r.Host, r.Reason, r.ApprovedBy, r.Until); err != nil {
			return err
		}
	}
	return tx.Commit()
}
