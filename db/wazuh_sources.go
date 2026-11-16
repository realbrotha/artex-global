package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/wazuh"
)

var ErrWazuhSourceNotFound = errors.New("Wazuh 연결을 찾을 수 없습니다")

// WazuhSource is one saved Wazuh connection plus its last asset snapshot.
type WazuhSource struct {
	ID            int64        `json:"id,string"`
	Name          string       `json:"name"`
	Revision      int64        `json:"revision"`
	Config        wazuh.Config `json:"config"`
	Enabled       bool         `json:"enabled"`
	CredentialSet bool         `json:"credential_set"`
	SecretCipher  []byte       `json:"-"`
	Graph         wazuh.Graph  `json:"-"`
	SyncedAt      *time.Time   `json:"synced_at"`
	SyncError     string       `json:"sync_error"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

const wazuhSourceColumns = `id,name,revision,config,secret_cipher,enabled,snapshot,synced_at,sync_error,updated_at`

func scanWazuhSource(row interface{ Scan(...any) error }) (*WazuhSource, error) {
	s := &WazuhSource{}
	var cfg, snap []byte
	var synced sql.NullTime
	if e := row.Scan(&s.ID, &s.Name, &s.Revision, &cfg, &s.SecretCipher, &s.Enabled, &snap, &synced, &s.SyncError, &s.UpdatedAt); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return nil, ErrWazuhSourceNotFound
		}
		return nil, e
	}
	if e := json.Unmarshal(cfg, &s.Config); e != nil {
		return nil, e
	}
	if e := json.Unmarshal(snap, &s.Graph); e != nil {
		return nil, e
	}
	if s.Graph.Nodes == nil {
		s.Graph.Nodes = []wazuh.Node{}
	}
	if s.Graph.Edges == nil {
		s.Graph.Edges = []wazuh.Edge{}
	}
	if synced.Valid {
		s.SyncedAt = &synced.Time
	}
	s.CredentialSet = len(s.SecretCipher) > 0
	return s, nil
}

func (d *DB) GetWazuhSource(ctx context.Context, id int64) (*WazuhSource, error) {
	return scanWazuhSource(d.QueryRowContext(ctx, `SELECT `+wazuhSourceColumns+` FROM wazuh_sources WHERE id=$1`, id))
}

func (d *DB) ListWazuhSources(ctx context.Context) ([]*WazuhSource, error) {
	rows, e := d.QueryContext(ctx, `SELECT `+wazuhSourceColumns+` FROM wazuh_sources ORDER BY id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []*WazuhSource{}
	for rows.Next() {
		s, e := scanWazuhSource(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) DeleteWazuhSource(ctx context.Context, id, expected int64) error {
	if id <= 0 || expected <= 0 {
		return ErrDefenseInvalid
	}
	res, e := d.ExecContext(ctx, `DELETE FROM wazuh_sources WHERE id=$1 AND revision=$2`, id, expected)
	if e != nil {
		return e
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, e = d.GetWazuhSource(ctx, id); e != nil {
		return e
	}
	return ErrDefenseConflict
}

// SaveWazuhSource creates (id 0) or updates a connection. An empty cipher on
// update keeps the stored credentials, which is refused when an endpoint
// changed so credentials are never forwarded to a new address.
func (d *DB) SaveWazuhSource(ctx context.Context, id, expected int64, name string, cfg wazuh.Config, enabled bool, cipher []byte) (*WazuhSource, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || strings.ContainsRune(name, 0) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 120 {
		return nil, ErrDefenseInvalid
	}
	cfg, e := wazuh.Validate(cfg)
	if e != nil {
		return nil, e
	}
	if id < 0 || expected < 0 {
		return nil, ErrDefenseInvalid
	}
	raw, _ := json.Marshal(cfg)
	if id == 0 {
		if expected != 0 || len(cipher) == 0 {
			return nil, ErrDefenseInvalid
		}
		return scanWazuhSource(d.QueryRowContext(ctx, `INSERT INTO wazuh_sources(name,config,secret_cipher,enabled) VALUES($1,$2,$3,$4) RETURNING `+wazuhSourceColumns, name, raw, cipher, enabled))
	}
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	old, e := scanWazuhSource(tx.QueryRowContext(ctx, `SELECT `+wazuhSourceColumns+` FROM wazuh_sources WHERE id=$1 FOR UPDATE`, id))
	if e != nil {
		return nil, e
	}
	if old.Revision != expected {
		return nil, ErrDefenseConflict
	}
	endpointChanged := old.Config.ManagerURL != cfg.ManagerURL || old.Config.IndexerURL != cfg.IndexerURL
	if len(cipher) == 0 {
		if endpointChanged {
			return nil, errors.New("연결 주소를 변경할 때 인증 정보를 다시 입력해 주세요")
		}
		cipher = old.SecretCipher
	}
	// A changed endpoint invalidates the previous snapshot.
	s, e := scanWazuhSource(tx.QueryRowContext(ctx, `UPDATE wazuh_sources SET name=$2,revision=revision+1,config=$3,secret_cipher=$4,enabled=$5,
		snapshot=CASE WHEN $6 THEN '{}'::jsonb ELSE snapshot END, synced_at=CASE WHEN $6 THEN NULL ELSE synced_at END,
		sync_error=CASE WHEN $6 THEN '' ELSE sync_error END, updated_at=clock_timestamp()
		WHERE id=$1 RETURNING `+wazuhSourceColumns, id, name, raw, cipher, enabled, endpointChanged))
	if e != nil {
		return nil, e
	}
	return s, tx.Commit()
}

// FinishWazuhSync records a sync result. A failure keeps the previous
// snapshot so the asset map stays readable while the connection is down.
func (d *DB) FinishWazuhSync(ctx context.Context, id, revision int64, graph *wazuh.Graph, syncErr string) error {
	if graph == nil {
		_, e := d.ExecContext(ctx, `UPDATE wazuh_sources SET sync_error=$3 WHERE id=$1 AND revision=$2`, id, revision, syncErr)
		return e
	}
	raw, e := json.Marshal(graph)
	if e != nil {
		return e
	}
	_, e = d.ExecContext(ctx, `UPDATE wazuh_sources SET snapshot=$3,synced_at=clock_timestamp(),sync_error='' WHERE id=$1 AND revision=$2`, id, revision, raw)
	return e
}
