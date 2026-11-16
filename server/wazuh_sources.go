package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/wazuh"
)

const (
	wazuhSyncInterval = 5 * time.Minute
	wazuhSyncTimeout  = 90 * time.Second
	wazuhCredentialAD = "wazuh-source-credentials/v1"
)

func (s *Server) registerWazuhSources(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/defensive/wazuh", s.listWazuhSources)
	mux.HandleFunc("POST /api/defensive/wazuh", s.saveWazuhSource)
	mux.HandleFunc("PUT /api/defensive/wazuh/{sourceID}", s.saveWazuhSource)
	mux.HandleFunc("DELETE /api/defensive/wazuh/{sourceID}", s.deleteWazuhSource)
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/test", s.testWazuhSource)
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/sync", s.syncWazuhSource)
	mux.HandleFunc("GET /api/defensive/assets", s.listProtectedAssets)
}

func (s *Server) encryptWazuhCredentials(c wazuh.Credentials) ([]byte, error) {
	a, e := s.sourceCipher()
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, e
	}
	return a.Seal(nonce, nonce, raw, []byte(wazuhCredentialAD)), nil
}

func (s *Server) wazuhCredentials(source *db.WazuhSource) (wazuh.Credentials, error) {
	c := wazuh.Credentials{}
	a, e := s.sourceCipher()
	if e != nil {
		return c, e
	}
	if len(source.SecretCipher) < a.NonceSize() {
		return c, errors.New("저장된 인증 정보를 읽지 못했습니다. 다시 입력해 주세요")
	}
	nonce := source.SecretCipher[:a.NonceSize()]
	raw, e := a.Open(nil, nonce, source.SecretCipher[a.NonceSize():], []byte(wazuhCredentialAD))
	if e != nil {
		return c, errors.New("저장된 인증 정보를 복호화하지 못했습니다. 다시 입력해 주세요")
	}
	if json.Unmarshal(raw, &c) != nil {
		return c, errors.New("연결 인증 정보 형식이 올바르지 않습니다")
	}
	return c, wazuh.ValidateCredentials(source.Config, c)
}

func wazuhSourceError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, wazuh.ErrInvalid), errors.Is(e, db.ErrDefenseInvalid):
		writeErr(w, 400, e.Error())
	case errors.Is(e, db.ErrDefenseConflict):
		writeErr(w, 409, "연결 설정이 변경됐습니다. 새로고침 후 다시 시도해 주세요")
	case errors.Is(e, db.ErrWazuhSourceNotFound):
		writeErr(w, 404, e.Error())
	default:
		writeErr(w, 500, "Wazuh 연결을 처리하지 못했습니다")
	}
}

func (s *Server) listWazuhSources(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rows, e := pg.ListWazuhSources(r.Context())
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"sources": rows})
}

func (s *Server) saveWazuhSource(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name             string       `json:"name"`
		Config           wazuh.Config `json:"config"`
		Enabled          bool         `json:"enabled"`
		ExpectedRevision int64        `json:"expected_revision"`
		ManagerUser      string       `json:"manager_user"`
		ManagerPassword  string       `json:"manager_password"`
		IndexerUser      string       `json:"indexer_user"`
		IndexerPassword  string       `json:"indexer_password"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 64<<10) {
		return
	}
	var id int64
	if r.Method == http.MethodPut {
		var ok bool
		if id, ok = pathInt(r, "sourceID"); !ok || id <= 0 {
			writeErr(w, 400, "연결 ID를 확인해 주세요")
			return
		}
	}
	cfg, e := wazuh.Validate(in.Config)
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	var encrypted []byte
	if in.ManagerUser != "" || in.ManagerPassword != "" || in.IndexerUser != "" || in.IndexerPassword != "" {
		c := wazuh.Credentials{ManagerUser: in.ManagerUser, ManagerPassword: in.ManagerPassword, IndexerUser: in.IndexerUser, IndexerPassword: in.IndexerPassword}
		if e = wazuh.ValidateCredentials(cfg, c); e != nil {
			wazuhSourceError(w, e)
			return
		}
		if encrypted, e = s.encryptWazuhCredentials(c); e != nil {
			wazuhSourceError(w, e)
			return
		}
	}
	if id == 0 && len(encrypted) == 0 {
		writeErr(w, 400, "연결 인증 정보를 입력해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if id > 0 && len(encrypted) == 0 {
		old, e := pg.GetWazuhSource(r.Context(), id)
		if e != nil {
			wazuhSourceError(w, e)
			return
		}
		// Stored credentials must still satisfy the new config (e.g. an
		// indexer URL added without indexer credentials).
		if _, e = s.wazuhCredentialsFor(old, cfg); e != nil {
			writeErr(w, 400, "주소 구성이 바뀌었습니다. 인증 정보를 다시 입력해 주세요")
			return
		}
	}
	out, e := pg.SaveWazuhSource(r.Context(), id, in.ExpectedRevision, in.Name, cfg, in.Enabled, encrypted)
	if e != nil {
		if errors.Is(e, wazuh.ErrInvalid) || errors.Is(e, db.ErrDefenseInvalid) || errors.Is(e, db.ErrDefenseConflict) || errors.Is(e, db.ErrWazuhSourceNotFound) {
			wazuhSourceError(w, e)
		} else {
			writeErr(w, 400, e.Error())
		}
		return
	}
	if out.Enabled {
		go s.runWazuhSync(out.ID)
	}
	code := 200
	if id == 0 {
		code = 201
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, code, out)
}

// wazuhCredentialsFor decrypts stored credentials and validates them against cfg.
func (s *Server) wazuhCredentialsFor(source *db.WazuhSource, cfg wazuh.Config) (wazuh.Credentials, error) {
	probe := *source
	probe.Config = cfg
	return s.wazuhCredentials(&probe)
}

func (s *Server) deleteWazuhSource(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "sourceID")
	if !ok || id <= 0 {
		writeErr(w, 400, "연결 ID를 확인해 주세요")
		return
	}
	var in struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 64<<10) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if e := pg.DeleteWazuhSource(r.Context(), id, in.ExpectedRevision); e != nil {
		wazuhSourceError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"deleted": strconv.FormatInt(id, 10)})
}

func (s *Server) loadWazuhSource(w http.ResponseWriter, r *http.Request) (*db.WazuhSource, wazuh.Credentials, bool) {
	id, ok := pathInt(r, "sourceID")
	if !ok || id <= 0 {
		writeErr(w, 400, "연결 ID를 확인해 주세요")
		return nil, wazuh.Credentials{}, false
	}
	pg := s.pg(w)
	if pg == nil {
		return nil, wazuh.Credentials{}, false
	}
	source, e := pg.GetWazuhSource(r.Context(), id)
	if e != nil {
		wazuhSourceError(w, e)
		return nil, wazuh.Credentials{}, false
	}
	auth, e := s.wazuhCredentials(source)
	if e != nil {
		writeErr(w, 400, e.Error())
		return nil, wazuh.Credentials{}, false
	}
	return source, auth, true
}

func (s *Server) testWazuhSource(w http.ResponseWriter, r *http.Request) {
	source, auth, ok := s.loadWazuhSource(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	agents, e := wazuh.Test(ctx, source.Config, auth)
	if e != nil {
		writeErr(w, 502, e.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"ok": true, "agents": agents, "indexer": source.Config.IndexerURL != ""})
}

// syncWazuhSource runs one sync inline so the caller sees the result.
func (s *Server) syncWazuhSource(w http.ResponseWriter, r *http.Request) {
	source, auth, ok := s.loadWazuhSource(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wazuhSyncTimeout)
	defer cancel()
	if e := s.wazuhSyncOnce(ctx, source, auth); e != nil {
		writeErr(w, 502, e.Error())
		return
	}
	out, e := s.m.pg.GetWazuhSource(r.Context(), source.ID)
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}

func (s *Server) wazuhSyncOnce(ctx context.Context, source *db.WazuhSource, auth wazuh.Credentials) error {
	graph, e := wazuhCollect(ctx, source.Config, auth)
	persist, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e != nil {
		if pe := s.m.pg.FinishWazuhSync(persist, source.ID, source.Revision, nil, e.Error()); pe != nil {
			log.Printf("[wazuh] sync result persistence: %v", pe)
		}
		return e
	}
	return s.m.pg.FinishWazuhSync(persist, source.ID, source.Revision, &graph, "")
}

func wazuhCollect(ctx context.Context, cfg wazuh.Config, auth wazuh.Credentials) (wazuh.Graph, error) {
	agents, e := wazuh.Agents(ctx, cfg, auth)
	if e != nil {
		return wazuh.Graph{}, e
	}
	records, e := wazuh.CheckRecords(ctx, cfg, auth)
	if e != nil {
		return wazuh.Graph{}, e
	}
	return wazuh.BuildGraph(agents, records), nil
}

func (s *Server) runWazuhSync(id int64) {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, wazuhSyncTimeout)
	defer cancel()
	source, e := s.m.pg.GetWazuhSource(ctx, id)
	if e != nil || !source.Enabled {
		return
	}
	auth, e := s.wazuhCredentials(source)
	if e != nil {
		_ = s.m.pg.FinishWazuhSync(ctx, source.ID, source.Revision, nil, e.Error())
		return
	}
	if e = s.wazuhSyncOnce(ctx, source, auth); e != nil {
		log.Printf("[wazuh] sync %q: %v", source.Name, e)
	}
}

func (s *Server) scheduleWazuhSync(ctx context.Context) {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(wazuhSyncInterval)
	defer ticker.Stop()
	for {
		sources, e := s.m.pg.ListWazuhSources(ctx)
		if e != nil {
			log.Printf("[wazuh] list sources: %v", e)
		}
		for _, source := range sources {
			if ctx.Err() != nil {
				return
			}
			if source.Enabled {
				s.runWazuhSync(source.ID)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// listProtectedAssets returns the last asset graph of every enabled source.
func (s *Server) listProtectedAssets(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rows, e := pg.ListWazuhSources(r.Context())
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	type entry struct {
		ID        string       `json:"id"`
		Name      string       `json:"name"`
		SyncedAt  *time.Time   `json:"synced_at"`
		SyncError string       `json:"sync_error"`
		Indexer   bool         `json:"indexer"`
		Nodes     []wazuh.Node `json:"nodes"`
		Edges     []wazuh.Edge `json:"edges"`
	}
	out := []entry{}
	for _, row := range rows {
		if row.Enabled {
			out = append(out, entry{ID: strconv.FormatInt(row.ID, 10), Name: row.Name, SyncedAt: row.SyncedAt, SyncError: row.SyncError,
				Indexer: row.Config.IndexerURL != "", Nodes: row.Graph.Nodes, Edges: row.Graph.Edges})
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"sources": out})
}

// ImportWazuhSource creates or updates the connection called name without
// going through the HTTP API. It backs `artex -wazuh-import`, which lets a
// local setup script move an existing environment's read-only credentials
// into the encrypted store without anyone typing them into the UI.
func ImportWazuhSource(ctx context.Context, pg *db.DB, dataDir, keyDir, name string, cfg wazuh.Config, creds wazuh.Credentials) (created bool, err error) {
	if pg == nil {
		return false, errors.New("PostgreSQL 연결이 필요합니다")
	}
	key, err := loadOrCreateJWTKey(keyDir, dataDir)
	if err != nil {
		return false, err
	}
	if cfg, err = wazuh.Validate(cfg); err != nil {
		return false, err
	}
	if err = wazuh.ValidateCredentials(cfg, creds); err != nil {
		return false, err
	}
	cipher, err := (&Server{jwtKey: key}).encryptWazuhCredentials(creds)
	if err != nil {
		return false, err
	}
	rows, err := pg.ListWazuhSources(ctx)
	if err != nil {
		return false, err
	}
	var id, revision int64
	for _, row := range rows {
		if row.Name == name {
			id, revision = row.ID, row.Revision
			break
		}
	}
	_, err = pg.SaveWazuhSource(ctx, id, revision, name, cfg, true, cipher)
	return id == 0, err
}
