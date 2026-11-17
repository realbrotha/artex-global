package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/wazuh"
	"github.com/Autumn-27/norma/llm"
)

const (
	wazuhSyncInterval = 5 * time.Minute
	wazuhSyncTimeout  = 90 * time.Second
	// How long a manual sync request waits before answering with the sync
	// still running. Below the 30 s response limit of the dev proxy.
	wazuhSyncAnswer = 20 * time.Second
	// Case extraction reads up to a week of alerts, so it runs on its own,
	// slower cadence and with its own time limit.
	wazuhCasesInterval = 30 * time.Minute
	wazuhCasesTimeout  = 5 * time.Minute
	wazuhCredentialAD  = "wazuh-source-credentials/v1"
)

func (s *Server) registerWazuhSources(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/defensive/wazuh", s.listWazuhSources)
	mux.HandleFunc("POST /api/defensive/wazuh", s.saveWazuhSource)
	mux.HandleFunc("PUT /api/defensive/wazuh/{sourceID}", s.saveWazuhSource)
	mux.HandleFunc("DELETE /api/defensive/wazuh/{sourceID}", s.deleteWazuhSource)
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/test", s.testWazuhSource)
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/sync", s.syncWazuhSource)
	mux.HandleFunc("GET /api/defensive/wazuh/{sourceID}/checks", s.wazuhHostChecks)
	mux.HandleFunc("GET /api/defensive/assets", s.listProtectedAssets)
	mux.HandleFunc("GET /api/defensive/cases", s.listCases)
	mux.HandleFunc("GET /api/defensive/wazuh/{sourceID}/cases/{caseID}", s.getCase)
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/cases/{caseID}/judge", s.judgeCase)
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/cases/{caseID}/correct", s.correctCase)
	mux.HandleFunc("GET /api/defensive/feedback", s.getFeedback)
	mux.HandleFunc("GET /api/defensive/accepted-risks", s.listAcceptedRisks)
	mux.HandleFunc("PUT /api/defensive/accepted-risks", s.replaceAcceptedRisks)
	mux.HandleFunc("GET /api/defensive/posture", s.listPosture)
	s.wazuhAnalysisRoutes(mux)
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
	// A manual sync also re-extracts cases, which can outlast a proxy's
	// response timeout. It runs detached from the request and the handler
	// answers after wazuhSyncAnswer at the latest; a sync still running then
	// finishes in the background and shows up on the next reload.
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), wazuhSyncTimeout+wazuhCasesTimeout)
		defer cancel()
		done <- s.wazuhSyncOnce(ctx, source, auth, true)
	}()
	select {
	case e := <-done:
		if e != nil {
			writeErr(w, 502, e.Error())
			return
		}
	case <-time.After(wazuhSyncAnswer):
	}
	out, e := s.m.pg.GetWazuhSource(r.Context(), source.ID)
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}

// wazuhSyncOnce refreshes the asset map and, when due or forced, the case
// candidates. A case-extraction failure is recorded on its own and does not
// fail the asset sync.
func (s *Server) wazuhSyncOnce(ctx context.Context, source *db.WazuhSource, auth wazuh.Credentials, forceCases bool) error {
	risks, e := s.m.pg.ListAcceptedRisks(ctx)
	if e != nil {
		return e
	}
	graph, issues, records, e := wazuhCollect(ctx, source.Config, auth, risks)
	persist, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e != nil {
		if pe := s.m.pg.FinishWazuhSync(persist, source.ID, source.Revision, nil, nil, e.Error()); pe != nil {
			log.Printf("[wazuh] sync result persistence: %v", pe)
		}
		return e
	}
	if e = s.m.pg.FinishWazuhSync(persist, source.ID, source.Revision, &graph, issues, ""); e != nil {
		return e
	}
	if source.Config.IndexerURL == "" {
		return nil
	}
	if !forceCases {
		if at, e := s.m.pg.WazuhCasesAt(ctx, source.ID); e == nil && at != nil && time.Since(*at) < wazuhCasesInterval {
			return nil
		}
	}
	s.wazuhCasesOnce(ctx, source, auth, records)
	return nil
}

// SIEM setting keys: detection inputs imported from a Thaki-Siem checkout.
const (
	siemEventCatalog  = "event-catalog"
	siemEventCriteria = "event-criteria"
	siemKnownActivity = "known-activity"
	siemAdminSources  = "admin-src"
)

// wazuhCasesOnce extracts case candidates and stores them (or the reason it
// could not).
func (s *Server) wazuhCasesOnce(parent context.Context, source *db.WazuhSource, auth wazuh.Credentials, records []wazuh.CheckRecord) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), wazuhCasesTimeout)
	defer cancel()
	cases, meta, e := wazuhExtractCases(ctx, s.m.pg, source.Config, auth, records, nil, nil)
	failure := ""
	if e != nil {
		failure = e.Error()
		log.Printf("[wazuh] case extraction %q: %v", source.Name, e)
	}
	persist, done := context.WithTimeout(context.Background(), 15*time.Second)
	defer done()
	if pe := s.m.pg.SaveWazuhCases(persist, source.ID, source.Revision, cases, meta, failure); pe != nil {
		log.Printf("[wazuh] case result persistence: %v", pe)
	}
}

var errNoEventCatalog = errors.New("탐지 기준이 등록되지 않았습니다. artex -siem-import <Thaki-Siem 경로> 로 가져와 주세요")

// hosts limits the alerts to those agents (nil = all); collected, when set, is
// called once the alerts are in, before the cases are built.
func wazuhExtractCases(ctx context.Context, pg *db.DB, cfg wazuh.Config, auth wazuh.Credentials, records []wazuh.CheckRecord, hosts []string, collected func(alerts []*wazuh.Alert, capped bool)) ([]wazuh.Case, db.CaseMeta, error) {
	meta := db.CaseMeta{WindowDays: wazuh.AlertWindowDays}
	settings, e := pg.GetSiemSettings(ctx)
	if e != nil {
		return nil, meta, e
	}
	if settings[siemEventCatalog] == "" || settings[siemEventCriteria] == "" {
		return nil, meta, errNoEventCatalog
	}
	in := wazuh.CaseInput{Today: time.Now(), Admin: wazuh.ParseAdminPrefixes(settings[siemAdminSources]), Posture: wazuh.PostureOf(records)}
	if in.Catalog, e = wazuh.ParseEventCatalog(settings[siemEventCatalog]); e != nil {
		return nil, meta, e
	}
	if in.Criteria, e = wazuh.ParseEventCriteria(settings[siemEventCriteria]); e != nil {
		return nil, meta, e
	}
	if in.Known, e = wazuh.ParseKnownActivity(settings[siemKnownActivity]); e != nil {
		return nil, meta, e
	}
	rules := in.Catalog.AnalysedRules()
	meta.Rules = len(rules)
	if in.Alerts, meta.Capped, e = wazuh.FetchHostAlerts(ctx, cfg, auth, rules, wazuh.AlertWindowDays, hosts); e != nil {
		return nil, meta, e
	}
	meta.Alerts = len(in.Alerts)
	if collected != nil {
		collected(in.Alerts, meta.Capped)
	}
	in.Seen, meta.SeenNote = wazuh.SeenLogins(ctx, cfg, auth, wazuh.AlertWindowDays, time.Now())
	return wazuh.BuildCases(in), meta, nil
}

// A verdict older than this is judged again (siem-assess: precedents
// expire after 30 days).
const caseVerdictMaxAge = 30 * 24 * time.Hour

type caseVerdictView struct {
	*db.CaseVerdict
	// Stale: the case has newer activity than the verdict judged, or the
	// verdict is past its age limit. It is shown, marked, until judged again.
	Stale bool `json:"stale"`
}

type caseView struct {
	wazuh.Case
	Verdict *caseVerdictView `json:"verdict,omitempty"`
}

func withVerdict(c wazuh.Case, verdicts map[string]*db.CaseVerdict, now time.Time) caseView {
	out := caseView{Case: c}
	if v := verdicts[db.CaseKey(c)]; v != nil {
		// A person's verdict does not age out; only new activity reopens it.
		aged := v.Method != wazuh.MethodHuman && now.Sub(v.JudgedAt) > caseVerdictMaxAge
		out.Verdict = &caseVerdictView{CaseVerdict: v, Stale: c.Last.After(v.CaseLast) || aged}
	}
	return out
}

type caseSourceView struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	CasesAt *time.Time  `json:"cases_at"`
	Error   string      `json:"error"`
	Meta    db.CaseMeta `json:"meta"`
	Cases   []caseView  `json:"cases"`
}

// listCases returns every connection's case candidates without timelines.
func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sets, e := pg.ListWazuhCases(r.Context())
	if e != nil {
		writeErr(w, 500, "사건 후보를 읽지 못했습니다")
		return
	}
	out := []caseSourceView{}
	now := time.Now()
	for _, set := range sets {
		verdicts, e := pg.CaseVerdicts(r.Context(), set.SourceID)
		if e != nil {
			writeErr(w, 500, "사건 판정을 읽지 못했습니다")
			return
		}
		views := make([]caseView, len(set.Cases))
		for i, c := range set.Cases {
			c.Timeline = nil
			views[i] = withVerdict(c, verdicts, now)
		}
		out = append(out, caseSourceView{ID: strconv.FormatInt(set.SourceID, 10), Name: set.Name, CasesAt: set.CasesAt, Error: set.Error, Meta: set.Meta, Cases: views})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"sources": out})
}

// getCase returns one case with its timeline.
func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "sourceID")
	caseID := r.PathValue("caseID")
	if !ok || id <= 0 || caseID == "" {
		writeErr(w, 400, "연결 ID와 사건 번호를 확인해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	set, e := pg.GetWazuhCases(r.Context(), id)
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	c, _ := findCase(set.Cases, caseID)
	if c == nil {
		// Case ids are positions in the latest extraction, so an older id can vanish.
		writeErr(w, 404, "사건 후보를 찾을 수 없습니다. 목록을 새로고침해 주세요")
		return
	}
	verdicts, e := pg.CaseVerdicts(r.Context(), id)
	if e != nil {
		writeErr(w, 500, "사건 판정을 읽지 못했습니다")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, withVerdict(*c, verdicts, time.Now()))
}

// caseCompleter adapts the configured model provider to a verdict prompt.
func caseCompleter(provider llm.Provider) wazuh.Completer {
	return func(ctx context.Context, system, user string, maxTokens int) (string, error) {
		message, _, _, err := provider.Complete(ctx, llm.CompletionRequest{System: []string{system}, Messages: []llm.Message{llm.UserText(user)}, MaxTokens: maxTokens})
		if err != nil {
			return "", wrapHuntProviderError(err)
		}
		var text strings.Builder
		for _, block := range message.Content {
			if block.Type == llm.BlockText {
				text.WriteString(block.Text)
			}
		}
		return text.String(), nil
	}
}

// judgeFailure maps a verdict error to an HTTP status and a message that is
// safe to show: provider errors are already sanitised.
func judgeFailure(e error) (int, string) {
	var callErr *huntProviderCallError
	switch {
	case errors.Is(e, wazuh.ErrVerdictFormat):
		return 502, e.Error()
	case errors.As(e, &callErr):
		return 502, callErr.Error()
	case errors.Is(e, context.DeadlineExceeded):
		return 504, "LLM 판정 시간이 초과됐습니다"
	default:
		return 502, "LLM 판정에 실패했습니다"
	}
}

func findCase(cases []wazuh.Case, id string) (*wazuh.Case, []wazuh.Case) {
	byID := map[string]*wazuh.Case{}
	for i := range cases {
		byID[cases[i].ID] = &cases[i]
	}
	c := byID[id]
	if c == nil {
		return nil, nil
	}
	near := []wazuh.Case{}
	for _, n := range c.Near {
		if other := byID[n]; other != nil && len(near) < 8 {
			near = append(near, *other)
		}
	}
	return c, near
}

const caseJudgeTimeout = 3 * time.Minute

// judgeCase sends one case to the configured model and stores the verdict.
// It runs only on request: case data leaves this server for the model
// provider, so nothing is judged in the background.
func (s *Server) judgeCase(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "sourceID")
	caseID := r.PathValue("caseID")
	if !ok || id <= 0 || caseID == "" {
		writeErr(w, 400, "연결 ID와 사건 번호를 확인해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	s.cfgMu.Lock()
	provider, model, ready := s.llmProv, s.llmCfg.Model, s.llmOn && s.llmProv != nil
	s.cfgMu.Unlock()
	if !ready {
		writeErr(w, 409, "LLM 이 설정되지 않았습니다. LLM 메뉴에서 모델을 연결해 주세요")
		return
	}
	set, e := pg.GetWazuhCases(r.Context(), id)
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	c, near := findCase(set.Cases, caseID)
	if c == nil {
		writeErr(w, 404, "사건 후보를 찾을 수 없습니다. 목록을 새로고침해 주세요")
		return
	}
	if c.Known != "" {
		writeErr(w, 409, "정상 업무 등록부와 일치한 사건은 판정하지 않습니다")
		return
	}
	// Detached from the request: a judgment can outlast a proxy's response
	// timeout, and a verdict the model already produced should still be
	// stored. The client then finds it on its next reload.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*caseJudgeTimeout)
	defer cancel()
	sched, se := s.siemSchedule(ctx)
	if se != nil {
		sched = wazuh.DefaultSchedule()
	}
	stored, status, e := s.judgeAndRecord(llmrec.WithWorker(ctx, "siem-judge"), provider, model, id, "", *c, near, sched.Debate)
	if e != nil {
		writeErr(w, status, e.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, caseVerdictView{CaseVerdict: stored})
}

// annotateCases marks each host node with the case candidates that involve it.
func annotateCases(nodes []wazuh.Node, cases []wazuh.Case) {
	type agg struct {
		n   int
		sev string
	}
	rank := map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
	byHost := map[string]*agg{}
	for _, c := range cases {
		if c.Known != "" {
			continue
		}
		for _, h := range c.Hosts {
			id := wazuh.HostNodeID(h)
			a := byHost[id]
			if a == nil {
				a = &agg{sev: c.Severity}
				byHost[id] = a
			}
			a.n++
			if rank[c.Severity] < rank[a.sev] {
				a.sev = c.Severity
			}
		}
	}
	for i := range nodes {
		if a := byHost[nodes[i].ID]; a != nil {
			nodes[i].Cases, nodes[i].CaseSev = a.n, a.sev
		}
	}
}

func wazuhCollect(ctx context.Context, cfg wazuh.Config, auth wazuh.Credentials, risks []wazuh.AcceptedRisk) (wazuh.Graph, map[string][]wazuh.Issue, []wazuh.CheckRecord, error) {
	agents, e := wazuh.Agents(ctx, cfg, auth)
	if e != nil {
		return wazuh.Graph{}, nil, nil, e
	}
	records, e := wazuh.CheckRecords(ctx, cfg, auth)
	if e != nil {
		return wazuh.Graph{}, nil, nil, e
	}
	// Interface addresses are an extra: a reader account without inventory
	// permission still gets the map, with the reason noted.
	addrNote := ""
	if e := wazuh.NetAddrs(ctx, cfg, auth, agents); e != nil {
		if ctx.Err() != nil {
			return wazuh.Graph{}, nil, nil, ctx.Err()
		}
		addrNote = e.Error()
	}
	now := time.Now()
	_, issues := wazuh.BuildChecks(records, risks, now)
	graph := wazuh.BuildGraph(agents, records, risks, now)
	graph.AddrNote = addrNote
	return graph, issues, records, nil
}

func (s *Server) listAcceptedRisks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	risks, e := pg.ListAcceptedRisks(r.Context())
	if e != nil {
		writeErr(w, 500, "위험 수용 등록부를 읽지 못했습니다")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"risks": risks})
}

// replaceAcceptedRisks replaces the registry with an uploaded TSV, then
// re-syncs every connection so counts reflect it right away.
func (s *Server) replaceAcceptedRisks(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TSV string `json:"tsv"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 2<<20) {
		return
	}
	risks, e := wazuh.ParseAcceptedRisks(in.TSV)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if e = pg.ReplaceAcceptedRisks(r.Context(), risks); e != nil {
		if errors.Is(e, wazuh.ErrInvalid) {
			writeErr(w, 400, e.Error())
		} else {
			writeErr(w, 500, "위험 수용 등록부를 저장하지 못했습니다")
		}
		return
	}
	go s.resyncAllWazuh()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"risks": risks})
}

func (s *Server) resyncAllWazuh() {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	sources, e := s.m.pg.ListWazuhSources(parent)
	if e != nil {
		log.Printf("[wazuh] resync: %v", e)
		return
	}
	for _, source := range sources {
		if source.Enabled {
			s.runWazuhSync(source.ID)
		}
	}
}

// wazuhHostChecks returns one node's config-check issues from the last sync.
func (s *Server) wazuhHostChecks(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "sourceID")
	node := r.URL.Query().Get("node")
	if !ok || id <= 0 || node == "" || len(node) > 300 {
		writeErr(w, 400, "연결 ID와 장비를 확인해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	issues, e := pg.WazuhHostIssues(r.Context(), id, node)
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"issues": issues})
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
		_ = s.m.pg.FinishWazuhSync(ctx, source.ID, source.Revision, nil, nil, e.Error())
		return
	}
	if e = s.wazuhSyncOnce(ctx, source, auth, false); e != nil {
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
		AddrNote  string       `json:"addr_note,omitempty"`
		Nodes     []wazuh.Node `json:"nodes"`
		Edges     []wazuh.Edge `json:"edges"`
	}
	caseSets, e := pg.ListWazuhCases(r.Context())
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	// Cases judged normal or false positive (and still current) are not
	// counted against a host, like known activity.
	casesOf := map[int64][]wazuh.Case{}
	now := time.Now()
	for _, set := range caseSets {
		verdicts, e := pg.CaseVerdicts(r.Context(), set.SourceID)
		if e != nil {
			wazuhSourceError(w, e)
			return
		}
		for _, c := range set.Cases {
			if v := withVerdict(c, verdicts, now).Verdict; v != nil && !v.Stale && (v.Verdict.Verdict == wazuh.VerdictNormal || v.Verdict.Verdict == wazuh.VerdictFalsePositive) {
				continue
			}
			casesOf[set.SourceID] = append(casesOf[set.SourceID], c)
		}
	}
	out := []entry{}
	for _, row := range rows {
		if row.Enabled {
			annotateCases(row.Graph.Nodes, casesOf[row.ID])
			out = append(out, entry{ID: strconv.FormatInt(row.ID, 10), Name: row.Name, SyncedAt: row.SyncedAt, SyncError: row.SyncError,
				Indexer: row.Config.IndexerURL != "", AddrNote: row.Graph.AddrNote, Nodes: row.Graph.Nodes, Edges: row.Graph.Edges})
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

// listPosture returns, per enabled connection, every config-check item with
// the hosts that fail it, need a review, errored or are accepted. Evidence is
// not included: it is read per host (wazuhHostChecks).
func (s *Server) listPosture(w http.ResponseWriter, r *http.Request) {
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
		ID       string               `json:"id"`
		Name     string               `json:"name"`
		SyncedAt *time.Time           `json:"synced_at"`
		Hosts    int                  `json:"hosts"` // hosts with a check result
		Checks   []wazuh.CheckSummary `json:"checks"`
	}
	out := []entry{}
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		issues, e := pg.WazuhIssues(r.Context(), row.ID)
		if e != nil {
			wazuhSourceError(w, e)
			return
		}
		names := map[string]string{}
		checked := 0
		for _, n := range row.Graph.Nodes {
			names[n.ID] = n.Name
			if n.Checks != nil {
				checked++
			}
		}
		out = append(out, entry{ID: strconv.FormatInt(row.ID, 10), Name: row.Name, SyncedAt: row.SyncedAt,
			Hosts: checked, Checks: wazuh.SummarizeChecks(issues, names)})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"sources": out})
}
