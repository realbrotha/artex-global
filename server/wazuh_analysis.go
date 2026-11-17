package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/wazuh"
)

// A manual analysis runs the scheduled pipeline (collect alerts, extract case
// candidates, judge them) for the hosts the user picked, and exposes each
// step as it happens. Jobs live in memory only: the verdicts they produce are
// stored like any other verdict, the run itself is not.
const (
	analysisTimeout  = 5 * time.Minute
	analysisKeep     = 30 * time.Minute
	analysisMaxJobs  = 16
	analysisMaxHosts = 500
)

type analysisStep struct {
	// "", "running", "done" or "failed"
	Status string `json:"status"`
	Ms     int64  `json:"ms,omitempty"`
}

type analysisCase struct {
	caseView
	// Verdict run of this job: "", "pending", "running", "done" or "failed".
	Judge      string `json:"judge,omitempty"`
	JudgeError string `json:"judge_error,omitempty"`
	JudgeMs    int64  `json:"judge_ms,omitempty"`
}

type analysisView struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Hosts []string `json:"hosts"`
	Days  int      `json:"days"`
	// "collecting", "extracting", "ready", "judging", "done", "failed" or "stopped"
	State   string       `json:"state"`
	Error   string       `json:"error,omitempty"`
	Collect analysisStep `json:"collect"`
	Alerts  int          `json:"alerts"`
	Capped  bool         `json:"capped"`
	Rules   int          `json:"rules"`
	Extract analysisStep `json:"extract"`
	// Case candidates per correlation pattern ("P1".."P9").
	Patterns map[string]int `json:"patterns"`
	Cases    []analysisCase `json:"cases"`
	JudgeAt  int            `json:"judge_done"`
	JudgeOf  int            `json:"judge_total"`
	Model    string         `json:"model,omitempty"`
}

type analysisJob struct {
	mu      sync.Mutex
	view    analysisView
	source  int64
	raw     []wazuh.Case // with timelines, for the verdict prompt
	created time.Time
	cancel  context.CancelFunc
}

func (j *analysisJob) update(f func(v *analysisView)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f(&j.view)
}

func (j *analysisJob) snapshot() analysisView {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := j.view
	// Never nil: an empty list must reach the client as [], not null.
	out.Cases = append([]analysisCase{}, j.view.Cases...)
	out.Hosts = append([]string{}, j.view.Hosts...)
	out.Patterns = map[string]int{}
	for k, n := range j.view.Patterns {
		out.Patterns[k] = n
	}
	return out
}

var analyses = struct {
	sync.Mutex
	jobs map[string]*analysisJob
}{jobs: map[string]*analysisJob{}}

func addAnalysis(job *analysisJob) {
	analyses.Lock()
	defer analyses.Unlock()
	for id, old := range analyses.jobs {
		if time.Since(old.created) > analysisKeep {
			old.cancel()
			delete(analyses.jobs, id)
		}
	}
	for len(analyses.jobs) >= analysisMaxJobs {
		oldest := ""
		for id, old := range analyses.jobs {
			if oldest == "" || old.created.Before(analyses.jobs[oldest].created) {
				oldest = id
			}
		}
		analyses.jobs[oldest].cancel()
		delete(analyses.jobs, oldest)
	}
	analyses.jobs[job.view.ID] = job
}

func (s *Server) wazuhAnalysisRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/analyses", s.startAnalysis)
	mux.HandleFunc("GET /api/defensive/wazuh/{sourceID}/analyses/{analysisID}", s.getAnalysis)
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/analyses/{analysisID}/judge", s.judgeAnalysis)
	mux.HandleFunc("POST /api/defensive/wazuh/{sourceID}/analyses/{analysisID}/stop", s.stopAnalysis)
}

func (s *Server) findAnalysis(w http.ResponseWriter, r *http.Request) *analysisJob {
	id, ok := pathInt(r, "sourceID")
	analyses.Lock()
	job := analyses.jobs[r.PathValue("analysisID")]
	analyses.Unlock()
	if !ok || job == nil || job.source != id {
		writeErr(w, 404, "분석을 찾을 수 없습니다. 다시 시작해 주세요")
		return nil
	}
	return job
}

// cleanHosts validates the agent names of a request: they go into an indexer
// query, so only plain host names are accepted.
func cleanHosts(in []string) ([]string, bool) {
	if len(in) > analysisMaxHosts {
		return nil, false
	}
	seen := map[string]bool{}
	out := []string{}
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h == "" || len(h) > 253 || strings.ContainsFunc(h, func(r rune) bool {
			return !(r == '-' || r == '.' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
		}) {
			return nil, false
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out, true
}

func (s *Server) startAnalysis(w http.ResponseWriter, r *http.Request) {
	source, auth, ok := s.loadWazuhSource(w, r)
	if !ok {
		return
	}
	var in struct {
		Label string   `json:"label"`
		Hosts []string `json:"hosts"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 1<<20) {
		return
	}
	hosts, valid := cleanHosts(in.Hosts)
	if !valid {
		writeErr(w, 400, "분석 대상 장비 이름을 확인해 주세요")
		return
	}
	if source.Config.IndexerURL == "" {
		writeErr(w, 409, "indexer 주소가 없는 연결은 경보를 분석할 수 없습니다")
		return
	}
	label := strings.TrimSpace(in.Label)
	if len([]rune(label)) > 120 {
		label = string([]rune(label)[:120])
	}
	id := make([]byte, 12)
	if _, e := rand.Read(id); e != nil {
		writeErr(w, 500, "분석을 시작하지 못했습니다")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), analysisTimeout)
	job := &analysisJob{source: source.ID, created: time.Now(), cancel: cancel, view: analysisView{
		ID: hex.EncodeToString(id), Label: label, Hosts: hosts, Days: wazuh.AlertWindowDays, State: "collecting",
		Collect: analysisStep{Status: "running"}, Patterns: map[string]int{}, Cases: []analysisCase{},
	}}
	addAnalysis(job)
	go func() {
		defer cancel()
		s.runAnalysis(ctx, job, source, auth)
	}()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, job.snapshot())
}

func (s *Server) runAnalysis(ctx context.Context, job *analysisJob, source *db.WazuhSource, auth wazuh.Credentials) {
	fail := func(e error) {
		job.update(func(v *analysisView) {
			if errors.Is(e, context.Canceled) {
				v.State = "stopped"
			} else {
				v.State, v.Error = "failed", e.Error()
			}
			if v.Collect.Status == "running" {
				v.Collect.Status = "failed"
			}
			if v.Extract.Status == "running" {
				v.Extract.Status = "failed"
			}
		})
	}
	started := time.Now()
	// Posture (config-check results) feeds case severity, as in the scheduled run.
	records, e := wazuh.CheckRecords(ctx, source.Config, auth)
	if e != nil {
		fail(e)
		return
	}
	var collected time.Time
	cases, meta, e := wazuhExtractCases(ctx, s.m.pg, source.Config, auth, records, job.view.Hosts, func(alerts int, capped bool) {
		collected = time.Now()
		job.update(func(v *analysisView) {
			v.Collect = analysisStep{Status: "done", Ms: collected.Sub(started).Milliseconds()}
			v.Alerts, v.Capped = alerts, capped
			v.State, v.Extract.Status = "extracting", "running"
		})
	})
	if e != nil {
		fail(e)
		return
	}
	verdicts, e := s.m.pg.CaseVerdicts(ctx, source.ID)
	if e != nil {
		fail(errors.New("사건 판정을 읽지 못했습니다"))
		return
	}
	now := time.Now()
	job.mu.Lock()
	job.raw = cases
	job.view.Rules = meta.Rules
	job.view.Extract = analysisStep{Status: "done", Ms: now.Sub(collected).Milliseconds()}
	for _, c := range cases {
		job.view.Patterns[c.Pattern]++
		row := analysisCase{caseView: withVerdict(c, verdicts, now)}
		row.Timeline = nil
		job.view.Cases = append(job.view.Cases, row)
	}
	job.view.State = "ready"
	job.mu.Unlock()
}

func (s *Server) getAnalysis(w http.ResponseWriter, r *http.Request) {
	job := s.findAnalysis(w, r)
	if job == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, job.snapshot())
}

func (s *Server) stopAnalysis(w http.ResponseWriter, r *http.Request) {
	job := s.findAnalysis(w, r)
	if job == nil {
		return
	}
	job.cancel()
	job.update(func(v *analysisView) {
		if v.State == "collecting" || v.State == "extracting" || v.State == "judging" {
			v.State = "stopped"
		}
	})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, job.snapshot())
}

// needsVerdict: not approved activity, and never judged or judged before its
// latest activity.
func needsVerdict(c analysisCase) bool {
	return c.Known == "" && (c.Verdict == nil || c.Verdict.Stale)
}

// judgeAnalysis sends the job's unjudged cases to the model, one at a time.
// It is a separate, explicit request because it is the step that sends alert
// content to the model provider.
func (s *Server) judgeAnalysis(w http.ResponseWriter, r *http.Request) {
	job := s.findAnalysis(w, r)
	if job == nil {
		return
	}
	s.cfgMu.Lock()
	provider, model, ready := s.llmProv, s.llmCfg.Model, s.llmOn && s.llmProv != nil
	s.cfgMu.Unlock()
	if !ready {
		writeErr(w, 409, "LLM 이 설정되지 않았습니다. LLM 메뉴에서 모델을 연결해 주세요")
		return
	}
	job.mu.Lock()
	if job.view.State != "ready" && job.view.State != "done" {
		job.mu.Unlock()
		writeErr(w, 409, "분석이 끝난 뒤에 판정할 수 있습니다")
		return
	}
	todo := []int{}
	ids := map[int]string{}
	for i, c := range job.view.Cases {
		if needsVerdict(c) {
			todo = append(todo, i)
			ids[i] = c.ID
			job.view.Cases[i].Judge, job.view.Cases[i].JudgeError = "pending", ""
		}
	}
	if len(todo) == 0 {
		job.mu.Unlock()
		writeErr(w, 409, "판정할 사건 후보가 없습니다")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Duration(len(todo))*caseJudgeTimeout)
	job.cancel = cancel
	job.view.State, job.view.JudgeAt, job.view.JudgeOf, job.view.Model = "judging", 0, len(todo), model
	raw := job.raw
	job.mu.Unlock()

	go func() {
		defer cancel()
		complete := caseCompleter(provider)
		for _, i := range todo {
			if ctx.Err() != nil {
				break
			}
			job.update(func(v *analysisView) { v.Cases[i].Judge = "running" })
			started := time.Now()
			c, near := findCase(raw, ids[i])
			var stored *db.CaseVerdict
			var e error
			if c == nil {
				e = errors.New("사건 후보를 찾을 수 없습니다")
			} else {
				one, done := context.WithTimeout(ctx, caseJudgeTimeout)
				var verdict wazuh.Verdict
				if verdict, e = wazuh.JudgeCase(one, complete, *c, near); e == nil {
					if stored, e = s.m.pg.SaveCaseVerdict(one, job.source, *c, verdict, model); e != nil {
						e = errors.New("판정을 저장하지 못했습니다")
					}
				} else {
					_, msg := judgeFailure(e)
					e = errors.New(msg)
				}
				done()
			}
			job.update(func(v *analysisView) {
				row := &v.Cases[i]
				row.JudgeMs = time.Since(started).Milliseconds()
				if e != nil {
					row.Judge, row.JudgeError = "failed", e.Error()
				} else {
					row.Judge, row.Verdict = "done", &caseVerdictView{CaseVerdict: stored}
				}
				v.JudgeAt++
			})
		}
		job.update(func(v *analysisView) {
			for i := range v.Cases {
				if v.Cases[i].Judge == "pending" || v.Cases[i].Judge == "running" {
					v.Cases[i].Judge = ""
				}
			}
			if v.State == "judging" {
				v.State = "done"
			}
		})
	}()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, job.snapshot())
}
