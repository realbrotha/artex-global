package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
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

// analysisRule is one detection rule and how many collected alerts it fired.
type analysisRule struct {
	ID    string `json:"id"`
	Desc  string `json:"desc"`
	Level int    `json:"level"`
	Count int    `json:"count"`
}

// analysisHostCount is one host and how many collected alerts came from it.
type analysisHostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// Rows kept per breakdown; the panel shows the first few and the rest on request.
const (
	analysisTopRules = 50
	analysisTopHosts = 100
)

// alertDigest summarises the collected alerts for the collect step: the hosts
// they came from, the period they span, and the rules that fired, most first.
func alertDigest(alerts []*wazuh.Alert) (byHost []analysisHostCount, from, to *time.Time, top []analysisRule) {
	seen := map[string]int{}
	rules := map[string]*analysisRule{}
	for _, a := range alerts {
		seen[a.Host]++
		t := a.T
		if from == nil || t.Before(*from) {
			from = &t
		}
		if to == nil || t.After(*to) {
			to = &t
		}
		r := rules[a.RuleID]
		if r == nil {
			r = &analysisRule{ID: a.RuleID, Desc: a.Desc, Level: a.Level}
			rules[a.RuleID] = r
		}
		r.Count++
	}
	top = make([]analysisRule, 0, len(rules))
	for _, r := range rules {
		top = append(top, *r)
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].ID < top[j].ID
	})
	if len(top) > analysisTopRules {
		top = top[:analysisTopRules]
	}
	byHost = make([]analysisHostCount, 0, len(seen))
	for host, n := range seen {
		byHost = append(byHost, analysisHostCount{Host: host, Count: n})
	}
	sort.Slice(byHost, func(i, j int) bool {
		if byHost[i].Count != byHost[j].Count {
			return byHost[i].Count > byHost[j].Count
		}
		return byHost[i].Host < byHost[j].Host
	})
	if len(byHost) > analysisTopHosts {
		byHost = byHost[:analysisTopHosts]
	}
	return byHost, from, to, top
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
	// Collect detail: hosts with a config-check result, hosts that produced
	// alerts, the period the alerts span and the rules that fired most.
	Checked    int            `json:"checked_hosts"`
	AlertHosts int            `json:"alert_hosts"`
	AlertFrom  *time.Time     `json:"alert_from,omitempty"`
	AlertTo    *time.Time     `json:"alert_to,omitempty"`
	TopRules   []analysisRule `json:"top_rules"`
	// Alerts per host, most first. AlertHosts is the full count.
	AlertByHost []analysisHostCount `json:"alert_by_host"`
	// Alerts written to the run history; -1 while they are being written.
	AlertsStored int `json:"alerts_stored"`
	Rules        int `json:"rules"`
	// Why first-seen logins could not be used, when they could not.
	SeenNote string       `json:"seen_note,omitempty"`
	Extract  analysisStep `json:"extract"`
	// Case candidates per correlation pattern ("P1".."P9").
	Patterns map[string]int `json:"patterns"`
	Cases    []analysisCase `json:"cases"`
	JudgeAt  int            `json:"judge_done"`
	JudgeOf  int            `json:"judge_total"`
	Model    string         `json:"model,omitempty"`
	// "manual" (started from a screen) or "schedule".
	Trigger string `json:"trigger"`
	// Judging: why it did not run or stopped short, and how many cases went
	// to a debate or were confirmed conservatively.
	JudgeNote string `json:"judge_note,omitempty"`
	Debated   int    `json:"debated"`
	Fallback  int    `json:"fallback"`
	// Cases left for the next run by the per-run limit.
	Deferred int `json:"deferred"`
}

type analysisJob struct {
	mu     sync.Mutex
	view   analysisView
	source int64
	// Connection name, for the stored run.
	sourceName string
	raw        []wazuh.Case // with timelines, for the verdict prompt
	created    time.Time
	cancel     context.CancelFunc
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
	out.TopRules = append([]analysisRule{}, j.view.TopRules...)
	out.AlertByHost = append([]analysisHostCount{}, j.view.AlertByHost...)
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
	s.siemHistoryRoutes(mux)
	s.siemScheduleRoutes(mux)
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
	job, e := s.launchAnalysis(source, auth, in.Label, hosts, "manual")
	if e != nil {
		writeErr(w, 500, "분석을 시작하지 못했습니다")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, job.snapshot())
}

// launchAnalysis starts a run in the background: collect, extract, then
// judge by itself when the schedule settings say so.
func (s *Server) launchAnalysis(source *db.WazuhSource, auth wazuh.Credentials, label string, hosts []string, trigger string) (*analysisJob, error) {
	label = strings.TrimSpace(label)
	if len([]rune(label)) > 120 {
		label = string([]rune(label)[:120])
	}
	id := make([]byte, 12)
	if _, e := rand.Read(id); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), analysisTimeout)
	job := &analysisJob{source: source.ID, sourceName: source.Name, created: time.Now(), cancel: cancel, view: analysisView{
		ID: hex.EncodeToString(id), Label: label, Hosts: hosts, Days: wazuh.AlertWindowDays, State: "collecting",
		Collect: analysisStep{Status: "running"}, Patterns: map[string]int{}, Cases: []analysisCase{}, Trigger: trigger,
	}}
	addAnalysis(job)
	s.persistAnalysis(job)
	go func() {
		defer cancel()
		if s.runAnalysis(ctx, job, source, auth) {
			s.autoJudge(job)
		}
	}()
	return job, nil
}

// runAnalysis collects and extracts; it reports whether the run reached the
// point where its cases can be judged.
func (s *Server) runAnalysis(ctx context.Context, job *analysisJob, source *db.WazuhSource, auth wazuh.Credentials) bool {
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
		s.persistAnalysis(job)
	}
	started := time.Now()
	label := job.view.Label
	scope := "all hosts"
	if n := len(job.view.Hosts); n > 0 {
		scope = strconv.Itoa(n) + " host(s)"
	}
	log.Printf("[siem-analysis] %q start: %s, last %d days", label, scope, job.view.Days)
	// Posture (config-check results) feeds case severity, as in the scheduled run.
	records, e := wazuh.CheckRecords(ctx, source.Config, auth)
	if e != nil {
		log.Printf("[siem-analysis] %q failed: %v", label, e)
		fail(e)
		return false
	}
	checked := map[string]bool{}
	for _, r := range records {
		checked[r.Agent] = true
	}
	var collected time.Time
	var collectedAlerts []*wazuh.Alert
	cases, meta, e := wazuhExtractCases(ctx, s.m.pg, source.Config, auth, records, job.view.Hosts, func(alerts []*wazuh.Alert, capped bool) {
		collected = time.Now()
		collectedAlerts = alerts
		byHost, from, to, top := alertDigest(alerts)
		hostCount := map[string]bool{}
		for _, a := range alerts {
			hostCount[a.Host] = true
		}
		job.update(func(v *analysisView) {
			v.Collect = analysisStep{Status: "done", Ms: collected.Sub(started).Milliseconds()}
			v.Alerts, v.Capped = len(alerts), capped
			v.Checked, v.AlertHosts, v.AlertFrom, v.AlertTo, v.TopRules, v.AlertByHost = len(checked), len(hostCount), from, to, top, byHost
			v.State, v.Extract.Status = "extracting", "running"
		})
	})
	if e != nil {
		log.Printf("[siem-analysis] %q failed: %v", label, e)
		fail(e)
		return false
	}
	verdicts, e := s.m.pg.CaseVerdicts(ctx, source.ID)
	if e != nil {
		fail(errors.New("사건 판정을 읽지 못했습니다"))
		return false
	}
	now := time.Now()
	job.mu.Lock()
	job.raw = cases
	job.view.Rules, job.view.SeenNote = meta.Rules, meta.SeenNote
	job.view.Extract = analysisStep{Status: "done", Ms: now.Sub(collected).Milliseconds()}
	for _, c := range cases {
		job.view.Patterns[c.Pattern]++
		row := analysisCase{caseView: withVerdict(c, verdicts, now)}
		row.Timeline = nil
		job.view.Cases = append(job.view.Cases, row)
	}
	job.view.State = "ready"
	job.view.AlertsStored = -1
	job.mu.Unlock()
	s.persistAnalysis(job)
	go s.storeRunAlerts(job, collectedAlerts)
	// A scheduled whole-connection run is also the connection's case list.
	if job.view.Trigger == "schedule" && len(job.view.Hosts) == 0 {
		persist, done := context.WithTimeout(context.Background(), 15*time.Second)
		if pe := s.m.pg.SaveWazuhCases(persist, source.ID, source.Revision, cases, meta, ""); pe != nil {
			log.Printf("[siem-analysis] case list: %v", pe)
		}
		done()
	}
	log.Printf("[siem-analysis] %q extracted: %d alert(s), %d rule(s), %d case candidate(s) in %s",
		label, meta.Alerts, meta.Rules, len(cases), now.Sub(started).Round(100*time.Millisecond))
	return true
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
	s.persistAnalysis(job)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, job.snapshot())
}

// needsVerdict: not approved activity, and never judged or judged before its
// latest activity.
func needsVerdict(c analysisCase) bool {
	return c.Known == "" && (c.Verdict == nil || c.Verdict.Stale)
}

// autoJudge judges a finished run's cases when the schedule settings ask for
// it; otherwise it leaves a note saying judging is turned off.
func (s *Server) autoJudge(job *analysisJob) {
	sched, e := s.siemSchedule(context.Background())
	if e != nil {
		log.Printf("[siem-analysis] schedule settings: %v", e)
		sched = wazuh.DefaultSchedule()
	}
	if !sched.AutoJudge {
		job.update(func(v *analysisView) { v.JudgeNote = "자동 판정이 꺼져 있음" })
		s.persistAnalysis(job)
		return
	}
	if msg := s.judgeJob(job, sched.JudgeLimit, sched.Debate); msg != "" {
		job.update(func(v *analysisView) { v.JudgeNote = msg })
		s.persistAnalysis(job)
	}
}

// judgeAnalysis judges a run's remaining cases on request; the same work
// autoJudge does after extraction.
func (s *Server) judgeAnalysis(w http.ResponseWriter, r *http.Request) {
	job := s.findAnalysis(w, r)
	if job == nil {
		return
	}
	sched, e := s.siemSchedule(r.Context())
	if e != nil {
		sched = wazuh.DefaultSchedule()
	}
	if msg := s.judgeJob(job, analysisMaxHosts, sched.Debate); msg != "" {
		writeErr(w, 409, msg)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, job.snapshot())
}

// judgeJob judges up to limit of the run's cases that need a verdict, in the
// background, most severe first. It returns a message when it does not start.
func (s *Server) judgeJob(job *analysisJob, limit int, debate bool) string {
	s.cfgMu.Lock()
	provider, model, ready := s.llmProv, s.llmCfg.Model, s.llmOn && s.llmProv != nil
	s.cfgMu.Unlock()
	if !ready {
		return "LLM 이 설정되지 않았습니다. LLM 메뉴에서 모델을 연결해 주세요"
	}
	job.mu.Lock()
	if job.view.State != "ready" && job.view.State != "done" {
		job.mu.Unlock()
		return "분석이 끝난 뒤에 판정할 수 있습니다"
	}
	todo := []int{}
	for i, c := range job.view.Cases {
		if needsVerdict(c) {
			todo = append(todo, i)
		}
	}
	// Server order is most urgent first, so the limit keeps the worst cases.
	deferred := 0
	if len(todo) > limit {
		deferred = len(todo) - limit
		todo = todo[:limit]
	}
	if len(todo) == 0 {
		job.view.State, job.view.Deferred = "done", 0
		job.mu.Unlock()
		s.persistAnalysis(job)
		return ""
	}
	ids := map[int]string{}
	for _, i := range todo {
		ids[i] = job.view.Cases[i].ID
		job.view.Cases[i].Judge, job.view.Cases[i].JudgeError = "pending", ""
	}
	// Room for a debate (four calls) on every case.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(todo))*2*caseJudgeTimeout)
	job.cancel = cancel
	job.view.State, job.view.JudgeAt, job.view.JudgeOf, job.view.Model = "judging", 0, len(todo), model
	job.view.Deferred, job.view.JudgeNote = deferred, ""
	raw := job.raw
	label, runID := job.view.Label, job.view.ID
	job.mu.Unlock()
	s.persistAnalysis(job)
	log.Printf("[siem-analysis] %q judge start: %d case(s), %d deferred, debate %v, model %s", label, len(todo), deferred, debate, model)

	go func() {
		defer cancel()
		// Labels these calls in the LLM records and the usage ledger.
		ctx := llmrec.WithWorker(ctx, "siem-judge")
		judgeStarted := time.Now()
		failed := 0
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
				one, done := context.WithTimeout(ctx, 2*caseJudgeTimeout)
				stored, _, e = s.judgeAndRecord(one, provider, model, job.source, runID, *c, near, debate)
				done()
			}
			job.update(func(v *analysisView) {
				row := &v.Cases[i]
				row.JudgeMs = time.Since(started).Milliseconds()
				if e != nil {
					failed++
					row.Judge, row.JudgeError = "failed", e.Error()
				} else {
					row.Judge, row.Verdict = "done", &caseVerdictView{CaseVerdict: stored}
					switch stored.Method {
					case wazuh.MethodDebate:
						v.Debated++
					case wazuh.MethodFallback:
						v.Fallback++
					}
				}
				v.JudgeAt++
			})
			// Saved case by case, so a run cut short keeps what it judged.
			s.persistAnalysis(job)
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
		s.persistAnalysis(job)
		log.Printf("[siem-analysis] %q judge end: %d of %d judged, %d failed in %s",
			label, len(todo)-failed, len(todo), failed, time.Since(judgeStarted).Round(100*time.Millisecond))
	}()
	return ""
}
