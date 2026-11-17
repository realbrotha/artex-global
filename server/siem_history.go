package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/wazuh"
)

const historyWriteTimeout = 10 * time.Second

// Human precedents shown to the model per judgment.
const precedentsShown = 5

// recordingCompleter passes every request to inner and keeps what was sent
// and what came back, so a judgment can be read later exactly as the model
// saw it.
func recordingCompleter(inner wazuh.Completer, system *string, attempts *[]db.JudgeAttempt) wazuh.Completer {
	return func(ctx context.Context, sys, user string, maxTokens int) (string, error) {
		started := time.Now()
		text, err := inner(ctx, sys, user, maxTokens)
		role := wazuh.RoleFrom(ctx)
		// The analyst's rules are the system prompt of the record; other
		// roles carry theirs with the attempt.
		if role == "" || role == wazuh.RoleAnalyst {
			*system = sys
		}
		a := db.JudgeAttempt{Role: role, Prompt: user, Response: text, Ms: time.Since(started).Milliseconds()}
		if role != "" && role != wazuh.RoleAnalyst {
			a.System = sys
		}
		if err != nil {
			a.Error = err.Error()
		}
		*attempts = append(*attempts, a)
		return text, err
	}
}

// judgeAndRecord judges one case to a conclusion (single pass, outside
// knowledge and a debate when unsure, conservative fallback), stores the
// verdict, and records the judgment (every prompt and answer, the method and
// why) whether or not it succeeded. runID is "" outside an analysis run. A
// failure, which only a failed model call produces, comes back as an HTTP
// status and a message that is safe to show.
func (s *Server) judgeAndRecord(ctx context.Context, complete wazuh.Completer, model string, sourceID int64, runID string, c wazuh.Case, near []wazuh.Case, sched wazuh.Schedule) (*db.CaseVerdict, int, error) {
	started := time.Now()
	record := db.Judgement{SourceID: sourceID, RunID: runID, Case: c, Model: model}
	result, e := wazuh.JudgeCaseAuto(ctx, recordingCompleter(complete, &record.System, &record.Attempts), c, s.judgeOptions(ctx, sourceID, c, near, sched, ""))
	verdict := result.Verdict
	record.Reason = result.Reason
	addResearch(&record, result.AutoResult())
	var stored *db.CaseVerdict
	status := 0
	if e != nil {
		var msg string
		status, msg = judgeFailure(e)
		e = errors.New(msg)
	} else if stored, e = s.m.pg.SaveCaseVerdict(ctx, sourceID, c, verdict, model); e != nil {
		status, e = 500, errors.New("판정을 저장하지 못했습니다")
	} else {
		record.Verdict = &verdict
	}
	if e != nil {
		record.Error = e.Error()
	}
	record.Ms = time.Since(started).Milliseconds()
	s.saveJudgement(ctx, record)
	return stored, status, e
}

// judgeOptions gathers what a judgment works with: nearby cases, people's
// corrections on the same criterion (except exceptKey's own, for a replay),
// and the research step.
func (s *Server) judgeOptions(ctx context.Context, sourceID int64, c wazuh.Case, near []wazuh.Case, sched wazuh.Schedule, exceptKey string) wazuh.JudgeOptions {
	o := wazuh.JudgeOptions{Near: near, Debate: sched.Debate}
	var e error
	if exceptKey == "" {
		o.Precedents, e = s.m.pg.Precedents(ctx, sourceID, c.Criterion, precedentsShown)
	} else {
		o.Precedents, e = s.m.pg.PrecedentsExcept(ctx, sourceID, c.Criterion, exceptKey, precedentsShown)
	}
	if e != nil {
		log.Printf("[siem-analysis] precedents: %v", e)
	}
	if sched.Research {
		o.Research = s.researchCase
	}
	return o
}

// addResearch puts the research step into the judgment record as its own
// entry: what was searched for and what was found.
func addResearch(record *db.Judgement, r wazuh.AutoResult) {
	if r.ResearchQuery == "" {
		return
	}
	notes := r.ResearchNotes
	if notes == "" {
		notes = "찾은 자료 없음"
	}
	record.Attempts = append(record.Attempts, db.JudgeAttempt{Role: "research", Prompt: r.ResearchQuery, Response: notes})
}

// saveJudgement writes a judgment record even when the request that asked
// for it is already cancelled or timed out.
func (s *Server) saveJudgement(ctx context.Context, record db.Judgement) {
	write, done := context.WithTimeout(context.WithoutCancel(ctx), historyWriteTimeout)
	defer done()
	if pe := s.m.pg.SaveJudgement(write, record); pe != nil {
		log.Printf("[siem-analysis] judgment record: %v", pe)
	}
}

// persistAnalysis stores the job as it is now, so the run can be opened
// after the in-memory job is gone.
func (s *Server) persistAnalysis(job *analysisJob) {
	if s.m.pg == nil {
		return
	}
	view := job.snapshot()
	// The stored run also keeps each case's alert timeline: the live panel
	// fetches it on demand, a past run has nowhere else to get it.
	job.mu.Lock()
	timelines := make(map[string][]wazuh.CaseEvent, len(job.raw))
	for _, c := range job.raw {
		timelines[c.ID] = c.Timeline
	}
	job.mu.Unlock()
	raw, e := json.Marshal(struct {
		analysisView
		Timelines map[string][]wazuh.CaseEvent `json:"timelines"`
	}{view, timelines})
	if e == nil {
		ctx, done := context.WithTimeout(context.Background(), historyWriteTimeout)
		defer done()
		e = s.m.pg.SaveAnalysisRun(ctx, view.ID, job.source, job.sourceName, view.Label, view.State, job.created, raw)
	}
	if e != nil {
		log.Printf("[siem-analysis] run record: %v", e)
	}
}

// storeRunAlerts writes the alerts the run collected to the history, apart
// from the run itself: there can be tens of thousands.
func (s *Server) storeRunAlerts(job *analysisJob, alerts []*wazuh.Alert) {
	stored := 0
	if s.m.pg != nil {
		ctx, done := context.WithTimeout(context.Background(), 2*time.Minute)
		defer done()
		var e error
		if stored, e = s.m.pg.SaveRunAlerts(ctx, job.view.ID, alerts); e != nil {
			log.Printf("[siem-analysis] alert record: %v", e)
		}
	}
	job.update(func(v *analysisView) { v.AlertsStored = stored })
	s.persistAnalysis(job)
}

// A stored run still marked active whose job is no longer in memory was cut
// short (server restart, expiry): it is shown as stopped.
func settledRunState(r *db.AnalysisRun) {
	if r.State != "collecting" && r.State != "extracting" && r.State != "judging" {
		return
	}
	analyses.Lock()
	_, running := analyses.jobs[r.ID]
	analyses.Unlock()
	if !running {
		r.State = "stopped"
	}
}

func (s *Server) siemHistoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/defensive/analysis-runs", s.listAnalysisRuns)
	mux.HandleFunc("GET /api/defensive/analysis-runs/{runID}", s.getAnalysisRun)
	mux.HandleFunc("GET /api/defensive/analysis-runs/{runID}/alerts", s.listRunAlerts)
	mux.HandleFunc("GET /api/defensive/judgements", s.listJudgements)
	mux.HandleFunc("GET /api/defensive/judgements/{judgementID}", s.getJudgement)
}

func historyError(w http.ResponseWriter, e error) {
	if errors.Is(e, db.ErrHistoryNotFound) {
		writeErr(w, 404, e.Error())
		return
	}
	writeErr(w, 500, "분석 이력을 읽지 못했습니다")
}

func (s *Server) listAnalysisRuns(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	runs, e := pg.ListAnalysisRuns(r.Context(), 200)
	if e != nil {
		historyError(w, e)
		return
	}
	for _, run := range runs {
		settledRunState(run)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"runs": runs})
}

// getAnalysisRun returns one run with its detail and the judgments made in it.
func (s *Server) getAnalysisRun(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	run, e := pg.GetAnalysisRun(r.Context(), r.PathValue("runID"))
	if e != nil {
		historyError(w, e)
		return
	}
	settledRunState(run)
	judgements, e := pg.ListJudgements(r.Context(), run.ID, 1000)
	if e != nil {
		historyError(w, e)
		return
	}
	// The latest recorded judgment of each case of this connection, whichever
	// run or screen made it: a case judged outside this run still shows what
	// the model read.
	all, e := pg.ListSourceJudgements(r.Context(), run.SourceID, 5000)
	if e != nil {
		historyError(w, e)
		return
	}
	latest := map[string]*db.Judgement{}
	for _, j := range all { // newest first
		if latest[j.CaseKey] == nil {
			latest[j.CaseKey] = j
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"run": run, "judgements": judgements, "latest": latest})
}

// listRunAlerts pages through the alerts a run collected.
// ?rule= ?host= ?q= narrow them; ?offset= ?limit= page them.
func (s *Server) listRunAlerts(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 100)
	if limit < 1 || limit > 500 {
		limit = 100
	}
	offset := max(atoiDefault(q.Get("offset"), 0), 0)
	total, alerts, e := pg.ListRunAlerts(r.Context(), r.PathValue("runID"),
		db.RunAlertFilter{Rule: q.Get("rule"), Host: q.Get("host"), Query: strings.TrimSpace(q.Get("q"))}, offset, limit)
	if e != nil {
		historyError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"total": total, "alerts": alerts})
}

func (s *Server) listJudgements(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	judgements, e := pg.ListJudgements(r.Context(), "", 300)
	if e != nil {
		historyError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"judgements": judgements})
}

func (s *Server) getJudgement(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "judgementID")
	if !ok {
		writeErr(w, 400, "판정 번호를 확인해 주세요")
		return
	}
	j, e := pg.GetJudgement(r.Context(), id)
	if e != nil {
		historyError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, j)
}
