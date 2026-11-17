package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/wazuh"
)

const (
	// Outside knowledge is fetched again after this long.
	knowledgeMaxAge = 30 * 24 * time.Hour
	siemChecklist   = "checklist"
	siemGolden      = "golden-last"
	gapMaxTokens    = 8000
)

// ---- background re-verification ----

type reviewPick struct {
	index  int
	rank   int
	reason string
	judged time.Time
}

// reviewJob re-reads some of the run's stored verdicts: those reached the
// hard way first (fallback, debate, low certainty), then those a newer human
// precedent may overturn, then the longest unchecked. A person's verdict is
// never re-read.
func (s *Server) reviewJob(job *analysisJob, sched wazuh.Schedule) {
	if sched.ReviewLimit <= 0 || s.m.pg == nil {
		return
	}
	complete, model, msg := s.judgeBackend(sched)
	if msg != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(sched.ReviewLimit)*2*caseJudgeTimeout)
	defer cancel()
	ctx = llmrec.WithWorker(ctx, "siem-judge")

	last, e := s.m.pg.LastReviewed(ctx, job.source)
	if e != nil {
		log.Printf("[siem-review] last reviews: %v", e)
		return
	}
	corrections, e := s.m.pg.ListCorrections(ctx, job.source, 500)
	if e != nil {
		log.Printf("[siem-review] corrections: %v", e)
		return
	}
	newest := map[string]time.Time{} // criterion -> latest correction
	for _, c := range corrections {
		if c.CreatedAt.After(newest[c.Criterion]) {
			newest[c.Criterion] = c.CreatedAt
		}
	}

	job.mu.Lock()
	picks := []reviewPick{}
	for i, c := range job.view.Cases {
		v := c.Verdict
		if c.Known != "" || v == nil || v.Stale || v.Method == wazuh.MethodHuman || c.Judge == "done" {
			continue
		}
		if at, ok := last[db.CaseKey(c.Case)]; ok && time.Since(at) < time.Duration(sched.ReviewEveryDays)*24*time.Hour {
			continue
		}
		p := reviewPick{index: i, rank: 3, reason: "오래 재검증하지 않은 판정", judged: v.JudgedAt}
		switch {
		case newest[c.Criterion].After(v.JudgedAt):
			p.rank, p.reason = 0, "판정 뒤에 같은 탐지 기준의 사람 판례가 생김"
		case v.Method == wazuh.MethodFallback:
			p.rank, p.reason = 0, "보수적 확정으로 끝난 판정"
		case v.Method == wazuh.MethodDebate:
			p.rank, p.reason = 1, "토론으로 확정한 판정"
		case v.Confidence == "low" || v.Confidence == "medium":
			p.rank, p.reason = 2, "확신도 "+v.Confidence+" 판정"
		}
		picks = append(picks, p)
	}
	raw, runID, label := job.raw, job.view.ID, job.view.Label
	job.mu.Unlock()
	sort.Slice(picks, func(i, j int) bool {
		if picks[i].rank != picks[j].rank {
			return picks[i].rank < picks[j].rank
		}
		return picks[i].judged.Before(picks[j].judged)
	})
	if len(picks) > sched.ReviewLimit {
		picks = picks[:sched.ReviewLimit]
	}
	if len(picks) == 0 {
		return
	}
	log.Printf("[siem-review] %q: re-reading %d verdict(s)", label, len(picks))
	changed := 0
	for _, p := range picks {
		if ctx.Err() != nil {
			break
		}
		job.mu.Lock()
		view := job.view.Cases[p.index]
		job.mu.Unlock()
		c, near := findCase(raw, view.ID)
		if c == nil {
			continue
		}
		started := time.Now()
		record := db.Judgement{SourceID: job.source, RunID: runID, Case: *c, Model: model}
		one, done := context.WithTimeout(ctx, 2*caseJudgeTimeout)
		result, e := wazuh.JudgeCaseReview(one, recordingCompleter(complete, &record.System, &record.Attempts), *c,
			s.judgeOptions(one, job.source, *c, near, sched, ""), view.Verdict.Verdict)
		done()
		if e != nil {
			log.Printf("[siem-review] %q %s: %v", label, db.CaseKey(*c), e)
			continue
		}
		record.Reason = "재검증: " + p.reason
		if result.Reason != "" {
			record.Reason += " · " + result.Reason
		}
		addResearch(&record, result.AutoResult)
		review := db.Review{RunID: runID, CaseKey: db.CaseKey(*c), Title: view.Verdict.Title, Prev: view.Verdict.Verdict.Verdict,
			New: result.Verdict.Verdict, Agreed: result.Agreed, Changed: result.Changed, PickReason: p.reason, Reason: result.Reason}
		if result.Changed {
			stored, se := s.m.pg.SaveCaseVerdict(ctx, job.source, *c, result.Verdict, model)
			if se != nil {
				log.Printf("[siem-review] save verdict: %v", se)
				continue
			}
			changed++
			record.Verdict = &result.Verdict
			job.update(func(v *analysisView) { v.Cases[p.index].Verdict = &caseVerdictView{CaseVerdict: stored} })
		} else {
			kept := view.Verdict.Verdict
			record.Verdict = &kept
		}
		record.Ms = time.Since(started).Milliseconds()
		s.saveJudgement(ctx, record)
		if se := s.m.pg.SaveReview(ctx, job.source, review); se != nil {
			log.Printf("[siem-review] record: %v", se)
		}
		job.update(func(v *analysisView) { v.Reviewed++; v.ReviewChanged = changed })
		s.persistAnalysis(job)
	}
	log.Printf("[siem-review] %q: %d re-read, %d changed", label, len(picks), changed)
}

// ---- outside knowledge ----

var (
	attackID     = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	attackDesc   = regexp.MustCompile(`(?s)<div class="description-body">(.*?)</div>`)
	attackTitle  = regexp.MustCompile(`(?s)<title>(.*?)</title>`)
	htmlTag      = regexp.MustCompile(`<[^>]+>`)
	knowledgeWeb = &http.Client{Timeout: 15 * time.Second}
	knowledgeMu  sync.Mutex
)

// attackKnowledge returns the description of an ATT&CK technique, from the
// cache or attack.mitre.org. The request carries the technique id and
// nothing else.
func (s *Server) attackKnowledge(ctx context.Context, id string) *db.Knowledge {
	if !attackID.MatchString(id) {
		return nil
	}
	key := "attack:" + id
	if k, e := s.m.pg.GetKnowledge(ctx, key); e == nil && k != nil && time.Since(k.FetchedAt) < knowledgeMaxAge {
		return k
	}
	knowledgeMu.Lock()
	defer knowledgeMu.Unlock()
	url := "https://attack.mitre.org/techniques/" + strings.Replace(id, ".", "/", 1) + "/"
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return nil
	}
	req.Header.Set("User-Agent", "siem-console")
	res, e := knowledgeWeb.Do(req)
	if e != nil {
		log.Printf("[siem-research] %s: %v", id, e)
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if e != nil {
		return nil
	}
	text := func(re *regexp.Regexp) string {
		m := re.FindSubmatch(raw)
		if m == nil {
			return ""
		}
		return strings.Join(strings.Fields(html.UnescapeString(htmlTag.ReplaceAllString(string(m[1]), " "))), " ")
	}
	k := db.Knowledge{Key: key, Title: text(attackTitle), Body: text(attackDesc), URL: url}
	if k.Body == "" {
		return nil
	}
	if len(k.Body) > 1500 {
		k.Body = strings.ToValidUTF8(k.Body[:1500], "")
	}
	if e = s.m.pg.SaveKnowledge(ctx, k); e != nil {
		log.Printf("[siem-research] cache: %v", e)
	}
	return &k
}

// researchCase looks up outside knowledge for a case the analyst was unsure
// of: the ATT&CK techniques the case is tagged with, and the collected
// threat trends that mention them or the criterion's subject. Only technique
// ids leave this server; the trend search runs on local data.
func (s *Server) researchCase(ctx context.Context, c wazuh.Case) (string, string) {
	ids := []string{}
	for _, a := range c.Attack {
		if a = strings.TrimSpace(a); attackID.MatchString(a) && len(ids) < 3 {
			ids = append(ids, a)
		}
	}
	notes := strings.Builder{}
	for _, id := range ids {
		if k := s.attackKnowledge(ctx, id); k != nil {
			fmt.Fprintf(&notes, "[MITRE ATT&CK %s] %s\n%s\n(%s)\n\n", id, k.Title, k.Body, k.URL)
		}
	}
	// Words of the criterion title, to find collected trend reports on the
	// same subject. The title is a detection rule's name, not case data.
	words := []string{}
	for _, w := range strings.FieldsFunc(c.Title, func(r rune) bool { return strings.ContainsRune(" ·,()/[]:-", r) }) {
		if len([]rune(w)) >= 3 && len(words) < 4 {
			words = append(words, strings.ToLower(w))
		}
	}
	if trends, _, e := s.m.pg.ListHuntTrends(ctx); e == nil {
		found := 0
		for _, t := range trends {
			text := strings.ToLower(t.Title + " " + t.Summary)
			hit := false
			for _, w := range append(append([]string{}, words...), ids...) {
				if strings.Contains(text, strings.ToLower(w)) {
					hit = true
					break
				}
			}
			if hit && found < 3 {
				found++
				fmt.Fprintf(&notes, "[수집된 위협 동향] %s\n%s\n\n", t.Title, t.Summary)
			}
		}
	}
	query := "ATT&CK: " + strings.Join(ids, ", ")
	if len(ids) == 0 {
		query = "ATT&CK: 없음"
	}
	if len(words) > 0 {
		query += " · 수집된 동향 검색어: " + strings.Join(words, ", ")
	}
	return query, strings.TrimSpace(notes.String())
}

// ---- detection gap review ----

// gapReview asks, once a day per connection, what the detection criteria
// may be missing, from the run's unmatched rules, near misses and the
// collected threat trends. Suggestions are stored for a person to decide.
func (s *Server) gapReview(job *analysisJob, sched wazuh.Schedule) {
	if !sched.GapReview || s.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), caseJudgeTimeout)
	defer cancel()
	key := "gap-last-" + strconv.FormatInt(job.source, 10)
	today := time.Now().Format("2006-01-02")
	settings, e := s.m.pg.GetSiemSettings(ctx)
	if e != nil || settings[key] == today {
		return
	}
	complete, _, msg := s.judgeBackend(sched)
	if msg != "" {
		return
	}
	job.mu.Lock()
	criteria := map[string]string{}
	for _, c := range job.raw {
		criteria[c.Criterion] = c.Title
	}
	unmatched := append([]wazuh.RuleCount{}, job.view.Unmatched...)
	near := append([]wazuh.NearMiss{}, job.view.NearMisses...)
	label := job.view.Label
	job.mu.Unlock()
	if len(unmatched) > 20 {
		unmatched = unmatched[:20]
	}
	if len(near) > 15 {
		near = near[:15]
	}
	briefs := []wazuh.TrendBrief{}
	if trends, _, e := s.m.pg.ListHuntTrends(ctx); e == nil {
		sort.Slice(trends, func(i, j int) bool { return trends[i].PublishedAt.After(trends[j].PublishedAt) })
		for _, t := range trends {
			if len(briefs) == 15 {
				break
			}
			briefs = append(briefs, wazuh.TrendBrief{Title: t.Title, Summary: t.Summary, Kind: t.Kind})
		}
	}
	system, user := wazuh.GapReviewPrompt(criteria, unmatched, near, briefs)
	text, e := complete(llmrec.WithWorker(ctx, "siem-gap"), system, user, gapMaxTokens)
	note := ""
	if e != nil {
		note = "탐지 공백 검토 실패"
		log.Printf("[siem-gap] %q: %v", label, e)
	} else if proposals, pe := wazuh.ParseProposals(text); pe != nil {
		note = "탐지 공백 검토 응답을 해석하지 못함"
		log.Printf("[siem-gap] %q: %v (answer %d chars)", label, pe, len(text))
	} else {
		added, se := s.m.pg.SaveProposals(ctx, job.source, proposals)
		if se != nil {
			log.Printf("[siem-gap] save: %v", se)
		}
		note = fmt.Sprintf("탐지 공백 검토: 제안 %d건 (새로 %d건)", len(proposals), added)
		log.Printf("[siem-gap] %q: %d proposal(s), %d new", label, len(proposals), added)
		_ = s.m.pg.SetSiemSettings(ctx, map[string]string{key: today})
	}
	job.update(func(v *analysisView) { v.GapNote = note })
	s.persistAnalysis(job)
}

// ---- answer set replay ----

type goldenItem struct {
	CaseKey  string `json:"case_key"`
	Title    string `json:"title"`
	Expected string `json:"expected"`
	Got      string `json:"got"`
	Method   string `json:"method"`
	Error    string `json:"error,omitempty"`
}

type goldenResult struct {
	At      time.Time    `json:"at"`
	Model   string       `json:"model"`
	Running bool         `json:"running"`
	Total   int          `json:"total"`
	Correct int          `json:"correct"`
	Items   []goldenItem `json:"items"`
}

var goldenBusy sync.Mutex

// runGolden replays the judging against the cases people corrected: each is
// judged again without its own correction as a precedent, and the answer is
// compared with what the person decided.
func (s *Server) runGolden(sourceID int64) {
	if !goldenBusy.TryLock() {
		return
	}
	defer goldenBusy.Unlock()
	sched, se := s.siemSchedule(context.Background())
	if se != nil {
		sched = wazuh.DefaultSchedule()
	}
	complete, model, msg := s.judgeBackend(sched)
	ready := msg == ""
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	ctx = llmrec.WithWorker(ctx, "siem-golden")
	key := siemGolden + "-" + strconv.FormatInt(sourceID, 10)
	save := func(r goldenResult) {
		raw, _ := json.Marshal(r)
		if e := s.m.pg.SetSiemSettings(context.Background(), map[string]string{key: string(raw)}); e != nil {
			log.Printf("[siem-golden] save: %v", e)
		}
	}
	out := goldenResult{At: time.Now(), Model: model, Running: true, Items: []goldenItem{}}
	cases, e := s.m.pg.GoldenCases(ctx, sourceID, 30)
	if e != nil || !ready {
		out.Running = false
		save(out)
		return
	}
	out.Total = len(cases)
	save(out)
	for _, g := range cases {
		item := goldenItem{CaseKey: g.CaseKey, Title: g.Case.Title, Expected: g.Expected}
		one, done := context.WithTimeout(ctx, 2*caseJudgeTimeout)
		result, je := wazuh.JudgeCaseAuto(one, complete, g.Case, s.judgeOptions(one, sourceID, g.Case, nil, sched, g.CaseKey))
		done()
		if je != nil {
			_, item.Error = judgeFailure(je)
		} else {
			item.Got, item.Method = result.Verdict.Verdict, result.Verdict.Method
			if item.Got == item.Expected {
				out.Correct++
			}
		}
		out.Items = append(out.Items, item)
		save(out)
	}
	out.Running = false
	save(out)
	log.Printf("[siem-golden] %d of %d match the human verdict", out.Correct, out.Total)
}

// ---- API ----

func (s *Server) siemQualityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/defensive/quality", s.getQuality)
	mux.HandleFunc("PUT /api/defensive/quality/checklist", s.putChecklist)
	mux.HandleFunc("POST /api/defensive/quality/proposals/{proposalID}", s.decideProposal)
	mux.HandleFunc("POST /api/defensive/quality/golden/{sourceID}", s.startGolden)
}

// loadChecklist applies the stored checklist, if a person edited it.
func (s *Server) loadChecklist(ctx context.Context) {
	if s.m.pg == nil {
		return
	}
	settings, e := s.m.pg.GetSiemSettings(ctx)
	if e != nil || settings[siemChecklist] == "" {
		return
	}
	var items map[string][]wazuh.Check
	if json.Unmarshal([]byte(settings[siemChecklist]), &items) == nil && wazuh.ValidateChecklist(items) == nil {
		wazuh.SetChecklist(items)
	}
}

func (s *Server) getQuality(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ctx := r.Context()
	sources, e := pg.ListWazuhSources(ctx)
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	settings, e := pg.GetSiemSettings(ctx)
	if e != nil {
		writeErr(w, 500, "설정을 읽지 못했습니다")
		return
	}
	sched, _ := s.siemSchedule(ctx)
	type entry struct {
		ID        string              `json:"id"`
		Name      string              `json:"name"`
		Weeks     []db.QualityWeek    `json:"weeks"`
		Reviews   []db.Review         `json:"reviews"`
		Watch     []db.WatchItem      `json:"watch"`
		Proposals []db.StoredProposal `json:"proposals"`
		Unmatched []wazuh.RuleCount   `json:"unmatched"`
		Golden    *goldenResult       `json:"golden"`
		GoldenSet int                 `json:"golden_set"`
		// Judgments with a complete checklist answer, of those that have a verdict.
		Checked   int    `json:"checked"`
		Unchecked int    `json:"unchecked"`
		GapLast   string `json:"gap_last"`
	}
	out := []entry{}
	fail := func(what string, e error) bool {
		if e != nil {
			log.Printf("[siem-quality] %s: %v", what, e)
			writeErr(w, 500, "탐지 품질 정보를 읽지 못했습니다")
			return true
		}
		return false
	}
	for _, source := range sources {
		if !source.Enabled {
			continue
		}
		en := entry{ID: strconv.FormatInt(source.ID, 10), Name: source.Name, Unmatched: []wazuh.RuleCount{}}
		if en.Weeks, e = pg.QualityWeeks(ctx, source.ID, 8); fail("weeks", e) {
			return
		}
		if en.Reviews, e = pg.ListReviews(ctx, source.ID, 100); fail("reviews", e) {
			return
		}
		if en.Watch, e = pg.ListWatch(ctx, source.ID, 100); fail("watch", e) {
			return
		}
		if en.Proposals, e = pg.ListProposals(ctx, source.ID); fail("proposals", e) {
			return
		}
		golden, e := pg.GoldenCases(ctx, source.ID, 30)
		if fail("golden", e) {
			return
		}
		en.GoldenSet = len(golden)
		if raw := settings[siemGolden+"-"+en.ID]; raw != "" {
			g := goldenResult{}
			if json.Unmarshal([]byte(raw), &g) == nil {
				en.Golden = &g
			}
		}
		en.GapLast = settings["gap-last-"+en.ID]
		if e = pg.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE jsonb_array_length(COALESCE(verdict->'checks','[]'::jsonb)) > 0),
			count(*) FILTER (WHERE jsonb_array_length(COALESCE(verdict->'checks','[]'::jsonb)) = 0)
			FROM siem_judgements WHERE source_id=$1 AND verdict IS NOT NULL`, source.ID).Scan(&en.Checked, &en.Unchecked); fail("checks", e) {
			return
		}
		// The newest scheduled run's unmatched rules.
		runs, e := pg.ListAnalysisRuns(ctx, 50)
		if fail("runs", e) {
			return
		}
		for _, run := range runs {
			if run.SourceID != source.ID {
				continue
			}
			full, e := pg.GetAnalysisRun(ctx, run.ID)
			if e != nil {
				continue
			}
			var detail struct {
				Trigger   string            `json:"trigger"`
				Unmatched []wazuh.RuleCount `json:"unmatched"`
			}
			if json.Unmarshal(full.Detail, &detail) == nil && detail.Trigger == "schedule" && detail.Unmatched != nil {
				en.Unmatched = detail.Unmatched
				break
			}
		}
		out = append(out, en)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"sources": out, "thresholds": wazuh.Thresholds(), "checklist": wazuh.Checklist(),
		"checklist_default": wazuh.DefaultChecklist(), "checklist_edited": settings[siemChecklist] != "",
		"schedule": sched, "review_every_days": sched.ReviewEveryDays,
	})
}

func (s *Server) putChecklist(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in struct {
		// nil restores the built-in checklist.
		Checklist map[string][]wazuh.Check `json:"checklist"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 1<<18) {
		return
	}
	value := ""
	if in.Checklist != nil {
		if e := wazuh.ValidateChecklist(in.Checklist); e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		raw, _ := json.Marshal(in.Checklist)
		value = string(raw)
	}
	if e := pg.SetSiemSettings(r.Context(), map[string]string{siemChecklist: value}); e != nil {
		writeErr(w, 500, "검사 목록을 저장하지 못했습니다")
		return
	}
	wazuh.SetChecklist(in.Checklist)
	writeJSON(w, 200, map[string]any{"checklist": wazuh.Checklist(), "checklist_edited": value != ""})
}

func (s *Server) decideProposal(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "proposalID")
	var in struct {
		Status string `json:"status"`
	}
	if !ok || !decodePurpleRequestLimit(w, r, &in, 1<<10) {
		if !ok {
			writeErr(w, 400, "제안 번호를 확인해 주세요")
		}
		return
	}
	if in.Status != "open" && in.Status != "accepted" && in.Status != "dismissed" {
		writeErr(w, 400, "상태는 open, accepted, dismissed 중 하나")
		return
	}
	if e := pg.DecideProposal(r.Context(), id, in.Status); e != nil {
		historyError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) startGolden(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	id, ok := pathInt(r, "sourceID")
	if !ok || id <= 0 {
		writeErr(w, 400, "연결 ID를 확인해 주세요")
		return
	}
	go s.runGolden(id)
	writeJSON(w, 200, map[string]any{"started": true})
}
