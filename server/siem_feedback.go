package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/wazuh"
)

// How far back the feedback summary reads model judgments.
const feedbackWindow = 90 * 24 * time.Hour

// correctCase sets a person's verdict on a case. It becomes the case's
// verdict (the automatic judging leaves it until new activity) and a
// precedent the model sees for other cases of the same criterion.
func (s *Server) correctCase(w http.ResponseWriter, r *http.Request) {
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
	var in struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 1<<16) {
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	switch in.Verdict {
	case wazuh.VerdictBreach, wazuh.VerdictSuspicious, wazuh.VerdictAttempt, wazuh.VerdictNormal, wazuh.VerdictFalsePositive:
	default:
		writeErr(w, 400, "판정 값을 확인해 주세요")
		return
	}
	if n := utf8.RuneCountInString(in.Reason); n < 5 || n > 500 {
		writeErr(w, 400, "정정 사유를 5~500자로 적어 주세요. 다음 판정에서 근거로 쓰입니다")
		return
	}
	set, e := pg.GetWazuhCases(r.Context(), id)
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	c, _ := findCase(set.Cases, caseID)
	if c == nil {
		writeErr(w, 404, "사건 후보를 찾을 수 없습니다. 목록을 새로고침해 주세요")
		return
	}
	verdicts, e := pg.CaseVerdicts(r.Context(), id)
	if e != nil {
		writeErr(w, 500, "사건 판정을 읽지 못했습니다")
		return
	}
	from := ""
	v := wazuh.Verdict{Verdict: in.Verdict, Title: c.Title, Explain: in.Reason, Severity: c.Severity,
		Confidence: "high", Method: wazuh.MethodHuman, Response: []string{}}
	if v.Title == "" {
		v.Title = c.Criterion
	}
	if old := verdicts[db.CaseKey(*c)]; old != nil {
		from = old.Verdict.Verdict
		v.Title, v.Evidence = old.Verdict.Title, old.Verdict.Evidence
	}
	if len(v.Evidence) == 0 {
		v.Evidence = []string{c.Summary}
	}
	stored, e := pg.SaveCorrection(r.Context(), id, *c, from, v, in.Reason)
	if e != nil {
		writeErr(w, 500, "정정을 저장하지 못했습니다")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, caseVerdictView{CaseVerdict: stored})
}

// getFeedback summarises, per connection, how each detection criterion has
// been judged, what people corrected, and the signals worth acting on.
func (s *Server) getFeedback(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	sources, e := pg.ListWazuhSources(r.Context())
	if e != nil {
		wazuhSourceError(w, e)
		return
	}
	type entry struct {
		ID          string                    `json:"id"`
		Name        string                    `json:"name"`
		Criteria    []wazuh.CriterionFeedback `json:"criteria"`
		Signals     []wazuh.FeedbackSignal    `json:"signals"`
		Corrections []db.Correction           `json:"corrections"`
		Methods     map[string]int            `json:"methods"`
	}
	out := []entry{}
	for _, source := range sources {
		if !source.Enabled {
			continue
		}
		verdicts, e := pg.CaseVerdicts(r.Context(), source.ID)
		if e != nil {
			writeErr(w, 500, "사건 판정을 읽지 못했습니다")
			return
		}
		judgements, e := pg.FeedbackJudgements(r.Context(), source.ID, time.Now().Add(-feedbackWindow))
		if e != nil {
			writeErr(w, 500, "판정 기록을 읽지 못했습니다")
			return
		}
		corrections, e := pg.ListCorrections(r.Context(), source.ID, 200)
		if e != nil {
			writeErr(w, 500, "정정 기록을 읽지 못했습니다")
			return
		}
		titles := map[string]string{}
		if set, e := pg.GetWazuhCases(r.Context(), source.ID); e == nil {
			for _, c := range set.Cases {
				if c.Title != "" {
					titles[c.Criterion] = c.Title
				}
			}
		}
		current := make([]wazuh.FeedbackVerdict, 0, len(verdicts))
		methods := map[string]int{}
		for key, v := range verdicts {
			current = append(current, wazuh.FeedbackVerdict{CaseKey: key, Verdict: v.Verdict.Verdict, Method: v.Method})
			method := v.Method
			if method == "" {
				method = wazuh.MethodSingle
			}
			methods[method]++
		}
		fixes := make([]wazuh.FeedbackCorrection, 0, len(corrections))
		for _, c := range corrections {
			fixes = append(fixes, wazuh.FeedbackCorrection{CaseKey: c.CaseKey, From: c.From, To: c.To})
		}
		criteria, signals := wazuh.SummarizeFeedback(current, judgements, fixes, titles)
		out = append(out, entry{ID: strconv.FormatInt(source.ID, 10), Name: source.Name, Criteria: criteria, Signals: signals,
			Corrections: corrections, Methods: methods})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"sources": out, "window_days": int(feedbackWindow.Hours() / 24)})
}
