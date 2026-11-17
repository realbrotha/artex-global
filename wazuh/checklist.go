package wazuh

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// Check is one question a verdict must answer before it is accepted. The
// model answers every check of the case's pattern; an answer that skips one
// is sent back.
type Check struct {
	ID       string `json:"id"`
	Question string `json:"question"`
}

// CheckAnswer is the model's answer to one check.
type CheckAnswer struct {
	ID string `json:"id"`
	// yes, no or unknown.
	Answer string `json:"answer"`
	// The timeline line or fact the answer rests on.
	Basis string `json:"basis"`
}

// ChecklistAll is the key of the checks every pattern must answer.
const ChecklistAll = "*"

var checkAnswers = map[string]bool{"yes": true, "no": true, "unknown": true}

// DefaultChecklist is the built-in checklist: checks for every pattern under
// ChecklistAll, then per pattern.
func DefaultChecklist() map[string][]Check {
	return map[string][]Check{
		ChecklistAll: {
			{"actor", "행위자(계정·출발지)를 특정할 수 있는가"},
			{"business", "업무·자동화로 설명되는 근거가 timeline 에 있는가"},
			{"success", "행위가 실제로 성공한 증거가 있는가"},
		},
		"P1": {{"after_login", "로그인 성공 뒤에 권한 상승이나 민감 행위가 이어졌는가"}},
		"P2": {{"source_seen", "이 출발지·계정 조합이 이전에도 정상적으로 쓰인 흔적이 있는가"}},
		"P3": {{"same_actor", "연쇄의 각 단계가 같은 행위자의 것으로 확인되는가"}},
		"P4": {{"restored", "무력화된 방어 기능이 다시 켜졌는가"}},
		"P5": {{"external_dest", "반출 대상이 외부(관리 대역 밖)인가"}},
		"P6": {{"any_success", "실패가 이어진 뒤 성공한 로그인이 있는가"}},
		"P7": {{"served", "공격성 요청에 성공 응답이 돌아간 흔적이 있는가"}},
		"P8": {{"change", "급증 시점에 배포·장애 같은 운영 변화가 보이는가"}},
		"P9": {{"periodic", "같은 행위가 일정한 주기로 반복되는가"}},
	}
}

var checklist = struct {
	sync.RWMutex
	items map[string][]Check
}{items: DefaultChecklist()}

// SetChecklist replaces the checklist in use; nil restores the default.
func SetChecklist(items map[string][]Check) {
	if items == nil {
		items = DefaultChecklist()
	}
	checklist.Lock()
	checklist.items = items
	checklist.Unlock()
}

// Checklist returns the checklist in use.
func Checklist() map[string][]Check {
	checklist.RLock()
	defer checklist.RUnlock()
	out := make(map[string][]Check, len(checklist.items))
	for k, v := range checklist.items {
		out[k] = append([]Check{}, v...)
	}
	return out
}

// ValidateChecklist checks a checklist a person edited.
func ValidateChecklist(items map[string][]Check) error {
	for pattern, list := range items {
		if pattern != ChecklistAll && patternMeaning[pattern] == "" {
			return fmt.Errorf("알 수 없는 패턴 %q", pattern)
		}
		if len(list) > 12 {
			return fmt.Errorf("%s: 검사는 12개 이하", pattern)
		}
		seen := map[string]bool{}
		for _, c := range list {
			id := strings.TrimSpace(c.ID)
			if id == "" || len(id) > 40 || strings.ContainsAny(id, " \t\"{}") || seen[id] {
				return fmt.Errorf("%s: 검사 ID %q 는 공백 없는 40자 이내, 중복 없이", pattern, c.ID)
			}
			seen[id] = true
			if n := utf8.RuneCountInString(strings.TrimSpace(c.Question)); n < 5 || n > 200 {
				return fmt.Errorf("%s/%s: 질문은 5~200자", pattern, id)
			}
		}
	}
	return nil
}

// ChecksFor returns the checks a case of this pattern must answer.
func ChecksFor(pattern string) []Check {
	checklist.RLock()
	defer checklist.RUnlock()
	out := append([]Check{}, checklist.items[ChecklistAll]...)
	seen := map[string]bool{}
	for _, c := range out {
		seen[c.ID] = true
	}
	for _, c := range checklist.items[pattern] {
		if !seen[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

// checkProblems lists the required checks a verdict did not answer properly.
func checkProblems(v Verdict, c Case) []string {
	answers := map[string]CheckAnswer{}
	for _, a := range v.Checks {
		answers[a.ID] = a
	}
	var problems []string
	for _, need := range ChecksFor(c.Pattern) {
		a, ok := answers[need.ID]
		switch {
		case !ok:
			problems = append(problems, "checks 에 "+need.ID+" 항목 누락")
		case !checkAnswers[a.Answer]:
			problems = append(problems, "checks."+need.ID+".answer 는 yes, no, unknown 중 하나")
		case strings.TrimSpace(a.Basis) == "" || utf8.RuneCountInString(a.Basis) > 200:
			problems = append(problems, "checks."+need.ID+".basis 는 1~200자")
		}
	}
	return problems
}

// CaseFacts are the facts the code can establish about a case, handed to the
// model so it does not have to work them out (or skip them).
func CaseFacts(c Case) map[string]string {
	first, last := c.First.In(KST), c.Last.In(KST)
	workHours := func(h int, wd int) bool { return wd >= 1 && wd <= 5 && h >= 9 && h < 18 }
	srcs, rules, actors := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range c.Timeline {
		if e.Src != "" && e.Src != "-" {
			srcs[e.Src] = true
		}
		rules[e.Rule] = true
		if e.Actor != "" && e.Actor != "-" {
			actors[e.Actor] = true
		}
	}
	yesNo := func(b bool) string {
		if b {
			return "예"
		}
		return "아니오"
	}
	list := func(m map[string]bool) string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 8 {
			keys = append(keys[:8], fmt.Sprintf("외 %d", len(keys)-8))
		}
		return strings.Join(keys, ", ")
	}
	return map[string]string{
		"첫 경보가 평일 업무 시간(09~18시)인가":   yesNo(workHours(first.Hour(), int(first.Weekday()))),
		"마지막 경보가 평일 업무 시간(09~18시)인가": yesNo(workHours(last.Hour(), int(last.Weekday()))),
		"활동 기간":                last.Sub(first).Round(60 * 1e9).String(),
		"경보 수":                 fmt.Sprint(c.N),
		"장비 수":                 fmt.Sprint(len(c.Hosts)),
		"timeline 의 출발지 수":     fmt.Sprint(len(srcs)),
		"timeline 의 행위자":       list(actors),
		"timeline 의 rule 종류 수": fmt.Sprint(len(rules)),
	}
}
