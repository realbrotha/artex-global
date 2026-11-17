package wazuh

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func autoCase(sev string) Case {
	t := time.Date(2026, 11, 10, 1, 0, 0, 0, time.UTC)
	return Case{ID: "CASE-1", Pattern: "P2", Severity: sev, Criterion: "EV-TEST", Title: "허용 대역 밖 로그인", Actor: "root",
		Hosts: []string{"web01"}, First: t, Last: t, N: 1, Summary: "로그인 성공 1건",
		Timeline: []CaseEvent{{T: t, Host: "web01", Rule: "5715", Level: 3, Actor: "root", Src: "203.0.113.5", Desc: "sshd: authentication success"}}}
}

const p2Checks = `[{"id":"actor","answer":"yes","basis":"root 계정"},{"id":"business","answer":"no","basis":"근거 없음"},` +
	`{"id":"success","answer":"yes","basis":"로그인 성공"},{"id":"source_seen","answer":"unknown","basis":"이전 기록 없음"}]`

func answer(verdict, confidence, sev string) string {
	return `{"verdict":"` + verdict + `","title":"새벽 허용 대역 밖 root 직접 로그인","explain":"새벽 1시에 허용 대역 밖에서 root 로 바로 로그인했다. 업무 근거가 없다.",` +
		`"evidence":["11-10 10:00 web01 root 로그인 성공 (rule 5715)"],"severity":"` + sev + `","adjust":"","response":[],"confidence":"` + confidence + `","checks":` + p2Checks + `}`
}

// scripted answers by role, in order; records the roles it was called with.
type scripted struct {
	answers map[string][]string
	calls   []string
}

func (s *scripted) complete(ctx context.Context, _, _ string, _ int) (string, error) {
	role := RoleFrom(ctx)
	s.calls = append(s.calls, role)
	list := s.answers[role]
	if len(list) == 0 {
		return "", errors.New("no answer for " + role)
	}
	s.answers[role] = list[1:]
	return list[0], nil
}

func TestJudgeCaseAutoSingleWhenConfident(t *testing.T) {
	s := &scripted{answers: map[string][]string{RoleAnalyst: {answer("suspicious", "high", "Medium")}}}
	r, err := JudgeCaseAuto(context.Background(), s.complete, autoCase("Medium"), JudgeOptions{Debate: true})
	if err != nil || r.Verdict.Method != MethodSingle || r.Verdict.Verdict != "suspicious" || len(s.calls) != 1 {
		t.Fatalf("result=%+v err=%v calls=%v", r, err, s.calls)
	}
}

func TestJudgeCaseAutoDebatesUnsureAnswer(t *testing.T) {
	s := &scripted{answers: map[string][]string{
		RoleAnalyst: {answer("suspicious", "low", "Medium")},
		RoleThreat:  {"공격 근거\n주장 판정: suspicious"},
		RoleBenign:  {"정상 근거\n주장 판정: normal"},
		RoleArbiter: {answer("normal", "medium", "Medium")},
	}}
	r, err := JudgeCaseAuto(context.Background(), s.complete, autoCase("Medium"), JudgeOptions{Debate: true})
	if err != nil || r.Verdict.Method != MethodDebate || r.Verdict.Verdict != "normal" || r.Reason == "" {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	if strings.Join(s.calls, ",") != "analyst,threat,benign,arbiter" {
		t.Errorf("calls = %v", s.calls)
	}
}

func TestJudgeCaseAutoDebatesDismissedSevereCase(t *testing.T) {
	s := &scripted{answers: map[string][]string{
		RoleAnalyst: {answer("normal", "high", "High")},
		RoleThreat:  {"주장 판정: suspicious"},
		RoleBenign:  {"주장 판정: normal"},
		RoleArbiter: {answer("suspicious", "high", "High")},
	}}
	r, err := JudgeCaseAuto(context.Background(), s.complete, autoCase("High"), JudgeOptions{Debate: true})
	if err != nil || r.Verdict.Method != MethodDebate || !strings.Contains(r.Reason, "High") {
		t.Fatalf("result=%+v err=%v", r, err)
	}
}

func TestJudgeCaseAutoFallsBackWhenNothingIsValid(t *testing.T) {
	bad := "형식 없는 답"
	s := &scripted{answers: map[string][]string{
		RoleAnalyst: {bad, bad, bad},
		RoleThreat:  {"주장 판정: suspicious"},
		RoleBenign:  {"주장 판정: normal"},
		RoleArbiter: {bad, bad, bad},
	}}
	r, err := JudgeCaseAuto(context.Background(), s.complete, autoCase("Low"), JudgeOptions{Debate: true})
	if err != nil || r.Verdict.Method != MethodFallback || r.Verdict.Verdict != VerdictSuspicious {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	// The fallback itself must satisfy the output rules.
	if problems := ValidateVerdict(r.Verdict, autoCase("Low")); len(problems) != 0 {
		t.Errorf("fallback breaks the rules: %v", problems)
	}
}

func TestJudgeCaseAutoWithoutDebate(t *testing.T) {
	s := &scripted{answers: map[string][]string{RoleAnalyst: {answer("suspicious", "low", "Medium")}}}
	r, err := JudgeCaseAuto(context.Background(), s.complete, autoCase("Medium"), JudgeOptions{})
	if err != nil || r.Verdict.Method != MethodSingle || len(s.calls) != 1 {
		t.Fatalf("result=%+v err=%v calls=%v", r, err, s.calls)
	}
}

func TestJudgeCaseAutoReturnsProviderFailure(t *testing.T) {
	s := &scripted{answers: map[string][]string{}}
	if _, err := JudgeCaseAuto(context.Background(), s.complete, autoCase("Medium"), JudgeOptions{Debate: true}); err == nil || errors.Is(err, ErrVerdictFormat) {
		t.Fatalf("a failed model call must be returned as an error, got %v", err)
	}
}

func TestScheduleInterval(t *testing.T) {
	s := DefaultSchedule()
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.Local)
	if !s.Due(nil, now) {
		t.Error("a schedule that never ran is due")
	}
	last := now.Add(-30 * time.Minute)
	if s.Due(&last, now) || !s.Next(&last, now).Equal(now.Add(30*time.Minute)) {
		t.Errorf("next = %v", s.Next(&last, now))
	}
	s.Enabled = false
	if s.Due(nil, now) || !s.Next(nil, now).IsZero() {
		t.Error("a disabled schedule never runs")
	}
}

func TestScheduleDaily(t *testing.T) {
	s := Schedule{Enabled: true, Mode: ScheduleDaily, Times: []string{"07:30", "18:00"}, Weekdays: []int{1, 2, 3, 4, 5}, JudgeLimit: 20, ReviewEveryDays: 7}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	// Tuesday 2026-11-17, 08:00: the 07:30 slot passed since the last run (Monday 18:00).
	now := time.Date(2026, 11, 17, 8, 0, 0, 0, time.Local)
	last := time.Date(2026, 11, 16, 18, 0, 0, 0, time.Local)
	if !s.Due(&last, now) {
		t.Error("the missed 07:30 slot is due")
	}
	ran := time.Date(2026, 11, 17, 7, 31, 0, 0, time.Local)
	if next := s.Next(&ran, now); !next.Equal(time.Date(2026, 11, 17, 18, 0, 0, 0, time.Local)) {
		t.Errorf("next = %v", next)
	}
	// Friday 18:01 after the 18:00 run: next is Monday 07:30.
	fri := time.Date(2026, 11, 20, 18, 1, 0, 0, time.Local)
	friRan := time.Date(2026, 11, 20, 18, 0, 30, 0, time.Local)
	if next := s.Next(&friRan, fri); !next.Equal(time.Date(2026, 11, 23, 7, 30, 0, 0, time.Local)) {
		t.Errorf("next after Friday = %v", next)
	}
}

func TestScheduleValidate(t *testing.T) {
	bad := []Schedule{
		{Mode: ScheduleInterval, IntervalMinutes: 1, JudgeLimit: 20},
		{Mode: ScheduleDaily, Times: []string{"25:00"}, JudgeLimit: 20},
		{Mode: ScheduleDaily, Times: []string{"07:30"}, Weekdays: []int{7}, JudgeLimit: 20},
		{Mode: "weekly", JudgeLimit: 20},
		{Mode: ScheduleInterval, IntervalMinutes: 60, JudgeLimit: 0},
		{Mode: ScheduleInterval, IntervalMinutes: 60, JudgeLimit: 20, ReviewEveryDays: 0},
	}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Errorf("%+v must be rejected", s)
		}
	}
}

func TestPrecedentsReachThePrompt(t *testing.T) {
	var got string
	complete := func(_ context.Context, _, user string, _ int) (string, error) {
		got = user
		return answer("normal", "high", "Medium"), nil
	}
	prec := []Precedent{{Actor: "backup", Summary: "야간 백업", From: "suspicious", Verdict: "normal", Reason: "매일 02시 백업 작업"}}
	if _, err := JudgeCaseAuto(context.Background(), complete, autoCase("Medium"), JudgeOptions{Precedents: prec, Debate: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"human_verdict":"normal"`) || !strings.Contains(got, "매일 02시 백업 작업") {
		t.Errorf("precedent missing from prompt: %s", got)
	}
	if !strings.Contains(VerdictPrompt(autoCase("Low"), nil), `"precedents":[]`) {
		t.Error("an empty precedent list must still be sent as []")
	}
}

func TestChecklistIsEnforced(t *testing.T) {
	c := autoCase("Medium")
	v, err := ParseVerdict(answer("suspicious", "high", "Medium"))
	if err != nil || len(ValidateVerdict(v, c)) != 0 {
		t.Fatalf("complete answer rejected: %v %v", err, ValidateVerdict(v, c))
	}
	v.Checks = v.Checks[:3] // drops the P2 check
	if p := ValidateVerdict(v, c); len(p) != 1 || !strings.Contains(p[0], "source_seen") {
		t.Errorf("missing check not reported: %v", p)
	}
	v.Checks = append(v.Checks, CheckAnswer{ID: "source_seen", Answer: "maybe", Basis: "x"})
	if p := ValidateVerdict(v, c); len(p) != 1 || !strings.Contains(p[0], "answer") {
		t.Errorf("bad answer not reported: %v", p)
	}
	prompt := VerdictPrompt(c, nil)
	if !strings.Contains(prompt, `"checks_required"`) || !strings.Contains(prompt, "source_seen") || !strings.Contains(prompt, `"facts"`) {
		t.Errorf("prompt lacks the checklist or facts: %s", prompt)
	}
	if err := ValidateChecklist(map[string][]Check{"P99": {{"x", "질문입니다 다섯자"}}}); err == nil {
		t.Error("an unknown pattern must be rejected")
	}
}

func TestJudgeCaseReview(t *testing.T) {
	c := autoCase("Medium")
	stored, _ := ParseVerdict(answer("suspicious", "high", "Medium"))

	// Second reading agrees: one call, verdict stands.
	s := &scripted{answers: map[string][]string{RoleAnalyst: {answer("suspicious", "medium", "Medium")}}}
	r, err := JudgeCaseReview(context.Background(), s.complete, c, JudgeOptions{Debate: true}, stored)
	if err != nil || !r.Agreed || r.Changed || len(s.calls) != 1 {
		t.Fatalf("agree: %+v err=%v calls=%v", r, err, s.calls)
	}

	// Second reading differs and the arbiter sides with it: verdict changes.
	researched := false
	s = &scripted{answers: map[string][]string{
		RoleAnalyst: {answer("normal", "high", "Medium")},
		RoleThreat:  {"주장 판정: suspicious"},
		RoleBenign:  {"주장 판정: normal"},
		RoleArbiter: {answer("normal", "high", "Medium")},
	}}
	o := JudgeOptions{Debate: true, Research: func(context.Context, Case) (string, string) {
		researched = true
		return "T1021", "원격 서비스 기법 설명"
	}}
	r, err = JudgeCaseReview(context.Background(), s.complete, c, o, stored)
	if err != nil || r.Agreed || !r.Changed || r.Verdict.Verdict != "normal" || !researched || r.ResearchQuery != "T1021" {
		t.Fatalf("change: %+v err=%v", r, err)
	}

	// The arbiter sides with the stored verdict: nothing changes.
	s = &scripted{answers: map[string][]string{
		RoleAnalyst: {answer("normal", "high", "Medium")},
		RoleThreat:  {"x"}, RoleBenign: {"y"},
		RoleArbiter: {answer("suspicious", "high", "Medium")},
	}}
	r, err = JudgeCaseReview(context.Background(), s.complete, c, JudgeOptions{Debate: true}, stored)
	if err != nil || !r.Agreed || r.Changed {
		t.Fatalf("uphold: %+v err=%v", r, err)
	}
}
