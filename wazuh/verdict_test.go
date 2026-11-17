package wazuh

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func judgedCase(t *testing.T) (Case, []Case) {
	t.Helper()
	cases := BuildCases(fixtureInput(t))
	byID := map[string]Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	c := cases[2] // P4 on app-02, near the P5 case
	if c.Pattern != "P4" || len(c.Near) != 1 {
		t.Fatalf("fixture case = %s %v", c.Pattern, c.Near)
	}
	return c, []Case{byID[c.Near[0]]}
}

const goodVerdict = `{"verdict":"suspicious","title":"업무 시간 중 감사 기능 중지 후 계정 정보 열람",
"explain":"같은 사용자가 감사 기능을 2번 멈춘 뒤 20분 안에 계정 비밀번호 파일을 읽고 명령 기록을 지웠다. 작업 요청과 일치하는 근거가 없어 운영 작업으로 설명되지 않는다.",
"evidence":["11-13 10:00 app-02 auid=1001 감사 데몬 중지 (rule 200003)","11-13 10:10 같은 계정 /etc/shadow 읽기 (rule 200005)"],
"severity":"High","adjust":"","response":["감사 데몬 재기동","해당 계정 비밀번호 교체"]}`

func TestVerdictPromptCarriesCaseAndTimeline(t *testing.T) {
	c, near := judgedCase(t)
	var doc map[string]any
	if err := json.Unmarshal([]byte(VerdictPrompt(c, near)), &doc); err != nil {
		t.Fatal(err)
	}
	cs := doc["case"].(map[string]any)
	if cs["criterion"] != "EV-CORR-04" || cs["pattern_meaning"] == "" || cs["severity"] != "High" || cs["alerts"].(float64) != 4 {
		t.Fatalf("case = %v", cs)
	}
	if n := cs["near_cases"].([]any); len(n) != 1 || n[0].(map[string]any)["criterion"] != "EV-CORR-05" {
		t.Fatalf("near = %v", n)
	}
	tl := doc["timeline"].([]any)
	first := tl[0].(map[string]any)
	// 2026-11-13 01:00 UTC = 10:00 KST, a Friday
	if len(tl) != 4 || first["t"] != "11-13 10:00 (금)" || first["rule"] != "200003" {
		t.Fatalf("timeline = %v", tl)
	}
}

func TestJudgeCaseAcceptsValidAnswer(t *testing.T) {
	c, near := judgedCase(t)
	calls := 0
	v, err := JudgeCase(context.Background(), func(_ context.Context, system, user string, _ int) (string, error) {
		calls++
		if !strings.Contains(system, "보수적 확정") || !strings.Contains(user, `"criterion":"EV-CORR-04"`) {
			t.Fatalf("prompt missing rules or case")
		}
		return "```json\n" + goodVerdict + "\n```", nil
	}, c, near)
	if err != nil || calls != 1 || v.Verdict != VerdictSuspicious || len(v.Evidence) != 2 || len(v.Response) != 2 {
		t.Fatalf("verdict = %+v, %v (calls %d)", v, err, calls)
	}
}

func TestJudgeCaseRetriesThenFails(t *testing.T) {
	c, near := judgedCase(t)
	bad := strings.Replace(goodVerdict, "업무 시간 중 감사 기능 중지 후 계정 정보 열람", "10.7.1.5 에서 rule 200003 의심 →", 1)
	var prompts []string
	answers := []string{bad, goodVerdict}
	v, err := JudgeCase(context.Background(), func(_ context.Context, _, user string, _ int) (string, error) {
		prompts = append(prompts, user)
		return answers[len(prompts)-1], nil
	}, c, near)
	if err != nil || v.Verdict != VerdictSuspicious || len(prompts) != 2 {
		t.Fatalf("retry: %+v, %v, calls %d", v, err, len(prompts))
	}
	for _, want := range []string{"title 에 IP 주소 포함", "title 에 rule 번호 포함", "title 에 판정 단어·화살표·마침표 금지"} {
		if !strings.Contains(prompts[1], want) {
			t.Errorf("retry prompt lacks %q", want)
		}
	}
	// two bad answers: an error, never a stored malformed verdict
	if _, err = JudgeCase(context.Background(), func(context.Context, string, string, int) (string, error) { return bad, nil }, c, near); !errors.Is(err, ErrVerdictFormat) {
		t.Fatalf("err = %v, want ErrVerdictFormat", err)
	}
	if _, err = JudgeCase(context.Background(), func(context.Context, string, string, int) (string, error) { return "모르겠습니다", nil }, c, near); !errors.Is(err, ErrVerdictFormat) {
		t.Fatalf("non-JSON: err = %v", err)
	}
	boom := errors.New("provider down")
	if _, err = JudgeCase(context.Background(), func(context.Context, string, string, int) (string, error) { return "", boom }, c, near); !errors.Is(err, boom) {
		t.Fatalf("provider error not passed through: %v", err)
	}
}

func TestValidateVerdictRules(t *testing.T) {
	c, _ := judgedCase(t)
	base, err := ParseVerdict(goodVerdict)
	if err != nil {
		t.Fatal(err)
	}
	if p := ValidateVerdict(base, c); len(p) != 0 {
		t.Fatalf("good verdict rejected: %v", p)
	}
	cases := map[string]func(v *Verdict){
		"verdict":           func(v *Verdict) { v.Verdict = "의심" },
		"title 은 8~40자":     func(v *Verdict) { v.Title = "짧음" },
		"explain 은 20~220자": func(v *Verdict) { v.Explain = "짧다." },
		"explain 에 파일 경로":   func(v *Verdict) { v.Explain += " 대상은 /etc/shadow 였다." },
		"explain 에 필드=값":    func(v *Verdict) { v.Explain += " user=root 로 실행했다." },
		"evidence 는 1~12줄":  func(v *Verdict) { v.Evidence = nil },
		"1~140자":            func(v *Verdict) { v.Evidence = []string{strings.Repeat("가", 141)} },
		"adjust 에 이유 필요":    func(v *Verdict) { v.Severity = "Critical" },
		"severity 는":        func(v *Verdict) { v.Severity = "Severe" },
		"response 는 4개 이하":  func(v *Verdict) { v.Response = []string{"a", "b", "c", "d", "e"} },
	}
	for want, mutate := range cases {
		v := base
		v.Evidence = append([]string(nil), base.Evidence...)
		mutate(&v)
		found := false
		for _, p := range ValidateVerdict(v, c) {
			found = found || strings.Contains(p, want)
		}
		if !found {
			t.Errorf("%s: not reported (%v)", want, ValidateVerdict(v, c))
		}
	}
	adjusted := base
	adjusted.Severity, adjusted.Adjust = "Critical", "반출 성공 흔적"
	if p := ValidateVerdict(adjusted, c); len(p) != 0 {
		t.Fatalf("adjusted severity with reason rejected: %v", p)
	}
}
