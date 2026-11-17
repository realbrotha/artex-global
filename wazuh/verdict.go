package wazuh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Case verdicts, following Thaki-Siem .claude/skills/siem-assess (section 5).
const (
	VerdictBreach        = "breach"         // 침해: evidence that an unauthorised action succeeded
	VerdictSuspicious    = "suspicious"     // 의심: possible, evidence incomplete
	VerdictAttempt       = "attempt"        // 시도: no evidence of success
	VerdictNormal        = "normal"         // 정상: matches confirmed or inferred operations
	VerdictFalsePositive = "false_positive" // 오탐: the rule misfired and the activity itself is normal
)

var verdictValues = map[string]bool{VerdictBreach: true, VerdictSuspicious: true, VerdictAttempt: true, VerdictNormal: true, VerdictFalsePositive: true}

// Verdict is the judged outcome of one case candidate.
type Verdict struct {
	Verdict  string   `json:"verdict"`
	Title    string   `json:"title"`
	Explain  string   `json:"explain"`
	Evidence []string `json:"evidence"`
	// Severity equals the code-computed severity unless Adjust gives a reason.
	Severity string   `json:"severity"`
	Adjust   string   `json:"adjust,omitempty"`
	Response []string `json:"response,omitempty"`
}

// ErrVerdictFormat: the model's answer did not satisfy the output rules.
var ErrVerdictFormat = errors.New("LLM 판정 응답이 형식 규칙을 충족하지 못했습니다")

// Completer sends one system + user prompt to the configured model and
// returns its text answer.
type Completer func(ctx context.Context, system, user string, maxTokens int) (string, error)

// The judging rules are condensed from the siem-assess skill, section 5.
const verdictSystemPrompt = `당신은 SIEM 사건 후보 1건을 판정하는 보안 분석가다. 입력 JSON 의 case 와 timeline 만 근거로 판정하고, JSON 객체 하나만 출력한다. 설명 문장, 코드 블록 표시는 출력하지 않는다.

## 판정 값 (verdict)
- breach: 비인가 행위가 성공한 증거가 있음
- suspicious: 가능성은 있으나 증거 부족
- attempt: 성공 증거 없는 시도
- normal: 업무·자동화와 일치가 확인되거나 추정됨
- false_positive: rule 이 잘못 걸렸고 행위 자체도 정상

## 판정 규칙
- 보수적 확정: 정상 근거가 없고 신호가 있으면 suspicious. 판정을 미루지 않는다.
- normal 은 근거가 있을 때만: 서비스·자동화 계정(서비스 계정, CI, 백업)의 일정 주기 반복, 같은 작업이 매일 같은 시각.
- false_positive 는 행위 자체도 정상일 때만. 허용 대역 밖, 업무 외 시간, 공용 자격증명, 반출 신호가 있으면 false_positive 금지.
- 행위자를 특정할 수 없다는 사실만으로 등급을 낮추지 않는다.
- P3(침해 연쇄)는 직전 로그인에 귀속한 추정이다. timeline 의 sudo 기록으로 행위자를 확인한 뒤 판정한다.

## 등급 (severity)
- case.severity 를 그대로 쓴다. normal, false_positive 판정이어도 등급을 내리지 않는다.
- 코드가 볼 수 없는 근거(반출 성공, 자격증명 노출, 업무 확인)가 있을 때만 바꾸고, 그 이유를 adjust 에 쉬운 말로 적는다. 바꾸지 않으면 adjust 는 빈 문자열.
- 값: Critical, High, Medium, Low, Info

## 제목 (title)
- 무엇이 왜 이상한지 명사형 한 줄, 8~40자. 순서: 시점·출처 신호 → 대상 → 행위.
- 판정 단어, 화살표(→), 마침표를 쓰지 않는다.
- 예: 주말 밤 허용 대역 밖 공용 계정 로그인 후 관리자 전환

## 설명 (explain)
- 보안 비전문가가 바로 이해하는 문장 1~3개, 20~220자.
- 첫 문장 = 사실(언제, 어디서, 누가, 무엇을, 몇 번). 둘째 문장 = 판단 이유.
- 건수·종류 수·기간은 말로 쓴다(11종을 7차례, 529번). 수량은 아라비아 숫자 + 단위.
- 용어 풀이: Secret → 비밀정보, kubernetes-admin 인증서 → 공용 K8s 관리자 인증서, sudo su - → 관리자 권한으로 전환, exec → Pod 접속.

## 제목·설명 금지
- IP 주소, rule 번호, 파일 경로, user= auid= 같은 필드=값, × 기호, CASE 번호. 계정명은 허용.
- 시각·요일·대역·계정 종류는 말로 쓴다(토요일 밤, 허용 대역 밖, 공용 관리자 인증서).

## 증거 (evidence)
- 판단에 쓴 데이터 원문. 문자열 배열, 1줄 = 행위 1개, 1줄 140자 이내, 비우지 않는다.
- 시각 있는 줄 먼저, 시각순: "MM-DD HH:MM <장비> <주체> (<출발지>) <행위> (rule <번호>)"
- 같은 장비·주체가 이어지면 둘째 줄부터 "같은 계정", "같은 토큰" 으로 줄인다.
- 시각 없는 집계 줄은 뒤에: "<무엇> N건 (rule <번호> N건)"
- 최대 12줄.

## 조치 (response)
- suspicious, breach, attempt 일 때 실행 가능한 조치 1~4개(예: 공용 관리자 인증서 폐기 후 개인 인증서 발급, 허용 대역 밖 출발지 차단, 노출된 비밀정보 교체). normal, false_positive 는 빈 배열.

## 출력 형식
{"verdict":"...","title":"...","explain":"...","evidence":["..."],"severity":"...","adjust":"","response":["..."]}`

var patternMeaning = map[string]string{
	"P1": "실패 반복 후 로그인 성공", "P2": "허용 대역 밖·최초 출발지·root 직접 로그인", "P3": "로그인 → 권한 변경 → 침해 행위 연쇄",
	"P4": "방어 무력화 후 민감정보 접근·흔적 삭제", "P5": "민감정보 접근 후 반출 도구 실행", "P6": "한 계정에 대한 다수 출발지 인증 실패",
	"P7": "외부 출발지의 탐색·웹 공격", "P8": "오류 급증 또는 sshd·sudo 비정상 종료", "P9": "고위험 탐지 rule 단건",
}

var weekdayKO = []string{"일", "월", "화", "수", "목", "금", "토"}

func kstWithWeekday(c Case, first bool) string {
	t := c.Last
	if first {
		t = c.First
	}
	k := t.In(KST)
	return fmt.Sprintf("%s (%s)", k.Format("01-02 15:04"), weekdayKO[k.Weekday()])
}

// VerdictPrompt builds the user message for one case. near holds the cases
// listed in c.Near (close in time), for context only.
func VerdictPrompt(c Case, near []Case) string {
	type nearView struct {
		Criterion string `json:"criterion"`
		Title     string `json:"title"`
		Actor     string `json:"actor"`
		Summary   string `json:"summary"`
		First     string `json:"first"`
		Last      string `json:"last"`
	}
	type eventView struct {
		T      string `json:"t"`
		Host   string `json:"host"`
		Rule   string `json:"rule"`
		Level  int    `json:"level"`
		Actor  string `json:"actor"`
		Src    string `json:"src"`
		Object string `json:"object,omitempty"`
		Desc   string `json:"desc"`
	}
	in := struct {
		Case struct {
			Criterion      string     `json:"criterion"`
			CriterionTitle string     `json:"criterion_title"`
			Pattern        string     `json:"pattern"`
			PatternMeaning string     `json:"pattern_meaning"`
			Severity       string     `json:"severity"`
			SevBasis       string     `json:"sev_basis"`
			Actor          string     `json:"actor"`
			Hosts          []string   `json:"hosts"`
			Entity         string     `json:"entity"`
			Summary        string     `json:"summary"`
			First          string     `json:"first"`
			Last           string     `json:"last"`
			Alerts         int        `json:"alerts"`
			Attack         []string   `json:"attack"`
			Near           []nearView `json:"near_cases"`
		} `json:"case"`
		TimelineNote string      `json:"timeline_note"`
		Timeline     []eventView `json:"timeline"`
	}{}
	in.Case.Criterion, in.Case.CriterionTitle, in.Case.Pattern, in.Case.PatternMeaning = c.Criterion, c.Title, c.Pattern, patternMeaning[c.Pattern]
	in.Case.Severity, in.Case.SevBasis, in.Case.Actor, in.Case.Hosts = c.Severity, c.SevBasis, c.Actor, c.Hosts
	in.Case.Entity, in.Case.Summary = clip(c.Entity, 600), c.Summary
	in.Case.First, in.Case.Last, in.Case.Alerts, in.Case.Attack = kstWithWeekday(c, true), kstWithWeekday(c, false), c.N, c.Attack
	in.Case.Near = []nearView{}
	for _, n := range near {
		in.Case.Near = append(in.Case.Near, nearView{n.Criterion, n.Title, n.Actor, clip(n.Summary, 200), kstWithWeekday(n, true), kstWithWeekday(n, false)})
	}
	in.TimelineNote = "시각은 KST. 전체 경보"
	if len(c.Timeline) < c.N {
		in.TimelineNote = fmt.Sprintf("시각은 KST. 전체 %d건 중 처음·마지막 %d건", c.N, len(c.Timeline))
	}
	in.Timeline = []eventView{}
	for _, e := range c.Timeline {
		k := e.T.In(KST)
		in.Timeline = append(in.Timeline, eventView{fmt.Sprintf("%s (%s)", k.Format("01-02 15:04"), weekdayKO[k.Weekday()]),
			e.Host, e.Rule, e.Level, e.Actor, e.Src, clip(e.Object, 200), clip(e.Desc, 200)})
	}
	raw, _ := json.Marshal(in)
	return string(raw)
}

// Text the title and explanation must not contain: they are read by people
// who are not looking at raw data; the raw data belongs in evidence.
var proseBans = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`), "IP 주소"},
	{regexp.MustCompile(`(?i)rule\s*=?\s*\d{3,}`), "rule 번호"},
	{regexp.MustCompile(`(^|[\s(])/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]*`), "파일 경로"},
	{regexp.MustCompile(`(?i)\b(user|auid|src|host|actor|uid)=`), "필드=값"},
	{regexp.MustCompile(`×`), "× 기호"},
	{regexp.MustCompile(`CASE-\d+`), "CASE 번호"},
}

func proseProblems(label, text string) []string {
	var out []string
	for _, b := range proseBans {
		if b.re.MatchString(text) {
			out = append(out, label+" 에 "+b.what+" 포함")
		}
	}
	return out
}

var verdictWords = regexp.MustCompile(`침해|의심|시도|정상|오탐`)

// ValidateVerdict checks an answer against the output rules and returns
// every violation (empty when it is acceptable).
func ValidateVerdict(v Verdict, c Case) []string {
	var problems []string
	if !verdictValues[v.Verdict] {
		problems = append(problems, "verdict 는 breach, suspicious, attempt, normal, false_positive 중 하나")
	}
	if n := utf8.RuneCountInString(v.Title); n < 8 || n > 40 {
		problems = append(problems, fmt.Sprintf("title 은 8~40자 (현재 %d자)", n))
	}
	if strings.Contains(v.Title, "→") || strings.HasSuffix(strings.TrimSpace(v.Title), ".") || verdictWords.MatchString(v.Title) {
		problems = append(problems, "title 에 판정 단어·화살표·마침표 금지")
	}
	problems = append(problems, proseProblems("title", v.Title)...)
	if n := utf8.RuneCountInString(v.Explain); n < 20 || n > 220 {
		problems = append(problems, fmt.Sprintf("explain 은 20~220자 (현재 %d자)", n))
	}
	problems = append(problems, proseProblems("explain", v.Explain)...)
	if len(v.Evidence) == 0 || len(v.Evidence) > 12 {
		problems = append(problems, "evidence 는 1~12줄")
	}
	for i, line := range v.Evidence {
		if n := utf8.RuneCountInString(line); n == 0 || n > 140 {
			problems = append(problems, fmt.Sprintf("evidence %d번째 줄은 1~140자 (현재 %d자)", i+1, n))
		}
	}
	if sevIndex(v.Severity) >= len(severities) {
		problems = append(problems, "severity 는 Critical, High, Medium, Low, Info 중 하나")
	} else if v.Severity != c.Severity && strings.TrimSpace(v.Adjust) == "" {
		problems = append(problems, fmt.Sprintf("severity 를 %s 에서 바꾸려면 adjust 에 이유 필요", c.Severity))
	}
	if len(v.Response) > 4 {
		problems = append(problems, "response 는 4개 이하")
	}
	return problems
}

// ParseVerdict extracts the JSON object from a model answer.
func ParseVerdict(text string) (Verdict, error) {
	var v Verdict
	start, end := strings.Index(text, "{"), strings.LastIndex(text, "}")
	if start < 0 || end <= start || len(text) > 64<<10 {
		return v, fmt.Errorf("%w: JSON 객체가 없습니다", ErrVerdictFormat)
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &v); err != nil {
		return v, fmt.Errorf("%w: JSON 을 해석하지 못했습니다", ErrVerdictFormat)
	}
	v.Title, v.Explain, v.Adjust = strings.TrimSpace(v.Title), strings.TrimSpace(v.Explain), strings.TrimSpace(v.Adjust)
	lines := []string{}
	for _, l := range v.Evidence {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	v.Evidence = lines
	if v.Response == nil {
		v.Response = []string{}
	}
	return v, nil
}

// verdictAttempts bounds one judgment: the first answer plus two corrections.
const (
	verdictAttempts  = 3
	verdictMaxTokens = 4000
)

// JudgeCase asks the model for a verdict on one case. An answer that breaks
// the output rules is sent back with the violations listed; when every
// attempt fails the result is an error, never a stored malformed verdict.
func JudgeCase(ctx context.Context, complete Completer, c Case, near []Case) (Verdict, error) {
	user := VerdictPrompt(c, near)
	var problems []string
	for attempt := 0; attempt < verdictAttempts; attempt++ {
		prompt := user
		if attempt > 0 {
			prompt += "\n\n직전 응답은 아래 규칙을 어겼다. 모두 고쳐서 JSON 객체 하나만 다시 출력한다.\n- " + strings.Join(problems, "\n- ")
		}
		text, err := complete(ctx, verdictSystemPrompt, prompt, verdictMaxTokens)
		if err != nil {
			return Verdict{}, err
		}
		v, err := ParseVerdict(text)
		if err != nil {
			problems = []string{"JSON 객체 하나만 출력"}
			continue
		}
		if problems = ValidateVerdict(v, c); len(problems) == 0 {
			return v, nil
		}
	}
	return Verdict{}, fmt.Errorf("%w: %s", ErrVerdictFormat, strings.Join(problems, "; "))
}
