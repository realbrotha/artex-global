package wazuh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// How a verdict was reached.
const (
	MethodHuman    = "human"    // set by a person; outranks any model verdict
	MethodSingle   = "single"   // one analyst pass
	MethodDebate   = "debate"   // two opposing reviews and an arbiter
	MethodFallback = "fallback" // nothing produced a valid answer: confirmed conservatively
)

// Judging roles, attached to the context of each model call so a recorder
// can say which voice a request belonged to.
const (
	RoleAnalyst = "analyst"
	RoleThreat  = "threat"
	RoleBenign  = "benign"
	RoleArbiter = "arbiter"
)

type roleKey struct{}

// WithRole marks a model call with the judging role that makes it.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleKey{}, role)
}

// RoleFrom returns the judging role of a model call, "" when unmarked.
func RoleFrom(ctx context.Context) string {
	role, _ := ctx.Value(roleKey{}).(string)
	return role
}

const debateMaxTokens = 1200

const threatSystemPrompt = `당신은 SIEM 사건 후보를 공격자 관점에서 검토하는 위협 분석가다. 입력 JSON 의 case 와 timeline 만 근거로, 이 활동이 비인가 행위이거나 침해로 이어졌을 수 있는 이유를 가장 강하게 주장한다.
- timeline 의 구체적 줄(시각, 장비, 계정, 행위)을 근거로 든다. timeline 에 없는 사실을 지어내지 않는다.
- 근거가 약한 부분은 약하다고 인정한다.
- 마지막 줄에 "주장 판정: breach|suspicious|attempt" 중 하나를 적는다.
- 600자 이내 평문. JSON, 코드 블록은 쓰지 않는다.`

const benignSystemPrompt = `당신은 SIEM 사건 후보를 운영자 관점에서 검토하는 시스템 운영 분석가다. 입력 JSON 의 case 와 timeline 만 근거로, 이 활동이 정상 업무·자동화이거나 rule 이 잘못 걸린 것일 수 있는 이유를 가장 강하게 주장한다.
- timeline 의 구체적 줄(시각, 장비, 계정, 행위)을 근거로 든다. timeline 에 없는 사실을 지어내지 않는다.
- 정상으로 설명되지 않는 부분은 설명되지 않는다고 인정한다.
- 마지막 줄에 "주장 판정: normal|false_positive|attempt" 중 하나를 적는다.
- 600자 이내 평문. JSON, 코드 블록은 쓰지 않는다.`

const arbiterAddendum = `

## 중재
- 입력 끝에 1차 판정과 두 검토 의견(위협 관점, 정상 관점)이 붙어 있다. 두 의견은 일부러 한쪽으로 치우쳐 쓴 것이다.
- 각 의견이 timeline 의 사실과 맞는지 직접 대조하고, 사실로 뒷받침되는 쪽을 따른다. 어느 쪽도 뒷받침되지 않으면 보수적 확정 규칙을 적용한다.
- 최종 판정을 하나로 확정한다. confidence 는 중재 후의 확신도를 적는다.`

// Escalate reports whether a first verdict should go to a debate, and why.
// A case is debated when the analyst was unsure, or when a Critical or High
// case was dismissed as normal or a false positive: a wrong dismissal there
// costs the most, so it gets a second look.
func Escalate(v Verdict, c Case) (bool, string) {
	if v.Confidence == "low" {
		return true, "1차 판정의 확신도가 낮음"
	}
	if (c.Severity == "Critical" || c.Severity == "High") && (v.Verdict == VerdictNormal || v.Verdict == VerdictFalsePositive) {
		return true, "등급 " + c.Severity + " 사건을 " + v.Verdict + " 로 판정함"
	}
	return false, ""
}

// AutoResult is the outcome of an automatic judgment.
type AutoResult struct {
	Verdict Verdict
	// Why the case went to a debate or a fallback; "" for a plain single pass.
	Reason string
}

// JudgeCaseAuto judges one case to a conclusion without a person. One
// analyst pass first; if that pass is unsure, dismisses a severe case, or
// cannot produce a valid answer, two opposing reviewers argue the case and
// an arbiter decides. If the arbiter cannot produce a valid answer either,
// the case is confirmed conservatively as suspicious. With debate false the
// analyst's answer stands, and a format failure still falls back.
//
// The only error returned is a failed model call (network, quota, timeout):
// that is not a judgment, and the case stays unjudged for the next run.
func JudgeCaseAuto(ctx context.Context, complete Completer, c Case, near []Case, precedents []Precedent, debate bool) (AutoResult, error) {
	first, err := judgeCase(WithRole(ctx, RoleAnalyst), complete, c, near, precedents)
	formatFailed := errors.Is(err, ErrVerdictFormat)
	if err != nil && !formatFailed {
		return AutoResult{}, err
	}
	reason := ""
	if formatFailed {
		reason = "1차 판정이 형식 규칙을 충족하지 못함"
	} else {
		var escalate bool
		if escalate, reason = Escalate(first, c); !escalate || !debate {
			first.Method = MethodSingle
			return AutoResult{Verdict: first}, nil
		}
	}
	if !debate {
		return AutoResult{Verdict: fallbackVerdict(c, reason), Reason: reason}, nil
	}

	prompt := VerdictPromptWith(c, near, precedents)
	threat, err := complete(WithRole(ctx, RoleThreat), threatSystemPrompt, prompt, debateMaxTokens)
	if err != nil {
		return AutoResult{}, err
	}
	benign, err := complete(WithRole(ctx, RoleBenign), benignSystemPrompt, prompt, debateMaxTokens)
	if err != nil {
		return AutoResult{}, err
	}
	brief := strings.Builder{}
	brief.WriteString(prompt)
	brief.WriteString("\n\n## 1차 판정\n")
	if formatFailed {
		brief.WriteString("형식 규칙을 충족한 답이 없었다.")
	} else {
		fmt.Fprintf(&brief, "%s (confidence %s): %s", first.Verdict, first.Confidence, first.Explain)
	}
	brief.WriteString("\n\n## 위협 관점 의견\n" + clip(strings.TrimSpace(threat), 1500))
	brief.WriteString("\n\n## 정상 관점 의견\n" + clip(strings.TrimSpace(benign), 1500))

	final, err := arbitrate(WithRole(ctx, RoleArbiter), complete, c, brief.String())
	if errors.Is(err, ErrVerdictFormat) {
		return AutoResult{Verdict: fallbackVerdict(c, reason+"; 중재도 형식 규칙을 충족하지 못함"), Reason: reason}, nil
	}
	if err != nil {
		return AutoResult{}, err
	}
	final.Method = MethodDebate
	return AutoResult{Verdict: final, Reason: reason}, nil
}

// arbitrate asks for the final verdict over the debate brief, with the same
// output rules and correction loop as a first verdict.
func arbitrate(ctx context.Context, complete Completer, c Case, brief string) (Verdict, error) {
	var problems []string
	for attempt := 0; attempt < verdictAttempts; attempt++ {
		prompt := brief
		if attempt > 0 {
			prompt += "\n\n직전 응답은 아래 규칙을 어겼다. 모두 고쳐서 JSON 객체 하나만 다시 출력한다.\n- " + strings.Join(problems, "\n- ")
		}
		text, err := complete(ctx, verdictSystemPrompt+arbiterAddendum, prompt, verdictMaxTokens)
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

// fallbackVerdict closes a case no model answer could: suspicious, at the
// computed severity, with the first alerts as evidence. Conservative on
// purpose: an unexplained case must stay visible, not disappear as normal.
func fallbackVerdict(c Case, reason string) Verdict {
	title := c.Title
	if title == "" {
		title = c.Criterion
	}
	if utf8.RuneCountInString(title) > 40 {
		title = string([]rune(title)[:40])
	}
	evidence := []string{}
	for _, e := range c.Timeline {
		if len(evidence) == 6 {
			break
		}
		k := e.T.In(KST)
		evidence = append(evidence, clip(fmt.Sprintf("%s %s %s %s (rule %s)", k.Format("01-02 15:04"), e.Host, e.Actor, e.Desc, e.Rule), 140))
	}
	if len(evidence) == 0 {
		evidence = append(evidence, clip(c.Summary, 140))
	}
	return Verdict{
		Verdict:    VerdictSuspicious,
		Title:      title,
		Explain:    "자동 판정이 결론을 내지 못해 보수적으로 의심으로 확정했다. 사람이 경보 타임라인을 직접 확인해야 한다.",
		Evidence:   evidence,
		Severity:   c.Severity,
		Response:   []string{"경보 타임라인을 직접 확인해 판정을 정정"},
		Confidence: "low",
		Method:     MethodFallback,
		Adjust:     "",
	}
}
