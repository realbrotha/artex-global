package wazuh

import "testing"

func TestSummarizeFeedback(t *testing.T) {
	verdicts := []FeedbackVerdict{}
	for _, actor := range []string{"a", "b", "c", "d"} {
		verdicts = append(verdicts, FeedbackVerdict{CaseKey: "EV-FP|" + actor, Verdict: VerdictFalsePositive})
	}
	verdicts = append(verdicts,
		FeedbackVerdict{CaseKey: "EV-FP|e", Verdict: VerdictSuspicious},
		FeedbackVerdict{CaseKey: "EV-OK|x", Verdict: VerdictSuspicious},
	)
	judgements := []FeedbackJudgement{
		{CaseKey: "EV-OK|backup", Verdict: VerdictNormal, Method: MethodSingle},
		{CaseKey: "EV-OK|backup", Verdict: VerdictNormal, Method: MethodSingle},
		{CaseKey: "EV-OK|backup", Verdict: VerdictNormal, Method: MethodDebate},
		{CaseKey: "EV-HARD|z", Verdict: VerdictSuspicious, Method: MethodDebate},
		{CaseKey: "EV-HARD|z", Verdict: VerdictSuspicious, Method: MethodFallback},
		{CaseKey: "EV-HARD|y", Verdict: VerdictNormal, Method: MethodSingle},
	}
	corrections := []FeedbackCorrection{
		{CaseKey: "EV-OK|x", From: VerdictSuspicious, To: VerdictNormal},
		{CaseKey: "EV-OK|w", From: VerdictBreach, To: VerdictAttempt},
	}
	rows, signals := SummarizeFeedback(verdicts, judgements, corrections, map[string]string{"EV-FP": "잦은 오탐 기준"})

	if rows[0].Criterion != "EV-FP" || rows[0].Cases != 5 || rows[0].Verdicts[VerdictFalsePositive] != 4 || rows[0].Title != "잦은 오탐 기준" {
		t.Fatalf("first row = %+v", rows[0])
	}
	kinds := map[string]FeedbackSignal{}
	for _, s := range signals {
		kinds[s.Kind] = s
	}
	if s := kinds[SignalFalsePositive]; s.Criterion != "EV-FP" || s.Count != 4 || s.Of != 5 {
		t.Errorf("false positive signal = %+v", s)
	}
	if s := kinds[SignalNormalRepeat]; s.CaseKey != "EV-OK|backup" || s.Count != 3 {
		t.Errorf("normal repeat signal = %+v", s)
	}
	if s := kinds[SignalUnstable]; s.Criterion != "EV-HARD" || s.Count != 2 || s.Of != 3 {
		t.Errorf("unstable signal = %+v", s)
	}
	if s := kinds[SignalCorrected]; s.Criterion != "EV-OK" || s.Count != 2 {
		t.Errorf("corrected signal = %+v", s)
	}
	// People overruling the model is listed first.
	if signals[0].Kind != SignalCorrected {
		t.Errorf("signal order = %+v", signals)
	}
}

func TestSummarizeFeedbackBelowThresholds(t *testing.T) {
	verdicts := []FeedbackVerdict{
		{CaseKey: "EV-A|a", Verdict: VerdictFalsePositive},
		{CaseKey: "EV-A|b", Verdict: VerdictFalsePositive},
	}
	judgements := []FeedbackJudgement{{CaseKey: "EV-A|a", Verdict: VerdictNormal}, {CaseKey: "EV-A|a", Verdict: VerdictNormal}}
	if _, signals := SummarizeFeedback(verdicts, judgements, nil, nil); len(signals) != 0 {
		t.Errorf("too few cases must not signal: %+v", signals)
	}
}
