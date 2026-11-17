package wazuh

import (
	"strings"
	"testing"
	"time"
)

func TestNearMissesAreRecorded(t *testing.T) {
	base := time.Date(2026, 11, 10, 1, 0, 0, 0, time.UTC)
	var watch []NearMiss
	in := CaseInput{Watch: &watch}
	// 4 of the 5 failures the burst rule needs.
	in.watch(NearMiss{Pattern: "P1", Kind: WatchNear, Subject: "src=a user=root", Count: 4, Threshold: p1Fails, Last: base})
	// 2 of 5: under the floor, not recorded.
	in.watch(NearMiss{Pattern: "P1", Kind: WatchNear, Subject: "src=b user=root", Count: 2, Threshold: p1Fails, Last: base})
	// A slow repeat is recorded whatever its share of the threshold.
	in.watch(NearMiss{Pattern: "P1", Kind: WatchSlow, Subject: "src=c user=root", Count: 12, Threshold: p1Fails, Last: base})
	in.watch(NearMiss{Pattern: "P1", Kind: WatchNear, Subject: "src=a user=root", Count: 3, Threshold: p1Fails, Last: base})
	got := SortNearMisses(watch)
	if len(got) != 2 || got[0].Kind != WatchSlow || got[1].Count != 4 {
		t.Fatalf("near misses = %+v", got)
	}
	// Without a sink nothing is recorded and nothing breaks.
	CaseInput{}.watch(NearMiss{Count: 4, Threshold: 5})
}

func TestBuildCasesReportsNearMisses(t *testing.T) {
	var watch []NearMiss
	in := fixtureInput(t)
	in.Watch = &watch
	plain := BuildCases(fixtureInput(t))
	if got := BuildCases(in); len(got) != len(plain) {
		t.Fatalf("watching changed the cases: %d vs %d", len(got), len(plain))
	}
	for _, n := range watch {
		if n.Threshold <= 0 || n.Note == "" || n.Pattern == "" {
			t.Errorf("incomplete near miss: %+v", n)
		}
		if n.Kind == WatchNear && n.Count >= n.Threshold {
			t.Errorf("a near miss at or over its threshold should have been a case: %+v", n)
		}
	}
}

func TestUnmatchedRules(t *testing.T) {
	alerts := []*Alert{
		{RuleID: "100", Desc: "in a case", Level: 5, Host: "a"},
		{RuleID: "200", Desc: "low", Level: 3, Host: "a"},
		{RuleID: "200", Desc: "low", Level: 3, Host: "b"},
		{RuleID: "300", Desc: "high", Level: 12, Host: "a"},
	}
	cases := []Case{{Timeline: []CaseEvent{{Rule: "100"}}}}
	got := UnmatchedRules(alerts, cases, 10)
	if len(got) != 2 || got[0].ID != "300" || got[1].ID != "200" || got[1].Count != 2 || got[1].Hosts != 2 {
		t.Fatalf("unmatched = %+v", got)
	}
}

func TestGapReviewPromptAndProposals(t *testing.T) {
	_, user := GapReviewPrompt(map[string]string{"EV-A": "기준 A"}, []RuleCount{{ID: "300", Desc: "high", Count: 3}},
		[]NearMiss{{Pattern: "P1", Kind: WatchNear, Note: "실패 4회"}}, []TrendBrief{{Title: "새 취약점", Summary: "요약"}})
	for _, want := range []string{`"EV-A"`, `"300"`, "실패 4회", "새 취약점"} {
		if !strings.Contains(user, want) {
			t.Errorf("prompt lacks %s", want)
		}
	}
	got, err := ParseProposals(`설명 [{"kind":"criterion","title":"새 기준","why":"이유","how":"방법","source":"300"},
		{"kind":"remove","title":"기준 삭제","why":"x"},{"kind":"watch","title":"","why":"x"}] 끝`)
	if err != nil || len(got) != 1 || got[0].Title != "새 기준" {
		t.Fatalf("proposals = %+v err=%v", got, err)
	}
	// An answer cut off mid-item keeps the items that are whole.
	cut, err := ParseProposals(`[{"kind":"watch","title":"온전한 항목","why":"이유"},{"kind":"criterion","title":"잘린 항`)
	if err != nil || len(cut) != 1 || cut[0].Title != "온전한 항목" {
		t.Fatalf("cut answer: %+v err=%v", cut, err)
	}
	if _, err = ParseProposals("없음"); err == nil {
		t.Error("an answer without an array must be an error")
	}
	if len(Thresholds()) < 6 {
		t.Error("the threshold ledger is incomplete")
	}
}
