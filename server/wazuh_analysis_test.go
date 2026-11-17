package server

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/wazuh"
)

func TestCleanHosts(t *testing.T) {
	got, ok := cleanHosts([]string{" web01 ", "db-01.example.com", "web01"})
	if !ok || !reflect.DeepEqual(got, []string{"db-01.example.com", "web01"}) {
		t.Fatalf("cleanHosts = %v, %v", got, ok)
	}
	if got, ok := cleanHosts(nil); !ok || len(got) != 0 {
		t.Fatalf("empty host list must mean every host: %v, %v", got, ok)
	}
	// Names go into an indexer query: anything but a plain host name is refused.
	for _, bad := range []string{"", "a b", `web"01`, "web01*", "web/01", "호스트"} {
		if _, ok := cleanHosts([]string{bad}); ok {
			t.Errorf("cleanHosts accepted %q", bad)
		}
	}
	if _, ok := cleanHosts(make([]string, analysisMaxHosts+1)); ok {
		t.Error("cleanHosts accepted more hosts than the limit")
	}
}

func TestAnalysisNeedsVerdict(t *testing.T) {
	row := func(known string, v *caseVerdictView) analysisCase {
		return analysisCase{caseView: caseView{Case: wazuh.Case{Known: known}, Verdict: v}}
	}
	current := &caseVerdictView{CaseVerdict: &db.CaseVerdict{}}
	stale := &caseVerdictView{CaseVerdict: &db.CaseVerdict{}, Stale: true}
	for name, tc := range map[string]struct {
		c    analysisCase
		want bool
	}{
		"never judged":   {row("", nil), true},
		"judged":         {row("", current), false},
		"stale verdict":  {row("", stale), true},
		"known activity": {row("백업 작업", nil), false},
	} {
		if got := needsVerdict(tc.c); got != tc.want {
			t.Errorf("%s: needsVerdict = %v, want %v", name, got, tc.want)
		}
	}
}

func TestAnalysisStoreEvictsOldJobs(t *testing.T) {
	analyses.Lock()
	saved := analyses.jobs
	analyses.jobs = map[string]*analysisJob{}
	analyses.Unlock()
	defer func() {
		analyses.Lock()
		analyses.jobs = saved
		analyses.Unlock()
	}()

	cancelled := map[string]bool{}
	job := func(id string, age time.Duration) *analysisJob {
		_, cancel := context.WithCancel(context.Background())
		return &analysisJob{created: time.Now().Add(-age), view: analysisView{ID: id}, cancel: func() {
			cancelled[id] = true
			cancel()
		}}
	}
	addAnalysis(job("expired", analysisKeep+time.Minute))
	for i := 0; i < analysisMaxJobs; i++ {
		addAnalysis(job(string(rune('a'+i)), time.Duration(analysisMaxJobs-i)*time.Second))
	}
	analyses.Lock()
	defer analyses.Unlock()
	if len(analyses.jobs) != analysisMaxJobs {
		t.Fatalf("store holds %d jobs, limit is %d", len(analyses.jobs), analysisMaxJobs)
	}
	if analyses.jobs["expired"] != nil || !cancelled["expired"] {
		t.Error("an expired job must be cancelled and dropped")
	}

	// Empty lists are serialised as [], which the client iterates.
	if raw, _ := json.Marshal(analyses.jobs["a"].snapshot()); !strings.Contains(string(raw), `"cases":[]`) || !strings.Contains(string(raw), `"hosts":[]`) {
		t.Errorf("empty snapshot = %s", raw)
	}

	// A snapshot must not share state with the job.
	j := analyses.jobs["b"]
	j.view.Cases = []analysisCase{{Judge: "pending"}}
	j.view.Patterns = map[string]int{"P1": 1}
	snap := j.snapshot()
	snap.Cases[0].Judge, snap.Patterns["P1"] = "done", 9
	if j.view.Cases[0].Judge != "pending" || j.view.Patterns["P1"] != 1 {
		t.Error("snapshot shares state with the job")
	}
}
