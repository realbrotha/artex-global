package wazuh

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtureInput(t *testing.T) CaseInput {
	t.Helper()
	var docs []map[string]any
	dec := json.NewDecoder(bytes.NewReader(readFixture(t, "alerts.json")))
	dec.UseNumber()
	if err := dec.Decode(&docs); err != nil {
		t.Fatal(err)
	}
	in := CaseInput{Today: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
	for _, d := range docs {
		a, err := ParseAlert(d)
		if err != nil {
			t.Fatal(err)
		}
		in.Alerts = append(in.Alerts, a)
	}
	var err error
	if in.Catalog, err = ParseEventCatalog(string(readFixture(t, "event-catalog.tsv"))); err != nil {
		t.Fatal(err)
	}
	if in.Criteria, err = ParseEventCriteria(string(readFixture(t, "event-criteria.tsv"))); err != nil {
		t.Fatal(err)
	}
	if in.Known, err = ParseKnownActivity(string(readFixture(t, "known-activity.tsv"))); err != nil {
		t.Fatal(err)
	}
	in.Admin = ParseAdminPrefixes(string(readFixture(t, "siem-admin-src")))
	var seen [][3]string
	if err = json.Unmarshal(readFixture(t, "seen.json"), &seen); err != nil {
		t.Fatal(err)
	}
	in.Seen = map[[3]string]bool{}
	for _, s := range seen {
		in.Seen[s] = true
	}
	var posture map[string][]string
	if err = json.Unmarshal(readFixture(t, "posture.json"), &posture); err != nil {
		t.Fatal(err)
	}
	in.Posture = map[string]map[string]bool{}
	for h, codes := range posture {
		in.Posture[h] = map[string]bool{}
		for _, c := range codes {
			in.Posture[h][c] = true
		}
	}
	return in
}

// goldenCase is the shape gen_golden.py writes from the original
// implementation's cases.tsv row and timeline.
type goldenCase struct {
	ID        string   `json:"id"`
	Pattern   string   `json:"pattern"`
	Score     int      `json:"score"`
	Entity    string   `json:"entity"`
	Hosts     []string `json:"hosts"`
	First     string   `json:"first"`
	Last      string   `json:"last"`
	N         int      `json:"n"`
	Attack    []string `json:"attack"`
	Summary   string   `json:"summary"`
	Known     string   `json:"known"`
	Near      []string `json:"near"`
	Severity  string   `json:"severity"`
	SevBasis  string   `json:"sev_basis"`
	Criterion string   `json:"criterion"`
	Actor     string   `json:"actor"`
	Timeline  [][]any  `json:"timeline"`
}

func toGolden(c Case) goldenCase {
	g := goldenCase{ID: c.ID, Pattern: c.Pattern, Score: c.Score, Entity: c.Entity, Hosts: c.Hosts, First: kstStamp(c.First),
		Last: kstStamp(c.Last), N: c.N, Attack: c.Attack, Summary: c.Summary, Known: c.Known, Near: c.Near, Severity: c.Severity,
		SevBasis: c.SevBasis, Criterion: c.Criterion, Actor: c.Actor, Timeline: [][]any{}}
	for _, e := range c.Timeline {
		g.Timeline = append(g.Timeline, []any{kstStamp(e.T), e.Host, e.Rule, float64(e.Level), e.Actor, e.Src, e.Object, e.Desc})
	}
	return g
}

// TestCasesMatchOriginal checks the port against the output of Thaki-Siem
// assess/events.py on the same fixture (testdata/gen_golden.py).
func TestCasesMatchOriginal(t *testing.T) {
	var want []goldenCase
	if err := json.Unmarshal(readFixture(t, "cases_golden.json"), &want); err != nil {
		t.Fatal(err)
	}
	got := BuildCases(fixtureInput(t))
	if len(got) != len(want) {
		t.Fatalf("cases = %d, want %d", len(got), len(want))
	}
	patterns := map[string]bool{}
	for i, c := range got {
		g := toGolden(c)
		patterns[g.Pattern] = true
		if !reflect.DeepEqual(g, want[i]) {
			a, _ := json.MarshalIndent(g, "", " ")
			b, _ := json.MarshalIndent(want[i], "", " ")
			t.Errorf("case %d differs\n--- port\n%s\n--- original\n%s", i+1, a, b)
		}
	}
	// The fixture is only a meaningful check while it exercises every pattern.
	for _, p := range []string{"P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"} {
		if !patterns[p] {
			t.Errorf("fixture produces no %s case", p)
		}
	}
}

func TestCaseTitlesAndExpiredKnown(t *testing.T) {
	in := fixtureInput(t)
	cases := BuildCases(in)
	if cases[0].Title != "Fail burst then success" {
		t.Fatalf("title = %q", cases[0].Title)
	}
	// The expired "user=alice" row must not turn the P1 case into known activity.
	if cases[0].Known != "" || cases[0].Actor != "user:alice@web-01" {
		t.Fatalf("first case = %+v", cases[0])
	}
	// The same row applies once the clock is before its expiry.
	in.Today = time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	found := false
	for _, c := range BuildCases(in) {
		if c.Actor == "user:alice@web-01" {
			found = true
			if c.Known == "" || c.Score != 0 || c.Severity != "Info" {
				t.Fatalf("alice case with unexpired row = %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("alice case missing")
	}
}

func TestZone(t *testing.T) {
	admin := []string{"10.7.", "192.168.50."}
	cases := map[string]string{"": "", "-": "", "10.7.1.5": "admin", "10.9.9.9": "internal", "45.33.32.156": "external",
		"100.64.1.1": "internal", "203.0.113.9": "internal", "198.51.100.7": "internal", "127.0.0.1": "internal",
		"169.254.1.1": "internal", "2001:db8::1": "internal", "2606:4700::1111": "external", "not-an-ip": "", "::ffff:10.9.9.9": "internal"}
	for ip, want := range cases {
		if got := zone(ip, admin); got != want {
			t.Errorf("zone(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestKnownActivityRejectsBadPatterns(t *testing.T) {
	head := "pattern\tmatch\treason\texpires\tapproved_by\n"
	for name, row := range map[string]string{"unsupported syntax": "P1\t(?=x)y\tr\t\ta\n", "matches empty": "P1\tx*\tr\t\ta\n"} {
		if _, err := ParseKnownActivity(head + row); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	rows, err := ParseKnownActivity("# only comments\n")
	if err != nil || len(rows) != 0 {
		t.Fatalf("empty registry = %v, %v", rows, err)
	}
}
