package wazuh

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const registryTSV = "# comment\n" +
	"code\thost\treason\tapproved_by\tuntil\n" +
	"U-03\tweb-01\tcompensating control\treviewer\t2027-01-01\n" +
	"CIS 6.3.1\t*\tWazuh FIM instead of AIDE\treviewer\t2027-01-01\n" +
	"CIS-K8s 1.2.1\tcp-01\tmanaged by installer\treviewer\t2027-01-01\n" +
	"U-04\t*\texpired exception\treviewer\t2026-01-01\n" +
	"KUBE-03\tweb-01\treview accepted\treviewer\t\n"

func TestParseAcceptedRisks(t *testing.T) {
	risks, err := ParseAcceptedRisks(registryTSV)
	if err != nil || len(risks) != 5 || risks[1].Code != "CIS 6.3.1" || risks[1].Host != "*" || risks[4].Until != "" {
		t.Fatalf("risks = %+v, %v", risks, err)
	}
	bad := map[string]string{
		"no header":   "U-03\tweb\tr\ta\t2027-01-01\n",
		"bad header":  "code\thost\treason\n",
		"short row":   "code\thost\treason\tapproved_by\tuntil\nU-03\tweb\tr\n",
		"bad date":    "code\thost\treason\tapproved_by\tuntil\nU-03\tweb\tr\ta\t2027/01/01\n",
		"no reason":   "code\thost\treason\tapproved_by\tuntil\nU-03\tweb\t\ta\t2027-01-01\n",
		"no approver": "code\thost\treason\tapproved_by\tuntil\nU-03\tweb\tr\t\t2027-01-01\n",
		"duplicate":   "code\thost\treason\tapproved_by\tuntil\nU-03\tWeb\tr\ta\t\nU-03\tweb\tr\ta\t\n",
	}
	for name, tsv := range bad {
		if _, err := ParseAcceptedRisks(tsv); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestAcceptedRisksApplied(t *testing.T) {
	risks, err := ParseAcceptedRisks(registryTSV)
	if err != nil {
		t.Fatal(err)
	}
	today := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	records := []CheckRecord{
		{Agent: "web-01.example.internal", Kind: "verdict", Code: "U-03", Result: "취약", Std: "kisa"},
		{Agent: "web-01", Kind: "verdict", Code: "6.3.1", Result: "취약", Std: "cis", Policy: "cis_ubuntu24-04"},
		// expired row: still a failure
		{Agent: "web-01", Kind: "verdict", Code: "U-04", Result: "취약", Std: "kisa"},
		{Agent: "web-01", Kind: "verdict", Code: "KUBE-03", Result: "판단필요", Std: "siem"},
		// errors are never accepted
		{Agent: "web-01", Kind: "verdict", Code: "U-03", Result: "오류", Std: "kisa"},
		// CIS-K8s row only matches its own host and prefix
		{Agent: "cp-01", Kind: "verdict", Code: "1.2.1", Result: "취약", Std: "cis", Policy: "siem_k8s_control_plane"},
		{Agent: "web-01", Kind: "verdict", Code: "1.2.1", Result: "취약", Std: "cis", Policy: "siem_k8s_control_plane"},
		// same number under the Ubuntu policy is a different registry code
		{Agent: "cp-01", Kind: "verdict", Code: "1.2.1", Result: "취약", Std: "cis", Policy: "cis_ubuntu24-04"},
	}
	counts, issues := BuildChecks(records, risks, today)
	if got, want := *counts["host:web-01"], (Checks{Fail: 2, Review: 0, Error: 1, Accepted: 3}); got != want {
		t.Fatalf("web-01 counts = %+v, want %+v", got, want)
	}
	if got, want := *counts["host:cp-01"], (Checks{Fail: 1, Accepted: 1}); got != want {
		t.Fatalf("cp-01 counts = %+v, want %+v", got, want)
	}
	byKey := map[string]Issue{}
	for _, i := range issues["host:web-01"] {
		byKey[i.Code+"/"+i.Result] = i
	}
	if a := byKey["6.3.1/fail"]; a.Accepted == nil || a.Accepted.Host != "*" || a.Key != "CIS 6.3.1" {
		t.Fatalf("CIS issue = %+v", a)
	}
	if a := byKey["U-03/fail"].Accepted; a == nil || a.Reason != "compensating control" || a.Until != "2027-01-01" {
		t.Fatalf("U-03 acceptance = %+v", a)
	}
	if byKey["U-04/fail"].Accepted != nil || byKey["U-03/error"].Accepted != nil {
		t.Fatal("expired row or error result accepted")
	}
	// Graph counts follow the registry too.
	g := BuildGraph([]Agent{{ID: "001", Name: "web-01", Status: "active"}}, records, risks, today)
	for _, n := range g.Nodes {
		if n.ID == "host:web-01" && (n.Checks == nil || n.Checks.Fail != 2 || n.Checks.Accepted != 3) {
			t.Fatalf("graph checks = %+v", n.Checks)
		}
	}
}

func TestRegistryCode(t *testing.T) {
	cases := map[[3]string]string{
		{"kisa", "", "U-44"}:                        "U-44",
		{"cis", "cis_ubuntu24-04", "5.1.20"}:        "CIS 5.1.20",
		{"cis", "siem_k8s_kubelet", "4.2.1"}:        "CIS-K8s 4.2.1",
		{"cis", "cis_docker", "2.1"}:                "CIS-Docker 2.1",
		{"cis", "", "1.1"}:                          "CIS-K8s 1.1",
		{"siem", "", strings.Repeat("A", 3) + "-1"}: "AAA-1",
	}
	for in, want := range cases {
		if got := RegistryCode(in[0], in[1], in[2]); got != want {
			t.Errorf("RegistryCode%v = %q, want %q", in, got, want)
		}
	}
}
