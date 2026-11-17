package wazuh

import (
	"reflect"
	"testing"
)

func TestSummarizeChecks(t *testing.T) {
	accepted := &Acceptance{Reason: "jump host", ApprovedBy: "sec"}
	issues := map[string][]Issue{
		"host:web01": {
			{Code: "U-01", Result: "fail", Sev: "상", Std: "kisa", Title: "root 원격 접속 제한"},
			// Same check on two targets: the worse result decides the host.
			{Code: "D-08", Result: "review", Sev: "상", Std: "kisa", Title: "암호화", Asset: "web01/db-a"},
			{Code: "D-08", Result: "fail", Sev: "상", Std: "kisa", Title: "암호화", Asset: "web01/db-b"},
			{Code: "6.3.1", Key: "CIS 6.3.1", Result: "fail", Std: "cis", Title: "auditd"},
		},
		"host:db01": {
			{Code: "U-01", Result: "fail", Sev: "상", Std: "kisa", Title: "root 원격 접속 제한", Accepted: accepted},
			{Code: "U-44", Result: "review", Sev: "하", Std: "kisa", Title: "tftp"},
			{Code: "U-45", Result: "error", Sev: "중", Std: "kisa", Title: "ntp"},
			{Code: "U-99", Result: "pass", Std: "kisa"}, // not an issue: ignored
		},
		"host:app01": {
			// Accepted on one target, still open on another: the host is not accepted.
			{Code: "D-08", Result: "fail", Sev: "상", Std: "kisa", Title: "암호화", Accepted: accepted},
			{Code: "D-08", Result: "review", Sev: "상", Std: "kisa", Title: "암호화"},
		},
	}
	got := SummarizeChecks(issues, map[string]string{"host:web01": "web01.example", "host:db01": "db01"})
	want := []CheckSummary{
		{Code: "D-08", Std: "kisa", Sev: "상", Title: "암호화", Fail: []string{"web01.example"}, Review: []string{"app01"}, Error: []string{}, Accepted: []string{}},
		{Code: "U-01", Std: "kisa", Sev: "상", Title: "root 원격 접속 제한", Fail: []string{"web01.example"}, Review: []string{}, Error: []string{}, Accepted: []string{"db01"}},
		{Code: "U-45", Std: "kisa", Sev: "중", Title: "ntp", Fail: []string{}, Review: []string{}, Error: []string{"db01"}, Accepted: []string{}},
		{Code: "U-44", Std: "kisa", Sev: "하", Title: "tftp", Fail: []string{}, Review: []string{"db01"}, Error: []string{}, Accepted: []string{}},
		{Code: "CIS 6.3.1", Std: "cis", Title: "auditd", Fail: []string{"web01.example"}, Review: []string{}, Error: []string{}, Accepted: []string{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SummarizeChecks =\n%+v\nwant\n%+v", got, want)
	}
}
