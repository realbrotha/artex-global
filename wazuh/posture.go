package wazuh

import (
	"sort"
	"strings"
)

// CheckSummary is one config-check item across every host of a connection:
// which hosts fail it, which need a manual review, which errored, and which
// are covered by the accepted-risk registry. Evidence stays with the host.
type CheckSummary struct {
	Code  string `json:"code"` // registry code ("U-01", "CIS 6.3.1")
	Std   string `json:"std,omitempty"`
	Sev   string `json:"sev,omitempty"`
	Title string `json:"title,omitempty"`
	// Host names, sorted. A host is in at most one of fail/review/error for a
	// code (its worst result), or in accepted when every result is accepted.
	Fail     []string `json:"fail"`
	Review   []string `json:"review"`
	Error    []string `json:"error"`
	Accepted []string `json:"accepted"`
}

var (
	postureStdRank = map[string]int{"kisa": 0, "cis": 1, "siem": 2}
	postureSevRank = map[string]int{"상": 0, "중": 1, "하": 2}
	// Worst first: a host that fails a check on one target and only needs a
	// review on another is a failing host.
	postureResultRank = map[string]int{"fail": 0, "error": 1, "review": 2}
)

// SummarizeChecks folds the per-host issue lists (node id -> issues) into one
// row per check. names maps node ids to host names; a node without a name is
// shown by its id without the "host:" prefix.
func SummarizeChecks(issues map[string][]Issue, names map[string]string) []CheckSummary {
	type key struct{ std, code string }
	type state struct {
		summary CheckSummary
		// host -> best (lowest) result rank seen that is NOT accepted; -1 = only accepted so far
		hosts map[string]int
	}
	rows := map[key]*state{}
	for node, list := range issues {
		host := names[node]
		if host == "" {
			host = strings.TrimPrefix(node, "host:")
		}
		for _, is := range list {
			code := is.Key
			if code == "" {
				code = is.Code
			}
			k := key{is.Std, code}
			row := rows[k]
			if row == nil {
				row = &state{summary: CheckSummary{Code: code, Std: is.Std, Sev: is.Sev, Title: is.Title}, hosts: map[string]int{}}
				rows[k] = row
			}
			if row.summary.Title == "" {
				row.summary.Title = is.Title
			}
			if row.summary.Sev == "" {
				row.summary.Sev = is.Sev
			}
			rank, known := postureResultRank[is.Result]
			if !known {
				continue
			}
			if is.Accepted != nil {
				rank = -1
			}
			prev, seen := row.hosts[host]
			// An open result always outranks an accepted one; among open
			// results the worst wins.
			if !seen || (prev == -1 && rank != -1) || (rank != -1 && rank < prev) {
				row.hosts[host] = rank
			}
		}
	}
	out := make([]CheckSummary, 0, len(rows))
	for _, row := range rows {
		s := row.summary
		s.Fail, s.Review, s.Error, s.Accepted = []string{}, []string{}, []string{}, []string{}
		for host, rank := range row.hosts {
			switch rank {
			case 0:
				s.Fail = append(s.Fail, host)
			case 1:
				s.Error = append(s.Error, host)
			case 2:
				s.Review = append(s.Review, host)
			default:
				s.Accepted = append(s.Accepted, host)
			}
		}
		if len(row.hosts) == 0 {
			continue // nothing but results that are not issues
		}
		sort.Strings(s.Fail)
		sort.Strings(s.Review)
		sort.Strings(s.Error)
		sort.Strings(s.Accepted)
		out = append(out, s)
	}
	rankOf := func(m map[string]int, k string) int {
		if r, ok := m[k]; ok {
			return r
		}
		return len(m)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := rankOf(postureStdRank, a.Std), rankOf(postureStdRank, b.Std); ra != rb {
			return ra < rb
		}
		if a.Std != b.Std {
			return a.Std < b.Std
		}
		if ra, rb := rankOf(postureSevRank, a.Sev), rankOf(postureSevRank, b.Sev); ra != rb {
			return ra < rb
		}
		if len(a.Fail) != len(b.Fail) {
			return len(a.Fail) > len(b.Fail)
		}
		return a.Code < b.Code
	})
	return out
}
