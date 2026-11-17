package wazuh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	// AlertWindowDays is the analysis window of case extraction (events.py
	// --window default; the indexer keeps 7 days of alerts).
	AlertWindowDays = 7
	alertPageSize   = 2000
	// MaxAlerts caps one extraction run (events.py MAX_DOCS).
	MaxAlerts = 200000
)

// ErrTestAlerts: rule-test log lines reached the real alert index.
var ErrTestAlerts = errors.New("경보에 시험 로그 표식(" + TestHost + ")이 있습니다. 시험 로그가 실제 수집 경로로 들어왔습니다")

func indexerSearch(ctx context.Context, h *http.Client, c Config, a Credentials, index string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, invalid("indexer 요청을 만들지 못했습니다")
	}
	r, err := http.NewRequest(http.MethodPost, c.IndexerURL+"/"+index+"/_search", bytes.NewReader(raw))
	if err != nil {
		return nil, invalid("indexer 요청을 만들지 못했습니다")
	}
	r.SetBasicAuth(a.IndexerUser, a.IndexerPassword)
	r.Header.Set("Content-Type", "application/json")
	return do(ctx, h, r, "indexer")
}

// FetchAlerts returns the alerts of the given rules inside the window, in
// timestamp order. capped reports that MaxAlerts was reached.
func FetchAlerts(ctx context.Context, c Config, a Credentials, ruleIDs []string, days int) (alerts []*Alert, capped bool, err error) {
	return FetchHostAlerts(ctx, c, a, ruleIDs, days, nil)
}

// FetchHostAlerts is FetchAlerts limited to the named agents. An empty host
// list means every agent.
func FetchHostAlerts(ctx context.Context, c Config, a Credentials, ruleIDs []string, days int, hosts []string) (alerts []*Alert, capped bool, err error) {
	if c.IndexerURL == "" || len(ruleIDs) == 0 {
		return nil, false, nil
	}
	h := httpClient(c)
	defer h.CloseIdleConnections()
	body := map[string]any{
		"size":    alertPageSize,
		"_source": AlertSourceFields,
		"sort":    []any{map[string]string{"timestamp": "asc"}, map[string]string{"_id": "asc"}},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"terms": map[string]any{"rule.id": ruleIDs}},
			map[string]any{"range": map[string]any{"timestamp": map[string]string{"gte": fmt.Sprintf("now-%dd", days)}}},
		}}},
	}
	if len(hosts) > 0 {
		filter := body["query"].(map[string]any)["bool"].(map[string]any)
		filter["filter"] = append(filter["filter"].([]any), map[string]any{"terms": map[string]any{"agent.name": hosts}})
	}
	for len(alerts) < MaxAlerts {
		b, err := indexerSearch(ctx, h, c, a, "wazuh-alerts-4.x-*", body)
		if err != nil {
			return nil, false, err
		}
		var page struct {
			Hits struct {
				Hits []struct {
					Source map[string]any `json:"_source"`
					Sort   []any          `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber() // keep ids and numeric fields exactly as indexed
		if dec.Decode(&page) != nil {
			return nil, false, fmt.Errorf("%w (indexer): 경보 검색 응답 형식이 올바르지 않습니다", ErrUnavailable)
		}
		hits := page.Hits.Hits
		for _, hit := range hits {
			al, err := ParseAlert(hit.Source)
			if err != nil {
				continue // an alert without a usable timestamp cannot be placed
			}
			if al.Host == TestHost {
				return nil, false, ErrTestAlerts
			}
			alerts = append(alerts, al)
		}
		if len(hits) < alertPageSize {
			return alerts, false, nil
		}
		body["search_after"] = hits[len(hits)-1].Sort
	}
	return alerts, true, nil
}

// SeenLogins returns the (host, user, source) triples first observed inside
// the window, from the siem-seen-login index. The result is nil, with a
// reason, when the index is unreadable, empty, or its baseline starts inside
// the window (every login would look new).
func SeenLogins(ctx context.Context, c Config, a Credentials, days int, now time.Time) (map[[3]string]bool, string) {
	if c.IndexerURL == "" {
		return nil, "불가 (indexer 미연결)"
	}
	h := httpClient(c)
	defer h.CloseIdleConnections()
	b, err := indexerSearch(ctx, h, c, a, "siem-seen-login", map[string]any{"size": 10000, "_source": []string{"agent", "user", "srcip", "first_seen"}})
	if err != nil {
		return nil, "불가 (siem-seen-login 조회 실패)"
	}
	var page struct {
		Hits struct {
			Hits []struct {
				Source struct {
					Agent     string  `json:"agent"`
					User      string  `json:"user"`
					SrcIP     string  `json:"srcip"`
					FirstSeen float64 `json:"first_seen"` // epoch milliseconds
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(b, &page) != nil || len(page.Hits.Hits) == 0 {
		return nil, "불가 (siem-seen-login 비어 있음)"
	}
	start := float64(now.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli())
	base := page.Hits.Hits[0].Source.FirstSeen
	for _, hit := range page.Hits.Hits {
		if hit.Source.FirstSeen < base {
			base = hit.Source.FirstSeen
		}
	}
	since := time.UnixMilli(int64(base)).In(KST).Format("2006-01-02 15:04")
	if base > start {
		return nil, fmt.Sprintf("보류 (siem-seen-login 기준선 %s 시작, 분석 창보다 짧음)", since)
	}
	seen := map[[3]string]bool{}
	for _, hit := range page.Hits.Hits {
		if s := hit.Source; s.FirstSeen >= start {
			seen[[3]string{s.Agent, s.User, s.SrcIP}] = true
		}
	}
	return seen, fmt.Sprintf("siem-seen-login (기준선 %s~)", since)
}

// PostureOf collects failed KISA-style check codes per agent from
// config-check records, as case extraction links them to patterns.
func PostureOf(records []CheckRecord) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, r := range records {
		if r.Kind != "verdict" || r.Result != resultBad || r.Code == "" {
			continue
		}
		if out[r.Agent] == nil {
			out[r.Agent] = map[string]bool{}
		}
		out[r.Agent][r.Code] = true
	}
	return out
}
