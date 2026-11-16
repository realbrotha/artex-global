// Package wazuh reads protected-asset inventory from a Wazuh deployment.
//
// Two read-only endpoints are used:
//   - manager API  : registered agents (name, status, groups, OS)
//   - indexer      : config-check host/target records (rule 101401/101402),
//     which carry virtualization identity, hypervisor guests,
//     the Kubernetes cluster CA fingerprint and detected services
//
// Nothing is written to Wazuh.
package wazuh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalid     = errors.New("Wazuh 연결 설정이 올바르지 않습니다")
	ErrAuth        = errors.New("Wazuh 인증에 실패했습니다. 계정과 비밀번호를 확인해 주세요")
	ErrPermission  = errors.New("Wazuh 계정에 조회 권한이 없습니다")
	ErrUnavailable = errors.New("Wazuh 에 연결하지 못했습니다")
)

const (
	maxResponseBytes = 16 << 20
	agentPageSize    = 500
	maxAgents        = 20000
	recordPageSize   = 2000
	maxRecords       = 100000
	// CheckWindowDays bounds the config-check lookback. Hosts report daily.
	CheckWindowDays = 3
)

// Config is the non-secret part of a connection.
type Config struct {
	ManagerURL string `json:"manager_url"`
	// IndexerURL is optional. Without it only the agent list is available:
	// no VM/bare-metal distinction, relations or services.
	IndexerURL     string `json:"indexer_url"`
	TLSFingerprint string `json:"tls_fingerprint"`
	// TLSSkipVerify disables certificate validation. Needed for a
	// kubectl port-forward to a cluster-internal self-signed endpoint.
	TLSSkipVerify bool `json:"tls_skip_verify"`
}

type Credentials struct {
	ManagerUser     string `json:"manager_user"`
	ManagerPassword string `json:"manager_password"`
	IndexerUser     string `json:"indexer_user,omitempty"`
	IndexerPassword string `json:"indexer_password,omitempty"`
}

func invalid(msg string) error { return fmt.Errorf("%w: %s", ErrInvalid, msg) }

func cleanURL(raw, label string, required bool) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		if required {
			return "", invalid(label + " 주소를 입력해 주세요")
		}
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || len(raw) > 512 {
		return "", invalid(label + " 주소는 경로·계정·쿼리 없는 HTTPS 주소여야 합니다")
	}
	return u.Scheme + "://" + u.Host, nil
}

// Validate normalizes a config.
func Validate(c Config) (Config, error) {
	var err error
	if c.ManagerURL, err = cleanURL(c.ManagerURL, "manager API", true); err != nil {
		return c, err
	}
	if c.IndexerURL, err = cleanURL(c.IndexerURL, "indexer", false); err != nil {
		return c, err
	}
	c.TLSFingerprint = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.TLSFingerprint), ":", ""))
	if c.TLSFingerprint != "" {
		if b, e := hex.DecodeString(c.TLSFingerprint); e != nil || len(b) != sha256.Size {
			return c, invalid("인증서 지문은 SHA-256 16진수 64자여야 합니다")
		}
		c.TLSSkipVerify = false
	}
	return c, nil
}

func validPair(user, pass string) bool {
	return user != "" && pass != "" && len(user) <= 256 && len(pass) <= 8192 &&
		!strings.ContainsAny(user, ":\r\n\x00") && !strings.ContainsRune(pass, 0)
}

// ValidateCredentials requires manager credentials; indexer credentials are
// required exactly when an indexer URL is configured.
func ValidateCredentials(c Config, a Credentials) error {
	if !validPair(a.ManagerUser, a.ManagerPassword) {
		return invalid("manager API 계정과 비밀번호가 필요합니다")
	}
	if c.IndexerURL != "" && !validPair(a.IndexerUser, a.IndexerPassword) {
		return invalid("indexer 계정과 비밀번호가 필요합니다")
	}
	return nil
}

func httpClient(c Config) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case c.TLSFingerprint != "":
		pin, _ := hex.DecodeString(c.TLSFingerprint)
		// An exact leaf-certificate pin replaces PKI validation.
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("인증서가 없습니다")
			}
			cert := cs.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			now := time.Now()
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("서버 인증서가 저장된 지문과 일치하지 않거나 만료됐습니다")
			}
			return nil
		}
	case c.TLSSkipVerify:
		tc.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{Proxy: nil, TLSClientConfig: tc, DisableKeepAlives: true, ResponseHeaderTimeout: 20 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func do(ctx context.Context, h *http.Client, r *http.Request, what string) ([]byte, error) {
	res, err := h.Do(r.WithContext(ctx))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w (%s): 주소·인증서·네트워크를 확인해 주세요", ErrUnavailable, what)
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("%w (%s)", ErrAuth, what)
	case res.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w (%s)", ErrPermission, what)
	case res.StatusCode >= 500:
		return nil, fmt.Errorf("%w (%s): HTTP %d", ErrUnavailable, what, res.StatusCode)
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s 조회가 HTTP %d 로 거절됐습니다", what, res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s 응답을 끝까지 읽지 못했습니다", what)
	}
	if len(b) > maxResponseBytes {
		return nil, fmt.Errorf("%s 응답이 16 MiB 를 초과했습니다", what)
	}
	return b, nil
}

// Agent is one registered Wazuh agent (the manager itself, id 000, is excluded).
type Agent struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	IP            string   `json:"ip"`
	Status        string   `json:"status"`
	Groups        []string `json:"group"`
	Version       string   `json:"version"`
	LastKeepAlive string   `json:"lastKeepAlive"`
	OS            struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Platform string `json:"platform"`
	} `json:"os"`
}

func managerToken(ctx context.Context, h *http.Client, c Config, a Credentials) (string, error) {
	r, err := http.NewRequest(http.MethodPost, c.ManagerURL+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return "", invalid("manager API 요청을 만들지 못했습니다")
	}
	r.SetBasicAuth(a.ManagerUser, a.ManagerPassword)
	b, err := do(ctx, h, r, "manager API")
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if token == "" || len(token) > 8192 || strings.ContainsAny(token, " \r\n") {
		return "", fmt.Errorf("%w (manager API): 토큰 응답 형식이 올바르지 않습니다", ErrUnavailable)
	}
	return token, nil
}

// Agents lists every registered agent.
func Agents(ctx context.Context, c Config, a Credentials) ([]Agent, error) {
	h := httpClient(c)
	defer h.CloseIdleConnections()
	token, err := managerToken(ctx, h, c, a)
	if err != nil {
		return nil, err
	}
	out := []Agent{}
	for offset := 0; offset < maxAgents; offset += agentPageSize {
		r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/agents?select=id,name,ip,status,group,version,lastKeepAlive,os.name,os.version,os.platform&limit=%d&offset=%d", c.ManagerURL, agentPageSize, offset), nil)
		if err != nil {
			return nil, invalid("manager API 요청을 만들지 못했습니다")
		}
		r.Header.Set("Authorization", "Bearer "+token)
		b, err := do(ctx, h, r, "manager API")
		if err != nil {
			return nil, err
		}
		var page struct {
			Data struct {
				Items []Agent `json:"affected_items"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &page) != nil {
			return nil, fmt.Errorf("%w (manager API): agent 목록 형식이 올바르지 않습니다", ErrUnavailable)
		}
		for _, ag := range page.Data.Items {
			if ag.ID != "000" && ag.Name != "" {
				out = append(out, ag)
			}
		}
		if len(page.Data.Items) < agentPageSize {
			break
		}
	}
	return out, nil
}

// CheckRecord is one config-check record of kind host or target.
type CheckRecord struct {
	Agent string
	Kind  string // host | target
	Run   string
	// host
	OS, Roles, Virt, VMUUID, K8sCA string
	// target
	Type, Ctx, Guests string
}

func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// CheckRecords returns host/target records of each agent's latest run.
func CheckRecords(ctx context.Context, c Config, a Credentials) ([]CheckRecord, error) {
	if c.IndexerURL == "" {
		return nil, nil
	}
	h := httpClient(c)
	defer h.CloseIdleConnections()
	body := map[string]any{
		"size":    recordPageSize,
		"_source": []string{"agent.name", "data.siem.check"},
		"sort":    []any{map[string]string{"timestamp": "asc"}, map[string]string{"_id": "asc"}},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"terms": map[string]any{"rule.id": []string{"101401", "101402"}}},
			map[string]any{"range": map[string]any{"timestamp": map[string]string{"gte": fmt.Sprintf("now-%dd", CheckWindowDays)}}},
		}}},
	}
	all := []CheckRecord{}
	latest := map[string]string{}
	for len(all) < maxRecords {
		raw, _ := json.Marshal(body)
		r, err := http.NewRequest(http.MethodPost, c.IndexerURL+"/wazuh-alerts-4.x-*/_search", bytes.NewReader(raw))
		if err != nil {
			return nil, invalid("indexer 요청을 만들지 못했습니다")
		}
		r.SetBasicAuth(a.IndexerUser, a.IndexerPassword)
		r.Header.Set("Content-Type", "application/json")
		b, err := do(ctx, h, r, "indexer")
		if err != nil {
			return nil, err
		}
		var page struct {
			Hits struct {
				Hits []struct {
					Source struct {
						Agent struct {
							Name string `json:"name"`
						} `json:"agent"`
						Data struct {
							Siem struct {
								Check map[string]any `json:"check"`
							} `json:"siem"`
						} `json:"data"`
					} `json:"_source"`
					Sort []any `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if json.Unmarshal(b, &page) != nil {
			return nil, fmt.Errorf("%w (indexer): 검색 응답 형식이 올바르지 않습니다", ErrUnavailable)
		}
		hits := page.Hits.Hits
		for _, hit := range hits {
			ck := hit.Source.Data.Siem.Check
			rec := CheckRecord{Agent: hit.Source.Agent.Name, Kind: str(ck, "kind"), Run: str(ck, "run")}
			if rec.Agent == "" || (rec.Kind != "host" && rec.Kind != "target") {
				continue
			}
			rec.OS, rec.Roles, rec.Virt = str(ck, "os"), str(ck, "roles"), str(ck, "virt")
			rec.VMUUID, rec.K8sCA = strings.ToLower(str(ck, "vm_uuid")), str(ck, "k8s_ca")
			rec.Type, rec.Ctx, rec.Guests = str(ck, "type"), str(ck, "ctx"), str(ck, "guests")
			if rec.Run > latest[rec.Agent] {
				latest[rec.Agent] = rec.Run
			}
			all = append(all, rec)
		}
		if len(hits) < recordPageSize {
			break
		}
		body["search_after"] = hits[len(hits)-1].Sort
	}
	out := all[:0]
	for _, rec := range all {
		if rec.Run == latest[rec.Agent] {
			out = append(out, rec)
		}
	}
	return out, nil
}

// Test verifies reachability and authentication of every configured endpoint.
func Test(ctx context.Context, c Config, a Credentials) (agents int, err error) {
	list, err := Agents(ctx, c, a)
	if err != nil {
		return 0, err
	}
	if c.IndexerURL != "" {
		h := httpClient(c)
		defer h.CloseIdleConnections()
		r, e := http.NewRequest(http.MethodPost, c.IndexerURL+"/wazuh-alerts-4.x-*/_search", strings.NewReader(`{"size":0}`))
		if e != nil {
			return 0, invalid("indexer 요청을 만들지 못했습니다")
		}
		r.SetBasicAuth(a.IndexerUser, a.IndexerPassword)
		r.Header.Set("Content-Type", "application/json")
		if _, e = do(ctx, h, r, "indexer"); e != nil {
			return 0, e
		}
	}
	return len(list), nil
}
