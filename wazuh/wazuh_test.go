package wazuh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fakeWazuh(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "reader" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("tok123\n"))
	})
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"affected_items":[
			{"id":"000","name":"manager","status":"active"},
			{"id":"001","name":"os-compute-01","ip":"10.0.0.11","status":"active","group":["openstack-node"],"os":{"name":"Ubuntu","version":"24.04"},"lastKeepAlive":"2026-11-16T01:00:00Z"},
			{"id":"002","name":"k8s-cp-01","ip":"10.0.1.5","status":"active","group":["k8s-node"]},
			{"id":"003","name":"bao-01","ip":"any","status":"disconnected"}]}}`))
	})
	mux.HandleFunc("POST /wazuh-alerts-4.x-*/_search", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "ix" || p != "ixpw" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["size"] == float64(0) {
			_, _ = w.Write([]byte(`{"hits":{"hits":[]}}`))
			return
		}
		hit := func(agent string, check string) string {
			return `{"_source":{"agent":{"name":"` + agent + `"},"data":{"siem":{"check":` + check + `}}},"sort":[1,"a"]}`
		}
		hits := []string{
			// stale run of the hypervisor must be dropped
			hit("os-compute-01", `{"kind":"target","run":"20261115T010000","type":"db.mysql","ctx":"host"}`),
			hit("os-compute-01", `{"kind":"host","run":"20261116T010000","os":"Ubuntu 24.04","roles":"openstack-compute","virt":"Dell Inc. PowerEdge R750","vm_uuid":"aaaa"}`),
			hit("os-compute-01", `{"kind":"target","run":"20261116T010000","type":"hv.qemu","ctx":"container","guests":"1111|instance-01|k8s-cp-01;2222|instance-02|orphan-vm"}`),
			hit("k8s-cp-01", `{"kind":"host","run":"20261116T020000","roles":"k8s-cp etcd","virt":"OpenStack Foundation OpenStack Nova","vm_uuid":"1111","k8s_ca":"abcdef123456"}`),
			hit("k8s-cp-01", `{"kind":"target","run":"20261116T020000","type":"container","ctx":"pod"}`),
			hit("k8s-cp-01", `{"kind":"verdict","run":"20261116T020000","code":"U-01","result":"취약","sev":"상","std":"kisa","title":"root 원격 접속 제한","ev":"PermitRootLogin yes"}`),
			hit("k8s-cp-01", `{"kind":"verdict","run":"20261116T020000","code":"KUBE-03","result":"판단필요","title":"감사 정책"}`),
			hit("k8s-cp-01", `{"kind":"verdict","run":"20261116T020000","code":"A-09","result":"오류","ev":"timeout"}`),
			hit("k8s-cp-01", `{"kind":"verdict","run":"20261116T020000","code":"U-02","result":"양호"}`),
			hit("k8s-cp-01", `{"kind":"pass","run":"20261116T020000","good":"U-03 U-04 U-05","na":"U-06"}`),
			// a previous run's failure must not be counted
			hit("k8s-cp-01", `{"kind":"verdict","run":"20261115T020000","code":"U-99","result":"취약"}`),
			hit("k8s-cp-01", `{"kind":"summary","run":"20261116T020000"}`),
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[` + strings.Join(hits, ",") + `]}}`))
	})
	return httptest.NewTLSServer(mux)
}

func testConfig(srv *httptest.Server) (Config, Credentials) {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return Config{ManagerURL: srv.URL, IndexerURL: srv.URL, TLSFingerprint: hex.EncodeToString(sum[:])},
		Credentials{ManagerUser: "reader", ManagerPassword: "pw", IndexerUser: "ix", IndexerPassword: "ixpw"}
}

func TestCollectAndBuildGraph(t *testing.T) {
	srv := fakeWazuh(t)
	defer srv.Close()
	cfg, auth := testConfig(srv)
	cfg, err := Validate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Test(context.Background(), cfg, auth)
	if err != nil || n != 3 {
		t.Fatalf("Test = %d, %v; want 3 agents (manager 000 excluded)", n, err)
	}
	agents, err := Agents(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	records, err := CheckRecords(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 9 {
		t.Fatalf("records = %d, want 9 (stale runs and summary dropped)", len(records))
	}
	g := BuildGraph(agents, records, nil, time.Now())
	nodes := map[string]Node{}
	for _, node := range g.Nodes {
		nodes[node.ID] = node
	}
	check := func(id, kind, status string) Node {
		t.Helper()
		node, ok := nodes[id]
		if !ok || node.Kind != kind || node.Status != status {
			t.Fatalf("node %s = %+v (found %v), want kind %s status %s", id, node, ok, kind, status)
		}
		return node
	}
	hv := check("host:os-compute-01", KindBareMetal, "active")
	if len(hv.Services) != 1 || hv.Services[0] != "hv.qemu" {
		t.Fatalf("hypervisor services = %v, want only latest-run hv.qemu", hv.Services)
	}
	cp := check("host:k8s-cp-01", KindVM, "active")
	if len(cp.Services) != 0 {
		t.Fatalf("container targets must not be listed as services: %v", cp.Services)
	}
	if cp.Checks == nil || *cp.Checks != (Checks{Fail: 1, Review: 1, Error: 1, Pass: 4, NA: 1}) {
		t.Fatalf("checks = %+v", cp.Checks)
	}
	if hv.Checks != nil {
		t.Fatalf("host without check results must have nil checks: %+v", hv.Checks)
	}
	_, issues := BuildChecks(records, nil, time.Now())
	got := issues["host:k8s-cp-01"]
	if len(issues) != 1 || len(got) != 3 || got[0].Code != "U-01" || got[0].Result != "fail" || got[0].Ev != "PermitRootLogin yes" ||
		got[1].Result != "error" || got[2].Result != "review" {
		t.Fatalf("issues = %+v", issues)
	}
	if bao := check("host:bao-01", KindUnknown, "disconnected"); bao.IP != "" {
		t.Fatalf("ip %q, want empty for 'any'", bao.IP)
	}
	if orphan := check("guest:2222", KindVM, StatusNoAgent); orphan.Name != "orphan-vm" {
		t.Fatalf("orphan name %q", orphan.Name)
	}
	if k := check("k8s:abcdef123456", KindK8s, ""); k.Members != 1 {
		t.Fatalf("k8s members %d", k.Members)
	}
	check("openstack", KindOpenStack, "")
	want := map[Edge]bool{
		{From: "host:k8s-cp-01", To: "host:os-compute-01", Kind: EdgeRunsOn}: true,
		{From: "guest:2222", To: "host:os-compute-01", Kind: EdgeRunsOn}:     true,
		{From: "host:k8s-cp-01", To: "k8s:abcdef123456", Kind: EdgeMemberOf}: true,
		{From: "host:os-compute-01", To: "openstack", Kind: EdgeMemberOf}:    true,
	}
	if len(g.Edges) != len(want) {
		t.Fatalf("edges = %+v, want %d", g.Edges, len(want))
	}
	for _, e := range g.Edges {
		if !want[e] {
			t.Fatalf("unexpected edge %+v", e)
		}
	}
}

func TestAuthAndTLSFailures(t *testing.T) {
	srv := fakeWazuh(t)
	defer srv.Close()
	cfg, auth := testConfig(srv)
	bad := auth
	bad.ManagerPassword = "wrong"
	if _, err := Agents(context.Background(), cfg, bad); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password: %v, want ErrAuth", err)
	}
	bad = auth
	bad.IndexerPassword = "wrong"
	if _, err := CheckRecords(context.Background(), cfg, bad); !errors.Is(err, ErrPermission) {
		t.Fatalf("indexer 403: %v, want ErrPermission", err)
	}
	// Without a pin or skip-verify the self-signed test certificate is refused.
	strict := cfg
	strict.TLSFingerprint = ""
	if _, err := Agents(context.Background(), strict, auth); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unverified cert: %v, want ErrUnavailable", err)
	}
	wrongPin := cfg
	wrongPin.TLSFingerprint = strings.Repeat("0", 64)
	if _, err := Agents(context.Background(), wrongPin, auth); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong pin: %v, want ErrUnavailable", err)
	}
	skip := strict
	skip.TLSSkipVerify = true
	if _, err := Agents(context.Background(), skip, auth); err != nil {
		t.Fatalf("skip verify: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, raw := range []string{"", "http://wazuh:55000", "https://u:p@wazuh:55000", "https://wazuh:55000/path", "https://wazuh:55000?x=1"} {
		if _, err := Validate(Config{ManagerURL: raw}); !errors.Is(err, ErrInvalid) {
			t.Errorf("manager url %q accepted", raw)
		}
	}
	c, err := Validate(Config{ManagerURL: " https://Wazuh:55000/ ", TLSFingerprint: "AA:" + strings.Repeat("bb", 31), TLSSkipVerify: true})
	if err != nil || c.ManagerURL != "https://Wazuh:55000" || c.TLSSkipVerify || len(c.TLSFingerprint) != 64 {
		t.Fatalf("normalized = %+v, %v", c, err)
	}
	if _, err := Validate(Config{ManagerURL: "https://w:1", TLSFingerprint: "zz"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad fingerprint accepted")
	}
	noIndexer := Config{ManagerURL: "https://w:1"}
	if err := ValidateCredentials(noIndexer, Credentials{ManagerUser: "a", ManagerPassword: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCredentials(Config{ManagerURL: "https://w:1", IndexerURL: "https://i:1"}, Credentials{ManagerUser: "a", ManagerPassword: "b"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("indexer credentials not required")
	}
}

func TestAgentsOnlyGraph(t *testing.T) {
	g := BuildGraph([]Agent{{ID: "001", Name: "Web-01.example.internal", Status: "active"}}, nil, nil, time.Now())
	if len(g.Nodes) != 1 || g.Nodes[0].ID != "host:web-01" || g.Nodes[0].Kind != KindUnknown || len(g.Edges) != 0 {
		t.Fatalf("graph = %+v", g)
	}
}

func TestEvidenceIsClipped(t *testing.T) {
	_, issues := BuildChecks([]CheckRecord{{Agent: "h", Kind: "verdict", Result: "취약", Code: "X", Ev: strings.Repeat("가", 2000)}}, nil, time.Now())
	if n := len([]rune(issues["host:h"][0].Ev)); n != maxEvidenceRunes+1 {
		t.Fatalf("evidence runes = %d", n)
	}
}
