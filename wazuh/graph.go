package wazuh

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Node kinds.
const (
	KindBareMetal = "baremetal"
	KindVM        = "vm"
	KindUnknown   = "unknown" // agent present, no config-check identity yet
	KindK8s       = "k8s_cluster"
	KindOpenStack = "openstack"
)

// Host statuses. Agent statuses are passed through from the manager
// (active, disconnected, pending, never_connected); StatusNoAgent marks a
// machine known only through another host (a hypervisor guest).
const StatusNoAgent = "no_agent"

// Edge kinds.
const (
	EdgeRunsOn   = "runs_on"   // VM -> hypervisor
	EdgeMemberOf = "member_of" // host -> cluster / platform
	// bastion -> cluster: the jump host on a cluster's private network. It
	// is how the nodes are reached, not what they run on.
	EdgeGatewayOf = "gateway_of"
)

type Node struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Status string `json:"status,omitempty"`
	IP     string `json:"ip,omitempty"`
	// First public IPv4 on a host interface, and every host-level address.
	// Both are empty when the inventory could not be read.
	PublicIP string   `json:"public_ip,omitempty"`
	Addrs    []Addr   `json:"addrs,omitempty"`
	OS       string   `json:"os,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Services []string `json:"services,omitempty"`
	Virt     string   `json:"virt,omitempty"`
	LastSeen string   `json:"last_seen,omitempty"`
	Checked  string   `json:"checked,omitempty"` // latest config-check run
	Members  int      `json:"members,omitempty"` // group nodes only
	Checks   *Checks  `json:"checks,omitempty"`  // nil = no config-check result
	// Case candidates involving this host (known activity excluded) and the
	// most severe of them. Filled when the asset map is served.
	Cases   int    `json:"cases,omitempty"`
	CaseSev string `json:"case_sev,omitempty"`
}

// Checks counts one host's latest config-check results.
type Checks struct {
	Fail   int `json:"fail"`
	Review int `json:"review"`
	Error  int `json:"error"`
	Pass   int `json:"pass"`
	NA     int `json:"na"`
	// Failed or review results covered by the accepted-risk registry. They
	// are not counted in Fail or Review.
	Accepted int `json:"accepted"`
}

// Issue is one check that needs attention (failed, needs review, or errored).
type Issue struct {
	Code   string `json:"code"`
	Result string `json:"result"` // fail | review | error
	Sev    string `json:"sev,omitempty"`
	Std    string `json:"std,omitempty"`
	Title  string `json:"title,omitempty"`
	Ev     string `json:"ev,omitempty"`
	Asset  string `json:"asset,omitempty"` // service/container the check ran against
	// Registry code ("CIS 6.3.1" for CIS checks); empty when equal to Code.
	Key      string      `json:"key,omitempty"`
	Accepted *Acceptance `json:"accepted,omitempty"`
}

// config-check result labels (tools/config-check core.py).
const (
	resultGood   = "양호"
	resultBad    = "취약"
	resultReview = "판단필요"
	resultNA     = "N/A"
	resultError  = "오류"
)

const maxEvidenceRunes = 600

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

var issueOrder = map[string]int{"fail": 0, "error": 1, "review": 2}

// BuildChecks folds verdict/pass records into per-host counts and the list
// of issues, keyed by node id. Failed and review results that the registry
// accepts (on the given day) are counted as Accepted instead.
func BuildChecks(records []CheckRecord, risks []AcceptedRisk, today time.Time) (map[string]*Checks, map[string][]Issue) {
	accepted := newAcceptanceIndex(risks, today)
	counts := map[string]*Checks{}
	issues := map[string][]Issue{}
	for _, r := range records {
		if r.Kind != "verdict" && r.Kind != "pass" {
			continue
		}
		id := "host:" + shortName(r.Agent)
		c := counts[id]
		if c == nil {
			c = &Checks{}
			counts[id] = c
		}
		if r.Kind == "pass" {
			c.Pass += len(strings.Fields(r.Good))
			c.NA += len(strings.Fields(r.NA))
			continue
		}
		result := ""
		switch r.Result {
		case resultGood:
			c.Pass++
		case resultNA:
			c.NA++
		case resultBad:
			c.Fail++
			result = "fail"
		case resultReview:
			c.Review++
			result = "review"
		case resultError:
			c.Error++
			result = "error"
		}
		if result == "" {
			continue
		}
		issue := Issue{Code: r.Code, Result: result, Sev: r.Sev, Std: r.Std, Title: r.Title,
			Ev: clipRunes(r.Ev, maxEvidenceRunes), Asset: r.Asset}
		if key := RegistryCode(r.Std, r.Policy, r.Code); key != r.Code {
			issue.Key = key
		}
		if result != "error" {
			if a := accepted.lookup(RegistryCode(r.Std, r.Policy, r.Code), r.Agent); a != nil {
				issue.Accepted = a
				c.Accepted++
				if result == "fail" {
					c.Fail--
				} else {
					c.Review--
				}
			}
		}
		issues[id] = append(issues[id], issue)
	}
	for id := range issues {
		list := issues[id]
		sort.SliceStable(list, func(i, j int) bool {
			if a, b := issueOrder[list[i].Result], issueOrder[list[j].Result]; a != b {
				return a < b
			}
			return list[i].Code < list[j].Code
		})
	}
	return counts, issues
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	// Why interface addresses are missing, when they are.
	AddrNote string `json:"addr_note,omitempty"`
}

// virtual vendors/products as reported by DMI inside a guest.
var virtMarkers = []string{"qemu", "kvm", "openstack", "vmware", "virtualbox", "virtual machine", "xen", "bochs", "bhyve", "parallels", "amazon ec2", "google compute", "nutanix"}

func hostKind(virt string) string {
	v := strings.ToLower(strings.TrimSpace(virt))
	if v == "" {
		return KindUnknown
	}
	for _, m := range virtMarkers {
		if strings.Contains(v, m) {
			return KindVM
		}
	}
	return KindBareMetal
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func shortName(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return strings.ToLower(name[:i])
	}
	return strings.ToLower(name)
}

type guest struct{ uuid, name, hypervisor string }

// BuildGraph merges the agent list with config-check records.
//
//   - one node per agent, keyed by short hostname
//   - config-check host record -> kind (VM / bare metal), roles, cluster CA
//   - hypervisor guest uuid == VM product uuid -> runs_on edge
//   - guests no agent reports as -> VM nodes with status no_agent
//   - shared Kubernetes CA fingerprint -> one cluster node + member_of edges
//   - openstack-* role -> one OpenStack node + member_of edges
func BuildGraph(agents []Agent, records []CheckRecord, risks []AcceptedRisk, today time.Time) Graph {
	hosts := map[string]*Node{}
	order := []string{}
	ensure := func(name string) *Node {
		id := "host:" + shortName(name)
		if n, ok := hosts[id]; ok {
			return n
		}
		n := &Node{ID: id, Kind: KindUnknown, Name: name}
		hosts[id] = n
		order = append(order, id)
		return n
	}
	for _, a := range agents {
		n := ensure(a.Name)
		n.Status, n.IP, n.Groups, n.LastSeen = a.Status, a.IP, uniqSorted(a.Groups), a.LastKeepAlive
		if n.IP == "any" {
			n.IP = ""
		}
		n.OS = strings.TrimSpace(a.OS.Name + " " + a.OS.Version)
		n.Addrs = a.Addrs
		for _, addr := range a.Addrs {
			if addr.Public && !strings.Contains(addr.IP, ":") {
				n.PublicIP = addr.IP
				break
			}
		}
	}

	uuidOf := map[string]string{} // vm uuid -> host id
	caOf := map[string]string{}   // host id -> k8s ca
	guests := []guest{}
	services := map[string][]string{}
	for _, r := range records {
		n := ensure(r.Agent)
		if n.Status == "" {
			// Reported recently but no longer registered on the manager.
			n.Status = "disconnected"
		}
		switch r.Kind {
		case "host":
			n.Kind, n.Virt, n.Checked = hostKind(r.Virt), r.Virt, r.Run
			n.Roles = uniqSorted(strings.Fields(r.Roles))
			if n.OS == "" {
				n.OS = r.OS
			}
			if r.VMUUID != "" {
				uuidOf[r.VMUUID] = n.ID
			}
			if r.K8sCA != "" {
				caOf[n.ID] = r.K8sCA
			}
			// The cloud's own answer beats an interface scan: a floating IP
			// is translated at the router and never appears on the host.
			if addr, err := netip.ParseAddr(r.ExtIP); err == nil && addr.Is4() {
				n.PublicIP = addr.String()
			}
		case "target":
			if r.Type != "" && r.Type != "container" {
				services[n.ID] = append(services[n.ID], r.Type)
			}
			for _, g := range strings.Split(r.Guests, ";") {
				p := strings.SplitN(g, "|", 3)
				if len(p) == 3 && p[0] != "" {
					name := p[2]
					if name == "" {
						name = p[1]
					}
					guests = append(guests, guest{uuid: strings.ToLower(p[0]), name: name, hypervisor: n.ID})
				}
			}
		}
	}
	for id, s := range services {
		hosts[id].Services = uniqSorted(s)
	}
	counts, _ := BuildChecks(records, risks, today)
	for id, c := range counts {
		if n, ok := hosts[id]; ok {
			n.Checks = c
		}
	}

	g := Graph{Nodes: []Node{}, Edges: []Edge{}}
	for _, gu := range guests {
		vmID, ok := uuidOf[gu.uuid]
		if !ok {
			vmID = "guest:" + gu.uuid
			if _, dup := hosts[vmID]; !dup {
				hosts[vmID] = &Node{ID: vmID, Kind: KindVM, Name: gu.name, Status: StatusNoAgent}
				order = append(order, vmID)
			}
		} else if hosts[vmID].Kind == KindUnknown {
			hosts[vmID].Kind = KindVM
		}
		if vmID != gu.hypervisor {
			g.Edges = append(g.Edges, Edge{From: vmID, To: gu.hypervisor, Kind: EdgeRunsOn})
		}
		// A machine that runs guests is a physical host unless proven otherwise.
		if hv := hosts[gu.hypervisor]; hv.Kind == KindUnknown {
			hv.Kind = KindBareMetal
		}
	}

	clusters := map[string]int{}
	openstack := 0
	for _, id := range order {
		n := hosts[id]
		if ca := caOf[id]; ca != "" {
			clusters[ca]++
			g.Edges = append(g.Edges, Edge{From: id, To: "k8s:" + ca, Kind: EdgeMemberOf})
		}
		for _, role := range n.Roles {
			if strings.HasPrefix(role, "openstack") {
				openstack++
				g.Edges = append(g.Edges, Edge{From: id, To: "openstack", Kind: EdgeMemberOf})
				break
			}
		}
	}
	// A bastion is tied to the one cluster whose nodes share its /24. What
	// marks a plain VM as the way in is an externally reachable address while
	// the cluster's own nodes have none. Until hosts report that address
	// (config-check ext_ip), the host name is the fallback signal.
	subnets := map[string]map[string]bool{}
	for id, ca := range caOf {
		if n, ok := hosts[id]; ok && ca != "" {
			if net := subnet24(n.IP); net != "" {
				if subnets[net] == nil {
					subnets[net] = map[string]bool{}
				}
				subnets[net][ca] = true
			}
		}
	}
	for _, id := range order {
		n := hosts[id]
		if caOf[id] != "" || !(n.PublicIP != "" || strings.Contains(strings.ToLower(n.Name), "bastion")) {
			continue
		}
		if on := subnets[subnet24(n.IP)]; len(on) == 1 {
			for ca := range on {
				g.Edges = append(g.Edges, Edge{From: id, To: "k8s:" + ca, Kind: EdgeGatewayOf})
			}
		}
	}

	cas := make([]string, 0, len(clusters))
	for ca := range clusters {
		cas = append(cas, ca)
	}
	sort.Strings(cas)
	for _, ca := range cas {
		g.Nodes = append(g.Nodes, Node{ID: "k8s:" + ca, Kind: KindK8s, Name: "Kubernetes " + ca[:min(6, len(ca))], Members: clusters[ca]})
	}
	if openstack > 0 {
		g.Nodes = append(g.Nodes, Node{ID: "openstack", Kind: KindOpenStack, Name: "OpenStack", Members: openstack})
	}
	sort.Strings(order)
	for _, id := range order {
		g.Nodes = append(g.Nodes, *hosts[id])
	}
	sort.SliceStable(g.Edges, func(i, j int) bool {
		if g.Edges[i].Kind != g.Edges[j].Kind {
			return g.Edges[i].Kind < g.Edges[j].Kind
		}
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	return g
}

// HostNodeID is the graph node id of a host or agent name.
func HostNodeID(name string) string { return "host:" + shortName(name) }

// subnet24 returns the /24 an IPv4 address is in, or "" for anything else.
func subnet24(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return ""
	}
	prefix, err := addr.Prefix(24)
	if err != nil {
		return ""
	}
	return prefix.String()
}
