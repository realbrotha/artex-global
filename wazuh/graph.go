package wazuh

import (
	"sort"
	"strings"
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
)

type Node struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Status   string   `json:"status,omitempty"`
	IP       string   `json:"ip,omitempty"`
	OS       string   `json:"os,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Services []string `json:"services,omitempty"`
	Virt     string   `json:"virt,omitempty"`
	LastSeen string   `json:"last_seen,omitempty"`
	Checked  string   `json:"checked,omitempty"` // latest config-check run
	Members  int      `json:"members,omitempty"` // group nodes only
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
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
func BuildGraph(agents []Agent, records []CheckRecord) Graph {
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
