package wazuh

import (
	"reflect"
	"testing"
	"time"
)

func TestHostAddrs(t *testing.T) {
	got := HostAddrs([]Addr{
		{IP: "127.0.0.1", Iface: "lo"},
		{IP: "10.0.5.6", Iface: "bond0"},
		{IP: "fe80::1%bond0", Iface: "bond0"},        // link-local
		{IP: "10.233.0.1", Iface: "kube-ipvs0"},      // service IP
		{IP: "172.17.0.1", Iface: "docker0"},         // container bridge
		{IP: "172.18.0.1", Iface: "br-0123456789ab"}, // docker user bridge
		{IP: "203.0.114.10/24", Iface: "br-ex"},      // named bridge = real uplink
		{IP: "100.64.3.4", Iface: "eth1"},            // CGNAT is not public
		{IP: "10.0.5.6", Iface: "bond0.100"},         // duplicate
		{IP: "not-an-ip", Iface: "eth0"},
		{IP: "2001:4860:4860::8888", Iface: "eth0"},
	})
	want := []Addr{
		{IP: "203.0.114.10", Iface: "br-ex", Public: true},
		{IP: "2001:4860:4860::8888", Iface: "eth0", Public: true},
		{IP: "10.0.5.6", Iface: "bond0"},
		{IP: "100.64.3.4", Iface: "eth1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HostAddrs =\n%+v\nwant\n%+v", got, want)
	}
}

func TestHostAddrsCap(t *testing.T) {
	rows := []Addr{}
	for i := 0; i < 60; i++ {
		rows = append(rows, Addr{IP: "10.0.0." + string(rune('0'+i%10)) + string(rune('0'+i/10)), Iface: "eth0"})
	}
	if n := len(HostAddrs(rows)); n > maxAddrsPerHost {
		t.Fatalf("got %d addresses, cap is %d", n, maxAddrsPerHost)
	}
}

func TestBuildGraphPublicIP(t *testing.T) {
	agents := []Agent{{ID: "001", Name: "web01", IP: "10.0.0.5", Status: "active",
		Addrs: []Addr{{IP: "198.51.100.7", Iface: "eth1", Public: true}, {IP: "10.0.0.5", Iface: "eth0"}}}}
	g := BuildGraph(agents, nil, nil, time.Now())
	if len(g.Nodes) != 1 || g.Nodes[0].PublicIP != "198.51.100.7" || len(g.Nodes[0].Addrs) != 2 {
		t.Fatalf("node = %+v", g.Nodes)
	}
}

func TestBuildGraphBastionGateway(t *testing.T) {
	agent := func(name, ip string) Agent { return Agent{ID: name, Name: name, IP: ip, Status: "active"} }
	host := func(name, ca string) CheckRecord {
		return CheckRecord{Agent: name, Kind: "host", Virt: "OpenStack Foundation OpenStack Nova", K8sCA: ca}
	}
	agents := []Agent{
		agent("wiki-001", "192.168.40.142"), agent("wiki-wk-001", "192.168.40.85"),
		agent("arc-001", "192.168.41.13"),
		agent("wiki-bastion-001", "192.168.40.233"), // name + subnet match one cluster
		agent("lost-bastion-001", "10.9.9.9"),       // no cluster on its network
		agent("jumpbox", "192.168.41.50"),           // right network, but not named a bastion
		agent("shared-a", "192.168.30.5"), agent("shared-b", "192.168.30.6"),
		agent("shared-bastion", "192.168.30.9"), // two clusters share the /24: ambiguous
	}
	records := []CheckRecord{
		host("wiki-001", "aaaaaa11"), host("wiki-wk-001", "aaaaaa11"), host("arc-001", "bbbbbb22"),
		host("wiki-bastion-001", ""), host("lost-bastion-001", ""), host("jumpbox", ""),
		host("shared-a", "cccccc33"), host("shared-b", "dddddd44"), host("shared-bastion", ""),
	}
	got := []Edge{}
	for _, e := range BuildGraph(agents, records, nil, time.Now()).Edges {
		if e.Kind == EdgeGatewayOf {
			got = append(got, e)
		}
	}
	want := []Edge{{From: "host:wiki-bastion-001", To: "k8s:aaaaaa11", Kind: EdgeGatewayOf}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway edges = %+v, want %+v", got, want)
	}
}

// A host that reports an external address fronts the cluster on its network,
// whatever it is called; cluster nodes themselves are never gateways.
func TestBuildGraphGatewayByExternalIP(t *testing.T) {
	agents := []Agent{
		{ID: "1", Name: "node-a", IP: "192.168.42.11", Status: "active"},
		{ID: "2", Name: "node-b", IP: "192.168.42.12", Status: "active"},
		{ID: "3", Name: "jump01", IP: "192.168.42.56", Status: "active"},
		{ID: "4", Name: "plain-vm", IP: "192.168.42.70", Status: "active"},
	}
	nova := "OpenStack Foundation OpenStack Nova"
	records := []CheckRecord{
		{Agent: "node-a", Kind: "host", Virt: nova, K8sCA: "aaaaaa11", ExtIP: "203.0.113.1"}, // a node with a floating IP is still a node
		{Agent: "node-b", Kind: "host", Virt: nova, K8sCA: "aaaaaa11"},
		{Agent: "jump01", Kind: "host", Virt: nova, ExtIP: "203.0.113.74"},
		{Agent: "plain-vm", Kind: "host", Virt: nova, ExtIP: "not-an-ip"},
	}
	g := BuildGraph(agents, records, nil, time.Now())
	got := []Edge{}
	for _, e := range g.Edges {
		if e.Kind == EdgeGatewayOf {
			got = append(got, e)
		}
	}
	if want := []Edge{{From: "host:jump01", To: "k8s:aaaaaa11", Kind: EdgeGatewayOf}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway edges = %+v, want %+v", got, want)
	}
	for _, n := range g.Nodes {
		want := map[string]string{"host:jump01": "203.0.113.74", "host:node-a": "203.0.113.1"}[n.ID]
		if n.PublicIP != want {
			t.Errorf("%s PublicIP = %q, want %q", n.ID, n.PublicIP, want)
		}
	}
}
