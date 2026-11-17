package wazuh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const (
	// Inventory is one request per agent; beyond this many agents the map
	// keeps the registration address only.
	maxInventoryAgents = 2000
	maxAddrsPerHost    = 32
)

// Addr is one address configured on a host interface, from the agent's
// inventory (syscollector).
type Addr struct {
	IP     string `json:"ip"`
	Iface  string `json:"iface,omitempty"`
	Public bool   `json:"public,omitempty"`
}

// Interfaces that carry container, pod or tenant-network plumbing rather
// than the host's own addresses. kube-ipvs0 alone holds every service IP.
var plumbingPrefixes = []string{
	"lo", "docker", "veth", "cni", "flannel", "cali", "lxc", "virbr", "tap", "tun", "kube-ipvs", "cilium",
	"tunl", "vxlan", "nodelocaldns", "dummy", "ovs-system", "genev", "qbr", "qvo", "qvb", "qr-", "qg-", "kube-bridge",
}

// Docker names its user-defined bridges br-<12 hex>; br-ex and other named
// bridges are real host uplinks and stay.
var dockerBridge = regexp.MustCompile(`^br-[0-9a-f]{12}$`)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func plumbingIface(name string) bool {
	if dockerBridge.MatchString(name) {
		return true
	}
	for _, p := range plumbingPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// publicAddr reports whether ip is routable on the internet. Carrier-grade
// NAT space is not: it never is the address a host is reached at from outside.
func publicAddr(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
}

// HostAddrs turns raw inventory rows into the addresses worth showing:
// host-level, unique, public first, then by interface and address.
func HostAddrs(rows []Addr) []Addr {
	out := []Addr{}
	seen := map[string]bool{}
	for _, r := range rows {
		// Inventory addresses may carry a zone ("fe80::1%eth0") or prefix.
		raw := strings.TrimSpace(r.IP)
		if i := strings.IndexAny(raw, "/%"); i >= 0 {
			raw = raw[:i]
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil || !ip.IsGlobalUnicast() || plumbingIface(r.Iface) {
			continue
		}
		ip = ip.Unmap()
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, Addr{IP: ip.String(), Iface: r.Iface, Public: publicAddr(ip)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Public != out[j].Public {
			return out[i].Public
		}
		if out[i].Iface != out[j].Iface {
			return out[i].Iface < out[j].Iface
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > maxAddrsPerHost {
		out = out[:maxAddrsPerHost]
	}
	return out
}

// NetAddrs fills Addrs on every agent from the manager's inventory API. It
// stops at the first permission error, which applies to all agents alike;
// an agent without inventory data is simply left without addresses.
func NetAddrs(ctx context.Context, c Config, a Credentials, agents []Agent) error {
	if len(agents) > maxInventoryAgents {
		return fmt.Errorf("agent 가 %d대를 넘어 인터페이스 주소를 수집하지 않았습니다", maxInventoryAgents)
	}
	h := httpClient(c)
	defer h.CloseIdleConnections()
	token, err := managerToken(ctx, h, c, a)
	if err != nil {
		return err
	}
	for i := range agents {
		r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/syscollector/%s/netaddr?select=iface,address&limit=500", c.ManagerURL, agents[i].ID), nil)
		if err != nil {
			return invalid("manager API 요청을 만들지 못했습니다")
		}
		r.Header.Set("Authorization", "Bearer "+token)
		b, err := do(ctx, h, r, "인벤토리")
		if err != nil {
			if errors.Is(err, ErrPermission) || errors.Is(err, ErrAuth) || errors.Is(err, ErrUnavailable) || ctx.Err() != nil {
				return err
			}
			continue // this agent has no inventory to offer
		}
		var page struct {
			Data struct {
				Items []struct {
					Iface   string `json:"iface"`
					Address string `json:"address"`
				} `json:"affected_items"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &page) != nil {
			continue
		}
		rows := make([]Addr, 0, len(page.Data.Items))
		for _, it := range page.Data.Items {
			rows = append(rows, Addr{IP: it.Address, Iface: it.Iface})
		}
		agents[i].Addrs = HostAddrs(rows)
	}
	return nil
}
