package routing

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
)

const (
	MarkTunnel  = "0x1"
	MarkDirect  = "0x0"
	TableTunnel = "100"

	IPSetDirect = "direct-ips"
	IPSetProxy  = "proxy-ips"

	// Sticky (CONNMARK) mode: each tunnel gets a dedicated fwmark, routing table
	// and default route. New tunnel-bound flows are hashed to a mark by a custom
	// chain and the mark is saved to conntrack; subsequent packets of the flow
	// restore that mark and pin to the same tunnel. Rebuilding the active set
	// only rewrites the selection chain, leaving established flows untouched.
	stickyMarkBase  = 0x10 // tunnel i → fwmark 0x10+i (supports up to 16 tunnels)
	stickyMarkMask  = "0xf0"
	stickyTableBase = 101 // tunnel i → table 101+i
	stickyChain     = "FTYB_SEL"
)

func stickyMark(i int) string  { return fmt.Sprintf("0x%x", stickyMarkBase+i) }
func stickyTable(i int) string { return fmt.Sprintf("%d", stickyTableBase+i) }

type Manager struct {
	wgIface      string
	tunIfaces    []string // all configured tunnel interfaces; ECMP is built across the active subset
	wgSubnet     string
	serverIPs    []string // every abroad VPS IP — each gets its own bypass route
	outboundMark int      // SO_MARK from a local proxy (e.g. XRay); 0 means disabled
	sticky       bool     // CONNMARK per-flow pinning instead of plain ECMP route

	ifaceIdx map[string]int // tunnel iface name → index (mark/table lookup)

	mu          sync.Mutex
	activeIface []string // current ECMP next-hop set (subset of tunIfaces)
}

// NewManager configures a routing manager for one or more tunnel interfaces.
// All abroad server IPs are bypassed (routed via the default gateway, not via
// any tunnel) so the underlying tunnel TCP flows themselves are not recursively
// captured by policy routing.
//
// Two ingress sources are supported and may be combined:
//   - wgIface != "":      mangle PREROUTING -i wgIface (WireGuard mode)
//   - outboundMark > 0:   mangle OUTPUT -m mark --mark <outboundMark> (XRay/proxy mode)
//
// GeoIP-based direct/proxy ipsets apply to both ingress sources.
func NewManager(wgIface string, tunIfaces []string, wgSubnet string, serverIPs []string, outboundMark int, sticky bool) *Manager {
	idx := make(map[string]int, len(tunIfaces))
	for i, t := range tunIfaces {
		idx[t] = i
	}
	return &Manager{
		wgIface:      wgIface,
		tunIfaces:    append([]string(nil), tunIfaces...),
		wgSubnet:     wgSubnet,
		serverIPs:    append([]string(nil), serverIPs...),
		outboundMark: outboundMark,
		sticky:       sticky,
		ifaceIdx:     idx,
	}
}

// Setup creates ipsets, loads subnets, configures iptables mangle rules,
// policy routing, and NAT masquerade. The tunnel default route initially uses
// every configured tunnel interface as ECMP next-hops; call RebuildECMP later
// to narrow it to only the healthy subset.
func (m *Manager) Setup(directSubnets []*net.IPNet) error {
	// 0. Ensure every server IP always routes via default gateway (not through tunnel)
	for _, ip := range m.serverIPs {
		if err := m.addServerBypass(ip); err != nil {
			return fmt.Errorf("server bypass route %s: %w", ip, err)
		}
	}

	// 1. Create ipsets
	if err := m.createIPSets(); err != nil {
		return fmt.Errorf("create ipsets: %w", err)
	}

	// 2. Load direct (RU) subnets
	if err := m.loadDirectSubnets(directSubnets); err != nil {
		return fmt.Errorf("load direct subnets: %w", err)
	}

	// 3+4. Traffic steering. Sticky (CONNMARK) and plain-ECMP use different
	// mangle rules and routing tables; pick one.
	if m.sticky {
		if m.wgIface == "" {
			return fmt.Errorf("routing_mode ecmp-sticky requires WireGuard ingress (transit mode not supported — use ecmp or active-standby)")
		}
		if len(m.tunIfaces) > 16 {
			return fmt.Errorf("routing_mode ecmp-sticky supports at most 16 tunnels (got %d)", len(m.tunIfaces))
		}
		if err := m.setupStickyRouting(); err != nil {
			return fmt.Errorf("setup sticky routing: %w", err)
		}
		if err := m.setupStickyMangle(); err != nil {
			return fmt.Errorf("setup sticky mangle: %w", err)
		}
	} else {
		// iptables mangle: mark packets from wg0
		if err := m.setupMangle(); err != nil {
			return fmt.Errorf("setup mangle: %w", err)
		}
		// Policy routing: fwmark 0x1 → table 100 → default dev stun0
		if err := m.setupPolicyRouting(); err != nil {
			return fmt.Errorf("setup policy routing: %w", err)
		}
	}

	// 5. NAT masquerade on eth0 and stun0
	if err := m.setupNAT(); err != nil {
		return fmt.Errorf("setup NAT: %w", err)
	}

	return nil
}

// Apply installs the active tunnel set using whichever steering mode is
// configured. In sticky mode it rewrites only the flow-selection chain (leaving
// established flows pinned); otherwise it replaces the ECMP default route.
func (m *Manager) Apply(active []string) error {
	if m.sticky {
		return m.RebuildSticky(active)
	}
	return m.RebuildECMP(active)
}

// Teardown removes all routing rules, iptables rules, and ipsets.
func (m *Manager) Teardown() {
	// Remove server bypass routes
	for _, ip := range m.serverIPs {
		run("ip", "route", "del", ip+"/32")
	}

	if m.sticky {
		// Remove sticky (CONNMARK) steering: PREROUTING chain, selection chain,
		// per-tunnel ip rules + tables.
		m.teardownSticky()
	} else {
		// Remove policy routing
		run("ip", "rule", "del", "fwmark", MarkTunnel, "table", TableTunnel)
		run("ip", "route", "flush", "table", TableTunnel)

		// Remove mangle rules — WG-side (PREROUTING)
		if m.wgIface != "" {
			run("iptables", "-t", "mangle", "-D", "PREROUTING",
				"-i", m.wgIface, "-j", "MARK", "--set-mark", MarkTunnel)
			run("iptables", "-t", "mangle", "-D", "PREROUTING",
				"-i", m.wgIface, "-m", "set", "--match-set", IPSetDirect, "dst",
				"-j", "MARK", "--set-mark", MarkDirect)
			run("iptables", "-t", "mangle", "-D", "PREROUTING",
				"-i", m.wgIface, "-m", "set", "--match-set", IPSetProxy, "dst",
				"-j", "MARK", "--set-mark", MarkTunnel)
		}
	}

	// Remove mangle rules — proxy-side (OUTPUT)
	if m.outboundMark > 0 {
		mark := fmt.Sprintf("0x%x", m.outboundMark)
		run("iptables", "-t", "mangle", "-D", "OUTPUT",
			"-m", "mark", "--mark", mark, "-j", "MARK", "--set-mark", MarkTunnel)
		run("iptables", "-t", "mangle", "-D", "OUTPUT",
			"-m", "mark", "--mark", mark,
			"-m", "set", "--match-set", IPSetDirect, "dst",
			"-j", "MARK", "--set-mark", MarkDirect)
		run("iptables", "-t", "mangle", "-D", "OUTPUT",
			"-m", "mark", "--mark", mark,
			"-m", "set", "--match-set", IPSetProxy, "dst",
			"-j", "MARK", "--set-mark", MarkTunnel)
	}

	// Remove NAT — one MASQUERADE per tunnel interface.
	for _, t := range m.tunIfaces {
		// WG-mode: source-restricted to wgSubnet
		if m.wgSubnet != "" {
			run("iptables", "-t", "nat", "-D", "POSTROUTING",
				"-s", m.wgSubnet, "-o", t, "-j", "MASQUERADE")
		}
		// Transit-mode: any-source MASQUERADE on tunnel interface
		if m.outboundMark > 0 {
			run("iptables", "-t", "nat", "-D", "POSTROUTING",
				"-o", t, "-j", "MASQUERADE")
		}
		if m.wgIface != "" {
			run("iptables", "-D", "FORWARD", "-i", t, "-o", m.wgIface, "-j", "ACCEPT")
		}
	}
	if m.wgIface != "" && m.wgSubnet != "" {
		run("iptables", "-t", "nat", "-D", "POSTROUTING",
			"-s", m.wgSubnet, "!", "-o", m.wgIface, "-j", "MASQUERADE")
	}

	// Remove FORWARD rules — WG-only
	if m.wgIface != "" {
		run("iptables", "-D", "FORWARD", "-i", m.wgIface, "-j", "ACCEPT")
		run("iptables", "-D", "FORWARD", "-o", m.wgIface, "-m", "state",
			"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		run("iptables", "-t", "mangle", "-D", "FORWARD",
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu")
	}

	// Destroy ipsets
	run("ipset", "destroy", IPSetDirect)
	run("ipset", "destroy", IPSetProxy)
	run("ipset", "destroy", IPSetDirect+"-tmp")
	run("ipset", "destroy", IPSetProxy+"-tmp")
}

// RebuildECMP replaces the default route in TableTunnel with a multipath route
// across the given tunnel interfaces. Called whenever the active member set
// changes (peer evicted or recovered). If active is empty, the route is left
// in place — the kernel still tries the last hop, which is harmless if all
// peers are down (traffic just fails until at least one recovers).
func (m *Manager) RebuildECMP(active []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(active) == 0 {
		log.Printf("[routing] RebuildECMP: no active tunnels — keeping previous route")
		return nil
	}

	// Skip if unchanged.
	if sameStringSet(active, m.activeIface) {
		return nil
	}

	args := []string{"route", "replace", "default", "table", TableTunnel}
	if len(active) == 1 {
		args = append(args, "dev", active[0])
	} else {
		// Multipath: nexthop dev tunA weight 1 nexthop dev tunB weight 1 ...
		for _, ifc := range active {
			args = append(args, "nexthop", "dev", ifc, "weight", "1")
		}
	}

	if err := run("ip", args...); err != nil {
		return fmt.Errorf("install ECMP route: %w", err)
	}

	m.activeIface = append([]string(nil), active...)
	log.Printf("[routing] ECMP rebuilt across %d tunnels: %s", len(active), strings.Join(active, ", "))
	return nil
}

// stickyPinnedMatch is the "flow already pinned to some tunnel" mark match.
func stickyPinnedMatch() string {
	return fmt.Sprintf("0x%x/%s", stickyMarkBase, stickyMarkMask)
}

// ifaceExists reports whether a network device with the given name is present.
func ifaceExists(name string) bool {
	return exec.Command("ip", "link", "show", "dev", name).Run() == nil
}

// filterIfaces returns the subset of ifaces for which pred returns true,
// preserving order. Split out from device probing so it is unit-testable.
func filterIfaces(ifaces []string, pred func(string) bool) []string {
	out := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		if pred(i) {
			out = append(out, i)
		}
	}
	return out
}

// existingIfaces keeps only the configured tunnels whose device actually exists.
// A configured-but-dead upstream never created its stunN device; building a
// route across it fails with "Cannot find device" and (historically) crashed
// the gateway on startup. The pool watcher installs the full set via Apply()
// as members recover.
func existingIfaces(ifaces []string) []string {
	return filterIfaces(ifaces, ifaceExists)
}

// setupStickyRouting installs, for every configured tunnel, a dedicated fwmark
// rule + routing table whose default route pins to that tunnel's device. These
// are static for the process lifetime: a flow pinned to a currently-down tunnel
// simply fails (its exit IP is gone anyway), while flows on healthy tunnels are
// never disturbed by a membership change — that is the whole point.
func (m *Manager) setupStickyRouting() error {
	for i, ifc := range m.tunIfaces {
		mark := stickyMark(i)
		table := stickyTable(i)
		if err := run("ip", "rule", "add", "fwmark", mark, "table", table); err != nil {
			if !strings.Contains(err.Error(), "exists") {
				return err
			}
		}
		// Only pin the per-tunnel default route if the device exists — a dead
		// upstream has no stunN yet. RebuildSticky re-installs it when the
		// member later brings its device up.
		if ifaceExists(ifc) {
			if err := run("ip", "route", "replace", "default", "dev", ifc, "table", table); err != nil {
				return fmt.Errorf("sticky route %s (table %s): %w", ifc, table, err)
			}
		}
	}
	// Flow-selection chain (populated by RebuildSticky). -N may fail if it
	// already exists from a prior run; flush to be safe.
	run("iptables", "-t", "mangle", "-N", stickyChain)
	run("iptables", "-t", "mangle", "-F", stickyChain)
	// Initial selection across tunnels whose device exists; narrowed/widened to
	// the healthy subset as the pool reports in.
	return m.RebuildSticky(existingIfaces(m.tunIfaces))
}

// setupStickyMangle installs the PREROUTING classification for WireGuard
// ingress. Order matters: restore the pinned mark first, short-circuit already
// pinned flows, then classify new flows (force-proxy → select tunnel, direct →
// leave unmarked so the main table sends it out directly, everything else →
// select tunnel). -g (goto) is used for the selection chain so a selected flow
// does not fall through into the direct rule.
func (m *Manager) setupStickyMangle() error {
	wg := m.wgIface
	steps := [][]string{
		{"-t", "mangle", "-A", "PREROUTING", "-i", wg, "-j", "CONNMARK", "--restore-mark"},
		{"-t", "mangle", "-A", "PREROUTING", "-i", wg, "-m", "mark", "--mark", stickyPinnedMatch(), "-j", "RETURN"},
		{"-t", "mangle", "-A", "PREROUTING", "-i", wg, "-m", "set", "--match-set", IPSetProxy, "dst", "-g", stickyChain},
		{"-t", "mangle", "-A", "PREROUTING", "-i", wg, "-m", "set", "--match-set", IPSetDirect, "dst", "-j", "RETURN"},
		{"-t", "mangle", "-A", "PREROUTING", "-i", wg, "-g", stickyChain},
	}
	for _, s := range steps {
		if err := run("iptables", s...); err != nil {
			return err
		}
	}
	return nil
}

// RebuildSticky repopulates the flow-selection chain to distribute NEW
// tunnel-bound flows across the given healthy tunnels (via -m statistic nth),
// saving each pick to conntrack. Established flows keep their previously saved
// mark and are not touched, so evicting/re-adding a peer never rehashes live
// flows on the surviving tunnels.
func (m *Manager) RebuildSticky(active []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(active) == 0 {
		log.Printf("[routing] RebuildSticky: no active tunnels — keeping previous selection")
		return nil
	}
	if sameStringSet(active, m.activeIface) {
		return nil
	}

	// (Re)pin the per-tunnel default route for each active tunnel. setupStickyRouting
	// skips devices that didn't exist yet (dead upstream on startup); doing it here
	// too means a member that comes up later gets its table populated the moment it
	// joins the active set.
	for _, ifc := range active {
		idx, ok := m.ifaceIdx[ifc]
		if !ok {
			return fmt.Errorf("unknown tunnel iface %q", ifc)
		}
		if err := run("ip", "route", "replace", "default", "dev", ifc, "table", stickyTable(idx)); err != nil {
			return fmt.Errorf("sticky route %s: %w", ifc, err)
		}
	}

	if err := run("iptables", "-t", "mangle", "-F", stickyChain); err != nil {
		return fmt.Errorf("flush %s: %w", stickyChain, err)
	}

	k := len(active)
	for j, ifc := range active {
		idx, ok := m.ifaceIdx[ifc]
		if !ok {
			return fmt.Errorf("unknown tunnel iface %q", ifc)
		}
		mark := stickyMark(idx)
		if j < k-1 {
			// nth --every (k-j) selects 1/(k-j) of the packets reaching this
			// rule; chaining gives an even split across the active set.
			every := fmt.Sprintf("%d", k-j)
			if err := run("iptables", "-t", "mangle", "-A", stickyChain,
				"-m", "statistic", "--mode", "nth", "--every", every, "--packet", "0",
				"-j", "MARK", "--set-mark", mark); err != nil {
				return err
			}
		} else {
			if err := run("iptables", "-t", "mangle", "-A", stickyChain,
				"-j", "MARK", "--set-mark", mark); err != nil {
				return err
			}
		}
	}
	if err := run("iptables", "-t", "mangle", "-A", stickyChain, "-j", "CONNMARK", "--save-mark"); err != nil {
		return err
	}

	m.activeIface = append([]string(nil), active...)
	log.Printf("[routing] sticky selection rebuilt across %d tunnels: %s", k, strings.Join(active, ", "))
	return nil
}

// teardownSticky removes everything setupStickyRouting/setupStickyMangle added.
func (m *Manager) teardownSticky() {
	wg := m.wgIface
	for _, s := range [][]string{
		{"-t", "mangle", "-D", "PREROUTING", "-i", wg, "-j", "CONNMARK", "--restore-mark"},
		{"-t", "mangle", "-D", "PREROUTING", "-i", wg, "-m", "mark", "--mark", stickyPinnedMatch(), "-j", "RETURN"},
		{"-t", "mangle", "-D", "PREROUTING", "-i", wg, "-m", "set", "--match-set", IPSetProxy, "dst", "-g", stickyChain},
		{"-t", "mangle", "-D", "PREROUTING", "-i", wg, "-m", "set", "--match-set", IPSetDirect, "dst", "-j", "RETURN"},
		{"-t", "mangle", "-D", "PREROUTING", "-i", wg, "-g", stickyChain},
	} {
		run("iptables", s...)
	}
	run("iptables", "-t", "mangle", "-F", stickyChain)
	run("iptables", "-t", "mangle", "-X", stickyChain)
	for i := range m.tunIfaces {
		run("ip", "rule", "del", "fwmark", stickyMark(i), "table", stickyTable(i))
		run("ip", "route", "flush", "table", stickyTable(i))
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			return false
		}
	}
	return true
}

// UpdateDirectIPs atomically replaces the direct-ips ipset via swap.
func (m *Manager) UpdateDirectIPs(subnets []*net.IPNet) error {
	tmpSet := IPSetDirect + "-tmp"

	// Create temp set
	if err := run("ipset", "create", tmpSet, "hash:net", "-exist"); err != nil {
		return err
	}
	// Flush it
	run("ipset", "flush", tmpSet)

	// Add all subnets
	for _, s := range subnets {
		run("ipset", "add", tmpSet, s.String(), "-exist")
	}

	// Atomic swap
	if err := run("ipset", "swap", tmpSet, IPSetDirect); err != nil {
		run("ipset", "destroy", tmpSet)
		return fmt.Errorf("ipset swap: %w", err)
	}

	// Cleanup temp
	run("ipset", "destroy", tmpSet)

	log.Printf("[routing] updated direct-ips: %d subnets", len(subnets))
	return nil
}

// AddProxyIP adds an IP to the proxy-ips ipset.
func (m *Manager) AddProxyIP(ip string) error {
	return run("ipset", "add", IPSetProxy, ip, "-exist")
}

// AddDirectIP adds an IP to the direct-ips ipset.
func (m *Manager) AddDirectIP(ip string) error {
	return run("ipset", "add", IPSetDirect, ip, "-exist")
}

// addServerBypass adds a host route for the abroad server IP via the current default gateway.
// This ensures the gateway's tunnel traffic never gets caught by policy routing.
func (m *Manager) addServerBypass(serverIP string) error {
	if serverIP == "" {
		return nil
	}

	// Get current default gateway
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return fmt.Errorf("get default route: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 3 || fields[0] != "default" {
		return fmt.Errorf("cannot parse default route: %s", string(out))
	}
	// "default via <gw> dev <iface> ..."
	gateway := fields[2]
	dev := ""
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			dev = fields[i+1]
			break
		}
	}

	// Delete stale route if exists
	run("ip", "route", "del", serverIP+"/32")

	args := []string{"route", "add", serverIP + "/32", "via", gateway}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	if err := run("ip", args...); err != nil {
		return fmt.Errorf("add server bypass: %w", err)
	}

	log.Printf("[routing] server bypass: %s via %s", serverIP, gateway)
	return nil
}

func (m *Manager) createIPSets() error {
	if err := run("ipset", "create", IPSetDirect, "hash:net", "-exist"); err != nil {
		return err
	}
	if err := run("ipset", "create", IPSetProxy, "hash:net", "-exist"); err != nil {
		return err
	}
	return nil
}

func (m *Manager) loadDirectSubnets(subnets []*net.IPNet) error {
	for _, s := range subnets {
		if err := run("ipset", "add", IPSetDirect, s.String(), "-exist"); err != nil {
			return err
		}
	}
	log.Printf("[routing] loaded %d direct subnets", len(subnets))
	return nil
}

func (m *Manager) setupMangle() error {
	// Source 1 (WireGuard): three rules in PREROUTING matched by -i wgIface.
	if m.wgIface != "" {
		if err := run("iptables", "-t", "mangle", "-A", "PREROUTING",
			"-i", m.wgIface, "-j", "MARK", "--set-mark", MarkTunnel); err != nil {
			return err
		}
		if err := run("iptables", "-t", "mangle", "-A", "PREROUTING",
			"-i", m.wgIface, "-m", "set", "--match-set", IPSetDirect, "dst",
			"-j", "MARK", "--set-mark", MarkDirect); err != nil {
			return err
		}
		if err := run("iptables", "-t", "mangle", "-A", "PREROUTING",
			"-i", m.wgIface, "-m", "set", "--match-set", IPSetProxy, "dst",
			"-j", "MARK", "--set-mark", MarkTunnel); err != nil {
			return err
		}
	}

	// Source 2 (local proxy via SO_MARK): three rules in OUTPUT matched by mark.
	// XRay (or any process) sets SO_MARK on its outbound sockets; we promote
	// it to fwmark 0x1 (tunnel) by default, but flip to 0x0 (direct) for RU
	// destinations and back to 0x1 for force-proxy destinations. The OUTPUT
	// chain runs after the socket layer, so SO_MARK is visible there.
	if m.outboundMark > 0 {
		mark := fmt.Sprintf("0x%x", m.outboundMark)
		if err := run("iptables", "-t", "mangle", "-A", "OUTPUT",
			"-m", "mark", "--mark", mark, "-j", "MARK", "--set-mark", MarkTunnel); err != nil {
			return err
		}
		if err := run("iptables", "-t", "mangle", "-A", "OUTPUT",
			"-m", "mark", "--mark", mark,
			"-m", "set", "--match-set", IPSetDirect, "dst",
			"-j", "MARK", "--set-mark", MarkDirect); err != nil {
			return err
		}
		if err := run("iptables", "-t", "mangle", "-A", "OUTPUT",
			"-m", "mark", "--mark", mark,
			"-m", "set", "--match-set", IPSetProxy, "dst",
			"-j", "MARK", "--set-mark", MarkTunnel); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setupPolicyRouting() error {
	// Add rule: fwmark 0x1 → table 100
	if err := run("ip", "rule", "add", "fwmark", MarkTunnel, "table", TableTunnel); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return err
		}
	}

	// Initial default route across only the tunnel devices that actually exist.
	// A configured-but-dead upstream never created its stunN device, and routing
	// across a missing device fails with "Cannot find device" — which used to
	// crash the whole gateway on startup whenever one pool member was down. The
	// pool watcher widens this to all healthy peers via Apply()/RebuildECMP once
	// they connect and provision their device.
	initial := existingIfaces(m.tunIfaces)
	if len(initial) == 0 {
		log.Printf("[routing] setupPolicyRouting: no tunnel devices up yet — deferring route to first Apply")
		return nil
	}
	if err := m.RebuildECMP(initial); err != nil {
		return fmt.Errorf("install initial ECMP route: %w", err)
	}

	return nil
}

func (m *Manager) setupNAT() error {
	// MASQUERADE per tunnel interface — packets leaving via stunN get SNAT'd
	// to that interface's tunnel IP. WG-mode restricts to wgSubnet; transit
	// mode (XRay/proxy) accepts any-source on the host.
	for _, t := range m.tunIfaces {
		if m.wgIface != "" && m.wgSubnet != "" {
			if err := run("iptables", "-t", "nat", "-A", "POSTROUTING",
				"-s", m.wgSubnet, "-o", t, "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
		if m.outboundMark > 0 {
			if err := run("iptables", "-t", "nat", "-A", "POSTROUTING",
				"-o", t, "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
	}

	// MASQUERADE for direct (non-tunnel) WG traffic — only relevant when WG
	// is enabled. In transit mode the host already MASQUERADEs its own
	// outbound traffic via the default ISP route, so no extra rule needed.
	if m.wgIface != "" && m.wgSubnet != "" {
		if err := run("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", m.wgSubnet, "!", "-o", m.wgIface, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}

	// FORWARD rules — only required when WG forwards traffic between two
	// network interfaces. In transit mode, everything originates from local
	// processes (XRay), which doesn't go through FORWARD at all.
	if m.wgIface != "" {
		if err := run("iptables", "-A", "FORWARD",
			"-i", m.wgIface, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := run("iptables", "-A", "FORWARD",
			"-o", m.wgIface, "-m", "state", "--state", "RELATED,ESTABLISHED",
			"-j", "ACCEPT"); err != nil {
			return err
		}
		for _, t := range m.tunIfaces {
			if err := run("iptables", "-A", "FORWARD",
				"-i", t, "-o", m.wgIface, "-j", "ACCEPT"); err != nil {
				return err
			}
		}

		// Clamp TCP MSS to the path MTU on forwarded SYN/SYN-ACK. The tunnel
		// (stunN) devices are 1420, so this caps negotiated MSS at ~1380 in
		// both directions and prevents oversized segments being dropped at the
		// 1420 boundary with DF set and no ICMP-needed returning — the classic
		// "small requests work, large transfers / video stall" failure.
		if err := run("iptables", "-t", "mangle", "-A", "FORWARD",
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"); err != nil {
			return err
		}
	}

	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
