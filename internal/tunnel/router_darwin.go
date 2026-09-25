//go:build darwin

package tunnel

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

type defaultRoute struct {
	gateway net.IP
	iface   string
}

// getDefaultRoutes returns all default routes from the routing table.
func getDefaultRoutes() ([]defaultRoute, error) {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("netstat -rn: %s: %w", string(out), err)
	}

	var routes []defaultRoute
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[0] != "default" {
			continue
		}
		gw := net.ParseIP(fields[1])
		if gw == nil {
			continue
		}
		iface := fields[len(fields)-1]
		iface = strings.TrimRight(iface, "!")
		routes = append(routes, defaultRoute{gateway: gw, iface: iface})
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("could not find default gateway with IP address in routing table")
	}
	return routes, nil
}

// GetDefaultGateway returns the current default gateway IP and interface name on macOS.
func GetDefaultGateway() (net.IP, string, error) {
	routes, err := getDefaultRoutes()
	if err != nil {
		return nil, "", err
	}
	return routes[0].gateway, routes[0].iface, nil
}

// findServerGateway picks the best gateway for the server host route.
// If another VPN is active (utun interface with default route), uses its gateway
// so traffic to the server keeps flowing through it. Otherwise uses the
// physical interface gateway.
func findServerGateway(ownTunName string) (net.IP, string, error) {
	routes, err := getDefaultRoutes()
	if err != nil {
		return nil, "", err
	}

	var vpnRoute, physRoute *defaultRoute
	for i := range routes {
		r := &routes[i]
		if strings.HasPrefix(r.iface, "utun") && r.iface != ownTunName {
			if vpnRoute == nil {
				vpnRoute = r
			}
		} else if !strings.HasPrefix(r.iface, "utun") {
			if physRoute == nil {
				physRoute = r
			}
		}
	}

	if vpnRoute != nil {
		return vpnRoute.gateway, vpnRoute.iface, nil
	}
	if physRoute != nil {
		return physRoute.gateway, physRoute.iface, nil
	}
	return routes[0].gateway, routes[0].iface, nil
}

const scutilDNSKey = "State:/Network/Service/shadowtunnel/DNS"

// setDNSviaScutil creates a system-wide DNS override using scutil.
// Unlike networksetup (which binds DNS to a specific interface and triggers
// scoped routing), scutil with SupplementalMatchDomains="" forces all DNS
// queries through the normal routing table → TUN → DoH interceptor.
func setDNSviaScutil() error {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(
		"d.init\n" +
			"d.add ServerAddresses * 1.1.1.1 1.0.0.1\n" +
			"d.add SupplementalMatchDomains * \"\"\n" +
			"set " + scutilDNSKey + "\n" +
			"quit\n",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil set DNS: %s: %w", string(out), err)
	}
	return nil
}

// removeDNSviaScutil removes the system-wide DNS override.
func removeDNSviaScutil() {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(
		"remove " + scutilDNSKey + "\n" +
			"quit\n",
	)
	cmd.Run()
}

// flushDNSCache clears the macOS DNS cache.
func flushDNSCache() {
	_ = run("dscacheutil", "-flushcache")
	// killall may fail if mDNSResponder is not running; ignore error.
	exec.Command("killall", "-HUP", "mDNSResponder").Run()
}

// CleanupStaleRoutes removes leftover routes and TUN interfaces from a previous
// tunnel session that wasn't cleaned up properly (crash, reboot, SIGKILL).
// Must be called before dialing the server, otherwise stale routes will
// send all traffic (including to the server) into a dead TUN.
func CleanupStaleRoutes(serverIP string) {
	routes, err := getDefaultRoutes()
	if err != nil {
		return
	}

	// Check if default route points to a utun interface — that's our stale tunnel
	for _, r := range routes {
		if !strings.HasPrefix(r.iface, "utun") {
			continue
		}
		// Found a utun with a default route — likely stale tunnel
		// Remove the split-default routes (0/1, 128/1) that we set up
		run("route", "delete", "-net", "0.0.0.0/1")
		run("route", "delete", "-net", "128.0.0.0/1")
		unblockIPv6()

		// Remove server host route if present
		if serverIP != "" {
			run("route", "delete", "-host", serverIP)
		}

		// Remove stale DNS override
		removeDNSviaScutil()
		flushDNSCache()

		log.Printf("  [!] cleaned up stale routes from previous session (via %s)", r.iface)
		return
	}
}

// SetupRoutes configures routing for the VPN tunnel on macOS.
// If customGW is non-empty, it is used as the gateway for the server host route
// instead of the auto-detected default gateway. This is needed when running
// through another VPN (e.g. VLESS) — use VLESS's gateway so traffic to the
// server continues to flow through it.
func SetupRoutes(serverIP, tunName, tunCIDR, customGW string, bypassIPs ...string) (cleanup func(), gwInfo string, err error) {
	var serverGW net.IP
	var gwSource string
	if customGW != "" {
		serverGW = net.ParseIP(customGW)
		if serverGW == nil {
			return nil, "", fmt.Errorf("invalid custom gateway: %s", customGW)
		}
		gwSource = "custom"
	} else {
		gw, iface, err := findServerGateway(tunName)
		if err != nil {
			return nil, "", fmt.Errorf("get gateway: %w", err)
		}
		serverGW = gw
		if strings.HasPrefix(iface, "utun") {
			gwSource = fmt.Sprintf("vpn/%s", iface)
		} else {
			gwSource = iface
		}
	}
	srvIP := net.ParseIP(serverIP)
	if srvIP == nil {
		return nil, "", fmt.Errorf("invalid server IP: %s", serverIP)
	}

	// Parse TUN IP for gateway (peer address)
	tunIP, tunNet, parseErr := net.ParseCIDR(tunCIDR)
	if parseErr != nil {
		return nil, "", fmt.Errorf("parse tun cidr: %w", parseErr)
	}
	tunGW := peerAddress(tunIP, tunNet)

	// Clean up stale DNS override from a previous run
	removeDNSviaScutil()

	// --- DNS leak fix via scutil ---
	dnsSet := false
	if dnsErr := setDNSviaScutil(); dnsErr == nil {
		dnsSet = true
		flushDNSCache()
	}

	// 0. Clean up stale server route from a previous run (e.g. crash/kill without cleanup)
	run("route", "delete", "-host", srvIP.String()) // ignore error — may not exist

	// Also clean up stale TUN routes
	run("route", "delete", "-net", "0.0.0.0/1")
	run("route", "delete", "-net", "128.0.0.0/1")

	// 1. Route to VPN server via gateway (original or custom/VLESS)
	if runErr := run("route", "add", "-host", srvIP.String(), serverGW.String()); runErr != nil {
		return nil, "", fmt.Errorf("add server route: %w", runErr)
	}

	// 1b. Bypass routes for additional IPs (e.g. DoH endpoints)
	var addedBypass []string
	for _, ip := range bypassIPs {
		if ip == "" || ip == serverIP {
			continue
		}
		run("route", "delete", "-host", ip) // clean stale
		if runErr := run("route", "add", "-host", ip, serverGW.String()); runErr == nil {
			addedBypass = append(addedBypass, ip)
		}
	}

	// 2. Override default: 0/1 and 128/1 via TUN gateway
	if runErr := run("route", "add", "-net", "0.0.0.0/1", tunGW.String()); runErr != nil {
		run("route", "delete", "-host", srvIP.String())
		return nil, "", fmt.Errorf("add route 0/1: %w", runErr)
	}
	if runErr := run("route", "add", "-net", "128.0.0.0/1", tunGW.String()); runErr != nil {
		run("route", "delete", "-net", "0.0.0.0/1")
		run("route", "delete", "-host", srvIP.String())
		return nil, "", fmt.Errorf("add route 128/1: %w", runErr)
	}

	// 3. The tunnel is IPv4-only: reject global IPv6 for the session so it
	// cannot bypass the VPN on a network with native IPv6.
	v6Blocked := true
	if blockErr := blockIPv6(); blockErr != nil {
		log.Printf("  [!] could not block IPv6, it may bypass the tunnel: %v", blockErr)
		v6Blocked = false
	}

	gwInfo = fmt.Sprintf("%s (%s)", serverGW, gwSource)
	cleanupFn := func() {
		if v6Blocked {
			unblockIPv6()
		}
		run("route", "delete", "-net", "128.0.0.0/1")
		run("route", "delete", "-net", "0.0.0.0/1")
		run("route", "delete", "-host", srvIP.String())
		for _, ip := range addedBypass {
			run("route", "delete", "-host", ip)
		}

		if dnsSet {
			removeDNSviaScutil()
			flushDNSCache()
		}
	}

	return cleanupFn, gwInfo, nil
}

// ipv6Halves covers all of IPv6 with two /1 routes. They are more specific
// than any default route but less specific than on-link prefixes, so the LAN
// (link-local, ULA /64s) keeps working while everything else is blocked.
var ipv6Halves = []string{"::/1", "8000::/1"}

// blockIPv6 installs reject routes for ipv6Halves. -reject (not -blackhole)
// makes connects fail at once, so apps fall back to IPv4 without a timeout.
func blockIPv6() error {
	for _, cidr := range ipv6Halves {
		run("route", "-n", "delete", "-inet6", "-net", cidr) // stale from a crash
		if err := run("route", "-n", "add", "-inet6", "-net", cidr, "::1", "-reject"); err != nil {
			unblockIPv6()
			return err
		}
	}
	return nil
}

func unblockIPv6() {
	for _, cidr := range ipv6Halves {
		run("route", "-n", "delete", "-inet6", "-net", cidr)
	}
}
