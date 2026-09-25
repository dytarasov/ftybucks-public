//go:build linux

package tunnel

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// GetDefaultGateway returns the current default gateway IP and interface name.
func GetDefaultGateway() (net.IP, string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, "", fmt.Errorf("list routes: %w", err)
	}

	for _, r := range routes {
		// Default route has nil Dst
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
			ifaceName := ""
			if r.LinkIndex > 0 {
				link, err := netlink.LinkByIndex(r.LinkIndex)
				if err == nil {
					ifaceName = link.Attrs().Name
				}
			}
			return r.Gw, ifaceName, nil
		}
	}

	return nil, "", fmt.Errorf("no default route found")
}

// CleanupStaleRoutes removes leftover routes from a previous tunnel session on Linux.
func CleanupStaleRoutes(serverIP string) {
	// On Linux, stale routes are cleaned up via netlink in SetupRoutes.
	// No utun persistence issue like macOS.
}

// SetupRoutes configures routing for the VPN tunnel:
// 1. Adds a host route for the VPN server via the original default gateway
// 2. Replaces the default route to go through the TUN interface
// Returns a cleanup function that restores original routes.
func SetupRoutes(serverIP, tunName, tunCIDR, customGW string, bypassIPs ...string) (cleanup func(), gwInfo string, err error) {
	origGW, origIface, err := GetDefaultGateway()
	if err != nil {
		return nil, "", fmt.Errorf("get default gateway: %w", err)
	}

	var serverGW net.IP
	if customGW != "" {
		serverGW = net.ParseIP(customGW)
		if serverGW == nil {
			return nil, "", fmt.Errorf("invalid custom gateway: %s", customGW)
		}
		gwInfo = fmt.Sprintf("%s (custom)", serverGW)
	} else {
		serverGW = origGW
		gwInfo = fmt.Sprintf("%s (%s)", serverGW, origIface)
	}

	tunLink, err := netlink.LinkByName(tunName)
	if err != nil {
		return nil, "", fmt.Errorf("get tun link %s: %w", tunName, err)
	}

	srvIP := net.ParseIP(serverIP)
	if srvIP == nil {
		return nil, "", fmt.Errorf("invalid server IP: %s", serverIP)
	}

	// 1. Route to VPN server via gateway (original or custom)
	serverRoute := &netlink.Route{
		Dst: &net.IPNet{
			IP:   srvIP,
			Mask: net.CIDRMask(32, 32),
		},
		Gw: serverGW,
	}
	if err := netlink.RouteAdd(serverRoute); err != nil {
		return nil, "", fmt.Errorf("add server route: %w", err)
	}

	// 1b. Bypass routes for additional IPs (e.g. DoH endpoints)
	var bypassRoutes []*netlink.Route
	for _, ip := range bypassIPs {
		if ip == "" || ip == serverIP {
			continue
		}
		bIP := net.ParseIP(ip)
		if bIP == nil {
			continue
		}
		r := &netlink.Route{
			Dst: &net.IPNet{IP: bIP, Mask: net.CIDRMask(32, 32)},
			Gw:  serverGW,
		}
		if err := netlink.RouteAdd(r); err == nil {
			bypassRoutes = append(bypassRoutes, r)
		}
	}

	// 2. Replace default route via TUN
	_, dst1, _ := net.ParseCIDR("0.0.0.0/1")
	_, dst2, _ := net.ParseCIDR("128.0.0.0/1")

	tunRoute1 := &netlink.Route{
		Dst:       dst1,
		LinkIndex: tunLink.Attrs().Index,
	}
	tunRoute2 := &netlink.Route{
		Dst:       dst2,
		LinkIndex: tunLink.Attrs().Index,
	}

	if err := netlink.RouteAdd(tunRoute1); err != nil {
		netlink.RouteDel(serverRoute)
		return nil, "", fmt.Errorf("add tun route 0/1: %w", err)
	}
	if err := netlink.RouteAdd(tunRoute2); err != nil {
		netlink.RouteDel(serverRoute)
		netlink.RouteDel(tunRoute1)
		return nil, "", fmt.Errorf("add tun route 128/1: %w", err)
	}

	cleanupFn := func() {
		netlink.RouteDel(tunRoute2)
		netlink.RouteDel(tunRoute1)
		netlink.RouteDel(serverRoute)
		for _, r := range bypassRoutes {
			netlink.RouteDel(r)
		}
		origLink, linkErr := netlink.LinkByName(origIface)
		if linkErr == nil {
			netlink.RouteAdd(&netlink.Route{
				Gw:        origGW,
				LinkIndex: origLink.Attrs().Index,
			})
		}
	}

	return cleanupFn, gwInfo, nil
}
