//go:build darwin

package tunnel

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

// CreateTUN creates and configures a TUN interface on macOS (utun).
func CreateTUN(name, cidr string, mtu int) (*water.Interface, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	cfg := water.Config{
		DeviceType: water.TUN,
	}
	// On macOS, water auto-assigns utunN. Name hint is ignored.

	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}

	ifName := iface.Name()

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		iface.Close()
		return nil, fmt.Errorf("parse cidr %s: %w", cidr, err)
	}

	// Calculate peer IP (server side of point-to-point link)
	peerIP := peerAddress(ip, ipNet)

	// ifconfig utunN inet 10.7.0.2 10.7.0.1 netmask 255.255.255.0 mtu 1400 up
	if err := run("ifconfig", ifName,
		"inet", ip.String(), peerIP.String(),
		"netmask", net.IP(ipNet.Mask).String(),
		"mtu", fmt.Sprintf("%d", mtu),
		"up",
	); err != nil {
		iface.Close()
		return nil, fmt.Errorf("ifconfig %s: %w", ifName, err)
	}

	return iface, nil
}

// RebindTUN is a Linux-only gateway operation; the gateway does not run on
// macOS. Defined here only so cross-package builds on darwin compile.
func RebindTUN(name, cidr string) error {
	return fmt.Errorf("RebindTUN not supported on darwin")
}

// peerAddress calculates the other end of the point-to-point tunnel.
// For 10.7.0.2/24 → returns 10.7.0.1 (network+1)
// For 10.7.0.1/24 → returns 10.7.0.2 (network+2)
func peerAddress(ip net.IP, ipNet *net.IPNet) net.IP {
	network := ipNet.IP.To4()
	peer := make(net.IP, 4)
	copy(peer, network)

	if ip.Equal(net.IPv4(network[0], network[1], network[2], network[3]+1)) {
		peer[3] = network[3] + 2
	} else {
		peer[3] = network[3] + 1
	}
	return peer
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), string(out), err)
	}
	return nil
}
