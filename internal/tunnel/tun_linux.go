//go:build linux

package tunnel

import (
	"fmt"
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// CreateTUN creates and configures a TUN interface on Linux.
func CreateTUN(name, cidr string, mtu int) (*water.Interface, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	cfg := water.Config{
		DeviceType: water.TUN,
	}
	cfg.Name = name

	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create tun %s: %w", name, err)
	}

	// Parse CIDR
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		iface.Close()
		return nil, fmt.Errorf("parse cidr %s: %w", cidr, err)
	}

	// Get the link by name
	link, err := netlink.LinkByName(iface.Name())
	if err != nil {
		iface.Close()
		return nil, fmt.Errorf("get link %s: %w", iface.Name(), err)
	}

	// Set MTU
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		iface.Close()
		return nil, fmt.Errorf("set mtu: %w", err)
	}

	// Add address
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		iface.Close()
		return nil, fmt.Errorf("add addr: %w", err)
	}

	// Bring interface up
	if err := netlink.LinkSetUp(link); err != nil {
		iface.Close()
		return nil, fmt.Errorf("set link up: %w", err)
	}

	return iface, nil
}

// RebindTUN replaces the address on an existing TUN device in place. Used as a
// safety net when the server hands a reconnecting member a different tunnel IP
// than it held before: instead of killing the whole gateway process (which
// tears down every peer's tunnel and WireGuard), we re-address just this one
// device and keep going. The device fd stays valid; per-interface MASQUERADE
// rules reference the name (unchanged), so SNAT follows the new primary address.
func RebindTUN(name, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %s: %w", cidr, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("get link %s: %w", name, err)
	}
	// Flush existing addresses.
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list addrs %s: %w", name, err)
	}
	for i := range addrs {
		if err := netlink.AddrDel(link, &addrs[i]); err != nil {
			return fmt.Errorf("del addr %s: %w", name, err)
		}
	}
	newAddr := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: ipNet.Mask}}
	if err := netlink.AddrAdd(link, newAddr); err != nil {
		return fmt.Errorf("add addr %s: %w", name, err)
	}
	return nil
}
