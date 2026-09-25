package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// IPPool manages a pool of IP addresses within a subnet.
// The first usable IP (.1) is reserved for the server.
type IPPool struct {
	mu        sync.Mutex
	network   *net.IPNet
	serverIP  net.IP
	allocated map[string]struct{}
}

// NewIPPool creates a new IP pool from a CIDR string.
// The network address (.0) and broadcast address are excluded.
// The first host address (.1) is reserved for the server.
func NewIPPool(cidr string) (*IPPool, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR: %w", err)
	}

	// Server IP is the IP from the CIDR (e.g. 10.7.0.1 from 10.7.0.1/24)
	serverIP := ip.To4()
	if serverIP == nil {
		return nil, fmt.Errorf("only IPv4 is supported")
	}

	pool := &IPPool{
		network:   network,
		serverIP:  serverIP,
		allocated: make(map[string]struct{}),
	}

	return pool, nil
}

// Allocate assigns an IP address from the pool.
// If preferred is non-nil and not 0.0.0.0, it tries to allocate that specific IP.
// Otherwise, it allocates the next available IP.
func (p *IPPool) Allocate(preferred net.IP) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	preferred = preferred.To4()

	// If client requested a specific IP
	if preferred != nil && !preferred.Equal(net.IPv4zero) {
		if !p.network.Contains(preferred) {
			return nil, fmt.Errorf("preferred IP %s not in subnet %s", preferred, p.network)
		}
		if preferred.Equal(p.serverIP) {
			return nil, fmt.Errorf("preferred IP %s is the server IP", preferred)
		}
		if p.isNetworkOrBroadcast(preferred) {
			return nil, fmt.Errorf("preferred IP %s is network/broadcast address", preferred)
		}
		key := preferred.String()
		if _, taken := p.allocated[key]; taken {
			return nil, fmt.Errorf("preferred IP %s already allocated", preferred)
		}
		p.allocated[key] = struct{}{}
		return preferred, nil
	}

	// Auto-allocate: scan the subnet for a free IP
	ip := p.nextFree()
	if ip == nil {
		return nil, fmt.Errorf("no free IPs in pool %s", p.network)
	}
	p.allocated[ip.String()] = struct{}{}
	return ip, nil
}

// Release returns an IP address to the pool.
func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allocated, ip.To4().String())
}

// PrefixLen returns the prefix length of the pool's network (e.g. 24 for /24).
func (p *IPPool) PrefixLen() int {
	ones, _ := p.network.Mask.Size()
	return ones
}

// nextFree finds the next available IP in the subnet.
func (p *IPPool) nextFree() net.IP {
	// Start from network base + 2 (skip .0 network and .1 server)
	base := binary.BigEndian.Uint32(p.network.IP.To4())
	ones, bits := p.network.Mask.Size()
	size := 1 << uint(bits-ones)

	for i := 2; i < size-1; i++ { // skip .0 (network) and last (broadcast)
		candidate := make(net.IP, 4)
		binary.BigEndian.PutUint32(candidate, base+uint32(i))
		if candidate.Equal(p.serverIP) {
			continue
		}
		if _, taken := p.allocated[candidate.String()]; !taken {
			return candidate
		}
	}
	return nil
}

// isNetworkOrBroadcast checks if the IP is the network or broadcast address.
func (p *IPPool) isNetworkOrBroadcast(ip net.IP) bool {
	ip4 := ip.To4()
	network := p.network.IP.To4()
	mask := p.network.Mask

	// Network address check
	if ip4.Equal(network) {
		return true
	}

	// Broadcast address check
	broadcast := make(net.IP, 4)
	for i := range broadcast {
		broadcast[i] = network[i] | ^mask[i]
	}
	return ip4.Equal(broadcast)
}
