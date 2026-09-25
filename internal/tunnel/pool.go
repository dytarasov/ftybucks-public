package tunnel

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Member is one upstream peer in a Pool: an independent VPN session with its
// own ConnManager, TUN interface, and assigned tunnel IP. Members fail and
// recover independently — when a member is unhealthy the Pool removes it from
// the active set so kernel routing can skip it.
type Member struct {
	Name   string // human-readable label, e.g. "n2"
	Addr   string // upstream address, e.g. "203.0.113.10:5432"
	IfName string // local TUN interface name, e.g. "stun0"
	CM     *ConnManager
	// Token is a stable per-member identity sent with every IP-assignment
	// request. It lets the server recognize a reconnecting member and hand it
	// back the SAME tunnel IP (sticky IP) instead of a fresh one — which would
	// otherwise force the gateway to rebind its TUN. Generated once at startup.
	Token []byte

	mu         sync.RWMutex
	healthy    bool
	lastDown   time.Time
	iface      any   // *water.Interface — kept untyped here to avoid an import cycle
	assignedIP []byte

	lastRTTus atomic.Int64 // last measured RTT in microseconds (0 = unknown)
}

// SetRTTus records the most recent measured round-trip time (microseconds).
func (m *Member) SetRTTus(us int64) { m.lastRTTus.Store(us) }

// RTTus returns the last measured round-trip time in microseconds (0 = unknown).
func (m *Member) RTTus() int64 { return m.lastRTTus.Load() }

// SetIface stashes the per-member TUN device and its assigned IP.
// `iface` is the *water.Interface value (untyped to avoid an import cycle from
// internal/tunnel back into itself).
func (m *Member) SetIface(iface any, ip []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.iface = iface
	m.assignedIP = append([]byte(nil), ip...)
}

// Iface returns the device set via SetIface, or nil if none has been provisioned.
func (m *Member) Iface() any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.iface
}

// AssignedIP returns the tunnel IP allocated by the upstream server.
func (m *Member) AssignedIP() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.assignedIP
}

// Healthy reports whether the member is currently considered reachable.
func (m *Member) Healthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy
}

func (m *Member) setHealthy(v bool) (changed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.healthy == v {
		return false
	}
	m.healthy = v
	if !v {
		m.lastDown = time.Now()
	}
	return true
}

// Pool aggregates several Members and tracks which are healthy. The active
// set (healthy members) is published via Active() and changes are broadcast
// through Events() so callers can rebuild kernel routes (ECMP) when a peer
// fails or recovers.
type Pool struct {
	members []*Member
	mu      sync.RWMutex
	events  chan struct{}

	stopOnce sync.Once
	done     chan struct{}
}

// NewPool builds a Pool with the given members (no connections established yet).
func NewPool(members []*Member) *Pool {
	return &Pool{
		members: members,
		events:  make(chan struct{}, 8),
		done:    make(chan struct{}),
	}
}

// Members returns the full configured list (regardless of health).
func (p *Pool) Members() []*Member {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Member, len(p.members))
	copy(out, p.members)
	return out
}

// Active returns the subset of members currently considered healthy.
func (p *Pool) Active() []*Member {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Member, 0, len(p.members))
	for _, m := range p.members {
		if m.Healthy() {
			out = append(out, m)
		}
	}
	return out
}

// Events returns a channel that fires whenever the set of healthy members
// changes. Callers should read it and rebuild routing on each tick.
// Events are coalesced — a slow consumer may miss intermediate states but
// will always eventually see the latest one.
func (p *Pool) Events() <-chan struct{} {
	return p.events
}

func (p *Pool) notify() {
	select {
	case p.events <- struct{}{}:
	default:
		// Channel full — consumer will pick up the latest state on next read.
	}
}

// MarkHealthy flips a member's status to healthy and fires an event if changed.
func (p *Pool) MarkHealthy(m *Member) {
	if m.setHealthy(true) {
		log.Printf("[POOL] %s (%s) → healthy, re-adding to active set", m.Name, m.Addr)
		p.notify()
	}
}

// MarkUnhealthy flips a member's status to unhealthy and fires an event if changed.
func (p *Pool) MarkUnhealthy(m *Member, reason string) {
	if m.setHealthy(false) {
		log.Printf("[POOL] %s (%s) → unhealthy: %s — evicting from active set", m.Name, m.Addr, reason)
		p.notify()
	}
}

// ConnectAll dials every member in parallel and marks reachable ones as healthy.
// Returns an error only if every member fails — in that case the pool is unusable.
func (p *Pool) ConnectAll() error {
	type result struct {
		m   *Member
		err error
	}
	ch := make(chan result, len(p.members))
	for _, m := range p.members {
		go func(m *Member) {
			err := m.CM.Connect()
			ch <- result{m, err}
		}(m)
	}

	healthy := 0
	for i := 0; i < len(p.members); i++ {
		r := <-ch
		if r.err == nil {
			healthy++
			r.m.setHealthy(true)
			log.Printf("[POOL] %s (%s) → connected", r.m.Name, r.m.Addr)
		} else {
			r.m.setHealthy(false)
			log.Printf("[POOL] %s (%s) → connect failed: %v", r.m.Name, r.m.Addr, r.err)
		}
	}

	if healthy == 0 {
		return fmt.Errorf("all %d pool members failed to connect", len(p.members))
	}
	p.notify()
	return nil
}

// Close shuts down every member's ConnManager.
func (p *Pool) Close() {
	p.stopOnce.Do(func() {
		close(p.done)
		for _, m := range p.members {
			m.CM.Close()
		}
	})
}

// Done returns a channel that closes when the pool is shut down.
func (p *Pool) Done() <-chan struct{} {
	return p.done
}

// SuggestIfaceName returns "tun_name + index" suitable for naming TUN devices
// when the pool has more than one member. Falls back to the configured name
// for single-member pools.
func SuggestIfaceName(base string, idx, total int) string {
	if total <= 1 {
		return base
	}
	return fmt.Sprintf("%s%d", base, idx)
}

// ResolveServerIPs returns the host portion of each "host:port" entry —
// used by routing.Manager to install bypass routes for every upstream.
func ResolveServerIPs(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			host = a
		}
		out = append(out, host)
	}
	return out
}
