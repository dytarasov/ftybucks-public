package transport

import (
	"fmt"
	"net"
	"time"

	"github.com/xtaci/smux"
)

func muxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	// Version 2 adds per-stream sender flow control. Under V1 (the default) a
	// consumer that cannot drain (slow TUN write / backpressured client link)
	// stops recvLoop from reading the socket, which also stops processing the
	// peer's keepalives — and V1 deliberately refuses to time out a session
	// whose shared receive bucket is empty, so the whole session wedges
	// silently with no RST and no reconnect (only a process restart clears it).
	// V2 throttles the SENDER on an empty window instead of deadlocking.
	// Both client and server obtain their config here, so they move to V2 together.
	cfg.Version = 2
	cfg.MaxFrameSize = 65535
	// Per-stream window. We run one stream per tunnel, so this is the effective
	// in-flight window for ALL of the user's multiplexed traffic on that tunnel.
	// 16 MB covers ~1.3 Gbit at 100 ms RTT — far above measured throughput
	// (240–340 Mbit), so V2 flow control never becomes the bottleneck, while
	// being much tighter than V1's 64 MB shared bucket (less bufferbloat under
	// load → better Telegram/interactive latency).
	cfg.MaxStreamBuffer = 16 << 20   // 16 MB
	// Session-wide cap, unchanged from the V1 config. It's a limit, not a
	// preallocation; keeping 64 MB preserves headroom and can't regress speed.
	cfg.MaxReceiveBuffer = 64 << 20  // 64 MB
	cfg.KeepAliveInterval = 7 * time.Second
	// Left at 30s deliberately. Tightening it risks a delayed keepalive under
	// heavy load being read as a dead peer → reconnect → MarkUnhealthy → ECMP
	// rebuild → rehash that breaks healthy flows on the *other* tunnels — the
	// exact instability we're trying to remove. The 60s app-level read-deadline
	// watchdog (see tunnelToTun/serverToTun) is the backstop for a true wedge.
	cfg.KeepAliveTimeout = 30 * time.Second
	return cfg
}

// NewMuxClient creates a smux client session over an existing connection.
func NewMuxClient(conn net.Conn) (*smux.Session, error) {
	session, err := smux.Client(conn, muxConfig())
	if err != nil {
		return nil, fmt.Errorf("smux client: %w", err)
	}
	return session, nil
}

// NewMuxServer creates a smux server session over an existing connection.
func NewMuxServer(conn net.Conn) (*smux.Session, error) {
	session, err := smux.Server(conn, muxConfig())
	if err != nil {
		return nil, fmt.Errorf("smux server: %w", err)
	}
	return session, nil
}
