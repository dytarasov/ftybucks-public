package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/songgao/water"
	"github.com/xtaci/smux"

	"ftybucks/internal/config"
	"ftybucks/internal/geoip"
	"ftybucks/internal/proto"
	"ftybucks/internal/routing"
	"ftybucks/internal/transport"
	"ftybucks/internal/tunnel"
	"ftybucks/internal/wireguard"
)

const gatewayTunMTU = 1420 // account for WireGuard overhead

// RTT/liveness probe cadence. The gateway sends a FramePing on each session
// every probeInterval; the server echoes FramePong. probeDeadMisses consecutive
// unanswered pings (~probeInterval × probeDeadMisses ≈ 12s) declares the path
// wedged and tears the session down — far faster than the 30s smux keepalive or
// the 60s data-read watchdog, both of which stay as backstops.
const (
	probeInterval   = 3 * time.Second
	probeDeadMisses = 4
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	args := os.Args[1:]
	cfgPath := "/etc/gateway/gateway.yaml"

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-config", "-c", "--config":
			if i+1 >= len(args) {
				fatal("missing value for %s", args[i])
			}
			i++
			cfgPath = args[i]
		case "-add-peer", "--add-peer":
			if i+1 >= len(args) {
				fatal("missing peer name for %s", args[i])
			}
			i++
			addPeer(cfgPath, args[i])
			return
		case "-remove-peer", "--remove-peer":
			if i+1 >= len(args) {
				fatal("missing peer name for %s", args[i])
			}
			i++
			removePeer(cfgPath, args[i])
			return
		case "-h", "--help", "help":
			printUsage()
			return
		default:
			if !strings.HasPrefix(args[i], "-") {
				cfgPath = args[i]
			} else {
				fatal("unknown flag: %s", args[i])
			}
		}
	}

	runGateway(cfgPath)
}

func printUsage() {
	fmt.Print(`gateway — WireGuard + tunnel gateway with GeoIP split-routing

Usage:
  gateway [-config gateway.yaml]
  gateway -add-peer <name>
  gateway -remove-peer <name>

Flags:
  -config, -c    Path to config file (default: /etc/gateway/gateway.yaml)
  -add-peer      Generate WireGuard config for a new peer
  -remove-peer   Remove a peer
  -h, --help     Print this help
`)
}

func addPeer(cfgPath, name string) {
	cfg, err := config.LoadGateway(cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}

	wg := wireguard.NewManager(cfg.WireGuard)

	// Only load keys and peers — interface is already up from main process
	if err := wg.InitKeys(); err != nil {
		fatal("wireguard init: %v", err)
	}
	_ = wg.LoadPeers() // may not exist yet

	clientCfg, err := wg.AddPeer(name)
	if err != nil {
		fatal("add peer: %v", err)
	}

	fmt.Printf("Peer %q added. Client configuration:\n\n%s\n", name, clientCfg)

	// Print QR code for mobile clients
	printQR(clientCfg)
}

func removePeer(cfgPath, name string) {
	cfg, err := config.LoadGateway(cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}

	wg := wireguard.NewManager(cfg.WireGuard)
	if err := wg.LoadPeers(); err != nil {
		fatal("load peers: %v", err)
	}

	if err := wg.RemovePeer(name); err != nil {
		fatal("remove peer: %v", err)
	}
	fmt.Printf("Peer %q removed.\n", name)
}

func runGateway(cfgPath string) {
	// 1. Load config
	logInfo("loading config from %s", cfgPath)
	cfg, err := config.LoadGateway(cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}

	psk, err := cfg.PSKBytes()
	if err != nil {
		fatal("invalid PSK: %v", err)
	}

	servers := cfg.ServerList()
	if len(servers) == 0 {
		fatal("no upstream servers configured")
	}
	logInfo("tunnel servers: %s", strings.Join(servers, ", "))
	routingMode := cfg.RoutingMode()
	logInfo("routing mode:   %s", routingMode)
	transit := cfg.IsTransitMode()
	if transit {
		logInfo("mode:           transit (XRay/proxy via SO_MARK 0x%x, no WireGuard)", cfg.Tunnel.OutboundMark)
	} else {
		logInfo("wireguard:      %s on %s:%d", cfg.WireGuard.Address, cfg.WireGuardInterface(), cfg.WireGuardListenPort())
	}

	// 2. Initialize GeoIP
	logInfo("loading GeoIP database...")
	geoDB, err := geoip.New(cfg.GeoIP.DatabasePath, cfg.GeoIP.CountryCode)
	if err != nil {
		fatal("geoip: %v", err)
	}
	defer geoDB.Close()

	// 3. Extract country subnets
	subnets, err := geoDB.ExtractSubnets()
	if err != nil {
		fatal("extract subnets: %v", err)
	}
	logOK("loaded %d %s subnets", len(subnets), cfg.GeoIP.CountryCode)

	// 4. Setup WireGuard (skipped in transit mode)
	if !transit {
		logInfo("setting up WireGuard...")
		wg := wireguard.NewManager(cfg.WireGuard)
		if err := wg.Setup(); err != nil {
			fatal("wireguard setup: %v", err)
		}
		defer wg.Teardown()
		logOK("WireGuard %s up", cfg.WireGuardInterface())
	}

	// 5. Build pool members (one ConnManager per upstream)
	baseTun := cfg.TunnelTunName()
	members := make([]*tunnel.Member, 0, len(servers))
	for i, addr := range servers {
		addr := addr
		ifName := tunnel.SuggestIfaceName(baseTun, i, len(servers))
		name := fmt.Sprintf("n%d", i+1)
		cm := tunnel.NewConnManager(
			func() (net.Conn, error) { return transport.DialServer(addr, psk) },
			func(stream *smux.Stream) ([]byte, error) { return proto.ClientHandshake(stream, psk) },
		)
		// Stable per-member token for sticky-IP reconnects (see requestIPAssignment).
		token := make([]byte, 8)
		if _, err := rand.Read(token); err != nil {
			fatal("generate member token: %v", err)
		}
		members = append(members, &tunnel.Member{
			Name:   name,
			Addr:   addr,
			IfName: ifName,
			CM:     cm,
			Token:  token,
		})
	}

	pool := tunnel.NewPool(members)
	defer pool.Close()

	logInfo("connecting tunnel pool (%d upstreams)...", len(members))
	t0 := time.Now()
	if err := pool.ConnectAll(); err != nil {
		fatal("pool connect: %v", err)
	}
	logOK("pool connected (%v) — %d/%d healthy", time.Since(t0).Round(time.Millisecond), len(pool.Active()), len(members))

	// 6. For each healthy member: request IP assignment + create TUN device.
	// Members that failed to dial are skipped here; reconnect goroutines handle
	// recovery later. A member only joins the ECMP route after both connect
	// and IP assignment succeed.
	provisioned := 0
	defer func() {
		for _, m := range pool.Members() {
			if iface, ok := m.Iface().(*water.Interface); ok {
				iface.Close()
			}
		}
	}()

	for _, m := range pool.Active() {
		cidr, err := requestIPAssignment(m.CM, cfg, net.IPv4zero, m.Token)
		if err != nil {
			pool.MarkUnhealthy(m, fmt.Sprintf("ip assign failed: %v", err))
			continue
		}
		assignedIP, _, _ := net.ParseCIDR(cidr)

		iface, err := tunnel.CreateTUN(m.IfName, cidr, gatewayTunMTU)
		if err != nil {
			pool.MarkUnhealthy(m, fmt.Sprintf("create TUN failed: %v", err))
			continue
		}
		m.SetIface(iface, assignedIP.To4())
		provisioned++
		logOK("[%s] %s up with %s (MTU %d)", m.Name, iface.Name(), cidr, gatewayTunMTU)
	}

	if provisioned == 0 {
		fatal("no upstream successfully provisioned a TUN — pool unusable")
	}

	// 7. Routing: every configured tunnel iface goes through MASQUERADE/FORWARD,
	// but the active ECMP next-hop set is rebuilt to match only healthy members.
	allIfaces := make([]string, 0, len(members))
	for _, m := range members {
		allIfaces = append(allIfaces, m.IfName)
	}
	serverHosts := tunnel.ResolveServerIPs(servers)
	wgIface := ""
	wgSubnet := ""
	if !transit {
		wgIface = cfg.WireGuardInterface()
		wgSubnet = cfg.WireGuard.Subnet
	}
	sticky := routingMode == config.RoutingECMPSticky
	standby := routingMode == config.RoutingActiveStdby
	rtMgr := routing.NewManager(wgIface, allIfaces, wgSubnet, serverHosts, cfg.Tunnel.OutboundMark, sticky)
	if err := rtMgr.Setup(subnets); err != nil {
		fatal("routing setup: %v", err)
	}
	defer rtMgr.Teardown()
	logOK("routing configured (mode=%s, direct: %d subnets, tunnel across %d peers)", routingMode, len(subnets), len(allIfaces))

	// Selects which tunnels the route/selection targets: all healthy for
	// ecmp/ecmp-sticky, a single primary (with sticky failover) for active-standby.
	sel := &routeSelector{pool: pool, standby: standby}

	// Initial route — only healthy peers with a provisioned TUN.
	if err := rtMgr.Apply(sel.active()); err != nil {
		logWarn("initial route apply: %v", err)
	}

	// 8. Domain exception resolver
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if len(cfg.Exceptions) > 0 {
		exResolver := routing.NewExceptionResolver(rtMgr, cfg.Exceptions)
		go exResolver.Start(ctx)
		logOK("exception resolver started (%d rules)", len(cfg.Exceptions))
	}

	// 9. Periodic GeoIP update
	go periodicGeoIPUpdate(ctx, geoDB, rtMgr, cfg.GeoIPUpdateInterval())

	// 10. Pool event watcher: rebuild ECMP whenever membership changes.
	// Events are debounced: a flapping peer fires down→up in quick succession,
	// and each RebuildECMP reshuffles the multipath hash buckets — which
	// migrates *surviving* flows onto a different exit IP and breaks them.
	// Coalescing bursts behind a short timer collapses a flap into a single
	// rebuild against the settled membership instead of two back-to-back
	// reshuffles.
	go func() {
		const debounce = 3 * time.Second
		var timer *time.Timer
		var timerC <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-pool.Events():
				if timer == nil {
					timer = time.NewTimer(debounce)
					timerC = timer.C
				} else {
					timer.Reset(debounce)
				}
			case <-timerC:
				timer = nil
				timerC = nil
				if err := rtMgr.Apply(sel.active()); err != nil {
					logWarn("route apply: %v", err)
				}
			}
		}
	}()

	// Signal handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	shutdownCh := make(chan struct{})

	// Diagnostics: pprof on loopback for `docker exec ... curl 127.0.0.1:6060/debug/pprof/goroutine?debug=2`.
	// SIGUSR1 dumps every goroutine to stderr — reachable from outside the
	// container via `docker kill -s USR1 ftybucks-gateway`. Both are read-only
	// and listen only on 127.0.0.1, so they don't expose anything externally.
	go func() {
		if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil && err != http.ErrServerClosed {
			log.Printf("[debug] pprof: %v", err)
		}
	}()
	debugSig := make(chan os.Signal, 1)
	signal.Notify(debugSig, syscall.SIGUSR1)
	go func() {
		buf := make([]byte, 1<<20)
		for range debugSig {
			n := runtime.Stack(buf, true)
			os.Stderr.Write(buf[:n])
		}
	}()

	// Periodic health snapshot — one line/minute. Quiet enough to leave on,
	// loud enough to spot "no events for hours, then user reboots" cases.
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				active := pool.Active()
				parts := make([]string, 0, len(active))
				for _, m := range active {
					if us := m.RTTus(); us > 0 {
						parts = append(parts, fmt.Sprintf("%s=%.0fms", m.Name, float64(us)/1000))
					} else {
						parts = append(parts, m.Name)
					}
				}
				log.Printf("[health] mode=%s active=%d/%d (%s) goroutines=%d",
					routingMode, len(active), len(pool.Members()), strings.Join(parts, ","), runtime.NumGoroutine())
			}
		}
	}()

	logOK("gateway active — Ctrl+C to stop")
	fmt.Println()

	// 11. Per-member data loop with reconnection.
	for _, m := range pool.Members() {
		if !m.Healthy() {
			// Failed-from-the-start member: still spin a reconnect loop so it
			// can join the pool later, but don't try to run a data loop yet.
			go reconnectOrphan(m, pool, cfg, sig, shutdownCh)
			continue
		}
		iface, ok := m.Iface().(*water.Interface)
		if !ok {
			continue
		}
		go memberDataLoop(m, pool, cfg, iface, net.IP(m.AssignedIP()), sig, shutdownCh)
	}

	// 12. Wait for shutdown signal.
	<-sig
	fmt.Println()
	logInfo("shutting down...")
	close(shutdownCh)
	cancel()
	logInfo("gateway stopped")
}

// activeIfaceNames returns the TUN device names of pool members that are both
// healthy and have a provisioned TUN. The route only includes peers in this set.
func activeIfaceNames(pool *tunnel.Pool) []string {
	out := make([]string, 0)
	for _, m := range pool.Active() {
		if iface, ok := m.Iface().(*water.Interface); ok {
			out = append(out, iface.Name())
		}
	}
	return out
}

// routeSelector decides which tunnel interfaces the routing manager targets.
// ecmp / ecmp-sticky use every healthy, provisioned tunnel. active-standby uses
// a single primary: it keeps the current primary while it stays healthy and
// only fails over to the next healthy tunnel (config order) when the primary
// drops — so live flows aren't churned while the primary is up.
type routeSelector struct {
	pool    *tunnel.Pool
	standby bool

	mu      sync.Mutex
	primary string
}

func (s *routeSelector) active() []string {
	healthy := activeIfaceNames(s.pool)
	if !s.standby {
		return healthy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range healthy {
		if h == s.primary {
			return []string{s.primary}
		}
	}
	if len(healthy) == 0 {
		s.primary = ""
		return nil
	}
	s.primary = healthy[0]
	log.Printf("[routing] active-standby primary → %s", s.primary)
	return []string{s.primary}
}

// memberDataLoop runs one peer's tunnel goroutines and reconnects when the
// underlying smux session drops. The peer is marked unhealthy while
// reconnecting (which evicts it from the ECMP route) and healthy again on
// success.
//
// The TUN reader is started exactly once per member and outlives every
// session — it pushes packets into a buffered channel that per-session
// writers consume. This avoids the goroutine-leak race where the old
// ReadPacket(tun) call stays blocked through a reconnect, then competes
// with the new session's reader for the same TUN fd.
func memberDataLoop(m *tunnel.Member, pool *tunnel.Pool, cfg *config.GatewayConfig,
	tunIface *water.Interface, assignedIP net.IP, sig <-chan os.Signal, shutdownCh <-chan struct{}) {

	packetCh := make(chan []byte, 256)
	go tunReader(m, tunIface, packetCh, shutdownCh)

	sessionNum := 1
	flapCount := 0
	for {
		stream, sessionKey := m.CM.GetActiveStream()

		cipher, err := proto.NewCipher(sessionKey)
		if err != nil {
			logWarn("[%s] cipher: %v", m.Name, err)
			pool.MarkUnhealthy(m, "cipher init failed")
			return
		}

		jitter := time.Duration(cfg.Tunnel.JitterMs) * time.Millisecond
		obfsConn := transport.NewObfuscatedConn(stream, jitter, cipher, cfg.Tunnel.Padding)

		sessionStart := time.Now()
		if sessionNum > 1 {
			logOK("[%s] session #%d established", m.Name, sessionNum)
		}

		sessionDone := make(chan struct{})
		var once sync.Once
		signalDone := func() { once.Do(func() { close(sessionDone) }) }

		probe := &rttProbe{}
		var rxBytes, txBytes atomic.Int64

		var writerWG sync.WaitGroup
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			defer signalDone()
			sessionWriter(packetCh, obfsConn, cipher, cfg.Tunnel.Padding, &txBytes, sessionDone, shutdownCh)
		}()
		go func() {
			defer signalDone()
			tunnelToTun(stream, tunIface, cipher, probe, &rxBytes, shutdownCh)
		}()
		// RTT/liveness prober — declares the path dead far faster than the
		// keepalive/watchdog backstops and records RTT for diagnostics.
		go probeLoop(m, obfsConn, cipher, cfg.Tunnel.Padding, probe, signalDone, sessionDone, shutdownCh)

		var sessionDuration time.Duration
		select {
		case <-sessionDone:
			sessionDuration = time.Since(sessionStart)
			obfsConn.Close()
			// Make sure the writer drains and exits before we mint a new cipher
			// for the next session — otherwise it could encode a packet under
			// the dead key after MarkHealthy and corrupt the new stream.
			writerWG.Wait()
			m.SetRTTus(0)
			pool.MarkUnhealthy(m, fmt.Sprintf("session lost after %v (rx=%dB tx=%dB lastRTT=%s)",
				sessionDuration.Round(time.Second), rxBytes.Load(), txBytes.Load(), probe.rttString()))
		case <-shutdownCh:
			closeFrame, _ := proto.Encode(proto.FrameClose, nil, cipher, cfg.Tunnel.Padding)
			if closeFrame != nil {
				stream.Write(closeFrame)
			}
			obfsConn.Close()
			return
		}

		// Reconnect with exponential backoff inside ConnManager.
		t0 := time.Now()
		if err := m.CM.Reconnect(); err != nil {
			logWarn("[%s] reconnect aborted: %v", m.Name, err)
			return
		}
		logOK("[%s] reconnected (%v)", m.Name, time.Since(t0).Round(time.Millisecond))

		// Re-request our OWN IP back (sticky). The server recognizes the member
		// token and hands the same IP, so a reconnect no longer disturbs the TUN.
		newCIDR, err := requestIPAssignment(m.CM, cfg, assignedIP, m.Token)
		if err != nil {
			pool.MarkUnhealthy(m, fmt.Sprintf("IP re-assignment failed: %v", err))
			return
		}
		newIP, _, _ := net.ParseCIDR(newCIDR)
		if !newIP.Equal(assignedIP) {
			// Sticky IP should make this impossible, but if the server still
			// handed us a different IP, rebind THIS member's TUN in place rather
			// than killing the whole gateway (which would drop every peer's
			// tunnel + WireGuard). Blast radius: one tunnel, not the process.
			logWarn("[%s] server reassigned IP %s (was %s) — rebinding %s in place", m.Name, newCIDR, assignedIP, m.IfName)
			if err := tunnel.RebindTUN(m.IfName, newCIDR); err != nil {
				pool.MarkUnhealthy(m, fmt.Sprintf("TUN rebind failed: %v", err))
				return
			}
			assignedIP = newIP.To4()
			m.SetIface(tunIface, assignedIP)
		}

		// Flap hold-down: if the session we just lost was short-lived, this peer
		// is flapping. Re-adding it to the active set immediately makes the ECMP
		// watcher reshuffle the multipath buckets and migrate *healthy* flows on
		// the surviving peers onto a different exit IP — breaking them. Hold the
		// recovered peer out of the active set for a growing backoff until it
		// proves stable. A long-lived session resets the counter.
		const flapThreshold = 20 * time.Second
		if sessionDuration > 0 && sessionDuration < flapThreshold {
			flapCount++
			holdoff := time.Duration(flapCount) * 5 * time.Second
			if holdoff > 30*time.Second {
				holdoff = 30 * time.Second
			}
			logWarn("[%s] flapping (last session %v, strike #%d) — holding out of pool %v",
				m.Name, sessionDuration.Round(time.Second), flapCount, holdoff)
			select {
			case <-time.After(holdoff):
			case <-shutdownCh:
				return
			}
		} else {
			flapCount = 0
		}

		pool.MarkHealthy(m)
		sessionNum++
	}
}

// reconnectOrphan keeps trying to bring up a member that failed during the
// initial pool dial. On success it provisions the TUN and joins the pool.
// Stops on shutdown.
func reconnectOrphan(m *tunnel.Member, pool *tunnel.Pool, cfg *config.GatewayConfig,
	sig <-chan os.Signal, shutdownCh <-chan struct{}) {

	logWarn("[%s] orphan: starting reconnect loop", m.Name)
	for {
		select {
		case <-shutdownCh:
			return
		default:
		}
		if err := m.CM.Reconnect(); err != nil {
			logWarn("[%s] orphan reconnect aborted: %v", m.Name, err)
			return
		}
		cidr, err := requestIPAssignment(m.CM, cfg, net.IPv4zero, m.Token)
		if err != nil {
			logWarn("[%s] orphan IP assign: %v", m.Name, err)
			time.Sleep(5 * time.Second)
			continue
		}
		assignedIP, _, _ := net.ParseCIDR(cidr)
		iface, err := tunnel.CreateTUN(m.IfName, cidr, gatewayTunMTU)
		if err != nil {
			logWarn("[%s] orphan TUN: %v", m.Name, err)
			time.Sleep(5 * time.Second)
			continue
		}
		m.SetIface(iface, assignedIP.To4())
		logOK("[%s] %s up with %s (joining pool)", m.Name, iface.Name(), cidr)
		pool.MarkHealthy(m)
		memberDataLoop(m, pool, cfg, iface, assignedIP, sig, shutdownCh)
		return
	}
}

// requestIPAssignment asks the server for a tunnel IP. `preferred` is the IP the
// gateway wants back (0.0.0.0 for a fresh assignment, or its previous IP on
// reconnect); `token` is the member's stable identity so the server can pin the
// same IP across reconnects (sticky IP). Request payload: preferred(4)+token(8).
func requestIPAssignment(cm *tunnel.ConnManager, cfg *config.GatewayConfig, preferred net.IP, token []byte) (string, error) {
	stream, sessionKey := cm.GetActiveStream()

	cipher, err := proto.NewCipher(sessionKey)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	// Bound the request: without a deadline a server that finishes mux
	// handshake but never replies to FrameAssign would park this goroutine
	// forever and freeze the member out of the pool with no log line.
	deadline := time.Now().Add(15 * time.Second)
	_ = stream.SetWriteDeadline(deadline)
	_ = stream.SetReadDeadline(deadline)
	defer func() {
		_ = stream.SetWriteDeadline(time.Time{})
		_ = stream.SetReadDeadline(time.Time{})
	}()

	pref := preferred.To4()
	if pref == nil {
		pref = net.IPv4zero.To4()
	}
	reqPayload := make([]byte, 0, 4+len(token))
	reqPayload = append(reqPayload, pref...)
	reqPayload = append(reqPayload, token...)

	assignReq, err := proto.Encode(proto.FrameAssign, reqPayload, cipher, cfg.Tunnel.Padding)
	if err != nil {
		return "", fmt.Errorf("encode assign request: %w", err)
	}
	if _, err := stream.Write(assignReq); err != nil {
		return "", fmt.Errorf("write assign request: %w", err)
	}

	frameType, payload, err := proto.Decode(stream, cipher)
	if err != nil {
		return "", fmt.Errorf("read assign response: %w", err)
	}
	if frameType != proto.FrameAssign || len(payload) < 5 {
		return "", fmt.Errorf("unexpected response: type=0x%02x len=%d", frameType, len(payload))
	}

	assignedIP := net.IP(payload[:4]).To4()
	prefix := int(payload[4])

	return fmt.Sprintf("%s/%d", assignedIP, prefix), nil
}

// tunReader reads packets from a TUN device for the lifetime of the device,
// rewrites their src IP to the assigned tunnel IP, and forwards them onto
// packetCh for the per-session writer. It is started exactly once per member;
// keeping a single ReadPacket caller on the fd is what prevents the
// "two readers competing on stun0 after reconnect" race.
//
// If packetCh is full (slow/missing writer) the packet is dropped instead of
// blocking — better to lose a packet than to wedge the kernel TUN queue.
func tunReader(m *tunnel.Member, tun *water.Interface, packetCh chan<- []byte, shutdownCh <-chan struct{}) {
	for {
		pkt, err := tunnel.ReadPacket(tun)
		if err != nil {
			select {
			case <-shutdownCh:
			default:
				log.Printf("[tun] read error: %v", err)
			}
			return
		}

		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			continue
		}

		srcIP := net.IP(pkt[12:16])
		dstIP := net.IP(pkt[16:20])
		if dstIP.Equal(net.IPv4bcast) || dstIP.Equal(net.IPv4zero) ||
			srcIP.Equal(net.IPv4zero) || dstIP[0] == 224 {
			continue
		}

		// Read the member's current tunnel IP each packet so an in-place TUN
		// rebind (rare IP reassignment) is picked up without restarting the reader.
		tunIP4 := m.AssignedIP()
		if tunIP4 == nil {
			continue
		}
		copy(pkt[12:16], tunIP4)
		fixIPv4Checksum(pkt)

		select {
		case packetCh <- pkt:
		case <-shutdownCh:
			return
		default:
			// No writer or writer is wedged — drop and keep draining the TUN.
		}
	}
}

// sessionWriter drains packetCh and pushes encrypted frames into obfsConn for
// the current session. It exits as soon as a Write fails, which signals the
// caller to evict the member and reconnect. sessionDone fires when the peer
// stream is dead so we don't sit forever blocked on an empty channel after
// the matching tunnelToTun has already torn the session down.
func sessionWriter(packetCh <-chan []byte, obfsConn *transport.ObfuscatedConn, cipher *proto.Cipher,
	padCfg config.PaddingConfig, tx *atomic.Int64, sessionDone <-chan struct{}, shutdownCh <-chan struct{}) {
	for {
		select {
		case pkt := <-packetCh:
			frame, err := proto.Encode(proto.FrameData, pkt, cipher, padCfg)
			if err != nil {
				log.Printf("[encode] %v", err)
				continue
			}
			n, err := obfsConn.Write(frame)
			tx.Add(int64(n))
			if err != nil {
				select {
				case <-shutdownCh:
				default:
					log.Printf("[send] write failed: %v", err)
				}
				return
			}
		case <-sessionDone:
			return
		case <-shutdownCh:
			return
		}
	}
}

// rttProbe records the liveness state of a session's ping/pong probe.
type rttProbe struct {
	lastRTTus atomic.Int64 // last measured round-trip time, microseconds
	misses    atomic.Int64 // pings sent since the last pong was seen
	sawPong   atomic.Bool  // true once any pong has been received this session
}

// onPong is called from the frame reader when a FramePong arrives. The payload
// echoes the send timestamp (client clock), so RTT is clock-domain-safe.
func (p *rttProbe) onPong(payload []byte) {
	if len(payload) >= 8 {
		sent := int64(binary.BigEndian.Uint64(payload[:8]))
		if rtt := time.Now().UnixNano() - sent; rtt > 0 {
			p.lastRTTus.Store(rtt / 1000)
		}
	}
	p.sawPong.Store(true)
	p.misses.Store(0)
}

func (p *rttProbe) rttString() string {
	us := p.lastRTTus.Load()
	if us == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1fms", float64(us)/1000)
}

// probeLoop sends a FramePing every probeInterval and tears the session down
// after probeDeadMisses consecutive unanswered pings. Runs until the session
// ends or shutdown.
func probeLoop(m *tunnel.Member, obfsConn *transport.ObfuscatedConn, cipher *proto.Cipher,
	padCfg config.PaddingConfig, probe *rttProbe, signalDone func(),
	sessionDone <-chan struct{}, shutdownCh <-chan struct{}) {
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		select {
		case <-sessionDone:
			return
		case <-shutdownCh:
			return
		case <-t.C:
			// Mirror the latest RTT onto the member for the periodic health line.
			m.SetRTTus(probe.lastRTTus.Load())
			// Only enforce the dead-path teardown once we've seen at least one
			// pong — otherwise a server that doesn't answer pings (older build)
			// would be false-flagged. Until then the 30s keepalive / 60s
			// data-read watchdogs remain the liveness backstop.
			if probe.sawPong.Load() && probe.misses.Load() >= probeDeadMisses {
				logWarn("[%s] probe: %d pings unanswered (~%v) — path wedged, tearing down",
					m.Name, probe.misses.Load(), time.Duration(probeDeadMisses)*probeInterval)
				signalDone()
				return
			}
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], uint64(time.Now().UnixNano()))
			ping, err := proto.Encode(proto.FramePing, buf[:], cipher, padCfg)
			if err != nil {
				continue
			}
			if _, err := obfsConn.Write(ping); err != nil {
				return // write failed → sessionWriter will also fail → teardown
			}
			probe.misses.Add(1) // reset to 0 by onPong
		}
	}
}

// fixIPv4Checksum recalculates the IPv4 header checksum.
func fixIPv4Checksum(pkt []byte) {
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return
	}
	// Zero out checksum field
	pkt[10] = 0
	pkt[11] = 0
	// Compute checksum over header
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	cs := ^uint16(sum)
	pkt[10] = byte(cs >> 8)
	pkt[11] = byte(cs)
}

// tunnelDataReadTimeout bounds how long a steady-state session may go without
// decoding ANY frame before we treat it as dead and tear it down. The peer
// emits smux keepalives (≤15s), app-level fake keepalives (≤30s) and Poisson
// decoy traffic (~4s mean), so a healthy idle session never approaches 60s;
// a wedged one trips the deadline and forces MarkUnhealthy → Reconnect instead
// of hanging silently until a process restart.
const tunnelDataReadTimeout = 60 * time.Second

// tunnelToTun reads encrypted frames from tunnel and writes to TUN (stun0).
func tunnelToTun(stream *smux.Stream, tun *water.Interface, cipher *proto.Cipher,
	probe *rttProbe, rx *atomic.Int64, shutdownCh <-chan struct{}) {
	for {
		_ = stream.SetReadDeadline(time.Now().Add(tunnelDataReadTimeout))
		frameType, payload, err := proto.Decode(stream, cipher)
		if err != nil {
			select {
			case <-shutdownCh:
			default:
				if err != io.EOF && !strings.Contains(err.Error(), "closed") {
					log.Printf("[recv] decode error: %v", err)
				}
			}
			return
		}

		switch frameType {
		case proto.FrameData:
			rx.Add(int64(len(payload)))
			if err := tunnel.WritePacket(tun, payload); err != nil {
				log.Printf("[tun] write error: %v", err)
			}
		case proto.FramePong:
			probe.onPong(payload)
		case proto.FrameKeepalive, proto.FramePing:
			// noop (server echoes our pings; we don't answer the server's)
		case proto.FrameDecoy:
			// Fake traffic — drop silently.
		case proto.FrameClose:
			logWarn("server sent close frame")
			return
		}
	}
}

func periodicGeoIPUpdate(ctx context.Context, geoDB *geoip.DB, rtMgr *routing.Manager, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			logInfo("updating GeoIP database...")
			if err := geoDB.Update(); err != nil {
				logWarn("geoip update failed: %v", err)
				continue
			}

			subnets, err := geoDB.ExtractSubnets()
			if err != nil {
				logWarn("geoip extract subnets: %v", err)
				continue
			}

			if err := rtMgr.UpdateDirectIPs(subnets); err != nil {
				logWarn("update direct IPs: %v", err)
				continue
			}

			logOK("geoip updated: %d subnets", len(subnets))
		}
	}
}

func printQR(config string) {
	cmd := exec.Command("qrencode", "-t", "ANSIUTF8")
	cmd.Stdin = strings.NewReader(config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "(qrencode not available: %v)\n", err)
	}
}

func logInfo(format string, a ...any) {
	log.Printf("  [-] "+format, a...)
}

func logOK(format string, a ...any) {
	log.Printf("  [+] "+format, a...)
}

func logWarn(format string, a ...any) {
	log.Printf("  [!] "+format, a...)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "  [x] "+format+"\n", a...)
	os.Exit(1)
}
