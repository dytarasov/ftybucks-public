package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/songgao/water"

	"crypto/tls"

	"ftybucks/internal/config"
	"ftybucks/internal/proto"
	"ftybucks/internal/transport"
	"ftybucks/internal/transport/pgproto"
	"ftybucks/internal/tunnel"
)

// serverTunMTU matches the gateway-side stunN and WireGuard client MTU so the
// inner-packet budget is consistent end-to-end (see CreateTUN call in main).
const serverTunMTU = 1420

// clientDataReadTimeout bounds how long a client session may go without any
// decoded frame before we tear it down and release its IP allocation. The
// gateway emits smux keepalives, app-level fake keepalives (≤30s) and decoy
// traffic, so a healthy idle session never approaches this; a half-open one
// (gateway crashed without a clean RST) is reaped in ~60s instead of lingering
// for the kernel TCP-keepalive timeout (hours) and holding its pool IP — which
// otherwise blocks the gateway from reclaiming the same IP on a fast reconnect.
const clientDataReadTimeout = 60 * time.Second

// connLimiter tracks per-IP connection rates to prevent brute-force probing.
type connLimiter struct {
	mu      sync.Mutex
	attempts map[string][]time.Time
}

func newConnLimiter() *connLimiter {
	cl := &connLimiter{attempts: make(map[string][]time.Time)}
	go cl.cleanup()
	return cl
}

// allow returns true if the IP hasn't exceeded the rate limit (5 attempts per minute).
func (cl *connLimiter) allow(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	// Trim old entries
	fresh := cl.attempts[ip][:0]
	for _, t := range cl.attempts[ip] {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	cl.attempts[ip] = append(fresh, now)

	return len(cl.attempts[ip]) <= 5
}

func (cl *connLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cl.mu.Lock()
		cutoff := time.Now().Add(-1 * time.Minute)
		for ip, times := range cl.attempts {
			fresh := times[:0]
			for _, t := range times {
				if t.After(cutoff) {
					fresh = append(fresh, t)
				}
			}
			if len(fresh) == 0 {
				delete(cl.attempts, ip)
			} else {
				cl.attempts[ip] = fresh
			}
		}
		cl.mu.Unlock()
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfgPath := flag.String("config", "configs/server.yaml", "path to server config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	psk, err := cfg.PSKBytes()
	if err != nil {
		log.Fatalf("invalid psk: %v", err)
	}

	// Create IP pool for client address assignment
	ipPool, err := tunnel.NewIPPool(cfg.TunCIDR)
	if err != nil {
		log.Fatalf("ip pool: %v", err)
	}

	// Create TUN interface. MTU 1420 matches the gateway-side stunN devices and
	// the WireGuard client MTU, so the inner-packet size budget is consistent
	// end-to-end; combined with the MSS clamp below this stops oversized return
	// packets from video CDNs being dropped at the 1420 boundary.
	tun, err := tunnel.CreateTUN("stun0", cfg.TunCIDR, serverTunMTU)
	if err != nil {
		log.Fatalf("create tun: %v", err)
	}
	defer tun.Close()
	log.Printf("TUN interface %s up with %s (MTU %d)", tun.Name(), cfg.TunCIDR, serverTunMTU)

	// Derive the tunnel subnet (e.g. 10.7.0.0/24) from the configured CIDR so
	// NAT rules track the config instead of a hard-coded literal.
	tunSubnet := cfg.TunCIDR
	if _, ipNet, err := net.ParseCIDR(cfg.TunCIDR); err == nil {
		tunSubnet = ipNet.String()
	}

	// Enable IP forwarding
	if err := enableIPForward(); err != nil {
		log.Printf("warning: failed to enable ip forwarding: %v", err)
	}

	// Setup NAT masquerade
	if err := setupNAT(tunSubnet); err != nil {
		log.Printf("warning: failed to setup NAT: %v", err)
	}
	defer cleanupNAT(tunSubnet)

	// Load or generate TLS certificate for PG protocol disguise
	cert, err := pgproto.LoadOrGenerateCert("")
	if err != nil {
		log.Fatalf("tls cert: %v", err)
	}
	log.Println("TLS certificate loaded")

	// Start TCP listener
	ln, err := transport.ListenServer(cfg.Listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	log.Printf("listening on %s", cfg.Listen)

	replayGuard := proto.NewReplayGuard()
	limiter := newConnLimiter()
	shutdownCh := make(chan struct{})

	table := newSessionTable(ipPool)

	// TUN → clients goroutine
	go func() {
		for {
			pkt, err := tunnel.ReadPacket(tun)
			if err != nil {
				select {
				case <-shutdownCh:
					return
				default:
				}
				log.Printf("[ERROR] tun read: %v", err)
				return
			}
			if len(pkt) < 20 {
				continue
			}

			dstIP := net.IP(pkt[16:20]).String()

			cs := table.get(dstIP)
			if cs == nil {
				continue
			}
			cipher := cs.cipherRef()
			if cipher == nil {
				continue
			}

			frame, err := proto.Encode(proto.FrameData, pkt, cipher, cfg.Padding)
			if err != nil {
				log.Printf("[ERROR] encode: %v", err)
				continue
			}
			if err := cs.send(frame); err != nil {
				log.Printf("[ERROR] write to client %s: %v", dstIP, err)
			}
		}
	}()

	// Accept connections
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-shutdownCh:
					return
				default:
				}
				log.Printf("[ERROR] accept: %v", err)
				return
			}
			remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if !limiter.allow(remoteIP) {
				log.Printf("[RATE] %s: rate limited, closing", remoteIP)
				conn.Close()
				continue
			}
			log.Printf("[CONN] new connection from %s", conn.RemoteAddr())
			go handleClient(conn, psk, cert, tun, cfg, replayGuard, table)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	close(shutdownCh)
	log.Println("shutting down")
}

// clientSession is one authenticated tunnel client: its assigned IP, the writer
// used to push encrypted frames back to it, and enough identity to support
// sticky-IP reconnects. writer/cipher are swapped in after IP assignment and
// read concurrently by the TUN→clients dispatcher, so they are mutex-guarded.
type clientSession struct {
	ip     net.IP
	ipStr  string
	token  string    // hex(token); "" if the client sent none
	id     uint64    // monotonic session id (for logs / eviction guard)
	stream io.Closer // underlying mux stream — closed to force-evict a stale session

	mu       sync.Mutex
	writer   io.Writer
	cipher   *proto.Cipher
	bytesOut atomic.Int64
}

func (cs *clientSession) setWriter(w io.Writer, c *proto.Cipher) {
	cs.mu.Lock()
	cs.writer, cs.cipher = w, c
	cs.mu.Unlock()
}

func (cs *clientSession) cipherRef() *proto.Cipher {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.cipher
}

func (cs *clientSession) send(frame []byte) error {
	cs.mu.Lock()
	w := cs.writer
	cs.mu.Unlock()
	if w == nil {
		return nil
	}
	n, err := w.Write(frame)
	cs.bytesOut.Add(int64(n))
	return err
}

// sessionTable maps assigned tunnel IPs (demux key for return traffic) and
// client tokens (sticky-IP identity) to live sessions.
type sessionTable struct {
	mu      sync.Mutex
	pool    *tunnel.IPPool
	byIP    map[string]*clientSession
	byToken map[string]*clientSession
	nextID  uint64
}

func newSessionTable(pool *tunnel.IPPool) *sessionTable {
	return &sessionTable{
		pool:    pool,
		byIP:    make(map[string]*clientSession),
		byToken: make(map[string]*clientSession),
	}
}

func (t *sessionTable) get(ipStr string) *clientSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byIP[ipStr]
}

// assign allocates or reuses a tunnel IP for a connecting client and returns a
// fresh session. A client presenting a known token (a reconnecting gateway
// member) gets its previous IP back and the stale session is returned as
// `evicted` for the caller to force-close. The same reclaim happens when a
// specific requested IP is still held but its owner's token no longer matches
// (e.g. the gateway process restarted). This is what makes IPs sticky and lets
// the gateway avoid rebinding its TUN on reconnect.
func (t *sessionTable) assign(token []byte, preferred net.IP, stream io.Closer) (cs, evicted *clientSession, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tokenStr := ""
	if len(token) > 0 {
		tokenStr = hex.EncodeToString(token)
	}

	var assignedIP net.IP
	if tokenStr != "" {
		if old, ok := t.byToken[tokenStr]; ok {
			assignedIP = old.ip
			evicted = old
		}
	}
	if assignedIP == nil {
		ip, allocErr := t.pool.Allocate(preferred)
		if allocErr != nil {
			// Requested a specific IP that is still held with no token match —
			// reclaim it from the stale owner rather than failing the reconnect.
			if preferred != nil && !preferred.Equal(net.IPv4zero) {
				if old, ok := t.byIP[preferred.String()]; ok {
					evicted = old
					assignedIP = old.ip
				}
			}
			if assignedIP == nil {
				return nil, nil, allocErr
			}
		} else {
			assignedIP = ip
		}
	}

	// Detach the evicted session from the maps before registering the new one,
	// so its pointer-guarded remove() won't release the IP we're re-handing out.
	if evicted != nil {
		if t.byIP[evicted.ipStr] == evicted {
			delete(t.byIP, evicted.ipStr)
		}
		if evicted.token != "" && t.byToken[evicted.token] == evicted {
			delete(t.byToken, evicted.token)
		}
	}

	t.nextID++
	cs = &clientSession{
		ip:     assignedIP.To4(),
		ipStr:  assignedIP.String(),
		token:  tokenStr,
		id:     t.nextID,
		stream: stream,
	}
	t.byIP[cs.ipStr] = cs
	if tokenStr != "" {
		t.byToken[tokenStr] = cs
	}
	return cs, evicted, nil
}

// remove detaches a session and releases its IP — but only if the maps still
// point at THIS session. A newer session that reclaimed the same IP/token will
// have replaced the entries, so a late-exiting old session is a no-op.
func (t *sessionTable) remove(cs *clientSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byIP[cs.ipStr] == cs {
		delete(t.byIP, cs.ipStr)
		t.pool.Release(cs.ip)
	}
	if cs.token != "" && t.byToken[cs.token] == cs {
		delete(t.byToken, cs.token)
	}
}

func handleClient(conn net.Conn, psk []byte, cert tls.Certificate, tun *water.Interface, cfg *config.Config, guard *proto.ReplayGuard, table *sessionTable) {
	remote := conn.RemoteAddr().String()
	t0 := time.Now()
	defer conn.Close()

	// PostgreSQL streaming replication handshake (DPI evasion)
	pgConn, err := pgproto.ServerHandshake(conn, psk, cert)
	if err != nil {
		log.Printf("[REJECT] %s: PG handshake failed after %v — %v", remote, time.Since(t0), err)
		return
	}
	defer pgConn.Close()

	muxSession, err := transport.NewMuxServer(pgConn)
	if err != nil {
		log.Printf("[ERROR] %s: mux server setup failed — %v", remote, err)
		return
	}
	defer muxSession.Close()

	stream, err := muxSession.AcceptStream()
	if err != nil {
		log.Printf("[ERROR] %s: accept stream failed — %v", remote, err)
		return
	}

	sessionKey, err := proto.ServerHandshake(stream, psk, guard)
	if err != nil {
		log.Printf("[REJECT] %s: crypto handshake failed — %v", remote, err)
		stream.Close()
		return
	}

	cipher, err := proto.NewCipher(sessionKey)
	if err != nil {
		log.Printf("[ERROR] %s: create cipher — %v", remote, err)
		stream.Close()
		return
	}

	log.Printf("[AUTH] %s: fully authenticated (%v)", remote, time.Since(t0))

	// IP assignment exchange. Payload is preferred-IP(4) + optional client
	// token(8): the token identifies a reconnecting member so we can hand back
	// the same IP (sticky) and evict its stale session.
	frameType, payload, err := proto.Decode(stream, cipher)
	if err != nil {
		log.Printf("[ERROR] %s: read assign request — %v", remote, err)
		return
	}
	if frameType != proto.FrameAssign || len(payload) < 4 {
		log.Printf("[REJECT] %s: expected FrameAssign, got 0x%02x (len=%d)", remote, frameType, len(payload))
		return
	}

	preferredIP := net.IP(payload[:4]).To4()
	var token []byte
	if len(payload) >= 12 {
		token = payload[4:12]
	}

	cs, evicted, err := table.assign(token, preferredIP, stream)
	if err != nil {
		log.Printf("[REJECT] %s: IP allocation failed (preferred %s) — %v", remote, preferredIP, err)
		return
	}
	if evicted != nil {
		log.Printf("[STICKY] %s: reclaimed IP %s from stale session #%d (token match) — evicting it", remote, cs.ipStr, evicted.id)
		evicted.stream.Close() // unblocks the old read loop → its remove() is a pointer-guarded no-op
	}
	assignedIP := cs.ip

	// Send assigned IP (4 bytes) + prefix length (1 byte)
	assignPayload := make([]byte, 5)
	copy(assignPayload[:4], assignedIP.To4())
	assignPayload[4] = byte(table.pool.PrefixLen())

	assignFrame, err := proto.Encode(proto.FrameAssign, assignPayload, cipher, cfg.Padding)
	if err != nil {
		table.remove(cs)
		log.Printf("[ERROR] %s: encode assign response — %v", remote, err)
		return
	}
	if _, err := stream.Write(assignFrame); err != nil {
		table.remove(cs)
		log.Printf("[ERROR] %s: write assign response — %v", remote, err)
		return
	}

	// Wrap stream in ObfuscatedConn (jitter=0) to gain fake-keepalive + decoy traffic.
	obfsConn := transport.NewObfuscatedConn(stream, 0, cipher, cfg.Padding)
	defer obfsConn.Close()

	// Publish the writer so the TUN→clients dispatcher can reach this client.
	cs.setWriter(obfsConn, cipher)

	tokenNote := "none"
	if cs.token != "" {
		tokenNote = cs.token[:8] // short prefix for logs
	}
	log.Printf("[ASSIGN] %s: TUN IP %s/%d (session #%d, token=%s)", remote, cs.ipStr, table.pool.PrefixLen(), cs.id, tokenNote)

	var rxData, rxBytes, pings int64
	defer func() {
		table.remove(cs)
		log.Printf("[DISCONNECT] %s (TUN %s, session #%d) after %v — rx=%d pkts/%d B, tx=%d B, pings=%d",
			remote, cs.ipStr, cs.id, time.Since(t0).Round(time.Second), rxData, rxBytes, cs.bytesOut.Load(), pings)
	}()

	for {
		_ = stream.SetReadDeadline(time.Now().Add(clientDataReadTimeout))
		frameType, payload, err := proto.Decode(stream, cipher)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				log.Printf("[ERROR] %s (TUN %s): decode — %v", remote, cs.ipStr, err)
			}
			return
		}

		switch frameType {
		case proto.FrameData:
			if len(payload) < 20 {
				continue
			}
			// Validate: srcIP must match assigned IP
			srcIP := net.IP(payload[12:16]).To4()
			if !srcIP.Equal(assignedIP) {
				log.Printf("[REJECT] %s: src IP %s != assigned %s", remote, srcIP, assignedIP)
				continue
			}
			rxData++
			rxBytes += int64(len(payload))
			if err := tunnel.WritePacket(tun, payload); err != nil {
				log.Printf("[ERROR] tun write: %v", err)
			}

		case proto.FramePing:
			// Echo the payload back so the client can measure RTT and liveness.
			pings++
			if pong, err := proto.Encode(proto.FramePong, payload, cipher, cfg.Padding); err == nil {
				if _, err := obfsConn.Write(pong); err != nil {
					return
				}
			}

		case proto.FrameKeepalive, proto.FramePong:
			// noop

		case proto.FrameDecoy:
			// Fake WAL-like traffic — drop silently.

		case proto.FrameClose:
			log.Printf("[CLOSE] %s: client sent close frame", remote)
			return
		}
	}
}

func enableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func setupNAT(subnet string) error {
	// MASQUERADE for tunnel traffic going to internet
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "!", "-d", subnet, "-j", "MASQUERADE").Run(); err != nil {
		return err
	}
	// FORWARD rules (needed when Docker sets FORWARD policy to DROP)
	exec.Command("iptables", "-I", "FORWARD", "-i", "stun0", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-I", "FORWARD", "-o", "stun0", "-j", "ACCEPT").Run()
	// Clamp TCP MSS to the path MTU on forwarded SYN/SYN-ACK. stun0 is 1420, so
	// this caps negotiated MSS at ~1380 and prevents oversized return segments
	// (video CDNs) being silently dropped at the 1420 boundary with the DF bit
	// set and no ICMP-needed making it back — the classic large-transfer stall.
	exec.Command("iptables", "-t", "mangle", "-A", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	return nil
}

func cleanupNAT(subnet string) {
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-d", subnet, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", "stun0", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-o", "stun0", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-t", "mangle", "-D", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
}
