package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
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
	"ftybucks/internal/dns"
	"ftybucks/internal/proto"
	"ftybucks/internal/transport"
	"ftybucks/internal/tunnel"
)

var version = "dev"

func main() {
	args := os.Args[1:]

	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage()
		os.Exit(0)
	}
	if args[0] == "-v" || args[0] == "--version" || args[0] == "version" {
		fmt.Printf("shadowtunnel %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Parse: shadowtunnel connect [-c config.yaml]
	cmd := args[0]
	if cmd != "connect" && cmd != "up" && cmd != "setup" {
		// Bare invocation with flags: shadowtunnel -c config.yaml
		if cmd == "-c" || cmd == "--config" {
			cmd = "connect"
		} else {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
			printUsage()
			os.Exit(1)
		}
	} else {
		args = args[1:]
	}

	if cmd == "setup" {
		runSetupWizard()
		return
	}

	cfgPath := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 >= len(args) {
				fatal("missing value for %s", args[i])
			}
			i++
			cfgPath = args[i]
		default:
			// Treat as config path if no flag prefix
			if !strings.HasPrefix(args[i], "-") {
				cfgPath = args[i]
			} else {
				fatal("unknown flag: %s", args[i])
			}
		}
	}

	// Auto-detect config if not specified
	if cfgPath == "" {
		cfgPath = findConfig()
	}
	if cfgPath == "" {
		cfgPath = runSetupWizard()
	}

	if cmd == "connect" {
		runConnect(cfgPath)
	}
}

func printUsage() {
	fmt.Print(`shadowtunnel — encrypted VPN tunnel disguised as PostgreSQL replication

Usage:
  sudo shadowtunnel connect [-c config.yaml]
  sudo shadowtunnel up [-c config.yaml]
  sudo shadowtunnel setup

Commands:
  connect, up    Establish VPN tunnel (requires root for TUN)
  setup          Run interactive config wizard

Flags:
  -c, --config   Path to config file (default: auto-detect)
  -v, --version  Print version
  -h, --help     Print this help

Config search order:
  1. -c flag (explicit path)
  2. ~/.config/ftybucks/client.yaml
  3. ./configs/client.yaml
  4. Not found → interactive setup wizard

Examples:
  sudo shadowtunnel connect
  sudo shadowtunnel connect -c /etc/shadowtunnel/client.yaml
  sudo shadowtunnel setup
`)
}

func runConnect(cfgPath string) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	logInfo("loading config from %s", cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fatal("config error: %v", err)
	}

	psk, err := cfg.PSKBytes()
	if err != nil {
		fatal("invalid PSK: %v", err)
	}

	logInfo("server:  %s", cfg.Server)
	if cfg.TunCIDR != "" {
		logInfo("tun:     %s (preferred, %s)", cfg.TunCIDR, tunName(cfg))
	} else {
		logInfo("tun:     auto (%s)", tunName(cfg))
	}
	if cfg.DNS != "" {
		logInfo("dns:     %s", cfg.DNS)
	}
	if cfg.JitterMs > 0 {
		logInfo("jitter:  %dms", cfg.JitterMs)
	}
	if cfg.Padding.Max > 0 {
		logInfo("padding: %d–%d bytes", cfg.Padding.Min, cfg.Padding.Max)
	}

	// Clean up stale routes from a previous session (crash/reboot/SIGKILL)
	serverHost := cfg.Server
	if h, _, err := net.SplitHostPort(serverHost); err == nil {
		serverHost = h
	}
	tunnel.CleanupStaleRoutes(serverHost)

	// Create ConnManager
	cm := tunnel.NewConnManager(
		func() (net.Conn, error) {
			return transport.DialServer(cfg.Server, psk)
		},
		func(stream *smux.Stream) ([]byte, error) {
			return proto.ClientHandshake(stream, psk)
		},
	)
	defer cm.Close()

	// Initial connection
	logInfo("connecting to %s...", cfg.Server)
	t0 := time.Now()
	if err := cm.Connect(); err != nil {
		fatal("connect failed: %v", err)
	}
	logOK("connected (%v)", time.Since(t0).Round(time.Millisecond))

	// IP assignment exchange
	tunCIDR, err := requestIPAssignment(cm, cfg)
	if err != nil {
		fatal("IP assignment: %v", err)
	}
	logOK("assigned %s", tunCIDR)

	// Create TUN interface
	tun, err := tunnel.CreateTUN(tunName(cfg), tunCIDR, tunnel.DefaultMTU)
	if err != nil {
		fatal("TUN interface: %v", err)
	}
	defer tun.Close()
	logOK("TUN %s up with %s", tun.Name(), tunCIDR)

	// Setup routes
	// DoH endpoint must bypass TUN to avoid circular dependency
	var bypassIPs []string
	if cfg.DNS != "" {
		if dohHost := parseHost(cfg.DNS); dohHost != "" {
			bypassIPs = append(bypassIPs, dohHost)
		}
	}
	cleanupRoutes, gwInfo, err := tunnel.SetupRoutes(serverHost, tun.Name(), tunCIDR, cfg.Gateway, bypassIPs...)
	if err != nil {
		fatal("routes: %v", err)
	}
	defer cleanupRoutes()
	logOK("routes configured (0/1 + 128/1 via TUN, server via %s)", gwInfo)

	// DNS resolver
	var resolver *dns.Resolver
	if cfg.DNS != "" {
		resolver = dns.NewDoHResolver(cfg.DNS)
		logOK("DoH resolver active")
	}

	// Signal handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	shutdownCh := make(chan struct{})

	logOK("tunnel active — Ctrl+C to disconnect")
	fmt.Println()

	// Parse assigned IP for preferred hint on reconnect
	assignedIP, _, _ := net.ParseCIDR(tunCIDR)

	// Long-lived TUN reader, started once and shared across reconnects. It is
	// the only caller of ReadPacket(tun) for the device's lifetime; per-session
	// writers consume from packetCh. Spawning a fresh tunToServer per session
	// (the old layout) raced: the previous one stayed blocked inside
	// ReadPacket through a reconnect and then competed with the new reader for
	// the same TUN fd, silently dropping packets into a dead connection.
	packetCh := make(chan []byte, 256)
	go clientTunReader(tun, resolver, packetCh, shutdownCh)

	sessionNum := 1

	// Tunnel loop — reconnects on failure
	for {
		stream, sessionKey := cm.GetActiveStream()

		cipher, err := proto.NewCipher(sessionKey)
		if err != nil {
			fatal("cipher: %v", err)
		}

		jitter := time.Duration(cfg.JitterMs) * time.Millisecond
		obfsConn := transport.NewObfuscatedConn(stream, jitter, cipher, cfg.Padding)

		sessionStart := time.Now()
		if sessionNum > 1 {
			logOK("session #%d established", sessionNum)
		}

		done := make(chan struct{}, 1)
		var once sync.Once
		signalDone := func() { once.Do(func() { close(done) }) }

		var writerWG sync.WaitGroup
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			defer signalDone()
			clientSessionWriter(packetCh, obfsConn, cipher, cfg.Padding, done, shutdownCh)
		}()

		go func() {
			defer signalDone()
			serverToTun(stream, tun, cipher, shutdownCh)
		}()

		select {
		case <-done:
			obfsConn.Close()
			// Drain the writer before minting a new cipher on reconnect, so it
			// cannot encode under the dead key into the next session.
			writerWG.Wait()
			logWarn("connection lost after %v, reconnecting...", time.Since(sessionStart).Round(time.Second))
		case <-sig:
			fmt.Println()
			logInfo("shutting down...")
			close(shutdownCh)
			closeFrame, _ := proto.Encode(proto.FrameClose, nil, cipher, cfg.Padding)
			if closeFrame != nil {
				stream.Write(closeFrame)
			}
			obfsConn.Close()
			logInfo("routes restored, tunnel closed")
			return
		}

		t0 := time.Now()
		if err := cm.Reconnect(); err != nil {
			fatal("reconnect failed: %v", err)
		}
		logOK("reconnected (%v)", time.Since(t0).Round(time.Millisecond))

		// Re-request same IP after reconnect
		newCIDR, err := requestIPAssignment(cm, cfg)
		if err != nil {
			fatal("IP re-assignment: %v", err)
		}
		newIP, _, _ := net.ParseCIDR(newCIDR)
		if !newIP.Equal(assignedIP) {
			// TUN interface still bound to old IP; continuing would break traffic
			// (server rejects packets with mismatched src IP).
			// Exit so the supervisor (systemd/docker) can restart us cleanly.
			fatal("server reassigned IP: %s (was %s) — restarting to rebind TUN", newCIDR, tunCIDR)
		}

		sessionNum++
	}
}

// requestIPAssignment sends a FrameAssign request to the server and returns the assigned CIDR.
func requestIPAssignment(cm *tunnel.ConnManager, cfg *config.Config) (string, error) {
	stream, sessionKey := cm.GetActiveStream()

	cipher, err := proto.NewCipher(sessionKey)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	// Build preferred IP: from config or 0.0.0.0
	preferred := net.IPv4zero.To4()
	if cfg.TunCIDR != "" {
		if ip, _, err := net.ParseCIDR(cfg.TunCIDR); err == nil {
			preferred = ip.To4()
		}
	}

	assignReq, err := proto.Encode(proto.FrameAssign, preferred, cipher, cfg.Padding)
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

// clientTunReader is the single, long-lived reader of the TUN device. It
// intercepts DNS (answered locally via DoH and written straight back to the
// TUN, never forwarded) and pushes everything else onto packetCh for the
// current session's writer. Started once for the device's lifetime so a
// reconnect never leaves a second ReadPacket caller racing on the fd.
//
// On a full channel the packet is dropped rather than blocking — losing a
// packet is recoverable; wedging the kernel TUN queue is not.
func clientTunReader(tun *water.Interface, resolver *dns.Resolver, packetCh chan<- []byte, shutdownCh <-chan struct{}) {
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

		if resolver != nil {
			if isDNS, dnsQuery := dns.IsDNSPacket(pkt); isDNS {
				go handleDNS(tun, resolver, pkt, dnsQuery)
				continue
			}
		}

		select {
		case packetCh <- pkt:
		case <-shutdownCh:
			return
		default:
			// No writer or writer wedged — drop and keep draining the TUN.
		}
	}
}

// clientSessionWriter drains packetCh and writes encrypted frames into the
// current session's obfsConn. Exits on the first write failure (signals the
// reconnect path) or when done/shutdown fires, so it never blocks forever on
// an empty channel after the matching serverToTun has torn the session down.
func clientSessionWriter(packetCh <-chan []byte, obfsConn *transport.ObfuscatedConn, cipher *proto.Cipher,
	padCfg config.PaddingConfig, done <-chan struct{}, shutdownCh <-chan struct{}) {
	for {
		select {
		case pkt := <-packetCh:
			frame, err := proto.Encode(proto.FrameData, pkt, cipher, padCfg)
			if err != nil {
				log.Printf("[encode] %v", err)
				continue
			}
			if _, err := obfsConn.Write(frame); err != nil {
				select {
				case <-shutdownCh:
				default:
					log.Printf("[send] write failed: %v", err)
				}
				return
			}
		case <-done:
			return
		case <-shutdownCh:
			return
		}
	}
}

// serverDataReadTimeout: a healthy idle session sees smux keepalives, app-level
// fake keepalives (≤30s) and decoy traffic, so it never approaches 60s without
// a frame. A wedged session trips the deadline → Decode errors → reconnect,
// instead of hanging silently until the process is restarted.
const serverDataReadTimeout = 60 * time.Second

func serverToTun(stream *smux.Stream, tun *water.Interface, cipher *proto.Cipher, shutdownCh <-chan struct{}) {
	for {
		_ = stream.SetReadDeadline(time.Now().Add(serverDataReadTimeout))
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
			if err := tunnel.WritePacket(tun, payload); err != nil {
				log.Printf("[tun] write error: %v", err)
			}
		case proto.FrameKeepalive:
			// noop
		case proto.FrameDecoy:
			// Fake traffic — drop silently.
		case proto.FrameClose:
			logWarn("server sent close frame")
			return
		}
	}
}

var (
	dnsErrCount  atomic.Int64
	dnsErrLogged atomic.Int64 // unix timestamp of last logged error
)

func handleDNS(tun interface{ Write([]byte) (int, error) }, resolver *dns.Resolver, pkt, dnsQuery []byte) {
	srcIP, dstIP, srcPort, dstPort := dns.ExtractDNSInfo(pkt)

	resp, err := resolver.Resolve(dnsQuery)
	if err != nil {
		n := dnsErrCount.Add(1)
		now := time.Now().Unix()
		last := dnsErrLogged.Load()
		if now-last >= 5 { // log at most once per 5 seconds
			dnsErrLogged.Store(now)
			if n > 1 {
				log.Printf("[dns] resolve error (%d failures): %v", n, err)
			} else {
				log.Printf("[dns] resolve error: %v", err)
			}
			dnsErrCount.Store(0)
		}
		return
	}
	dnsErrCount.Store(0)

	respPkt := dns.BuildDNSResponse(resp, dstIP, srcIP, dstPort, srcPort)
	if _, err := tun.Write(respPkt); err != nil {
		log.Printf("[dns] write error: %v", err)
	}
}

func parseHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return host
	}
	// Domain name — resolve before routes are up
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func tunName(cfg *config.Config) string {
	if cfg.TunName != "" {
		return cfg.TunName
	}
	return "stun0"
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
