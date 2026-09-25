package main

import (
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
	"github.com/xtaci/smux"

	"ftybucks/internal/config"
	"ftybucks/internal/dns"
	"ftybucks/internal/proto"
	"ftybucks/internal/transport"
	"ftybucks/internal/tunnel"
)

type State int

const (
	Disconnected State = iota
	Connecting
	Connected
	Disconnecting
)

func (s State) String() string {
	switch s {
	case Disconnected:
		return "Disconnected"
	case Connecting:
		return "Connecting..."
	case Connected:
		return "Connected"
	case Disconnecting:
		return "Disconnecting..."
	default:
		return "Unknown"
	}
}

type TunnelController struct {
	cfg *config.Config

	mu        sync.Mutex
	state     State
	stateCh   chan State
	stopCh    chan struct{}
	startTime time.Time
	lastErr   error
}

func NewTunnelController(cfg *config.Config) *TunnelController {
	return &TunnelController{
		cfg:     cfg,
		stateCh: make(chan State, 8),
	}
}

func (tc *TunnelController) State() State {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.state
}

func (tc *TunnelController) StartTime() time.Time {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.startTime
}

func (tc *TunnelController) LastError() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.lastErr
}

func (tc *TunnelController) setState(s State) {
	tc.mu.Lock()
	tc.state = s
	tc.mu.Unlock()
	select {
	case tc.stateCh <- s:
	default:
	}
}

func (tc *TunnelController) Connect() {
	tc.mu.Lock()
	if tc.state != Disconnected {
		tc.mu.Unlock()
		return
	}
	tc.state = Connecting
	tc.lastErr = nil
	tc.stopCh = make(chan struct{})
	tc.mu.Unlock()

	tc.stateCh <- Connecting
	go tc.run()
}

func (tc *TunnelController) Disconnect() {
	tc.mu.Lock()
	if tc.state != Connected && tc.state != Connecting {
		tc.mu.Unlock()
		return
	}
	tc.state = Disconnecting
	tc.mu.Unlock()

	tc.stateCh <- Disconnecting
	close(tc.stopCh)
}

func (tc *TunnelController) run() {
	cfg := tc.cfg
	stopCh := tc.stopCh

	psk, err := cfg.PSKBytes()
	if err != nil {
		tc.mu.Lock()
		tc.lastErr = err
		tc.mu.Unlock()
		tc.setState(Disconnected)
		return
	}

	cm := tunnel.NewConnManager(
		func() (net.Conn, error) {
			return transport.DialServer(cfg.Server, psk)
		},
		func(stream *smux.Stream) ([]byte, error) {
			return proto.ClientHandshake(stream, psk)
		},
	)

	// Connect
	if err := cm.Connect(); err != nil {
		log.Printf("[tray] connect failed: %v", err)
		tc.mu.Lock()
		tc.lastErr = err
		tc.mu.Unlock()
		cm.Close()
		tc.setState(Disconnected)
		return
	}

	// Check if stopped during connect
	select {
	case <-stopCh:
		cm.Close()
		tc.setState(Disconnected)
		return
	default:
	}

	// Create TUN
	tunName := cfg.TunName
	if tunName == "" {
		tunName = "stun0"
	}
	tun, err := tunnel.CreateTUN(tunName, cfg.TunCIDR, tunnel.DefaultMTU)
	if err != nil {
		log.Printf("[tray] TUN error: %v", err)
		tc.mu.Lock()
		tc.lastErr = err
		tc.mu.Unlock()
		cm.Close()
		tc.setState(Disconnected)
		return
	}

	// Setup routes
	serverHost := cfg.Server
	if h, _, splitErr := net.SplitHostPort(serverHost); splitErr == nil {
		serverHost = h
	}
	cleanupRoutes, _, err := tunnel.SetupRoutes(serverHost, tun.Name(), cfg.TunCIDR, cfg.Gateway)
	if err != nil {
		log.Printf("[tray] routes error: %v", err)
		tc.mu.Lock()
		tc.lastErr = err
		tc.mu.Unlock()
		tun.Close()
		cm.Close()
		tc.setState(Disconnected)
		return
	}

	// DNS resolver
	var resolver *dns.Resolver
	if cfg.DNS != "" {
		resolver = dns.NewDoHResolver(cfg.DNS)
	}

	tc.mu.Lock()
	tc.startTime = time.Now()
	tc.mu.Unlock()
	tc.setState(Connected)

	// Tunnel loop with reconnection
	defer func() {
		cleanupRoutes()
		tun.Close()
		cm.Close()
		tc.setState(Disconnected)
	}()

	// Single long-lived TUN reader shared across reconnects (see client/gateway
	// for the rationale: a per-session reader races on the TUN fd across a
	// reconnect). It exits when stopCh fires or tun.Close() in the defer above
	// makes ReadPacket error.
	packetCh := make(chan []byte, 256)
	go trayTunReader(tun, resolver, packetCh, stopCh)

	for {
		stream, sessionKey := cm.GetActiveStream()

		cipher, err := proto.NewCipher(sessionKey)
		if err != nil {
			log.Printf("[tray] cipher error: %v", err)
			return
		}

		jitter := time.Duration(cfg.JitterMs) * time.Millisecond
		obfsConn := transport.NewObfuscatedConn(stream, jitter, cipher, cfg.Padding)

		done := make(chan struct{}, 1)
		var once sync.Once
		signalDone := func() { once.Do(func() { close(done) }) }

		var writerWG sync.WaitGroup
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			defer signalDone()
			traySessionWriter(packetCh, obfsConn, cipher, cfg.Padding, done, stopCh)
		}()

		go func() {
			defer signalDone()
			serverToTun(stream, tun, cipher)
		}()

		select {
		case <-done:
			obfsConn.Close()
			writerWG.Wait()
			log.Printf("[tray] connection lost, reconnecting...")
		case <-stopCh:
			// Send close frame
			closeFrame, _ := proto.Encode(proto.FrameClose, nil, cipher, cfg.Padding)
			if closeFrame != nil {
				stream.Write(closeFrame)
			}
			obfsConn.Close()
			return
		}

		// Check if stopped
		select {
		case <-stopCh:
			return
		default:
		}

		if err := cm.Reconnect(); err != nil {
			log.Printf("[tray] reconnect failed: %v", err)
			tc.mu.Lock()
			tc.lastErr = err
			tc.mu.Unlock()
			return
		}
		log.Printf("[tray] reconnected")
	}
}

// trayTunReader is the single long-lived TUN reader: it intercepts DNS
// (answered locally) and pushes everything else to packetCh for the current
// session's writer. Drops on a full channel rather than blocking the TUN queue.
func trayTunReader(tun *water.Interface, resolver *dns.Resolver, packetCh chan<- []byte, stopCh <-chan struct{}) {
	for {
		pkt, err := tunnel.ReadPacket(tun)
		if err != nil {
			select {
			case <-stopCh:
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
		case <-stopCh:
			return
		default:
			// No writer or writer wedged — drop and keep draining the TUN.
		}
	}
}

// traySessionWriter drains packetCh into the current session's obfsConn,
// exiting on write failure / done / stop so it never blocks forever after the
// matching serverToTun tore the session down.
func traySessionWriter(packetCh <-chan []byte, obfsConn *transport.ObfuscatedConn, cipher *proto.Cipher,
	padCfg config.PaddingConfig, done <-chan struct{}, stopCh <-chan struct{}) {
	for {
		select {
		case pkt := <-packetCh:
			frame, err := proto.Encode(proto.FrameData, pkt, cipher, padCfg)
			if err != nil {
				log.Printf("[encode] %v", err)
				continue
			}
			if _, err := obfsConn.Write(frame); err != nil {
				log.Printf("[send] write failed: %v", err)
				return
			}
		case <-done:
			return
		case <-stopCh:
			return
		}
	}
}

// trayDataReadTimeout: see serverDataReadTimeout in the client. A healthy idle
// session never approaches 60s without a frame; a wedged one trips it and
// forces a reconnect instead of hanging until the app is restarted.
const trayDataReadTimeout = 60 * time.Second

func serverToTun(stream *smux.Stream, tun *water.Interface, cipher *proto.Cipher) {
	for {
		_ = stream.SetReadDeadline(time.Now().Add(trayDataReadTimeout))
		frameType, payload, err := proto.Decode(stream, cipher)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				log.Printf("[recv] decode error: %v", err)
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
		case proto.FrameClose:
			log.Printf("[tray] server sent close frame")
			return
		}
	}
}

func handleDNS(tun interface{ Write([]byte) (int, error) }, resolver *dns.Resolver, pkt, dnsQuery []byte) {
	srcIP, dstIP, srcPort, dstPort := dns.ExtractDNSInfo(pkt)

	resp, err := resolver.Resolve(dnsQuery)
	if err != nil {
		log.Printf("[dns] resolve error: %v", err)
		return
	}

	respPkt := dns.BuildDNSResponse(resp, dstIP, srcIP, dstPort, srcPort)
	if _, err := tun.Write(respPkt); err != nil {
		log.Printf("[dns] write error: %v", err)
	}
}
