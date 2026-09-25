package tunnel

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"ftybucks/internal/transport"
)

const (
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
	// reconnectTimeout bounds the dial+mux+handshake chain so a half-open peer
	// (TCP succeeds, mux/handshake stalls) cannot freeze a member out of the
	// pool indefinitely. With dial timeout 10s, leaves ~5s budget for mux+HS.
	reconnectTimeout = 15 * time.Second
)

// DialFunc establishes a new raw TCP connection.
type DialFunc func() (net.Conn, error)

// HandshakeFunc performs the custom handshake on a mux stream and returns the session key.
type HandshakeFunc func(stream *smux.Stream) ([]byte, error)

// ConnManager handles connection lifecycle, reconnection, and multiplexing.
type ConnManager struct {
	dial      DialFunc
	handshake HandshakeFunc

	mu         sync.RWMutex
	session    *smux.Session
	stream     *smux.Stream
	sessionKey []byte
	rawConn    net.Conn

	done chan struct{}
}

// NewConnManager creates a ConnManager that uses the provided dial/handshake functions.
func NewConnManager(dial DialFunc, handshake HandshakeFunc) *ConnManager {
	return &ConnManager{
		dial:      dial,
		handshake: handshake,
		done:      make(chan struct{}),
	}
}

// Connect establishes the initial connection.
func (cm *ConnManager) Connect() error {
	return cm.reconnect()
}

// reconnect performs: dial → mux → open stream → handshake(stream). The whole
// chain is bounded by reconnectTimeout via a watchdog goroutine that force-closes
// the in-progress conn if any step stalls — without this a peer that completes
// TCP but stops responding mid-handshake parks the member forever.
func (cm *ConnManager) reconnect() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Close old resources
	if cm.stream != nil {
		cm.stream.Close()
	}
	if cm.session != nil {
		cm.session.Close()
	}
	if cm.rawConn != nil {
		cm.rawConn.Close()
	}

	// Step 1: Dial
	conn, err := cm.dial()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	// Watchdog: if mux/handshake doesn't finish in time, slam the conn so the
	// blocked io.ReadFull / Write returns instead of parking forever.
	wdDone := make(chan struct{})
	wdFired := make(chan struct{})
	go func() {
		select {
		case <-wdDone:
		case <-time.After(reconnectTimeout):
			close(wdFired)
			conn.Close()
		}
	}()
	defer close(wdDone)

	// Step 2: Create mux session
	session, err := transport.NewMuxClient(conn)
	if err != nil {
		conn.Close()
		select {
		case <-wdFired:
			return fmt.Errorf("mux client: timed out after %s", reconnectTimeout)
		default:
			return fmt.Errorf("mux client: %w", err)
		}
	}

	// Step 3: Open stream
	stream, err := session.OpenStream()
	if err != nil {
		session.Close()
		conn.Close()
		select {
		case <-wdFired:
			return fmt.Errorf("open stream: timed out after %s", reconnectTimeout)
		default:
			return fmt.Errorf("open stream: %w", err)
		}
	}

	// Step 4: Handshake on the stream
	key, err := cm.handshake(stream)
	if err != nil {
		stream.Close()
		session.Close()
		conn.Close()
		select {
		case <-wdFired:
			return fmt.Errorf("handshake: timed out after %s", reconnectTimeout)
		default:
			return fmt.Errorf("handshake: %w", err)
		}
	}

	cm.rawConn = conn
	cm.session = session
	cm.stream = stream
	cm.sessionKey = key

	return nil
}

// GetActiveStream returns the current mux stream and session key.
func (cm *ConnManager) GetActiveStream() (*smux.Stream, []byte) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.stream, cm.sessionKey
}

// SessionKey returns the current session encryption key.
func (cm *ConnManager) SessionKey() []byte {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.sessionKey
}

// Reconnect attempts to re-establish the connection with exponential backoff.
func (cm *ConnManager) Reconnect() error {
	backoff := initialBackoff
	for {
		select {
		case <-cm.done:
			return fmt.Errorf("connection manager closed")
		default:
		}

		log.Printf("attempting reconnect (backoff=%v)", backoff)
		err := cm.reconnect()
		if err == nil {
			log.Println("reconnected successfully")
			return nil
		}

		log.Printf("reconnect failed: %v", err)

		select {
		case <-cm.done:
			return fmt.Errorf("connection manager closed")
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// Close shuts down the connection manager.
func (cm *ConnManager) Close() {
	close(cm.done)
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.stream != nil {
		cm.stream.Close()
	}
	if cm.session != nil {
		cm.session.Close()
	}
	if cm.rawConn != nil {
		cm.rawConn.Close()
	}
}
