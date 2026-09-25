package transport

import (
	"crypto/rand"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ftybucks/internal/config"
	"ftybucks/internal/proto"
)

const (
	DefaultJitterMax  = 50 * time.Millisecond
	MinKeepaliveDelay = 5 * time.Second
	MaxKeepaliveDelay = 30 * time.Second
)

// ObfuscatedConn wraps a net.Conn with anti-DPI obfuscation techniques:
// timing jitter, fake keepalives, and decoy WAL-like traffic.
// All writes are serialized with a mutex.
type ObfuscatedConn struct {
	net.Conn
	jitterMax time.Duration
	cipher    *proto.Cipher
	padCfg    config.PaddingConfig

	writeMu     sync.Mutex
	closeOnce   sync.Once
	done        chan struct{}
	lastWriteNs atomic.Int64 // unix nano of the last real write
	decoy       *DecoyGenerator
}

// NewObfuscatedConn wraps a connection with obfuscation.
func NewObfuscatedConn(conn net.Conn, jitterMax time.Duration, cipher *proto.Cipher, padCfg config.PaddingConfig) *ObfuscatedConn {
	oc := &ObfuscatedConn{
		Conn:      conn,
		jitterMax: jitterMax,
		cipher:    cipher,
		padCfg:    padCfg,
		done:      make(chan struct{}),
	}
	if cipher != nil {
		go oc.fakeKeepalives()
		oc.decoy = NewDecoyGenerator(oc, cipher, padCfg)
		oc.decoy.Start()
	}
	return oc
}

// Write sends data with timing jitter. Thread-safe.
// Marks the connection as "active" so decoy traffic backs off.
func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	if c.jitterMax > 0 {
		jitter := randomDuration(c.jitterMax)
		time.Sleep(jitter)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.lastWriteNs.Store(time.Now().UnixNano())
	return c.Conn.Write(b)
}

// writeRaw writes already-encoded bytes directly without updating the
// lastWriteTime marker (used by decoy/keepalive goroutines).
// Uses TryLock so background traffic never stalls the real-data path:
// if a real Write is in progress, the decoy/keepalive frame is skipped.
func (c *ObfuscatedConn) writeRaw(b []byte) error {
	if !c.writeMu.TryLock() {
		return nil
	}
	defer c.writeMu.Unlock()
	_, err := c.Conn.Write(b)
	return err
}

// lastWriteTime returns the time of the last real Write() call.
func (c *ObfuscatedConn) lastWriteTime() time.Time {
	ns := c.lastWriteNs.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (c *ObfuscatedConn) fakeKeepalives() {
	for {
		delay := randomDuration(MaxKeepaliveDelay-MinKeepaliveDelay) + MinKeepaliveDelay
		select {
		case <-c.done:
			return
		case <-time.After(delay):
			frame, err := proto.Encode(proto.FrameKeepalive, nil, c.cipher, c.padCfg)
			if err != nil {
				continue
			}
			if !c.writeMu.TryLock() {
				continue
			}
			_, err = c.Conn.Write(frame)
			c.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (c *ObfuscatedConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.decoy != nil {
			c.decoy.Stop()
		}
	})
	return c.Conn.Close()
}

func randomDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max / 2
	}
	return time.Duration(n.Int64())
}
