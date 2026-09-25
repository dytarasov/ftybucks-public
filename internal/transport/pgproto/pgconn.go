package pgproto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// bufPools provides power-of-two sized buffer pools (2^4=16 through 2^24=16MB).
var bufPools [21]sync.Pool

func poolIdx(size int) int {
	if size <= 16 {
		return 0
	}
	idx := bits.Len(uint(size-1)) - 4
	if idx < 0 {
		return 0
	}
	if idx >= len(bufPools) {
		return len(bufPools) - 1
	}
	return idx
}

func getBuf(size int) []byte {
	idx := poolIdx(size)
	if b, ok := bufPools[idx].Get().([]byte); ok {
		return b[:size]
	}
	return make([]byte, size, 1<<(idx+4))
}

func putBuf(b []byte) {
	c := cap(b)
	if c < 16 || c&(c-1) != 0 {
		return
	}
	idx := bits.TrailingZeros(uint(c)) - 4
	if idx < 0 || idx >= len(bufPools) {
		return
	}
	bufPools[idx].Put(b[:c])
}

// keepaliveBase is the median period for Standby/Primary keepalive frames.
// Shortened from the typical 10s to 7s because RU↔EU peering routers have been
// observed to RST idle TCP flows past ~10–15s. The actual delay between frames
// is randomized ±30% (5–9.1s) to defeat DPI that fingerprints periodic traffic.
const keepaliveBase = 7 * time.Second

func keepaliveDelay() time.Duration {
	var b [2]byte
	rand.Read(b[:])
	// Map uint16 → [0.7, 1.3] → ±30% jitter around the base.
	frac := 0.7 + float64(binary.BigEndian.Uint16(b[:]))/65535.0*0.6
	return time.Duration(float64(keepaliveBase) * frac)
}

// PGConn wraps a net.Conn with PostgreSQL CopyData framing.
// Implements net.Conn — drop-in replacement for the underlying connection.
type PGConn struct {
	conn     net.Conn
	isServer bool
	walPos   atomic.Uint64
	writeMu  sync.Mutex
	readBuf  bytes.Buffer
	closeOnce sync.Once
	done      chan struct{}
}

const walSegmentSize = 16 * 1024 * 1024 // 16MB PG WAL segment

func newPGConn(conn net.Conn, isServer bool) *PGConn {
	pc := &PGConn{
		conn:     conn,
		isServer: isServer,
		done:     make(chan struct{}),
	}

	// Random WAL offset: 16GB–4TB, aligned to 16MB segment boundaries.
	// Matches realistic LSN magnitude for a production standby with months of history.
	var walBuf [8]byte
	rand.Read(walBuf[:])
	const minWAL = uint64(16) * 1024 * 1024 * 1024        // 16 GB
	const maxWAL = uint64(4) * 1024 * 1024 * 1024 * 1024  // 4 TB
	initialWAL := minWAL + binary.BigEndian.Uint64(walBuf[:])%(maxWAL-minWAL)
	initialWAL = (initialWAL / uint64(walSegmentSize)) * uint64(walSegmentSize)
	pc.walPos.Store(initialWAL)

	go pc.keepaliveLoop()
	return pc
}

// Write wraps data in CopyData frames using a single pooled buffer.
// Server side: CopyData { XLogData header + payload } — 30 + len(b) bytes
// Client side: CopyData { payload } — 5 + len(b) bytes
func (pc *PGConn) Write(b []byte) (int, error) {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	var totalLen int
	if pc.isServer {
		totalLen = 30 + len(b)
	} else {
		totalLen = 5 + len(b)
	}

	buf := getBuf(totalLen)

	if pc.isServer {
		walPos := pc.walPos.Load()
		// CopyData header
		buf[0] = tagCopyData
		binary.BigEndian.PutUint32(buf[1:5], uint32(29+len(b)))
		// XLogData header (25 bytes)
		buf[5] = 'w'
		binary.BigEndian.PutUint64(buf[6:14], walPos)
		binary.BigEndian.PutUint64(buf[14:22], walPos+uint64(len(b)))
		binary.BigEndian.PutUint64(buf[22:30], uint64(pgTimestamp()))
		copy(buf[30:], b)
	} else {
		buf[0] = tagCopyData
		binary.BigEndian.PutUint32(buf[1:5], uint32(4+len(b)))
		copy(buf[5:], b)
	}

	pc.walPos.Add(uint64(len(b)))

	_, err := pc.conn.Write(buf[:totalLen])
	putBuf(buf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read reads application data from CopyData frames, stripping PG framing.
func (pc *PGConn) Read(b []byte) (int, error) {
	for pc.readBuf.Len() == 0 {
		if err := pc.readFrame(); err != nil {
			return 0, err
		}
	}
	return pc.readBuf.Read(b)
}

func (pc *PGConn) readFrame() error {
	var hdr [5]byte
	for {
		// Read CopyData header: tag(1) + length(4)
		if _, err := io.ReadFull(pc.conn, hdr[:]); err != nil {
			return err
		}

		length := binary.BigEndian.Uint32(hdr[1:5])
		if length < 4 || length > 1<<24 {
			return fmt.Errorf("invalid copydata length: %d", length)
		}

		if hdr[0] != tagCopyData {
			// Skip non-CopyData messages
			discard := getBuf(int(length) - 4)
			_, err := io.ReadFull(pc.conn, discard)
			putBuf(discard)
			if err != nil {
				return err
			}
			continue
		}

		payloadLen := int(length) - 4
		if payloadLen == 0 {
			continue
		}

		payload := getBuf(payloadLen)
		if _, err := io.ReadFull(pc.conn, payload); err != nil {
			putBuf(payload)
			return err
		}

		// Inspect replication message type
		switch payload[0] {
		case 'w': // XLogData — strip 25-byte header, buffer remaining
			if payloadLen <= 25 {
				putBuf(payload)
				continue
			}
			pc.readBuf.Write(payload[25:payloadLen])
			putBuf(payload)
			return nil
		case 'k': // PrimaryKeepalive — discard
			putBuf(payload)
			continue
		case 'r': // StandbyStatusUpdate — discard
			putBuf(payload)
			continue
		default:
			// Raw CopyData (client→server sends raw payloads)
			pc.readBuf.Write(payload[:payloadLen])
			putBuf(payload)
			return nil
		}
	}
}

func (pc *PGConn) keepaliveLoop() {
	for {
		select {
		case <-pc.done:
			return
		case <-time.After(keepaliveDelay()):
			pc.writeMu.Lock()
			var msg []byte
			walPos := pc.walPos.Load()
			if pc.isServer {
				msg = buildPrimaryKeepalive(walPos, false)
			} else {
				msg = buildStandbyStatusUpdate(walPos)
			}
			_, err := pc.conn.Write(msg)
			pc.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (pc *PGConn) Close() error {
	pc.closeOnce.Do(func() {
		close(pc.done)
	})
	return pc.conn.Close()
}

func (pc *PGConn) LocalAddr() net.Addr               { return pc.conn.LocalAddr() }
func (pc *PGConn) RemoteAddr() net.Addr               { return pc.conn.RemoteAddr() }
func (pc *PGConn) SetDeadline(t time.Time) error      { return pc.conn.SetDeadline(t) }
func (pc *PGConn) SetReadDeadline(t time.Time) error   { return pc.conn.SetReadDeadline(t) }
func (pc *PGConn) SetWriteDeadline(t time.Time) error  { return pc.conn.SetWriteDeadline(t) }
