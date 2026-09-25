package transport

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"

	"ftybucks/internal/config"
	"ftybucks/internal/proto"
)

// Decoy traffic models idle PostgreSQL streaming replication:
//   - Inter-arrival times: exponential distribution (Poisson process)
//   - Payload sizes: log-normal distribution (matches WAL record sizes)
//
// Real PG WAL record sizes during idle period:
//   - Small (heartbeats, commits): 50–500 B
//   - Medium (row updates): 500 B – 4 KB
//   - Large (bulk changes, TOAST): 4 KB – 32 KB
//
// Defaults below target ~1 frame every 3–5 seconds on average, with sizes
// centered around ~300 B but occasionally spiking to a few KB.
const (
	decoyRateHz    = 0.25 // ~1 frame every 4s on average
	decoyLogMu     = 5.7  // exp(5.7) ≈ 300 bytes median
	decoyLogSigma  = 1.3  // spread: occasional 4–8 KB frames
	decoyMinBytes  = 64
	decoyMaxBytes  = 16 * 1024

	// Decoys are suppressed if real traffic was sent within this window.
	decoyIdleThreshold = 2 * time.Second
)

// decoyWriter is the minimal interface DecoyGenerator needs.
type decoyWriter interface {
	writeRaw([]byte) error
	lastWriteTime() time.Time
}

// DecoyGenerator emits FrameDecoy frames at Poisson-distributed intervals
// with log-normal-distributed sizes to simulate idle WAL replication activity.
type DecoyGenerator struct {
	w       decoyWriter
	cipher  *proto.Cipher
	padding config.PaddingConfig

	stopOnce sync.Once
	done     chan struct{}
}

// NewDecoyGenerator creates a generator that emits decoy frames via the given writer.
func NewDecoyGenerator(w decoyWriter, cipher *proto.Cipher, padding config.PaddingConfig) *DecoyGenerator {
	return &DecoyGenerator{
		w:       w,
		cipher:  cipher,
		padding: padding,
		done:    make(chan struct{}),
	}
}

// Start begins the decoy goroutine.
func (d *DecoyGenerator) Start() {
	go d.loop()
}

// Stop halts the decoy goroutine.
func (d *DecoyGenerator) Stop() {
	d.stopOnce.Do(func() { close(d.done) })
}

func (d *DecoyGenerator) loop() {
	for {
		wait := exponentialDelay(decoyRateHz)
		select {
		case <-d.done:
			return
		case <-time.After(wait):
		}

		// Probabilistically suppress if real traffic recently flowed. Real PG
		// replication can overlap heartbeats with WAL bursts occasionally, so
		// a hard 0% rate during activity is itself a fingerprint. Drop to ~20%
		// emission during active windows instead of 0%.
		if time.Since(d.w.lastWriteTime()) < decoyIdleThreshold {
			var b [1]byte
			rand.Read(b[:])
			if b[0] >= 51 { // ~20% pass through (51/256 ≈ 0.20)
				continue
			}
		}

		size := logNormalSize()
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			continue
		}

		frame, err := proto.Encode(proto.FrameDecoy, payload, d.cipher, d.padding)
		if err != nil {
			continue
		}

		if err := d.w.writeRaw(frame); err != nil {
			return
		}
	}
}

// exponentialDelay returns a duration from Exp(λ) with rate in events/sec.
func exponentialDelay(rate float64) time.Duration {
	var buf [8]byte
	rand.Read(buf[:])
	u := float64(binary.BigEndian.Uint64(buf[:])) / float64(^uint64(0))
	if u <= 0 {
		u = 1e-12
	}
	seconds := -math.Log(u) / rate
	return time.Duration(seconds * float64(time.Second))
}

// logNormalSize returns a size in bytes from LogNormal(μ, σ), clamped.
// Uses Box–Muller to transform two uniform samples into one normal sample.
func logNormalSize() int {
	var buf [16]byte
	rand.Read(buf[:])
	u1 := float64(binary.BigEndian.Uint64(buf[0:8])) / float64(^uint64(0))
	u2 := float64(binary.BigEndian.Uint64(buf[8:16])) / float64(^uint64(0))
	if u1 <= 0 {
		u1 = 1e-12
	}
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	if math.IsNaN(z) || math.IsInf(z, 0) {
		z = 0
	}
	sizeF := math.Exp(decoyLogMu + decoyLogSigma*z)
	if math.IsNaN(sizeF) || math.IsInf(sizeF, 0) || sizeF < float64(decoyMinBytes) {
		return decoyMinBytes
	}
	if sizeF > float64(decoyMaxBytes) {
		return decoyMaxBytes
	}
	return int(sizeF)
}
