package main

import (
	"encoding/binary"
	"testing"
	"time"
)

// TestRttProbeOnPong verifies a pong resets the miss counter and records a
// positive RTT derived from the echoed send timestamp.
func TestRttProbeOnPong(t *testing.T) {
	p := &rttProbe{}
	p.misses.Store(3)

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(time.Now().Add(-10*time.Millisecond).UnixNano()))
	p.onPong(buf[:])

	if got := p.misses.Load(); got != 0 {
		t.Fatalf("misses not reset: %d", got)
	}
	if got := p.lastRTTus.Load(); got <= 0 {
		t.Fatalf("rtt not recorded: %d", got)
	}
	if p.rttString() == "n/a" {
		t.Fatalf("rttString should not be n/a after a pong")
	}
}

// TestRttProbeShortPayload ignores a malformed pong payload without recording RTT.
func TestRttProbeShortPayload(t *testing.T) {
	p := &rttProbe{}
	p.misses.Store(2)
	p.onPong([]byte{1, 2, 3}) // < 8 bytes
	if got := p.misses.Load(); got != 0 {
		t.Fatalf("misses should still reset on any pong: %d", got)
	}
	if got := p.lastRTTus.Load(); got != 0 {
		t.Fatalf("rtt should be unrecorded for short payload: %d", got)
	}
}
