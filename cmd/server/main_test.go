package main

import (
	"net"
	"testing"

	"ftybucks/internal/tunnel"
)

type nopCloser struct{ closed bool }

func (n *nopCloser) Close() error { n.closed = true; return nil }

// TestSessionTableStickyIP covers the reconnect-by-token path: a client that
// re-presents its token gets the same IP back, the stale session is evicted, and
// the stale session's late remove() must not clobber or free the new session.
func TestSessionTableStickyIP(t *testing.T) {
	pool, err := tunnel.NewIPPool("10.7.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	table := newSessionTable(pool)

	tok := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	s1, ev, err := table.assign(tok, net.IPv4zero.To4(), &nopCloser{})
	if err != nil {
		t.Fatalf("first assign: %v", err)
	}
	if ev != nil {
		t.Fatalf("unexpected eviction on first assign")
	}
	ip1 := s1.ipStr
	if table.get(ip1) != s1 {
		t.Fatalf("s1 not registered by IP")
	}

	// Reconnect with the same token, preferring the same IP.
	s2, ev, err := table.assign(tok, s1.ip, &nopCloser{})
	if err != nil {
		t.Fatalf("reconnect assign: %v", err)
	}
	if ev != s1 {
		t.Fatalf("expected s1 to be evicted, got %v", ev)
	}
	if s2.ipStr != ip1 {
		t.Fatalf("sticky IP not preserved: %s != %s", s2.ipStr, ip1)
	}
	if table.get(ip1) != s2 {
		t.Fatalf("IP should now point at s2")
	}

	// The evicted session's read loop exits later and calls remove(s1). Because
	// the maps now point at s2, this must be a no-op (no release, no clobber).
	table.remove(s1)
	if table.get(ip1) != s2 {
		t.Fatalf("stale remove(s1) clobbered s2")
	}

	// Removing the live session releases the IP.
	table.remove(s2)
	if table.get(ip1) != nil {
		t.Fatalf("expected IP released after remove(s2)")
	}

	// Freed IP can be handed out again.
	s3, _, err := table.assign(nil, net.ParseIP(ip1).To4(), &nopCloser{})
	if err != nil {
		t.Fatalf("reallocate freed IP: %v", err)
	}
	if s3.ipStr != ip1 {
		t.Fatalf("wanted %s got %s", ip1, s3.ipStr)
	}
}

// TestSessionTableReclaimByIP covers a client with no token requesting a
// specific IP that is still held (e.g. gateway restarted, token changed): the
// stale holder is reclaimed instead of the assignment failing.
func TestSessionTableReclaimByIP(t *testing.T) {
	pool, err := tunnel.NewIPPool("10.7.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	table := newSessionTable(pool)

	ip := net.ParseIP("10.7.0.5").To4()

	s1, ev, err := table.assign(nil, ip, &nopCloser{})
	if err != nil || ev != nil {
		t.Fatalf("first assign: err=%v ev=%v", err, ev)
	}
	s2, ev, err := table.assign(nil, ip, &nopCloser{})
	if err != nil {
		t.Fatalf("reclaim assign: %v", err)
	}
	if ev != s1 {
		t.Fatalf("expected s1 reclaimed, got %v", ev)
	}
	if s2.ipStr != "10.7.0.5" {
		t.Fatalf("got %s", s2.ipStr)
	}
}

// TestSessionTableDistinctTokens verifies two different members get two
// different IPs and neither evicts the other.
func TestSessionTableDistinctTokens(t *testing.T) {
	pool, err := tunnel.NewIPPool("10.7.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	table := newSessionTable(pool)

	a, ev, err := table.assign([]byte("aaaaaaaa"), net.IPv4zero.To4(), &nopCloser{})
	if err != nil || ev != nil {
		t.Fatalf("assign a: err=%v ev=%v", err, ev)
	}
	b, ev, err := table.assign([]byte("bbbbbbbb"), net.IPv4zero.To4(), &nopCloser{})
	if err != nil || ev != nil {
		t.Fatalf("assign b: err=%v ev=%v", err, ev)
	}
	if a.ipStr == b.ipStr {
		t.Fatalf("distinct members share IP %s", a.ipStr)
	}
}
