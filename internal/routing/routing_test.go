package routing

import "testing"

// TestFilterIfaces verifies the device-existence filter keeps order and drops
// only the entries the predicate rejects — the core of the fix that stops a
// dead pool member's missing stunN device from crashing the gateway at startup.
func TestFilterIfaces(t *testing.T) {
	all := []string{"stun0", "stun1", "stun2"}
	// stun1 is "dead" (device absent).
	got := filterIfaces(all, func(n string) bool { return n != "stun1" })
	want := []string{"stun0", "stun2"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	// All dead → empty (setupPolicyRouting then defers the route).
	if g := filterIfaces(all, func(string) bool { return false }); len(g) != 0 {
		t.Fatalf("expected empty, got %v", g)
	}
	// All alive → unchanged.
	if g := filterIfaces(all, func(string) bool { return true }); len(g) != 3 {
		t.Fatalf("expected all 3, got %v", g)
	}
}
