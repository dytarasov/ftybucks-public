package routing

import (
	"strconv"
	"testing"
)

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

// simulateSel runs n new flows (mark 0) through FTYB_SEL rules with iptables
// semantics: rules are evaluated in order, MARK does not stop the chain, a
// match list is short-circuited left to right, and each statistic match keeps
// its own nth counter that only advances when the match is evaluated.
func simulateSel(t *testing.T, rules [][]string, n int) map[string]int {
	t.Helper()
	counters := make([]int, len(rules))
	got := map[string]int{}
	for f := 0; f < n; f++ {
		mark := "0x0"
	rule:
		for i, r := range rules {
			for a := 0; a < len(r); a++ {
				switch {
				case r[a] == "--mark":
					if r[a+1] != "0x0/"+stickyMarkMask {
						t.Fatalf("unexpected mark match %q", r[a+1])
					}
					if mark != "0x0" {
						continue rule
					}
				case r[a] == "--every":
					every, _ := strconv.Atoi(r[a+1])
					hit := counters[i]%every == 0
					counters[i]++
					if !hit {
						continue rule
					}
				case r[a] == "--set-mark":
					mark = r[a+1]
				}
			}
		}
		got[mark]++
	}
	return got
}

func TestStickySelectRulesSpreadEvenly(t *testing.T) {
	for k := 1; k <= 4; k++ {
		marks := make([]string, k)
		for i := range marks {
			marks[i] = stickyMark(i)
		}
		rules := stickySelectRules(marks)
		if last := rules[len(rules)-1]; last[len(last)-1] != "--save-mark" {
			t.Fatalf("k=%d: last rule must save the mark, got %v", k, last)
		}
		const perTunnel = 100
		got := simulateSel(t, rules, k*perTunnel)
		for _, m := range marks {
			if got[m] != perTunnel {
				t.Errorf("k=%d: %s got %d flows, want %d (all: %v)", k, m, got[m], perTunnel, got)
			}
		}
		if got["0x0"] != 0 {
			t.Errorf("k=%d: %d flows left unmarked", k, got["0x0"])
		}
	}
}
