//go:build linux && netintegration

// Integration tests against a real kernel, iptables, ipset and iproute2.
// They change the host's firewall and routing, so run them only inside a
// throwaway privileged container:
//
//	docker run --rm --privileged -v "$PWD":/src -w /src golang:1.24 \
//	  sh -c 'apt-get update -qq && apt-get install -yqq iptables ipset iproute2 >/dev/null &&
//	         go test -tags netintegration -count=1 -v ./internal/routing/'
package routing

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if err := run(name, args...); err != nil {
		t.Fatal(err)
	}
}

func output(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %s: %v", name, args, out, err)
	}
	return string(out)
}

func requireRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (run in a privileged container)")
	}
}

// dummyNet brings up dummy0 with 10.77.0.1/24 so packets to 10.77.x have
// somewhere to go; removed on cleanup.
func dummyNet(t *testing.T) {
	t.Helper()
	run("ip", "link", "del", "dummy0")
	mustRun(t, "ip", "link", "add", "dummy0", "type", "dummy")
	mustRun(t, "ip", "addr", "add", "10.77.0.1/24", "dev", "dummy0")
	mustRun(t, "ip", "link", "set", "dummy0", "up")
	t.Cleanup(func() { run("ip", "link", "del", "dummy0") })
}

// sendUDP sends n datagrams to dst:9 from a socket carrying SO_MARK mark.
func sendUDP(t *testing.T, dst string, mark, n int) {
	t.Helper()
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if mark != 0 {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
			}
		}); err != nil {
			return err
		}
		return serr
	}}
	c, err := d.Dial("udp4", net.JoinHostPort(dst, "9"))
	if err != nil {
		t.Fatalf("dial %s: %v", dst, err)
	}
	defer c.Close()
	for i := 0; i < n; i++ {
		c.Write([]byte("x"))
	}
}

// counters returns packet counts of a chain's rules keyed by rule comment.
func counters(t *testing.T, table, chain string) map[string]int {
	t.Helper()
	got := map[string]int{}
	for _, line := range strings.Split(output(t, "iptables", "-t", table, "-L", chain, "-v", "-n", "-x"), "\n") {
		i := strings.Index(line, "/* ")
		if i < 0 {
			continue
		}
		f := strings.Fields(line)
		n, _ := strconv.Atoi(f[0])
		got[strings.TrimSuffix(line[i+3:], " */")] += n
	}
	return got
}

// countMarks appends counting rules to mangle POSTROUTING for dst: one per
// mark of interest, labelled "<label>=<mark>".
func countMarks(t *testing.T, label, dst string, marks ...string) {
	t.Helper()
	for _, m := range marks {
		mustRun(t, "iptables", "-t", "mangle", "-A", "POSTROUTING", "-d", dst,
			"-m", "mark", "--mark", m, "-m", "comment", "--comment", label+"="+m)
	}
	t.Cleanup(func() { run("iptables", "-t", "mangle", "-F", "POSTROUTING") })
}

func TestIntegrationStickyRestoreSplitsAndIsAtomic(t *testing.T) {
	requireRoot(t)
	dummyNet(t)
	run("iptables", "-t", "mangle", "-N", stickyChain)
	t.Cleanup(func() {
		run("iptables", "-t", "mangle", "-D", "OUTPUT", "-d", "10.77.0.2", "-j", stickyChain)
		run("iptables", "-t", "mangle", "-F", stickyChain)
		run("iptables", "-t", "mangle", "-X", stickyChain)
	})
	mustRun(t, "iptables", "-t", "mangle", "-A", "OUTPUT", "-d", "10.77.0.2", "-j", stickyChain)

	marks := []string{stickyMark(0), stickyMark(1), stickyMark(2)}
	if err := runStdin(stickyRestore(marks), "iptables-restore", "--noflush"); err != nil {
		t.Fatal(err)
	}
	countMarks(t, "sel", "10.77.0.2", marks...)
	sendUDP(t, "10.77.0.2", 0, 300)
	got := counters(t, "mangle", "POSTROUTING")
	for _, m := range marks {
		if got["sel="+m] != 100 {
			t.Errorf("mark %s: %d packets, want 100 (all: %v)", m, got["sel="+m], got)
		}
	}

	// A rebuild that fails part-way must leave the previous selection intact.
	before := output(t, "iptables", "-t", "mangle", "-S", stickyChain)
	if err := runStdin(stickyRestore([]string{stickyMark(0), "not-a-mark"}), "iptables-restore", "--noflush"); err == nil {
		t.Fatal("restore with an invalid mark should fail")
	}
	if after := output(t, "iptables", "-t", "mangle", "-S", stickyChain); after != before {
		t.Fatalf("failed restore changed the chain:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestIntegrationFallbackRouteBlocksLeak(t *testing.T) {
	requireRoot(t)
	dummyNet(t)
	const table = "100"
	run("ip", "rule", "del", "fwmark", MarkTunnel, "table", table)
	mustRun(t, "ip", "rule", "add", "fwmark", MarkTunnel, "table", table)
	t.Cleanup(func() {
		run("ip", "rule", "del", "fwmark", MarkTunnel, "table", table)
		run("ip", "route", "flush", "table", table)
	})
	// The main table has a route to 10.77.0.9 (dummy0), i.e. a "direct exit".
	if err := addFallbackRoute(table); err != nil {
		t.Fatal(err)
	}
	// A tunnel device standing in for stunN.
	mustRun(t, "ip", "link", "add", "stuntest", "type", "dummy")
	mustRun(t, "ip", "link", "set", "stuntest", "up")
	t.Cleanup(func() { run("ip", "link", "del", "stuntest") })
	mustRun(t, "ip", "route", "replace", "default", "dev", "stuntest", "table", table)

	if out := output(t, "ip", "route", "get", "10.77.0.9", "mark", MarkTunnel); !strings.Contains(out, "dev stuntest") {
		t.Fatalf("with the tunnel up, marked traffic should use it: %s", out)
	}
	// Tunnel device disappears → its route goes with it.
	mustRun(t, "ip", "link", "del", "stuntest")
	out, err := exec.Command("ip", "route", "get", "10.77.0.9", "mark", MarkTunnel).CombinedOutput()
	if err == nil {
		t.Fatalf("tunnel gone: marked traffic must be rejected, not routed: %s", out)
	}
	// The unreachable route makes the kernel answer EHOSTUNREACH.
	if !strings.Contains(string(out), "No route to host") {
		t.Fatalf("expected the fallback to reject, got: %s", out)
	}
	// Unmarked traffic still goes direct as before.
	if out := output(t, "ip", "route", "get", "10.77.0.9"); !strings.Contains(out, "dev dummy0") {
		t.Fatalf("unmarked traffic should use the main table: %s", out)
	}
}

func TestIntegrationTransitChainClassifies(t *testing.T) {
	requireRoot(t)
	dummyNet(t)
	for _, set := range []string{IPSetDirect, IPSetProxy} {
		run("ipset", "destroy", set)
		mustRun(t, "ipset", "create", set, "hash:net")
		set := set
		t.Cleanup(func() { run("ipset", "destroy", set) })
	}
	mustRun(t, "ipset", "add", IPSetDirect, "10.77.0.0/24") // "RU"
	mustRun(t, "ipset", "add", IPSetProxy, "10.77.0.128/25") // force-proxy inside RU

	for _, ob := range []int{255, 1} { // 1 is the case where the proxy mark equals MarkTunnel
		t.Run("outbound_mark="+strconv.Itoa(ob), func(t *testing.T) {
			run("iptables", "-t", "mangle", "-N", outChain)
			for _, s := range append(outChainRules(), transitJumpRule("-A", ob)) {
				mustRun(t, "iptables", s...)
			}
			t.Cleanup(func() {
				run("iptables", transitJumpRule("-D", ob)...)
				run("iptables", "-t", "mangle", "-F", outChain)
				run("iptables", "-t", "mangle", "-X", outChain)
			})
			countMarks(t, "direct", "10.77.0.10", MarkDirect, MarkTunnel)
			countMarks(t, "proxy", "10.77.0.200", MarkDirect, MarkTunnel)
			sendUDP(t, "10.77.0.10", ob, 5)
			sendUDP(t, "10.77.0.200", ob, 5)
			got := counters(t, "mangle", "POSTROUTING")
			if got["direct="+MarkDirect] != 5 || got["direct="+MarkTunnel] != 0 {
				t.Errorf("RU destination should leave direct (mark 0): %v", got)
			}
			if got["proxy="+MarkTunnel] != 5 || got["proxy="+MarkDirect] != 0 {
				t.Errorf("force-proxy destination should be tunnelled (mark 1): %v", got)
			}
		})
	}
}
