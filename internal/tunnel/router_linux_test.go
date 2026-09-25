//go:build linux && netintegration

// Run inside a throwaway privileged container (changes host routing):
//
//	docker run --rm --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 \
//	  -v "$PWD":/src -w /src golang:1.24 \
//	  sh -c 'apt-get update -qq && apt-get install -yqq iproute2 >/dev/null &&
//	         go test -tags netintegration -count=1 -v ./internal/tunnel/'
package tunnel

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func ipOut(args ...string) (string, error) {
	out, err := exec.Command("ip", args...).CombinedOutput()
	return string(out), err
}

func TestIntegrationBlockIPv6(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	// Fake "native IPv6": a LAN prefix on dummy6 plus a default route out of it.
	exec.Command("ip", "link", "del", "dummy6").Run()
	for _, a := range [][]string{
		{"link", "add", "dummy6", "type", "dummy"},
		{"link", "set", "dummy6", "up"},
		{"-6", "addr", "add", "fd00:77::1/64", "dev", "dummy6", "nodad"},
		{"-6", "route", "add", "default", "via", "fd00:77::fe", "dev", "dummy6"},
	} {
		if out, err := ipOut(a...); err != nil {
			t.Fatalf("ip %v: %s", a, out)
		}
	}
	defer exec.Command("ip", "link", "del", "dummy6").Run()

	const internet, lan = "2001:4860:4860::8888", "fd00:77::5"
	if out, err := ipOut("-6", "route", "get", internet); err != nil || !strings.Contains(out, "dummy6") {
		t.Fatalf("precondition: IPv6 internet should route via dummy6: %s %v", out, err)
	}

	undo, err := blockIPv6()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := ipOut("-6", "route", "get", internet); err == nil {
		t.Errorf("blocked: IPv6 internet must be unreachable, got route: %s", out)
	}
	if out, err := ipOut("-6", "route", "get", lan); err != nil || !strings.Contains(out, "dummy6") {
		t.Errorf("blocked: on-link IPv6 LAN must still work: %s %v", out, err)
	}
	// Idempotent: a second block (stale routes after a crash) must not fail.
	undo2, err := blockIPv6()
	if err != nil {
		t.Fatalf("second blockIPv6: %v", err)
	}
	undo2()
	undo()
	if out, err := ipOut("-6", "route", "get", internet); err != nil || !strings.Contains(out, "dummy6") {
		t.Errorf("after disconnect IPv6 must be restored: %s %v", out, err)
	}
}
