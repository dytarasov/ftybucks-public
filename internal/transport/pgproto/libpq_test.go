package pgproto

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRealLibpqClient points a genuine PostgreSQL client (psql/libpq) at the
// server. psql cannot know the PSK, so the connection must fail at password
// authentication — which proves libpq accepted the SSLRequest reply, finished
// its TLS handshake and got as far as auth, exactly as against a real server.
// Skipped when psql is not installed.
func TestRealLibpqClient(t *testing.T) {
	psql, err := exec.LookPath("psql")
	if err != nil {
		t.Skip("psql not in PATH")
	}
	cert := generateTestCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		_, err = ServerHandshake(c, []byte("the-real-psk-psql-does-not-know"), cert)
		srvErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	port := ln.Addr().(*net.TCPAddr).Port
	cmd := exec.CommandContext(ctx, psql,
		fmt.Sprintf("host=127.0.0.1 port=%d user=replicator dbname=postgres sslmode=require connect_timeout=5", port),
		"-c", "select 1")
	cmd.Env = append(os.Environ(), "PGPASSWORD=wrong", "PGSSLMODE=require")
	out, _ := cmd.CombinedOutput()
	msg := string(out)
	t.Logf("psql: %s", strings.TrimSpace(msg))

	if strings.Contains(msg, "SSL negotiation") || strings.Contains(msg, "SSL") && !strings.Contains(msg, "password") {
		t.Fatalf("libpq rejected the TLS negotiation: %s", msg)
	}
	if !strings.Contains(msg, "password authentication failed") {
		t.Fatalf("expected psql to reach password auth, got: %s", msg)
	}
	select {
	case err := <-srvErr:
		if err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("server should fail at auth, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not finish")
	}
}
