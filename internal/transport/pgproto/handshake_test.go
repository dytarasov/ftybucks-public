package pgproto

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
)

// tcpPipe creates a pair of connected TCP connections via loopback.
// uTLS requires real TCP connections (net.Pipe doesn't work with HelloRandomized).
func tcpPipe(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server = <-ch
	return client, server
}

func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	return cert
}

func TestHandshakeRoundTrip(t *testing.T) {
	psk := []byte("test-psk-for-handshake-verification")
	cert := generateTestCert(t)

	clientConn, serverConn := tcpPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 2)
	var serverPG *PGConn
	var clientPG *PGConn

	// Server side
	go func() {
		var err error
		serverPG, err = ServerHandshake(serverConn, psk, cert)
		errCh <- err
	}()

	// Client side
	go func() {
		var err error
		clientPG, err = ClientHandshake(clientConn, psk)
		errCh <- err
	}()

	// Wait for both handshakes
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("handshake error: %v", err)
		}
	}

	defer serverPG.Close()
	defer clientPG.Close()

	// Verify PGConns are usable
	if serverPG == nil || clientPG == nil {
		t.Fatal("nil PGConn returned")
	}
}

func TestHandshakeWrongPSK(t *testing.T) {
	serverPSK := []byte("correct-psk")
	clientPSK := []byte("wrong-psk")
	cert := generateTestCert(t)

	clientConn, serverConn := tcpPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 2)

	go func() {
		_, err := ServerHandshake(serverConn, serverPSK, cert)
		errCh <- err
	}()

	go func() {
		_, err := ClientHandshake(clientConn, clientPSK)
		errCh <- err
	}()

	// At least one side should fail
	var hadError bool
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			hadError = true
		}
	}
	if !hadError {
		t.Fatal("expected handshake failure with wrong PSK")
	}
}

func TestHandshakeTLS(t *testing.T) {
	psk := []byte("test-psk-tls-verify")
	cert := generateTestCert(t)

	clientConn, serverConn := tcpPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 2)
	var serverPG, clientPG *PGConn

	go func() {
		var err error
		serverPG, err = ServerHandshake(serverConn, psk, cert)
		errCh <- err
	}()

	go func() {
		var err error
		clientPG, err = ClientHandshake(clientConn, psk)
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("handshake error: %v", err)
		}
	}

	defer serverPG.Close()
	defer clientPG.Close()

	// Verify data can be sent over the TLS-wrapped connection
	testData := []byte("hello over TLS")
	go func() {
		clientPG.Write(testData)
	}()

	buf := make([]byte, 1024)
	n, err := serverPG.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Fatalf("got %q, want %q", buf[:n], testData)
	}
}

// TestServerSSLReplyMatchesPostgres checks the server against the PostgreSQL
// protocol spec rather than against our own client: the reply to SSLRequest is
// sent in cleartext, so any byte other than 'S' marks the server as not-PG.
func TestServerSSLReplyMatchesPostgres(t *testing.T) {
	cert := generateTestCert(t)
	clientConn, serverConn := tcpPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	go ServerHandshake(serverConn, []byte("psk"), cert)

	// SSLRequest exactly as libpq sends it: int32 length 8, int32 code 80877103.
	if _, err := clientConn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(clientConn, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != 'S' {
		t.Fatalf("SSLRequest reply = %q, PostgreSQL sends 'S'", reply[0])
	}
}
