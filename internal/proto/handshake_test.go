package proto

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
)

// pipeConn pairs two in-memory connections for testing.
func pipeConn() (net.Conn, net.Conn) {
	return net.Pipe()
}

func TestHandshakeSuccess(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	clientConn, serverConn := pipeConn()
	guard := NewReplayGuard()

	var clientKey, serverKey []byte
	var clientErr, serverErr error

	done := make(chan struct{})

	go func() {
		defer close(done)
		serverKey, serverErr = ServerHandshake(serverConn, psk, guard)
	}()

	clientKey, clientErr = ClientHandshake(clientConn, psk)
	<-done

	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatal("client and server derived different session keys")
	}

	if len(clientKey) != KeySize {
		t.Fatalf("session key size %d != %d", len(clientKey), KeySize)
	}
}

func TestHandshakeWrongPSK(t *testing.T) {
	psk1 := make([]byte, 32)
	rand.Read(psk1)
	psk2 := make([]byte, 32)
	rand.Read(psk2)

	clientConn, serverConn := pipeConn()
	guard := NewReplayGuard()

	var serverErr error
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer serverConn.Close()
		_, serverErr = ServerHandshake(serverConn, psk2, guard)
	}()

	_, clientErr := ClientHandshake(clientConn, psk1)
	clientConn.Close()
	<-done

	// At least one side should fail
	if clientErr == nil && serverErr == nil {
		t.Fatal("expected at least one side to fail with mismatched PSKs")
	}
}

func TestReplayGuard(t *testing.T) {
	guard := NewReplayGuard()

	salt := make([]byte, SaltSize)
	rand.Read(salt)

	// First check should pass
	if !guard.Check(salt) {
		t.Fatal("first check should return true")
	}

	// Second check with same salt should fail
	if guard.Check(salt) {
		t.Fatal("second check should return false (replay)")
	}

	// Different salt should pass
	salt2 := make([]byte, SaltSize)
	rand.Read(salt2)
	if !guard.Check(salt2) {
		t.Fatal("different salt should return true")
	}
}

func TestReplayGuardInvalidSize(t *testing.T) {
	guard := NewReplayGuard()
	if guard.Check([]byte("short")) {
		t.Fatal("should reject short salt")
	}
}

func TestECDHForwardSecrecy(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	guard := NewReplayGuard()

	// Session 1
	c1, s1 := pipeConn()
	var key1Client, key1Server []byte
	var err1C, err1S error

	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		key1Server, err1S = ServerHandshake(s1, psk, guard)
	}()
	key1Client, err1C = ClientHandshake(c1, psk)
	<-done1

	if err1C != nil {
		t.Fatalf("session 1 client: %v", err1C)
	}
	if err1S != nil {
		t.Fatalf("session 1 server: %v", err1S)
	}
	if !bytes.Equal(key1Client, key1Server) {
		t.Fatal("session 1: client/server keys differ")
	}

	// Session 2 (same PSK → different session keys due to ECDH)
	c2, s2 := pipeConn()
	var key2Client, key2Server []byte
	var err2C, err2S error

	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		key2Server, err2S = ServerHandshake(s2, psk, guard)
	}()
	key2Client, err2C = ClientHandshake(c2, psk)
	<-done2

	if err2C != nil {
		t.Fatalf("session 2 client: %v", err2C)
	}
	if err2S != nil {
		t.Fatalf("session 2 server: %v", err2S)
	}
	if !bytes.Equal(key2Client, key2Server) {
		t.Fatal("session 2: client/server keys differ")
	}

	// The two session keys MUST differ (ephemeral ECDH ensures this)
	if bytes.Equal(key1Client, key2Client) {
		t.Fatal("two sessions with same PSK produced identical keys — no forward secrecy")
	}
}
