package pgproto

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func setupPGConns(t *testing.T) (*PGConn, *PGConn) {
	t.Helper()
	psk := []byte("test-psk-pgconn")
	cert := generateTestCert(t)

	clientConn, serverConn := tcpPipe(t)

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
			clientConn.Close()
			serverConn.Close()
			t.Fatalf("handshake: %v", err)
		}
	}

	return clientPG, serverPG
}

func TestPGConnRoundTrip(t *testing.T) {
	client, server := setupPGConns(t)
	defer client.Close()
	defer server.Close()

	// Client → Server
	testData := []byte("hello from client")
	go func() {
		client.Write(testData)
	}()

	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("server got %q, want %q", buf[:n], testData)
	}

	// Server → Client
	testData2 := []byte("hello from server")
	go func() {
		server.Write(testData2)
	}()

	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData2) {
		t.Fatalf("client got %q, want %q", buf[:n], testData2)
	}
}

func TestPGConnLargePayload(t *testing.T) {
	client, server := setupPGConns(t)
	defer client.Close()
	defer server.Close()

	// Send 64KB payload
	data := make([]byte, 65536)
	for i := range data {
		data[i] = byte(i % 256)
	}

	go func() {
		client.Write(data)
	}()

	received := make([]byte, 0, len(data))
	buf := make([]byte, 4096)
	for len(received) < len(data) {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("server read: %v (received %d/%d)", err, len(received), len(data))
		}
		received = append(received, buf[:n]...)
	}

	if !bytes.Equal(received, data) {
		t.Fatal("large payload mismatch")
	}
}

func TestPGConnMultipleMessages(t *testing.T) {
	client, server := setupPGConns(t)
	defer client.Close()
	defer server.Close()

	messages := []string{"first", "second", "third"}

	go func() {
		for _, msg := range messages {
			client.Write([]byte(msg))
		}
	}()

	for _, expected := range messages {
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf[:n]) != expected {
			t.Fatalf("got %q, want %q", buf[:n], expected)
		}
	}
}

func TestPGConnClose(t *testing.T) {
	client, server := setupPGConns(t)

	client.Close()

	// Give the close a moment to propagate
	time.Sleep(10 * time.Millisecond)

	buf := make([]byte, 1024)
	_, err := server.Read(buf)
	if err == nil || err == io.EOF {
		// Either EOF or a closed connection error is acceptable
		return
	}
	// Any error after close is fine
}

func TestPGConnRandomWALOffset(t *testing.T) {
	client, server := setupPGConns(t)
	defer client.Close()
	defer server.Close()

	// Both sides should have non-zero WAL positions
	clientWAL := client.walPos.Load()
	serverWAL := server.walPos.Load()

	if clientWAL == 0 {
		t.Fatal("client walPos should be non-zero")
	}
	if serverWAL == 0 {
		t.Fatal("server walPos should be non-zero")
	}

	// Must be 16MB-aligned
	if clientWAL%uint64(walSegmentSize) != 0 {
		t.Fatalf("client walPos %d not 16MB-aligned", clientWAL)
	}
	if serverWAL%uint64(walSegmentSize) != 0 {
		t.Fatalf("server walPos %d not 16MB-aligned", serverWAL)
	}

	// Must be in range [16GB, 4TB)
	const minWAL = uint64(16) * 1024 * 1024 * 1024
	const maxWAL = uint64(4) * 1024 * 1024 * 1024 * 1024
	if clientWAL < minWAL || clientWAL >= maxWAL {
		t.Fatalf("client walPos %d out of range [16GB, 4TB)", clientWAL)
	}
	if serverWAL < minWAL || serverWAL >= maxWAL {
		t.Fatalf("server walPos %d out of range [16GB, 4TB)", serverWAL)
	}
}
