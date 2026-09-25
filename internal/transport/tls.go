package transport

import (
	"fmt"
	"net"
	"time"

	"ftybucks/internal/transport/pgproto"
)

// tcpBufferSize is the SO_RCVBUF/SO_SNDBUF value applied to outer TCP sockets.
// Linux respects the actual size only up to net.core.{r,w}mem_max (sysctl); we
// set 16MB so high-BDP paths (RTT 80–100ms) can fill the pipe instead of
// stalling on the default 128KB socket buffer.
const tcpBufferSize = 16 * 1024 * 1024

func tuneTCPConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetReadBuffer(tcpBufferSize)
	_ = tc.SetWriteBuffer(tcpBufferSize)
}

// DialServer establishes a TCP connection to the server and performs
// a PostgreSQL streaming replication handshake for DPI evasion.
// Returns a PGConn that implements net.Conn with CopyData framing.
func DialServer(addr string, psk []byte) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}
	tuneTCPConn(conn)

	pgConn, err := pgproto.ClientHandshake(conn, psk)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("pg handshake: %w", err)
	}

	return pgConn, nil
}

// ListenServer starts a TCP listener with TCP_NODELAY enabled on accepted connections.
func ListenServer(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return &noDelayListener{ln}, nil
}

// noDelayListener wraps a net.Listener to set TCP_NODELAY on accepted connections,
// disabling Nagle's algorithm to avoid 40ms batching delays on small writes.
type noDelayListener struct {
	net.Listener
}

func (l *noDelayListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	tuneTCPConn(conn)
	return conn, nil
}
