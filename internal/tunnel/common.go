package tunnel

import (
	"fmt"
	"sync"

	"github.com/songgao/water"
)

const DefaultMTU = 1500

const readBufSize = DefaultMTU + 100

// Pool for TUN read buffers.
var readBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, readBufSize)
		return &buf
	},
}

// ReadPacket reads a single IP packet from the TUN interface.
// The returned slice is valid until the next call — caller must copy if needed.
func ReadPacket(tun *water.Interface) ([]byte, error) {
	bufPtr := readBufPool.Get().(*[]byte)
	buf := *bufPtr
	n, err := tun.Read(buf)
	if err != nil {
		readBufPool.Put(bufPtr)
		return nil, fmt.Errorf("tun read: %w", err)
	}
	// Copy out so the pool buffer can be reused
	pkt := make([]byte, n)
	copy(pkt, buf[:n])
	readBufPool.Put(bufPtr)
	return pkt, nil
}

// WritePacket writes an IP packet to the TUN interface.
func WritePacket(tun *water.Interface, pkt []byte) error {
	_, err := tun.Write(pkt)
	if err != nil {
		return fmt.Errorf("tun write: %w", err)
	}
	return nil
}
