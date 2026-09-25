package proto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"ftybucks/internal/config"
)

const (
	Version = 0x01

	FrameData      byte = 0x01
	FrameKeepalive byte = 0x02
	FrameHandshake byte = 0x03
	FrameClose     byte = 0x04
	FrameAssign    byte = 0x05
	FrameDecoy     byte = 0x06 // fake WAL-like traffic (dropped by receiver)
	FramePing      byte = 0x07 // RTT/liveness probe; payload echoed back as FramePong
	FramePong      byte = 0x08 // reply to FramePing carrying the same payload

	// Header: Version(1) + FrameType(1) + PayloadLen(2) + PaddingLen(2) + Nonce(12) = 18 bytes
	HeaderSize = 1 + 1 + 2 + 2 + NonceSize

	MaxPayloadSize = 65535
)

// Pool for plaintext assembly buffers (payload + padding) to avoid per-packet allocations.
var plaintextPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 2048)
		return &buf
	},
}

// Pool for ciphertext read buffers in Decode.
var ciphertextPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 2048)
		return &buf
	},
}

// Encode builds a complete frame using a cached Cipher:
//
//	[Version 1B][FrameType 1B][PayloadLen 2B][PaddingLen 2B][Nonce 12B][Encrypted(payload+padding)]
func Encode(frameType byte, payload []byte, c *Cipher, padCfg config.PaddingConfig) ([]byte, error) {
	if len(payload) > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d > %d", len(payload), MaxPayloadSize)
	}

	// Calculate padding length
	padLen := 0
	if padCfg.Max > 0 {
		padLen = randomPadLen(padCfg.Min, padCfg.Max)
	}

	plaintextLen := len(payload) + padLen
	totalSize := HeaderSize + plaintextLen + c.Overhead()

	// Single allocation for the entire frame
	frame := make([]byte, totalSize)

	// Build header in-place
	header := frame[:HeaderSize]
	header[0] = Version
	header[1] = frameType
	binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint16(header[4:6], uint16(padLen))
	nonce := header[6:HeaderSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Assemble plaintext (payload + padding) in pool buffer
	ptBufPtr := plaintextPool.Get().(*[]byte)
	ptBuf := *ptBufPtr
	if cap(ptBuf) < plaintextLen {
		ptBuf = make([]byte, plaintextLen)
	} else {
		ptBuf = ptBuf[:plaintextLen]
	}
	copy(ptBuf, payload)
	if padLen > 0 {
		rand.Read(ptBuf[len(payload):])
	}

	// Encrypt: Seal appends ciphertext after header
	c.Seal(frame[HeaderSize:HeaderSize], nonce, ptBuf, header[:6])

	*ptBufPtr = ptBuf
	plaintextPool.Put(ptBufPtr)

	return frame, nil
}

// Decode reads and decodes a frame using a cached Cipher.
// Returns the frame type and decrypted payload (without padding).
func Decode(r io.Reader, c *Cipher) (byte, []byte, error) {
	// Read header into stack-allocated array
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, fmt.Errorf("read header: %w", err)
	}

	version := header[0]
	if version != Version {
		return 0, nil, fmt.Errorf("unsupported version: 0x%02x", version)
	}

	frameType := header[1]
	payloadLen := binary.BigEndian.Uint16(header[2:4])
	padLen := binary.BigEndian.Uint16(header[4:6])
	nonce := header[6:]

	// Calculate ciphertext size: plaintext(payload+padding) + AEAD overhead (16 bytes poly1305 tag)
	totalPlain := int(payloadLen) + int(padLen)
	ciphertextLen := totalPlain + c.Overhead()

	// Read ciphertext into pool buffer
	ctBufPtr := ciphertextPool.Get().(*[]byte)
	ctBuf := *ctBufPtr
	if cap(ctBuf) < ciphertextLen {
		ctBuf = make([]byte, ciphertextLen)
	} else {
		ctBuf = ctBuf[:ciphertextLen]
	}

	if _, err := io.ReadFull(r, ctBuf); err != nil {
		*ctBufPtr = ctBuf
		ciphertextPool.Put(ctBufPtr)
		return 0, nil, fmt.Errorf("read ciphertext: %w", err)
	}

	// Decrypt — allocates the plaintext result (caller owns it)
	plaintext, err := c.Open(nil, nonce, ctBuf, header[:6])

	*ctBufPtr = ctBuf
	ciphertextPool.Put(ctBufPtr)

	if err != nil {
		return 0, nil, fmt.Errorf("decrypt: %w", err)
	}

	return frameType, plaintext[:payloadLen], nil
}

// EncodeRaw encodes a frame from raw bytes (used for already-assembled data like handshake).
func EncodeRaw(frameType byte, data []byte) []byte {
	frame := make([]byte, 2+2+len(data))
	frame[0] = Version
	frame[1] = frameType
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)
	return frame
}

// randomPadLen returns a random padding length in [min, max].
func randomPadLen(min, max int) int {
	if max == 0 {
		return 0
	}
	rangeSize := max - min + 1
	var buf [2]byte
	rand.Read(buf[:])
	return min + int(binary.BigEndian.Uint16(buf[:]))%rangeSize
}
