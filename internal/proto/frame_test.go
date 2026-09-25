package proto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"ftybucks/internal/config"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncodeDecodeData(t *testing.T) {
	c := testCipher(t)
	payload := []byte("this is an IP packet simulation for testing")
	padCfg := config.PaddingConfig{Min: 16, Max: 64}

	encoded, err := Encode(FrameData, payload, c, padCfg)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	reader := bytes.NewReader(encoded)
	frameType, decoded, err := Decode(reader, c)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if frameType != FrameData {
		t.Fatalf("frame type 0x%02x != 0x%02x", frameType, FrameData)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded payload mismatch: got %q, want %q", decoded, payload)
	}
}

func TestEncodeDecodeKeepalive(t *testing.T) {
	c := testCipher(t)
	padCfg := config.PaddingConfig{Min: 0, Max: 32}

	encoded, err := Encode(FrameKeepalive, nil, c, padCfg)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	reader := bytes.NewReader(encoded)
	frameType, decoded, err := Decode(reader, c)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if frameType != FrameKeepalive {
		t.Fatalf("frame type 0x%02x != 0x%02x", frameType, FrameKeepalive)
	}
	if len(decoded) != 0 {
		t.Fatalf("keepalive should have empty payload, got %d bytes", len(decoded))
	}
}

func TestEncodeDecodeMultipleFrames(t *testing.T) {
	c := testCipher(t)
	padCfg := config.PaddingConfig{Min: 8, Max: 128}

	var buf bytes.Buffer
	payloads := [][]byte{
		[]byte("packet-one"),
		[]byte("packet-two-longer-data-here"),
		[]byte("p3"),
	}

	for _, p := range payloads {
		encoded, err := Encode(FrameData, p, c, padCfg)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		buf.Write(encoded)
	}

	reader := &buf
	for i, expected := range payloads {
		frameType, decoded, err := Decode(reader, c)
		if err != nil {
			t.Fatalf("Decode frame %d: %v", i, err)
		}
		if frameType != FrameData {
			t.Fatalf("frame %d: type 0x%02x != 0x%02x", i, frameType, FrameData)
		}
		if !bytes.Equal(decoded, expected) {
			t.Fatalf("frame %d: payload mismatch", i)
		}
	}
}

func TestEncodePayloadTooLarge(t *testing.T) {
	c := testCipher(t)
	padCfg := config.PaddingConfig{Min: 0, Max: 0}
	bigPayload := make([]byte, MaxPayloadSize+1)

	_, err := Encode(FrameData, bigPayload, c, padCfg)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestDecodeCorruptedHeader(t *testing.T) {
	c := testCipher(t)
	// Wrong version byte
	data := make([]byte, HeaderSize+32)
	data[0] = 0xFF // bad version
	reader := bytes.NewReader(data)

	_, _, err := Decode(reader, c)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestFrameSizeVariation(t *testing.T) {
	c := testCipher(t)
	payload := []byte("fixed payload for size test")
	padCfg := config.PaddingConfig{Min: 32, Max: 256}

	sizes := make(map[int]bool)
	for i := 0; i < 50; i++ {
		encoded, err := Encode(FrameData, payload, c, padCfg)
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(encoded)] = true
	}

	if len(sizes) < 3 {
		t.Fatalf("expected frame size variation due to padding, got %d unique sizes", len(sizes))
	}
}
