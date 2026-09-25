package pgproto

import (
	"encoding/binary"
	"testing"
)

func TestBuildStartupMessage(t *testing.T) {
	msg := buildStartupMessage()

	length := binary.BigEndian.Uint32(msg[0:4])
	if int(length) != len(msg) {
		t.Fatalf("length field %d != actual %d", length, len(msg))
	}

	proto := binary.BigEndian.Uint32(msg[4:8])
	if proto != 0x00030000 {
		t.Fatalf("protocol %x != 0x00030000", proto)
	}

	// Verify it contains user=replicator
	params := parseStartupParams(msg[8:])
	if params["user"] != "replicator" {
		t.Fatalf("user = %q, want replicator", params["user"])
	}
	if params["database"] != "replication" {
		t.Fatalf("database = %q, want replication", params["database"])
	}
	if params["replication"] != "true" {
		t.Fatalf("replication = %q, want true", params["replication"])
	}
}

func TestBuildAuthMD5Password(t *testing.T) {
	salt := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}
	msg := buildAuthMD5Password(salt)

	if msg[0] != tagAuthRequest {
		t.Fatalf("tag = %c, want R", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if length != 12 {
		t.Fatalf("length = %d, want 12", length)
	}
	authType := binary.BigEndian.Uint32(msg[5:9])
	if authType != authMD5Password {
		t.Fatalf("auth type = %d, want %d", authType, authMD5Password)
	}
	if msg[9] != 0xDE || msg[10] != 0xAD || msg[11] != 0xBE || msg[12] != 0xEF {
		t.Fatalf("salt mismatch")
	}
}

func TestBuildAuthOk(t *testing.T) {
	msg := buildAuthOk()

	if msg[0] != tagAuthRequest {
		t.Fatalf("tag = %c, want R", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if length != 8 {
		t.Fatalf("length = %d, want 8", length)
	}
	authType := binary.BigEndian.Uint32(msg[5:9])
	if authType != authOK {
		t.Fatalf("auth type = %d, want 0", authType)
	}
}

func TestBuildPasswordMessage(t *testing.T) {
	hash := "md5abcdef1234567890abcdef12345678"
	msg := buildPasswordMessage(hash)

	if msg[0] != tagPassword {
		t.Fatalf("tag = %c, want p", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	// length = 4 + len(hash) + 1 (null terminator)
	expected := uint32(4 + len(hash) + 1)
	if length != expected {
		t.Fatalf("length = %d, want %d", length, expected)
	}
	// Verify null-terminated payload
	payload := string(msg[5:])
	if payload != hash+"\x00" {
		t.Fatalf("payload = %q, want %q", payload, hash+"\x00")
	}
}

func TestBuildParameterStatus(t *testing.T) {
	msg := buildParameterStatus("server_version", "16.2")

	if msg[0] != tagParameterStatus {
		t.Fatalf("tag = %c, want S", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	expectedPayload := "server_version\x0016.2\x00"
	if length != uint32(4+len(expectedPayload)) {
		t.Fatalf("length = %d, want %d", length, 4+len(expectedPayload))
	}
}

func TestBuildReadyForQuery(t *testing.T) {
	msg := buildReadyForQuery()

	if msg[0] != tagReadyForQuery {
		t.Fatalf("tag = %c, want Z", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if length != 5 {
		t.Fatalf("length = %d, want 5", length)
	}
	if msg[5] != 'I' {
		t.Fatalf("status = %c, want I", msg[5])
	}
}

func TestBuildCopyBothResponse(t *testing.T) {
	msg := buildCopyBothResponse()

	if msg[0] != tagCopyBoth {
		t.Fatalf("tag = %c, want W", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if length != 7 {
		t.Fatalf("length = %d, want 7", length)
	}
}

func TestBuildErrorResponse(t *testing.T) {
	msg := buildErrorResponse("28P01", "test", "auth.c", "42", "ClientAuthentication")

	if msg[0] != tagErrorResponse {
		t.Fatalf("tag = %c, want E", msg[0])
	}
	// Just verify it has a valid length
	length := binary.BigEndian.Uint32(msg[1:5])
	if int(length)+1 != len(msg) {
		t.Fatalf("length field %d + 1 != actual %d", length, len(msg))
	}
}

func TestWrapCopyData(t *testing.T) {
	payload := []byte("hello world")
	msg := wrapCopyData(payload)

	if msg[0] != tagCopyData {
		t.Fatalf("tag = %c, want d", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if length != uint32(4+len(payload)) {
		t.Fatalf("length = %d, want %d", length, 4+len(payload))
	}
	if string(msg[5:]) != "hello world" {
		t.Fatalf("payload = %q, want %q", msg[5:], "hello world")
	}
}

func TestBuildXLogDataHeader(t *testing.T) {
	hdr := buildXLogDataHeader(0x1000, 100)

	if hdr[0] != 'w' {
		t.Fatalf("type = %c, want w", hdr[0])
	}
	walStart := binary.BigEndian.Uint64(hdr[1:9])
	if walStart != 0x1000 {
		t.Fatalf("walStart = %x, want 0x1000", walStart)
	}
	walEnd := binary.BigEndian.Uint64(hdr[9:17])
	if walEnd != 0x1000+100 {
		t.Fatalf("walEnd = %x, want %x", walEnd, 0x1000+100)
	}
	if len(hdr) != 25 {
		t.Fatalf("header length = %d, want 25", len(hdr))
	}
}

func TestBuildPrimaryKeepalive(t *testing.T) {
	msg := buildPrimaryKeepalive(0x2000, true)

	// Should be wrapped in CopyData
	if msg[0] != tagCopyData {
		t.Fatalf("outer tag = %c, want d", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if length != uint32(4+18) {
		t.Fatalf("length = %d, want %d", length, 4+18)
	}
	inner := msg[5:]
	if inner[0] != 'k' {
		t.Fatalf("inner type = %c, want k", inner[0])
	}
	if inner[17] != 1 {
		t.Fatalf("replyRequested = %d, want 1", inner[17])
	}
}

func TestBuildStandbyStatusUpdate(t *testing.T) {
	msg := buildStandbyStatusUpdate(0x3000)

	if msg[0] != tagCopyData {
		t.Fatalf("outer tag = %c, want d", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if length != uint32(4+34) {
		t.Fatalf("length = %d, want %d", length, 4+34)
	}
	inner := msg[5:]
	if inner[0] != 'r' {
		t.Fatalf("inner type = %c, want r", inner[0])
	}
}
