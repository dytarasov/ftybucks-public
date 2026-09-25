package pgproto

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const handshakeTimeout = 10 * time.Second

// libpqClientHello returns a uTLS ClientHelloSpec mimicking libpq linked against
// OpenSSL 3.x with TLS 1.3 support. Real PostgreSQL 16+ clients offer TLS 1.3.
// OpenSSL's default cipher suite ordering, no SNI (IP-based connections).
func libpqClientHello() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.3 suites (OpenSSL default order)
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			// TLS 1.2 suites (OpenSSL 3.x default order)
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
		Extensions: []utls.TLSExtension{
			// OpenSSL 3.x default extension order (no SNI — IP-based connection like libpq)
			&utls.ExtendedMasterSecretExtension{},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
			&utls.SessionTicketExtension{},
			&utls.GenericExtension{Id: 22}, // encrypt_then_mac
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				0x0809, // ed25519
				0x080a, // ed448
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
		},
	}
}

// buildSSLRequest builds the 8-byte SSLRequest message: [len=8][code=80877103].
func buildSSLRequest() []byte {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], sslRequestCode)
	return msg
}

// ClientHandshake performs the client side of the PG replication handshake.
// Sends SSLRequest, upgrades to TLS, then continues PG protocol.
// Returns a PGConn wrapping the underlying connection.
func ClientHandshake(conn net.Conn, psk []byte) (*PGConn, error) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	// 1. Send SSLRequest
	if _, err := conn.Write(buildSSLRequest()); err != nil {
		return nil, fmt.Errorf("send ssl request: %w", err)
	}

	// 2. Read 1 byte — expect 'S' (PostgreSQL's "SSL accepted"). 'Y' is what
	// servers built before the fix sent; accept it until every node is upgraded.
	var sslResp [1]byte
	if _, err := io.ReadFull(conn, sslResp[:]); err != nil {
		return nil, fmt.Errorf("read ssl response: %w", err)
	}
	if sslResp[0] != sslAccepted && sslResp[0] != sslAcceptedLegacy {
		return nil, fmt.Errorf("server rejected SSL (got %c)", sslResp[0])
	}

	// 3. TLS upgrade (uTLS mimics libpq/OpenSSL 3.x fingerprint)
	tlsConn := utls.UClient(conn, &utls.Config{
		InsecureSkipVerify: true,
	}, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(libpqClientHello()); err != nil {
		return nil, fmt.Errorf("apply tls preset: %w", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	// From here on, all PG protocol runs inside TLS
	var pgConn net.Conn = tlsConn

	// 4. Send StartupMessage
	if _, err := pgConn.Write(buildStartupMessage()); err != nil {
		return nil, fmt.Errorf("send startup: %w", err)
	}

	// 5. Read AuthenticationMD5Password
	tag, payload, err := readPGMessage(pgConn)
	if err != nil {
		return nil, fmt.Errorf("read auth request: %w", err)
	}
	if tag != tagAuthRequest {
		return nil, fmt.Errorf("expected auth request, got tag %c", tag)
	}
	if len(payload) < 8 || binary.BigEndian.Uint32(payload[0:4]) != authMD5Password {
		return nil, fmt.Errorf("expected MD5 auth challenge")
	}
	var salt [4]byte
	copy(salt[:], payload[4:8])

	// 6. Send PasswordMessage
	hash := computePGMD5(psk, salt)
	if _, err := pgConn.Write(buildPasswordMessage(hash)); err != nil {
		return nil, fmt.Errorf("send password: %w", err)
	}

	// 7. Read AuthenticationOk (or ErrorResponse)
	tag, payload, err = readPGMessage(pgConn)
	if err != nil {
		return nil, fmt.Errorf("read auth response: %w", err)
	}
	if tag == tagErrorResponse {
		return nil, fmt.Errorf("authentication failed")
	}
	if tag != tagAuthRequest || len(payload) < 4 || binary.BigEndian.Uint32(payload[0:4]) != authOK {
		return nil, fmt.Errorf("expected auth ok, got tag %c", tag)
	}

	// 8. Read ParameterStatus messages, BackendKeyData, ReadyForQuery
	for {
		tag, _, err = readPGMessage(pgConn)
		if err != nil {
			return nil, fmt.Errorf("read post-auth: %w", err)
		}
		if tag == tagReadyForQuery {
			break
		}
		// Discard ParameterStatus ('S') and BackendKeyData ('K')
	}

	// 9a. Optional pre-replication queries.
	//
	// Real walreceivers usually run IDENTIFY_SYSTEM (and sometimes
	// TIMELINE_HISTORY <n>) before subscribing — that's how they learn the
	// upstream's systemid, current timeline, and starting xlogpos. Sending
	// nothing before START_REPLICATION is itself a fingerprint, so we
	// emit IDENTIFY_SYSTEM on a fraction of connections and drain the reply
	// up through ReadyForQuery before issuing the actual replication command.
	if shouldSendIdentifySystem() {
		if _, err := pgConn.Write(buildQuery("IDENTIFY_SYSTEM")); err != nil {
			return nil, fmt.Errorf("send identify_system: %w", err)
		}
		for {
			tag, _, err := readPGMessage(pgConn)
			if err != nil {
				return nil, fmt.Errorf("read identify_system response: %w", err)
			}
			if tag == tagReadyForQuery {
				break
			}
			if tag == tagErrorResponse {
				// Old server that doesn't know IDENTIFY_SYSTEM — it would
				// already have closed the connection in that case. Treat as
				// fatal here so the upper Reconnect path retries cleanly.
				return nil, fmt.Errorf("server rejected IDENTIFY_SYSTEM")
			}
		}
	}

	// 9b. Send START_REPLICATION query
	// Randomize slot name and start LSN so multiple connections don't share identifiers.
	slotName := randomSlotName()
	startLSN := randomStartLSN()
	query := fmt.Sprintf("START_REPLICATION SLOT %s PHYSICAL %s", slotName, startLSN)
	if _, err := pgConn.Write(buildQuery(query)); err != nil {
		return nil, fmt.Errorf("send replication query: %w", err)
	}

	// 10. Read CopyBothResponse
	tag, _, err = readPGMessage(pgConn)
	if err != nil {
		return nil, fmt.Errorf("read copy both: %w", err)
	}
	if tag != tagCopyBoth {
		return nil, fmt.Errorf("expected CopyBothResponse, got tag %c", tag)
	}

	return newPGConn(pgConn, false), nil
}

// ServerHandshake performs the server side of the PG replication handshake.
// Handles SSLRequest/GSSENCRequest with TLS upgrade, then continues PG protocol.
// All rejection paths complete the full auth flow to prevent timing analysis.
// Returns a PGConn wrapping the underlying connection.
func ServerHandshake(conn net.Conn, psk []byte, cert tls.Certificate) (*PGConn, error) {
	remote := conn.RemoteAddr().String()
	t0 := time.Now()
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	// 1. Read first message — may be SSLRequest, GSSENCRequest, or CancelRequest
	msgLen, protoVer, err := readStartupHeader(conn)
	if err != nil {
		log.Printf("[PG] %s: failed at startup read after %v — %v (likely port scanner)", remote, time.Since(t0), err)
		return nil, fmt.Errorf("read startup: %w", err)
	}

	var pgConn net.Conn = conn

	// Handle special request codes in a loop (client may send GSSENCRequest then SSLRequest)
	for protoVer == sslRequestCode || protoVer == gssEncRequestCode || protoVer == cancelRequestCode {
		switch protoVer {
		case sslRequestCode:
			// Respond 'S' (as real PostgreSQL does) and upgrade to TLS
			if _, err := conn.Write([]byte{sslAccepted}); err != nil {
				return nil, fmt.Errorf("send ssl accept: %w", err)
			}
			tlsConn := tls.Server(conn, serverTLSConfig(cert))
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("[PG] %s: TLS handshake failed — %v (TLS scanner or incompatible client)", remote, err)
				return nil, fmt.Errorf("tls handshake: %w", err)
			}
			pgConn = tlsConn

		case gssEncRequestCode:
			// Respond 'N' — GSS encryption not supported (like real PG without GSS)
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("send gss reject: %w", err)
			}

		case cancelRequestCode:
			// CancelRequest is 16 bytes total (8 already read). Read remaining 8 and close.
			var discard [8]byte
			io.ReadFull(conn, discard[:])
			return nil, fmt.Errorf("cancel request")
		}

		// Read next startup message
		msgLen, protoVer, err = readStartupHeader(pgConn)
		if err != nil {
			log.Printf("[PG] %s: startup read failed — %v", remote, err)
			return nil, fmt.Errorf("read startup: %w", err)
		}
	}

	// 2. Verify protocol 3.0
	if protoVer != 0x00030000 {
		log.Printf("[PG] %s: wrong protocol version 0x%08x (expected PG 3.0)", remote, protoVer)
		pgConn.Write(buildProtocolError(fmt.Sprintf("unsupported frontend protocol %d.%d: server supports 3.0 to 3.0", protoVer>>16, protoVer&0xffff)))
		return nil, fmt.Errorf("unsupported protocol: %d", protoVer)
	}

	// Read remaining startup params
	remaining := int(msgLen) - 8 // already read 4 (len) + 4 (proto)
	if remaining < 0 || remaining > 10000 {
		log.Printf("[PG] %s: invalid startup length %d (malformed message)", remote, msgLen)
		return nil, fmt.Errorf("invalid startup message length")
	}
	params := make([]byte, remaining)
	if _, err := io.ReadFull(pgConn, params); err != nil {
		return nil, fmt.Errorf("read startup params: %w", err)
	}

	// Parse startup params — remember user for error messages
	paramMap := parseStartupParams(params)
	user := paramMap["user"]
	if user == "" {
		user = "unknown"
	}

	// Track whether this is our tunnel client.
	// We ALWAYS complete the full MD5 auth exchange to prevent timing analysis.
	isTunnelClient := paramMap["user"] == "replicator" && paramMap["replication"] == "true"

	if !isTunnelClient {
		if paramMap["user"] != "replicator" {
			log.Printf("[PG] %s: rejected: user=%q database=%q", remote, paramMap["user"], paramMap["database"])
		} else {
			log.Printf("[PG] %s: rejected: replication flag not set", remote)
		}
	}

	// 3. Send AuthenticationMD5Password — always, regardless of user
	var salt [4]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	if _, err := pgConn.Write(buildAuthMD5Password(salt)); err != nil {
		return nil, fmt.Errorf("send auth challenge: %w", err)
	}

	// 4. Read PasswordMessage
	tag, payload, err := readPGMessage(pgConn)
	if err != nil {
		log.Printf("[PG] %s: no password response — %v (probe abandoned after auth challenge)", remote, err)
		return nil, fmt.Errorf("read password: %w", err)
	}
	if tag != tagPassword {
		log.Printf("[PG] %s: expected password msg, got tag 0x%02x/%c (protocol confusion)", remote, tag, tag)
		pgConn.Write(buildProtocolError("expected password response"))
		return nil, fmt.Errorf("expected password message, got tag %c", tag)
	}

	// Password is null-terminated
	clientHash := strings.TrimRight(string(payload), "\x00")
	expectedHash := computePGMD5(psk, salt)

	// 5. Verify: must be our tunnel client AND correct password
	if !isTunnelClient || subtle.ConstantTimeCompare([]byte(clientHash), []byte(expectedHash)) != 1 {
		if isTunnelClient {
			log.Printf("[PG] %s: wrong PSK (MD5 auth failed) — bad password or wrong key", remote)
		}
		pgConn.Write(buildAuthError(user))
		return nil, fmt.Errorf("authentication failed")
	}

	// 6. Send AuthenticationOk
	if _, err := pgConn.Write(buildAuthOk()); err != nil {
		return nil, fmt.Errorf("send auth ok: %w", err)
	}

	// 7. Send ParameterStatus messages (match real PG 16.2).
	// application_name echoes whatever the client sent (mirrors real PG behavior).
	echoedAppName := paramMap["application_name"]
	if echoedAppName == "" {
		echoedAppName = randomAppName()
	}
	pgParams := []struct{ name, value string }{
		{"server_version", "16.2"},
		{"server_encoding", "UTF8"},
		{"client_encoding", "UTF8"},
		{"application_name", echoedAppName},
		{"default_transaction_read_only", "off"},
		{"in_hot_standby", "off"},
		{"is_superuser", "off"},
		{"session_authorization", "replicator"},
		{"DateStyle", "ISO, MDY"},
		{"IntervalStyle", "postgres"},
		{"TimeZone", "UTC"},
		{"integer_datetimes", "on"},
		{"standard_conforming_strings", "on"},
	}
	for _, p := range pgParams {
		if _, err := pgConn.Write(buildParameterStatus(p.name, p.value)); err != nil {
			return nil, fmt.Errorf("send param status: %w", err)
		}
	}

	// 8. Send BackendKeyData
	var pidBuf, keyBuf [4]byte
	rand.Read(pidBuf[:])
	rand.Read(keyBuf[:])
	pid := binary.BigEndian.Uint32(pidBuf[:])
	key := binary.BigEndian.Uint32(keyBuf[:])
	if _, err := pgConn.Write(buildBackendKeyData(pid, key)); err != nil {
		return nil, fmt.Errorf("send backend key: %w", err)
	}

	// 9. Send ReadyForQuery
	if _, err := pgConn.Write(buildReadyForQuery()); err != nil {
		return nil, fmt.Errorf("send ready: %w", err)
	}

	// 10. Read queries until START_REPLICATION arrives. Real walreceivers
	// typically run IDENTIFY_SYSTEM (and sometimes TIMELINE_HISTORY n) first,
	// so we accept and answer those with synthesized data rather than
	// short-circuiting on START_REPLICATION as the only valid first command.
	for {
		tag, payload, err = readPGMessage(pgConn)
		if err != nil {
			log.Printf("[PG] %s: no query after auth — %v (authenticated but not our client)", remote, err)
			return nil, fmt.Errorf("read query: %w", err)
		}
		if tag != tagQuery {
			log.Printf("[PG] %s: expected query tag, got 0x%02x/%c (wrong PG command sequence)", remote, tag, tag)
			pgConn.Write(buildProtocolError("expected simple query"))
			return nil, fmt.Errorf("expected query, got tag %c", tag)
		}
		query := strings.TrimRight(string(payload), "\x00")
		upper := strings.ToUpper(strings.TrimSpace(query))

		switch {
		case strings.HasPrefix(upper, "START_REPLICATION"):
			// Fall through to CopyBothResponse below.
		case strings.HasPrefix(upper, "IDENTIFY_SYSTEM"):
			for _, msg := range buildIdentifySystemResponse() {
				if _, err := pgConn.Write(msg); err != nil {
					return nil, fmt.Errorf("send identify_system: %w", err)
				}
			}
			continue
		case strings.HasPrefix(upper, "TIMELINE_HISTORY"):
			// We don't actually have a history file; emit an empty result set
			// + CommandComplete + ReadyForQuery so the client moves on.
			fields := []rowDescField{
				{"filename", pgTypeOIDText, -1, -1, 0},
				{"content", pgTypeOIDText, -1, -1, 0},
			}
			for _, msg := range [][]byte{
				buildRowDescription(fields),
				buildCommandComplete("TIMELINE_HISTORY"),
				buildReadyForQuery(),
			} {
				if _, err := pgConn.Write(msg); err != nil {
					return nil, fmt.Errorf("send timeline_history: %w", err)
				}
			}
			continue
		default:
			log.Printf("[PG] %s: wrong query %q (PG client sent non-replication query)", remote, query)
			pgConn.Write(buildSyntaxError(fmt.Sprintf("syntax error at or near \"%s\"", truncateQuery(query))))
			return nil, fmt.Errorf("unexpected query: %s", query)
		}
		break
	}

	// 11. Send CopyBothResponse
	if _, err := pgConn.Write(buildCopyBothResponse()); err != nil {
		return nil, fmt.Errorf("send copy both: %w", err)
	}

	log.Printf("[CONN] %s: PG handshake OK (%v)", remote, time.Since(t0))
	return newPGConn(pgConn, true), nil
}

// truncateQuery returns a safe prefix of the query for error messages.
func truncateQuery(q string) string {
	if len(q) > 32 {
		return q[:32]
	}
	return q
}

// readPGMessage reads a tagged PG message: [tag 1B][len 4B][payload].
// Returns tag, payload (without length prefix bytes), error.
func readPGMessage(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	tag := hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:5]) // includes self (4 bytes)
	if length < 4 || length > 1<<20 {
		return 0, nil, fmt.Errorf("invalid message length: %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return tag, payload, nil
}

// readStartupHeader reads the first 8 bytes of a startup message:
// [int32 length][int32 protocol/code]
func readStartupHeader(r io.Reader) (uint32, uint32, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, 0, err
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	code := binary.BigEndian.Uint32(hdr[4:8])
	return length, code, nil
}

// parseStartupParams parses null-terminated key-value pairs from startup message.
func parseStartupParams(data []byte) map[string]string {
	params := make(map[string]string)
	for len(data) > 0 {
		// Find key
		idx := 0
		for idx < len(data) && data[idx] != 0 {
			idx++
		}
		if idx >= len(data) {
			break
		}
		key := string(data[:idx])
		data = data[idx+1:]
		if key == "" {
			break // terminal \0
		}
		// Find value
		idx = 0
		for idx < len(data) && data[idx] != 0 {
			idx++
		}
		if idx >= len(data) {
			params[key] = string(data)
			break
		}
		params[key] = string(data[:idx])
		data = data[idx+1:]
	}
	return params
}

// randomSlotName generates a plausible PHYSICAL replication slot name.
// Only uses prefixes that make sense for physical streaming: standby/replica/
// walreceiver/pgstandby. Earlier `sub` was included but `sub_*` is the
// convention for logical subscription slots — pairing it with a PHYSICAL
// START_REPLICATION is a fingerprint a DPI vendor can match on.
func randomSlotName() string {
	prefixes := []string{"standby", "replica", "walreceiver", "pgstandby"}
	var b [2]byte
	rand.Read(b[:])
	prefix := prefixes[int(b[0])%len(prefixes)]
	// Suffix: small number (0-255) or 4-hex string, like real slot naming
	if b[0]&1 == 0 {
		return fmt.Sprintf("%s_%d", prefix, int(b[1]))
	}
	var h [2]byte
	rand.Read(h[:])
	return fmt.Sprintf("%s_%02x%02x", prefix, h[0], h[1])
}

// shouldSendIdentifySystem returns true ~40% of the time. Real walreceivers
// always run IDENTIFY_SYSTEM first, but pg_receivewal/pg_basebackup can skip
// it if started with --slot, so a mixed population on the wire is plausible.
// Picking randomly per session means a per-flow DPI fingerprint can't latch
// on to "always sends IDENTIFY_SYSTEM" or "never sends IDENTIFY_SYSTEM".
func shouldSendIdentifySystem() bool {
	var b [1]byte
	rand.Read(b[:])
	return b[0] < 102 // 102/256 ≈ 0.4
}

// randomStartLSN returns a realistic replication start position as "HIGH/LOW" hex.
// Range: 16GB to ~4TB of accumulated WAL (realistic for a running standby).
// LSNs are 64-bit, PG prints them as two 32-bit halves in hex separated by "/".
func randomStartLSN() string {
	var b [8]byte
	rand.Read(b[:])
	// 16GB = 0x4_0000_0000, 4TB = 0x400_0000_0000
	const minLSN = uint64(16) * 1024 * 1024 * 1024
	const maxLSN = uint64(4) * 1024 * 1024 * 1024 * 1024
	lsn := minLSN + binary.BigEndian.Uint64(b[:])%(maxLSN-minLSN)
	// Align to 16MB segment boundary (realistic)
	lsn &^= (16*1024*1024 - 1)
	high := uint32(lsn >> 32)
	low := uint32(lsn & 0xFFFFFFFF)
	return fmt.Sprintf("%X/%X", high, low)
}
