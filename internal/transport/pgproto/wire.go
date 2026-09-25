package pgproto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// realisticAppNames are application_name values consistent with PHYSICAL
// streaming replication (replication=true, START_REPLICATION ... PHYSICAL).
// Earlier we included pglogical/patroni/repmgrd, but those are tied to
// logical replication / cluster-management workflows and combining them
// with a PHYSICAL replication slot is a tell — a DPI vendor can flag the
// inconsistency. Keep only names that real WAL receivers actually use.
var realisticAppNames = []string{
	"walreceiver",
	"pg_basebackup",
	"pg_receivewal",
}

func randomAppName() string {
	var b [1]byte
	rand.Read(b[:])
	return realisticAppNames[int(b[0])%len(realisticAppNames)]
}

// PostgreSQL wire protocol message type tags.
const (
	tagAuthRequest     = 'R'
	tagParameterStatus = 'S'
	tagBackendKeyData  = 'K'
	tagReadyForQuery   = 'Z'
	tagQuery           = 'Q'
	tagPassword        = 'p'
	tagCopyBoth        = 'W'
	tagCopyData        = 'd'
	tagErrorResponse   = 'E'
	tagRowDescription  = 'T'
	tagDataRow         = 'D'
	tagCommandComplete = 'C'
)

// PostgreSQL builtin type OIDs (subset — only what we synthesize for
// IDENTIFY_SYSTEM/TIMELINE_HISTORY responses).
const (
	pgTypeOIDText = 25
	pgTypeOIDInt4 = 23
)

// Authentication request types.
const (
	authOK          = 0
	authMD5Password = 5
)

// SSLRequest code (special startup message).
const sslRequestCode = 80877103

// Single-byte replies to SSLRequest. Real PostgreSQL answers 'S' to accept TLS
// and 'N' to refuse. Early builds of this server sent 'Y', a byte no genuine
// server ever sends, so clients still accept it while old nodes are upgraded.
const (
	sslAccepted       = 'S'
	sslAcceptedLegacy = 'Y'
)

// GSSENCRequest and CancelRequest codes.
const (
	gssEncRequestCode  = 80877104
	cancelRequestCode  = 80877102
)

// startupParam is a single key/value pair inside a StartupMessage body.
type startupParam struct {
	name, value string
}

// startupProfile drives random selection of optional parameters that go
// alongside the required user/database/replication/application_name set. Each
// profile mirrors the connection-string defaults of one real PG client (bare
// libpq, libpq with default options, psql). Picking a profile per session
// plus shuffling the in-message order of params (with `user` pinned first —
// libpq always emits user first) gives the wire shape enough variability
// that a per-flow DPI fingerprint cannot latch on for long.
type startupProfile struct {
	name  string
	extra []startupParam
}

var startupProfiles = []startupProfile{
	{
		name:  "minimal",
		extra: nil,
	},
	{
		name: "with-encoding",
		extra: []startupParam{
			{"client_encoding", "UTF8"},
		},
	},
	{
		name: "libpq-default",
		extra: []startupParam{
			{"client_encoding", "UTF8"},
			{"DateStyle", "ISO, MDY"},
			{"TimeZone", "UTC"},
		},
	},
	{
		name: "psql-default",
		extra: []startupParam{
			{"client_encoding", "UTF8"},
			{"DateStyle", "ISO, MDY"},
			{"TimeZone", "Etc/UTC"},
			{"IntervalStyle", "postgres"},
		},
	},
}

func pickProfile() startupProfile {
	var b [1]byte
	rand.Read(b[:])
	return startupProfiles[int(b[0])%len(startupProfiles)]
}

// shuffleParamsKeepUserFirst randomizes order of params[1:] in place. The
// first slot is left untouched — the caller is expected to put `user` there,
// matching libpq's PQconnect frontend StartupPacket where `user` is always
// the first connection option.
func shuffleParamsKeepUserFirst(params []startupParam) {
	if len(params) <= 2 {
		return
	}
	for i := len(params) - 1; i > 1; i-- {
		var b [1]byte
		rand.Read(b[:])
		j := 1 + int(b[0])%i
		params[i], params[j] = params[j], params[i]
	}
}

// buildStartupMessage builds a PostgreSQL v3 startup message:
// [int32 len][int32 0x00030000][params...\0\0]
//
// Required params (user, database, replication, application_name) are
// always present; an extra set is selected from a randomly chosen profile
// (see startupProfiles). Param order — except for `user` which stays first —
// is shuffled per call. The server identifies tunnel clients by the
// {user="replicator", replication="true"} pair regardless of order, so the
// random shape costs nothing on the receiving side.
func buildStartupMessage() []byte {
	profile := pickProfile()

	params := []startupParam{
		{"user", "replicator"},
		{"database", "replication"},
		{"replication", "true"},
		{"application_name", randomAppName()},
	}
	params = append(params, profile.extra...)
	shuffleParamsKeepUserFirst(params)

	var body []byte
	for _, p := range params {
		body = append(body, p.name...)
		body = append(body, 0)
		body = append(body, p.value...)
		body = append(body, 0)
	}
	body = append(body, 0) // params-list terminator

	length := 4 + 4 + len(body)
	msg := make([]byte, length)
	binary.BigEndian.PutUint32(msg[0:4], uint32(length))
	binary.BigEndian.PutUint32(msg[4:8], 0x00030000)
	copy(msg[8:], body)
	return msg
}

// buildAuthMD5Password builds an AuthenticationMD5Password message:
// ['R'][int32 12][int32 5][4-byte salt]
func buildAuthMD5Password(salt [4]byte) []byte {
	msg := make([]byte, 13)
	msg[0] = tagAuthRequest
	binary.BigEndian.PutUint32(msg[1:5], 12) // length includes self
	binary.BigEndian.PutUint32(msg[5:9], authMD5Password)
	copy(msg[9:13], salt[:])
	return msg
}

// buildAuthOk builds an AuthenticationOk message:
// ['R'][int32 8][int32 0]
func buildAuthOk() []byte {
	msg := make([]byte, 9)
	msg[0] = tagAuthRequest
	binary.BigEndian.PutUint32(msg[1:5], 8)
	binary.BigEndian.PutUint32(msg[5:9], authOK)
	return msg
}

// buildPasswordMessage builds a PasswordMessage:
// ['p'][int32 len][hash\0]
func buildPasswordMessage(hash string) []byte {
	payload := hash + "\x00"
	msg := make([]byte, 1+4+len(payload))
	msg[0] = tagPassword
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// buildParameterStatus builds a ParameterStatus message:
// ['S'][int32 len][name\0][value\0]
func buildParameterStatus(name, value string) []byte {
	payload := name + "\x00" + value + "\x00"
	msg := make([]byte, 1+4+len(payload))
	msg[0] = tagParameterStatus
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// buildBackendKeyData builds a BackendKeyData message:
// ['K'][int32 12][int32 pid][int32 key]
func buildBackendKeyData(pid, key uint32) []byte {
	msg := make([]byte, 13)
	msg[0] = tagBackendKeyData
	binary.BigEndian.PutUint32(msg[1:5], 12)
	binary.BigEndian.PutUint32(msg[5:9], pid)
	binary.BigEndian.PutUint32(msg[9:13], key)
	return msg
}

// buildReadyForQuery builds a ReadyForQuery message:
// ['Z'][int32 5]['I']
func buildReadyForQuery() []byte {
	return []byte{tagReadyForQuery, 0, 0, 0, 5, 'I'}
}

// buildQuery builds a Query message:
// ['Q'][int32 len][sql\0]
func buildQuery(sql string) []byte {
	payload := sql + "\x00"
	msg := make([]byte, 1+4+len(payload))
	msg[0] = tagQuery
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// buildCopyBothResponse builds a CopyBothResponse message:
// ['W'][int32 7][int8 0][int16 0]  (binary format, 0 columns)
func buildCopyBothResponse() []byte {
	msg := make([]byte, 8)
	msg[0] = tagCopyBoth
	binary.BigEndian.PutUint32(msg[1:5], 7)
	// msg[5] = 0 (binary format)
	// msg[6:8] = 0x0000 (0 columns)
	return msg
}

// buildErrorResponse builds a FATAL error with given SQLSTATE code, message,
// and source location fields (F/L/R) matching real PostgreSQL 16.x output.
func buildErrorResponse(code, message, file, line, routine string) []byte {
	fields := ""
	fields += "SFATAL\x00"
	fields += "VFATAL\x00"
	fields += "C" + code + "\x00"
	fields += "M" + message + "\x00"
	fields += "F" + file + "\x00"
	fields += "L" + line + "\x00"
	fields += "R" + routine + "\x00"
	fields += "\x00" // terminator

	msg := make([]byte, 1+4+len(fields))
	msg[0] = tagErrorResponse
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(fields)))
	copy(msg[5:], fields)
	return msg
}

// buildAuthError builds a FATAL 28P01 authentication error for the given user.
func buildAuthError(user string) []byte {
	return buildErrorResponse("28P01",
		fmt.Sprintf("password authentication failed for user \"%s\"", user),
		"auth.c", "326", "auth_failed")
}

// buildFeatureError builds a FATAL 0A000 feature_not_supported error.
func buildFeatureError(message string) []byte {
	return buildErrorResponse("0A000", message, "walsender.c", "689", "exec_replication_command")
}

// buildSyntaxError builds a FATAL 42601 syntax error.
func buildSyntaxError(message string) []byte {
	return buildErrorResponse("42601", message, "scan.l", "1176", "scanner_yyerror")
}

// buildProtocolError builds a FATAL 08P01 protocol violation error.
func buildProtocolError(message string) []byte {
	return buildErrorResponse("08P01", message, "postgres.c", "694", "ProcessStartupPacket")
}

// wrapCopyData wraps payload in a CopyData message:
// ['d'][int32 len][payload]
func wrapCopyData(payload []byte) []byte {
	msg := make([]byte, 1+4+len(payload))
	msg[0] = tagCopyData
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// buildXLogDataHeader builds a 25-byte XLogData header:
// ['w'][walStart 8B][walEnd 8B][serverTime 8B]
func buildXLogDataHeader(walPos uint64, dataLen int) []byte {
	hdr := make([]byte, 25)
	hdr[0] = 'w'
	binary.BigEndian.PutUint64(hdr[1:9], walPos)
	binary.BigEndian.PutUint64(hdr[9:17], walPos+uint64(dataLen))
	binary.BigEndian.PutUint64(hdr[17:25], uint64(pgTimestamp()))
	return hdr
}

// buildPrimaryKeepalive builds an 18-byte PrimaryKeepalive wrapped in CopyData.
// ['k'][walEnd 8B][serverTime 8B][replyRequested 1B]
func buildPrimaryKeepalive(walPos uint64, replyRequested bool) []byte {
	inner := make([]byte, 18)
	inner[0] = 'k'
	binary.BigEndian.PutUint64(inner[1:9], walPos)
	binary.BigEndian.PutUint64(inner[9:17], uint64(pgTimestamp()))
	if replyRequested {
		inner[17] = 1
	}
	return wrapCopyData(inner)
}

// buildStandbyStatusUpdate builds a 34-byte StandbyStatusUpdate wrapped in CopyData.
// ['r'][walReceived 8B][walFlushed 8B][walApplied 8B][clientTime 8B][replyRequested 1B]
func buildStandbyStatusUpdate(walPos uint64) []byte {
	inner := make([]byte, 34)
	inner[0] = 'r'
	binary.BigEndian.PutUint64(inner[1:9], walPos)
	binary.BigEndian.PutUint64(inner[9:17], walPos)
	binary.BigEndian.PutUint64(inner[17:25], walPos)
	binary.BigEndian.PutUint64(inner[25:33], uint64(pgTimestamp()))
	// inner[33] = 0 (no reply requested)
	return wrapCopyData(inner)
}

// rowDescField describes one column for a RowDescription message.
type rowDescField struct {
	name     string
	typeOID  uint32
	typeSize int16 // -1 for variable-length (text)
	typeMod  int32 // -1 for none
	format   int16 // 0 = text
}

// buildRowDescription builds a RowDescription ('T') message with the given
// fields, all on table OID 0 / column number 0 (synthetic — we don't pretend
// to come from a real relation).
func buildRowDescription(fields []rowDescField) []byte {
	var body []byte
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp[:2], uint16(len(fields)))
	body = append(body, tmp[:2]...)
	for _, f := range fields {
		body = append(body, f.name...)
		body = append(body, 0)
		// table OID (4) — 0 = no table
		binary.BigEndian.PutUint32(tmp[:4], 0)
		body = append(body, tmp[:4]...)
		// column number (2) — 0 = none
		binary.BigEndian.PutUint16(tmp[:2], 0)
		body = append(body, tmp[:2]...)
		// type OID (4)
		binary.BigEndian.PutUint32(tmp[:4], f.typeOID)
		body = append(body, tmp[:4]...)
		// type size (2)
		binary.BigEndian.PutUint16(tmp[:2], uint16(f.typeSize))
		body = append(body, tmp[:2]...)
		// type modifier (4)
		binary.BigEndian.PutUint32(tmp[:4], uint32(f.typeMod))
		body = append(body, tmp[:4]...)
		// format code (2)
		binary.BigEndian.PutUint16(tmp[:2], uint16(f.format))
		body = append(body, tmp[:2]...)
	}
	msg := make([]byte, 1+4+len(body))
	msg[0] = tagRowDescription
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(body)))
	copy(msg[5:], body)
	return msg
}

// buildDataRow builds a DataRow ('D') message. A nil entry in values encodes
// a SQL NULL (length = -1).
func buildDataRow(values [][]byte) []byte {
	var body []byte
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp[:2], uint16(len(values)))
	body = append(body, tmp[:2]...)
	for _, v := range values {
		if v == nil {
			binary.BigEndian.PutUint32(tmp[:4], 0xFFFFFFFF) // -1 as int32
			body = append(body, tmp[:4]...)
			continue
		}
		binary.BigEndian.PutUint32(tmp[:4], uint32(len(v)))
		body = append(body, tmp[:4]...)
		body = append(body, v...)
	}
	msg := make([]byte, 1+4+len(body))
	msg[0] = tagDataRow
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(body)))
	copy(msg[5:], body)
	return msg
}

// buildCommandComplete builds a CommandComplete ('C') message with a
// null-terminated command tag like "IDENTIFY_SYSTEM".
func buildCommandComplete(tag string) []byte {
	payload := tag + "\x00"
	msg := make([]byte, 1+4+len(payload))
	msg[0] = tagCommandComplete
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// buildIdentifySystemResponse synthesizes the four messages a real PG
// walsender emits in reply to `IDENTIFY_SYSTEM`: RowDescription, DataRow,
// CommandComplete, ReadyForQuery. systemid is randomized per call, timeline
// is "1" (the typical value when there have been no failovers), xlogpos
// reuses our randomStartLSN format, dbname is NULL (replication connections
// don't have a database).
func buildIdentifySystemResponse() [][]byte {
	fields := []rowDescField{
		{"systemid", pgTypeOIDText, -1, -1, 0},
		{"timeline", pgTypeOIDInt4, 4, -1, 0},
		{"xlogpos", pgTypeOIDText, -1, -1, 0},
		{"dbname", pgTypeOIDText, -1, -1, 0},
	}

	var sysBuf [8]byte
	rand.Read(sysBuf[:])
	systemid := fmt.Sprintf("%d", binary.BigEndian.Uint64(sysBuf[:]))

	return [][]byte{
		buildRowDescription(fields),
		buildDataRow([][]byte{
			[]byte(systemid),
			[]byte("1"),
			[]byte(randomStartLSN()),
			nil, // dbname = NULL on replication connections
		}),
		buildCommandComplete("IDENTIFY_SYSTEM"),
		buildReadyForQuery(),
	}
}
