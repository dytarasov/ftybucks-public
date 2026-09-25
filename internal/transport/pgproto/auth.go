package pgproto

import (
	"crypto/md5"
	"encoding/hex"
)

// computePGMD5 computes the PostgreSQL MD5 password hash:
// "md5" + md5hex(md5hex(password + username) + salt)
//
// We use the PSK as the "password" and "replicator" as the username.
func computePGMD5(psk []byte, salt [4]byte) string {
	// Step 1: md5(password + username)
	h1 := md5.New()
	h1.Write(psk)
	h1.Write([]byte("replicator"))
	inner := hex.EncodeToString(h1.Sum(nil))

	// Step 2: md5(inner_hex + salt)
	h2 := md5.New()
	h2.Write([]byte(inner))
	h2.Write(salt[:])
	outer := hex.EncodeToString(h2.Sum(nil))

	return "md5" + outer
}
