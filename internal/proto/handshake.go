package proto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	SaltSize         = 32
	HMACSize         = 32 // SHA-256
	TimestampSize    = 8
	MaxTimestampSkew = 30 * time.Second
	NoncesTTL        = 60 * time.Second

	// ClientHello = salt(32) + timestamp(8) + ecdhPub(32) + hmac(32) = 104 bytes
	ClientHelloSize = SaltSize + TimestampSize + ECDHKeySize + HMACSize
	// ServerHello = salt(32) + ecdhPub(32) + hmac(32) = 96 bytes
	ServerHelloSize = SaltSize + ECDHKeySize + HMACSize
)

// ReplayGuard stores seen nonces to prevent replay attacks.
type ReplayGuard struct {
	mu    sync.Mutex
	seen  map[[SaltSize]byte]time.Time
	ttl   time.Duration
}

// NewReplayGuard creates a new replay guard with periodic cleanup.
func NewReplayGuard() *ReplayGuard {
	rg := &ReplayGuard{
		seen: make(map[[SaltSize]byte]time.Time),
		ttl:  NoncesTTL,
	}
	go rg.cleanup()
	return rg
}

func (rg *ReplayGuard) cleanup() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		rg.mu.Lock()
		now := time.Now()
		for k, t := range rg.seen {
			if now.Sub(t) > rg.ttl {
				delete(rg.seen, k)
			}
		}
		rg.mu.Unlock()
	}
}

// Check returns true if salt has NOT been seen before (i.e., it's fresh).
func (rg *ReplayGuard) Check(salt []byte) bool {
	if len(salt) != SaltSize {
		return false
	}
	var key [SaltSize]byte
	copy(key[:], salt)

	rg.mu.Lock()
	defer rg.mu.Unlock()

	if _, exists := rg.seen[key]; exists {
		return false
	}
	rg.seen[key] = time.Now()
	return true
}

// computeHMAC calculates HMAC-SHA256.
func computeHMAC(psk, data []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(data)
	return mac.Sum(nil)
}

// ClientHandshake performs the client side of the handshake.
// Returns the derived session key.
func ClientHandshake(rw io.ReadWriter, psk []byte) ([]byte, error) {
	// Generate client salt
	clientSalt := make([]byte, SaltSize)
	if _, err := rand.Read(clientSalt); err != nil {
		return nil, fmt.Errorf("generate client salt: %w", err)
	}

	// Generate ephemeral X25519 keypair
	var clientPriv [ECDHKeySize]byte
	if _, err := rand.Read(clientPriv[:]); err != nil {
		return nil, fmt.Errorf("generate ecdh key: %w", err)
	}
	clientPub, err := curve25519.X25519(clientPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("compute ecdh pubkey: %w", err)
	}

	// Build timestamp
	timestamp := make([]byte, TimestampSize)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()))

	// HMAC covers: salt || timestamp || ecdhPub
	hmacInput := make([]byte, SaltSize+TimestampSize+ECDHKeySize)
	copy(hmacInput, clientSalt)
	copy(hmacInput[SaltSize:], timestamp)
	copy(hmacInput[SaltSize+TimestampSize:], clientPub)
	mac := computeHMAC(psk, hmacInput)

	// ClientHello: salt(32) + timestamp(8) + ecdhPub(32) + hmac(32) = 104
	hello := make([]byte, ClientHelloSize)
	copy(hello, clientSalt)
	copy(hello[SaltSize:], timestamp)
	copy(hello[SaltSize+TimestampSize:], clientPub)
	copy(hello[SaltSize+TimestampSize+ECDHKeySize:], mac)

	// Send as handshake frame
	frame := EncodeRaw(FrameHandshake, hello)
	if _, err := rw.Write(frame); err != nil {
		return nil, fmt.Errorf("send client hello: %w", err)
	}

	// Read server hello: Version(1) + Type(1) + Len(2) + ServerHelloSize
	serverFrame := make([]byte, 4+ServerHelloSize)
	if _, err := io.ReadFull(rw, serverFrame); err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}

	if serverFrame[0] != Version || serverFrame[1] != FrameHandshake {
		return nil, fmt.Errorf("invalid server hello frame")
	}

	serverSalt := serverFrame[4 : 4+SaltSize]
	serverECDHPub := serverFrame[4+SaltSize : 4+SaltSize+ECDHKeySize]
	serverMAC := serverFrame[4+SaltSize+ECDHKeySize:]

	// Verify server HMAC (covers salt || ecdhPub)
	serverHMACInput := make([]byte, SaltSize+ECDHKeySize)
	copy(serverHMACInput, serverSalt)
	copy(serverHMACInput[SaltSize:], serverECDHPub)
	expectedMAC := computeHMAC(psk, serverHMACInput)
	if !hmac.Equal(serverMAC, expectedMAC) {
		return nil, fmt.Errorf("server HMAC verification failed")
	}

	// Compute ECDH shared secret
	sharedSecret, err := curve25519.X25519(clientPriv[:], serverECDHPub)
	if err != nil {
		return nil, fmt.Errorf("compute ecdh shared secret: %w", err)
	}

	// Derive session key from PSK + ECDH shared secret + combined salts
	combinedSalt := make([]byte, SaltSize*2)
	copy(combinedSalt, clientSalt)
	copy(combinedSalt[SaltSize:], serverSalt)

	sessionKey, err := DeriveKey(psk, sharedSecret, combinedSalt)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}

	return sessionKey, nil
}

// ServerHandshake performs the server side of the handshake.
// Returns the derived session key.
func ServerHandshake(rw io.ReadWriter, psk []byte, guard *ReplayGuard) ([]byte, error) {
	// Read client hello: Version(1) + Type(1) + Len(2) + ClientHelloSize
	clientFrame := make([]byte, 4+ClientHelloSize)
	if _, err := io.ReadFull(rw, clientFrame); err != nil {
		log.Printf("[HS]: read client hello failed — %v", err)
		return nil, fmt.Errorf("read client hello: %w", err)
	}

	if clientFrame[0] != Version || clientFrame[1] != FrameHandshake {
		log.Printf("[HS]: invalid frame header version=0x%02x type=0x%02x", clientFrame[0], clientFrame[1])
		return nil, fmt.Errorf("invalid client hello frame")
	}

	clientSalt := clientFrame[4 : 4+SaltSize]
	timestamp := clientFrame[4+SaltSize : 4+SaltSize+TimestampSize]
	clientECDHPub := clientFrame[4+SaltSize+TimestampSize : 4+SaltSize+TimestampSize+ECDHKeySize]
	clientMAC := clientFrame[4+SaltSize+TimestampSize+ECDHKeySize:]

	// Verify timestamp freshness
	ts := int64(binary.BigEndian.Uint64(timestamp))
	diff := time.Now().Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(math.Ceil(MaxTimestampSkew.Seconds())) {
		log.Printf("[HS]: timestamp skew %ds (max %v) — clock mismatch or replay", diff, MaxTimestampSkew)
		return nil, fmt.Errorf("timestamp too skewed: %ds", diff)
	}

	// Verify client HMAC (covers salt || timestamp || ecdhPub)
	hmacInput := make([]byte, SaltSize+TimestampSize+ECDHKeySize)
	copy(hmacInput, clientSalt)
	copy(hmacInput[SaltSize:], timestamp)
	copy(hmacInput[SaltSize+TimestampSize:], clientECDHPub)
	expectedMAC := computeHMAC(psk, hmacInput)
	if !hmac.Equal(clientMAC, expectedMAC) {
		log.Printf("[HS]: HMAC mismatch — wrong PSK or corrupted hello")
		return nil, fmt.Errorf("client HMAC verification failed")
	}

	// Replay protection
	if !guard.Check(clientSalt) {
		log.Printf("[HS]: replay detected — duplicate salt")
		return nil, fmt.Errorf("replay detected: salt already seen")
	}

	// Generate ephemeral X25519 keypair
	var serverPriv [ECDHKeySize]byte
	if _, err := rand.Read(serverPriv[:]); err != nil {
		return nil, fmt.Errorf("generate ecdh key: %w", err)
	}
	serverPub, err := curve25519.X25519(serverPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("compute ecdh pubkey: %w", err)
	}

	// Compute ECDH shared secret
	sharedSecret, err := curve25519.X25519(serverPriv[:], clientECDHPub)
	if err != nil {
		return nil, fmt.Errorf("compute ecdh shared secret: %w", err)
	}

	// Generate server salt
	serverSalt := make([]byte, SaltSize)
	if _, err := rand.Read(serverSalt); err != nil {
		return nil, fmt.Errorf("generate server salt: %w", err)
	}

	// Build server hello: salt(32) + ecdhPub(32) + hmac(psk, salt||ecdhPub)(32) = 96
	serverHMACInput := make([]byte, SaltSize+ECDHKeySize)
	copy(serverHMACInput, serverSalt)
	copy(serverHMACInput[SaltSize:], serverPub)
	mac := computeHMAC(psk, serverHMACInput)

	hello := make([]byte, ServerHelloSize)
	copy(hello, serverSalt)
	copy(hello[SaltSize:], serverPub)
	copy(hello[SaltSize+ECDHKeySize:], mac)

	frame := EncodeRaw(FrameHandshake, hello)
	if _, err := rw.Write(frame); err != nil {
		return nil, fmt.Errorf("send server hello: %w", err)
	}

	// Derive session key
	combinedSalt := make([]byte, SaltSize*2)
	copy(combinedSalt, clientSalt)
	copy(combinedSalt[SaltSize:], serverSalt)

	sessionKey, err := DeriveKey(psk, sharedSecret, combinedSalt)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}

	return sessionKey, nil
}
