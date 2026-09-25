package proto

import (
	"crypto/cipher"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	KeySize     = chacha20poly1305.KeySize  // 32 bytes
	NonceSize   = chacha20poly1305.NonceSize // 12 bytes
	ECDHKeySize = 32                         // X25519 key size
)

// Cipher wraps a cached ChaCha20-Poly1305 AEAD instance.
// Safe for concurrent use — AEAD.Seal/Open are thread-safe.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher creates a Cipher with a cached AEAD from the given key.
func NewCipher(key []byte) (*Cipher, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Overhead returns the AEAD overhead (Poly1305 tag size = 16 bytes).
func (c *Cipher) Overhead() int {
	return c.aead.Overhead()
}

// Seal encrypts plaintext with the given nonce and additional data.
// Appends ciphertext to dst and returns the result.
func (c *Cipher) Seal(dst, nonce, plaintext, ad []byte) []byte {
	return c.aead.Seal(dst, nonce, plaintext, ad)
}

// Open decrypts ciphertext with the given nonce and additional data.
// Appends plaintext to dst and returns the result.
func (c *Cipher) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	return c.aead.Open(dst, nonce, ciphertext, ad)
}

// DeriveKey derives a 32-byte encryption key using HKDF-SHA256.
// IKM = psk || ecdhSecret (forward secrecy when ecdhSecret is from ephemeral X25519).
func DeriveKey(psk, ecdhSecret, salt []byte) ([]byte, error) {
	ikm := make([]byte, len(psk)+len(ecdhSecret))
	copy(ikm, psk)
	copy(ikm[len(psk):], ecdhSecret)
	hk := hkdf.New(sha256.New, ikm, salt, []byte("shadowtunnel-session-v1"))
	key := make([]byte, KeySize)
	if _, err := hk.Read(key); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return key, nil
}
