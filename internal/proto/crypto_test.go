package proto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	salt := make([]byte, 32)
	rand.Read(salt)

	key1, err := DeriveKey(psk, nil, salt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if len(key1) != KeySize {
		t.Fatalf("key size %d != %d", len(key1), KeySize)
	}

	// Same inputs → same key
	key2, err := DeriveKey(psk, nil, salt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("same inputs produced different keys")
	}

	// Different salt → different key
	salt2 := make([]byte, 32)
	rand.Read(salt2)
	key3, err := DeriveKey(psk, nil, salt2)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if bytes.Equal(key1, key3) {
		t.Fatal("different salts produced same key")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	plaintext := []byte("secret tunnel data - IP packets go here")
	ad := []byte("additional-data")

	ciphertext := c.Seal(nil, nonce, plaintext, ad)

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	decrypted, err := c.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted data doesn't match plaintext")
	}
}

func TestDecryptTampered(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	plaintext := []byte("data")
	ad := []byte("ad")

	ciphertext := c.Seal(nil, nonce, plaintext, ad)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xff

	_, err = c.Open(nil, nonce, ciphertext, ad)
	if err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, KeySize)
	rand.Read(key1)
	key2 := make([]byte, KeySize)
	rand.Read(key2)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	c1, err := NewCipher(key1)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	c2, err := NewCipher(key2)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	ciphertext := c1.Seal(nil, nonce, []byte("hello"), nil)

	_, err = c2.Open(nil, nonce, ciphertext, nil)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}
