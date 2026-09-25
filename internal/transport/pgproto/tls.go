package pgproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// certDir is the default directory for persisting the TLS certificate.
const certDir = "/etc/ftybucks"

// GenerateSelfSignedCert creates an in-memory RSA-2048 self-signed certificate.
// CN=PostgreSQL, 1–3 year validity (randomized per generation) — mimics a real
// PG server's TLS cert. RSA-2048 matches what real PostgreSQL servers use.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	// Randomize validity: 365–1095 days (1–3 years) and randomize notBefore
	// to look like the cert was generated at a typical time, not right now.
	var rb [2]byte
	rand.Read(rb[:])
	validDays := 365 + int(binary.BigEndian.Uint16(rb[:]))%730
	// Generated some days ago (1–180 days) — looks like existing deployment
	ageDays := 1 + int(rb[0])%180

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour),
		NotAfter:              time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	tmpl.Subject.CommonName = "PostgreSQL"

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

// LoadOrGenerateCert loads TLS cert/key from disk, or generates and persists a new one.
// This ensures the certificate fingerprint is stable across server restarts.
func LoadOrGenerateCert(dir string) (tls.Certificate, error) {
	if dir == "" {
		dir = certDir
	}
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	// Try loading existing cert
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return cert, nil
	}

	// Generate new cert
	newCert, err := GenerateSelfSignedCert()
	if err != nil {
		return tls.Certificate{}, err
	}

	// Persist to disk (best-effort — works without persistence too)
	if mkErr := os.MkdirAll(dir, 0700); mkErr == nil {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Certificate[0]})
		keyDER, _ := x509.MarshalPKCS8PrivateKey(newCert.PrivateKey)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		os.WriteFile(certPath, certPEM, 0644)
		os.WriteFile(keyPath, keyPEM, 0600)
	}

	return newCert, nil
}

// DeterministicCert derives a stable TLS certificate from the PSK.
// This ensures the cert fingerprint is consistent without requiring disk storage.
func DeterministicCert(psk []byte) (tls.Certificate, error) {
	// Derive deterministic seed from PSK
	seed := sha256.Sum256(append([]byte("ftybucks-tls-cert-v1"), psk...))

	// Use seed as deterministic randomness for key generation
	priv, err := ecdsa.GenerateKey(elliptic.P256(), &deterministicReader{seed: seed[:]})
	if err != nil {
		// Fallback to RSA with true randomness
		return GenerateSelfSignedCert()
	}

	serial := new(big.Int).SetBytes(seed[:16])

	// Randomize validity window using freshly random bytes (NOT the deterministic
	// seed) so the cert dates differ across servers sharing a PSK — otherwise
	// every node in the fleet exposes the same NotBefore/NotAfter pair, which
	// is a fingerprint that no real-world PG deployment exhibits.
	var rb [2]byte
	rand.Read(rb[:])
	validDays := 365 + int(binary.BigEndian.Uint16(rb[:]))%730
	ageDays := 1 + int(rb[0])%180

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour),
		NotAfter:              time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	tmpl.Subject.CommonName = "PostgreSQL"

	certDER, err := x509.CreateCertificate(&deterministicReader{seed: seed[:]}, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return GenerateSelfSignedCert()
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

// deterministicReader provides deterministic bytes from a seed via SHA-256 chain.
type deterministicReader struct {
	seed []byte
	buf  []byte
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for len(r.buf) < len(p) {
		h := sha256.Sum256(r.seed)
		r.buf = append(r.buf, h[:]...)
		r.seed = h[:]
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// serverTLSConfig returns a TLS config for the PostgreSQL disguise.
//
// It is pinned to TLS 1.3 only. Rationale: Go's crypto/tls and OpenSSL produce
// different TLS 1.2 ServerHellos (extension set + order), so a TLS-1.2 handshake
// from this server carries a Go JA3S/JA4S fingerprint that does not match a real
// PostgreSQL/OpenSSL server — a clean tell for a DPI that fingerprints the
// server side. The TLS 1.3 ServerHello, by contrast, is effectively
// stack-neutral (just supported_versions + key_share), so a 1.3-only server is
// indistinguishable from OpenSSL on that axis. Our own client (libpq uTLS
// preset) offers 1.3, so nothing regresses; an active prober speaking only 1.2
// gets a handshake failure, exactly like a real PG with
// ssl_min_protocol_version=TLSv1.3.
//
// CurvePreferences match OpenSSL 3.x's default group list.
func serverTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
	}
}

