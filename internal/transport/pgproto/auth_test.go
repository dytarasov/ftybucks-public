package pgproto

import (
	"strings"
	"testing"
)

func TestComputePGMD5(t *testing.T) {
	psk := []byte("mysecretpassword")
	salt := [4]byte{0x01, 0x02, 0x03, 0x04}

	result := computePGMD5(psk, salt)

	// Must start with "md5"
	if !strings.HasPrefix(result, "md5") {
		t.Fatalf("result %q doesn't start with 'md5'", result)
	}

	// Must be "md5" + 32 hex chars = 35 total
	if len(result) != 35 {
		t.Fatalf("result length = %d, want 35", len(result))
	}

	// Same inputs → same output (deterministic)
	result2 := computePGMD5(psk, salt)
	if result != result2 {
		t.Fatalf("non-deterministic: %q != %q", result, result2)
	}

	// Different salt → different output
	salt2 := [4]byte{0x05, 0x06, 0x07, 0x08}
	result3 := computePGMD5(psk, salt2)
	if result == result3 {
		t.Fatalf("different salt produced same hash")
	}

	// Different password → different output
	result4 := computePGMD5([]byte("otherpassword"), salt)
	if result == result4 {
		t.Fatalf("different password produced same hash")
	}
}
