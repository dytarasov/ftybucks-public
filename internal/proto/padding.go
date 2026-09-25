package proto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"ftybucks/internal/config"
)

// GeneratePadding creates random padding bytes with length in [min, max].
func GeneratePadding(min, max int) ([]byte, error) {
	if min < 0 || max < 0 || min > max {
		return nil, fmt.Errorf("invalid padding range [%d, %d]", min, max)
	}
	if max == 0 {
		return nil, nil
	}

	rangeSize := max - min + 1
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, fmt.Errorf("random read: %w", err)
	}
	padLen := min + int(binary.BigEndian.Uint16(buf[:]))%rangeSize

	padding := make([]byte, padLen)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("generate padding: %w", err)
	}
	return padding, nil
}

// PadPayload appends random padding to payload and returns the padded result and padding length.
func PadPayload(payload []byte, padCfg config.PaddingConfig) ([]byte, uint16, error) {
	padding, err := GeneratePadding(padCfg.Min, padCfg.Max)
	if err != nil {
		return nil, 0, err
	}
	padLen := uint16(len(padding))

	padded := make([]byte, len(payload)+len(padding))
	copy(padded, payload)
	copy(padded[len(payload):], padding)

	return padded, padLen, nil
}
