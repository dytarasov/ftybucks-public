package proto

import (
	"testing"

	"ftybucks/internal/config"
)

func TestGeneratePadding(t *testing.T) {
	tests := []struct {
		name    string
		min     int
		max     int
		wantErr bool
	}{
		{"zero range", 0, 0, false},
		{"fixed size", 10, 10, false},
		{"range", 64, 512, false},
		{"invalid negative min", -1, 10, true},
		{"invalid min > max", 100, 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pad, err := GeneratePadding(tt.min, tt.max)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.max == 0 {
				if pad != nil {
					t.Fatalf("expected nil padding for max=0, got %d bytes", len(pad))
				}
				return
			}
			if len(pad) < tt.min || len(pad) > tt.max {
				t.Fatalf("padding length %d not in [%d, %d]", len(pad), tt.min, tt.max)
			}
		})
	}
}

func TestPadPayload(t *testing.T) {
	payload := []byte("hello world")
	padCfg := config.PaddingConfig{Min: 10, Max: 50}

	padded, padLen, err := PadPayload(payload, padCfg)
	if err != nil {
		t.Fatalf("PadPayload: %v", err)
	}

	if int(padLen) < padCfg.Min || int(padLen) > padCfg.Max {
		t.Fatalf("padLen %d not in [%d, %d]", padLen, padCfg.Min, padCfg.Max)
	}

	if len(padded) != len(payload)+int(padLen) {
		t.Fatalf("padded len %d != payload(%d) + padLen(%d)", len(padded), len(payload), padLen)
	}

	// Payload should be preserved at the beginning
	if string(padded[:len(payload)]) != "hello world" {
		t.Fatal("payload corrupted")
	}
}

func TestGeneratePaddingRandomness(t *testing.T) {
	// Generate multiple paddings and verify they're not all the same length
	lengths := make(map[int]bool)
	for i := 0; i < 100; i++ {
		pad, err := GeneratePadding(1, 256)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		lengths[len(pad)] = true
	}
	if len(lengths) < 5 {
		t.Fatalf("expected variety in padding lengths, got only %d unique values", len(lengths))
	}
}
