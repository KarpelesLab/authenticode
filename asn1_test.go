package authenticode

import (
	"bytes"
	"testing"
)

// TestTLVRoundTrip drives tlv() at the length boundaries that decide
// between short-form, 1-, 2-, and 3-byte long-form encodings — and
// then re-parses with tlvValue to confirm the inverse.
func TestTLVRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 200, 255, 256, 65535, 65536, 70000} {
		body := bytes.Repeat([]byte{0xAB}, n)
		out := tlv(0x30, body)
		if out[0] != 0x30 {
			t.Fatalf("len=%d: tag = %02x, want 30", n, out[0])
		}
		v, err := tlvValue(out)
		if err != nil {
			t.Fatalf("len=%d: tlvValue: %v", n, err)
		}
		if !bytes.Equal(v, body) {
			t.Fatalf("len=%d: round-trip mismatch", n)
		}
		// Spot-check the length encoding.
		switch {
		case n < 0x80:
			if int(out[1]) != n || len(out) != 2+n {
				t.Fatalf("len=%d: short-form encoding wrong: % x...", n, out[:2])
			}
		case n <= 0xFF:
			if out[1] != 0x81 || int(out[2]) != n {
				t.Fatalf("len=%d: 1-byte long form wrong: % x", n, out[:3])
			}
		case n <= 0xFFFF:
			if out[1] != 0x82 {
				t.Fatalf("len=%d: 2-byte long form wrong: % x", n, out[:4])
			}
		default:
			if out[1] != 0x83 && out[1] != 0x84 {
				t.Fatalf("len=%d: long form length byte = %02x", n, out[1])
			}
		}
	}
}

// TestTLVValueErrors covers the rejection paths.
func TestTLVValueErrors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"single byte", []byte{0x30}},
		{"long form zero length", []byte{0x30, 0x80}},
		{"long form length truncated", []byte{0x30, 0x82, 0x00}},
		{"value truncated", []byte{0x30, 0x05, 0x00, 0x00}},
		// 9-byte long form is over the cap; we refuse it rather than
		// risk int overflow on 32-bit.
		{"oversized length field", append([]byte{0x30, 0x89}, bytes.Repeat([]byte{0xFF}, 9)...)},
	}
	for _, tc := range cases {
		if _, err := tlvValue(tc.in); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}
