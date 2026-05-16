package authenticode

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse drives Parse and AuthenticodeDigest with arbitrary bytes.
// Goal: no panics on malformed input. A successful Parse must yield a
// reproducible, panic-free digest. The hello.exe fixture seeds the
// corpus so the fuzzer has a known-good starting point to mutate.
func FuzzParse(f *testing.F) {
	if data, err := os.ReadFile(filepath.Join("testdata", "hello.exe")); err == nil {
		f.Add(data)
	}
	// A handful of degenerate seeds to push the fuzzer toward the
	// shallow-parse error paths early.
	f.Add([]byte{})
	f.Add([]byte("MZ"))
	f.Add(append([]byte("MZ"), make([]byte, 62)...))
	f.Add(append([]byte("MZ"), make([]byte, 4096)...))

	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Parse(raw)
		if err != nil {
			return
		}
		// Computing the digest twice must be deterministic.
		d1 := p.AuthenticodeDigest(sha256.New())
		d2 := p.AuthenticodeDigest(sha256.New())
		if len(d1) != sha256.Size || len(d2) != sha256.Size {
			t.Fatalf("digest length: got %d/%d, want %d", len(d1), len(d2), sha256.Size)
		}
		for i := range d1 {
			if d1[i] != d2[i] {
				t.Fatalf("digest non-deterministic on len=%d input", len(raw))
			}
		}
	})
}

// FuzzTLVValue exercises the hand-rolled length parser used to peel the
// outer SEQUENCE off a freshly built SpcIndirectDataContent. Must not
// panic on garbage and must reject truncated long-form lengths.
func FuzzTLVValue(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x81, 0x01, 0xAA})
	f.Add([]byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := tlvValue(raw)
		if err != nil {
			return
		}
		if len(v) > len(raw) {
			t.Fatalf("tlvValue returned %d bytes from %d-byte input", len(v), len(raw))
		}
	})
}
