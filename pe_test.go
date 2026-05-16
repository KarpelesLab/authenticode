package authenticode

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"os"
	"path/filepath"
	"testing"
)

// TestAuthenticodeDigestStable verifies that parsing the test PE
// returns consistent offsets and that the digest is reproducible.
// The actual digest VALUE comparison against osslsigncode lives in
// the example program (requires the binary on disk).
func TestAuthenticodeDigestStable(t *testing.T) {
	for _, path := range []string{"/tmp/gs_test.exe", "/tmp/gs_test.signed.exe"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("skipping %s: %v", path, err)
			continue
		}
		p, err := Parse(data)
		if err != nil {
			t.Fatalf("Parse %s: %v", path, err)
		}
		for _, hf := range []struct {
			name string
			new  func() hash.Hash
		}{
			{"sha256", sha256.New},
			{"sha384", sha512.New384},
		} {
			d1 := p.AuthenticodeDigest(hf.new())
			d2 := p.AuthenticodeDigest(hf.new())
			if hex.EncodeToString(d1) != hex.EncodeToString(d2) {
				t.Fatalf("%s %s: digest not deterministic", path, hf.name)
			}
			t.Logf("%s %s: %s", path, hf.name, hex.EncodeToString(d1))
		}
	}
}

// TestPEChecksumMatchesFixture asserts that peChecksum recreates the
// CheckSum value already stored in testdata/hello.exe — i.e. the
// algorithm agrees with whatever toolchain originally produced the
// binary (and with Microsoft's CheckSumMappedFile).
func TestPEChecksumMatchesFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "hello.exe"))
	if err != nil {
		t.Fatal(err)
	}
	lfanew := int(binary.LittleEndian.Uint32(data[60:64]))
	csOff := lfanew + 4 + 20 + 64 // PE sig (4) + COFF (20) + offset to CheckSum (64)
	stored := binary.LittleEndian.Uint32(data[csOff : csOff+4])
	got := peChecksum(data, csOff)
	if got != stored {
		t.Fatalf("checksum mismatch: stored=%08X computed=%08X", stored, got)
	}
}

// TestSignProducesValidChecksum signs the fixture, then verifies the
// stored CheckSum in the output equals peChecksum recomputed over the
// same bytes — i.e. EmbedSignature actually populates the field.
func TestSignProducesValidChecksum(t *testing.T) {
	pe, err := os.ReadFile(filepath.Join("testdata", "hello.exe"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(pe)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	signed := p.EmbedSignature([]byte{0x30, 0x00}) // any opaque blob
	stored := binary.LittleEndian.Uint32(signed[p.checksumOff : p.checksumOff+4])
	if stored == 0 {
		t.Fatal("checksum field still zero after EmbedSignature")
	}
	if got := peChecksum(signed, p.checksumOff); got != stored {
		t.Fatalf("checksum self-consistency: stored=%08X recomputed=%08X", stored, got)
	}
}
