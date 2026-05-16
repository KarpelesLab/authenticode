package authenticode

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"os"
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
