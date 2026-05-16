package authenticode

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// chainlessSigner returns nil from CertificateChain(), forcing Sign to
// fall back to Certificate().
type chainlessSigner struct{ *selfSignedSigner }

func (c chainlessSigner) CertificateChain() []*x509.Certificate { return nil }

// noCertSigner returns nil for both — exercises the empty-input error.
type noCertSigner struct{ *selfSignedSigner }

func (n noCertSigner) Certificate() *x509.Certificate        { return nil }
func (n noCertSigner) CertificateChain() []*x509.Certificate { return nil }

func TestSignDefaultsToSHA256(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	// Zero-value SignOptions → Hash defaults to SHA-256.
	signed, err := Sign(pe, signer, SignOptions{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	spc := decodeEmbeddedSpc(t, signed)
	if !spc.MessageDigest.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Fatalf("digestAlgorithm = %v, want SHA-256", spc.MessageDigest.DigestAlgorithm.Algorithm)
	}
	if len(spc.MessageDigest.Digest) != sha256.Size {
		t.Fatalf("digest len = %d, want %d", len(spc.MessageDigest.Digest), sha256.Size)
	}
}

func TestSignEmptyChainRejected(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	if _, err := SignWithChain(pe, signer, nil, SignOptions{}); err == nil {
		t.Fatal("expected error from SignWithChain with empty chain")
	}
}

func TestSignNoCertificateRejected(t *testing.T) {
	base := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	if _, err := Sign(pe, noCertSigner{base}, SignOptions{}); err == nil {
		t.Fatal("expected error from Sign with no certificate")
	}
}

func TestSignFallbackToCertificate(t *testing.T) {
	base := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	signed, err := Sign(pe, chainlessSigner{base}, SignOptions{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Contains(signed, base.cert.Raw) {
		t.Fatal("leaf cert not embedded in signed output")
	}
}

func TestSignRejectsGarbagePE(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	if _, err := Sign([]byte("not a PE"), signer, SignOptions{}); err == nil {
		t.Fatal("expected error from Sign on non-PE input")
	}
}

// TestReSignReplacesExistingTable signs hello.exe twice. The second
// signed file should parse, carry a single WIN_CERTIFICATE whose
// embedded SpcIndirectDataContent digest matches the freshly stripped
// PE — i.e. EmbedSignature peeled the prior table off before hashing.
func TestReSignReplacesExistingTable(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P384(), crypto.SHA384)
	pe := loadHelloPE(t)
	once, err := Sign(pe, signer, SignOptions{Hash: crypto.SHA384})
	if err != nil {
		t.Fatalf("first Sign: %v", err)
	}
	twice, err := Sign(once, signer, SignOptions{Hash: crypto.SHA384})
	if err != nil {
		t.Fatalf("re-Sign: %v", err)
	}
	// Size should be roughly the same (re-signed, not appended).
	if len(twice) > len(once)+512 {
		t.Fatalf("re-sign grew unexpectedly: %d → %d", len(once), len(twice))
	}
	spc := decodeEmbeddedSpc(t, twice)
	p, _ := Parse(twice)
	got := p.AuthenticodeDigest(crypto.SHA384.New())
	if !bytes.Equal(got, spc.MessageDigest.Digest) {
		t.Fatalf("re-sign digest mismatch:\n  got %x\n  spc %x", got, spc.MessageDigest.Digest)
	}
}

// TestSignMatrix verifies the full sign/parse/verify loop for every
// curve + hash combination we advertise.
func TestSignMatrix(t *testing.T) {
	cases := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
		oid   asn1.ObjectIdentifier
	}{
		{"P256-SHA256", elliptic.P256(), crypto.SHA256, oidECDSAWithSHA256},
		{"P384-SHA384", elliptic.P384(), crypto.SHA384, oidECDSAWithSHA384},
		{"P521-SHA512", elliptic.P521(), crypto.SHA512, oidECDSAWithSHA512},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			signer := newSelfSignedSigner(t, tc.curve, tc.hash)
			pe := loadHelloPE(t)
			signed, err := Sign(pe, signer, SignOptions{Hash: tc.hash})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			si := decodeEmbeddedSignerInfo(t, signed)
			if !si.SignatureAlgorithm.Algorithm.Equal(tc.oid) {
				t.Fatalf("signature alg = %v, want %v", si.SignatureAlgorithm.Algorithm, tc.oid)
			}
			// Verify the SignerInfo signature against the SET-form of the
			// signed attributes.
			setForSigning := append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
			hh := tc.hash.New()
			hh.Write(setForSigning)
			if !ecdsa.VerifyASN1(&signer.key.PublicKey, hh.Sum(nil), si.Signature) {
				t.Fatal("SignerInfo signature did not verify")
			}
		})
	}
}

// TestSignMatrixOsslsigncode reruns the matrix and shells out to
// osslsigncode verify. Skipped automatically when the binary is absent
// (e.g. local laptops without the package installed).
func TestSignMatrixOsslsigncode(t *testing.T) {
	if _, err := exec.LookPath("osslsigncode"); err != nil {
		t.Skip("osslsigncode not installed")
	}
	cases := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P256-SHA256", elliptic.P256(), crypto.SHA256},
		{"P384-SHA384", elliptic.P384(), crypto.SHA384},
		{"P521-SHA512", elliptic.P521(), crypto.SHA512},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			signer := newSelfSignedSigner(t, tc.curve, tc.hash)
			pe := loadHelloPE(t)
			signed, err := Sign(pe, signer, SignOptions{Hash: tc.hash})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			dir := t.TempDir()
			exePath := filepath.Join(dir, "signed.exe")
			caPath := filepath.Join(dir, "self.pem")
			if err := os.WriteFile(exePath, signed, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := writePEM(caPath, signer.cert.Raw); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("osslsigncode", "verify",
				"-CAfile", caPath, "-TSA-CAfile", caPath, "-ignore-timestamp",
				"-in", exePath).CombinedOutput()
			t.Logf("osslsigncode output:\n%s", out)
			if err != nil {
				t.Fatalf("osslsigncode verify failed: %v", err)
			}
			if bytes.Contains(out, []byte("invalid PE checksum")) {
				t.Fatal("osslsigncode reported an invalid PE checksum")
			}
		})
	}
}

// TestEmbedSignatureAlignment confirms the WIN_CERTIFICATE table is
// 8-byte aligned and that the data-directory entry agrees with the
// table header's dwLength.
func TestEmbedSignatureAlignment(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	signed, err := Sign(pe, signer, SignOptions{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	p, err := Parse(signed)
	if err != nil {
		t.Fatalf("Parse signed: %v", err)
	}
	if p.certTableVA == 0 {
		t.Fatal("no cert table in signed output")
	}
	if p.certTableVA%8 != 0 {
		t.Fatalf("cert table VA %d not 8-byte aligned", p.certTableVA)
	}
	wc := signed[p.certTableVA : p.certTableVA+p.certTableSize]
	if len(wc) < 8 {
		t.Fatal("WIN_CERTIFICATE smaller than header")
	}
	dwLength := uint32(wc[0]) | uint32(wc[1])<<8 | uint32(wc[2])<<16 | uint32(wc[3])<<24
	if dwLength != p.certTableSize {
		t.Fatalf("dwLength %d != certTableSize %d", dwLength, p.certTableSize)
	}
}

// decodeEmbeddedSpc walks a signed PE down to the SpcIndirectDataContent.
func decodeEmbeddedSpc(t *testing.T, signed []byte) *spcIndirectDataContent {
	t.Helper()
	p, err := Parse(signed)
	if err != nil {
		t.Fatalf("Parse signed: %v", err)
	}
	if p.certTableVA == 0 {
		t.Fatal("no cert table in signed output")
	}
	cms := signed[p.certTableVA+8 : p.certTableVA+p.certTableSize]
	for len(cms) > 0 && cms[len(cms)-1] == 0 {
		cms = cms[:len(cms)-1]
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(cms, &ci); err != nil {
		t.Fatalf("decode ContentInfo: %v", err)
	}
	var sd struct {
		Version          int
		DigestAlgorithms []algorithmIdentifier `asn1:"set"`
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     asn1.RawValue `asn1:"explicit,tag:0,optional"`
		}
		Certificates asn1.RawValue   `asn1:"tag:0,implicit,optional"`
		SignerInfos  []asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("decode SignedData: %v", err)
	}
	var spc spcIndirectDataContent
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &spc); err != nil {
		t.Fatalf("decode SpcIndirectDataContent: %v", err)
	}
	return &spc
}

type embeddedSignerInfo struct {
	Version int
	SID     struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"tag:0,implicit,optional"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"tag:1,implicit,optional"`
}

// decodeEmbeddedSignerInfo returns the first SignerInfo from the
// embedded SignedData.
func decodeEmbeddedSignerInfo(t *testing.T, signed []byte) *embeddedSignerInfo {
	t.Helper()
	p, err := Parse(signed)
	if err != nil {
		t.Fatalf("Parse signed: %v", err)
	}
	cms := signed[p.certTableVA+8 : p.certTableVA+p.certTableSize]
	for len(cms) > 0 && cms[len(cms)-1] == 0 {
		cms = cms[:len(cms)-1]
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(cms, &ci); err != nil {
		t.Fatalf("decode ContentInfo: %v", err)
	}
	var sd struct {
		Version          int
		DigestAlgorithms []algorithmIdentifier `asn1:"set"`
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     asn1.RawValue `asn1:"explicit,tag:0,optional"`
		}
		Certificates asn1.RawValue        `asn1:"tag:0,implicit,optional"`
		SignerInfos  []embeddedSignerInfo `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("decode SignedData: %v", err)
	}
	if len(sd.SignerInfos) == 0 {
		t.Fatal("no SignerInfos")
	}
	return &sd.SignerInfos[0]
}
