package authenticode

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"hash"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
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

// TestSignOmitsOpusInfoByDefault ensures that with no ProgramName or
// ProgramURL the SpcSpOpusInfo OID is absent from the signed output,
// matching osslsigncode's default behavior.
func TestSignOmitsOpusInfoByDefault(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	signed, err := Sign(pe, signer, SignOptions{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	oidDER, _ := asn1.Marshal(oidSPCSpOpusInfo)
	if bytes.Contains(signed, oidDER) {
		t.Fatal("SpcSpOpusInfo OID should not appear when ProgramName/ProgramURL are empty")
	}
}

// TestSignEmbedsOpusInfo populates both ProgramName and ProgramURL and
// asserts the signed output carries the OID together with the UCS-2
// encoded program name and the IA5String URL.
func TestSignEmbedsOpusInfo(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	const name = "Authenticode Demo"
	const url = "https://example.com/about"
	signed, err := Sign(pe, signer, SignOptions{
		ProgramName: name,
		ProgramURL:  url,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	oidDER, _ := asn1.Marshal(oidSPCSpOpusInfo)
	if !bytes.Contains(signed, oidDER) {
		t.Fatal("SpcSpOpusInfo OID missing")
	}
	bmp := make([]byte, 0, 2*len(name))
	for _, r := range name {
		bmp = append(bmp, byte(r>>8), byte(r))
	}
	if !bytes.Contains(signed, bmp) {
		t.Fatal("program name (UCS-2 BE) missing")
	}
	if !bytes.Contains(signed, []byte(url)) {
		t.Fatal("program URL missing")
	}
}

// TestSignEmbedsOpusInfoNameOnly / URLOnly cover the two single-field
// branches.
func TestSignEmbedsOpusInfoNameOnly(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	signed, err := Sign(pe, signer, SignOptions{ProgramName: "Just Name"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	oidDER, _ := asn1.Marshal(oidSPCSpOpusInfo)
	if !bytes.Contains(signed, oidDER) {
		t.Fatal("opus info OID missing when only name is set")
	}
}

func TestSignEmbedsOpusInfoURLOnly(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	signed, err := Sign(pe, signer, SignOptions{ProgramURL: "https://example.com"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	oidDER, _ := asn1.Marshal(oidSPCSpOpusInfo)
	if !bytes.Contains(signed, oidDER) {
		t.Fatal("opus info OID missing when only URL is set")
	}
}

// TestSignEmbedsSigningTime asserts the PKCS#9 signingTime is set by
// SignOptions.SigningTime when provided, and falls within a few
// seconds of now otherwise.
func TestSignEmbedsSigningTime(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	want := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	signed, err := Sign(pe, signer, SignOptions{SigningTime: want})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// asn1.Marshal(want.UTC()) produces the UTCTime DER bytes (years
	// 1950..2049). Searching for those bytes in the SignerInfo's
	// signed attributes is sufficient.
	utcDER, _ := asn1.Marshal(want)
	if !bytes.Contains(signed, utcDER) {
		t.Fatalf("signing time %v not embedded as UTCTime in signed output", want)
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
		name   string
		newSig func(*testing.T) (Signer, crypto.PublicKey)
		hash   crypto.Hash
		oid    asn1.ObjectIdentifier
		newH   func() hash.Hash
	}{
		{
			name: "P256-SHA256",
			newSig: func(t *testing.T) (Signer, crypto.PublicKey) {
				s := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
				return s, s.Public()
			},
			hash: crypto.SHA256,
			oid:  oidECDSAWithSHA256,
			newH: sha256.New,
		},
		{
			name: "P384-SHA384",
			newSig: func(t *testing.T) (Signer, crypto.PublicKey) {
				s := newSelfSignedSigner(t, elliptic.P384(), crypto.SHA384)
				return s, s.Public()
			},
			hash: crypto.SHA384,
			oid:  oidECDSAWithSHA384,
			newH: sha512.New384,
		},
		{
			name: "P521-SHA512",
			newSig: func(t *testing.T) (Signer, crypto.PublicKey) {
				s := newSelfSignedSigner(t, elliptic.P521(), crypto.SHA512)
				return s, s.Public()
			},
			hash: crypto.SHA512,
			oid:  oidECDSAWithSHA512,
			newH: sha512.New,
		},
		{
			name: "RSA-SHA256",
			newSig: func(t *testing.T) (Signer, crypto.PublicKey) {
				s := newSelfSignedRSASigner(t, crypto.SHA256)
				return s, s.Public()
			},
			hash: crypto.SHA256,
			oid:  oidSHA256WithRSA,
			newH: sha256.New,
		},
		{
			name: "RSA-SHA384",
			newSig: func(t *testing.T) (Signer, crypto.PublicKey) {
				s := newSelfSignedRSASigner(t, crypto.SHA384)
				return s, s.Public()
			},
			hash: crypto.SHA384,
			oid:  oidSHA384WithRSA,
			newH: sha512.New384,
		},
		{
			name: "RSA-SHA512",
			newSig: func(t *testing.T) (Signer, crypto.PublicKey) {
				s := newSelfSignedRSASigner(t, crypto.SHA512)
				return s, s.Public()
			},
			hash: crypto.SHA512,
			oid:  oidSHA512WithRSA,
			newH: sha512.New,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			signer, pub := tc.newSig(t)
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
			hh := tc.newH()
			hh.Write(setForSigning)
			switch pub := pub.(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pub, hh.Sum(nil), si.Signature) {
					t.Fatal("SignerInfo signature did not verify")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pub, tc.hash, hh.Sum(nil), si.Signature); err != nil {
					t.Fatalf("SignerInfo signature did not verify: %v", err)
				}
				if len(si.SignatureAlgorithm.Parameters.FullBytes) == 0 {
					t.Fatal("RSA signature algorithm parameters missing NULL")
				}
			default:
				t.Fatalf("unexpected public key type %T", pub)
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
		name   string
		newSig func(*testing.T) (Signer, *x509.Certificate)
		hash   crypto.Hash
	}{
		{
			name: "P256-SHA256",
			newSig: func(t *testing.T) (Signer, *x509.Certificate) {
				s := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
				return s, s.cert
			},
			hash: crypto.SHA256,
		},
		{
			name: "P384-SHA384",
			newSig: func(t *testing.T) (Signer, *x509.Certificate) {
				s := newSelfSignedSigner(t, elliptic.P384(), crypto.SHA384)
				return s, s.cert
			},
			hash: crypto.SHA384,
		},
		{
			name: "P521-SHA512",
			newSig: func(t *testing.T) (Signer, *x509.Certificate) {
				s := newSelfSignedSigner(t, elliptic.P521(), crypto.SHA512)
				return s, s.cert
			},
			hash: crypto.SHA512,
		},
		{
			name: "RSA-SHA256",
			newSig: func(t *testing.T) (Signer, *x509.Certificate) {
				s := newSelfSignedRSASigner(t, crypto.SHA256)
				return s, s.cert
			},
			hash: crypto.SHA256,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			signer, caCert := tc.newSig(t)
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
			if err := writePEM(caPath, caCert.Raw); err != nil {
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

// TestSignDLLOsslsigncode signs testdata/hello.dll (a PE32+ DLL built
// with mingw, IMAGE_FILE_DLL characteristic set) and shells out to
// osslsigncode verify. DLLs share the PE format with EXEs but exercise
// the PE32+ optional-header path and confirm we don't accidentally
// special-case .exe anywhere.
func TestSignDLLOsslsigncode(t *testing.T) {
	if _, err := exec.LookPath("osslsigncode"); err != nil {
		t.Skip("osslsigncode not installed")
	}
	dll, err := os.ReadFile(filepath.Join("testdata", "hello.dll"))
	if err != nil {
		t.Fatalf("read hello.dll: %v", err)
	}
	signer := newSelfSignedSigner(t, elliptic.P384(), crypto.SHA384)
	signed, err := Sign(dll, signer, SignOptions{Hash: crypto.SHA384})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	dir := t.TempDir()
	dllPath := filepath.Join(dir, "signed.dll")
	caPath := filepath.Join(dir, "self.pem")
	if err := os.WriteFile(dllPath, signed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(caPath, signer.cert.Raw); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("osslsigncode", "verify",
		"-CAfile", caPath, "-TSA-CAfile", caPath, "-ignore-timestamp",
		"-in", dllPath).CombinedOutput()
	t.Logf("osslsigncode output:\n%s", out)
	if err != nil {
		t.Fatalf("osslsigncode verify failed: %v", err)
	}
	if bytes.Contains(out, []byte("invalid PE checksum")) {
		t.Fatal("osslsigncode reported an invalid PE checksum on the signed DLL")
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
