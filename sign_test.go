package authenticode

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedSigner is a minimal authenticode.Signer implementation
// using an in-memory private key for unit-test signing — no token required.
type selfSignedSigner struct {
	key   crypto.Signer
	cert  *x509.Certificate
	chain []*x509.Certificate
}

func (s *selfSignedSigner) Public() crypto.PublicKey              { return s.key.Public() }
func (s *selfSignedSigner) Certificate() *x509.Certificate        { return s.cert }
func (s *selfSignedSigner) CertificateChain() []*x509.Certificate { return s.chain }
func (s *selfSignedSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rnd, digest, opts)
}

func newSelfSignedSigner(t *testing.T, curve elliptic.Curve, hash crypto.Hash) *selfSignedSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:       big.NewInt(0xC0DE),
		Subject:            pkix.Name{CommonName: "authenticode self-signed test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	if hash == crypto.SHA256 {
		tpl.SignatureAlgorithm = x509.ECDSAWithSHA256
	}
	if hash == crypto.SHA512 {
		tpl.SignatureAlgorithm = x509.ECDSAWithSHA512
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &selfSignedSigner{
		key:   key,
		cert:  cert,
		chain: []*x509.Certificate{cert},
	}
}

func newSelfSignedRSASigner(t *testing.T, hash crypto.Hash) *selfSignedSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:       big.NewInt(0xC0DF),
		Subject:            pkix.Name{CommonName: "authenticode self-signed RSA test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SignatureAlgorithm: x509.SHA384WithRSA,
	}
	if hash == crypto.SHA256 {
		tpl.SignatureAlgorithm = x509.SHA256WithRSA
	}
	if hash == crypto.SHA512 {
		tpl.SignatureAlgorithm = x509.SHA512WithRSA
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &selfSignedSigner{
		key:   key,
		cert:  cert,
		chain: []*x509.Certificate{cert},
	}
}

func loadHelloPE(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("testdata", "hello.exe")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// TestSignSelfSignedRoundTrip signs the test PE with a freshly
// generated ECDSA P-384 / SHA-384 self-signed cert, then verifies
// every layer of the result purely in Go:
//   - the file is still a parseable PE
//   - the WIN_CERTIFICATE table embeds a valid ContentInfo (signedData)
//   - the SignedData decodes
//   - the messageDigest in the SpcIndirectDataContent matches the
//     Authenticode digest of the freshly stripped PE
//   - the SignerInfo's signature verifies against the signed-attrs DER
func TestSignSelfSignedRoundTrip(t *testing.T) {
	signer := newSelfSignedSigner(t, elliptic.P384(), crypto.SHA384)
	pe := loadHelloPE(t)
	signed, err := Sign(pe, signer, SignOptions{Hash: crypto.SHA384})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signed) <= len(pe) {
		t.Fatalf("signed file (%d B) not larger than input (%d B)", len(signed), len(pe))
	}

	// Re-parse and locate the embedded WIN_CERTIFICATE.
	p, err := Parse(signed)
	if err != nil {
		t.Fatalf("Parse signed: %v", err)
	}
	if p.certTableVA == 0 || p.certTableSize == 0 {
		t.Fatal("signed PE has no attribute certificate table entry")
	}
	wc := signed[p.certTableVA : p.certTableVA+p.certTableSize]
	if len(wc) < 8 {
		t.Fatal("WIN_CERTIFICATE too small")
	}
	cmsBlob := wc[8:] // skip dwLength/wRevision/wCertificateType
	// Strip any 8-byte padding tail introduced by EmbedSignature.
	for len(cmsBlob) > 0 && cmsBlob[len(cmsBlob)-1] == 0 {
		cmsBlob = cmsBlob[:len(cmsBlob)-1]
	}

	// Decode ContentInfo -> SignedData.
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(cmsBlob, &ci); err != nil {
		t.Fatalf("decode ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		t.Fatalf("contentType = %v, want %v", ci.ContentType, oidSignedData)
	}
	var sd struct {
		Version          int
		DigestAlgorithms []algorithmIdentifier `asn1:"set"`
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     asn1.RawValue `asn1:"explicit,tag:0,optional"`
		}
		Certificates asn1.RawValue `asn1:"tag:0,implicit,optional"`
		SignerInfos  []struct {
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
		} `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("decode SignedData: %v", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidSPCIndirectDataContent) {
		t.Fatalf("eContentType = %v, want %v", sd.EncapContentInfo.EContentType, oidSPCIndirectDataContent)
	}

	// Decode the SpcIndirectDataContent and pull out the PE digest.
	spcDER := sd.EncapContentInfo.EContent.Bytes
	var spc spcIndirectDataContent
	if _, err := asn1.Unmarshal(spcDER, &spc); err != nil {
		t.Fatalf("decode SpcIndirectDataContent: %v", err)
	}

	// Recompute the Authenticode digest of the signed PE and compare —
	// the cert table is excluded so the value must equal the one inside
	// SpcIndirectDataContent.
	gotPE := p.AuthenticodeDigest(sha512.New384())
	if !bytesSame(gotPE, spc.MessageDigest.Digest) {
		t.Fatalf("PE digest mismatch:\n  got %x\n  spc %x", gotPE, spc.MessageDigest.Digest)
	}

	// Verify the SignerInfo signature against the signed-attrs DER.
	si := sd.SignerInfos[0]
	if !si.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA384) {
		t.Fatalf("signatureAlgorithm = %v, want ecdsa-with-sha384", si.SignatureAlgorithm.Algorithm)
	}
	// Build the SET-form (tag 0x31) of signedAttrs that was signed.
	if len(si.SignedAttrs.FullBytes) == 0 {
		t.Fatal("SignedAttrs empty")
	}
	setForSigning := append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	h := sha512.New384()
	h.Write(setForSigning)
	hashed := h.Sum(nil)
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !ecdsa.VerifyASN1(pub, hashed, si.Signature) {
		t.Fatal("SignerInfo signature failed to verify against signed-attrs hash")
	}

	t.Logf("signed PE %d B; verified self-signed Authenticode end-to-end", len(signed))
}

// TestSignSelfSignedOsslsigncode runs the same self-signed flow and
// then hands the result to osslsigncode verify (with -CAfile pointing
// at our own cert). Skipped when osslsigncode is not installed.
func TestSignSelfSignedOsslsigncode(t *testing.T) {
	if _, err := exec.LookPath("osslsigncode"); err != nil {
		t.Skip("osslsigncode not installed")
	}
	signer := newSelfSignedSigner(t, elliptic.P384(), crypto.SHA384)
	pe := loadHelloPE(t)
	signed, err := Sign(pe, signer, SignOptions{Hash: crypto.SHA384})
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
}

func writePEM(path string, der []byte) error {
	const head = "-----BEGIN CERTIFICATE-----\n"
	const tail = "-----END CERTIFICATE-----\n"
	enc := base64Lines(der)
	return os.WriteFile(path, []byte(head+enc+tail), 0o644)
}

func base64Lines(b []byte) string {
	// inline minimal base64 with 64-col wrapping to avoid an extra import
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for len(b) >= 3 {
		v := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		out = append(out, alphabet[(v>>18)&0x3F], alphabet[(v>>12)&0x3F], alphabet[(v>>6)&0x3F], alphabet[v&0x3F])
		b = b[3:]
	}
	if len(b) == 2 {
		v := uint32(b[0])<<16 | uint32(b[1])<<8
		out = append(out, alphabet[(v>>18)&0x3F], alphabet[(v>>12)&0x3F], alphabet[(v>>6)&0x3F], '=')
	} else if len(b) == 1 {
		v := uint32(b[0]) << 16
		out = append(out, alphabet[(v>>18)&0x3F], alphabet[(v>>12)&0x3F], '=', '=')
	}
	// wrap
	var wrapped []byte
	for i := 0; i < len(out); i += 64 {
		end := i + 64
		if end > len(out) {
			end = len(out)
		}
		wrapped = append(wrapped, out[i:end]...)
		wrapped = append(wrapped, '\n')
	}
	return string(wrapped)
}

func bytesSame(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
