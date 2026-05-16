package authenticode

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeTSA stands up an httptest.Server that decodes the TimeStampReq,
// invokes `inspect` for assertions, and returns the supplied response
// body verbatim. Always returns Content-Type: application/timestamp-reply.
type fakeTSA struct {
	t      *testing.T
	body   []byte // pre-marshaled TimeStampResp
	status int
	hits   int
	last   *timeStampReq
}

func (f *fakeTSA) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.hits++
		if got := r.Header.Get("Content-Type"); got != "application/timestamp-query" {
			f.t.Errorf("Content-Type = %q, want application/timestamp-query", got)
		}
		reqBytes, err := io.ReadAll(r.Body)
		if err != nil {
			f.t.Errorf("read TSA request: %v", err)
		}
		var req timeStampReq
		if _, err := asn1.Unmarshal(reqBytes, &req); err != nil {
			f.t.Errorf("decode TimeStampReq: %v", err)
		}
		f.last = &req
		w.Header().Set("Content-Type", "application/timestamp-reply")
		st := f.status
		if st == 0 {
			st = http.StatusOK
		}
		w.WriteHeader(st)
		_, _ = w.Write(f.body)
	}
}

func buildStubTSAResp(t *testing.T, status int, token []byte) []byte {
	t.Helper()
	if token == nil {
		// empty SEQUENCE — opaque but valid ASN.1.
		token = []byte{0x30, 0x00}
	}
	type resp struct {
		Status         pkiStatusInfo
		TimeStampToken asn1.RawValue `asn1:"optional"`
	}
	out, err := asn1.Marshal(resp{
		Status:         pkiStatusInfo{Status: status},
		TimeStampToken: asn1.RawValue{FullBytes: token},
	})
	if err != nil {
		t.Fatalf("marshal stub resp: %v", err)
	}
	return out
}

// TestRequestTimestamp checks the request shape (imprint length, hash
// alg, nonce > 0, certReq=true) and confirms the returned token bytes
// match the stub.
func TestRequestTimestamp(t *testing.T) {
	const sentinelStr = "FAKE-TIMESTAMP-TOKEN"
	tokenBytes := append([]byte{0x30, byte(len(sentinelStr))}, []byte(sentinelStr)...)
	tsa := &fakeTSA{t: t, body: buildStubTSAResp(t, 0, tokenBytes)}
	srv := httptest.NewServer(tsa.handler())
	defer srv.Close()

	signature := []byte("pretend signature bytes")
	got, err := RequestTimestamp(context.Background(), srv.URL, signature, crypto.SHA256)
	if err != nil {
		t.Fatalf("RequestTimestamp: %v", err)
	}
	if !bytes.Equal(got, tokenBytes) {
		t.Fatalf("token mismatch:\n got %x\n want %x", got, tokenBytes)
	}
	if tsa.hits != 1 {
		t.Fatalf("expected 1 TSA hit, got %d", tsa.hits)
	}
	if !tsa.last.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Fatalf("imprint alg = %v, want SHA-256", tsa.last.MessageImprint.HashAlgorithm.Algorithm)
	}
	want := sha256.Sum256(signature)
	if !bytes.Equal(tsa.last.MessageImprint.HashedMessage, want[:]) {
		t.Fatal("imprint hash mismatch")
	}
	if tsa.last.Nonce == nil || tsa.last.Nonce.Sign() <= 0 {
		t.Fatalf("expected positive nonce, got %v", tsa.last.Nonce)
	}
	if !tsa.last.CertReq {
		t.Error("certReq should be true")
	}
}

func TestRequestTimestampRejectsBadStatus(t *testing.T) {
	tsa := &fakeTSA{t: t, body: buildStubTSAResp(t, 2, nil)}
	srv := httptest.NewServer(tsa.handler())
	defer srv.Close()
	if _, err := RequestTimestamp(context.Background(), srv.URL, []byte{0x01}, crypto.SHA256); err == nil {
		t.Fatal("expected error on PKIStatusInfo status=2")
	}
}

func TestRequestTimestampHTTPError(t *testing.T) {
	tsa := &fakeTSA{t: t, body: []byte("nope"), status: http.StatusInternalServerError}
	srv := httptest.NewServer(tsa.handler())
	defer srv.Close()
	if _, err := RequestTimestamp(context.Background(), srv.URL, []byte{0x01}, crypto.SHA256); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestRequestTimestampUnsupportedHash(t *testing.T) {
	if _, err := RequestTimestamp(context.Background(), "http://example.invalid", []byte{0x01}, crypto.SHA1); err == nil {
		t.Fatal("expected error on unsupported hash")
	}
}

func TestRequestTimestampContextCancel(t *testing.T) {
	// Server that blocks until the test wants it released.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := RequestTimestamp(ctx, srv.URL, []byte{0x01}, crypto.SHA256); err == nil {
		t.Fatal("expected context-deadline error")
	}
}

// TestSignWithTSAEmbedsToken drives a full Sign() with the stub TSA
// URL and asserts the signed PE carries SPC_RFC3161_OBJID
// in the SignerInfo's unsigned attrs.
func TestSignWithTSAEmbedsToken(t *testing.T) {
	const sentinelStr = "STUB-TOKEN-PAYLOAD"
	tokenBytes := append([]byte{0x30, byte(len(sentinelStr))}, []byte(sentinelStr)...)
	tsa := &fakeTSA{t: t, body: buildStubTSAResp(t, 0, tokenBytes)}
	srv := httptest.NewServer(tsa.handler())
	defer srv.Close()

	signer := newSelfSignedSigner(t, elliptic.P256(), crypto.SHA256)
	pe := loadHelloPE(t)
	signed, err := Sign(pe, signer, SignOptions{TSAURL: srv.URL})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if tsa.hits != 1 {
		t.Fatalf("expected stub TSA to be hit once, got %d", tsa.hits)
	}
	si := decodeEmbeddedSignerInfo(t, signed)
	if len(si.UnsignedAttrs.FullBytes) == 0 {
		t.Fatal("UnsignedAttrs missing — timestamp not embedded")
	}
	// Make sure the embedded token bytes are present somewhere in the
	// unsigned-attrs blob.
	if !bytes.Contains(si.UnsignedAttrs.FullBytes, tokenBytes) {
		t.Fatal("token bytes not found in UnsignedAttrs")
	}
	// And that the OID for SPC_RFC3161_OBJID appears.
	oidDER, _ := asn1.Marshal(oidTimestampToken)
	if !bytes.Contains(si.UnsignedAttrs.FullBytes, oidDER) {
		t.Fatal("SPC_RFC3161_OBJID OID missing from UnsignedAttrs")
	}
}
