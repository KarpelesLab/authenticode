package authenticode

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

// id-ct-TSTInfo (RFC 3161). Used inside TimeStampToken.
var oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     asn1.RawValue         `asn1:"tag:0,implicit,optional"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.RawValue `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// RequestTimestamp asks an RFC 3161 Time-Stamp Authority to timestamp
// the given signature bytes. It returns the raw TimeStampToken (a CMS
// ContentInfo) ready for embedding as the value of the
// SPC_RFC3161_OBJID (1.3.6.1.4.1.311.3.3.1) unsigned attribute on a
// SignerInfo — the Microsoft-Authenticode-specific carrier that
// signtool / osslsigncode actually parse.
//
// The TSA URL must accept POSTs with Content-Type
// application/timestamp-query (the standard).
func RequestTimestamp(ctx context.Context, tsaURL string, signature []byte, h crypto.Hash) ([]byte, error) {
	hOID, err := hashOID(h)
	if err != nil {
		return nil, err
	}
	hh := h.New()
	hh.Write(signature)
	imprint := hh.Sum(nil)

	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, err
	}

	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: newAlgorithmIDWithNullParams(hOID),
			HashedMessage: imprint,
		},
		Nonce:   nonce,
		CertReq: true,
	}
	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal TimeStampReq: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tsaURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("TSA POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("TSA %s: HTTP %d: %s", tsaURL, resp.StatusCode, body)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tsr timeStampResp
	if _, err := asn1.Unmarshal(respBody, &tsr); err != nil {
		return nil, fmt.Errorf("parse TimeStampResp: %w", err)
	}
	if tsr.Status.Status != 0 && tsr.Status.Status != 1 {
		return nil, fmt.Errorf("TSA refused with status %d", tsr.Status.Status)
	}
	if len(tsr.TimeStampToken.FullBytes) == 0 {
		return nil, errors.New("TSA returned no timestamp token")
	}
	return tsr.TimeStampToken.FullBytes, nil
}

// buildUnsignedAttrsWithTimestamp wraps an RFC 3161 TimeStampToken
// inside Microsoft's SPC_RFC3161_OBJID unsigned attribute, IMPLICIT
// [1]-tagged so it can drop into SignerInfo.UnsignedAttrs.
func buildUnsignedAttrsWithTimestamp(tstToken []byte) ([]byte, error) {
	attr := attribute{
		Type:   oidTimestampToken,
		Values: asn1.RawValue{FullBytes: tlv(0x31, tstToken)},
	}
	attrDER, err := asn1.Marshal(attr)
	if err != nil {
		return nil, err
	}
	return tlv(0xA1, attrDER), nil
}
