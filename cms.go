package authenticode

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// SignOptions configures the CMS signing operation.
type SignOptions struct {
	// Hash selects the digest algorithm used for both the
	// SpcIndirectDataContent's messageDigest and the SignerInfo's
	// signed-attrs hash. Defaults to crypto.SHA256.
	Hash crypto.Hash

	// TSAURL, if non-empty, requests an RFC 3161 timestamp from the
	// given Time-Stamp Authority over HTTP and embeds the resulting
	// token under SPC_RFC3161_OBJID (1.3.6.1.4.1.311.3.3.1) in the
	// SignerInfo's unsigned attributes — the OID Authenticode
	// verifiers (signtool, osslsigncode) look up.
	TSAURL string

	// Context governs the TSA HTTP call. Defaults to
	// context.Background().
	Context context.Context

	// SigningTime overrides the PKCS#9 signingTime attribute. Zero
	// (the default) means time.Now() at signing — which is what
	// signtool / osslsigncode do. Set explicitly only for reproducible
	// builds or tests.
	SigningTime time.Time

	// ProgramName and ProgramURL populate the SpcSpOpusInfo signed
	// attribute (signtool's "/d <name>" / "/du <url>"; osslsigncode's
	// "-n <name>" / "-i <url>"). If both are empty the attribute is
	// omitted entirely, matching osslsigncode's behavior — verifiers
	// surface them as the publisher's display name / "more info" link.
	ProgramName string
	ProgramURL  string
}

// contentInfo wraps a CMS payload with a content-type OID. Content is
// pre-wrapped in [0] EXPLICIT bytes by the caller and passed in
// FullBytes — encoding/asn1 emits RawValue.FullBytes verbatim and
// ignores any explicit/tag directive on the field.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

// encapsulatedContentInfo carries the SpcIndirectDataContent inside
// the SignedData. Per Authenticode (and unlike vanilla CMS) the
// eContent is the direct SpcIndirectDataContent SEQUENCE, not wrapped
// in an OCTET STRING. EContent is supplied pre-wrapped in [0] EXPLICIT.
type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue
}

// signedData mirrors RFC 5652 SignedData.
type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"tag:0,implicit,optional"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

// issuerAndSerialNumber is the v1 SignerIdentifier choice.
type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// signerInfo mirrors RFC 5652 SignerInfo (v1).
type signerInfo struct {
	Version            int
	SID                issuerAndSerialNumber
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"tag:0,implicit,optional"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"tag:1,implicit,optional"`
}

// attribute is one entry of SignedAttributes / UnsignedAttributes.
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// BuildSignedData assembles a complete CMS SignedData ContentInfo
// around the supplied SpcIndirectDataContent. The signing key is
// driven through the standard crypto.Signer interface — pass an
// idprime.Signer (or any other implementation) and the resulting
// SignedData carries an ECDSA signature ready for embedding in a PE.
//
// chain must start with the leaf certificate that matches signer's
// public key; subsequent entries (intermediates) are embedded as-is.
//
// If opts.TSAURL is set, an RFC 3161 timestamp is fetched and embedded
// as an unsigned attribute on the SignerInfo.
func BuildSignedData(spc []byte, signer crypto.Signer, chain []*x509.Certificate, opts SignOptions) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("authenticode: cert chain is empty (leaf required)")
	}
	if opts.Hash == 0 {
		opts.Hash = crypto.SHA256
	}
	if opts.Context == nil {
		opts.Context = context.Background()
	}
	leaf := chain[0]
	h := opts.Hash

	hOID, err := hashOID(h)
	if err != nil {
		return nil, err
	}
	sigOID, err := ecdsaWithHashOID(h)
	if err != nil {
		return nil, err
	}

	// messageDigest attribute hashes the *value* bytes of the
	// SpcIndirectDataContent SEQUENCE (i.e. its contents, NOT the
	// outer 30 <len> wrapper) — the Authenticode-specific quirk that
	// keeps CMS' "digest the eContent value" rule meaningful when
	// eContent is a direct SEQUENCE instead of an OCTET STRING.
	spcValue, err := tlvValue(spc)
	if err != nil {
		return nil, fmt.Errorf("parse SpcIndirectDataContent: %w", err)
	}
	hh := h.New()
	hh.Write(spcValue)
	messageDigest := hh.Sum(nil)

	// Signed attributes.
	st := opts.SigningTime
	if st.IsZero() {
		st = time.Now()
	}
	signedAttrs, err := buildSignedAttrs(messageDigest, st.UTC(), opts.ProgramName, opts.ProgramURL)
	if err != nil {
		return nil, err
	}
	// The bytes to be signed: signedAttrs *as a SET* (tag 0x31), not
	// as the IMPLICIT [0] form that ends up in SignerInfo.
	setForSigning := append([]byte{0x31}, signedAttrs[1:]...)
	hh.Reset()
	hh.Write(setForSigning)
	digest := hh.Sum(nil)

	signature, err := signer.Sign(rand.Reader, digest, h)
	if err != nil {
		return nil, fmt.Errorf("token sign: %w", err)
	}

	// Optionally request an RFC 3161 timestamp on the signature.
	var unsignedAttrs asn1.RawValue
	if opts.TSAURL != "" {
		tstToken, err := RequestTimestamp(opts.Context, opts.TSAURL, signature, h)
		if err != nil {
			return nil, fmt.Errorf("rfc3161 timestamp: %w", err)
		}
		ua, err := buildUnsignedAttrsWithTimestamp(tstToken)
		if err != nil {
			return nil, err
		}
		unsignedAttrs = asn1.RawValue{FullBytes: ua}
	}

	// SignerInfo.
	si := signerInfo{
		Version: 1,
		SID: issuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: leaf.RawIssuer},
			SerialNumber: leaf.SerialNumber,
		},
		DigestAlgorithm:    newAlgorithmIDWithNullParams(hOID),
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrs},
		SignatureAlgorithm: newAlgorithmIDNoParams(sigOID),
		Signature:          signature,
		UnsignedAttrs:      unsignedAttrs,
	}

	// Certificate set: concatenated DER cert bytes, wrapped under
	// [0] IMPLICIT.
	var certBytes []byte
	for _, c := range chain {
		certBytes = append(certBytes, c.Raw...)
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{newAlgorithmIDWithNullParams(hOID)},
		EncapContentInfo: encapsulatedContentInfo{
			EContentType: oidSPCIndirectDataContent,
			EContent:     asn1.RawValue{FullBytes: tlv(0xA0, spc)},
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certBytes,
		},
		SignerInfos: []signerInfo{si},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal SignedData: %w", err)
	}
	ci := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{FullBytes: tlv(0xA0, sdDER)},
	}
	return asn1.Marshal(ci)
}

// buildSignedAttrs builds the SignedAttributes SET *as an IMPLICIT [0]
// form* (tag 0xA0). The caller flips the tag to 0x31 to compute the
// hash that gets signed.
func buildSignedAttrs(messageDigest []byte, signingTime time.Time, programName, programURL string) ([]byte, error) {
	// Each attribute's Values is a SET (tag 0x31). encoding/asn1's
	// `asn1:"set"` directive is ignored when we pass FullBytes, so we
	// pre-wrap each value in SET ourselves.
	//
	// contentType attribute → SET { OID SPC_INDIRECT_DATA }
	ctVal, err := asn1.Marshal(oidSPCIndirectDataContent)
	if err != nil {
		return nil, err
	}
	ct := attribute{
		Type:   oidContentType,
		Values: asn1.RawValue{FullBytes: tlv(0x31, ctVal)},
	}
	// messageDigest attribute → SET { OCTET STRING <digest> }
	mdVal, err := asn1.Marshal(messageDigest)
	if err != nil {
		return nil, err
	}
	md := attribute{
		Type:   oidMessageDigest,
		Values: asn1.RawValue{FullBytes: tlv(0x31, mdVal)},
	}
	// signingTime attribute → SET { UTCTime / GeneralizedTime }
	// asn1.Marshal picks UTCTime for years 1950..2049 — which is what
	// signtool / osslsigncode also emit.
	stVal, err := asn1.Marshal(signingTime)
	if err != nil {
		return nil, err
	}
	signingTimeAttr := attribute{
		Type:   oidSigningTime,
		Values: asn1.RawValue{FullBytes: tlv(0x31, stVal)},
	}
	// SpcStatementType → SET { SEQUENCE OF OID { individualCodeSigning } }
	stOIDDER, err := asn1.Marshal(oidSPCIndividualSPKey)
	if err != nil {
		return nil, err
	}
	st := attribute{
		Type:   oidSPCStatementType,
		Values: asn1.RawValue{FullBytes: tlv(0x31, tlv(0x30, stOIDDER))},
	}

	attrs := []attribute{ct, md, signingTimeAttr, st}
	if programName != "" || programURL != "" {
		opusBody, err := buildSpcSpOpusInfo(programName, programURL)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attribute{
			Type:   oidSPCSpOpusInfo,
			Values: asn1.RawValue{FullBytes: tlv(0x31, opusBody)},
		})
	}
	// DER requires SET OF elements to be sorted by their encoded byte
	// representations.
	encoded := make([][]byte, 0, len(attrs))
	for _, a := range attrs {
		b, err := asn1.Marshal(a)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, b)
	}
	sort.Slice(encoded, func(i, j int) bool {
		return bytes.Compare(encoded[i], encoded[j]) < 0
	})
	body := bytes.Join(encoded, nil)
	return tlv(0xA0, body), nil
}

// tlvValue returns the value bytes (skipping the outer tag and length)
// of a single TLV at the start of `der`. Supports definite-length only.
func tlvValue(der []byte) ([]byte, error) {
	if len(der) < 2 {
		return nil, errors.New("truncated TLV")
	}
	off := 2
	l := int(der[1])
	if l&0x80 != 0 {
		nl := l & 0x7F
		// Cap nl at 4 bytes: a single ASN.1 TLV bigger than 4 GiB is
		// nothing we'll ever process here, and refusing keeps the
		// multi-byte length from overflowing int on 32-bit builds.
		if nl == 0 || nl > 4 || 2+nl > len(der) {
			return nil, errors.New("bad long-form length")
		}
		l = 0
		for i := 0; i < nl; i++ {
			l = (l << 8) | int(der[2+i])
		}
		off = 2 + nl
	}
	if l < 0 || off+l > len(der) {
		return nil, errors.New("truncated TLV body")
	}
	return der[off : off+l], nil
}
