package authenticode

import (
	"crypto"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
)

// Authenticode and CMS object identifiers used by Microsoft's
// SpcIndirectDataContent and related signed-attribute machinery.
var (
	oidSPCIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}  // id-spcIndirectDataContent
	oidSPCPEImageDataObj      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15} // SPC_PE_IMAGE_DATAOBJ
	oidSPCSpOpusInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidSPCStatementType       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	oidSPCIndividualSPKey     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}

	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2} // id-signedData
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// Microsoft's Authenticode-specific OID for an RFC 3161 counter
	// signature carried as a SignerInfo unsigned attribute. The
	// CMS-standard id-smime-aa-timeStampToken (1.2.840.113549.1.9.16.2.14)
	// is *not* what Authenticode verifiers (signtool, osslsigncode) look
	// for; they want SPC_RFC3161_OBJID below.
	oidTimestampToken = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}

	// ECDSA signature algorithm OIDs (the with-SHA-* form embeds the
	// hash; we pick the right one based on the digest used).
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// hashOID returns the OID for an Authenticode-supported digest hash.
func hashOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return oidSHA256, nil
	case crypto.SHA384:
		return oidSHA384, nil
	case crypto.SHA512:
		return oidSHA512, nil
	}
	return nil, fmt.Errorf("authenticode: unsupported hash %v", h)
}

// ecdsaWithHashOID returns the ecdsa-with-* signature OID matching h.
func ecdsaWithHashOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return oidECDSAWithSHA256, nil
	case crypto.SHA384:
		return oidECDSAWithSHA384, nil
	case crypto.SHA512:
		return oidECDSAWithSHA512, nil
	}
	return nil, fmt.Errorf("authenticode: unsupported hash %v", h)
}

// algorithmIdentifier with parameters: NULL (the customary form for
// SHA-* in DigestInfo / SignerInfo.digestAlgorithm).
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func newAlgorithmIDWithNullParams(oid asn1.ObjectIdentifier) algorithmIdentifier {
	return algorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{Tag: asn1.TagNull, FullBytes: []byte{0x05, 0x00}},
	}
}

func newAlgorithmIDNoParams(oid asn1.ObjectIdentifier) algorithmIdentifier {
	return algorithmIdentifier{Algorithm: oid}
}

// digestInfo as used inside SpcIndirectDataContent.
type digestInfo struct {
	DigestAlgorithm algorithmIdentifier
	Digest          []byte
}

// spcIndirectDataContent SEQUENCE { data, messageDigest }.
type spcIndirectDataContent struct {
	Data          spcAttributeTypeAndOptionalValue
	MessageDigest digestInfo
}

// spcAttributeTypeAndOptionalValue SEQUENCE { type OID, value ANY }
// — value carried as a RawValue so we can plug in SpcPeImageData
// without exposing its concrete Go type to encoding/asn1's matcher.
type spcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// BuildSpcIndirectDataContent builds the SpcIndirectDataContent
// payload that goes into the eContent field of the signed CMS
// ContentInfo. peDigest is the Authenticode digest of the PE image
// (the bytes produced by PE.AuthenticodeDigest), and h is the hash
// algorithm used to compute it.
func BuildSpcIndirectDataContent(peDigest []byte, h crypto.Hash) ([]byte, error) {
	if len(peDigest) != h.Size() {
		return nil, fmt.Errorf("authenticode: digest length %d != hash size %d", len(peDigest), h.Size())
	}
	hOID, err := hashOID(h)
	if err != nil {
		return nil, err
	}
	peImageData, err := buildSpcPeImageData()
	if err != nil {
		return nil, err
	}
	spc := spcIndirectDataContent{
		Data: spcAttributeTypeAndOptionalValue{
			Type:  oidSPCPEImageDataObj,
			Value: asn1.RawValue{FullBytes: peImageData},
		},
		MessageDigest: digestInfo{
			DigestAlgorithm: newAlgorithmIDWithNullParams(hOID),
			Digest:          peDigest,
		},
	}
	return asn1.Marshal(spc)
}

// buildSpcPeImageData manually constructs the SpcPeImageData
// SEQUENCE. encoding/asn1 does not produce the BIT STRING / nested
// [n] EXPLICIT/IMPLICIT shape Authenticode requires, so we emit the
// bytes directly:
//
//	SEQUENCE {
//	    BIT STRING 0 unused bits, 0 content bits,                   -- 03 01 00
//	    [0] EXPLICIT {
//	        [2] EXPLICIT {
//	            [0] IMPLICIT BMPString "<<<Obsolete>>>"              -- UTF-16BE
//	        }
//	    }
//	}
func buildSpcPeImageData() ([]byte, error) {
	const obsolete = "<<<Obsolete>>>"
	// BMPString = UCS-2 big-endian.
	bmp := make([]byte, 2*len(obsolete))
	for i, r := range []rune(obsolete) {
		if r > 0xFFFF {
			return nil, errors.New("authenticode: rune outside BMP")
		}
		binary.BigEndian.PutUint16(bmp[2*i:], uint16(r))
	}
	// [0] IMPLICIT BMPString => tag 0x80, definite-length, content = bmp.
	bmpInner := tlv(0x80, bmp)
	// [2] EXPLICIT { bmpInner }.
	spcLink := tlv(0xA2, bmpInner)
	// [0] EXPLICIT { spcLink }.
	fileWrap := tlv(0xA0, spcLink)
	// Flags: BIT STRING with 0 unused bits, 0 content bits.
	flags := []byte{0x03, 0x01, 0x00}
	body := append([]byte{}, flags...)
	body = append(body, fileWrap...)
	return tlv(0x30, body), nil
}

// tlv emits an ASN.1 type-length-value triple with a definite,
// minimal-length encoding (short form when len < 128, otherwise long
// form with the smallest number of length bytes).
func tlv(tag byte, value []byte) []byte {
	n := len(value)
	switch {
	case n < 0x80:
		out := make([]byte, 0, 2+n)
		return append(append(out, tag, byte(n)), value...)
	case n <= 0xFF:
		out := make([]byte, 0, 3+n)
		return append(append(out, tag, 0x81, byte(n)), value...)
	case n <= 0xFFFF:
		out := make([]byte, 0, 4+n)
		return append(append(out, tag, 0x82, byte(n>>8), byte(n)), value...)
	case n <= 0xFFFFFF:
		out := make([]byte, 0, 5+n)
		return append(append(out, tag, 0x83, byte(n>>16), byte(n>>8), byte(n)), value...)
	default:
		out := make([]byte, 0, 6+n)
		return append(append(out, tag, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n)), value...)
	}
}
