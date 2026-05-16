package authenticode

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
)

// Signer is a signing key bundled with the certificate (and the rest
// of the chain) that asserts its public key. hsm.Key from
// github.com/KarpelesLab/hsm v0.2.5+ satisfies it directly — an
// IDPrime smart-card key plugs in without conversion.
//
// CertificateChain must return the chain leaf-first; intermediates
// and (optionally) the root follow. When the slice is empty Sign
// falls back to Certificate() and signs with a single-element chain.
type Signer interface {
	crypto.Signer
	Certificate() *x509.Certificate
	CertificateChain() []*x509.Certificate
}

// Sign produces a Microsoft Authenticode signature over the given PE
// image, embeds it as a WIN_CERTIFICATE in the file, and returns the
// new bytes. The signing key + cert chain are supplied through
// Signer. If opts.TSAURL is set, an RFC 3161 timestamp from that
// authority is fetched and embedded in the SignerInfo's unsigned
// attributes.
//
// The input slice is not modified.
func Sign(pe []byte, signer Signer, opts SignOptions) ([]byte, error) {
	chain := signer.CertificateChain()
	if len(chain) == 0 {
		leaf := signer.Certificate()
		if leaf == nil {
			return nil, errors.New("authenticode: signer has neither certificate nor chain")
		}
		chain = []*x509.Certificate{leaf}
	}
	return SignWithChain(pe, signer, chain, opts)
}

// SignWithChain is the lower-level entry point: pass a raw
// crypto.Signer plus the certificate chain explicitly (leaf first).
// Useful when the chain comes from somewhere other than the Signer.
func SignWithChain(pe []byte, signer crypto.Signer, chain []*x509.Certificate, opts SignOptions) ([]byte, error) {
	if opts.Hash == 0 {
		opts.Hash = crypto.SHA256
	}
	p, err := Parse(pe)
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}
	peDigest := p.AuthenticodeDigest(opts.Hash.New())
	spc, err := BuildSpcIndirectDataContent(peDigest, opts.Hash)
	if err != nil {
		return nil, fmt.Errorf("build SpcIndirectDataContent: %w", err)
	}
	cms, err := BuildSignedData(spc, signer, chain, opts)
	if err != nil {
		return nil, fmt.Errorf("build SignedData: %w", err)
	}
	return p.EmbedSignature(cms), nil
}
