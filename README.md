# authenticode

[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/authenticode.svg)](https://pkg.go.dev/github.com/KarpelesLab/authenticode)
[![CI](https://github.com/KarpelesLab/authenticode/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/authenticode/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/authenticode/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/authenticode?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/KarpelesLab/authenticode)](https://goreportcard.com/report/github.com/KarpelesLab/authenticode)

Pure-Go [Microsoft Authenticode](https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools) signing for Windows PE (`.exe` / `.dll`) files. No CGO, no `osslsigncode` shell-out, no PKCS#11 engine — just `encoding/asn1` and the standard `crypto.Signer` interface.

## What it does

- Parses PE32 / PE32+ images and computes the Authenticode digest (skipping the file checksum, the attribute-certificate data directory entry, and the existing attribute certificate table, per Microsoft's spec).
- Builds the `SpcIndirectDataContent` structure and the CMS `SignedData` ContentInfo with the four Authenticode-required signed attributes (`contentType`, `messageDigest`, `SpcSpOpusInfo`, `SpcStatementType`).
- Optionally requests an RFC 3161 timestamp from any `Content-Type: application/timestamp-query` TSA and embeds it under `id-smime-aa-timeStampToken`.
- Wraps the result in a `WIN_CERTIFICATE` and writes it into a new attribute certificate table on the PE.

Verified end-to-end with `osslsigncode verify` (DigiCert-issued code-signing chain, ECDSA P-384 / SHA-384).

## Usage

```go
import "github.com/KarpelesLab/authenticode"

// signer is anything implementing authenticode.Signer:
//   crypto.Signer + Certificate() *x509.Certificate + CertificateChain() []*x509.Certificate
// (github.com/KarpelesLab/hsm Key satisfies it directly.)
signed, err := authenticode.Sign(peBytes, signer, authenticode.SignOptions{
    Hash:   crypto.SHA384,
    TSAURL: "http://timestamp.digicert.com",
})
```

`SignWithChain` is the lower-level form that accepts a raw `crypto.Signer` and an explicit chain.

## Status

- ECDSA leaf certs only (P-256, P-384, P-521); RSA leaf support and richer compatibility tests are open follow-ups.

## License

MIT — see [`LICENSE`](LICENSE).
