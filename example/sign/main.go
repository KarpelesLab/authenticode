// Command sign drives a full Authenticode signing pipeline using
// github.com/KarpelesLab/hsm (for the on-token key + cert chain) and
// the parent authenticode package (for PE + CMS + RFC 3161
// timestamping).
//
// Configuration via environment variables (HSM=idprime by default):
//
//	HSM, IDPRIME_PIN, IDPRIME_READER, …  -- token / backend selection
//	AC_TSA  http://timestamp.digicert.com -- optional RFC 3161 URL
//	AC_HASH sha256|sha384|sha512          -- default: sha384
//
// Usage:
//
//	example/sign <input.exe> <output.exe>
package main

import (
	"crypto"
	"log"
	"os"

	"github.com/KarpelesLab/authenticode"
	"github.com/KarpelesLab/hsm"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("sign: ")
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s <input.exe> <output.exe>", os.Args[0])
	}
	inPath, outPath := os.Args[1], os.Args[2]

	if os.Getenv("HSM") == "" {
		os.Setenv("HSM", "idprime")
	}
	h, err := hsm.New()
	if err != nil {
		log.Fatalf("hsm: %v", err)
	}
	keys, err := h.ListKeys()
	if err != nil {
		log.Fatalf("ListKeys: %v", err)
	}
	if len(keys) == 0 {
		log.Fatal("no keys available on the token")
	}
	key := keys[0]
	log.Printf("using key: %s", key)

	signer, ok := key.(authenticode.Signer)
	if !ok {
		log.Fatalf("hsm key does not implement authenticode.Signer")
	}

	in, err := os.ReadFile(inPath)
	if err != nil {
		log.Fatalf("read %s: %v", inPath, err)
	}

	opts := authenticode.SignOptions{
		Hash:   parseHash(os.Getenv("AC_HASH")),
		TSAURL: os.Getenv("AC_TSA"),
	}
	signed, err := authenticode.Sign(in, signer, opts)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	if err := os.WriteFile(outPath, signed, 0o644); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
	log.Printf("signed: %s (%d -> %d bytes)", outPath, len(in), len(signed))
}

func parseHash(s string) crypto.Hash {
	switch s {
	case "", "sha384":
		return crypto.SHA384
	case "sha256":
		return crypto.SHA256
	case "sha512":
		return crypto.SHA512
	}
	log.Fatalf("unknown hash %q", s)
	return 0
}
