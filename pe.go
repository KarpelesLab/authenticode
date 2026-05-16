// Package authenticode implements Microsoft Authenticode PE signing in
// pure Go. It computes the Authenticode digest, builds the CMS
// SignedData (with SpcIndirectDataContent), embeds an RFC3161 timestamp,
// and writes the resulting WIN_CERTIFICATE into the PE's attribute
// certificate table. It signs through any crypto.Signer (e.g. the
// github.com/KarpelesLab/hsm IDPrime backend driving a USB token).
package authenticode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
)

// PE represents a parsed PE32 / PE32+ image and remembers the offsets
// the Authenticode hash algorithm needs to skip.
type PE struct {
	raw                []byte
	is64               bool
	checksumOff        int // 4 bytes
	certDirEntryOff    int // 8 bytes (VirtualAddress + Size of attribute certificate table)
	certTableVA        uint32
	certTableSize      uint32
	sizeOfHeaders      uint32
	numSections        uint16
	sectionTableOffset int
}

// Parse parses a PE32 or PE32+ image and locates the offsets used by
// Authenticode hashing. Does not modify the input slice.
func Parse(raw []byte) (*PE, error) {
	if len(raw) < 64 {
		return nil, errors.New("authenticode: too small to be a PE")
	}
	if raw[0] != 'M' || raw[1] != 'Z' {
		return nil, errors.New("authenticode: missing MZ header")
	}
	lfanew := int(binary.LittleEndian.Uint32(raw[60:64]))
	if lfanew < 0 || lfanew+24 > len(raw) {
		return nil, fmt.Errorf("authenticode: bad e_lfanew %d", lfanew)
	}
	if !bytesEqual(raw[lfanew:lfanew+4], []byte{'P', 'E', 0, 0}) {
		return nil, errors.New("authenticode: missing PE signature")
	}
	coff := lfanew + 4
	if coff+20 > len(raw) {
		return nil, errors.New("authenticode: truncated COFF header")
	}
	numSections := binary.LittleEndian.Uint16(raw[coff+2 : coff+4])
	optHdrSize := int(binary.LittleEndian.Uint16(raw[coff+16 : coff+18]))
	optHdr := coff + 20
	if optHdr+optHdrSize > len(raw) {
		return nil, errors.New("authenticode: truncated optional header")
	}
	if optHdrSize < 96 {
		return nil, fmt.Errorf("authenticode: optional header too small (%d)", optHdrSize)
	}
	magic := binary.LittleEndian.Uint16(raw[optHdr : optHdr+2])
	pe := &PE{
		raw:                raw,
		checksumOff:        optHdr + 64,
		numSections:        numSections,
		sectionTableOffset: optHdr + optHdrSize,
	}
	var dataDirOff int
	switch magic {
	case 0x10B: // PE32
		dataDirOff = optHdr + 96
		pe.sizeOfHeaders = binary.LittleEndian.Uint32(raw[optHdr+60 : optHdr+64])
	case 0x20B: // PE32+
		pe.is64 = true
		dataDirOff = optHdr + 112
		pe.sizeOfHeaders = binary.LittleEndian.Uint32(raw[optHdr+60 : optHdr+64])
	default:
		return nil, fmt.Errorf("authenticode: unknown optional header magic 0x%X", magic)
	}
	// Data directory entry 4 is the Attribute Certificate Table.
	pe.certDirEntryOff = dataDirOff + 4*8
	if pe.certDirEntryOff+8 > len(raw) {
		return nil, errors.New("authenticode: cert dir entry past EOF")
	}
	pe.certTableVA = binary.LittleEndian.Uint32(raw[pe.certDirEntryOff : pe.certDirEntryOff+4])
	pe.certTableSize = binary.LittleEndian.Uint32(raw[pe.certDirEntryOff+4 : pe.certDirEntryOff+8])
	return pe, nil
}

// AuthenticodeDigest computes the Microsoft Authenticode hash over the
// PE image, omitting the four-byte file checksum, the eight-byte
// attribute-certificate-table data-directory entry, and any existing
// attribute certificate table contents.
func (p *PE) AuthenticodeDigest(h hash.Hash) []byte {
	// Hash from start of file up to (but not including) the checksum.
	h.Write(p.raw[:p.checksumOff])
	// Skip 4 bytes (checksum).
	// Continue from after checksum to start of cert-table dir entry.
	h.Write(p.raw[p.checksumOff+4 : p.certDirEntryOff])
	// Skip 8 bytes (cert table dir entry: VA + Size).
	// Continue from after cert-dir entry to end of headers.
	end := int(p.sizeOfHeaders)
	if end > len(p.raw) {
		end = len(p.raw)
	}
	h.Write(p.raw[p.certDirEntryOff+8 : end])

	// Hash each section in order of file offset (per MS spec).
	type secRange struct {
		off, size int
	}
	secs := make([]secRange, 0, p.numSections)
	for i := 0; i < int(p.numSections); i++ {
		sh := p.sectionTableOffset + i*40
		if sh+40 > len(p.raw) {
			break
		}
		size := int(binary.LittleEndian.Uint32(p.raw[sh+16 : sh+20])) // SizeOfRawData
		off := int(binary.LittleEndian.Uint32(p.raw[sh+20 : sh+24]))  // PointerToRawData
		if size == 0 || off == 0 {
			continue
		}
		secs = append(secs, secRange{off, size})
	}
	sort.Slice(secs, func(i, j int) bool { return secs[i].off < secs[j].off })
	tailEnd := int(p.sizeOfHeaders)
	for _, s := range secs {
		if s.off+s.size > len(p.raw) {
			h.Write(p.raw[s.off:])
			tailEnd = len(p.raw)
			continue
		}
		h.Write(p.raw[s.off : s.off+s.size])
		if s.off+s.size > tailEnd {
			tailEnd = s.off + s.size
		}
	}
	// Hash any trailing bytes outside the section table and outside the
	// existing attribute certificate table (if any).
	if p.certTableVA > 0 && p.certTableSize > 0 {
		// Trailing bytes split into [tailEnd .. certTableVA) and
		// [certTableVA+certTableSize .. EOF).
		ctStart := int(p.certTableVA)
		ctEnd := ctStart + int(p.certTableSize)
		if ctStart > tailEnd && ctStart <= len(p.raw) {
			h.Write(p.raw[tailEnd:ctStart])
		}
		if ctEnd < len(p.raw) {
			h.Write(p.raw[ctEnd:])
		}
	} else if tailEnd < len(p.raw) {
		h.Write(p.raw[tailEnd:])
	}
	// The WIN_CERTIFICATE table is 8-byte aligned; zero bytes
	// inserted between the end of the image and the cert table count
	// toward the Authenticode hash. Hash that padding here so the
	// digest is invariant under signing — computing the digest before
	// embedding equals computing it after.
	imgEnd := len(p.raw)
	if p.certTableVA > 0 && p.certTableSize > 0 {
		imgEnd = int(p.certTableVA)
	}
	for imgEnd%8 != 0 {
		h.Write([]byte{0})
		imgEnd++
	}
	return h.Sum(nil)
}

// EmbedSignature returns a copy of the PE with the given CMS
// SignedData blob embedded as a WIN_CERTIFICATE in a new attribute
// certificate table appended to the file. The data-directory entry is
// updated accordingly.
//
// Any pre-existing attribute certificate table is replaced.
func (p *PE) EmbedSignature(cms []byte) []byte {
	// Strip any existing certificate table from the source bytes.
	src := p.raw
	if p.certTableVA > 0 && p.certTableSize > 0 {
		ctStart := int(p.certTableVA)
		ctEnd := ctStart + int(p.certTableSize)
		if ctEnd <= len(src) {
			tmp := make([]byte, 0, len(src)-int(p.certTableSize))
			tmp = append(tmp, src[:ctStart]...)
			tmp = append(tmp, src[ctEnd:]...)
			src = tmp
		}
	}
	out := make([]byte, len(src), len(src)+len(cms)+24)
	copy(out, src)

	// Pad to 8-byte boundary before the WIN_CERTIFICATE.
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	winCertOffset := len(out)

	// WIN_CERTIFICATE header (8 bytes), then PKCS#7 blob padded to 8.
	padded := len(cms)
	for padded%8 != 0 {
		padded++
	}
	dwLength := uint32(8 + padded)

	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(hdr[0:4], dwLength)
	binary.LittleEndian.PutUint16(hdr[4:6], 0x0200) // WIN_CERT_REVISION_2_0
	binary.LittleEndian.PutUint16(hdr[6:8], 0x0002) // WIN_CERT_TYPE_PKCS_SIGNED_DATA
	out = append(out, hdr...)
	out = append(out, cms...)
	for i := len(cms); i < padded; i++ {
		out = append(out, 0)
	}

	// Update the cert-table data directory entry in place.
	binary.LittleEndian.PutUint32(out[p.certDirEntryOff:p.certDirEntryOff+4], uint32(winCertOffset))
	binary.LittleEndian.PutUint32(out[p.certDirEntryOff+4:p.certDirEntryOff+8], dwLength)
	return out
}

func bytesEqual(a, b []byte) bool {
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
