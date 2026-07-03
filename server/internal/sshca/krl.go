package sshca

import (
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file implements the OpenSSH Key Revocation List (KRL) binary format,
// specified in OpenSSH's PROTOCOL.krl. A KRL is the artifact sshd consumes via
// its RevokedKeys option, so certificates revoked here stop authenticating on
// every host that fetches the list. Only the writer and the sections this CA
// emits are implemented: one KRL_SECTION_CERTIFICATES bound to the issuing CA's
// public key, revoking by certificate serial and by key ID. The parser exists
// so tests and operators can round-trip a generated KRL without ssh-keygen.
//
// The format is hand-rolled — like the attestation CBOR and OCSP-nonce ASN.1 —
// because x/crypto/ssh has no KRL support and pulling a dependency for ~200
// lines of length-prefixed wire encoding is not worth it.

// KRL header magic: "SSHKRL\n\0" as a big-endian uint64.
const krlMagic = 0x5353484b524c0a00

// KRL format version (PROTOCOL.krl section 1).
const krlFormatVersion = 1

// Top-level KRL section types.
const (
	krlSectionCertificates      = 1
	krlSectionExplicitKey       = 2
	krlSectionFingerprintSHA1   = 3
	krlSectionSignature         = 4 // deprecated in OpenSSH; never emitted
	krlSectionFingerprintSHA256 = 5
	krlSectionExtension         = 255
)

// Sub-section types within a KRL_SECTION_CERTIFICATES section.
const (
	krlCertSectionSerialList   = 0x20
	krlCertSectionSerialRange  = 0x21
	krlCertSectionSerialBitmap = 0x22
	krlCertSectionKeyID        = 0x23
)

// KRLContent is the material a generated KRL revokes for one certificate
// authority.
type KRLContent struct {
	// Version is the KRL's monotonically increasing version number.
	Version uint64
	// GeneratedAt is stamped into the header as the generation time.
	GeneratedAt time.Time
	// Comment is an optional human-readable note carried in the header.
	Comment string
	// CAKey is the issuing CA's public key; the certificate section is bound to
	// it so the revoked serials cannot collide with another CA's serial space.
	CAKey ssh.PublicKey
	// Serials are the revoked certificate serials.
	Serials []uint64
	// KeyIDs are the revoked certificate key IDs (revoking every certificate
	// issued for that identity under this CA).
	KeyIDs []string
}

// MarshalKRL encodes the content as an OpenSSH KRL blob.
func MarshalKRL(c *KRLContent) ([]byte, error) {
	if c.CAKey == nil {
		return nil, fmt.Errorf("krl: a CA public key is required to scope certificate revocations")
	}

	var out []byte
	out = appendKRLUint64(out, krlMagic)
	out = appendKRLUint32(out, krlFormatVersion)
	out = appendKRLUint64(out, c.Version)
	out = appendKRLUint64(out, uint64(c.GeneratedAt.Unix()))
	out = appendKRLUint64(out, 0) // flags: none defined
	out = appendKRLString(out, nil)
	out = appendKRLString(out, []byte(c.Comment))

	if len(c.Serials) == 0 && len(c.KeyIDs) == 0 {
		// An empty KRL (header only) is valid and revokes nothing; ssh-keygen
		// produces the same for an empty revocation spec.
		return out, nil
	}

	// One certificates section scoped to the CA key.
	var sect []byte
	sect = appendKRLString(sect, c.CAKey.Marshal())
	sect = appendKRLString(sect, nil) // reserved

	if len(c.Serials) > 0 {
		serials := append([]uint64(nil), c.Serials...)
		sort.Slice(serials, func(i, j int) bool { return serials[i] < serials[j] })
		var list []byte
		prev := uint64(0)
		for i, s := range serials {
			if i > 0 && s == prev {
				continue // dedupe
			}
			prev = s
			list = appendKRLUint64(list, s)
		}
		sect = append(sect, krlCertSectionSerialList)
		sect = appendKRLString(sect, list)
	}

	if len(c.KeyIDs) > 0 {
		keyIDs := append([]string(nil), c.KeyIDs...)
		sort.Strings(keyIDs)
		var list []byte
		prev := ""
		for i, id := range keyIDs {
			if i > 0 && id == prev {
				continue // dedupe
			}
			prev = id
			list = appendKRLString(list, []byte(id))
		}
		sect = append(sect, krlCertSectionKeyID)
		sect = appendKRLString(sect, list)
	}

	out = append(out, krlSectionCertificates)
	out = appendKRLString(out, sect)
	return out, nil
}

// KRLCertificateSection is one parsed KRL_SECTION_CERTIFICATES section.
type KRLCertificateSection struct {
	// CAKey is the CA public key the section is bound to; nil means the section
	// applies to certificates from any CA.
	CAKey   ssh.PublicKey
	Serials []uint64
	// SerialRanges holds [min,max] inclusive pairs from serial-range sections.
	SerialRanges [][2]uint64
	KeyIDs       []string
}

// ParsedKRL is the decoded form of a KRL blob, exposing the sections this
// package understands (certificate revocations). Explicit-key and fingerprint
// sections are tolerated but not interpreted.
type ParsedKRL struct {
	Version      uint64
	GeneratedAt  time.Time
	Comment      string
	Certificates []KRLCertificateSection
}

// IsSerialRevoked reports whether the KRL revokes the given certificate serial
// under the given CA key (sections bound to no CA key match any CA).
func (k *ParsedKRL) IsSerialRevoked(caKey ssh.PublicKey, serial uint64) bool {
	for _, sect := range k.Certificates {
		if !sect.matchesCA(caKey) {
			continue
		}
		for _, s := range sect.Serials {
			if s == serial {
				return true
			}
		}
		for _, r := range sect.SerialRanges {
			if serial >= r[0] && serial <= r[1] {
				return true
			}
		}
	}
	return false
}

// IsKeyIDRevoked reports whether the KRL revokes the given certificate key ID
// under the given CA key.
func (k *ParsedKRL) IsKeyIDRevoked(caKey ssh.PublicKey, keyID string) bool {
	for _, sect := range k.Certificates {
		if !sect.matchesCA(caKey) {
			continue
		}
		for _, id := range sect.KeyIDs {
			if id == keyID {
				return true
			}
		}
	}
	return false
}

func (s *KRLCertificateSection) matchesCA(caKey ssh.PublicKey) bool {
	if s.CAKey == nil {
		return true
	}
	return caKey != nil && string(s.CAKey.Marshal()) == string(caKey.Marshal())
}

// ParseKRL decodes a KRL blob.
func ParseKRL(data []byte) (*ParsedKRL, error) {
	r := krlReader{buf: data}
	magic, err := r.uint64()
	if err != nil || magic != krlMagic {
		return nil, fmt.Errorf("krl: bad magic (not a KRL)")
	}
	version, err := r.uint32()
	if err != nil {
		return nil, fmt.Errorf("krl: truncated header")
	}
	if version != krlFormatVersion {
		return nil, fmt.Errorf("krl: unsupported format version %d", version)
	}
	out := &ParsedKRL{}
	if out.Version, err = r.uint64(); err != nil {
		return nil, fmt.Errorf("krl: truncated header")
	}
	generated, err := r.uint64()
	if err != nil {
		return nil, fmt.Errorf("krl: truncated header")
	}
	out.GeneratedAt = time.Unix(int64(generated), 0).UTC()
	if _, err = r.uint64(); err != nil { // flags
		return nil, fmt.Errorf("krl: truncated header")
	}
	if _, err = r.bytes(); err != nil { // reserved
		return nil, fmt.Errorf("krl: truncated header")
	}
	comment, err := r.bytes()
	if err != nil {
		return nil, fmt.Errorf("krl: truncated header")
	}
	out.Comment = string(comment)

	for !r.empty() {
		sectionType, err := r.byte()
		if err != nil {
			return nil, fmt.Errorf("krl: truncated section")
		}
		sectionData, err := r.bytes()
		if err != nil {
			return nil, fmt.Errorf("krl: truncated section")
		}
		switch sectionType {
		case krlSectionCertificates:
			sect, err := parseKRLCertSection(sectionData)
			if err != nil {
				return nil, err
			}
			out.Certificates = append(out.Certificates, *sect)
		case krlSectionExplicitKey, krlSectionFingerprintSHA1,
			krlSectionFingerprintSHA256, krlSectionSignature, krlSectionExtension:
			// Recognized but not interpreted by this CA.
		default:
			return nil, fmt.Errorf("krl: unknown section type %d", sectionType)
		}
	}
	return out, nil
}

func parseKRLCertSection(data []byte) (*KRLCertificateSection, error) {
	r := krlReader{buf: data}
	caBlob, err := r.bytes()
	if err != nil {
		return nil, fmt.Errorf("krl: truncated certificates section")
	}
	if _, err := r.bytes(); err != nil { // reserved
		return nil, fmt.Errorf("krl: truncated certificates section")
	}
	sect := &KRLCertificateSection{}
	if len(caBlob) > 0 {
		key, err := ssh.ParsePublicKey(caBlob)
		if err != nil {
			return nil, fmt.Errorf("krl: invalid CA key in certificates section: %v", err)
		}
		sect.CAKey = key
	}
	for !r.empty() {
		subType, err := r.byte()
		if err != nil {
			return nil, fmt.Errorf("krl: truncated certificate sub-section")
		}
		subData, err := r.bytes()
		if err != nil {
			return nil, fmt.Errorf("krl: truncated certificate sub-section")
		}
		sub := krlReader{buf: subData}
		switch subType {
		case krlCertSectionSerialList:
			for !sub.empty() {
				serial, err := sub.uint64()
				if err != nil {
					return nil, fmt.Errorf("krl: truncated serial list")
				}
				sect.Serials = append(sect.Serials, serial)
			}
		case krlCertSectionSerialRange:
			lo, err := sub.uint64()
			if err != nil {
				return nil, fmt.Errorf("krl: truncated serial range")
			}
			hi, err := sub.uint64()
			if err != nil {
				return nil, fmt.Errorf("krl: truncated serial range")
			}
			sect.SerialRanges = append(sect.SerialRanges, [2]uint64{lo, hi})
		case krlCertSectionKeyID:
			for !sub.empty() {
				id, err := sub.bytes()
				if err != nil {
					return nil, fmt.Errorf("krl: truncated key-id list")
				}
				sect.KeyIDs = append(sect.KeyIDs, string(id))
			}
		case krlCertSectionSerialBitmap:
			// Not emitted by this CA; tolerated (skipped) when reading foreign KRLs.
		default:
			return nil, fmt.Errorf("krl: unknown certificate sub-section type %#x", subType)
		}
	}
	return sect, nil
}

// --- wire-format primitives (SSH-style length-prefixed encoding) ------------

func appendKRLUint32(b []byte, v uint32) []byte {
	return binary.BigEndian.AppendUint32(b, v)
}

func appendKRLUint64(b []byte, v uint64) []byte {
	return binary.BigEndian.AppendUint64(b, v)
}

func appendKRLString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

type krlReader struct {
	buf []byte
}

func (r *krlReader) empty() bool { return len(r.buf) == 0 }

func (r *krlReader) byte() (byte, error) {
	if len(r.buf) < 1 {
		return 0, fmt.Errorf("short read")
	}
	v := r.buf[0]
	r.buf = r.buf[1:]
	return v, nil
}

func (r *krlReader) uint32() (uint32, error) {
	if len(r.buf) < 4 {
		return 0, fmt.Errorf("short read")
	}
	v := binary.BigEndian.Uint32(r.buf)
	r.buf = r.buf[4:]
	return v, nil
}

func (r *krlReader) uint64() (uint64, error) {
	if len(r.buf) < 8 {
		return 0, fmt.Errorf("short read")
	}
	v := binary.BigEndian.Uint64(r.buf)
	r.buf = r.buf[8:]
	return v, nil
}

func (r *krlReader) bytes() ([]byte, error) {
	n, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if uint64(len(r.buf)) < uint64(n) {
		return nil, fmt.Errorf("short read")
	}
	v := r.buf[:n]
	r.buf = r.buf[n:]
	return v, nil
}
