package hsmattest

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// YubiHSM attestation certificate extensions, under Yubico's private arc
// 1.3.6.1.4.1.41482.4. The device stamps these into the attestation
// certificate it signs over the attested key, so they are assertions made by
// the hardware about an object it holds, not metadata the CA supplies.
//
// The gap between .6 and .9 is Yubico's, not an omission here: a YubiHSM 2
// running firmware 2.4.0 emits exactly 1, 2, 3, 4, 5, 6 and 9.
var (
	oidFirmwareVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 1}
	oidDeviceSerial    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 2}
	oidOrigin          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 3}
	oidDomains         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 4}
	oidCapabilities    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 5}
	oidObjectID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 6}
	oidLabel           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 9}
)

// Origin bits report how the attested key came to exist on the device. This is
// the other half of the extractability question: a key that was imported was,
// by definition, in software somewhere before it arrived, so "cannot leave the
// device" says nothing about whether a copy already exists elsewhere.
const (
	OriginGenerated       = 0x01 // generated on-device; private material never existed off it
	OriginImported        = 0x02 // imported in the clear
	OriginImportedWrapped = 0x10 // imported under a wrap key
)

// Claims are the device's assertions about one attested key, decoded from the
// attestation certificate's Yubico extensions.
type Claims struct {
	// FirmwareVersion is the attesting device's firmware, e.g. "2.4.0".
	FirmwareVersion string `json:"firmware_version,omitempty"`
	// DeviceSerial is the attesting YubiHSM's serial number.
	DeviceSerial string `json:"device_serial,omitempty"`
	// Origin is the raw origin bitmask; see the Origin* constants.
	Origin uint8 `json:"origin"`
	// Domains lists the YubiHSM domains (1..16) the key belongs to.
	Domains []int `json:"domains,omitempty"`
	// Capabilities is the key's capability mask.
	Capabilities Capabilities `json:"capabilities"`
	// CapabilityNames is the decoded capability list, carried alongside the
	// mask so a stored or transmitted attestation stays readable without this
	// build's bit table.
	CapabilityNames []string `json:"capability_names,omitempty"`
	// ObjectID is the on-device object identifier of the attested key. On a
	// YubiHSM this is the two-byte handle that also appears as the PKCS#11
	// CKA_ID and as target_key in the device audit log, which is what lets an
	// attestation be joined to the audit evidence from Task 167.
	ObjectID uint16 `json:"object_id"`
	// Label is the key's on-device label.
	Label string `json:"label,omitempty"`
	// Missing lists attestation extensions that were absent. A YubiHSM emits
	// all of them, so an absence means the certificate was not produced by one
	// — or was edited afterwards.
	Missing []string `json:"missing_extensions,omitempty"`
}

// Exportable reports whether the attested private key can leave the device.
//
// On a YubiHSM this is decided by one capability bit: a key holding
// exportable-under-wrap can be exported wrapped under a wrap key and unwrapped
// wherever that wrap key is, so its confinement is only as good as the wrap
// key's. A key without it has no command path off the device at all.
func (c *Claims) Exportable() bool { return c.Capabilities.Has(CapExportableUnderWrap) }

// GeneratedOnDevice reports whether the private key was created inside the HSM
// and therefore never existed anywhere else.
func (c *Claims) GeneratedOnDevice() bool {
	return c.Origin&OriginGenerated != 0 && !c.Imported()
}

// Imported reports whether the key was placed on the device from outside, in
// the clear or under wrap.
func (c *Claims) Imported() bool {
	return c.Origin&(OriginImported|OriginImportedWrapped) != 0
}

// OriginString renders the origin bitmask in Yubico's vocabulary.
func (c *Claims) OriginString() string {
	var parts []string
	if c.Origin&OriginGenerated != 0 {
		parts = append(parts, "generated")
	}
	if c.Origin&OriginImported != 0 {
		parts = append(parts, "imported")
	}
	if c.Origin&OriginImportedWrapped != 0 {
		parts = append(parts, "imported-under-wrap")
	}
	if rest := c.Origin &^ (OriginGenerated | OriginImported | OriginImportedWrapped); rest != 0 {
		parts = append(parts, fmt.Sprintf("unknown-origin-bits(0x%02x)", rest))
	}
	if len(parts) == 0 {
		return "unspecified"
	}
	return strings.Join(parts, "+")
}

// ParseClaims decodes the Yubico attestation extensions from cert.
//
// It does not verify anything — signature checking and policy live in Verify.
// Extensions that are absent are recorded in Claims.Missing rather than
// treated as an error, so a caller can report precisely which assertion a
// non-conforming certificate failed to make instead of a blanket parse
// failure. A present-but-malformed extension is an error: that is corruption
// or forgery, not an older firmware revision.
func ParseClaims(cert *x509.Certificate) (*Claims, error) {
	if cert == nil {
		return nil, fmt.Errorf("hsmattest: nil certificate")
	}
	c := &Claims{}
	seen := map[string]bool{}

	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidFirmwareVersion):
			seen["firmware-version"] = true
			v, err := parseFirmware(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("attestation firmware-version extension: %w", err)
			}
			c.FirmwareVersion = v
		case ext.Id.Equal(oidDeviceSerial):
			seen["device-serial"] = true
			n, err := parseASN1Integer(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("attestation device-serial extension: %w", err)
			}
			c.DeviceSerial = n.String()
		case ext.Id.Equal(oidOrigin):
			seen["origin"] = true
			b, err := parseBitStringBytes(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("attestation origin extension: %w", err)
			}
			if len(b) != 1 {
				return nil, fmt.Errorf("attestation origin extension: got %d bytes, want 1", len(b))
			}
			c.Origin = b[0]
		case ext.Id.Equal(oidDomains):
			seen["domains"] = true
			b, err := parseBitStringBytes(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("attestation domains extension: %w", err)
			}
			c.Domains = decodeDomains(b)
		case ext.Id.Equal(oidCapabilities):
			seen["capabilities"] = true
			b, err := parseBitStringBytes(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("attestation capabilities extension: %w", err)
			}
			mask, err := beUint64(b)
			if err != nil {
				return nil, fmt.Errorf("attestation capabilities extension: %w", err)
			}
			c.Capabilities = Capabilities(mask)
			c.CapabilityNames = c.Capabilities.Names()
		case ext.Id.Equal(oidObjectID):
			seen["object-id"] = true
			n, err := parseASN1Integer(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("attestation object-id extension: %w", err)
			}
			if !n.IsUint64() || n.Uint64() > 0xffff {
				return nil, fmt.Errorf("attestation object-id extension: %s out of range for a YubiHSM object handle", n)
			}
			c.ObjectID = uint16(n.Uint64())
		case ext.Id.Equal(oidLabel):
			seen["label"] = true
			s, err := parseUTF8String(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("attestation label extension: %w", err)
			}
			c.Label = s
		}
	}

	for _, name := range []string{"firmware-version", "device-serial", "origin", "domains", "capabilities", "object-id", "label"} {
		if !seen[name] {
			c.Missing = append(c.Missing, name)
		}
	}
	sort.Strings(c.Missing)

	if len(seen) == 0 {
		return nil, fmt.Errorf("hsmattest: certificate carries no YubiHSM attestation extensions (arc 1.3.6.1.4.1.41482.4); is it a YubiHSM key attestation?")
	}
	return c, nil
}

// parseFirmware decodes the firmware-version extension: an OCTET STRING
// wrapping three bytes, major.minor.patch.
func parseFirmware(der []byte) (string, error) {
	var raw []byte
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return "", err
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("%d trailing byte(s)", len(rest))
	}
	if len(raw) != 3 {
		return "", fmt.Errorf("got %d bytes, want 3", len(raw))
	}
	return fmt.Sprintf("%d.%d.%d", raw[0], raw[1], raw[2]), nil
}

// parseASN1Integer decodes an INTEGER extension value. big.Int is used rather
// than int64 because nothing guarantees a device serial stays in range, and an
// overflow here would silently mis-identify a device.
func parseASN1Integer(der []byte) (*big.Int, error) {
	// The target must be **big.Int: encoding/asn1 recognises a *big.Int field
	// as an INTEGER, whereas handing it a *big.Int directly makes it treat the
	// struct as a SEQUENCE.
	var n *big.Int
	rest, err := asn1.Unmarshal(der, &n)
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, fmt.Errorf("empty INTEGER")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%d trailing byte(s)", len(rest))
	}
	if n.Sign() < 0 {
		return nil, fmt.Errorf("negative value %s", n)
	}
	return n, nil
}

// parseBitStringBytes decodes a BIT STRING extension value and returns its
// content bytes.
//
// The YubiHSM encodes origin, domains and capabilities as BIT STRINGs whose
// content is the big-endian bitmask, always with zero unused bits — the
// capability mask, for instance, is a full eight bytes even when only one bit
// is set. A non-zero unused-bit count would mean the encoding is not that, so
// it is rejected rather than guessed at.
func parseBitStringBytes(der []byte) ([]byte, error) {
	var bs asn1.BitString
	rest, err := asn1.Unmarshal(der, &bs)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%d trailing byte(s)", len(rest))
	}
	if bs.BitLength != len(bs.Bytes)*8 {
		return nil, fmt.Errorf("BIT STRING has %d unused bit(s); expected a whole number of bytes",
			len(bs.Bytes)*8-bs.BitLength)
	}
	return bs.Bytes, nil
}

// parseUTF8String decodes a UTF8String extension value.
func parseUTF8String(der []byte) (string, error) {
	var s string
	rest, err := asn1.UnmarshalWithParams(der, &s, "utf8")
	if err != nil {
		return "", err
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("%d trailing byte(s)", len(rest))
	}
	return s, nil
}

// beUint64 interprets up to eight bytes as a big-endian unsigned integer.
func beUint64(b []byte) (uint64, error) {
	if len(b) > 8 {
		return 0, fmt.Errorf("got %d bytes, want at most 8", len(b))
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// decodeDomains expands the 16-bit domain mask into domain numbers 1..16.
func decodeDomains(b []byte) []int {
	mask, err := beUint64(b)
	if err != nil {
		return nil
	}
	var out []int
	for i := 0; i < 16; i++ {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, i+1)
		}
	}
	return out
}
