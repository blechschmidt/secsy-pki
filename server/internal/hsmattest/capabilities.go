package hsmattest

import (
	"fmt"
	"sort"
	"strings"
)

// YubiHSM 2 object capabilities.
//
// A capability is a bit position in the 64-bit capability mask that the device
// stamps into the attestation certificate (extension 1.3.6.1.4.1.41482.4.5).
// For an asymmetric key the mask is the complete statement of what that key may
// ever be used for, so reading it is how a verifier learns whether the key can
// sign, and — the question this package exists to answer — whether it can
// leave the device.
//
// The table below was extracted mechanically from the capability array inside
// Yubico's own libyubihsm 2.8.0 rather than transcribed from documentation,
// because a single wrong bit here would silently invert a security verdict:
// mistaking the bit for exportable-under-wrap would report an extractable CA
// key as confined to hardware. Bits 0..55 are contiguous and complete.
const (
	// CapExportableUnderWrap is the capability that decides extractability. A
	// key that has it can be exported under a wrap key and unwrapped elsewhere,
	// so its private material is only as confined as the wrap key. A key that
	// lacks it can never leave the device in any form, which is the property a
	// CA key is supposed to have.
	CapExportableUnderWrap = 16
	// CapSignAttestationCertificate lets a key sign attestation certificates.
	CapSignAttestationCertificate = 34
)

// capabilityNames maps capability bit position to Yubico's canonical name.
var capabilityNames = map[uint8]string{
	0:  "get-opaque",
	1:  "put-opaque",
	2:  "put-authentication-key",
	3:  "put-asymmetric-key",
	4:  "generate-asymmetric-key",
	5:  "sign-pkcs",
	6:  "sign-pss",
	7:  "sign-ecdsa",
	8:  "sign-eddsa",
	9:  "decrypt-pkcs",
	10: "decrypt-oaep",
	11: "derive-ecdh",
	12: "export-wrapped",
	13: "import-wrapped",
	14: "put-wrap-key",
	15: "generate-wrap-key",
	16: "exportable-under-wrap",
	17: "set-option",
	18: "get-option",
	19: "get-pseudo-random",
	20: "put-mac-key",
	21: "generate-hmac-key",
	22: "sign-hmac",
	23: "verify-hmac",
	24: "get-log-entries",
	25: "sign-ssh-certificate",
	26: "get-template",
	27: "put-template",
	28: "reset-device",
	29: "decrypt-otp",
	30: "create-otp-aead",
	31: "randomize-otp-aead",
	32: "rewrap-from-otp-aead-key",
	33: "rewrap-to-otp-aead-key",
	34: "sign-attestation-certificate",
	35: "put-otp-aead-key",
	36: "generate-otp-aead-key",
	37: "wrap-data",
	38: "unwrap-data",
	39: "delete-opaque",
	40: "delete-authentication-key",
	41: "delete-asymmetric-key",
	42: "delete-wrap-key",
	43: "delete-hmac-key",
	44: "delete-template",
	45: "delete-otp-aead-key",
	46: "change-authentication-key",
	47: "put-symmetric-key",
	48: "generate-symmetric-key",
	49: "delete-symmetric-key",
	50: "decrypt-ecb",
	51: "encrypt-ecb",
	52: "decrypt-cbc",
	53: "encrypt-cbc",
	54: "put-public-wrap-key",
	55: "delete-public-wrap-key",
}

// signingCapabilities are the capabilities that let a key produce a signature.
// A key holding none of them cannot sign at all, which is worth reporting: an
// attestation for such a key says nothing about issuance.
var signingCapabilities = []uint8{
	5,  // sign-pkcs
	6,  // sign-pss
	7,  // sign-ecdsa
	8,  // sign-eddsa
	22, // sign-hmac
	25, // sign-ssh-certificate
	34, // sign-attestation-certificate
}

// CapabilityName returns Yubico's canonical name for a capability bit, or a
// numeric placeholder for a bit this build does not know. Unknown bits are
// reported rather than dropped: a capability introduced by newer firmware is
// exactly the kind of thing a verifier must not silently ignore.
func CapabilityName(bit uint8) string {
	if n, ok := capabilityNames[bit]; ok {
		return n
	}
	return fmt.Sprintf("unknown-capability-%d", bit)
}

// CapabilityBit resolves a canonical capability name to its bit position.
func CapabilityBit(name string) (uint8, bool) {
	for bit, n := range capabilityNames {
		if n == name {
			return bit, true
		}
	}
	return 0, false
}

// Capabilities is a YubiHSM capability mask.
type Capabilities uint64

// Has reports whether the given capability bit is set.
func (c Capabilities) Has(bit uint8) bool { return c&(1<<bit) != 0 }

// Names lists the set capabilities by canonical name, in bit order.
func (c Capabilities) Names() []string {
	var out []string
	for bit := 0; bit < 64; bit++ {
		if c.Has(uint8(bit)) {
			out = append(out, CapabilityName(uint8(bit)))
		}
	}
	return out
}

// CanSign reports whether the mask permits any signing operation.
func (c Capabilities) CanSign() bool {
	for _, bit := range signingCapabilities {
		if c.Has(bit) {
			return true
		}
	}
	return false
}

// Unknown lists set bits this build has no name for, so a caller can decide
// whether an unrecognised capability granted by newer firmware is acceptable.
func (c Capabilities) Unknown() []uint8 {
	var out []uint8
	for bit := 0; bit < 64; bit++ {
		if c.Has(uint8(bit)) {
			if _, known := capabilityNames[uint8(bit)]; !known {
				out = append(out, uint8(bit))
			}
		}
	}
	return out
}

func (c Capabilities) String() string {
	names := c.Names()
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// ParseCapabilityNames builds a mask from canonical capability names, so that
// policy can be expressed in configuration the same way Yubico's own tooling
// spells it.
func ParseCapabilityNames(names []string) (Capabilities, error) {
	var mask Capabilities
	var bad []string
	for _, raw := range names {
		n := strings.ToLower(strings.TrimSpace(raw))
		if n == "" {
			continue
		}
		bit, ok := CapabilityBit(n)
		if !ok {
			bad = append(bad, raw)
			continue
		}
		mask |= 1 << bit
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return 0, fmt.Errorf("unknown YubiHSM capability name(s): %s", strings.Join(bad, ", "))
	}
	return mask, nil
}
