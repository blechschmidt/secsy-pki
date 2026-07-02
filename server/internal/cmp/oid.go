package cmp

import "encoding/asn1"

// Object identifiers used across CMP (RFC 4210 / RFC 9483) and the CRMF
// certificate-request structures it embeds (RFC 4211).
var (
	// id-PasswordBasedMac (RFC 4210 §5.1.3.1) is the shared-secret (MAC) message
	// protection algorithm. Its parameters carry the salt, one-way function,
	// iteration count, and MAC algorithm.
	oidPasswordBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}

	// One-way functions usable as the PBM owf.
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// MAC algorithms usable as the PBM mac.
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	// Signature algorithms used for signature-based message protection.
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	// id-it-implicitConfirm (RFC 4210 §5.3.19.13 / RFC 9483): a generalInfo value
	// a client sends to skip the certConf round-trip, and the server echoes to
	// grant it.
	oidImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}
)
