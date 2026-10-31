package pki

// The attribute catalogue behind the raw PKCS#11 inspector (Task 218).
//
// PKCS#11 has no "list this object's attributes" call. C_GetAttributeValue only
// answers questions: you name a CK_ATTRIBUTE_TYPE and the token either returns
// its value or refuses. So "all attributes of all objects" can only ever mean
// "every attribute the standard defines, asked of every object" — and that set
// has to be written down somewhere. This file is that set, together with how
// each attribute's bytes are to be read (a CK_BBOOL is not a CK_ULONG is not a
// DER-encoded name) and which class of object the standard defines it for.
//
// Two policies are expressed here, both deliberate:
//
//  1. An attribute whose value IS private key material — the RSA CRT factors, a
//     private exponent, the private scalar or secret-key bytes behind CKA_VALUE
//     — is never requested. Not "requested and redacted": never put on the
//     wire. A correctly configured token refuses these anyway
//     (CKR_ATTRIBUTE_SENSITIVE), and that refusal is itself worth showing — but
//     the inspector must not be the one path in this system that turns a
//     mis-provisioned, extractable key into an HTTP response body. The
//     inspector reports them as withheld, naming the policy, and the
//     non-extractability verdict in the key inventory remains the way an
//     operator learns a key is exportable.
//
//  2. The CK_ATTRIBUTE-array attributes (CKA_WRAP_TEMPLATE and friends) are not
//     requested either. Their value is an array of CK_ATTRIBUTE structs whose
//     pValue members are pointers the caller is supposed to have set up; a
//     module handed a zeroed buffer may write through them. There is no
//     portable way to read one blind, so they are reported as not read rather
//     than risking the module's address space.
//
// Everything else is fair game, including the attributes a token refuses: a row
// reading "CKA_VALUE — CKR_ATTRIBUTE_SENSITIVE" is evidence about the token.

import "github.com/miekg/pkcs11"

// attrKind says how an attribute's bytes are to be interpreted for display. It
// is the Cryptoki type of the attribute, not a guess from the bytes: the same
// four bytes are a CK_ULONG, a CK_MECHANISM_TYPE or the start of a modulus
// depending only on which attribute they came from.
type attrKind string

const (
	kindBool      attrKind = "bool"       // CK_BBOOL
	kindULong     attrKind = "ulong"      // CK_ULONG
	kindString    attrKind = "string"     // RFC 2279 / UTF-8 string
	kindBytes     attrKind = "bytes"      // opaque byte array
	kindBigInt    attrKind = "biginteger" // big integer, big-endian
	kindDate      attrKind = "date"       // CK_DATE (YYYYMMDD)
	kindClass     attrKind = "class"      // CK_OBJECT_CLASS
	kindKeyType   attrKind = "key-type"   // CK_KEY_TYPE
	kindCertType  attrKind = "cert-type"  // CK_CERTIFICATE_TYPE
	kindHWFeature attrKind = "hw-feature" // CK_HW_FEATURE_TYPE
	kindMechanism attrKind = "mechanism"  // CK_MECHANISM_TYPE
	kindMechList  attrKind = "mechanisms" // CK_MECHANISM_TYPE array
	kindDER       attrKind = "der"        // DER-encoded structure (name, OID, SPKI)
	kindTemplate  attrKind = "template"   // CK_ATTRIBUTE array — never read, see above
)

// Object-class bits. An attribute is requested of an object when the object's
// CKA_CLASS is in the attribute's class set, so a certificate is not
// interrogated about CKA_PIXEL_X. Setting InspectOptions.AllAttributes asks
// every object for every attribute in the catalogue instead, which is the honest
// way to discover what a particular module answers outside the standard.
const (
	clsData = 1 << iota
	clsCert
	clsPub
	clsPriv
	clsSecret
	clsDomain
	clsHW
	clsMech
	clsOTP

	// clsKeys is every key class; clsAll is every class, used for the storage
	// attributes every object has.
	clsKeys = clsPub | clsPriv | clsSecret | clsOTP
	clsAll  = clsData | clsCert | clsKeys | clsDomain | clsHW | clsMech
)

// classBit maps a CKA_CLASS value to its bit, for matching against a spec's
// class set. An unknown (vendor) class matches nothing by itself, so a vendor
// object is inspected for the storage attributes only — unless AllAttributes
// asks for the whole catalogue.
func classBit(class uint) int {
	switch class {
	case pkcs11.CKO_DATA:
		return clsData
	case pkcs11.CKO_CERTIFICATE:
		return clsCert
	case pkcs11.CKO_PUBLIC_KEY:
		return clsPub
	case pkcs11.CKO_PRIVATE_KEY:
		return clsPriv
	case pkcs11.CKO_SECRET_KEY:
		return clsSecret
	case pkcs11.CKO_DOMAIN_PARAMETERS:
		return clsDomain
	case pkcs11.CKO_HW_FEATURE:
		return clsHW
	case pkcs11.CKO_MECHANISM:
		return clsMech
	case pkcs11.CKO_OTP_KEY:
		return clsOTP
	}
	return 0
}

// attrSpec describes one catalogued attribute.
type attrSpec struct {
	kind attrKind
	// classes is the set of object classes the standard defines this attribute
	// for; 0 means "storage attribute, every object".
	classes int
	// secret marks an attribute whose value is private key material. Never
	// requested. See the policy note at the top of this file.
	secret int // the classes for which the value is key material
}

// applies reports whether the attribute is defined for an object of this class.
func (s attrSpec) applies(class uint) bool {
	if s.classes == 0 {
		return true
	}
	return s.classes&classBit(class) != 0
}

// withheldFor reports whether the attribute's value is private key material for
// an object of this class, in which case it is not requested at all.
func (s attrSpec) withheldFor(class uint) bool {
	return s.secret != 0 && s.secret&classBit(class) != 0
}

// pkcs11Attributes is the catalogue: every CK_ATTRIBUTE_TYPE this inspector
// knows how to ask for. Order is the output order, grouped the way the standard
// groups them (storage, then per-class), so the rendered attribute list reads
// like the spec's tables rather than like a hash map.
//
// Attribute names are not repeated here — they come from the generated tables in
// pkcs11names_gen.go, which are derived from the binding's own constants.
var pkcs11Attributes = []struct {
	typ  uint
	spec attrSpec
}{
	// --- Common / storage attributes (every object) -------------------------
	{pkcs11.CKA_CLASS, attrSpec{kind: kindClass}},
	{pkcs11.CKA_TOKEN, attrSpec{kind: kindBool}},
	{pkcs11.CKA_PRIVATE, attrSpec{kind: kindBool}},
	{pkcs11.CKA_MODIFIABLE, attrSpec{kind: kindBool}},
	{pkcs11.CKA_COPYABLE, attrSpec{kind: kindBool}},
	{pkcs11.CKA_DESTROYABLE, attrSpec{kind: kindBool}},
	{pkcs11.CKA_LABEL, attrSpec{kind: kindString}},

	// --- Data objects ------------------------------------------------------
	{pkcs11.CKA_APPLICATION, attrSpec{kind: kindString, classes: clsData}},
	{pkcs11.CKA_OBJECT_ID, attrSpec{kind: kindDER, classes: clsData}},

	// --- Certificates ------------------------------------------------------
	{pkcs11.CKA_CERTIFICATE_TYPE, attrSpec{kind: kindCertType, classes: clsCert}},
	{pkcs11.CKA_CERTIFICATE_CATEGORY, attrSpec{kind: kindULong, classes: clsCert}},
	{pkcs11.CKA_TRUSTED, attrSpec{kind: kindBool, classes: clsCert}},
	{pkcs11.CKA_ISSUER, attrSpec{kind: kindDER, classes: clsCert}},
	{pkcs11.CKA_SERIAL_NUMBER, attrSpec{kind: kindDER, classes: clsCert}},
	{pkcs11.CKA_AC_ISSUER, attrSpec{kind: kindDER, classes: clsCert}},
	{pkcs11.CKA_OWNER, attrSpec{kind: kindDER, classes: clsCert}},
	{pkcs11.CKA_ATTR_TYPES, attrSpec{kind: kindBytes, classes: clsCert}},
	{pkcs11.CKA_JAVA_MIDP_SECURITY_DOMAIN, attrSpec{kind: kindULong, classes: clsCert}},
	{pkcs11.CKA_URL, attrSpec{kind: kindString, classes: clsCert}},
	{pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY, attrSpec{kind: kindBytes, classes: clsCert}},
	{pkcs11.CKA_HASH_OF_ISSUER_PUBLIC_KEY, attrSpec{kind: kindBytes, classes: clsCert}},
	{pkcs11.CKA_NAME_HASH_ALGORITHM, attrSpec{kind: kindMechanism, classes: clsCert}},

	// --- Keys (common) -----------------------------------------------------
	{pkcs11.CKA_KEY_TYPE, attrSpec{kind: kindKeyType, classes: clsKeys | clsDomain}},
	{pkcs11.CKA_ID, attrSpec{kind: kindBytes, classes: clsCert | clsKeys}},
	{pkcs11.CKA_SUBJECT, attrSpec{kind: kindDER, classes: clsCert | clsPub | clsPriv}},
	{pkcs11.CKA_START_DATE, attrSpec{kind: kindDate, classes: clsKeys}},
	{pkcs11.CKA_END_DATE, attrSpec{kind: kindDate, classes: clsKeys}},
	{pkcs11.CKA_DERIVE, attrSpec{kind: kindBool, classes: clsKeys}},
	{pkcs11.CKA_LOCAL, attrSpec{kind: kindBool, classes: clsKeys}},
	{pkcs11.CKA_KEY_GEN_MECHANISM, attrSpec{kind: kindMechanism, classes: clsKeys}},
	{pkcs11.CKA_ALLOWED_MECHANISMS, attrSpec{kind: kindMechList, classes: clsKeys}},

	// --- Public keys -------------------------------------------------------
	{pkcs11.CKA_ENCRYPT, attrSpec{kind: kindBool, classes: clsPub | clsSecret}},
	{pkcs11.CKA_VERIFY, attrSpec{kind: kindBool, classes: clsPub | clsSecret}},
	{pkcs11.CKA_VERIFY_RECOVER, attrSpec{kind: kindBool, classes: clsPub}},
	{pkcs11.CKA_WRAP, attrSpec{kind: kindBool, classes: clsPub | clsSecret}},
	{pkcs11.CKA_WRAP_TEMPLATE, attrSpec{kind: kindTemplate, classes: clsPub | clsSecret}},
	{pkcs11.CKA_PUBLIC_KEY_INFO, attrSpec{kind: kindDER, classes: clsPub | clsPriv}},

	// --- Private keys ------------------------------------------------------
	{pkcs11.CKA_SENSITIVE, attrSpec{kind: kindBool, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_DECRYPT, attrSpec{kind: kindBool, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_SIGN, attrSpec{kind: kindBool, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_SIGN_RECOVER, attrSpec{kind: kindBool, classes: clsPriv}},
	{pkcs11.CKA_UNWRAP, attrSpec{kind: kindBool, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_UNWRAP_TEMPLATE, attrSpec{kind: kindTemplate, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_EXTRACTABLE, attrSpec{kind: kindBool, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_ALWAYS_SENSITIVE, attrSpec{kind: kindBool, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_NEVER_EXTRACTABLE, attrSpec{kind: kindBool, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_WRAP_WITH_TRUSTED, attrSpec{kind: kindBool, classes: clsPriv | clsSecret}},
	{pkcs11.CKA_ALWAYS_AUTHENTICATE, attrSpec{kind: kindBool, classes: clsPriv}},
	{pkcs11.CKA_DERIVE_TEMPLATE, attrSpec{kind: kindTemplate, classes: clsKeys}},

	// --- Secret keys -------------------------------------------------------
	{pkcs11.CKA_CHECK_VALUE, attrSpec{kind: kindBytes, classes: clsSecret}},
	{pkcs11.CKA_VALUE_LEN, attrSpec{kind: kindULong, classes: clsSecret}},

	// --- RSA ---------------------------------------------------------------
	{pkcs11.CKA_MODULUS, attrSpec{kind: kindBigInt, classes: clsPub | clsPriv}},
	{pkcs11.CKA_MODULUS_BITS, attrSpec{kind: kindULong, classes: clsPub}},
	{pkcs11.CKA_PUBLIC_EXPONENT, attrSpec{kind: kindBigInt, classes: clsPub | clsPriv}},
	// The CRT factors and the private exponent are withheld for EVERY key
	// class, not only CKO_PRIVATE_KEY: AllAttributes bypasses the class
	// scoping, and "ask a secret key for CKA_PRIME_1 and see what happens" is
	// not a request this inspector should ever make.
	{pkcs11.CKA_PRIVATE_EXPONENT, attrSpec{kind: kindBigInt, classes: clsPriv, secret: clsKeys}},
	{pkcs11.CKA_PRIME_1, attrSpec{kind: kindBigInt, classes: clsPriv, secret: clsKeys}},
	{pkcs11.CKA_PRIME_2, attrSpec{kind: kindBigInt, classes: clsPriv, secret: clsKeys}},
	{pkcs11.CKA_EXPONENT_1, attrSpec{kind: kindBigInt, classes: clsPriv, secret: clsKeys}},
	{pkcs11.CKA_EXPONENT_2, attrSpec{kind: kindBigInt, classes: clsPriv, secret: clsKeys}},
	{pkcs11.CKA_COEFFICIENT, attrSpec{kind: kindBigInt, classes: clsPriv, secret: clsKeys}},

	// --- DSA / DH / X9.42 domain parameters --------------------------------
	{pkcs11.CKA_PRIME, attrSpec{kind: kindBigInt, classes: clsPub | clsPriv | clsDomain}},
	{pkcs11.CKA_SUBPRIME, attrSpec{kind: kindBigInt, classes: clsPub | clsPriv | clsDomain}},
	{pkcs11.CKA_BASE, attrSpec{kind: kindBigInt, classes: clsPub | clsPriv | clsDomain}},
	{pkcs11.CKA_PRIME_BITS, attrSpec{kind: kindULong, classes: clsDomain}},
	{pkcs11.CKA_SUBPRIME_BITS, attrSpec{kind: kindULong, classes: clsDomain}},
	{pkcs11.CKA_VALUE_BITS, attrSpec{kind: kindULong, classes: clsPriv}},

	// --- Elliptic curve ----------------------------------------------------
	{pkcs11.CKA_EC_PARAMS, attrSpec{kind: kindDER, classes: clsPub | clsPriv | clsDomain}},
	{pkcs11.CKA_EC_POINT, attrSpec{kind: kindDER, classes: clsPub}},

	// --- GOST --------------------------------------------------------------
	{pkcs11.CKA_GOSTR3410_PARAMS, attrSpec{kind: kindDER, classes: clsPub | clsPriv}},
	{pkcs11.CKA_GOSTR3411_PARAMS, attrSpec{kind: kindDER, classes: clsPub | clsPriv}},
	{pkcs11.CKA_GOST28147_PARAMS, attrSpec{kind: kindBytes, classes: clsPub | clsPriv | clsSecret}},

	// --- CKA_VALUE: the certificate body, a data object's contents, a DSA/EC
	// public value — or the private scalar / secret-key bytes, which are the
	// two cases the catalogue withholds.
	{pkcs11.CKA_VALUE, attrSpec{kind: kindBytes, classes: clsData | clsCert | clsKeys | clsDomain, secret: clsPriv | clsSecret | clsOTP}},

	// --- Hardware feature objects ------------------------------------------
	{pkcs11.CKA_HW_FEATURE_TYPE, attrSpec{kind: kindHWFeature, classes: clsHW}},
	{pkcs11.CKA_RESET_ON_INIT, attrSpec{kind: kindBool, classes: clsHW}},
	{pkcs11.CKA_HAS_RESET, attrSpec{kind: kindBool, classes: clsHW}},
	{pkcs11.CKA_PIXEL_X, attrSpec{kind: kindULong, classes: clsHW}},
	{pkcs11.CKA_PIXEL_Y, attrSpec{kind: kindULong, classes: clsHW}},
	{pkcs11.CKA_RESOLUTION, attrSpec{kind: kindULong, classes: clsHW}},
	{pkcs11.CKA_CHAR_ROWS, attrSpec{kind: kindULong, classes: clsHW}},
	{pkcs11.CKA_CHAR_COLUMNS, attrSpec{kind: kindULong, classes: clsHW}},
	{pkcs11.CKA_COLOR, attrSpec{kind: kindBool, classes: clsHW}},
	{pkcs11.CKA_BITS_PER_PIXEL, attrSpec{kind: kindULong, classes: clsHW}},
	{pkcs11.CKA_CHAR_SETS, attrSpec{kind: kindString, classes: clsHW}},
	{pkcs11.CKA_ENCODING_METHODS, attrSpec{kind: kindString, classes: clsHW}},
	{pkcs11.CKA_MIME_TYPES, attrSpec{kind: kindString, classes: clsHW}},

	// --- Mechanism objects -------------------------------------------------
	{pkcs11.CKA_MECHANISM_TYPE, attrSpec{kind: kindMechanism, classes: clsMech}},

	// --- OTP keys ----------------------------------------------------------
	{pkcs11.CKA_OTP_FORMAT, attrSpec{kind: kindULong, classes: clsOTP}},
	{pkcs11.CKA_OTP_LENGTH, attrSpec{kind: kindULong, classes: clsOTP}},
	{pkcs11.CKA_OTP_TIME_INTERVAL, attrSpec{kind: kindULong, classes: clsOTP}},
	{pkcs11.CKA_OTP_USER_FRIENDLY_MODE, attrSpec{kind: kindBool, classes: clsOTP}},
	{pkcs11.CKA_OTP_CHALLENGE_REQUIREMENT, attrSpec{kind: kindULong, classes: clsOTP}},
	{pkcs11.CKA_OTP_TIME_REQUIREMENT, attrSpec{kind: kindULong, classes: clsOTP}},
	{pkcs11.CKA_OTP_COUNTER_REQUIREMENT, attrSpec{kind: kindULong, classes: clsOTP}},
	{pkcs11.CKA_OTP_PIN_REQUIREMENT, attrSpec{kind: kindULong, classes: clsOTP}},
	{pkcs11.CKA_OTP_COUNTER, attrSpec{kind: kindBytes, classes: clsOTP}},
	{pkcs11.CKA_OTP_TIME, attrSpec{kind: kindString, classes: clsOTP}},
	{pkcs11.CKA_OTP_USER_IDENTIFIER, attrSpec{kind: kindString, classes: clsOTP}},
	{pkcs11.CKA_OTP_SERVICE_IDENTIFIER, attrSpec{kind: kindString, classes: clsOTP}},
	{pkcs11.CKA_OTP_SERVICE_LOGO, attrSpec{kind: kindBytes, classes: clsOTP}},
	{pkcs11.CKA_OTP_SERVICE_LOGO_TYPE, attrSpec{kind: kindString, classes: clsOTP}},

	// --- CMS ---------------------------------------------------------------
	{pkcs11.CKA_REQUIRED_CMS_ATTRIBUTES, attrSpec{kind: kindBytes, classes: clsCert}},
	{pkcs11.CKA_DEFAULT_CMS_ATTRIBUTES, attrSpec{kind: kindBytes, classes: clsCert}},
	{pkcs11.CKA_SUPPORTED_CMS_ATTRIBUTES, attrSpec{kind: kindBytes, classes: clsCert}},
}

// attributeName returns the CKA_ name of an attribute type, or a synthetic
// description for one outside the standard — a vendor attribute is reported as
// CKA_VENDOR_DEFINED+0x… so it is still identifiable.
func attributeName(typ uint) string {
	if n, ok := ckaNames[typ]; ok {
		return n
	}
	if typ&pkcs11.CKA_VENDOR_DEFINED != 0 {
		return "CKA_VENDOR_DEFINED+" + hexNum(typ&^pkcs11.CKA_VENDOR_DEFINED)
	}
	return "CKA_" + hexNum(typ)
}

// namedValue renders a Cryptoki enumeration value as "CKx_NAME (0x…)", or just
// the number when the value is not in the table.
func namedValue(table map[uint]string, v uint) string {
	if n, ok := table[v]; ok {
		return n + " (" + hexNum(v) + ")"
	}
	return hexNum(v)
}
