package certlint

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/smime"
)

// S/MIME check codes (CA/B Forum S/MIME Baseline Requirements, mailbox-
// validated profiles). They run only when Policy.SMIME is set and are gated
// enforce/warn per profile exactly like the baseline checks.
const (
	// CheckSMIMESANPresent requires at least one rfc822Name subjectAltName —
	// the mailbox the certificate protects (SMBR §7.1.4.2.1).
	CheckSMIMESANPresent = "smime_san_present"
	// CheckSMIMESANTypes forbids non-mailbox SAN types (dNSName, iPAddress,
	// URI) in a mailbox-validated certificate (SMBR §7.1.4.2.1).
	CheckSMIMESANTypes = "smime_san_types"
	// CheckSMIMEEmailSyntax requires every rfc822Name to be a valid RFC 5321
	// addr-spec in normalized (lowercase A-label domain) form.
	CheckSMIMEEmailSyntax = "smime_email_syntax"
	// CheckSMIMEEKU requires id-kp-emailProtection and forbids the EKUs the
	// SMBRs exclude — serverAuth, codeSigning, timeStamping, OCSPSigning, and
	// anyExtendedKeyUsage; under the strict class no other EKU may appear at
	// all (SMBR §7.1.2.3(f)).
	CheckSMIMEEKU = "smime_eku"
	// CheckSMIMEKeyUsage constrains the key-usage bits to the signing /
	// encryption split the profile variant declares (SMBR §7.1.2.3(e)).
	CheckSMIMEKeyUsage = "smime_key_usage"
	// CheckSMIMEValidity caps the validity period per SMBR class (§6.3.2):
	// 1185 days for legacy, 825 days for multipurpose and strict.
	CheckSMIMEValidity = "smime_validity"
	// CheckSMIMESubjectEmail requires any subject emailAddress attribute (and a
	// mailbox-shaped common name) to match one of the rfc822Name SANs.
	CheckSMIMESubjectEmail = "smime_subject_email"
)

// SMIMEClass is the CA/B Forum S/MIME Baseline Requirements generation a
// profile targets. The classes differ in validity caps and EKU exclusivity.
type SMIMEClass string

const (
	// SMIMEClassLegacy permits the longest validity (1185 days) and additional
	// EKUs, easing migration of existing deployments.
	SMIMEClassLegacy SMIMEClass = "legacy"
	// SMIMEClassMultipurpose caps validity at 825 days and permits additional
	// (non-excluded) EKUs. It is the default.
	SMIMEClassMultipurpose SMIMEClass = "multipurpose"
	// SMIMEClassStrict caps validity at 825 days and permits no EKU other than
	// id-kp-emailProtection.
	SMIMEClassStrict SMIMEClass = "strict"
)

// SMIMEVariant declares which S/MIME operations the certified key performs,
// driving the expected key-usage split.
type SMIMEVariant string

const (
	// SMIMEVariantSign is a signing-only certificate: digitalSignature
	// (optionally contentCommitment), no key-management usage.
	SMIMEVariantSign SMIMEVariant = "sign"
	// SMIMEVariantEncrypt is a key-management-only certificate: keyEncipherment
	// (RSA) or keyAgreement (EC), no signing usage.
	SMIMEVariantEncrypt SMIMEVariant = "encrypt"
	// SMIMEVariantDual is a single-key certificate used for both. It is the
	// default; the SMBRs permit it, though split keys are recommended so the
	// encryption key can be escrowed without escrowing the signing key.
	SMIMEVariantDual SMIMEVariant = "dual"
)

const (
	// MaxSMIMELegacyValidity is the SMBR §6.3.2 validity cap for the legacy class.
	MaxSMIMELegacyValidity = 1185 * 24 * time.Hour
	// MaxSMIMEValidity is the SMBR §6.3.2 validity cap for the multipurpose and
	// strict classes.
	MaxSMIMEValidity = 825 * 24 * time.Hour
)

// SMIMEPolicy enables the S/MIME rule set for a lint run. The zero value of
// each field selects the default (multipurpose class, dual-use variant).
type SMIMEPolicy struct {
	Class   SMIMEClass
	Variant SMIMEVariant
}

func (p SMIMEPolicy) class() SMIMEClass {
	switch p.Class {
	case SMIMEClassLegacy, SMIMEClassStrict:
		return p.Class
	default:
		return SMIMEClassMultipurpose
	}
}

func (p SMIMEPolicy) variant() SMIMEVariant {
	switch p.Variant {
	case SMIMEVariantSign, SMIMEVariantEncrypt:
		return p.Variant
	default:
		return SMIMEVariantDual
	}
}

// oidEmailAddress is the PKCS#9 emailAddress attribute (1.2.840.113549.1.9.1)
// historically carried in the subject DN of S/MIME certificates.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// checkSMIME runs the S/MIME Baseline Requirements rule set.
func checkSMIME(cert *x509.Certificate, pol SMIMEPolicy, add adder) {
	checkSMIMESANs(cert, add)
	checkSMIMEEKU(cert, pol.class(), add)
	checkSMIMEKeyUsage(cert, pol, add)
	checkSMIMEValidity(cert, pol.class(), add)
	checkSMIMESubjectEmail(cert, add)
}

// checkSMIMESANs enforces rfc822Name presence, SAN-type exclusivity, and
// address syntax/normalization.
func checkSMIMESANs(cert *x509.Certificate, add adder) {
	if len(cert.EmailAddresses) == 0 {
		add(CheckSMIMESANPresent, "S/MIME certificate must include at least one rfc822Name subjectAltName")
	}
	if n := len(cert.DNSNames); n > 0 {
		add(CheckSMIMESANTypes, "mailbox-validated S/MIME certificate must not carry dNSName SANs (%d present)", n)
	}
	if n := len(cert.IPAddresses); n > 0 {
		add(CheckSMIMESANTypes, "mailbox-validated S/MIME certificate must not carry iPAddress SANs (%d present)", n)
	}
	if n := len(cert.URIs); n > 0 {
		add(CheckSMIMESANTypes, "mailbox-validated S/MIME certificate must not carry URI SANs (%d present)", n)
	}
	for _, e := range cert.EmailAddresses {
		m, err := smime.NormalizeEmail(e)
		if err != nil {
			add(CheckSMIMEEmailSyntax, "rfc822Name %q is not a valid mailbox address: %v", e, err)
			continue
		}
		if m.Address() != e {
			add(CheckSMIMEEmailSyntax, "rfc822Name %q is not in normalized form (want %q)", e, m.Address())
		}
	}
}

// smimeExcludedEKUs are the extended key usages the SMBRs forbid in any
// S/MIME certificate (§7.1.2.3(f)).
var smimeExcludedEKUs = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:          "anyExtendedKeyUsage",
	x509.ExtKeyUsageServerAuth:   "serverAuth",
	x509.ExtKeyUsageCodeSigning:  "codeSigning",
	x509.ExtKeyUsageTimeStamping: "timeStamping",
	x509.ExtKeyUsageOCSPSigning:  "ocspSigning",
}

// checkSMIMEEKU enforces emailProtection presence and EKU exclusivity.
func checkSMIMEEKU(cert *x509.Certificate, class SMIMEClass, add adder) {
	hasEmailProtection := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageEmailProtection {
			hasEmailProtection = true
			continue
		}
		if name, excluded := smimeExcludedEKUs[eku]; excluded {
			add(CheckSMIMEEKU, "S/MIME certificate must not carry the %s extended key usage", name)
			continue
		}
		if class == SMIMEClassStrict {
			add(CheckSMIMEEKU, "strict S/MIME profile permits no extended key usage besides emailProtection")
		}
	}
	if class == SMIMEClassStrict && len(cert.UnknownExtKeyUsage) > 0 {
		add(CheckSMIMEEKU, "strict S/MIME profile permits no extended key usage besides emailProtection (found %v)", cert.UnknownExtKeyUsage)
	}
	if !hasEmailProtection {
		add(CheckSMIMEEKU, "S/MIME certificate must carry the emailProtection extended key usage")
	}
}

// checkSMIMEKeyUsage enforces the SMBR key-usage split for the declared
// variant and, when the subject public key is known, its algorithm fit.
func checkSMIMEKeyUsage(cert *x509.Certificate, pol SMIMEPolicy, add adder) {
	ku := cert.KeyUsage
	if ku == 0 {
		add(CheckSMIMEKeyUsage, "S/MIME certificate must define a key-usage extension")
		return
	}

	allowed := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
	if pol.class() == SMIMEClassLegacy {
		allowed |= x509.KeyUsageDataEncipherment
	}
	if extra := ku &^ allowed; extra != 0 {
		add(CheckSMIMEKeyUsage, "S/MIME certificate carries key-usage bits outside the S/MIME Baseline Requirements set")
	}

	const encBits = x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageDataEncipherment
	const signBits = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	switch pol.variant() {
	case SMIMEVariantSign:
		if ku&x509.KeyUsageDigitalSignature == 0 {
			add(CheckSMIMEKeyUsage, "S/MIME signing certificate must carry the digitalSignature key usage")
		}
		if ku&encBits != 0 {
			add(CheckSMIMEKeyUsage, "S/MIME signing certificate must not carry key-management usages (keyEncipherment/keyAgreement)")
		}
	case SMIMEVariantEncrypt:
		if ku&(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 {
			add(CheckSMIMEKeyUsage, "S/MIME encryption certificate must carry keyEncipherment (RSA) or keyAgreement (EC)")
		}
		if ku&signBits != 0 {
			add(CheckSMIMEKeyUsage, "S/MIME encryption certificate must not carry signing usages (digitalSignature/contentCommitment)")
		}
	default: // dual-use
		if ku&x509.KeyUsageDigitalSignature == 0 {
			add(CheckSMIMEKeyUsage, "dual-use S/MIME certificate must carry the digitalSignature key usage")
		}
		if ku&(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 {
			add(CheckSMIMEKeyUsage, "dual-use S/MIME certificate must carry keyEncipherment (RSA) or keyAgreement (EC)")
		}
	}

	// Key-algorithm fit: keyEncipherment is an RSA operation and keyAgreement an
	// EC one; Ed25519 keys cannot do S/MIME key management at all.
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if ku&x509.KeyUsageKeyAgreement != 0 {
			add(CheckSMIMEKeyUsage, "RSA subject key cannot perform keyAgreement; use keyEncipherment for RSA key management")
		}
	case *ecdsa.PublicKey:
		if ku&(x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment) != 0 {
			add(CheckSMIMEKeyUsage, "EC subject key cannot perform keyEncipherment; use keyAgreement (ECDH) for EC key management")
		}
	case ed25519.PublicKey:
		if ku&encBits != 0 {
			add(CheckSMIMEKeyUsage, "Ed25519 subject key is signing-only and cannot carry key-management usages")
		}
	}
}

// checkSMIMEValidity enforces the SMBR class validity cap.
func checkSMIMEValidity(cert *x509.Certificate, class SMIMEClass, add adder) {
	if !cert.NotAfter.After(cert.NotBefore) {
		return // ordering is reported by the baseline validity check
	}
	limit := MaxSMIMEValidity
	if class == SMIMEClassLegacy {
		limit = MaxSMIMELegacyValidity
	}
	if span := cert.NotAfter.Sub(cert.NotBefore); span > limit+validityGrace {
		add(CheckSMIMEValidity, "validity period %s exceeds the S/MIME Baseline Requirements %s-class maximum of %s",
			roundDays(span), class, roundDays(limit))
	}
}

// checkSMIMESubjectEmail requires subject-carried mailboxes (the PKCS#9
// emailAddress attribute and a mailbox-shaped common name) to match an
// rfc822Name SAN.
func checkSMIMESubjectEmail(cert *x509.Certificate, add adder) {
	sans := make([]smime.Mailbox, 0, len(cert.EmailAddresses))
	for _, e := range cert.EmailAddresses {
		if m, err := smime.NormalizeEmail(e); err == nil {
			sans = append(sans, m)
		}
	}
	inSAN := func(m smime.Mailbox) bool {
		for _, s := range sans {
			if s.Equal(m) {
				return true
			}
		}
		return false
	}

	for _, v := range subjectEmailAttributes(cert) {
		m, err := smime.NormalizeEmail(v)
		if err != nil {
			add(CheckSMIMESubjectEmail, "subject emailAddress %q is not a valid mailbox address: %v", v, err)
			continue
		}
		if !inSAN(m) {
			add(CheckSMIMESubjectEmail, "subject emailAddress %q is not present among the rfc822Name SANs", v)
		}
	}

	// A common name is free-form (typically a personal name), but when it is
	// shaped like a mailbox it must be one of the certified addresses.
	if cn := strings.TrimSpace(cert.Subject.CommonName); strings.Contains(cn, "@") {
		if m, err := smime.NormalizeEmail(cn); err == nil && !inSAN(m) {
			add(CheckSMIMESubjectEmail, "common name %q is a mailbox address not present among the rfc822Name SANs", cn)
		}
	}
}

// subjectEmailAttributes extracts every PKCS#9 emailAddress attribute value
// from the subject, covering both a parsed certificate (Subject.Names) and a
// to-be-signed template (Subject.ExtraNames).
func subjectEmailAttributes(cert *x509.Certificate) []string {
	var out []string
	for _, atvs := range [][]pkix.AttributeTypeAndValue{cert.Subject.Names, cert.Subject.ExtraNames} {
		for _, atv := range atvs {
			if !atv.Type.Equal(oidEmailAddress) {
				continue
			}
			switch v := atv.Value.(type) {
			case string:
				out = append(out, v)
			case asn1.RawValue:
				out = append(out, string(v.Bytes))
			}
		}
	}
	return out
}
