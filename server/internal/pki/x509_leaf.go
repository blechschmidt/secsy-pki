package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

// LeafCertRequest describes an end-entity (leaf) certificate to be issued by a
// CA. Unlike CACertRequest it is never self-signed: an issuing CA certificate
// and its signer are always required so the resulting certificate chains to a
// real issuer (with a correct Authority Key Identifier).
type LeafCertRequest struct {
	// Subject is the distinguished name of the certificate holder.
	Subject pkix.Name
	// PublicKey is the subject's public key (typically taken from a CSR).
	PublicKey crypto.PublicKey
	// Serial is the certificate serial number. It must be positive and unique
	// within the issuing CA; callers should obtain it from a safe allocator.
	Serial *big.Int
	// NotBefore / NotAfter bound the certificate validity.
	NotBefore time.Time
	NotAfter  time.Time

	// KeyUsage is the X.509 key-usage bitmask (from a profile).
	KeyUsage x509.KeyUsage
	// ExtKeyUsage is the set of extended key usages (from a profile).
	ExtKeyUsage []x509.ExtKeyUsage
	// UnknownExtKeyUsage carries extended key usages that crypto/x509 has no enum
	// constant for (the Microsoft smartcard-logon and Kerberos PKINIT client-auth
	// EKUs). x509.CreateCertificate folds them into the same extKeyUsage extension
	// as ExtKeyUsage.
	UnknownExtKeyUsage []asn1.ObjectIdentifier

	// Subject Alternative Names.
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []string
	// UPNs are Microsoft/Kerberos User Principal Names ("user@REALM") emitted as
	// id-ms-UPN otherName SANs. crypto/x509 cannot encode an otherName, so when
	// UPNs are present leafTemplate hand-rolls the entire subjectAltName extension
	// (merging the other SAN types) and supplies it via ExtraExtensions.
	UPNs []string

	// CRLDistributionPoints and OCSPServer, when set, are embedded so relying
	// parties can locate revocation information for the certificate.
	CRLDistributionPoints []string
	OCSPServer            []string

	// IsCA and MaxPathLen allow a profile to mint a subordinate CA certificate
	// rather than a leaf. For ordinary end-entity certificates IsCA is false.
	IsCA       bool
	MaxPathLen *int

	// ExtraExtensions are appended verbatim after the built-in extensions. This
	// is how Certificate Transparency data is carried: the precertificate poison
	// extension, or the SCT list extension in the final certificate. Because they
	// are appended last, a precertificate and its final certificate differ only
	// in this trailing extension, keeping their TBSCertificates aligned for SCT
	// verification.
	ExtraExtensions []pkix.Extension
}

// CreateLeafCertificate builds and signs an X.509 end-entity certificate.
//
// issuer is the issuing CA's certificate and signer is that CA's key (which for
// an HSM-backed provider performs the signature on the device — the private key
// never leaves it). The issuer's Subject Key Identifier is copied into the leaf
// as its Authority Key Identifier by x509.CreateCertificate, and the leaf's own
// Subject Key Identifier is derived from its public key.
//
// The returned bytes are the DER encoding of the certificate.
func CreateLeafCertificate(signer crypto.Signer, issuer *x509.Certificate, req LeafCertRequest) ([]byte, error) {
	if issuer == nil {
		return nil, fmt.Errorf("leaf certificate requires an issuing CA certificate")
	}
	if signer == nil {
		return nil, fmt.Errorf("leaf certificate requires a signer")
	}
	if req.Serial == nil || req.Serial.Sign() <= 0 {
		return nil, fmt.Errorf("leaf certificate serial must be a positive integer")
	}
	if req.PublicKey == nil {
		return nil, fmt.Errorf("leaf certificate requires a subject public key")
	}
	if err := fips.CheckIssuance(signer.Public(), req.PublicKey); err != nil {
		return nil, err
	}
	if req.NotAfter.After(issuer.NotAfter) {
		return nil, fmt.Errorf("leaf certificate not_after (%s) exceeds issuer expiry (%s)", req.NotAfter, issuer.NotAfter)
	}

	template, err := leafTemplate(req)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, req.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("creating leaf certificate: %w", err)
	}
	return der, nil
}

// leafTemplate assembles the crypto/x509 template for a leaf certificate from a
// LeafCertRequest, computing the subject key identifier and parsing URI SANs. It
// is the single source of truth for the leaf template so both the real
// (HSM-signed) certificate and the throwaway linting certificate (see
// LintCertificateDER) share an identical TBSCertificate structure.
func leafTemplate(req LeafCertRequest) (*x509.Certificate, error) {
	if req.Serial == nil || req.Serial.Sign() <= 0 {
		return nil, fmt.Errorf("leaf certificate serial must be a positive integer")
	}
	if req.PublicKey == nil {
		return nil, fmt.Errorf("leaf certificate requires a subject public key")
	}
	if !req.NotAfter.After(req.NotBefore) {
		return nil, fmt.Errorf("leaf certificate not_after (%s) must be after not_before (%s)", req.NotAfter, req.NotBefore)
	}

	ski, err := subjectKeyID(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("computing subject key identifier: %w", err)
	}

	parsedURIs := make([]*url.URL, 0, len(req.URIs))
	for _, raw := range req.URIs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid URI SAN %q: %w", raw, err)
		}
		parsedURIs = append(parsedURIs, u)
	}

	template := &x509.Certificate{
		SerialNumber:          req.Serial,
		Subject:               req.Subject,
		NotBefore:             req.NotBefore,
		NotAfter:              req.NotAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		UnknownExtKeyUsage:    req.UnknownExtKeyUsage,
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
		EmailAddresses:        req.EmailAddresses,
		URIs:                  parsedURIs,
		CRLDistributionPoints: req.CRLDistributionPoints,
		OCSPServer:            req.OCSPServer,
		ExtraExtensions:       req.ExtraExtensions,
	}

	// When the leaf carries a UPN, hand-roll the whole subjectAltName extension
	// (crypto/x509 cannot emit an otherName). It merges every SAN type, is
	// prepended to ExtraExtensions so any Certificate-Transparency poison/SCT-list
	// extension stays the trailing one (keeping the precertificate and final
	// certificate TBSCertificates aligned), and the typed SAN fields are cleared
	// so x509.CreateCertificate does not also generate its own SAN extension.
	if len(req.UPNs) > 0 {
		sanExt, err := SubjectAltNameExtension(req.DNSNames, req.IPAddresses, req.EmailAddresses, req.URIs, req.UPNs, emptyASN1Subject(template))
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = append([]pkix.Extension{sanExt}, template.ExtraExtensions...)
		template.DNSNames = nil
		template.IPAddresses = nil
		template.EmailAddresses = nil
		template.URIs = nil
	}

	if req.IsCA {
		template.IsCA = true
		if req.MaxPathLen != nil {
			template.MaxPathLen = *req.MaxPathLen
			template.MaxPathLenZero = *req.MaxPathLen == 0
		}
	}
	return template, nil
}

// emptyASN1Subject reports whether the certificate's subject DN would encode to
// an empty RDNSequence, mirroring crypto/x509's own rule for marking the
// subjectAltName extension critical (RFC 5280 §4.2.1.6: SAN MUST be critical
// when the subject is empty).
func emptyASN1Subject(template *x509.Certificate) bool {
	if len(template.Subject.ExtraNames) > 0 {
		return false
	}
	der, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return false
	}
	// An empty RDNSequence encodes as the two bytes 30 00 (SEQUENCE, length 0).
	return len(der) == 2 && der[0] == 0x30 && der[1] == 0x00
}

// subjectKeyID derives an RFC 5280 §4.2.1.2 (method 1) subject key identifier:
// the SHA-1 hash of the subject public key's BIT STRING.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:], nil
}
