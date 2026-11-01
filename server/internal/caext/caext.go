// Package caext models the X.509 v3 extension set a CA certificate carries.
//
// Creating a certificate authority is the one issuance decision that cannot be
// revised later: a root's extensions bind every certificate that will ever chain
// through it, and changing them means a new key and a new trust-store rollout.
// So the CA-creation path accepts the full common extension vocabulary rather
// than the handful crypto/x509 exposes on a template — Config below is that
// vocabulary, in the shape an operator writes it (JSON over the REST API, flags
// or a file on the CLI, a form in the console), and Build compiles it into the
// pieces internal/pki hands to the signer.
//
// The division of labour is deliberate:
//
//   - Config holds strings and is validated, never trusted. Every OID, DN,
//     duration and encoding is parsed here so a bad request fails before a key
//     is generated, not after.
//   - Built holds Go/ASN.1 values. The native fields are the ones crypto/x509
//     encodes correctly from its own template; Extensions carries everything
//     crypto/x509 cannot express, already DER-encoded. Because
//     x509.CreateCertificate lets ExtraExtensions win over its own generation
//     for the same OID, the two never collide.
//
// Name Constraints (2.5.29.30) and the certificate-policy family
// (2.5.29.32/.33/.36) are configured by their own long-standing packages
// (internal/nameconstraints, internal/certpolicy) and are not duplicated here;
// Config covers the rest, including an escape hatch (Custom) for any OID at all.
package caext

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// DefaultKeyUsages is the key-usage set a CA certificate gets when Config does
// not name one: certSign and crlSign because a CA signs subordinate certificates
// and CRLs, and digitalSignature so the same key may also sign OCSP responses
// directly (secsy-pki's default responder configuration).
var DefaultKeyUsages = []string{"certSign", "crlSign", "digitalSignature"}

// Config is the operator-facing X.509 extension set for a CA certificate. The
// zero value asks for the defaults: the usual CA key usages, basic constraints
// from the surrounding request's path length, and nothing else.
type Config struct {
	// KeyUsages replaces the default CA key-usage set. Accepted names are the
	// RFC 5280 §4.2.1.3 bits in either spelling: digitalSignature,
	// contentCommitment (nonRepudiation), keyEncipherment, dataEncipherment,
	// keyAgreement, certSign (keyCertSign), crlSign (cRLSign), encipherOnly,
	// decipherOnly. certSign is mandatory — a CA certificate without it cannot
	// sign the subordinate certificates that are the point of having it.
	KeyUsages []string `json:"key_usages,omitempty"`
	// ExtKeyUsages constrains what the certificates below this CA may be used
	// for (2.5.29.37). A conforming path validator intersects the EKUs down the
	// chain, so an intermediate carrying only serverAuth cannot be abused to
	// mint a code-signing certificate even if its own profile allows one — the
	// single most useful constraint on a delegated issuing CA. Names come from
	// ExtKeyUsageOIDs; a dotted OID is accepted for anything unlisted.
	ExtKeyUsages []string `json:"ext_key_usages,omitempty"`
	// ExtKeyUsageCritical marks extKeyUsage critical. RFC 5280 permits either;
	// critical is the stronger form (a validator that cannot process the
	// extension must reject the certificate) and is unusual on a CA.
	ExtKeyUsageCritical bool `json:"ext_key_usage_critical,omitempty"`

	// SubjectAltName emits subjectAltName (2.5.29.17) on the CA certificate.
	// Uncommon but legitimate: a directoryName or URI identifying the authority
	// itself, or a DNS name for a CA that also terminates TLS.
	SubjectAltName *GeneralNamesConfig `json:"subject_alt_name,omitempty"`
	// IssuerAltName emits issuerAltName (2.5.29.18), naming the issuer in a form
	// its DN cannot express.
	IssuerAltName *GeneralNamesConfig `json:"issuer_alt_name,omitempty"`

	// CRLDistributionPoints lists URIs at which this CA's own revocation status
	// is published by its parent (2.5.29.31). A root has none: nothing revokes
	// a self-signed trust anchor.
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
	// FreshestCRL lists delta-CRL URIs (2.5.29.46), the companion to
	// CRLDistributionPoints when the parent publishes deltas.
	FreshestCRL []string `json:"freshest_crl,omitempty"`
	// OCSPServers and CAIssuers populate authorityInfoAccess (id-ad-ocsp and
	// id-ad-caIssuers): where to check this CA certificate's revocation status,
	// and where to fetch its issuer so a relying party can complete the chain.
	OCSPServers []string `json:"ocsp_servers,omitempty"`
	CAIssuers   []string `json:"ca_issuers,omitempty"`
	// CARepositories and TimestampServers populate subjectInfoAccess
	// (id-ad-caRepository and id-ad-timeStamping): services this CA itself
	// offers — where it publishes the certificates it issues, and its TSA.
	CARepositories   []string `json:"ca_repositories,omitempty"`
	TimestampServers []string `json:"timestamp_servers,omitempty"`

	// InhibitAnyPolicy, when non-nil, emits id-ce-inhibitAnyPolicy (2.5.29.54):
	// the number of further certificates in the path for which the anyPolicy OID
	// still satisfies a policy requirement. 0 stops it immediately below this CA.
	// Always critical, as RFC 5280 §4.2.1.14 requires.
	InhibitAnyPolicy *int `json:"inhibit_any_policy,omitempty"`

	// PrivateKeyUsagePeriod narrows the window in which this CA's key may
	// *produce* signatures (2.5.29.16) to less than the certificate's validity,
	// so the key can be retired while the certificates it signed stay verifiable.
	PrivateKeyUsagePeriod *PrivateKeyUsagePeriodConfig `json:"private_key_usage_period,omitempty"`

	// SubjectDirectoryAttributes emits id-ce-subjectDirectoryAttributes
	// (2.5.29.9): non-identifying directory attributes of the subject.
	SubjectDirectoryAttributes []AttributeConfig `json:"subject_directory_attributes,omitempty"`

	// MustStaple emits the RFC 7633 TLS Feature extension asserting
	// status_request. On a CA certificate it declares that every certificate
	// issued beneath it is expected to be served with a stapled OCSP response.
	MustStaple bool `json:"must_staple,omitempty"`
	// TLSFeatures lists raw RFC 7633 feature numbers, for features beyond
	// status_request (5). MustStaple is shorthand for including 5.
	TLSFeatures []int `json:"tls_features,omitempty"`

	// OCSPNoCheck emits id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1). It belongs
	// on a short-lived delegated OCSP-responder certificate, not on an issuing
	// CA; it is offered because a CA key that also answers OCSP directly is a
	// configuration some deployments choose.
	OCSPNoCheck bool `json:"ocsp_no_check,omitempty"`

	// NetscapeComment and NetscapeCertType emit the two legacy Netscape
	// extensions (2.16.840.1.113730.1.13 and .1.1). keyUsage and extKeyUsage
	// supersede them; they are here for old appliances that still read them.
	// NetscapeCertType names: sslClient, sslServer, sslCA, smime, smimeCA,
	// objsign, objCA.
	NetscapeComment  string   `json:"netscape_comment,omitempty"`
	NetscapeCertType []string `json:"netscape_cert_type,omitempty"`

	// SubjectKeyID overrides the subject key identifier (2.5.29.14) with these
	// exact bytes, given as hex (colons and spaces are ignored). Empty derives
	// it from the public key, which is what a conforming CA does; an explicit
	// value exists for reproducing an identifier a relying party already pins.
	SubjectKeyID string `json:"subject_key_id,omitempty"`

	// Custom carries any extension this struct does not model, by OID. It is the
	// reason "all common extensions" is not a closed list: an enterprise OID, a
	// national-scheme extension or a brand-new RFC can be stamped without a code
	// change.
	Custom []CustomExtension `json:"custom,omitempty"`
}

// GeneralNamesConfig is the string form of an RFC 5280 GeneralNames set, used
// for subjectAltName and issuerAltName.
type GeneralNamesConfig struct {
	DNS   []string `json:"dns,omitempty"`
	IP    []string `json:"ip,omitempty"`
	Email []string `json:"email,omitempty"`
	URI   []string `json:"uri,omitempty"`
	// UPN emits Microsoft/Kerberos User Principal Names as id-ms-UPN otherNames.
	UPN []string `json:"upn,omitempty"`
	// DirNames are directoryName entries as RFC 4514 DNs ("O=Acme,C=US").
	DirNames []string `json:"dir_names,omitempty"`
	// RegisteredIDs are registeredID entries as dotted OIDs.
	RegisteredIDs []string `json:"registered_ids,omitempty"`
	// OtherNames are otherName entries for any type-id at all.
	OtherNames []OtherNameConfig `json:"other_names,omitempty"`
	// Critical marks the extension critical. RFC 5280 requires a critical SAN
	// only when the subject DN is empty, which a CA's never is.
	Critical bool `json:"critical,omitempty"`
}

// IsZero reports whether the set names nothing.
func (g *GeneralNamesConfig) IsZero() bool {
	return g == nil || (len(g.DNS) == 0 && len(g.IP) == 0 && len(g.Email) == 0 &&
		len(g.URI) == 0 && len(g.UPN) == 0 && len(g.DirNames) == 0 &&
		len(g.RegisteredIDs) == 0 && len(g.OtherNames) == 0)
}

// OtherNameConfig is one GeneralName otherName: a type-id OID and a value in one
// of the encodings ValueEncodings names (default utf8).
type OtherNameConfig struct {
	OID      string `json:"oid"`
	Encoding string `json:"encoding,omitempty"`
	Value    string `json:"value"`
}

// AttributeConfig is one subjectDirectoryAttributes entry: an attribute type OID
// and one or more values sharing an encoding (default utf8).
type AttributeConfig struct {
	OID      string   `json:"oid"`
	Encoding string   `json:"encoding,omitempty"`
	Values   []string `json:"values"`
}

// CustomExtension is an arbitrary extension: an OID, a criticality, and a value
// in one of the encodings ValueEncodings names. The "der" encodings place the
// supplied bytes in the extension verbatim, which is how an extension whose
// syntax nothing here models is carried.
type CustomExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Value    string `json:"value,omitempty"`
}

// PrivateKeyUsagePeriodConfig narrows a CA key's signing window inside the
// certificate's validity (id-ce-privateKeyUsagePeriod, 2.5.29.16). Exactly one
// form may be used, mirroring the leaf-profile block of the same name:
//
//   - Duration: the key may sign for that long from the certificate notBefore
//     ("365d", "52w", "8760h", "1y").
//   - Fraction: for that fraction (0,1] of the certificate's lifetime — the
//     common "sign for the first third, then only validate" CA policy.
//   - NotBefore / NotAfter: explicit RFC 3339 instants (either or both).
//
// The resolved window is always clamped to the certificate's own validity.
type PrivateKeyUsagePeriodConfig struct {
	Duration  string  `json:"duration,omitempty"`
	Fraction  float64 `json:"fraction,omitempty"`
	NotBefore string  `json:"not_before,omitempty"`
	NotAfter  string  `json:"not_after,omitempty"`
}

// IsZero reports whether the Config asks for nothing beyond the defaults, so
// callers can pass a zero value unconditionally.
func (c *Config) IsZero() bool {
	if c == nil {
		return true
	}
	return len(c.KeyUsages) == 0 && len(c.ExtKeyUsages) == 0 && !c.ExtKeyUsageCritical &&
		c.SubjectAltName.IsZero() && c.IssuerAltName.IsZero() &&
		len(c.CRLDistributionPoints) == 0 && len(c.FreshestCRL) == 0 &&
		len(c.OCSPServers) == 0 && len(c.CAIssuers) == 0 &&
		len(c.CARepositories) == 0 && len(c.TimestampServers) == 0 &&
		c.InhibitAnyPolicy == nil && c.PrivateKeyUsagePeriod == nil &&
		len(c.SubjectDirectoryAttributes) == 0 &&
		!c.MustStaple && len(c.TLSFeatures) == 0 && !c.OCSPNoCheck &&
		strings.TrimSpace(c.NetscapeComment) == "" && len(c.NetscapeCertType) == 0 &&
		strings.TrimSpace(c.SubjectKeyID) == "" && len(c.Custom) == 0
}

// Built is a validated Config. The first group of fields is handed to the
// crypto/x509 certificate template, which encodes them correctly; Extensions
// holds the DER of everything crypto/x509 cannot express and is passed through
// ExtraExtensions.
type Built struct {
	// KeyUsage is the resolved key-usage bitmask (never zero: certSign is
	// required, and the default set applies when Config named none).
	KeyUsage x509.KeyUsage
	// SubjectKeyID, when non-empty, overrides the derived identifier.
	SubjectKeyID []byte
	// CRLDistributionPoints, OCSPServers and CAIssuers are emitted natively by
	// crypto/x509 as cRLDistributionPoints and authorityInfoAccess, both
	// non-critical as RFC 5280 requires.
	CRLDistributionPoints []string
	OCSPServers           []string
	CAIssuers             []string
	// Extensions is the hand-rolled set, in a stable order.
	Extensions []pkix.Extension
	// pkup is the resolved private-key usage period, applied once the
	// certificate's validity is known (see ApplyValidity).
	pkup *PrivateKeyUsagePeriodConfig
}

// Build validates the configuration and compiles it. It never partially applies:
// any error means nothing was emitted, so a caller can validate a request before
// generating a key.
//
// Extensions whose content depends on the certificate's validity window (the
// private-key usage period) are resolved later by ApplyValidity, because at
// Build time the notBefore/notAfter are not yet fixed.
func (c *Config) Build() (Built, error) {
	var b Built
	if c == nil {
		c = &Config{}
	}

	ku, err := buildKeyUsage(c.KeyUsages)
	if err != nil {
		return Built{}, err
	}
	b.KeyUsage = ku

	if len(c.ExtKeyUsages) > 0 {
		ekuOIDs, err := resolveExtKeyUsages(c.ExtKeyUsages)
		if err != nil {
			return Built{}, err
		}
		ext, err := extKeyUsageExtension(ekuOIDs, c.ExtKeyUsageCritical)
		if err != nil {
			return Built{}, err
		}
		b.Extensions = append(b.Extensions, ext)
	} else if c.ExtKeyUsageCritical {
		return Built{}, fmt.Errorf("ext_key_usage_critical is set but no ext_key_usages were given")
	}

	// A criticality with nothing to mark critical is a half-finished edit, not a
	// choice: the extension would be silently omitted, and the operator would
	// believe they had pinned something. Same rule as ext_key_usage_critical.
	if c.SubjectAltName != nil && c.SubjectAltName.Critical && c.SubjectAltName.IsZero() {
		return Built{}, fmt.Errorf("subject_alt_name is marked critical but names nothing")
	}
	if c.IssuerAltName != nil && c.IssuerAltName.Critical && c.IssuerAltName.IsZero() {
		return Built{}, fmt.Errorf("issuer_alt_name is marked critical but names nothing")
	}
	if !c.SubjectAltName.IsZero() {
		gn, err := c.SubjectAltName.build()
		if err != nil {
			return Built{}, fmt.Errorf("subject_alt_name: %w", err)
		}
		ext, err := pki.GeneralNamesExtension(pki.OIDSubjectAltName, c.SubjectAltName.Critical, gn)
		if err != nil {
			return Built{}, fmt.Errorf("subject_alt_name: %w", err)
		}
		b.Extensions = append(b.Extensions, ext)
	}
	if !c.IssuerAltName.IsZero() {
		gn, err := c.IssuerAltName.build()
		if err != nil {
			return Built{}, fmt.Errorf("issuer_alt_name: %w", err)
		}
		ext, err := pki.GeneralNamesExtension(pki.OIDIssuerAltName, c.IssuerAltName.Critical, gn)
		if err != nil {
			return Built{}, fmt.Errorf("issuer_alt_name: %w", err)
		}
		b.Extensions = append(b.Extensions, ext)
	}

	// trimAll drops blank entries rather than rejecting them: an empty textarea
	// in the console posts them, and "nothing configured" is the right reading.
	b.CRLDistributionPoints = trimAll(c.CRLDistributionPoints)
	b.OCSPServers = trimAll(c.OCSPServers)
	b.CAIssuers = trimAll(c.CAIssuers)

	if freshest := trimAll(c.FreshestCRL); len(freshest) > 0 {
		ext, err := pki.DistributionPointsExtension(pki.OIDFreshestCRL, freshest)
		if err != nil {
			return Built{}, err
		}
		b.Extensions = append(b.Extensions, ext)
	}

	var sia []pki.AccessDescription
	for _, u := range trimAll(c.CARepositories) {
		sia = append(sia, pki.AccessDescription{Method: pki.OIDAccessMethodCARepository, URI: u})
	}
	for _, u := range trimAll(c.TimestampServers) {
		sia = append(sia, pki.AccessDescription{Method: pki.OIDAccessMethodTimeStamping, URI: u})
	}
	if len(sia) > 0 {
		ext, err := pki.AccessSyntaxExtension(pki.OIDSubjectInfoAccess, sia)
		if err != nil {
			return Built{}, err
		}
		b.Extensions = append(b.Extensions, ext)
	}

	if c.InhibitAnyPolicy != nil {
		ext, err := pki.InhibitAnyPolicyExtension(*c.InhibitAnyPolicy)
		if err != nil {
			return Built{}, err
		}
		b.Extensions = append(b.Extensions, ext)
	}

	if len(c.SubjectDirectoryAttributes) > 0 {
		attrs := make([]pki.DirectoryAttribute, 0, len(c.SubjectDirectoryAttributes))
		for i, a := range c.SubjectDirectoryAttributes {
			oid, err := ParseOID(a.OID)
			if err != nil {
				return Built{}, fmt.Errorf("subject_directory_attributes[%d]: %w", i, err)
			}
			if len(a.Values) == 0 {
				return Built{}, fmt.Errorf("subject_directory_attributes[%d] (%s): at least one value is required", i, a.OID)
			}
			values := make([][]byte, 0, len(a.Values))
			for j, v := range a.Values {
				der, err := EncodeValue(a.Encoding, v)
				if err != nil {
					return Built{}, fmt.Errorf("subject_directory_attributes[%d].values[%d]: %w", i, j, err)
				}
				values = append(values, der)
			}
			attrs = append(attrs, pki.DirectoryAttribute{Type: oid, Values: values})
		}
		ext, err := pki.SubjectDirectoryAttributesExtension(attrs)
		if err != nil {
			return Built{}, err
		}
		b.Extensions = append(b.Extensions, ext)
	}

	if features := tlsFeatures(c); len(features) > 0 {
		ext, err := pki.TLSFeatureExtension(features...)
		if err != nil {
			return Built{}, err
		}
		b.Extensions = append(b.Extensions, ext)
	}

	if c.OCSPNoCheck {
		b.Extensions = append(b.Extensions, pki.OCSPNoCheckExtension())
	}

	if comment := strings.TrimSpace(c.NetscapeComment); comment != "" {
		ext, err := pki.NetscapeCommentExtension(comment)
		if err != nil {
			return Built{}, err
		}
		b.Extensions = append(b.Extensions, ext)
	}
	if len(c.NetscapeCertType) > 0 {
		bits := make([]int, 0, len(c.NetscapeCertType))
		for _, name := range c.NetscapeCertType {
			bit, ok := pki.NetscapeCertTypeFromString[strings.TrimSpace(name)]
			if !ok {
				return Built{}, fmt.Errorf("unknown netscape cert type %q (want one of sslClient, sslServer, sslCA, smime, smimeCA, objsign, objCA)", name)
			}
			bits = append(bits, bit)
		}
		ext, err := pki.NetscapeCertTypeExtension(bits)
		if err != nil {
			return Built{}, err
		}
		b.Extensions = append(b.Extensions, ext)
	}

	if ski := strings.TrimSpace(c.SubjectKeyID); ski != "" {
		raw, err := parseHexBytes(ski)
		if err != nil {
			return Built{}, fmt.Errorf("subject_key_id: %w", err)
		}
		if len(raw) == 0 {
			return Built{}, fmt.Errorf("subject_key_id: no bytes given")
		}
		b.SubjectKeyID = raw
	}

	for i, ce := range c.Custom {
		oid, err := ParseOID(ce.OID)
		if err != nil {
			return Built{}, fmt.Errorf("custom[%d]: %w", i, err)
		}
		value, err := EncodeValue(ce.Encoding, ce.Value)
		if err != nil {
			return Built{}, fmt.Errorf("custom[%d] (%s): %w", i, ce.OID, err)
		}
		b.Extensions = append(b.Extensions, pkix.Extension{Id: oid, Critical: ce.Critical, Value: value})
	}

	if c.PrivateKeyUsagePeriod != nil {
		if err := c.PrivateKeyUsagePeriod.validate(); err != nil {
			return Built{}, err
		}
		b.pkup = c.PrivateKeyUsagePeriod
	}

	if err := checkDuplicateOIDs(b.Extensions); err != nil {
		return Built{}, err
	}
	return b, nil
}

// ApplyValidity resolves the extensions whose content depends on the
// certificate's validity window and appends them. It is called by the CA layer
// once notBefore/notAfter are fixed, and is a no-op when none were configured.
func (b *Built) ApplyValidity(notBefore, notAfter time.Time) error {
	if b.pkup == nil {
		return nil
	}
	pkup, err := b.pkup.resolve(notBefore, notAfter)
	if err != nil {
		return err
	}
	ext, err := pkup.Extension()
	if err != nil {
		return err
	}
	b.Extensions = append(b.Extensions, ext)
	b.pkup = nil
	return checkDuplicateOIDs(b.Extensions)
}

// buildKeyUsage resolves the configured key-usage names, falling back to the CA
// default set. certSign is mandatory: a CA certificate that cannot sign
// certificates is not a CA, and silently minting one would surface as an opaque
// path-validation failure much later.
func buildKeyUsage(names []string) (x509.KeyUsage, error) {
	if len(names) == 0 {
		names = DefaultKeyUsages
	}
	var ku x509.KeyUsage
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		v, ok := keyUsageAliases[name]
		if !ok {
			v, ok = pki.X509KeyUsageFromString[name]
		}
		if !ok {
			return 0, fmt.Errorf("unknown key usage %q", raw)
		}
		ku |= v
	}
	if ku == 0 {
		return 0, fmt.Errorf("key_usages names no usage")
	}
	if ku&x509.KeyUsageCertSign == 0 {
		return 0, fmt.Errorf("key_usages must include certSign for a CA certificate")
	}
	return ku, nil
}

// keyUsageAliases accepts the RFC 5280 ASN.1 spellings alongside the shorter
// names internal/pki uses, so an operator transcribing from the RFC or from an
// OpenSSL config is not told their input is unknown.
var keyUsageAliases = map[string]x509.KeyUsage{
	"nonRepudiation": x509.KeyUsageContentCommitment,
	"keyCertSign":    x509.KeyUsageCertSign,
	"cRLSign":        x509.KeyUsageCRLSign,
}

// tlsFeatures merges the MustStaple shorthand with any explicit feature numbers,
// de-duplicating while preserving order.
func tlsFeatures(c *Config) []int {
	var out []int
	seen := map[int]bool{}
	add := func(f int) {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if c.MustStaple {
		add(5) // status_request
	}
	for _, f := range c.TLSFeatures {
		add(f)
	}
	return out
}

// build converts the string form of a GeneralNames set into the encodable form,
// validating every entry.
func (g *GeneralNamesConfig) build() (pki.GeneralNames, error) {
	var out pki.GeneralNames
	for _, u := range g.UPN {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		on, err := pki.OtherNameUTF8(pki.OIDUserPrincipalName, u)
		if err != nil {
			return pki.GeneralNames{}, err
		}
		out.OtherNames = append(out.OtherNames, on)
	}
	for i, on := range g.OtherNames {
		oid, err := ParseOID(on.OID)
		if err != nil {
			return pki.GeneralNames{}, fmt.Errorf("other_names[%d]: %w", i, err)
		}
		value, err := EncodeValue(on.Encoding, on.Value)
		if err != nil {
			return pki.GeneralNames{}, fmt.Errorf("other_names[%d] (%s): %w", i, on.OID, err)
		}
		out.OtherNames = append(out.OtherNames, pki.OtherName{TypeID: oid, Value: value})
	}
	out.Emails = trimAll(g.Email)
	out.DNSNames = trimAll(g.DNS)
	out.URIs = trimAll(g.URI)
	for _, raw := range trimAll(g.IP) {
		ip := net.ParseIP(raw)
		if ip == nil {
			return pki.GeneralNames{}, fmt.Errorf("invalid IP address %q", raw)
		}
		out.IPs = append(out.IPs, ip)
	}
	for _, raw := range trimAll(g.DirNames) {
		rdns, err := nameconstraints.ParseDNSequence(raw)
		if err != nil {
			return pki.GeneralNames{}, err
		}
		out.DirNames = append(out.DirNames, rdns)
	}
	for _, raw := range trimAll(g.RegisteredIDs) {
		oid, err := ParseOID(raw)
		if err != nil {
			return pki.GeneralNames{}, fmt.Errorf("registered_ids: %w", err)
		}
		out.RegisteredIDs = append(out.RegisteredIDs, oid)
	}
	if out.IsEmpty() {
		return pki.GeneralNames{}, fmt.Errorf("no general names given")
	}
	return out, nil
}

// validate checks a private-key usage period block names exactly one form and
// that its values parse.
func (p *PrivateKeyUsagePeriodConfig) validate() error {
	if p == nil {
		return nil
	}
	modes := 0
	if strings.TrimSpace(p.Duration) != "" {
		modes++
	}
	if p.Fraction != 0 {
		modes++
	}
	if strings.TrimSpace(p.NotBefore) != "" || strings.TrimSpace(p.NotAfter) != "" {
		modes++
	}
	switch {
	case modes == 0:
		return fmt.Errorf("private_key_usage_period: set one of duration, fraction, or not_before/not_after")
	case modes > 1:
		return fmt.Errorf("private_key_usage_period: set only one of duration, fraction, or not_before/not_after")
	}
	if s := strings.TrimSpace(p.Duration); s != "" {
		d, err := ParseFlexibleDuration(s)
		if err != nil {
			return fmt.Errorf("private_key_usage_period duration: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("private_key_usage_period duration must be positive (got %q)", s)
		}
	}
	if p.Fraction != 0 && (p.Fraction < 0 || p.Fraction > 1) {
		return fmt.Errorf("private_key_usage_period fraction must be in (0,1] (got %v)", p.Fraction)
	}
	if s := strings.TrimSpace(p.NotBefore); s != "" {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return fmt.Errorf("private_key_usage_period not_before: %w", err)
		}
	}
	if s := strings.TrimSpace(p.NotAfter); s != "" {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return fmt.Errorf("private_key_usage_period not_after: %w", err)
		}
	}
	return nil
}

// resolve turns the block into an absolute window, clamped to the certificate's
// validity so the key can never be declared usable outside it.
func (p *PrivateKeyUsagePeriodConfig) resolve(certNotBefore, certNotAfter time.Time) (pki.PrivateKeyUsagePeriod, error) {
	var out pki.PrivateKeyUsagePeriod
	switch {
	case strings.TrimSpace(p.Duration) != "":
		d, err := ParseFlexibleDuration(strings.TrimSpace(p.Duration))
		if err != nil {
			return out, fmt.Errorf("private_key_usage_period duration: %w", err)
		}
		out.NotBefore = certNotBefore
		out.NotAfter = certNotBefore.Add(d)
	case p.Fraction != 0:
		out.NotBefore = certNotBefore
		out.NotAfter = certNotBefore.Add(time.Duration(float64(certNotAfter.Sub(certNotBefore)) * p.Fraction))
	default:
		if s := strings.TrimSpace(p.NotBefore); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return out, fmt.Errorf("private_key_usage_period not_before: %w", err)
			}
			out.NotBefore = t
		}
		if s := strings.TrimSpace(p.NotAfter); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return out, fmt.Errorf("private_key_usage_period not_after: %w", err)
			}
			out.NotAfter = t
		}
	}
	// Clamp to the certificate's own validity.
	if !out.NotBefore.IsZero() && out.NotBefore.Before(certNotBefore) {
		out.NotBefore = certNotBefore
	}
	if !out.NotAfter.IsZero() && out.NotAfter.After(certNotAfter) {
		out.NotAfter = certNotAfter
	}
	if out.IsZero() {
		return out, fmt.Errorf("private_key_usage_period resolved to an empty window")
	}
	if !out.NotBefore.IsZero() && !out.NotAfter.IsZero() && out.NotAfter.Before(out.NotBefore) {
		return out, fmt.Errorf("private_key_usage_period not_after (%s) precedes not_before (%s)",
			out.NotAfter.UTC().Format(time.RFC3339), out.NotBefore.UTC().Format(time.RFC3339))
	}
	return out, nil
}

// extKeyUsageExtension hand-rolls extKeyUsage (2.5.29.37) from resolved OIDs.
// crypto/x509 can emit this extension, but only ever non-critical and only for
// the usages it has constants for; encoding it here keeps one code path and lets
// the criticality be chosen.
func extKeyUsageExtension(oids []asn1.ObjectIdentifier, critical bool) (pkix.Extension, error) {
	if len(oids) == 0 {
		return pkix.Extension{}, fmt.Errorf("extKeyUsage requires at least one usage")
	}
	value, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding extKeyUsage: %w", err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: critical, Value: value}, nil
}

// resolveExtKeyUsages maps operator-facing EKU names (or dotted OIDs) to OIDs,
// rejecting duplicates so the emitted extension is well formed.
func resolveExtKeyUsages(names []string) ([]asn1.ObjectIdentifier, error) {
	out := make([]asn1.ObjectIdentifier, 0, len(names))
	seen := map[string]bool{}
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		oid, ok := ExtKeyUsageOIDs[name]
		if !ok {
			var err error
			if oid, err = ParseOID(name); err != nil {
				return nil, fmt.Errorf("unknown extended key usage %q (give a known name or a dotted OID)", raw)
			}
		}
		if seen[oid.String()] {
			continue
		}
		seen[oid.String()] = true
		out = append(out, oid)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ext_key_usages names no usage")
	}
	return out, nil
}

// checkDuplicateOIDs rejects two extensions with the same OID: RFC 5280 §4.2
// forbids it, and crypto/x509 would emit both.
func checkDuplicateOIDs(exts []pkix.Extension) error {
	seen := map[string]bool{}
	for _, e := range exts {
		key := e.Id.String()
		if seen[key] {
			return fmt.Errorf("extension %s is configured twice", key)
		}
		seen[key] = true
	}
	return nil
}

// ParseOID parses a dotted object identifier. It requires at least two arcs, as
// every real OID has.
func ParseOID(s string) (asn1.ObjectIdentifier, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("an OID is required")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q: bad arc %q", s, p)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

// ValueEncodings lists the accepted encodings for an extension, otherName or
// directory-attribute value, in the order they are documented.
var ValueEncodings = []string{
	"utf8", "ia5", "printable", "oid", "int", "bool", "null",
	"octet-string", "bit-string", "der-hex", "der-base64",
}

// EncodeValue turns an operator-supplied string into the DER its encoding names.
// The "der-*" encodings carry the bytes verbatim, which is how an extension
// whose syntax nothing here models is stamped; everything else wraps the value
// in the named ASN.1 type. An empty encoding defaults to utf8, except that an
// empty value with an empty encoding is rejected rather than silently producing
// an empty UTF8String.
func EncodeValue(encoding, value string) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" {
		enc = "utf8"
	}
	switch enc {
	case "null":
		return []byte{0x05, 0x00}, nil
	case "der", "der-hex", "hex":
		raw, err := parseHexBytes(value)
		if err != nil {
			return nil, err
		}
		if err := checkCompleteDER(raw); err != nil {
			return nil, err
		}
		return raw, nil
	case "der-base64", "base64":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid base64 value: %w", err)
		}
		if err := checkCompleteDER(raw); err != nil {
			return nil, err
		}
		return raw, nil
	}
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("a value is required for encoding %q", enc)
	}
	switch enc {
	case "utf8", "utf8string":
		return asn1.MarshalWithParams(value, "utf8")
	case "ia5", "ia5string":
		return asn1.MarshalWithParams(value, "ia5")
	case "printable", "printablestring":
		return asn1.MarshalWithParams(value, "printable")
	case "oid", "objectidentifier":
		oid, err := ParseOID(value)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(oid)
	case "int", "integer":
		n := new(big.Int)
		if _, ok := n.SetString(strings.TrimSpace(value), 10); !ok {
			return nil, fmt.Errorf("invalid integer value %q", value)
		}
		return asn1.Marshal(n)
	case "bool", "boolean":
		b, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid boolean value %q", value)
		}
		return asn1.Marshal(b)
	case "octet-string", "octetstring", "octets":
		raw, err := parseHexBytes(value)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(raw)
	case "bit-string", "bitstring", "bits":
		raw, err := parseHexBytes(value)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(asn1.BitString{Bytes: raw, BitLength: len(raw) * 8})
	default:
		return nil, fmt.Errorf("unknown value encoding %q (want one of %s)", encoding, strings.Join(ValueEncodings, ", "))
	}
}

// checkCompleteDER rejects a verbatim value that is not a single complete DER
// element, which would make the certificate unparseable — the one mistake the
// "der-*" escape hatch makes easy, caught before a key is generated.
func checkCompleteDER(raw []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty DER value")
	}
	var probe asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &probe)
	if err != nil {
		return fmt.Errorf("value is not valid DER: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("value has %d trailing byte(s) after the first DER element", len(rest))
	}
	return nil
}

// parseHexBytes decodes hex that may be written with the colon, space or dash
// separators `openssl x509 -text` and packet dumps use.
func parseHexBytes(s string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ':', ' ', '-', '\n', '\r', '\t', '_':
			return -1
		}
		return r
	}, s)
	cleaned = strings.TrimPrefix(strings.TrimPrefix(cleaned, "0x"), "0X")
	if cleaned == "" {
		return nil, fmt.Errorf("empty hex value")
	}
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid hex value: %w", err)
	}
	return raw, nil
}

// ParseFlexibleDuration parses a duration that may use the day, week or year
// units time.ParseDuration lacks ("365d", "52w", "1y"), delegating anything else
// to time.ParseDuration ("8760h", "24h30m").
func ParseFlexibleDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	switch last := s[len(s)-1]; last {
	case 'd', 'D', 'w', 'W', 'y', 'Y':
		n, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		var unit time.Duration
		switch last {
		case 'd', 'D':
			unit = 24 * time.Hour
		case 'w', 'W':
			unit = 7 * 24 * time.Hour
		case 'y', 'Y':
			unit = 365 * 24 * time.Hour
		}
		return time.Duration(n * float64(unit)), nil
	default:
		return time.ParseDuration(s)
	}
}

// trimAll trims every entry and drops the empty ones.
func trimAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
