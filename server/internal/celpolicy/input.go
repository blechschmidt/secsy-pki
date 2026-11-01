// Package celpolicy is the CEL-based restriction engine for certificate
// generation: operator-written rules, evaluated before any HSM signature, that
// decide whether a certificate request may be certified and — when it may not —
// say why in words the requester can act on.
//
// # Why an expression language
//
// The declarative restrictions this PKI already enforces each answer one
// question well: a profile caps validity, a restriction set lists permitted SAN
// patterns, the issuing CA's Name Constraints bound the namespace, CAA asks the
// domain owner. What none of them can express is a *relationship between facts
// that live in different places* — "a wildcard is allowed only for a caller
// whose token carries the `pki.wildcard` entitlement", "the staging CA may only
// certify names under the requester's own department, which is encoded in its
// group membership", "a 2-year lifetime needs an `O=` that matches the tenant".
// Enumerating those as configuration fields means a new field, a new release,
// and a new deploy for every policy an enterprise invents.
//
// A CEL rule closes that gap without turning the configuration into a program.
// CEL is non-Turing-complete by construction: no loops, no recursion, no I/O,
// no mutation. A rule is a total function of the facts it is handed, it
// terminates, and its cost is bounded before it runs (see
// celexpr.DefaultCostLimit) — the properties that make it safe to evaluate
// operator-written text on the signing path, where an embedded interpreter
// would be a remote-code-execution surface.
//
// # What a rule sees
//
//	request    the certificate request: subject, every SAN type, requested
//	           validity, key, profile, and issuing CA — as a typed object, so a
//	           misspelled field is a load error rather than a denied issuance
//	jwt        the verified claim set of the presented token, by claim name
//	url        the HTTP request as an object: method, host, path, segments, query
//	path       that request's full path, for the common case
//	body       the decoded request body parameters, by name
//	principal  the authenticated caller: subject, roles, groups, tenants
//	now        evaluation time
//
// # What a rule says
//
// A rule's expression may yield a bool ("this condition must hold"), a string,
// or a list of strings. The string forms are the reason this engine exists in
// an enterprise PKI: a rule that returns text has *explained* the rejection,
// and that text travels to the requester in the API error. A rule that returns
// nothing to say is satisfied. See Rule for the shapes and Decision for how the
// verdicts combine.
//
// Every failure mode is a denial. An expression that errors at runtime, blows
// the cost ceiling, or returns an unusable type denies the request and names
// itself in the reason, unless the operator marked that rule fail-open.
package celpolicy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Variable names an expression references. They are constants because an
// activation that misses a *declared* variable fails only at evaluation —
// which, on this path, is a denied certificate.
const (
	VarRequest   = "request"
	VarJWT       = "jwt"
	VarURL       = "url"
	VarPath      = "path"
	VarBody      = "body"
	VarPrincipal = "principal"
	VarNow       = "now"
)

// Source names the issuance surface a request arrived on. An automated protocol
// carries no operator token, no JSON body and no console URL, so a rule that
// reasons about those facts must be able to tell which kind of request it is
// looking at rather than inferring it from an empty value.
const (
	SourceUnknown = "unknown"
	SourceREST    = "rest"
	SourceGRPC    = "grpc"
	SourceACME    = "acme"
	SourceEST     = "est"
	SourceSCEP    = "scep"
	SourceCMP     = "cmp"
	SourceWSTEP   = "wstep"
	SourceBulk    = "bulk"
	SourcePKCS12  = "pkcs12"
	SourceSPIFFE  = "spiffe"
	SourceCanary  = "canary"
	SourceCLI     = "cli"
	SourcePreview = "preview"
	// SourceRawSign is the legacy raw signing endpoint (/api/keys/{id}/sign-x509),
	// which hands a CA key a CSR directly rather than going through the issuance
	// path. It is named so a rule can treat it differently — it has no issuance
	// profile, so the profile-derived facts are empty — rather than having to
	// infer "this did not come from an issuance surface" from an absence.
	SourceRawSign = "rawsign"
)

// Operation names what is being asked of the CA.
const (
	OpIssue   = "issue"
	OpRenew   = "renew"
	OpPreview = "preview"
)

// CertRequest is the certificate request as a rule sees it: `request`.
//
// Every field is always present — this is a struct, not a claim map — so an
// expression needs no has() guard and a request that carries no e-mail SAN
// reads as an empty list rather than an error. The `cel` tags fix the
// vocabulary at snake_case so a rule reads like the JSON an API caller sent.
type CertRequest struct {
	// Source is the issuance surface (one of the Source* constants) and
	// Operation what is being asked (one of the Op* constants).
	Source    string `cel:"source" json:"source,omitempty"`
	Operation string `cel:"operation" json:"operation,omitempty"`

	// Profile is the requested issuance profile's name.
	Profile string `cel:"profile" json:"profile,omitempty"`
	// CA identifies the issuing authority.
	CA CAInfo `cel:"ca" json:"ca,omitempty"`
	// Subject is the requested distinguished name.
	Subject Subject `cel:"subject" json:"subject,omitempty"`

	// The subject alternative names, by type. DNSNames are as requested (not
	// lowercased) so a rule can reject a name on its presentation; IPAddresses
	// and URIs are rendered as strings, which is what ip()/cidr() and the string
	// functions consume.
	DNSNames       []string `cel:"dns_names" json:"dns_names,omitempty"`
	IPAddresses    []string `cel:"ip_addresses" json:"ip_addresses,omitempty"`
	EmailAddresses []string `cel:"email_addresses" json:"email_addresses,omitempty"`
	URIs           []string `cel:"uris" json:"uris,omitempty"`
	UPNs           []string `cel:"upns" json:"upns,omitempty"`
	// SANCount is the total number of subject alternative names of every type —
	// the cheap way to write a "one name per certificate" rule.
	SANCount int `cel:"san_count" json:"san_count,omitempty"`
	// Wildcard reports whether any requested DNS name is a wildcard ("*.x.y").
	Wildcard bool `cel:"wildcard" json:"wildcard,omitempty"`

	// KeyUsages and ExtKeyUsages are the usages the profile assigns, named as
	// the API and CLI name them ("digitalSignature", "serverAuth").
	KeyUsages    []string `cel:"key_usages" json:"key_usages,omitempty"`
	ExtKeyUsages []string `cel:"ext_key_usages" json:"ext_key_usages,omitempty"`
	// ExtensionOIDs lists the dotted OIDs of the extra extensions the template
	// carries at the point the gate runs.
	ExtensionOIDs []string `cel:"extension_oids" json:"extension_oids,omitempty"`

	// IsCA and MaxPathLen describe a request for a subordinate CA certificate.
	// MaxPathLen is -1 when the request sets none.
	IsCA       bool `cel:"is_ca" json:"is_ca,omitempty"`
	MaxPathLen int  `cel:"max_path_len" json:"max_path_len,omitempty"`
	// MustStaple is the resolved RFC 7633 OCSP Must-Staple decision.
	MustStaple bool `cel:"must_staple" json:"must_staple,omitempty"`

	// NotBefore / NotAfter bound the requested validity, Validity is the window
	// as a duration, and ValidityDays the same rounded up to whole days — the
	// unit an operator writes a lifetime ceiling in.
	NotBefore    time.Time     `cel:"not_before" json:"not_before,omitempty"`
	NotAfter     time.Time     `cel:"not_after" json:"not_after,omitempty"`
	Validity     time.Duration `cel:"validity" json:"validity,omitempty"`
	ValidityDays int           `cel:"validity_days" json:"validity_days,omitempty"`

	// Key describes the subject public key being certified.
	Key KeyInfo `cel:"key" json:"key,omitempty"`
	// Algorithm is the signature-scheme family of the profile: "classical",
	// "pqc" or "hybrid".
	Algorithm string `cel:"algorithm" json:"algorithm,omitempty"`
	// Serial is the allocated certificate serial in decimal, empty when the gate
	// runs before allocation (a preview).
	Serial string `cel:"serial" json:"serial,omitempty"`
	// RequestedBy is the identity the issuance was attributed to. It is the
	// principal's subject for an authenticated API call and a protocol-specific
	// account identifier otherwise.
	RequestedBy string `cel:"requested_by" json:"requested_by,omitempty"`
}

// CAInfo identifies the issuing authority: `request.ca`.
type CAInfo struct {
	ID    string `cel:"id" json:"id,omitempty"`
	Label string `cel:"label" json:"label,omitempty"`
	// Tenant is the CA's tenant id, empty for a platform-level CA.
	Tenant string `cel:"tenant" json:"tenant,omitempty"`
	// Subject is the CA's own distinguished name in RFC 2253 form.
	Subject string `cel:"subject" json:"subject,omitempty"`
	// NotAfter is when the CA certificate itself expires.
	NotAfter time.Time `cel:"not_after" json:"not_after,omitempty"`
}

// Subject is a requested distinguished name: `request.subject`.
type Subject struct {
	CommonName         string   `cel:"common_name" json:"common_name,omitempty"`
	Organization       []string `cel:"organization" json:"organization,omitempty"`
	OrganizationalUnit []string `cel:"organizational_unit" json:"organizational_unit,omitempty"`
	Country            []string `cel:"country" json:"country,omitempty"`
	Locality           []string `cel:"locality" json:"locality,omitempty"`
	Province           []string `cel:"province" json:"province,omitempty"`
	StreetAddress      []string `cel:"street_address" json:"street_address,omitempty"`
	PostalCode         []string `cel:"postal_code" json:"postal_code,omitempty"`
	SerialNumber       string   `cel:"serial_number" json:"serial_number,omitempty"`
	// DN is the whole name in RFC 2253 form, for a rule that would rather match
	// the string than enumerate the attributes.
	DN string `cel:"dn" json:"dn,omitempty"`
}

// KeyInfo describes the subject public key: `request.key`.
type KeyInfo struct {
	// Algorithm is "RSA", "ECDSA", "Ed25519", "ML-DSA", or "unknown".
	Algorithm string `cel:"algorithm" json:"algorithm,omitempty"`
	// Size is the RSA modulus size in bits, or the curve size for ECDSA; 0 when
	// the notion does not apply.
	Size int `cel:"size" json:"size,omitempty"`
	// Curve is the ECDSA curve name ("P-256"), empty otherwise.
	Curve string `cel:"curve" json:"curve,omitempty"`
	// Fingerprint is the SubjectPublicKeyInfo SHA-256 fingerprint in the
	// "SHA256:<base64>" form the blocklist and the inventory search use.
	Fingerprint string `cel:"fingerprint" json:"fingerprint,omitempty"`
}

// Principal is the authenticated caller: `principal`.
type Principal struct {
	Subject       string `cel:"subject" json:"subject,omitempty"`
	Email         string `cel:"email" json:"email,omitempty"`
	EmailVerified bool   `cel:"email_verified" json:"email_verified,omitempty"`
	Name          string `cel:"name" json:"name,omitempty"`
	// Roles are the platform-wide RBAC roles; TenantRoles maps a tenant id to
	// the roles held within it, and Tenants is just that map's keys.
	Roles       []string            `cel:"roles" json:"roles,omitempty"`
	TenantRoles map[string][]string `cel:"tenant_roles" json:"tenant_roles,omitempty"`
	Tenants     []string            `cel:"tenants" json:"tenants,omitempty"`
	// Groups are the identity provider's asserted group memberships.
	Groups []string `cel:"groups" json:"groups,omitempty"`
	IsRoot bool     `cel:"is_root" json:"is_root,omitempty"`
	// AuthProvider names the configured provider that authenticated the caller.
	AuthProvider string `cel:"auth_provider" json:"auth_provider,omitempty"`
	// Authenticated is false when the request carried no operator identity at
	// all — an automated protocol enrollment. A rule that requires an
	// entitlement should check it rather than reasoning about empty roles.
	Authenticated bool `cel:"authenticated" json:"authenticated,omitempty"`
}

// RequestURL is the HTTP request as an object: `url`.
type RequestURL struct {
	Method string `cel:"method" json:"method,omitempty"`
	// Full is the reconstructed absolute URL, as far as the request reveals it.
	Full   string `cel:"full" json:"full,omitempty"`
	Scheme string `cel:"scheme" json:"scheme,omitempty"`
	Host   string `cel:"host" json:"host,omitempty"`
	Port   string `cel:"port" json:"port,omitempty"`
	// Path is the request path and Segments its non-empty slash-separated
	// components, so a rule can address one without splitting the string.
	Path     string   `cel:"path" json:"path,omitempty"`
	Segments []string `cel:"segments" json:"segments,omitempty"`
	RawQuery string   `cel:"raw_query" json:"raw_query,omitempty"`
	// Query maps each query parameter to all of its values.
	Query map[string][]string `cel:"query" json:"query,omitempty"`
	// ClientIP is the peer address the request arrived from, without a port.
	ClientIP string `cel:"client_ip" json:"client_ip,omitempty"`
	// Present is false when the request did not arrive over HTTP, which is how a
	// rule distinguishes "no such URL" from "a URL whose fields are empty".
	Present bool `cel:"present" json:"present,omitempty"`
}

// Input is the complete fact set a rule is evaluated against. Build the
// activation with Activation so every declared variable is populated.
type Input struct {
	Request   CertRequest            `json:"request"`
	JWT       map[string]interface{} `json:"jwt,omitempty"`
	URL       RequestURL             `json:"url,omitempty"`
	Body      map[string]interface{} `json:"body,omitempty"`
	Principal Principal              `json:"principal,omitempty"`
	Now       time.Time              `json:"now,omitempty"`
}

// Activation renders the input as a CEL activation. Every variable the
// environment declares is present, with an empty map or a zero-valued object
// where the request carries nothing: a rule is a function of a complete input,
// never of a partial one.
func (in Input) Activation() map[string]interface{} {
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	jwt := in.JWT
	if jwt == nil {
		jwt = map[string]interface{}{}
	}
	body := in.Body
	if body == nil {
		body = map[string]interface{}{}
	}
	return map[string]interface{}{
		VarRequest:   in.Request.normalized(),
		VarJWT:       jwt,
		VarURL:       in.URL.normalized(),
		VarPath:      in.URL.Path,
		VarBody:      body,
		VarPrincipal: in.Principal.normalized(),
		VarNow:       now,
	}
}

// normalized replaces nil slices with empty ones. cel-go renders a nil Go slice
// as an empty list either way, but materializing it keeps size() and the
// comprehension macros on a value the test suite can compare directly, and
// documents that "absent" is spelled "empty" throughout this input.
func (r CertRequest) normalized() CertRequest {
	r.DNSNames = orEmpty(r.DNSNames)
	r.IPAddresses = orEmpty(r.IPAddresses)
	r.EmailAddresses = orEmpty(r.EmailAddresses)
	r.URIs = orEmpty(r.URIs)
	r.UPNs = orEmpty(r.UPNs)
	r.KeyUsages = orEmpty(r.KeyUsages)
	r.ExtKeyUsages = orEmpty(r.ExtKeyUsages)
	r.ExtensionOIDs = orEmpty(r.ExtensionOIDs)
	r.Subject.Organization = orEmpty(r.Subject.Organization)
	r.Subject.OrganizationalUnit = orEmpty(r.Subject.OrganizationalUnit)
	r.Subject.Country = orEmpty(r.Subject.Country)
	r.Subject.Locality = orEmpty(r.Subject.Locality)
	r.Subject.Province = orEmpty(r.Subject.Province)
	r.Subject.StreetAddress = orEmpty(r.Subject.StreetAddress)
	r.Subject.PostalCode = orEmpty(r.Subject.PostalCode)
	if r.Source == "" {
		r.Source = SourceUnknown
	}
	if r.Operation == "" {
		r.Operation = OpIssue
	}
	return r
}

func (u RequestURL) normalized() RequestURL {
	u.Segments = orEmpty(u.Segments)
	if u.Query == nil {
		u.Query = map[string][]string{}
	}
	return u
}

func (p Principal) normalized() Principal {
	p.Roles = orEmpty(p.Roles)
	p.Groups = orEmpty(p.Groups)
	p.Tenants = orEmpty(p.Tenants)
	if p.TenantRoles == nil {
		p.TenantRoles = map[string][]string{}
	}
	return p
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// FromLeafRequest builds the request facts from a pki.LeafCertRequest — the
// to-be-signed template every issuance surface converges on. Deriving the facts
// from the template rather than from each surface's own request shape is what
// keeps the engine's view identical whether the request arrived over REST, ACME,
// EST, SCEP, CMP or the CLI: a rule cannot be true of the JSON and false of the
// certificate.
func FromLeafRequest(base pki.LeafCertRequest) CertRequest {
	r := CertRequest{
		Subject:        subjectOf(base.Subject),
		DNSNames:       base.DNSNames,
		EmailAddresses: base.EmailAddresses,
		URIs:           base.URIs,
		UPNs:           base.UPNs,
		KeyUsages:      pki.KeyUsageNames(base.KeyUsage),
		ExtKeyUsages:   pki.ExtKeyUsageNames(base.ExtKeyUsage),
		IsCA:           base.IsCA,
		MaxPathLen:     -1,
		NotBefore:      base.NotBefore.UTC(),
		NotAfter:       base.NotAfter.UTC(),
		Key:            keyInfoOf(base.PublicKey),
	}
	for _, ip := range base.IPAddresses {
		r.IPAddresses = append(r.IPAddresses, ip.String())
	}
	for _, oid := range base.UnknownExtKeyUsage {
		r.ExtKeyUsages = append(r.ExtKeyUsages, oid.String())
	}
	for _, e := range base.ExtraExtensions {
		r.ExtensionOIDs = append(r.ExtensionOIDs, e.Id.String())
	}
	if base.MaxPathLen != nil {
		r.MaxPathLen = *base.MaxPathLen
	}
	if base.Serial != nil {
		r.Serial = base.Serial.String()
	}
	r.SANCount = len(r.DNSNames) + len(r.IPAddresses) + len(r.EmailAddresses) + len(r.URIs) + len(r.UPNs)
	for _, d := range r.DNSNames {
		if strings.HasPrefix(d, "*.") {
			r.Wildcard = true
			break
		}
	}
	if !base.NotAfter.IsZero() && !base.NotBefore.IsZero() && base.NotAfter.After(base.NotBefore) {
		r.Validity = base.NotAfter.Sub(base.NotBefore)
		// Whole days, truncated — the same arithmetic the preview response and the
		// API's validity_days use (see ca.durationDays). Agreement matters more
		// than precision here: a template's notBefore is backdated by a few minutes
		// of clock skew, so a 90-day request spans 90 days and change, and a rule
		// written `validity_days <= 90` must not refuse the very request the
		// profile was configured to allow. An operator who needs the exact window
		// has request.validity, which is a duration.
		r.ValidityDays = int(r.Validity / (24 * time.Hour))
	}
	return r
}

// subjectOf renders a pkix.Name as the Subject object, including the RFC 2253
// string form a rule may prefer to match whole.
func subjectOf(n pkix.Name) Subject {
	return Subject{
		CommonName:         n.CommonName,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Country:            n.Country,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
		DN:                 n.String(),
	}
}

// keyInfoOf describes a public key for the engine: family, size, curve, and the
// SPKI fingerprint. An unrecognized key type is reported as "unknown" with a
// zero size rather than omitted, so a rule requiring a minimum size denies it.
func keyInfoOf(pub interface{}) KeyInfo {
	k := KeyInfo{Algorithm: "unknown"}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		k.Algorithm, k.Size = "RSA", key.N.BitLen()
	case *ecdsa.PublicKey:
		k.Algorithm = "ECDSA"
		if key.Curve != nil {
			k.Size = key.Curve.Params().BitSize
			k.Curve = curveName(key.Curve)
		}
	case ed25519.PublicKey:
		k.Algorithm, k.Size = "Ed25519", 256
	case nil:
		return k
	}
	if pub != nil {
		if fp, err := keycheck.Fingerprint(pub); err == nil {
			k.Fingerprint = fp
		}
	}
	return k
}

// curveName names a NIST curve the way a certificate profile does.
func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	}
	if p := c.Params(); p != nil {
		return p.Name
	}
	return ""
}

// FromCSR fills in the request facts a CSR carries, for the surfaces that hold a
// parsed CSR before a template exists (the preview and approval paths).
func FromCSR(csr *x509.CertificateRequest) CertRequest {
	if csr == nil {
		return CertRequest{MaxPathLen: -1}
	}
	return FromLeafRequest(pki.LeafCertRequest{
		Subject:        csr.Subject,
		PublicKey:      csr.PublicKey,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           uriStrings(csr),
	})
}

func uriStrings(csr *x509.CertificateRequest) []string {
	out := make([]string, 0, len(csr.URIs))
	for _, u := range csr.URIs {
		out = append(out, u.String())
	}
	return out
}

// PrincipalFrom renders an authenticated caller for the engine. A nil info is an
// unauthenticated request (an automated protocol enrollment), which is reported
// as such rather than as an operator with no roles.
func PrincipalFrom(subject, email, name string, emailVerified, isRoot bool, roles, groups []string, tenantRoles map[string][]string, provider string) Principal {
	p := Principal{
		Subject:       subject,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Roles:         roles,
		Groups:        groups,
		TenantRoles:   tenantRoles,
		IsRoot:        isRoot,
		AuthProvider:  provider,
		Authenticated: true,
	}
	for t := range tenantRoles {
		p.Tenants = append(p.Tenants, t)
	}
	sort.Strings(p.Tenants)
	return p
}

// URLFrom renders an inbound HTTP request as the url object. The scheme and host
// are reconstructed from the request the way a server sees it (r.URL carries
// neither for a server-side request), and the client address is stripped of its
// ephemeral port so a rule can hand it to ip() or cidr().containsIP().
func URLFrom(r *http.Request) RequestURL {
	if r == nil {
		return RequestURL{}
	}
	u := RequestURL{
		Method:   r.Method,
		Scheme:   schemeOf(r),
		Host:     hostOnly(r.Host),
		Port:     portOnly(r.Host),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Query:    map[string][]string(r.URL.Query()),
		ClientIP: clientIP(r),
		Present:  true,
	}
	for _, seg := range strings.Split(strings.Trim(r.URL.Path, "/"), "/") {
		if seg != "" {
			u.Segments = append(u.Segments, seg)
		}
	}
	full := url.URL{Scheme: u.Scheme, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	u.Full = full.String()
	return u
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	return "http"
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func portOnly(hostport string) string {
	if _, p, err := net.SplitHostPort(hostport); err == nil {
		return p
	}
	return ""
}

// clientIP returns the peer address without its port. It deliberately ignores
// X-Forwarded-For: a header a client can set must not be what an issuance rule
// trusts.
func clientIP(r *http.Request) string {
	if r.RemoteAddr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// ClaimSet renders a verified token's claims as the `jwt` fact map.
//
// It starts from the raw claim set — every claim the issuer asserted, which is
// what makes a rule able to inspect `jwt.groups` or `jwt.repository` without
// this PKI having to enumerate the entitlement vocabularies of every identity
// provider — and then fills in the four claims the verifier itself resolved
// (sub, email, iss, aud) so a rule can rely on them even when the raw decode
// did not carry them in the shape CEL wants.
//
// Only verified claims must ever be passed here. A rule that tests
// `jwt.entitlements` is a security control exactly to the extent that the token
// was checked before it got here.
func ClaimSet(subject, email, issuer string, audience []string, raw map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(raw)+4)
	for k, v := range raw {
		out[k] = v
	}
	if subject != "" {
		out["sub"] = subject
	}
	if email != "" {
		out["email"] = email
	}
	if issuer != "" {
		out["iss"] = issuer
	}
	if len(audience) > 0 {
		// The audience is normalized to a list even when the token carried a bare
		// string, so `"x" in jwt.aud` is always a valid test. RFC 7519 permits both
		// forms, and a rule that had to handle both would be written wrong once.
		aud := make([]interface{}, 0, len(audience))
		for _, a := range audience {
			aud = append(aud, a)
		}
		out["aud"] = aud
	}
	return out
}
