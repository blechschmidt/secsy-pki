package celpolicy

// The signing-restriction vocabulary (Task 224).
//
// Task 223 put the engine in front of certificate *generation*. It left every
// other signature this PKI produces with its HSM-held keys ungoverned: an
// OpenSSH certificate signed by an SSH CA, a CMS/CAdES signature over a release
// artifact, a raw signature over caller data with a named signing key. Those are
// the same act — a key the deployment is responsible for is asked to attest to
// something — and an enterprise that can say "this CA may not certify
// *.internal" has every reason to also say "this SSH CA may not sign a
// certificate whose principal is root", "this code-signing key is only for
// release pipelines" or "a detached signature over an artifact needs a
// countersigned timestamp".
//
// So the engine is the same engine: the same rule record, the same effects and
// modes, the same fail-closed reading, the same store, the same editors. Only
// the facts differ, which is what a rule's `kind` selects. A certificate rule
// reasons about `request`; a signing rule reasons about `signing` — and because
// they are separate environments, a signing rule that mentions `request.dns_names`
// does not compile, rather than quietly evaluating against an empty certificate.

import (
	"context"
	"crypto"
	"crypto/x509"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Variables a signing rule may reference. `jwt`, `url`, `path`, `body`,
// `principal` and `now` are shared with the certificate vocabulary — they are
// facts of the *request*, not of the certificate — so one editor, one capture
// middleware and one set of habits serve both kinds.
const (
	VarSigning = "signing"
)

// SigningOperation names what kind of signature is being asked for. A rule that
// restricts one operation must be able to say which, because the facts that are
// populated differ: an OpenSSH certificate has principals and a key ID, an
// artifact signature has a digest and a CAdES level, a raw signature has neither.
const (
	// OpSignSSHCert is an OpenSSH certificate signed by an SSH CA
	// (internal/sshca, and the legacy /api/keys/{id}/sign endpoint).
	OpSignSSHCert = "ssh-certificate"
	// OpSignArtifact is a CMS/PKCS#7 detached signature over a release artifact,
	// optionally countersigned by the RFC 3161 TSA (internal/signing).
	OpSignArtifact = "artifact"
	// OpSignData is a raw, application-level signature over caller data with a
	// named signing key (internal/secret).
	OpSignData = "data"
	// OpSignJWTSVID is a SPIFFE JWT-SVID: a short-lived bearer token minted and
	// signed with a CA's issuer key (internal/ca, JWT-SVID issuance). It is a
	// credential, not a certificate — nothing is recorded in the inventory and
	// no leaf template exists — so the certificate gate never sees it.
	OpSignJWTSVID = "jwt-svid"
)

// SigningOperations lists the operations in documentation order.
func SigningOperations() []string {
	return []string{OpSignSSHCert, OpSignArtifact, OpSignData, OpSignJWTSVID}
}

// SigningChecker is the gate a signing service consults before it uses a key.
//
// It is declared here, next to the facts, so internal/sshca, internal/signing
// and internal/secret can accept a gate without importing the package that
// implements it (internal/signpolicy, which pulls in the store, the audit log
// and the metrics registry). A nil SigningChecker permits everything: it means
// no rule store was wired, which is a different thing from a rule set that
// could not be read.
type SigningChecker interface {
	// CheckSigning returns a *DenyError when an enforcing rule refused the
	// operation, and a non-nil non-deny error when the rules could not be
	// evaluated at all — which callers must also treat as a refusal.
	CheckSigning(ctx context.Context, req SigningRequest) error
}

// Check consults an optional gate. It is the one-liner every signing service
// calls, so "a nil gate permits" is written once rather than at each site.
func Check(ctx context.Context, gate SigningChecker, req SigningRequest) error {
	if gate == nil {
		return nil
	}
	return gate.CheckSigning(ctx, req)
}

// SigningRequest is the signing operation as a rule sees it: `signing`.
//
// Like CertRequest it is a struct rather than a map, so every field is always
// present and a misspelled one is a compile error. The three per-operation fact
// groups (ssh, artifact, data) each carry a `present` flag: a rule that reads
// `signing.ssh.key_id` on an artifact signature sees the empty string, and
// `signing.ssh.present` is how it tells that apart from an SSH certificate whose
// key ID really is empty (which cannot happen, but the same reasoning applies to
// every optional group).
type SigningRequest struct {
	// Operation is one of the OpSign* constants and Source the surface the
	// request arrived on (one of the Source* constants).
	Operation string `cel:"operation" json:"operation,omitempty"`
	Source    string `cel:"source" json:"source,omitempty"`

	// Tenant is the tenant the signing key belongs to, empty for a
	// platform-level key.
	Tenant string `cel:"tenant" json:"tenant,omitempty"`
	// RequestedBy is the identity the signature is attributed to.
	RequestedBy string `cel:"requested_by" json:"requested_by,omitempty"`
	// Purpose is the free-text reason the caller supplied, where the surface
	// accepts one. Empty when it accepts none or the caller gave none.
	Purpose string `cel:"purpose" json:"purpose,omitempty"`

	// Key describes the key that would produce the signature.
	Key SigningKeyInfo `cel:"key" json:"key,omitempty"`
	// Payload describes what is being signed, as far as the surface reveals it.
	Payload PayloadInfo `cel:"payload" json:"payload,omitempty"`

	// SSH, Artifact, Data and JWTSVID hold the per-operation facts. Exactly one
	// has Present set; the others are zero.
	SSH      SSHCertInfo  `cel:"ssh" json:"ssh,omitempty"`
	Artifact ArtifactInfo `cel:"artifact" json:"artifact,omitempty"`
	Data     DataInfo     `cel:"data" json:"data,omitempty"`
	JWTSVID  JWTSVIDInfo  `cel:"jwt_svid" json:"jwt_svid,omitempty"`
}

// SigningKeyInfo describes the key a signature would be made with:
// `signing.key`.
type SigningKeyInfo struct {
	// Name is how the caller addressed the key: the signer name for an artifact
	// signature, the signing-key name for a raw signature, the CA label for an
	// SSH certificate.
	Name string `cel:"name" json:"name,omitempty"`
	// Label is the key's label in the key provider, and Ref its provider
	// reference (a PKCS#11 URI, a KMS key id) where one is recorded.
	Label string `cel:"label" json:"label,omitempty"`
	Ref   string `cel:"ref" json:"ref,omitempty"`
	// Algorithm is the signature algorithm family or the stored algorithm
	// identifier ("RSA", "ECDSA", "Ed25519", "ecdsa-p256", "rsa-pss-3072").
	Algorithm string `cel:"algorithm" json:"algorithm,omitempty"`
	// Type is the key type as the key provider names it ("rsa-2048",
	// "ecdsa-p256", "ed25519"), empty when the surface does not record one.
	Type string `cel:"type" json:"type,omitempty"`
	// Size is the RSA modulus size or the curve size in bits; 0 when the notion
	// does not apply.
	Size int `cel:"size" json:"size,omitempty"`
	// Curve is the elliptic curve name ("P-256"), empty otherwise.
	Curve string `cel:"curve" json:"curve,omitempty"`
	// Fingerprint is the public key's SubjectPublicKeyInfo SHA-256 fingerprint
	// in the "SHA256:<base64>" form the inventory search and the blocklist use.
	Fingerprint string `cel:"fingerprint" json:"fingerprint,omitempty"`
	// Provider names the key backend ("pkcs11", "awskms", "software").
	Provider string `cel:"provider" json:"provider,omitempty"`
	// Tenant is the key's tenant, empty for a platform-level key.
	Tenant string `cel:"tenant" json:"tenant,omitempty"`
}

// PayloadInfo describes what would be signed: `signing.payload`.
//
// It is deliberately shallow — a size, a digest and whether the caller supplied
// the digest rather than the bytes. A rule has no business reading the content
// of a release artifact, and a service that signs a 4 GiB image never sees the
// bytes in the first place.
type PayloadInfo struct {
	// Present is false when the surface reveals nothing about the payload.
	Present bool `cel:"present" json:"present,omitempty"`
	// Size is the byte length of the content the caller supplied. It is 0 when
	// the caller supplied a precomputed digest instead — an *unknown* message
	// length, not a tiny one — and 0 for an OpenSSH certificate, whose payload is
	// the certificate's own to-be-signed encoding (every fact a rule could want
	// from it is already spelled out under SSH).
	Size int `cel:"size" json:"size,omitempty"`
	// Digest is the lowercase hex digest of what is being signed and
	// DigestAlgorithm names the hash ("SHA-256").
	Digest          string `cel:"digest" json:"digest,omitempty"`
	DigestAlgorithm string `cel:"digest_algorithm" json:"digest_algorithm,omitempty"`
	// Prehashed reports that the caller supplied the digest rather than the
	// content, so the service never saw what it is attesting to. A policy that
	// insists on signing only data it has seen tests this.
	Prehashed bool `cel:"prehashed" json:"prehashed,omitempty"`
}

// SSHCertInfo is the OpenSSH certificate a request would mint:
// `signing.ssh`.
type SSHCertInfo struct {
	Present bool `cel:"present" json:"present,omitempty"`
	// CertType is "user" or "host".
	CertType string `cel:"cert_type" json:"cert_type,omitempty"`
	// KeyID is the certificate's key ID — what the target host writes to its
	// auth log, and the field an audit trail is reconstructed from.
	KeyID string `cel:"key_id" json:"key_id,omitempty"`
	// Principals are the user names (user certs) or host names (host certs) the
	// certificate is valid for; PrincipalCount is their number, so a
	// "one principal per certificate" rule needs no size() call.
	Principals     []string `cel:"principals" json:"principals,omitempty"`
	PrincipalCount int      `cel:"principal_count" json:"principal_count,omitempty"`
	// Extensions and CriticalOptions are the resolved permission *names*, sorted
	// — `"permit-agent-forwarding" in signing.ssh.extensions` — and
	// CriticalOptionValues maps each critical option to its value, which is
	// where force-command and source-address live.
	Extensions           []string          `cel:"extensions" json:"extensions,omitempty"`
	CriticalOptions      []string          `cel:"critical_options" json:"critical_options,omitempty"`
	CriticalOptionValues map[string]string `cel:"critical_option_values" json:"critical_option_values,omitempty"`
	// Profile is the SSH signing profile's name.
	Profile string `cel:"profile" json:"profile,omitempty"`
	// Serial is the allocated certificate serial, decimal.
	Serial string `cel:"serial" json:"serial,omitempty"`
	// ValidAfter / ValidBefore bound the certificate's lifetime, Validity is the
	// window as a duration, and ValidityDays the same truncated to whole days.
	ValidAfter   time.Time     `cel:"valid_after" json:"valid_after,omitempty"`
	ValidBefore  time.Time     `cel:"valid_before" json:"valid_before,omitempty"`
	Validity     time.Duration `cel:"validity" json:"validity,omitempty"`
	ValidityDays int           `cel:"validity_days" json:"validity_days,omitempty"`
	// PublicKey describes the key being certified.
	PublicKey SSHKeyInfo `cel:"public_key" json:"public_key,omitempty"`
	// CA identifies the signing authority.
	CA CAInfo `cel:"ca" json:"ca,omitempty"`
}

// SSHKeyInfo describes an OpenSSH public key: `signing.ssh.public_key`.
type SSHKeyInfo struct {
	// Type is the OpenSSH key type ("ssh-ed25519", "ecdsa-sha2-nistp256",
	// "ssh-rsa", "sk-ssh-ed25519@openssh.com" for a FIDO-backed key).
	Type string `cel:"type" json:"type,omitempty"`
	// Fingerprint is the OpenSSH SHA256:… fingerprint.
	Fingerprint string `cel:"fingerprint" json:"fingerprint,omitempty"`
	// Bits is the key size in bits where the notion applies (RSA, ECDSA), 0
	// otherwise.
	Bits int `cel:"bits" json:"bits,omitempty"`
	// HardwareBacked is true for a FIDO/U2F-resident key ("sk-" prefixed type),
	// which is the one thing a public key can prove about where it lives.
	HardwareBacked bool `cel:"hardware_backed" json:"hardware_backed,omitempty"`
}

// ArtifactInfo is the artifact-signature request: `signing.artifact`.
type ArtifactInfo struct {
	Present bool `cel:"present" json:"present,omitempty"`
	// Signer is the configured signing identity's name.
	Signer string `cel:"signer" json:"signer,omitempty"`
	// Level is the requested CAdES baseline level ("b", "t" or "lt") and
	// Timestamped reports whether the signature will carry an RFC 3161
	// countersignature.
	Level       string `cel:"level" json:"level,omitempty"`
	Timestamped bool   `cel:"timestamped" json:"timestamped,omitempty"`
	// Name is the artifact name the caller supplied, where the surface accepts
	// one (the CLI's file name, the API's optional name). It is caller-asserted
	// metadata, not something the signature binds — a rule that wants a *bound*
	// fact reads payload.digest.
	Name string `cel:"name" json:"name,omitempty"`
	// Certificate describes the signing certificate that will be embedded.
	Certificate SignerCertInfo `cel:"certificate" json:"certificate,omitempty"`
}

// SignerCertInfo describes an artifact signer's certificate:
// `signing.artifact.certificate`.
type SignerCertInfo struct {
	// Subject and Issuer are RFC 2253 distinguished names.
	Subject string `cel:"subject" json:"subject,omitempty"`
	Issuer  string `cel:"issuer" json:"issuer,omitempty"`
	// Serial is the certificate serial in decimal.
	Serial string `cel:"serial" json:"serial,omitempty"`
	// NotBefore / NotAfter bound the certificate's own validity, so a rule can
	// refuse a signature made close to its expiry without a timestamp.
	NotBefore time.Time `cel:"not_before" json:"not_before,omitempty"`
	NotAfter  time.Time `cel:"not_after" json:"not_after,omitempty"`
	// ExtKeyUsages are the EKUs the certificate carries, named as a profile
	// names them ("codeSigning").
	ExtKeyUsages []string `cel:"ext_key_usages" json:"ext_key_usages,omitempty"`
}

// DataInfo is the raw-signature request: `signing.data`.
type DataInfo struct {
	Present bool `cel:"present" json:"present,omitempty"`
	// Key is the signing key's name, and Algorithm its fixed algorithm
	// identifier ("ecdsa-p256", "rsa-pss-3072", "ed25519").
	Key       string `cel:"key" json:"key,omitempty"`
	Algorithm string `cel:"algorithm" json:"algorithm,omitempty"`
	// Hash names the message hash the signature uses ("SHA-256"); empty for
	// Ed25519, which hashes internally as part of the scheme.
	Hash string `cel:"hash" json:"hash,omitempty"`
}

// JWTSVIDInfo is the SPIFFE JWT-SVID a request would mint: `signing.jwt_svid`.
type JWTSVIDInfo struct {
	Present bool `cel:"present" json:"present,omitempty"`
	// SPIFFEID is the workload identity the token asserts, verbatim —
	// `spiffe://trust.domain/path`. TrustDomain and Path are the same value
	// split, so a rule can restrict a namespace without parsing a URI.
	SPIFFEID    string `cel:"spiffe_id" json:"spiffe_id,omitempty"`
	TrustDomain string `cel:"trust_domain" json:"trust_domain,omitempty"`
	Path        string `cel:"path" json:"path,omitempty"`
	// Audience is the token's intended audience set ("aud"), which for a
	// JWT-SVID is the set of services permitted to accept it — the field a
	// policy most often restricts.
	Audience []string `cel:"audience" json:"audience,omitempty"`
	// Algorithm is the JWS algorithm the issuer key implies ("ES256") and KeyID
	// the RFC 7638 thumbprint published in the trust bundle.
	Algorithm string `cel:"algorithm" json:"algorithm,omitempty"`
	KeyID     string `cel:"key_id" json:"key_id,omitempty"`
	// NotBefore / Expiry bound the token, TTL is the window as a duration, and
	// TTLSeconds the same in whole seconds — the unit a JWT-SVID lifetime is
	// written in, because the whole point of the credential is that it is short.
	NotBefore  time.Time     `cel:"not_before" json:"not_before,omitempty"`
	Expiry     time.Time     `cel:"expiry" json:"expiry,omitempty"`
	TTL        time.Duration `cel:"ttl" json:"ttl,omitempty"`
	TTLSeconds int           `cel:"ttl_seconds" json:"ttl_seconds,omitempty"`
	// CA identifies the issuing authority whose key signs the token.
	CA CAInfo `cel:"ca" json:"ca,omitempty"`
}

// SigningInput is the complete fact set a signing rule is evaluated against.
type SigningInput struct {
	Signing   SigningRequest         `json:"signing"`
	JWT       map[string]interface{} `json:"jwt,omitempty"`
	URL       RequestURL             `json:"url,omitempty"`
	Body      map[string]interface{} `json:"body,omitempty"`
	Principal Principal              `json:"principal,omitempty"`
	Now       time.Time              `json:"now,omitempty"`
}

// Activation renders the input as a CEL activation, with every declared
// variable present. See Input.Activation for why absence is spelled "empty".
func (in SigningInput) Activation() map[string]interface{} {
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
		VarSigning:   in.Signing.normalized(),
		VarJWT:       jwt,
		VarURL:       in.URL.normalized(),
		VarPath:      in.URL.Path,
		VarBody:      body,
		VarPrincipal: in.Principal.normalized(),
		VarNow:       now,
	}
}

// normalized materializes empty slices and maps and fills in the defaults, so a
// rule never meets a nil and `signing.operation` is never the empty string.
func (s SigningRequest) normalized() SigningRequest {
	if s.Operation == "" {
		s.Operation = OpSignData
	}
	if s.Source == "" {
		s.Source = SourceUnknown
	}
	s.SSH.Principals = orEmpty(s.SSH.Principals)
	s.SSH.Extensions = orEmpty(s.SSH.Extensions)
	s.SSH.CriticalOptions = orEmpty(s.SSH.CriticalOptions)
	if s.SSH.CriticalOptionValues == nil {
		s.SSH.CriticalOptionValues = map[string]string{}
	}
	s.Artifact.Certificate.ExtKeyUsages = orEmpty(s.Artifact.Certificate.ExtKeyUsages)
	s.JWTSVID.Audience = orEmpty(s.JWTSVID.Audience)
	return s
}

// SigningInput combines the captured HTTP facts with the signing facts. A nil
// holder yields empty HTTP facts and an unauthenticated principal — the correct
// reading for a CLI invocation or a background job, and the reason a rule that
// requires a token claim refuses one.
func (f *Facts) SigningInput(req SigningRequest) SigningInput {
	in := SigningInput{Signing: req, Now: time.Now().UTC()}
	if f == nil {
		in.Signing = in.Signing.normalized()
		return in
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	in.URL = f.url
	in.Body = cloneMap(f.body)
	in.JWT = cloneMap(f.jwt)
	in.Principal = f.principal
	if req.Source == "" || req.Source == SourceUnknown {
		if f.source != "" {
			in.Signing.Source = f.source
		} else if f.url.Present {
			in.Signing.Source = SourceREST
		}
	}
	if in.Signing.RequestedBy == "" {
		in.Signing.RequestedBy = f.principal.Subject
	}
	in.Signing = in.Signing.normalized()
	return in
}

// SortedKeys returns a map's keys in sorted order. Signing facts expose
// permission *names* as a sorted list rather than as a map so `in` reads
// naturally and the order a rule's message reports them in is stable.
func SortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// HashName renders a crypto.Hash the way an operator writes it ("SHA-256"),
// which is also how the API and the CLI name it. crypto.Hash's own String()
// produces "SHA-256" for the SHA-2 family already, but it panics on an
// unregistered hash and spells 0 as "unknown hash value 0" — neither of which
// belongs in a policy fact.
func HashName(h crypto.Hash) string {
	switch h {
	case 0:
		return ""
	case crypto.SHA256:
		return "SHA-256"
	case crypto.SHA384:
		return "SHA-384"
	case crypto.SHA512:
		return "SHA-512"
	case crypto.SHA1:
		return "SHA-1"
	}
	return strings.ReplaceAll(h.String(), " ", "-")
}

// SignerCertFactsFrom reads the facts of an artifact signer's certificate.
func SignerCertFactsFrom(cert *x509.Certificate) SignerCertInfo {
	if cert == nil {
		return SignerCertInfo{ExtKeyUsages: []string{}}
	}
	out := SignerCertInfo{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
	}
	if cert.SerialNumber != nil {
		out.Serial = cert.SerialNumber.String()
	}
	ekus := pki.ExtKeyUsageNames(cert.ExtKeyUsage)
	for _, oid := range cert.UnknownExtKeyUsage {
		ekus = append(ekus, oid.String())
	}
	out.ExtKeyUsages = orEmpty(ekus)
	return out
}

// KeyFactsFromPublic fills in the algorithm facts a public key reveals, so the
// signing surfaces describe a key the way the certificate vocabulary describes
// the key it certifies — same spellings ("RSA", "ECDSA", "Ed25519"), same
// fingerprint form.
func KeyFactsFromPublic(pub interface{}) SigningKeyInfo {
	k := keyInfoOf(pub)
	return SigningKeyInfo{
		Algorithm:   k.Algorithm,
		Size:        k.Size,
		Curve:       k.Curve,
		Fingerprint: k.Fingerprint,
	}
}
