// Package signing implements an HSM-backed code/artifact signing service
// (Task 60): CMS/PKCS#7 detached signatures (RFC 5652) over release artifacts,
// produced with code-signing keys that live in the key provider (an HSM via
// PKCS#11, a cloud KMS, or the software keystore) and certificates issued by
// the PKI's own CA under the lint-gated "code-signing" profile.
//
// A signature optionally embeds an RFC 3161 timestamp countersignature from
// the in-process Time-Stamp Authority (internal/tsa) as the id-aa-timeStampToken
// unsigned attribute (RFC 3161 Appendix A). The token binds the signature value
// to a trusted time, so the signature remains verifiable after the signing
// certificate expires — the property release pipelines need from a TSA.
//
// Design invariants:
//
//   - Private keys never leave the provider: signing flows exclusively through
//     crypto.Signer (one HSM signature per artifact, plus one on the TSA key
//     when countersigning).
//   - Signatures are always detached: the artifact is never embedded, so the
//     signature file is small and the artifact's own distribution channel is
//     unchanged.
//   - Artifacts may be presented as content or as a precomputed digest, so
//     multi-gigabyte images can be signed without shipping them to the service.
//   - Verification is fail-closed: the signer chain must build to the supplied
//     trust anchors with the codeSigning EKU, and an embedded timestamp must
//     itself verify before it is allowed to move the validation time.
package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// OIDTimeStampToken (id-aa-timeStampToken, RFC 3161 Appendix A) is the unsigned
// attribute carrying a TimeStampToken over the SignerInfo signature value.
var OIDTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// clockSkew is the tolerance applied to certificate-window and timestamp
// plausibility checks.
const clockSkew = 5 * time.Minute

// ErrUnavailable marks failures of the signing backend (key provider, TSA, or
// signer configuration) as opposed to a problem with the request itself, so
// transports can answer 5xx — a CI caller should retry these, not fix its
// request. Test with errors.Is.
var ErrUnavailable = errors.New("signing backend unavailable")

// SignerConfig is one configured signing identity: a provider-resident key and
// its CA-issued code-signing certificate.
type SignerConfig struct {
	// Name is the identity callers reference in sign requests. Required, unique.
	Name string
	// KeyLabel is the provider label of the signing key (RSA or ECDSA).
	KeyLabel string
	// Certificate is the signer's code-signing certificate (EKU id-kp-codeSigning,
	// KU digitalSignature), issued under the CA's "code-signing" profile.
	Certificate *x509.Certificate
	// Chain is the signer certificate followed by its issuer(s); it is embedded
	// in every signature so verifiers can build the path. When empty, the signer
	// certificate alone is embedded.
	Chain []*x509.Certificate
	// Digest is the message-digest / signature hash (default SHA-256; SHA-1 is
	// refused for new signatures).
	Digest crypto.Hash
	// TimestampByDefault embeds an RFC 3161 countersignature on every signature
	// unless the request explicitly opts out. Requires a TSA.
	TimestampByDefault bool
	// TenantID is the tenant this signer belongs to, scoping RBAC and audit at
	// the API layer. Empty means the default tenant (resolved by the caller).
	TenantID string
}

// Service signs artifacts with the configured signers. It is safe for
// concurrent use.
type Service struct {
	provider  keyprovider.Provider
	authority *tsa.Authority // nil = timestamping unavailable
	signers   map[string]*SignerConfig
	names     []string // sorted, for stable listings
}

// NewService validates the configured signers and builds the service. A
// misconfigured signer (wrong EKU, missing key usage, unusable digest, or a
// default-timestamp signer without a TSA) fails fast at startup rather than
// producing unverifiable signatures later.
func NewService(provider keyprovider.Provider, authority *tsa.Authority, signers []SignerConfig) (*Service, error) {
	if provider == nil {
		return nil, errors.New("signing: a key provider is required")
	}
	if len(signers) == 0 {
		return nil, errors.New("signing: at least one signer must be configured")
	}
	s := &Service{
		provider:  provider,
		authority: authority,
		signers:   make(map[string]*SignerConfig, len(signers)),
	}
	for i := range signers {
		sc := signers[i]
		if sc.Name == "" {
			return nil, errors.New("signing: signer name is required")
		}
		if _, dup := s.signers[sc.Name]; dup {
			return nil, fmt.Errorf("signing: duplicate signer %q", sc.Name)
		}
		if sc.KeyLabel == "" {
			return nil, fmt.Errorf("signing: signer %q: key_label is required", sc.Name)
		}
		if sc.Certificate == nil {
			return nil, fmt.Errorf("signing: signer %q: a certificate is required", sc.Name)
		}
		if err := CheckCodeSigningCert(sc.Certificate); err != nil {
			return nil, fmt.Errorf("signing: signer %q: %w", sc.Name, err)
		}
		if sc.Digest == 0 {
			sc.Digest = crypto.SHA256
		}
		switch sc.Digest {
		case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		default:
			return nil, fmt.Errorf("signing: signer %q: unsupported digest %v (sha256, sha384, or sha512)", sc.Name, sc.Digest)
		}
		if len(sc.Chain) == 0 {
			sc.Chain = []*x509.Certificate{sc.Certificate}
		} else if !bytes.Equal(sc.Chain[0].Raw, sc.Certificate.Raw) {
			return nil, fmt.Errorf("signing: signer %q: chain must start with the signer certificate", sc.Name)
		}
		if sc.TimestampByDefault && authority == nil {
			return nil, fmt.Errorf("signing: signer %q requests timestamping by default, but no TSA is configured (enable tsa in config)", sc.Name)
		}
		s.signers[sc.Name] = &sc
		s.names = append(s.names, sc.Name)
	}
	sort.Strings(s.names)
	return s, nil
}

// CheckCodeSigningCert enforces the shape of a usable code-signing certificate:
// the id-kp-codeSigning extended key usage, the digitalSignature key usage, and
// an end-entity basic constraint. It runs at service construction and again in
// the provisioning CLI, so a wrong-profile certificate is caught before any
// signature exists.
func CheckCodeSigningCert(cert *x509.Certificate) error {
	hasCodeSigning := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
		}
	}
	if !hasCodeSigning {
		return errors.New("certificate lacks the id-kp-codeSigning extended key usage (issue it under the code-signing profile)")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate lacks the digitalSignature key usage")
	}
	if cert.IsCA {
		return errors.New("certificate is a CA certificate, not a code-signing leaf")
	}
	return nil
}

// Signers returns the configured signer identities in stable (name) order.
func (s *Service) Signers() []*SignerConfig {
	out := make([]*SignerConfig, 0, len(s.names))
	for _, n := range s.names {
		out = append(out, s.signers[n])
	}
	return out
}

// Signer returns the named signer configuration, or nil when unknown.
func (s *Service) Signer(name string) *SignerConfig { return s.signers[name] }

// TimestampingAvailable reports whether an in-process TSA is wired up.
func (s *Service) TimestampingAvailable() bool { return s.authority != nil }

// SignRequest describes one artifact-signing operation. Exactly one of Content
// or Digest must be provided.
type SignRequest struct {
	// Signer names the configured signing identity.
	Signer string
	// Content is the artifact to sign (file input).
	Content []byte
	// Digest is the precomputed digest of the artifact, computed with the
	// signer's digest algorithm (digest input, for artifacts too large to ship).
	Digest []byte
	// Timestamp overrides the signer's TimestampByDefault when non-nil.
	Timestamp *bool
}

// SignResult is the outcome of a successful signing operation.
type SignResult struct {
	// Signature is the DER-encoded CMS/PKCS#7 detached SignedData.
	Signature []byte
	// Signer is the identity that signed.
	Signer *SignerConfig
	// DigestAlgorithm / ArtifactDigest identify exactly what was signed.
	DigestAlgorithm crypto.Hash
	ArtifactDigest  []byte
	// Timestamped reports whether an RFC 3161 countersignature is embedded;
	// TimestampGenTime / TimestampSerial describe the token when it is.
	Timestamped      bool
	TimestampGenTime time.Time
	TimestampSerial  *big.Int
}

// Sign produces a CMS detached signature over the artifact with the named
// signer, optionally countersigned by the in-process TSA. The private key is
// used exclusively through the provider's crypto.Signer.
func (s *Service) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	sc := s.signers[req.Signer]
	if sc == nil {
		return nil, fmt.Errorf("signing: unknown signer %q (configured: %v)", req.Signer, s.names)
	}

	if req.Content == nil && req.Digest == nil {
		return nil, errors.New("signing: either the artifact content or its digest is required")
	}
	if req.Content != nil && req.Digest != nil {
		return nil, errors.New("signing: provide the artifact content or its digest, not both")
	}
	artifactDigest := req.Digest
	if artifactDigest != nil {
		if len(artifactDigest) != sc.Digest.Size() {
			return nil, fmt.Errorf("signing: digest length %d does not match signer %q digest %v (want %d bytes)",
				len(artifactDigest), sc.Name, sc.Digest, sc.Digest.Size())
		}
	} else {
		h := sc.Digest.New()
		h.Write(req.Content)
		artifactDigest = h.Sum(nil)
	}

	// Refuse to sign outside the certificate's validity window: the signature
	// would be born broken (or become unverifiable the moment it is checked).
	now := time.Now()
	if now.Add(clockSkew).Before(sc.Certificate.NotBefore) {
		return nil, fmt.Errorf("signing: signer %q certificate is not yet valid (notBefore %s)", sc.Name, sc.Certificate.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(sc.Certificate.NotAfter) {
		return nil, fmt.Errorf("signing: signer %q certificate expired %s — provision a new one with `secsy-ca signing-key`", sc.Name, sc.Certificate.NotAfter.UTC().Format(time.RFC3339))
	}

	wantTimestamp := sc.TimestampByDefault
	if req.Timestamp != nil {
		wantTimestamp = *req.Timestamp
	}
	if wantTimestamp && s.authority == nil {
		return nil, errors.New("signing: timestamping requested but no TSA is configured (enable tsa in config)")
	}

	// KeyLabel may be a bare label or a full RFC 7512 pkcs11: URI (addressing by
	// CKA_ID or token serial/slot-id); KeyRefFor handles both.
	signer, err := s.provider.Signer(ctx, keyprovider.KeyRefFor(sc.KeyLabel))
	if err != nil {
		return nil, fmt.Errorf("signing: opening signing key %q: %v: %w", sc.KeyLabel, err, ErrUnavailable)
	}
	defer signer.Close()

	// The provider key must be the one the certificate certifies; a mismatch
	// (e.g. a re-generated key under a stale label) would produce signatures
	// nothing can verify.
	if err := checkKeyMatchesCert(signer.Public(), sc.Certificate); err != nil {
		return nil, fmt.Errorf("signing: signer %q: %v: %w", sc.Name, err, ErrUnavailable)
	}

	scv2, err := cms.SigningCertificateV2Attribute(sc.Chain)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	result := &SignResult{
		Signer:          sc,
		DigestAlgorithm: sc.Digest,
		ArtifactDigest:  artifactDigest,
	}

	opts := cms.SignedDataOpts{
		ContentDigest: artifactDigest,
		Detached:      true,
		SignerCert:    sc.Certificate,
		Signer:        signer,
		Digest:        sc.Digest,
		Certificates:  sc.Chain,
		ExtraAttrs: []cms.Attribute{
			scv2,
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}, Value: now.UTC().Truncate(time.Second)}, // signingTime (RFC 8933)
		},
	}
	if wantTimestamp {
		opts.UnauthAttrsFunc = func(sig []byte) ([]cms.Attribute, error) {
			token, info, err := s.countersign(ctx, sc.Digest, sig)
			if err != nil {
				return nil, err
			}
			result.Timestamped = true
			result.TimestampGenTime = info.GenTime
			result.TimestampSerial = info.SerialNumber
			return []cms.Attribute{{Type: OIDTimeStampToken, Value: asn1.RawValue{FullBytes: token}}}, nil
		}
	}

	der, err := cms.BuildSignedData(opts)
	if err != nil {
		// Everything request-shaped was validated above; a build failure here is
		// the signing backend (HSM signature, TSA countersignature) misbehaving.
		return nil, fmt.Errorf("%v: %w", err, ErrUnavailable)
	}
	result.Signature = der
	return result, nil
}

// countersign obtains an RFC 3161 timestamp token over the signature value from
// the in-process TSA and validates that the token really covers it (imprint and
// nonce echo) before it is embedded. Outcomes are metered separately from the
// signing operation so TSA trouble is distinguishable from signing trouble.
func (s *Service) countersign(ctx context.Context, hash crypto.Hash, signature []byte) (_ []byte, _ *tsa.TokenInfo, err error) {
	defer func() {
		if err != nil {
			metrics.ArtifactTimestamps.Inc("error")
		} else {
			metrics.ArtifactTimestamps.Inc("success")
		}
	}()

	h := hash.New()
	h.Write(signature)
	imprint := h.Sum(nil)

	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("signing: generating timestamp nonce: %w", err)
	}
	reqDER, err := tsa.MakeRequest(hash, imprint, &tsa.RequestOptions{Nonce: nonce, CertReq: true})
	if err != nil {
		return nil, nil, fmt.Errorf("signing: building timestamp request: %w", err)
	}
	res, err := s.authority.Stamp(ctx, reqDER)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: obtaining timestamp: %w", err)
	}
	if !res.Granted {
		return nil, nil, fmt.Errorf("signing: TSA rejected the timestamp request: %s", res.Detail)
	}
	token, err := tsa.ExtractToken(res.Response)
	if err != nil {
		return nil, nil, err
	}
	info, err := tsa.ParseTokenInfo(token)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(info.HashedMessage, imprint) {
		return nil, nil, errors.New("signing: timestamp token does not cover the signature value")
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		return nil, nil, errors.New("signing: timestamp token did not echo the request nonce")
	}
	return token, info, nil
}

// checkKeyMatchesCert confirms the provider key's public half equals the
// certificate's subject public key.
func checkKeyMatchesCert(pub crypto.PublicKey, cert *x509.Certificate) error {
	got, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encoding provider public key: %w", err)
	}
	want, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("encoding certificate public key: %w", err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("provider key does not match the signer certificate (was the key re-generated under this label?)")
	}
	return nil
}
