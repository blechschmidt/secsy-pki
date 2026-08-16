package handlers

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/signing"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// SetSigningService installs the artifact code-signing service (Task 60),
// enabling the /api/sign endpoints.
func (a *API) SetSigningService(svc *signing.Service) { a.signingService = svc }

// SignArtifactRequest is the body of POST /api/sign. Exactly one of Artifact
// (the bytes, base64) or Digest (its hash, hex, computed with the signer's
// digest algorithm) must be provided — the digest form signs artifacts too
// large to ship through the API.
type SignArtifactRequest struct {
	Signer   string `json:"signer"`
	Artifact string `json:"artifact,omitempty"`
	Digest   string `json:"digest,omitempty"`
	// Level requests a CAdES baseline level (b|t|lt): b is signed attributes
	// only, t adds an RFC 3161 signature-timestamp, lt additionally embeds
	// long-term-validation revocation material. Empty applies the signer's
	// default. Takes precedence over timestamp.
	Level string `json:"level,omitempty"`
	// Timestamp overrides the signer's configured default when present. Ignored
	// when level is set.
	Timestamp *bool `json:"timestamp,omitempty"`
}

// SignArtifactResponse carries the detached signature and what it covers.
type SignArtifactResponse struct {
	// Signature is the DER CMS/PKCS#7 detached signature, base64-encoded;
	// SignaturePEM is the same bytes as a PKCS7 PEM block for file use.
	Signature    string `json:"signature"`
	SignaturePEM string `json:"signature_pem"`
	Signer       string `json:"signer"`
	// SignerCertificate is the code-signing certificate (PEM).
	SignerCertificate string `json:"signer_certificate"`
	DigestAlgorithm   string `json:"digest_algorithm"`
	Digest            string `json:"digest"`
	// Level is the achieved CAdES baseline level (b|t|lt).
	Level           string `json:"level"`
	Timestamped     bool   `json:"timestamped"`
	TimestampTime   string `json:"timestamp_time,omitempty"`
	TimestampSerial string `json:"timestamp_serial,omitempty"`
	// EmbeddedCRLs / EmbeddedOCSPs count the long-term-validation revocation
	// objects embedded for a CAdES-LT signature.
	EmbeddedCRLs  int `json:"embedded_crls,omitempty"`
	EmbeddedOCSPs int `json:"embedded_ocsps,omitempty"`
}

// SignArtifact handles POST /api/sign: a CMS detached signature over the
// submitted artifact (or digest) with a configured code-signing key. Requires
// the artifact:sign capability (signer role) within the signer's tenant.
func (a *API) SignArtifact(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if a.signingService == nil {
		writeError(w, http.StatusServiceUnavailable, "artifact signing is not enabled (set signing.enabled in config)")
		return
	}

	var req SignArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Signer == "" {
		writeError(w, http.StatusBadRequest, "signer is required")
		return
	}

	sc := a.signingService.Signer(req.Signer)
	if sc == nil {
		// Disclose the configured signer set only to principals that hold the
		// capability somewhere; everyone else gets the same denial as below.
		if a.can(user, rbac.ActionSignArtifact) {
			writeError(w, http.StatusNotFound, "unknown signer %q", req.Signer)
			return
		}
		// A constant label: the request string must not mint unbounded metric series.
		metrics.ArtifactSignatures.Inc("unknown", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionArtifactSign, req.Signer, "", audit.ResultDenied, "artifact:sign capability required (signer role)")
		writeError(w, http.StatusForbidden, "artifact:sign capability required (signer role)")
		return
	}

	// Tenant scoping: the signer belongs to a tenant; the caller must hold the
	// capability within it (or platform-wide). Record the tenant on the context
	// first so the audit event is attributed even on denial.
	middleware.SetTenant(r.Context(), sc.TenantID)
	if !a.canInTenant(user, sc.TenantID, rbac.ActionSignArtifact) {
		metrics.ArtifactSignatures.Inc(sc.Name, metrics.ResultDenied)
		a.recordEvent(r, audit.ActionArtifactSign, sc.Name, "", audit.ResultDenied, "artifact:sign capability required (signer role)")
		writeError(w, http.StatusForbidden, "artifact:sign capability required (signer role)")
		return
	}

	level, err := signing.ParseLevel(req.Level)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	svcReq := signing.SignRequest{Signer: req.Signer, Level: level, Timestamp: req.Timestamp}
	switch {
	case req.Artifact != "" && req.Digest != "":
		writeError(w, http.StatusBadRequest, "provide artifact or digest, not both")
		return
	case req.Artifact != "":
		content, err := base64.StdEncoding.DecodeString(req.Artifact)
		if err != nil {
			writeError(w, http.StatusBadRequest, "artifact is not valid base64: %v", err)
			return
		}
		svcReq.Content = content
	case req.Digest != "":
		digest, err := hex.DecodeString(strings.TrimSpace(req.Digest))
		if err != nil {
			writeError(w, http.StatusBadRequest, "digest is not valid hex: %v", err)
			return
		}
		svcReq.Digest = digest
	default:
		writeError(w, http.StatusBadRequest, "either artifact (base64) or digest (hex) is required")
		return
	}

	a.consumeHSMAuditLogs("")
	res, err := a.signingService.Sign(r.Context(), svcReq)
	a.consumeHSMAuditLogs("")
	if err != nil {
		metrics.ArtifactSignatures.Inc(sc.Name, metrics.ResultError)
		a.recordEvent(r, audit.ActionArtifactSign, sc.Name, "", audit.ResultError, err.Error())
		if errors.Is(err, signing.ErrUnavailable) {
			// Backend trouble (provider/TSA), not a request problem: answer 503 so
			// pipelines retry, and keep provider internals out of the response —
			// the audit event above carries the full detail.
			writeError(w, http.StatusServiceUnavailable, "signing backend unavailable; retry later")
			return
		}
		writeError(w, http.StatusBadRequest, "failed to sign artifact: %v", err)
		return
	}

	metrics.ArtifactSignatures.Inc(sc.Name, metrics.ResultSuccess)
	digestHex := hex.EncodeToString(res.ArtifactDigest)
	a.recordEvent(r, audit.ActionArtifactSign, sc.Name, sc.Certificate.Subject.CommonName, audit.ResultSuccess,
		fmt.Sprintf("digest=%s:%s level=%s timestamped=%t crls=%d ocsps=%d cert_serial=%s",
			hashName(res.DigestAlgorithm), digestHex, res.Level, res.Timestamped, res.EmbeddedCRLs, res.EmbeddedOCSPs, sc.Certificate.SerialNumber))

	resp := SignArtifactResponse{
		Signature:         base64.StdEncoding.EncodeToString(res.Signature),
		SignaturePEM:      string(pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: res.Signature})),
		Signer:            sc.Name,
		SignerCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sc.Certificate.Raw})),
		DigestAlgorithm:   hashName(res.DigestAlgorithm),
		Digest:            digestHex,
		Level:             string(res.Level),
		Timestamped:       res.Timestamped,
		EmbeddedCRLs:      res.EmbeddedCRLs,
		EmbeddedOCSPs:     res.EmbeddedOCSPs,
	}
	if res.Timestamped {
		resp.TimestampTime = res.TimestampGenTime.UTC().Format(time.RFC3339)
		resp.TimestampSerial = res.TimestampSerial.String()
	}
	writeJSON(w, http.StatusOK, resp)
}

// VerifyArtifactRequest is the body of POST /api/sign/verify.
type VerifyArtifactRequest struct {
	// Signature is the detached CMS signature: base64 DER, or a PKCS7 PEM block.
	Signature string `json:"signature"`
	// Artifact (base64) or Digest (hex, in the signature's digest algorithm) —
	// exactly one of the two.
	Artifact string `json:"artifact,omitempty"`
	Digest   string `json:"digest,omitempty"`
	// CAID restricts the trust anchors to one CA (and its chain); empty trusts
	// every CA of the tenants the caller belongs to.
	CAID string `json:"ca_id,omitempty"`
	// RequireTimestamp fails verification when no RFC 3161 countersignature is
	// embedded.
	RequireTimestamp bool `json:"require_timestamp,omitempty"`
	// RequireLevel fails verification when the achieved CAdES level is below this
	// minimum (b|t|lt). Empty imposes no floor.
	RequireLevel string `json:"require_level,omitempty"`
}

// VerifyArtifactResponse reports the verification outcome. Valid=false with a
// Reason is a successful request (HTTP 200) whose answer is "no".
type VerifyArtifactResponse struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
	// Signer details, present when the signature parsed far enough.
	SignerSubject     string `json:"signer_subject,omitempty"`
	SignerSerial      string `json:"signer_serial,omitempty"`
	SignerCertificate string `json:"signer_certificate,omitempty"`
	DigestAlgorithm   string `json:"digest_algorithm,omitempty"`
	Digest            string `json:"digest,omitempty"`
	// Level is the achieved CAdES baseline level (b|t|lt), on a valid signature.
	Level           string `json:"level,omitempty"`
	RevocationCRLs  int    `json:"revocation_crls,omitempty"`
	RevocationOCSPs int    `json:"revocation_ocsps,omitempty"`
	Timestamped     bool   `json:"timestamped,omitempty"`
	TimestampTime   string `json:"timestamp_time,omitempty"`
	TimestampSerial string `json:"timestamp_serial,omitempty"`
	// VerifiedAt is the instant chain validity was evaluated at: the timestamp
	// genTime when countersigned, else the wall clock.
	VerifiedAt string `json:"verified_at,omitempty"`
}

// VerifyArtifact handles POST /api/sign/verify: checks a detached signature
// against the artifact (or digest) and the PKI's CA certificates as trust
// anchors. Any assigned role may verify; the anchor set is confined to CAs of
// tenants the caller belongs to.
func (a *API) VerifyArtifact(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "an assigned role is required")
		return
	}

	var req VerifyArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Signature == "" {
		writeError(w, http.StatusBadRequest, "signature is required")
		return
	}
	sigDER, err := decodeSignature(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	requireLevel, err := signing.ParseLevel(req.RequireLevel)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	vreq := signing.VerifyRequest{Signature: sigDER, RequireTimestamp: req.RequireTimestamp, RequireLevel: requireLevel}
	switch {
	case req.Artifact != "" && req.Digest != "":
		writeError(w, http.StatusBadRequest, "provide artifact or digest, not both")
		return
	case req.Artifact != "":
		content, err := base64.StdEncoding.DecodeString(req.Artifact)
		if err != nil {
			writeError(w, http.StatusBadRequest, "artifact is not valid base64: %v", err)
			return
		}
		vreq.Content = content
	case req.Digest != "":
		digest, err := hex.DecodeString(strings.TrimSpace(req.Digest))
		if err != nil {
			writeError(w, http.StatusBadRequest, "digest is not valid hex: %v", err)
			return
		}
		vreq.Digest = digest
	default:
		writeError(w, http.StatusBadRequest, "either artifact (base64) or digest (hex) is required")
		return
	}

	roots, err := a.trustAnchorsFor(r, user, req.CAID)
	if err != nil {
		metrics.ArtifactVerifications.Inc(metrics.ResultError)
		writeError(w, http.StatusInternalServerError, "loading trust anchors: %v", err)
		return
	}
	if len(roots) == 0 {
		writeError(w, http.StatusBadRequest, "no CA trust anchors available to verify against")
		return
	}
	vreq.Roots = roots

	resp := VerifyArtifactResponse{}
	fillSignerDetails(&resp, sigDER)

	result, verr := signing.Verify(vreq)
	if verr != nil {
		resp.Valid = false
		resp.Reason = verr.Error()
		metrics.ArtifactVerifications.Inc("invalid")
		a.recordEvent(r, audit.ActionArtifactVerify, resp.SignerSubject, "", audit.ResultDenied, verr.Error())
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp.Valid = true
	resp.SignerSubject = result.SignerCertificate.Subject.String()
	resp.SignerSerial = result.SignerCertificate.SerialNumber.String()
	resp.SignerCertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.SignerCertificate.Raw}))
	resp.DigestAlgorithm = hashName(result.DigestAlgorithm)
	resp.Digest = hex.EncodeToString(result.ArtifactDigest)
	resp.Level = string(result.Level)
	resp.RevocationCRLs = result.RevocationCRLs
	resp.RevocationOCSPs = result.RevocationOCSPs
	resp.Timestamped = result.Timestamped
	resp.VerifiedAt = result.VerifiedAt.UTC().Format(time.RFC3339)
	if result.Timestamped {
		resp.TimestampTime = result.TimestampGenTime.UTC().Format(time.RFC3339)
		resp.TimestampSerial = result.TimestampSerial.String()
	}
	metrics.ArtifactVerifications.Inc("valid")
	a.recordEvent(r, audit.ActionArtifactVerify, resp.SignerSubject, "", audit.ResultSuccess,
		fmt.Sprintf("digest=%s:%s level=%s timestamped=%t", resp.DigestAlgorithm, resp.Digest, resp.Level, resp.Timestamped))
	writeJSON(w, http.StatusOK, resp)
}

// SignerInfoResponse is one configured signing identity in GET /api/sign/signers.
type SignerInfoResponse struct {
	Name             string `json:"name"`
	Subject          string `json:"subject"`
	Serial           string `json:"serial"`
	NotBefore        string `json:"not_before"`
	NotAfter         string `json:"not_after"`
	DigestAlgorithm  string `json:"digest_algorithm"`
	TimestampDefault bool   `json:"timestamp_default"`
	LevelDefault     string `json:"level_default,omitempty"`
	Tenant           string `json:"tenant"`
}

// ListSigners handles GET /api/sign/signers: the configured signing identities,
// confined to tenants the caller belongs to.
func (a *API) ListSigners(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "an assigned role is required")
		return
	}
	out := []SignerInfoResponse{}
	if a.signingService != nil {
		for _, sc := range a.signingService.Signers() {
			if !a.isTenantMember(user, sc.TenantID) {
				continue
			}
			out = append(out, SignerInfoResponse{
				Name:             sc.Name,
				Subject:          sc.Certificate.Subject.String(),
				Serial:           sc.Certificate.SerialNumber.String(),
				NotBefore:        sc.Certificate.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:         sc.Certificate.NotAfter.UTC().Format(time.RFC3339),
				DigestAlgorithm:  hashName(sc.Digest),
				TimestampDefault: sc.TimestampByDefault,
				LevelDefault:     string(sc.DefaultLevel),
				Tenant:           sc.TenantID,
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// trustAnchorsFor collects the CA certificates the caller may verify against:
// a single named CA (which must be visible to the caller) or every X.509 CA of
// the caller's tenants (all CAs for root/platform principals).
func (a *API) trustAnchorsFor(r *http.Request, user *models.UserInfo, caID string) ([]*x509.Certificate, error) {
	if caID != "" {
		ca, err := a.db.GetCA(caID)
		if err != nil {
			return nil, err
		}
		if ca == nil || ca.Certificate == "" || !a.isTenantMember(user, ca.TenantID) {
			// Same shape for missing and cross-tenant: don't disclose existence.
			return nil, nil
		}
		middleware.SetTenant(r.Context(), ca.TenantID)
		cert, err := pki.ParseCertificatePEM([]byte(ca.Certificate))
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	}
	cas, err := a.db.ListCAs()
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for _, ca := range cas {
		if ca.Certificate == "" || !a.isTenantMember(user, ca.TenantID) {
			continue
		}
		cert, err := pki.ParseCertificatePEM([]byte(ca.Certificate))
		if err != nil {
			continue // a single unparsable stored CA must not break verification
		}
		out = append(out, cert)
	}
	return out, nil
}

// decodeSignature accepts a detached signature as base64 DER or a PEM block.
func decodeSignature(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, fmt.Errorf("signature PEM did not decode")
		}
		return block.Bytes, nil
	}
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("signature is neither PEM nor valid base64: %v", err)
	}
	return der, nil
}

// fillSignerDetails best-effort extracts signer identity and timestamp facts
// from a signature so an invalid-verdict response still names what was checked.
func fillSignerDetails(resp *VerifyArtifactResponse, sigDER []byte) {
	p, err := cms.ParseSignedData(sigDER)
	if err != nil {
		return
	}
	for _, c := range p.Certificates {
		resp.SignerSubject = c.Subject.String()
		resp.SignerSerial = c.SerialNumber.String()
		break
	}
	if raw, ok := p.UnauthenticatedAttribute(signing.OIDTimeStampToken); ok {
		if info, err := tsa.ParseTokenInfo(raw.FullBytes); err == nil {
			resp.Timestamped = true
			resp.TimestampTime = info.GenTime.UTC().Format(time.RFC3339)
			resp.TimestampSerial = info.SerialNumber.String()
		}
	}
}

// hashName renders a crypto.Hash as its config/JSON identifier.
func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	case crypto.SHA1:
		return "sha1"
	default:
		return h.String()
	}
}
