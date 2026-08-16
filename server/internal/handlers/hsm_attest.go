package handlers

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// YubiHSM key attestation over the REST API (Task 168).
//
// Two operations, deliberately separated:
//
//   - Producing an attestation needs the device, so it is gated on hsm:manage.
//   - Verifying one needs nothing but the bytes, so it is gated on audit:read
//     and is the endpoint a third party uses. Requiring device access to check
//     a claim about the device would defeat the point.
//
// The verify endpoint is also why the response carries certificates rather than
// only conclusions: a relying party is meant to re-derive the verdict, not
// accept this server's word for it.

// hsmAttestationResponse is what both the fetch and CA-key endpoints return.
type hsmAttestationResponse struct {
	Attestation  *hsmattest.Attestation `json:"attestation"`
	Verification *hsmattest.Result      `json:"verification"`
}

// attestationPolicy returns the configured policy, or the built-in default when
// none was installed (tests, and any caller that skips SetKeyAttestationPolicy).
// It cannot fail: the server resolves trust anchors and capability names once at
// startup, so a bad value is a boot failure rather than a per-request error.
//
// The returned Policy is a copy, so per-request expectations (expected key,
// label, serial) can be set on it without mutating shared state.
func (a *API) attestationPolicy() hsmattest.Policy {
	if a.attestPolicy != nil {
		return *a.attestPolicy
	}
	return hsmattest.DefaultPolicy()
}

// GetHSMKeyAttestation attests one asymmetric key on the YubiHSM by label and
// returns the attestation together with this server's own verdict on it.
func (a *API) GetHSMKeyAttestation(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageHSM) {
		writeError(w, http.StatusForbidden, "hsm:manage capability required (admin role)")
		return
	}
	label := r.PathValue("label")
	if strings.TrimSpace(label) == "" {
		writeError(w, http.StatusBadRequest, "key label is required")
		return
	}

	a.attestAndRespond(w, r, label, nil, a.attestationPolicy())
}

// GetCAKeyAttestation attests the HSM key behind one CA and binds the result to
// that CA's certificate.
//
// The binding is the point. An attestation on its own proves that some object
// on the device is non-exportable; only comparing the attested public key
// against the key in the CA certificate shows that the object in question is
// the one this CA actually signs with. The endpoint therefore sets
// ExpectedPublicKey from the stored CA certificate, and a mismatch fails.
//
// It is gated on hsm:manage rather than a tenant-scoped capability because the
// operation reaches the physical device and the response describes it — serial,
// firmware, and the other objects' domain layout — which is platform
// information regardless of which tenant owns the CA.
func (a *API) GetCAKeyAttestation(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageHSM) {
		writeError(w, http.StatusForbidden, "hsm:manage capability required (admin role)")
		return
	}
	caID := r.PathValue("id")

	caRec, err := a.db.GetCA(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CA lookup failed: %v", err)
		return
	}
	if caRec == nil {
		writeError(w, http.StatusNotFound, "CA %q not found", caID)
		return
	}
	label := pki.ExtractKeyLabel(caRec.PKCS11URI)
	if label == "" {
		writeError(w, http.StatusBadRequest,
			"CA %q has no resolvable HSM key label (pkcs11_uri=%q); only HSM-backed CAs can be attested", caID, caRec.PKCS11URI)
		return
	}

	pol := a.attestationPolicy()
	pol.ExpectedLabel = label

	// Bind to the CA certificate's key when there is one. A CA that exists only
	// as an SSH signing key has no X.509 certificate; the public key column
	// still pins the key, so fall back to it rather than silently dropping the
	// binding that makes the attestation meaningful.
	if pub, err := caPublicKey(caRec.Certificate, caRec.PublicKey); err == nil && pub != nil {
		pol.ExpectedPublicKey = pub
	}

	a.attestAndRespond(w, r, label, &caID, pol)
}

// attestAndRespond performs the device round-trip, verifies, audits and writes.
func (a *API) attestAndRespond(w http.ResponseWriter, r *http.Request, label string, caID *string, pol hsmattest.Policy) {
	// Attestation is a force-audited device command that consumes a log entry,
	// so drain first for the same reason the other device endpoints do: a full
	// ring makes the device refuse the command outright.
	a.consumeHSMAuditLogs("")
	att, err := hsmattest.NewShellAttester(a.hsmCfg).AttestKey(r.Context(), label)
	a.consumeHSMAuditLogs("")
	if err != nil {
		metrics.KeyAttestations.Inc("error")
		writeError(w, http.StatusInternalServerError, "attesting key %q: %v", label, err)
		return
	}

	res := hsmattest.Verify(att, pol)
	metrics.RecordKeyAttestation(res)

	detail := res.Summary
	if caID != nil {
		detail = fmt.Sprintf("ca=%s %s", *caID, detail)
	}
	result := audit.ResultSuccess
	if !res.Verified {
		result = audit.ResultError
	}
	a.recordEvent(r, audit.ActionHSMKeyAttestation, "hsm_key", label, result, detail)

	// A failed verification is reported with 200: the request succeeded and the
	// verdict is the answer. Returning an error status would make a client's
	// error handling swallow exactly the finding it needs to see.
	writeJSON(w, http.StatusOK, hsmAttestationResponse{Attestation: att, Verification: res})
}

// verifyAttestationRequest is the body of the verify endpoint.
type verifyAttestationRequest struct {
	// CertificatePEM is the per-key attestation certificate.
	CertificatePEM string `json:"certificate_pem"`
	// DeviceCertificatePEM is the device attestation certificate that issued it.
	DeviceCertificatePEM string `json:"device_certificate_pem,omitempty"`
	// ExpectedPublicKeyPEM, when given, must equal the attested key. Accepts a
	// PUBLIC KEY or a CERTIFICATE, so a caller can paste the certificate whose
	// key they want to check without extracting the SPKI first.
	ExpectedPublicKeyPEM string `json:"expected_public_key_pem,omitempty"`
	// ExpectedLabel and ExpectedSerial, when given, must match the device's
	// assertions.
	ExpectedLabel  string `json:"expected_label,omitempty"`
	ExpectedSerial string `json:"expected_serial,omitempty"`
	// RequireAnchoredChain overrides the configured anchoring requirement.
	RequireAnchoredChain *bool `json:"require_anchored_chain,omitempty"`
}

// VerifyHSMAttestation verifies a caller-supplied YubiHSM key attestation.
//
// It touches no device and no database, so it is the endpoint an auditor uses
// against an attestation they were handed. Gating it on audit:read rather than
// hsm:manage follows the same reasoning as the Task 167 audit bundle: requiring
// the capability that administers the device would mean only the audited party
// could check the evidence.
func (a *API) VerifyHSMAttestation(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "audit:read capability required (admin or auditor role)")
		return
	}

	var req verifyAttestationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: %v", err)
		return
	}
	if strings.TrimSpace(req.CertificatePEM) == "" {
		writeError(w, http.StatusBadRequest, "certificate_pem is required")
		return
	}

	pol := a.attestationPolicy()
	pol.ExpectedLabel = req.ExpectedLabel
	pol.ExpectedSerial = req.ExpectedSerial
	if req.RequireAnchoredChain != nil {
		pol.RequireAnchoredChain = *req.RequireAnchoredChain
	}
	if s := strings.TrimSpace(req.ExpectedPublicKeyPEM); s != "" {
		pub, err := parseExpectedPublicKeyPEM(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expected_public_key_pem: %v", err)
			return
		}
		pol.ExpectedPublicKey = pub
	}

	att := &hsmattest.Attestation{
		CertificatePEM:       req.CertificatePEM,
		DeviceCertificatePEM: req.DeviceCertificatePEM,
	}
	res := hsmattest.Verify(att, pol)
	metrics.RecordKeyAttestation(res)
	writeJSON(w, http.StatusOK, map[string]any{"verification": res})
}

// caPublicKey recovers a CA's public key, preferring the X.509 certificate and
// falling back to the stored public-key column.
func caPublicKey(certPEM, pubPEM string) (crypto.PublicKey, error) {
	if s := strings.TrimSpace(certPEM); s != "" {
		if block, _ := pem.Decode([]byte(s)); block != nil && block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			return cert.PublicKey, nil
		}
	}
	if s := strings.TrimSpace(pubPEM); s != "" {
		return parseExpectedPublicKeyPEM(s)
	}
	return nil, nil
}

// parseExpectedPublicKeyPEM accepts either a PUBLIC KEY or a CERTIFICATE block.
func parseExpectedPublicKeyPEM(s string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("not valid PEM")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	default:
		return nil, fmt.Errorf("PEM type %q; want PUBLIC KEY or CERTIFICATE", block.Type)
	}
}
