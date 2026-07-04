package handlers

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Single-request pre-issuance dry-run / validation-preview endpoint (Task 113):
// POST /api/ca/{id}/certificates:preview, mirrored on gRPC (PreviewCertificate).
//
// It validates one would-be issuance through the full fail-closed gate stack —
// certlint (Task 27/88), CAA (Task 31/96), Name Constraints & certificate policy
// (Task 46), S/MIME policy (Task 66), validity caps, the attestation posture
// (Task 49), and the manual-approval "would-park" signal (Task 84) — and returns
// the resolved leaf extensions plus each gate's pass/fail/reason, WITHOUT calling
// the HSM to sign, allocating a durable serial, persisting a record, appending an
// audit event, or taking a rate-limit / tenant reservation. It lets operators and
// CI validate a request before a real, HSM-consuming issuance.
//
// Authorization is exactly the issue capability a single POST /issue call needs
// (canIssueOn, tenant-scoped). The endpoint is deliberately side-effect-free: it
// records no audit event and increments no issuance metric, so a preview can be
// run freely without polluting the audit trail or operational dashboards.

// PreviewCertificate handles POST /api/ca/{id}/certificates:preview.
func (a *API) PreviewCertificate(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req models.PreviewCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	spec, berr := previewSpecFromRequest(caID, req, user)
	if berr != nil {
		writeError(w, http.StatusBadRequest, "%v", berr)
		return
	}
	result, err := a.PreviewIssuance(r.Context(), spec)
	if err != nil {
		// A resolution error (unknown CA/profile, malformed CSR) is a client error;
		// gate failures are reported inside the 200 body, not as an HTTP error.
		writeError(w, http.StatusBadRequest, "issuance preview failed: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// PreviewIssuance is the transport-agnostic core of the issuance preview, shared
// by the REST and gRPC surfaces. It runs the ca-layer gate stack (no HSM / no
// persistence / no serial consumption) and then refines the two verdicts the ca
// layer cannot resolve on its own: the manual-approval "would-park" signal (which
// needs the four-eyes engine state) and the attestation posture (an
// enrollment-protocol concern layered above ca). It records no audit event and no
// metric — the preview is a pure read.
func (a *API) PreviewIssuance(ctx context.Context, spec ca.PreviewSpec) (*ca.PreviewResult, error) {
	mgr := ca.NewManager(a.db, a.keyProvider)
	result, err := mgr.PreviewIssuance(ctx, spec)
	if err != nil {
		return nil, err
	}

	// Refine the approval verdict with the real four-eyes engine state: the profile
	// requesting approval only parks issuance when the engine is enabled and guards
	// cert.issue. Otherwise issuance proceeds immediately.
	if _, gated, perr := a.issuanceApprovalRequired(spec.Profile); perr == nil {
		switch {
		case gated:
			result.WouldPark = true
			result.SetGate(ca.GateVerdict{
				Name:   ca.GateApproval,
				Status: ca.GateWarn,
				Reason: "operator/API issuance would be held for four-eyes approval: the request would be parked and the certificate delivered only once the approver threshold is met",
			})
		case result.RequiresApproval:
			result.SetGate(ca.GateVerdict{
				Name:   ca.GateApproval,
				Status: ca.GatePass,
				Reason: "profile requests approval, but the approvals engine is not enabled for cert.issue; issuance would proceed immediately",
			})
		}
	}

	// Attestation posture (Task 49). Attestation is enforced on the enrollment
	// paths (EST/SCEP/ACME), not on the direct CSR issue path, so the preview
	// reports it as informational rather than a hard gate.
	result.SetGate(a.attestationPreviewGate(spec.Profile))
	result.Recompute()
	return result, nil
}

// attestationPreviewGate reports a profile's enrollment key-attestation posture
// for the preview. It never rejects (the direct issue path does not enforce
// attestation), so it is informational: "require" is surfaced as a warning that
// enrollment would demand attestation this preview cannot supply.
func (a *API) attestationPreviewGate(profileName string) ca.GateVerdict {
	// Verifier.Mode is nil-safe and returns ModeOff when no verifier is installed.
	switch a.attestationVerifier.Mode(profileName) {
	case attestation.ModeRequire:
		return ca.GateVerdict{
			Name:   ca.GateAttestation,
			Status: ca.GateWarn,
			Reason: "profile requires hardware key attestation on the enrollment paths (EST/SCEP/ACME); the direct CSR issue path does not verify it, so this preview cannot confirm an attestation would satisfy the requirement",
		}
	case attestation.ModePermissive:
		return ca.GateVerdict{
			Name:   ca.GateAttestation,
			Status: ca.GateSkipped,
			Reason: "profile evaluates attestation permissively on enrollment paths (never blocking)",
		}
	default: // ModeOff / no verifier installed
		return ca.GateVerdict{
			Name:   ca.GateAttestation,
			Status: ca.GateSkipped,
			Reason: "attestation not required for this profile",
		}
	}
}

// previewSpecFromRequest builds a ca.PreviewSpec from a decoded REST request. The
// requested validity is passed through raw (not globally capped) so the validity
// gate can report a request that exceeds the profile maximum.
func previewSpecFromRequest(caID string, req models.PreviewCertRequest, user *models.UserInfo) (ca.PreviewSpec, error) {
	spec := ca.PreviewSpec{
		CAID:        caID,
		CSRPEM:      []byte(req.CSR),
		Profile:     req.Profile,
		Validity:    daysToDuration(req.ValidityDays),
		RequestedBy: user.Subject,
		MustStaple:  req.MustStaple,
	}
	if req.CSR == "" {
		spec.Subject = pkix.Name{CommonName: req.CommonName}
		spec.DNSNames = req.DNSNames
		spec.EmailAddresses = req.EmailAddresses
		spec.URIs = req.URIs
		for _, ip := range req.IPAddresses {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return ca.PreviewSpec{}, fmt.Errorf("invalid ip_addresses entry %q", ip)
			}
			spec.IPAddresses = append(spec.IPAddresses, parsed)
		}
	}
	return spec, nil
}
