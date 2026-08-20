package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// YubiHSM device-authenticity attestation over the REST API (Task 189, exposed
// for console parity in Task 190).
//
// The split mirrors the key-attestation endpoints next door, and for the same
// reason: producing an attestation needs the device (hsm:manage), while checking
// one needs nothing but the bytes (audit:read), and requiring device access to
// evaluate a claim about the device would defeat the point.
//
// What it establishes is a different claim from the key endpoints, though.
// GetHSMKeyAttestation says what an object on the device is; this says the
// device itself is genuine Yubico hardware carrying the serial it claims, as
// certified by Yubico's published attestation CA. Both matter: a perfect key
// attestation from a device nobody has authenticated is an assertion signed by
// an unknown key.

// attestDeviceRequest is the body of the device-attestation endpoint.
type attestDeviceRequest struct {
	// Challenge is the nonce the device must answer. Empty means "generate a
	// fresh one", which is what an operator clicking the button wants; an auditor
	// who chose the nonce themselves sends it here so the answer is to *their*
	// request rather than to one the audited party picked.
	Challenge string `json:"challenge,omitempty"`
	// NoChallenge takes the read-only form: read and check the device
	// certificate without making the device answer anything. It establishes that
	// a genuine YubiHSM with this serial exists, not that it is the one on the
	// other end of the cable — VerifyDevice says so plainly in its verdict.
	NoChallenge bool `json:"no_challenge,omitempty"`
	// ObjectID overrides the reserved handle the throwaway challenge key
	// occupies. Zero uses hsmattest.DefaultDeviceChallengeKeyID.
	ObjectID uint16 `json:"object_id,omitempty"`
	// ExpectedSerial, when set, must equal the certified serial.
	ExpectedSerial string `json:"expected_serial,omitempty"`
}

// deviceAttestationResponse carries the bundle and this server's verdict on it.
// The bundle travels with the verdict for the same reason the key endpoints do
// it: a relying party is meant to re-derive the conclusion, not accept ours.
type deviceAttestationResponse struct {
	Attestation  *hsmattest.DeviceAttestation `json:"attestation"`
	Verification *hsmattest.DeviceResult      `json:"verification"`
}

// deviceAttestationPolicy derives the device policy from the configured
// key-attestation policy.
//
// The two share trust anchors and the anchoring requirement — a deployment that
// trusts a set of Yubico attestation roots for keys trusts them for devices —
// which is exactly the relationship config.DeviceAttestationPolicy encodes.
// Deriving it here rather than installing a second policy keeps the two from
// drifting apart, and means a deployment that pins custom roots pins them once.
//
// The returned policy is a value, so per-request expectations can be set on it.
func (a *API) deviceAttestationPolicy() hsmattest.DevicePolicy {
	key := a.attestationPolicy()
	pol := hsmattest.DefaultDevicePolicy()
	pol.RequireAnchoredChain = key.RequireAnchoredChain
	pol.Roots, pol.Intermediates = key.Roots, key.Intermediates
	return pol
}

// AttestDevice proves the attached YubiHSM is genuine Yubico hardware and
// reports its verified serial number.
func (a *API) AttestDevice(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageHSM) {
		writeError(w, http.StatusForbidden, "hsm:manage capability required (admin role)")
		return
	}

	var req attestDeviceRequest
	// An empty body is the common case (attest with a fresh challenge), so it is
	// accepted rather than rejected as malformed.
	if r.Body != nil {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
		if err := dec.Decode(&req); err != nil && err.Error() != "EOF" {
			writeError(w, http.StatusBadRequest, "invalid request body: %v", err)
			return
		}
	}
	if req.NoChallenge && strings.TrimSpace(req.Challenge) != "" {
		writeError(w, http.StatusBadRequest, "challenge and no_challenge are mutually exclusive")
		return
	}

	pol := a.deviceAttestationPolicy()
	pol.ExpectedSerial = strings.TrimSpace(req.ExpectedSerial)

	// A challenge is the difference between authenticating the device and
	// authenticating a certificate, so it happens unless the caller asks for the
	// read-only form.
	nonce := strings.TrimSpace(req.Challenge)
	switch {
	case req.NoChallenge:
		nonce = ""
		pol.RequireProofOfPossession = false
	case nonce == "":
		var err error
		if nonce, err = hsmattest.NewChallenge(); err != nil {
			writeError(w, http.StatusInternalServerError, "generating a device challenge: %v", err)
			return
		}
	}
	pol.ExpectedChallenge = nonce

	// Answering a challenge writes three force-audited entries to the device's
	// 62-entry log ring, so drain on both sides exactly as the key-attestation
	// path does: a full ring makes the device refuse the command outright, and
	// unaccounted entries afterwards are what the audit subsystem alarms on.
	a.consumeHSMAuditLogs("")
	auth := hsmattest.NewDeviceAuthenticator(a.hsmCfg)
	auth.ChallengeObjectID = req.ObjectID
	att, err := auth.Attest(r.Context(), nonce)
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionHSMDeviceAttestation, "hsm_device", "", audit.ResultError,
			fmt.Sprintf("device attestation failed: %v", err))
		writeError(w, http.StatusInternalServerError, "attesting device: %v", err)
		return
	}

	res := hsmattest.VerifyDevice(att, pol)
	a.recordDeviceAttestation(r, res)

	// A failed verification is reported with 200 for the same reason the key
	// endpoint does it: the request succeeded and the verdict is the answer.
	writeJSON(w, http.StatusOK, deviceAttestationResponse{Attestation: att, Verification: res})
}

// verifyDeviceAttestationRequest is the body of the offline verify endpoint.
type verifyDeviceAttestationRequest struct {
	// Attestation is a device-attestation bundle as produced by AttestDevice or
	// `secsy-ca hsm-attest device`. Taking the whole bundle rather than loose
	// fields is deliberate: it is what an auditor was handed, and re-typing its
	// parts is where transcription errors turn into wrong verdicts.
	Attestation *hsmattest.DeviceAttestation `json:"attestation"`
	// ExpectedChallenge, when set, must equal the nonce the bundle answers. An
	// auditor who chose the nonce sets this; without it the bundle proves
	// possession at some unknown time rather than in answer to their request.
	ExpectedChallenge string `json:"expected_challenge,omitempty"`
	// ExpectedSerial, when set, must equal the certified serial.
	ExpectedSerial string `json:"expected_serial,omitempty"`
	// AllowNoChallenge accepts a bundle that answers no challenge, downgrading
	// the claim to "a genuine YubiHSM with this serial exists".
	AllowNoChallenge bool `json:"allow_no_challenge,omitempty"`
	// RequireAnchoredChain overrides the configured anchoring requirement.
	RequireAnchoredChain *bool `json:"require_anchored_chain,omitempty"`
}

// VerifyDeviceAttestation checks a caller-supplied device attestation.
//
// It touches no device and no database, so an auditor handed a bundle can
// evaluate it here. Gated on audit:read rather than hsm:manage for the same
// reason as the Task 167 audit bundle and the key-attestation verifier:
// requiring the capability that administers the device would mean only the
// audited party could check the evidence.
func (a *API) VerifyDeviceAttestation(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "audit:read capability required (admin or auditor role)")
		return
	}

	var req verifyDeviceAttestationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: %v", err)
		return
	}
	if req.Attestation == nil || strings.TrimSpace(req.Attestation.DeviceCertificatePEM) == "" {
		writeError(w, http.StatusBadRequest, "attestation.device_certificate_pem is required")
		return
	}

	pol := a.deviceAttestationPolicy()
	pol.ExpectedChallenge = strings.TrimSpace(req.ExpectedChallenge)
	pol.ExpectedSerial = strings.TrimSpace(req.ExpectedSerial)
	if req.AllowNoChallenge {
		pol.RequireProofOfPossession = false
	}
	if req.RequireAnchoredChain != nil {
		pol.RequireAnchoredChain = *req.RequireAnchoredChain
	}

	res := hsmattest.VerifyDevice(req.Attestation, pol)
	writeJSON(w, http.StatusOK, map[string]any{"verification": res})
}

// recordDeviceAttestation writes the audit event for one checked device
// attestation. The certified serial is the object identifier because it is the
// answer the operation exists to produce — an audit trail that says "a device
// was attested" without saying which device is worth very little.
func (a *API) recordDeviceAttestation(r *http.Request, res *hsmattest.DeviceResult) {
	result := audit.ResultSuccess
	if !res.Verified {
		result = audit.ResultError
	}
	a.recordEvent(r, audit.ActionHSMDeviceAttestation, "hsm_device", res.Serial, result, res.Summary)
}
