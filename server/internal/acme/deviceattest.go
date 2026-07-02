package acme

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// deviceAttestResponse is the challenge-response payload a client POSTs to
// answer a device-attest-01 challenge (draft-ietf-acme-device-attest §5): a
// JSON object carrying the base64url-encoded WebAuthn attestation object.
type deviceAttestResponse struct {
	AttObj string `json:"attObj"`
}

// validateDeviceAttest01 verifies a device-attest-01 challenge response. It
// decodes the attestation object from the request payload, verifies it through
// the configured attestation.Verifier (Apple/TPM statement, chained to a trusted
// manufacturer root and committed to this challenge's key authorization), and
// records a cert.attestation audit event and metrics. It returns nil on success
// or an ACME Problem describing the failure.
func (s *Server) validateDeviceAttest01(r *http.Request, acct *acmeAccount, authz *models.ACMEAuthorization, payload []byte, keyAuth string) *Problem {
	mode := s.attestationMode()
	if mode == attestation.ModeOff || s.cfg.Attestation == nil {
		// The challenge should never have been offered; treat as unsupported.
		return newProblem(probMalformed, http.StatusBadRequest, "device-attest-01 is not enabled")
	}

	var resp deviceAttestResponse
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &resp); err != nil {
			return s.recordAttestFailure(r, acct, authz, mode, true,
				"malformed device-attest-01 payload: "+err.Error())
		}
	}
	var attObj []byte
	if resp.AttObj != "" {
		// The attestation object is base64url; tolerate both raw and padded forms.
		decoded, err := decodeBase64URL(resp.AttObj)
		if err != nil {
			return s.recordAttestFailure(r, acct, authz, mode, true,
				"attObj is not valid base64url: "+err.Error())
		}
		attObj = decoded
	}

	dec := s.cfg.Attestation.VerifyACMEDeviceAttest(s.cfg.Profile, attObj, keyAuth)

	// For device-attest-01 the challenge itself IS the proof of hardware
	// possession, so it passes only when the attestation actually verified —
	// regardless of whether the mode is permissive or require. (The mode governs
	// whether the challenge is offered at all.)
	if dec.Result == nil || !dec.Result.Verified {
		return s.recordAttestFailure(r, acct, authz, mode, dec.Missing, dec.Detail)
	}

	metrics.AttestationChecks.Inc("acme", string(dec.Mode), "pass")
	metrics.AttestationVerified.Inc(dec.Result.Format)
	s.recordEvent(r, acct.rec.ID, audit.ActionCertAttestation, authz.OrderID, audit.ResultSuccess, dec.Detail)
	return nil
}

// recordAttestFailure records a denied cert.attestation audit event and the
// denial metric, then returns a badAttestationStatement Problem.
func (s *Server) recordAttestFailure(r *http.Request, acct *acmeAccount, authz *models.ACMEAuthorization, mode attestation.Mode, missing bool, detail string) *Problem {
	metrics.AttestationDenied.Inc("acme")
	label := "invalid"
	if missing {
		label = "missing"
	}
	metrics.AttestationChecks.Inc("acme", string(mode), label)
	s.recordEvent(r, acct.rec.ID, audit.ActionCertAttestation, authz.OrderID, audit.ResultDenied, detail)
	return newProblem(probBadAttestation, http.StatusForbidden, "device attestation failed: "+detail)
}

// decodeBase64URL decodes base64url with or without padding.
func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
