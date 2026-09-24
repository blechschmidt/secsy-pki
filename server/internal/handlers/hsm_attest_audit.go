package handlers

// REST counterpart of `secsy-ca hsm-attest audit` (Task 198) — attesting every
// asymmetric key the device holds in one pass.
//
// The per-key endpoints answer "is this one key safe". This one answers the
// question an operator actually has: "is ANYTHING on this device exportable".
// A key that was created exportable-under-wrap, or imported rather than
// generated, is invisible until something enumerates them — which is why the
// posture check has to walk the inventory rather than the CA list.
//
// Two properties are inherited deliberately from the CLI's audit pass:
//
//   - No per-key expectation is imposed. Each key is judged on the device's own
//     assertions, because this pass is an inventory: there is no expected public
//     key to bind to when the key is not (yet) referenced by anything.
//   - One key's failure is a datum, not a failed request. A device with one
//     unattestable object still owes the operator the verdict on the other
//     twenty, so a per-key error becomes a row carrying the error and the rollup
//     counts it, exactly as the CLI's table prints "ERROR: …" on that line and
//     keeps walking.
//
// It reuses both halves rather than writing a third: providerKeyDescriptors
// (keyinventory.go) enumerates, attestKeyVerdict (hsm_attest.go) attests and
// verifies. The one difference from the CLI is the addressing: the CLI holds raw
// device object handles and calls AttestObject, while this walks the provider
// inventory and attests by label — so a key with no label, or a duplicated one,
// surfaces here as an error row rather than an attested one.

import (
	"fmt"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// HSMKeyAuditEntry is one key's line in the device-wide attestation audit.
// Attestation and Verification are present when the device answered; Error is
// present when it did not, and the two cases are mutually exclusive.
type HSMKeyAuditEntry struct {
	// Label is the provider label the key was attested by.
	Label string `json:"label"`
	// KeyType is what the inventory reports for the key, so an error row still
	// says what the unattestable object is.
	KeyType string `json:"key_type,omitempty"`
	// CALabel names the CA bound to this key, empty when no CA record references
	// it (a KEK, TSA, signing or orphaned key) — the same annotation
	// GET /api/inventory/keys makes, and the one that turns "some object is
	// exportable" into "which of our authorities is affected".
	CALabel      string                 `json:"ca_label,omitempty"`
	Attestation  *hsmattest.Attestation `json:"attestation,omitempty"`
	Verification *hsmattest.Result      `json:"verification,omitempty"`
	// Error reports why this key could not be attested. It is a datum about one
	// key, not a failure of the audit.
	Error string `json:"error,omitempty"`
}

// HSMAttestationAudit is the whole-device verdict: one entry per key plus the
// rollup an operator reads first. It is deliberately NOT named
// <OperationId>Response — oapi-codegen derives that name for the generated
// client's response wrapper type.
type HSMAttestationAudit struct {
	// Provider is the backend that was enumerated.
	Provider string `json:"provider"`
	// Keys carries one entry per enumerated key, label-sorted.
	Keys []HSMKeyAuditEntry `json:"keys"`
	// Total is len(Keys): every key the provider holds.
	Total int `json:"total"`
	// Verified counts keys that satisfied the attestation policy in full.
	Verified int `json:"verified"`
	// Failed counts keys the device attested but which failed policy.
	Failed int `json:"failed"`
	// Errors counts keys that could not be attested at all.
	Errors int `json:"errors"`
	// Exportable counts attested keys whose capabilities permit export — the
	// headline finding this pass exists to surface.
	Exportable int `json:"exportable"`
	// Imported counts attested keys that were not generated on the device, so a
	// copy may have existed before they arrived.
	Imported int `json:"imported"`
	// Summary is the one-line verdict, worded as the CLI's closing line.
	Summary string `json:"summary"`
}

// GetHSMAttestationAudit handles GET /api/hsm/attestation-audit: attest every key
// the provider holds and report the per-key verdicts with a rollup.
//
// Gated on hsm:manage like the other attestation producers: it reaches the
// physical device once per key, and the response describes the device's whole
// object layout, which is platform information regardless of which tenant owns
// any particular key.
func (a *API) GetHSMAttestationAudit(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageHSM) {
		writeError(w, http.StatusForbidden, "hsm:manage capability required (admin role)")
		return
	}

	keys, ok := a.providerKeyDescriptors(w, r)
	if !ok {
		return
	}
	caByLabel, err := a.caLabelsByKeyLabel()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing CAs: %v", err)
		return
	}

	pol := a.attestationPolicy()
	resp := HSMAttestationAudit{Provider: a.keyProvider.Name(), Keys: []HSMKeyAuditEntry{}, Total: len(keys)}
	for _, k := range keys {
		entry := HSMKeyAuditEntry{Label: k.Label, KeyType: k.KeyType, CALabel: caByLabel[k.Label]}
		att, res, err := a.attestKeyVerdict(r.Context(), k.Label, pol)
		if err != nil {
			entry.Error = err.Error()
			resp.Errors++
			resp.Keys = append(resp.Keys, entry)
			continue
		}
		entry.Attestation, entry.Verification = att, res
		if res.Verified {
			resp.Verified++
		} else {
			resp.Failed++
		}
		if !res.NonExportable {
			resp.Exportable++
		}
		if !res.GeneratedOnDevice {
			resp.Imported++
		}
		resp.Keys = append(resp.Keys, entry)
	}
	resp.Summary = auditSummary(resp)

	// One rollup event, not one per key: the pass is the operation, and the
	// per-key detail is in the response the operator is reading. A pass that
	// found anything is recorded as an error result so it stands out in the log.
	result := audit.ResultSuccess
	if resp.Failed > 0 || resp.Errors > 0 {
		result = audit.ResultError
	}
	a.recordEvent(r, audit.ActionHSMKeyAttestation, "hsm_device", "attestation-audit", result, resp.Summary)

	// Findings are reported with 200: the request succeeded and the verdicts are
	// the answer. An error status would make a client's error handling swallow
	// exactly the finding it needs to see — the same reason the per-key endpoints
	// report a failed verification with 200.
	writeJSON(w, http.StatusOK, resp)
}

// auditSummary words the rollup the way the CLI's closing line does: the count
// that passed when everything did, and what went wrong when it did not.
func auditSummary(resp HSMAttestationAudit) string {
	switch {
	case resp.Total == 0:
		return "No keys on the device."
	case resp.Failed == 0 && resp.Errors == 0:
		return fmt.Sprintf("%s attested; all satisfy the attestation policy.", keyCount(resp.Total))
	case resp.Errors == 0:
		return fmt.Sprintf("%d of %s did not satisfy the attestation policy.", resp.Failed, keyCount(resp.Total))
	case resp.Failed == 0:
		return fmt.Sprintf("%s of %d could not be attested.", keyCount(resp.Errors), resp.Total)
	default:
		return fmt.Sprintf("%d of %s did not satisfy the attestation policy; %d could not be attested.",
			resp.Failed, keyCount(resp.Total), resp.Errors)
	}
}

// keyCount renders "1 key" / "2 keys".
func keyCount(n int) string {
	if n == 1 {
		return "1 key"
	}
	return fmt.Sprintf("%d keys", n)
}
