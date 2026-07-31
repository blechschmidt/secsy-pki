package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ers"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
)

// RFC 4998 Evidence Records verify endpoint (Task 161): POST /api/ers/verify.
//
// It verifies a long-term-preservation Evidence Record — a stored record by id,
// or a standalone DER supplied in the body — end to end: every embedded RFC 3161
// archive timestamp's CMS signature and imprint, each reduced hash tree, the
// chain/sequence linkage across time-stamp and hash-tree renewals, and coverage
// of the protected data objects. For a stored audit-scope record the protected
// objects are re-derived from the event log, so the endpoint also proves the
// live audit chain still matches what the record attested.
//
// It is a pure read: no HSM is touched and nothing is signed. Certificate-path
// verification against TSA trust anchors is left to the `secsy-ca ers verify
// -tsa-ca` CLI; the endpoint checks token integrity, structure, and coverage.
// Authorization is the standard read standing (canRead / audit:read), matching
// the audit-log verify endpoint.

// VerifyEvidenceRecordRequest is the POST /api/ers/verify body. Provide either a
// stored record id, or a base64 DER record; artifact objects (base64) are
// supplied for records whose protected bytes are not re-derivable server-side.
type VerifyEvidenceRecordRequest struct {
	// ID is a stored Evidence Record's id.
	ID string `json:"id,omitempty"`
	// Record is the base64-encoded DER of a standalone Evidence Record.
	Record string `json:"record,omitempty"`
	// Objects are the base64-encoded protected data objects (required for a
	// standalone record or an artifact-scope stored record; ignored for an
	// audit-scope record, whose objects are re-derived from the event log).
	Objects []string `json:"objects,omitempty"`
}

// VerifyEvidenceRecord handles POST /api/ers/verify.
func (a *API) VerifyEvidenceRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	var req VerifyEvidenceRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if (req.ID == "") == (req.Record == "") {
		writeError(w, http.StatusBadRequest, "provide exactly one of \"id\" or \"record\"")
		return
	}

	objs, err := decodeErsObjects(req.Objects)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	var er *ers.EvidenceRecord
	target := ""
	if req.ID != "" {
		target = req.ID
		rec, gerr := a.db.GetEvidenceRecord(req.ID)
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, "looking up evidence record: %v", gerr)
			return
		}
		if rec == nil {
			writeError(w, http.StatusNotFound, "no evidence record with id %s", req.ID)
			return
		}
		er, err = ers.Parse(rec.Record)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "stored evidence record is corrupt: %v", err)
			return
		}
		// Re-derive audit-scope objects from the log unless the caller supplied
		// their own; an artifact-scope record needs supplied objects.
		if len(objs) == 0 && rec.Scope == ers.ScopeAudit {
			svc := ers.NewService(a.db, nil, ers.Options{})
			objs, err = svc.ResolveObjects(*rec)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "re-deriving audit objects: %v", err)
				return
			}
		}
	} else {
		der, derr := base64.StdEncoding.DecodeString(req.Record)
		if derr != nil {
			writeError(w, http.StatusBadRequest, "record is not valid base64: %v", derr)
			return
		}
		er, err = ers.Parse(der)
		if err != nil {
			writeError(w, http.StatusBadRequest, "parsing evidence record: %v", err)
			return
		}
	}

	res, err := ers.Verify(er, ers.VerifyOptions{Objects: objs})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verifying evidence record: %v", err)
		return
	}

	result := audit.ResultSuccess
	status := http.StatusOK
	if !res.Valid {
		result = audit.ResultDenied
		status = http.StatusConflict // 409 = the evidence record does not verify
	}
	a.recordEvent(r, audit.ActionERSVerify, target, "", result,
		fmt.Sprintf("valid=%t chains=%d objects=%d", res.Valid, len(res.Chains), len(res.Objects)))
	writeJSON(w, status, res)
}

// decodeErsObjects decodes base64 protected data objects, labelling each by
// index for the per-object verification report.
func decodeErsObjects(encoded []string) ([]ers.DataObject, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	objs := make([]ers.DataObject, 0, len(encoded))
	for i, e := range encoded {
		b, err := base64.StdEncoding.DecodeString(e)
		if err != nil {
			return nil, fmt.Errorf("object %d is not valid base64: %v", i, err)
		}
		objs = append(objs, ers.DataObject{ID: fmt.Sprintf("object:%d", i), Bytes: b})
	}
	return objs, nil
}
