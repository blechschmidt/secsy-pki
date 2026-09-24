package handlers

// REST surface for RFC 4998 Evidence Records — the counterpart of
// `secsy-ca ers list|generate|renew|export` (Task 198). Only `ers verify` had an
// API (POST /api/ers/verify, ers.go), so the console could show an operator that
// a record verifies but never which records exist, nor mint, renew, or hand one
// out. An Evidence Record whose TSA certificate quietly expires is worthless, so
// "which records exist and when do they need renewing" is exactly the question
// the console has to be able to answer.
//
// The split of HSM dependence follows the CLI's: list and export are pure reads
// over the store (usable during an HSM outage, like verify), while generate and
// renew need an archive-timestamp source and therefore build the TSA-role key
// provider lazily — and only when the internal TSA is that source, so a
// deployment pointing ers.tsa_url at an external TSA needs no local key at all.

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ers"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// ersDefaultPageSize / ersMaxPageSize bound GET /api/ers, matching the CT
// inclusion listing's convention (?limit=0 or an over-large limit means "as many
// as the hard cap allows"). Records are bounded by the number of preservation
// batches, so a page is cheap either way.
const (
	ersDefaultPageSize = 200
	ersMaxPageSize     = 1000
)

// maxERSAuditSpan caps how many event-log entries ONE audit-scope Evidence Record
// may cover. ers.GenerateAuditRange turns the requested span straight into a SQL
// LIMIT and then hashes every returned event into a Merkle tree in memory, so an
// unbounded span is a store-sized allocation driven by a single request field.
// A hundred thousand events is far more than any real preservation batch (the
// background cycle works in cursor-advancing increments) and still bounded; a
// larger range is split into several records, which is what RFC 4998 renewal
// operates on anyway.
const maxERSAuditSpan = 100_000

// EvidenceRecordListResponse is the body of GET /api/ers: a page of stored
// records, newest first, with the total count so the console can paginate. Each
// item is the same models.EvidenceRecord row `secsy-ca ers list -json` prints
// (the Evidence Record DER itself is never inlined here — fetch it from
// GET /api/ers/export).
type EvidenceRecordListResponse struct {
	Items  []models.EvidenceRecord `json:"items"`
	Total  int                     `json:"total"`
	Limit  int                     `json:"limit"`
	Offset int                     `json:"offset"`
}

// GenerateEvidenceRecordRequest is the body of POST /api/ers/generate — the REST
// form of `secsy-ca ers generate`. Exactly one scope must be named: an inclusive
// audit-event range, or one or more artifact objects.
type GenerateEvidenceRecordRequest struct {
	// AuditFrom/AuditTo are the inclusive event_log sequence range to preserve
	// (the -audit-from/-audit-to flags). Both are required together and are
	// mutually exclusive with Objects.
	AuditFrom int64 `json:"audit_from,omitempty"`
	AuditTo   int64 `json:"audit_to,omitempty"`
	// Objects are the base64-encoded artifact bytes to preserve, standing in for
	// the CLI's FILE arguments. They are NOT stored: renewing or verifying an
	// artifact-scope record later requires re-supplying exactly these bytes.
	Objects []string `json:"objects,omitempty"`
	// ObjectIDs optionally labels each object (the CLI uses the file path). When
	// given it must have one entry per object; otherwise objects are labelled
	// "object:<index>". These labels are persisted and are the only human record
	// of what an artifact-scope record covers.
	ObjectIDs []string `json:"object_ids,omitempty"`
	// Description is the human label for an artifact-scope record. It is ignored
	// for an audit range, which the preservation service labels itself ("audit
	// events N-M") so every consumer names the same range identically.
	Description string `json:"description,omitempty"`
	// Hash is the hash-tree algorithm: sha256, sha384, or sha512. Empty uses the
	// configured ers.hash (else sha256).
	Hash string `json:"hash,omitempty"`
}

// RenewEvidenceRecordRequest is the body of POST /api/ers/renew — the REST form
// of `secsy-ca ers renew`.
type RenewEvidenceRecordRequest struct {
	// ID is the stored record to renew. Required.
	ID string `json:"id"`
	// HashTree selects a hash-tree renewal (a new chain under a stronger
	// algorithm, for algorithm deprecation) instead of the default time-stamp
	// renewal (a fresh token before the TSA certificate expires).
	HashTree bool `json:"hashtree,omitempty"`
	// Hash is the target algorithm for a hash-tree renewal: sha256, sha384, or
	// sha512. Empty uses the configured ers.hash when it is stronger than
	// SHA-256, else sha512 — the CLI's default.
	Hash string `json:"hash,omitempty"`
	// Objects are the base64-encoded protected objects, required for a hash-tree
	// renewal of an artifact-scope record (whose bytes the server never stored).
	// An audit-scope record re-derives its objects from the event log.
	Objects []string `json:"objects,omitempty"`
}

// EvidenceRecordResponse is the body of POST /api/ers/generate and
// POST /api/ers/renew: the persisted row (flattened, exactly as `secsy-ca ers
// generate|renew -json` emits it) plus the renewal kind that produced it.
type EvidenceRecordResponse struct {
	models.EvidenceRecord
	// Kind is "generated" for a new record, or "timestamp"/"hashtree" for the
	// renewal that was performed.
	Kind string `json:"kind"`
}

// ExportEvidenceRecordResponse is the JSON body of GET /api/ers/export: the row,
// the decoded structure `secsy-ca ers export` prints, and the Evidence Record DER
// itself so the console can offer a download without a second call.
type ExportEvidenceRecordResponse struct {
	models.EvidenceRecord
	// Info is the decoded structure: version, chains, digest algorithms, and every
	// ArchiveTimeStamp with its genTime and TSA certificate expiry.
	Info ers.Info `json:"info"`
	// Record is the base64-encoded DER of the RFC 4998 EvidenceRecord — the bytes
	// `ers export -out FILE` writes, and exactly what POST /api/ers/verify accepts
	// in its own "record" field, so an export can be fed straight back in. Also
	// retrievable raw via ?format=der. It deliberately shadows the embedded row's
	// raw []byte field of the same name, which is never serialized (json:"-").
	Record string `json:"record"`
	// Size is the DER length in bytes.
	Size int `json:"size"`
}

// ListEvidenceRecords handles GET /api/ers — the REST form of `secsy-ca ers
// list`.
//
// Read-gated with the same standing as POST /api/ers/verify (canRead: any
// assigned role), and deliberately not narrowed to platform audit:read: a
// principal that may verify a record by id would otherwise be unable to discover
// the ids, and the rows carry preservation metadata (scope, hash, chain count,
// covered seq range, TSA expiry) rather than any event or artifact content. It is
// a pure read — no HSM, no signing, no audit event.
func (a *API) ListEvidenceRecords(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	limit, offset, ok := ersPageParams(w, r)
	if !ok {
		return
	}
	records, total, err := a.db.ListEvidenceRecords(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing evidence records: %v", err)
		return
	}
	if records == nil {
		records = []models.EvidenceRecord{}
	}
	writeJSON(w, http.StatusOK, EvidenceRecordListResponse{
		Items: records, Total: total, Limit: limit, Offset: offset,
	})
}

// ersPageParams reads ?limit / ?offset, writing the error response itself. A
// missing or zero limit means the hard cap; a malformed one is a request error
// (silently serving a different page than asked for is worse than a 400).
func ersPageParams(w http.ResponseWriter, r *http.Request) (limit, offset int, ok bool) {
	q := r.URL.Query()
	limit = ersDefaultPageSize
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid limit %q", v)
			return 0, 0, false
		}
		limit = n
	}
	if limit == 0 || limit > ersMaxPageSize {
		limit = ersMaxPageSize
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid offset %q", v)
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

// GenerateEvidenceRecord handles POST /api/ers/generate — the REST form of
// `secsy-ca ers generate`.
//
// Gated on the PLATFORM-wide ca:manage capability (a.can, so a tenant admin is
// denied): minting an Evidence Record signs with the deployment's timestamp
// authority over the shared audit chain, which is deployment infrastructure in
// exactly the way the TSA credential itself is, not a tenant resource.
func (a *API) GenerateEvidenceRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionERSGenerate, "", "", audit.ResultDenied, "platform ca:manage capability required")
		writeError(w, http.StatusForbidden, "platform ca:manage capability required (admin role)")
		return
	}

	var req GenerateEvidenceRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	// Scope selection, mirroring the CLI's mutual exclusion.
	auditMode := req.AuditFrom != 0 || req.AuditTo != 0
	switch {
	case auditMode && len(req.Objects) > 0:
		writeError(w, http.StatusBadRequest, "give either an audit range or artifact objects, not both")
		return
	case !auditMode && len(req.Objects) == 0:
		writeError(w, http.StatusBadRequest,
			"nothing to preserve: give \"audit_from\"/\"audit_to\" or one or more \"objects\"")
		return
	case auditMode && (req.AuditFrom == 0 || req.AuditTo == 0):
		writeError(w, http.StatusBadRequest, "audit_from and audit_to must be given together")
		return
	case auditMode && (req.AuditFrom < 1 || req.AuditTo < req.AuditFrom):
		writeError(w, http.StatusBadRequest, "invalid audit range %d-%d", req.AuditFrom, req.AuditTo)
		return
	}
	// Bound the range before it becomes a SQL LIMIT, and before opening a key
	// provider: the service would reject an impossible range the same way, but only
	// after an HSM session and a TSA round trip had been spent on it.
	//
	// Two bounds, in this order, because each covers what the other cannot.
	//
	// The span cap is applied to the REQUESTED range, before anything is read: it is
	// what bounds the SQL LIMIT and the hash tree built from the result, and it must
	// hold whatever the log's size and whether the head is readable at all. So
	// {"audit_from":1,"audit_to":9223372036854775807} is refused here rather than
	// quietly reinterpreted as something else.
	//
	// audit_to is then clamped DOWNWARD to the chain head, because a record cannot
	// cover events that do not exist — and clamping means "preserve through the end
	// of the log" works without the caller reading the head first.
	if auditMode {
		if span := req.AuditTo - req.AuditFrom + 1; span > maxERSAuditSpan {
			writeError(w, http.StatusBadRequest,
				"the requested range covers %d events; one evidence record preserves at most %d — split the range",
				span, maxERSAuditSpan)
			return
		}
		if head, err := a.db.MaxEventSeq(); err == nil {
			if req.AuditFrom > head {
				writeError(w, http.StatusBadRequest,
					"audit_from %d is past the event-log head %d", req.AuditFrom, head)
				return
			}
			if req.AuditTo > head {
				req.AuditTo = head
			}
		}
	}

	deps, ok := a.requireOps(w, "evidence-record generation")
	if !ok {
		return
	}
	hashName := req.Hash
	if hashName == "" {
		hashName = deps.Config.Ers.ResolvedHash()
	}
	hash := ers.HashByName(hashName)
	if hash == 0 {
		// hashName is the request's value, or the configured ers.hash when it was
		// omitted — name whichever one is actually unsupported.
		writeError(w, http.StatusBadRequest, "unsupported hash %q (want sha256, sha384, or sha512)", hashName)
		return
	}

	// Decode the artifact objects before opening a key provider: a malformed body
	// must not cost an HSM session.
	objs, err := ersObjects(req.Objects, req.ObjectIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	ts, release, ok := a.ersTimestamper(w, "evidence-record generation")
	if !ok {
		return
	}
	defer release()

	// The service appends its own ers.generate event (actor "ers") carrying the
	// scope and hash; the event recorded below adds what that path cannot know —
	// which operator asked for the record.
	svc := ers.NewService(a.db, ts, ers.Options{Hash: hash})
	var rec *models.EvidenceRecord
	if auditMode {
		rec, err = svc.GenerateAuditRange(r.Context(), req.AuditFrom, req.AuditTo)
	} else {
		desc := req.Description
		if desc == "" {
			desc = fmt.Sprintf("%d artifact(s)", len(objs))
		}
		rec, err = svc.GenerateArtifact(r.Context(), desc, objs)
	}
	if err != nil {
		a.recordEvent(r, audit.ActionERSGenerate, "", "", audit.ResultError, err.Error())
		// Nothing to preserve is the caller's mistake; a timestamp-source or
		// storage failure is ours.
		if errors.Is(err, ers.ErrEmpty) {
			writeError(w, http.StatusBadRequest, "generating evidence record: %v", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "generating evidence record: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionERSGenerate, rec.ID, rec.Description, audit.ResultSuccess, ersDetail(rec)+" via=api")
	writeJSON(w, http.StatusCreated, EvidenceRecordResponse{EvidenceRecord: *rec, Kind: "generated"})
}

// RenewEvidenceRecord handles POST /api/ers/renew — the REST form of `secsy-ca
// ers renew`. Same gate and TSA dependence as generation.
func (a *API) RenewEvidenceRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionERSRenew, "", "", audit.ResultDenied, "platform ca:manage capability required")
		writeError(w, http.StatusForbidden, "platform ca:manage capability required (admin role)")
		return
	}

	var req RenewEvidenceRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	deps, ok := a.requireOps(w, "evidence-record renewal")
	if !ok {
		return
	}

	rec, err := a.db.GetEvidenceRecord(req.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "looking up evidence record: %v", err)
		return
	}
	if rec == nil {
		writeError(w, http.StatusNotFound, "no evidence record with id %s", req.ID)
		return
	}
	er, err := ers.Parse(rec.Record)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stored evidence record is corrupt: %v", err)
		return
	}

	// Resolve the hash-tree target and the protected objects before touching a key
	// provider, so every request error is answered HSM-free.
	kind := "timestamp"
	var target crypto.Hash
	var objs []ers.DataObject
	if req.HashTree {
		kind = "hashtree"
		if req.Hash != "" {
			if target = ers.HashByName(req.Hash); target == 0 {
				writeError(w, http.StatusBadRequest, "unsupported hash %q (want sha256, sha384, or sha512)", req.Hash)
				return
			}
		} else {
			target = ersHashTreeTarget(deps.Config.Ers.ResolvedHash())
		}
		if objs, err = a.ersRenewObjects(*rec, req.Objects); err != nil {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
	}

	ts, release, ok := a.ersTimestamper(w, "evidence-record renewal")
	if !ok {
		return
	}
	defer release()

	var renewed *ers.EvidenceRecord
	if req.HashTree {
		renewed, err = er.RenewHashTree(r.Context(), ts, objs, target)
	} else {
		renewed, err = er.RenewTimestamp(r.Context(), ts)
	}
	if err != nil {
		a.recordEvent(r, audit.ActionERSRenew, rec.ID, rec.Description, audit.ResultError, "kind="+kind+" "+err.Error())
		writeError(w, http.StatusInternalServerError, "renewing evidence record: %v", err)
		return
	}
	// RefreshRow is the shared metadata update the background job and the CLI use,
	// so a record renewed through the API is indistinguishable from either.
	if err := ers.RefreshRow(rec, renewed, time.Now()); err != nil {
		a.recordEvent(r, audit.ActionERSRenew, rec.ID, rec.Description, audit.ResultError, "kind="+kind+" "+err.Error())
		writeError(w, http.StatusInternalServerError, "encoding renewed evidence record: %v", err)
		return
	}
	if err := a.db.UpdateEvidenceRecord(rec); err != nil {
		a.recordEvent(r, audit.ActionERSRenew, rec.ID, rec.Description, audit.ResultError, "kind="+kind+" "+err.Error())
		writeError(w, http.StatusInternalServerError, "persisting renewed evidence record: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionERSRenew, rec.ID, rec.Description, audit.ResultSuccess,
		"kind="+kind+" "+ersDetail(rec)+" via=api")
	writeJSON(w, http.StatusOK, EvidenceRecordResponse{EvidenceRecord: *rec, Kind: kind})
}

// ExportEvidenceRecord handles GET /api/ers/export?id=... — the REST form of
// `secsy-ca ers export`. ?format=der streams the raw Evidence Record DER (what
// `-out FILE` writes); the default JSON body carries the row, the decoded
// structure, and the same DER base64-encoded.
//
// Read-gated exactly like the listing: an Evidence Record is a set of hashes and
// RFC 3161 tokens over data the holder must already have, so handing it out
// discloses no event or artifact content. HSM-free.
func (a *API) ExportEvidenceRecord(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "der" {
		writeError(w, http.StatusBadRequest, "invalid format %q (want json or der)", format)
		return
	}

	rec, err := a.db.GetEvidenceRecord(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "looking up evidence record: %v", err)
		return
	}
	if rec == nil {
		writeError(w, http.StatusNotFound, "no evidence record with id %s", id)
		return
	}

	if format == "der" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "evidence-record-"+rec.ID+".der"))
		_, _ = w.Write(rec.Record)
		return
	}

	er, err := ers.Parse(rec.Record)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stored evidence record is corrupt: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, ExportEvidenceRecordResponse{
		EvidenceRecord: *rec,
		Info:           er.Info(),
		Record:         base64.StdEncoding.EncodeToString(rec.Record),
		Size:           len(rec.Record),
	})
}

// --- shared helpers -------------------------------------------------------

// ersTimestamper selects the archive-timestamp source for an API-triggered
// generate/renew, mirroring the CLI's buildErsTimestamperCLI exactly: the
// configured external TSA URL, else an in-process authority over the TSA-role key
// provider. The returned release function must always be called; it closes the
// provider when one was opened (the external-TSA path opens none, so those
// deployments never need a local TSA key at all).
func (a *API) ersTimestamper(w http.ResponseWriter, what string) (ers.Timestamper, func(), bool) {
	deps, ok := a.requireOps(w, what)
	if !ok {
		return nil, nil, false
	}
	if url := deps.Config.Ers.TSAURL; url != "" {
		return ers.NewHTTPTimestamper(url, time.Duration(deps.Config.Ers.TimeoutSeconds)*time.Second), func() {}, true
	}
	authority, release, ok := a.internalTSAAuthority(w, what)
	if !ok {
		return nil, nil, false
	}
	return ers.NewAuthorityTimestamper(authority), release, true
}

// ersObjects decodes the base64 protected data objects of a generate request,
// applying the caller's labels when supplied. It reuses decodeErsObjects (the
// verify endpoint's decoder) so both paths label and validate identically.
func ersObjects(encoded, ids []string) ([]ers.DataObject, error) {
	objs, err := decodeErsObjects(encoded)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return objs, nil
	}
	if len(ids) != len(objs) {
		return nil, fmt.Errorf("object_ids has %d entries but %d objects were supplied", len(ids), len(objs))
	}
	for i := range objs {
		if ids[i] == "" {
			return nil, fmt.Errorf("object_ids[%d] is empty", i)
		}
		objs[i].ID = ids[i]
	}
	return objs, nil
}

// ersRenewObjects reconstructs the objects for a hash-tree renewal, mirroring the
// CLI: an audit-scope record re-derives them from the event log, an artifact-scope
// record needs the original bytes re-supplied.
func (a *API) ersRenewObjects(rec models.EvidenceRecord, encoded []string) ([]ers.DataObject, error) {
	if len(encoded) > 0 {
		return decodeErsObjects(encoded)
	}
	if rec.Scope != ers.ScopeAudit {
		return nil, fmt.Errorf("a hash-tree renewal of a %q-scope record needs the original object(s) in \"objects\"", rec.Scope)
	}
	return ers.NewService(a.db, nil, ers.Options{}).ResolveObjects(rec)
}

// ersHashTreeTarget picks the default hash-tree-renewal target from the
// configured algorithm: it if stronger than SHA-256, else SHA-512 — the CLI's
// rule, so a renewal never silently migrates to the same strength.
func ersHashTreeTarget(configured string) crypto.Hash {
	if h := ers.HashByName(configured); h != 0 && h != crypto.SHA256 {
		return h
	}
	return crypto.SHA512
}

// ersDetail renders the audit detail for a record in the same key=value shape the
// ers service's own events use.
func ersDetail(rec *models.EvidenceRecord) string {
	return fmt.Sprintf("scope=%s hash=%s chains=%d objects=%d", rec.Scope, rec.DigestAlg, rec.Chains, len(rec.ObjectIDs))
}
