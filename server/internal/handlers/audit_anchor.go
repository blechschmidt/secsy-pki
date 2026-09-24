package handlers

// REST surface for on-demand audit-chain anchoring — the counterpart of
// `secsy-ca audit anchor` (Task 198). POST /api/events/anchor.
//
// Anchoring binds the tamper-evident event log's current head (seq, hash) into an
// RFC 3161 timestamp token and persists it, so `audit verify` can later detect a
// whole-chain truncation or rewrite *behind* that point — the one attack the hash
// chain alone cannot catch, because an attacker who can rewrite the log can
// re-chain it consistently. The background job does this on a cadence; until now
// the only way to anchor *now* — before a maintenance window, after an incident,
// or immediately before exporting evidence — was shell access to the CA host.
//
// The token source is the same one the background job and the CLI use: the
// configured external TSA URL, else the in-process authority over the TSA-ROLE key
// provider, built lazily so this endpoint is the only API path that needs it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/anchor"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// AnchorAuditChainRequest is the body of POST /api/events/anchor. The body is
// optional; omitting it anchors with the default (skip-if-unchanged) semantics.
type AnchorAuditChainRequest struct {
	// Force anchors even when the head has not moved since the last anchor (the
	// CLI's -force). Without it an unchanged head is reported as skipped, so a
	// console button cannot mint a pile of redundant tokens over one head.
	Force bool `json:"force,omitempty"`
}

// AnchorAuditChainResponse reports the outcome of one anchoring attempt. It is
// anchor.Result rendered in the API's snake_case convention.
type AnchorAuditChainResponse struct {
	// Skipped is true when nothing needed anchoring; Reason says why.
	Skipped bool   `json:"skipped"`
	Reason  string `json:"reason,omitempty"`
	// Anchor is the persisted anchor on success (absent when skipped). Its token
	// is the base64 DER TimeStampToken, so an auditor can archive it or re-verify
	// it offline (openssl ts -verify) against the TSA certificate.
	Anchor *audit.Anchor `json:"anchor,omitempty"`
	// TSASource is where the token came from: "internal" for the deployment's own
	// TSA, else the external TSA URL. Reported separately from the anchor row
	// (whose tsa_source is empty for the internal authority) so the console can
	// always name the authority without special-casing the empty string.
	TSASource string `json:"tsa_source,omitempty"`
}

// AnchorAuditChain handles POST /api/events/anchor — the REST form of `secsy-ca
// audit anchor`.
//
// Gated on the PLATFORM-wide ca:manage capability (a.can, so a tenant admin is
// denied): an anchor is a signed statement about the whole deployment's audit
// chain, made with the deployment's timestamp authority. The read side of the same
// feature (GET /api/events/verify, which validates the stored anchors) stays at
// platform audit:read; creating one is deliberately held higher.
func (a *API) AnchorAuditChain(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionAuditAnchor, "", "", audit.ResultDenied, "platform ca:manage capability required")
		writeError(w, http.StatusForbidden, "platform ca:manage capability required (admin role)")
		return
	}

	var req AnchorAuditChainRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	ts, release, ok := a.anchorTimestamper(w)
	if !ok {
		return
	}
	defer release()

	// AnchorOnce appends the shared audit.anchor event (actor "anchor") carrying
	// seq/head/gen_time/tsa, exactly as the background job and the CLI do.
	res, err := anchor.NewService(a.db, ts).AnchorOnce(r.Context(), req.Force)
	if err != nil {
		a.recordEvent(r, audit.ActionAuditAnchor, "", "", audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "anchoring the audit chain: %v", err)
		return
	}
	if res.Skipped {
		// Nothing was created, so nothing is recorded: an idle head must stay
		// byte-identical across repeated polls, or the next call would see "new
		// events" and anchor after all — defeating the skip it just reported.
		writeJSON(w, http.StatusOK, AnchorAuditChainResponse{
			Skipped: true, Reason: res.Reason, TSASource: anchorSourceLabel(ts),
		})
		return
	}

	// The operator attribution the service's own event cannot carry.
	a.recordEvent(r, audit.ActionAuditAnchor, res.Anchor.ID, "", audit.ResultSuccess,
		fmt.Sprintf("seq=%d head=%s gen_time=%s tsa=%s via=api",
			res.Anchor.Seq, res.Anchor.HeadHash,
			res.Anchor.GenTime.UTC().Format(time.RFC3339), anchorSourceLabel(ts)))
	writeJSON(w, http.StatusCreated, AnchorAuditChainResponse{
		Anchor: res.Anchor, TSASource: anchorSourceLabel(ts),
	})
}

// anchorTimestamper selects the anchor token source, mirroring the CLI's
// buildAnchorTimestamperCLI: the configured external TSA URL, else an in-process
// authority over the TSA-role key provider. The returned release function must
// always be called; it closes the provider when one was opened.
func (a *API) anchorTimestamper(w http.ResponseWriter) (anchor.Timestamper, func(), bool) {
	const what = "audit-chain anchoring"
	deps, ok := a.requireOps(w, what)
	if !ok {
		return nil, nil, false
	}
	if url := deps.Config.Audit.Anchor.TSAURL; url != "" {
		timeout := time.Duration(deps.Config.Audit.Anchor.TimeoutSeconds) * time.Second
		return anchor.NewHTTPTimestamper(url, timeout), func() {}, true
	}
	authority, release, ok := a.internalTSAAuthority(w, what)
	if !ok {
		return nil, nil, false
	}
	return anchor.NewAuthorityTimestamper(authority), release, true
}

// internalTSAAuthority builds the in-process RFC 3161 authority over the TSA-ROLE
// key provider, shared by audit anchoring and evidence-record generation/renewal
// (the two API paths that need a signing key other than a CA's). The returned
// release function closes the provider and must always be called.
//
// It is built per request rather than held on the API: the TSA key is only
// touched by these on-demand operations, and opening the session lazily keeps
// every other endpoint — including the anchor/evidence-record *verification*
// paths, which are pure public-key math — working through an HSM outage.
func (a *API) internalTSAAuthority(w http.ResponseWriter, what string) (*tsa.Authority, func(), bool) {
	deps, ok := a.requireOps(w, what)
	if !ok {
		return nil, nil, false
	}
	if deps.Config.TSA.KeyLabel == "" || deps.Config.TSA.CertificateFile == "" {
		writeError(w, http.StatusServiceUnavailable,
			"%s needs a timestamp source: configure an external TSA URL, or the internal tsa: block "+
				"(key_label + certificate_file; provision the credential with `secsy-ca tsa-key`)", what)
		return nil, nil, false
	}
	// The same loader the server's /tsa endpoint and the CLI use, so every consumer
	// builds an identical authority from one config block.
	tsaCfg, err := tsa.LoadAuthorityConfig(a.db, deps.Config.TSA)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "loading the TSA configuration: %v", err)
		return nil, nil, false
	}
	// The TSA-role provider, which is the SERVING provider whenever the tsa role
	// resolves to the CA's backend (the common single-token deployment). Opening a
	// second one unconditionally would mean a second session pool: a YubiHSM 2
	// allows 16 sessions and the serving provider already holds eight, so anchoring
	// and evidence-record generation — both reached from this helper — would sit at
	// the device limit and two concurrent requests would starve live CA signing.
	// release() is a no-op for the shared provider, so every path below must call it
	// rather than Close the provider directly.
	provider, release, ok := a.providerForRole(w, "tsa", what)
	if !ok {
		return nil, nil, false
	}
	authority, err := tsa.New(a.db, provider, tsaCfg)
	if err != nil {
		release()
		writeError(w, http.StatusServiceUnavailable, "the configured timestamp authority is unusable: %v", err)
		return nil, nil, false
	}
	return authority, release, true
}

// anchorSourceLabel names the token source for responses and audit details,
// spelling the in-process authority "internal" (the anchor row records it as an
// empty string).
func anchorSourceLabel(ts anchor.Timestamper) string {
	if src := ts.Source(); src != "" {
		return src
	}
	return "internal"
}

// decodeOptionalJSONBody decodes an optional JSON request body: an empty body is
// the zero value rather than an error, so a flag-less POST (the common "just do
// it" case for the anchor and CT-verification triggers) needs no body at all.
func decodeOptionalJSONBody(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
