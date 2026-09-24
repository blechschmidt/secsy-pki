//go:build sqlite

package handlers

// Tests for POST /api/events/anchor (Task 198).
//
// The property this endpoint carries is that the anchor it creates must actually
// detect a rewritten log later: TestAnchorCreatesVerifiableAnchor drives the
// anchor through the API and then validates it with the SAME anchor.VerifyAnchors
// the `secsy-ca audit verify` path uses — including the negative case, where the
// chain is tampered with behind the anchor and verification must break.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/anchor"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// postAnchor drives the handler as the given principal.
func postAnchor(api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	return postAs(api.AnchorAuditChain, user, "/api/events/anchor", body)
}

// TestAnchorAuthz: an anchor is a signed statement about the whole deployment's
// audit chain, made with the deployment's timestamp authority, so the gate is
// PLATFORM ca:manage — strictly above the platform audit:read that verifies the
// stored anchors. A tenant admin and a platform auditor are both denied.
func TestAnchorAuthz(t *testing.T) {
	api, db := tsaOpsAPI(t)
	appendErsTestEvents(t, db, 2)

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, http.StatusForbidden},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, http.StatusForbidden},
		{"tenant admin", tenantUser("alice", models.DefaultTenantID, "admin"), http.StatusForbidden},
		{"platform admin", platAdminUser(), http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAnchor(api, tc.user, `{}`)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	// A denial is recorded, so an attempt to anchor without standing is visible.
	if log := eventDetails(t, db); !strings.Contains(log, audit.ActionAuditAnchor+"||platform ca:manage capability required") {
		t.Errorf("denied anchor attempts must be audited:\n%s", log)
	}
}

// TestAnchorOpsAbsent503 / no timestamp source: the endpoint cannot invent a token
// source, so it reports 503 with the two ways to configure one instead of
// half-working.
func TestAnchorOpsAbsent503(t *testing.T) {
	api, db := tenantAPI(t) // no SetOps
	appendErsTestEvents(t, db, 1)
	if rec := postAnchor(api, platAdminUser(), `{}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no ops deps: status = %d, want 503: %s", rec.Code, rec.Body.String())
	}

	api.SetOps(&OpsDeps{Config: &config.Config{}}) // deps present, no TSA configured
	rec := postAnchor(api, platAdminUser(), `{}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no timestamp source: status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "timestamp source") {
		t.Errorf("error should name the missing timestamp source, got %s", body)
	}
}

// TestAnchorBadInput: a malformed body is a request error, while an ABSENT body is
// fine — anchoring with default semantics needs no parameters at all.
func TestAnchorBadInput(t *testing.T) {
	api, db := tsaOpsAPI(t)
	appendErsTestEvents(t, db, 1)

	if rec := postAnchor(api, platAdminUser(), `{"force":`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := postAnchor(api, platAdminUser(), ``); rec.Code != http.StatusCreated {
		t.Fatalf("empty body: status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

// TestAnchorEmptyLogSkips: with nothing in the log there is nothing to attest, so
// the attempt is reported as skipped (200, no anchor) rather than persisting a
// token over a head that does not exist. Nothing is recorded either — an idle head
// must stay byte-identical across repeated polls.
func TestAnchorEmptyLogSkips(t *testing.T) {
	api, db := tsaOpsAPI(t)

	rec := postAnchor(api, platAdminUser(), `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp AnchorAuditChainResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Skipped || resp.Anchor != nil || resp.Reason == "" {
		t.Fatalf("response = %+v, want skipped with a reason and no anchor", resp)
	}
	anchors, err := db.ListAuditAnchorsAsc()
	if err != nil {
		t.Fatalf("ListAuditAnchorsAsc: %v", err)
	}
	if len(anchors) != 0 {
		t.Fatalf("a skipped attempt persisted %d anchor(s)", len(anchors))
	}
	if head, err := db.MaxEventSeq(); err != nil || head != 0 {
		t.Fatalf("event log head = %d (err %v), want 0: a skipped anchor must append nothing", head, err)
	}
}

// TestAnchorCreatesVerifiableAnchor is the headline proof: the anchor the endpoint
// persists attests the current head and is accepted by the same verifier
// `secsy-ca audit verify` uses — and rejects the chain once the anchored prefix is
// rewritten.
func TestAnchorCreatesVerifiableAnchor(t *testing.T) {
	api, db := tsaOpsAPI(t)
	appendErsTestEvents(t, db, 3)
	head, _ := db.MaxEventSeq()

	rec := postAnchor(api, platAdminUser(), `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp AnchorAuditChainResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Skipped || resp.Anchor == nil {
		t.Fatalf("response = %+v, want a created anchor", resp)
	}
	if resp.Anchor.Seq != head {
		t.Errorf("anchored seq = %d, want the head %d", resp.Anchor.Seq, head)
	}
	if len(resp.Anchor.Token) == 0 {
		t.Fatal("the anchor must carry its RFC 3161 token so an auditor can re-verify it offline")
	}
	if resp.TSASource != "internal" {
		t.Errorf("tsa_source = %q, want internal", resp.TSASource)
	}

	// The persisted anchor verifies against the live chain.
	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatalf("ListAllEventsAsc: %v", err)
	}
	anchors, err := db.ListAuditAnchorsAsc()
	if err != nil {
		t.Fatalf("ListAuditAnchorsAsc: %v", err)
	}
	if len(anchors) != 1 {
		t.Fatalf("stored anchors = %d, want 1", len(anchors))
	}
	for _, c := range anchor.VerifyAnchors(events, anchors, nil, time.Now()) {
		if !c.Valid {
			t.Fatalf("anchor %d does not verify: %s", c.Seq, c.Reason)
		}
	}

	// Negative control: the anchor is only worth something if it breaks when the
	// anchored prefix is altered.
	tampered := make([]audit.Event, len(events))
	copy(tampered, events)
	for i := range tampered {
		if tampered[i].Seq == resp.Anchor.Seq {
			tampered[i].Hash = "00" + tampered[i].Hash[2:]
		}
	}
	broken := false
	for _, c := range anchor.VerifyAnchors(tampered, anchors, nil, time.Now()) {
		if !c.Valid {
			broken = true
		}
	}
	if !broken {
		t.Fatal("a rewritten head hash must invalidate the anchor")
	}

	// The operator is attributed alongside the anchor service's own event.
	if log := eventDetails(t, db); !strings.Contains(log, "via=api") {
		t.Errorf("anchor audit trail lacks the operator-attributed event:\n%s", log)
	}
}

// TestAnchorTSAProviderReuse is the HSM session-budget invariant for the shared
// internalTSAAuthority helper, which both POST /api/events/anchor and the
// evidence-record generate/renew endpoints reach.
//
// A second key provider is a second session pool: a YubiHSM 2 allows 16 concurrent
// sessions and the serving provider holds eight, so a request opening eight more
// sits at the device limit and two concurrent ones starve live CA signing. So the
// tsa role reuses the SERVING provider whenever it resolves to the CA's backend,
// and opens its own ONLY when the configured backend genuinely differs — which is
// the same rule the CLI applies and the reason a role-scoped key must never be
// written to the wrong token.
func TestAnchorTSAProviderReuse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tsaRole  string // key_provider.roles.tsa; empty means "same as the CA's"
		wantOpen int
	}{
		{"tsa shares the CA backend", "", 0},
		{"tsa has its own backend", "software-tsa", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, db := tsaOpsAPI(t)
			appendErsTestEvents(t, db, 2)

			// Re-wire the installed bundle with a counting factory over the same
			// keystore, so both branches resolve the same TSA key and the only
			// difference observed is whether a provider was opened.
			deps := api.opsDeps()
			inner := deps.ProviderFor
			calls := 0
			cfg := &config.Config{TSA: deps.Config.TSA}
			cfg.KeyProvider.Type = "software"
			cfg.KeyProvider.Roles.TSA = tc.tsaRole
			api.SetOps(&OpsDeps{
				Config: cfg,
				ProviderFor: func(role string) (keyprovider.Provider, error) {
					calls++
					if role != "tsa" {
						t.Errorf("ProviderFor(%q), want only the tsa role", role)
					}
					return inner(role)
				},
			})

			if rec := postAnchor(api, platAdminUser(), `{}`); rec.Code != http.StatusCreated {
				t.Fatalf("anchor: status = %d, want 201: %s", rec.Code, rec.Body.String())
			}
			if calls != tc.wantOpen {
				t.Errorf("opened %d role-scoped provider(s), want %d", calls, tc.wantOpen)
			}
			// Either way the serving provider survives: release() closes only a
			// provider it opened, never the server's own.
			if _, err := api.keyProvider.FindKey(t.Context(), keyprovider.KeyRef{Label: "ops-tsa"}); err != nil {
				t.Errorf("the serving key provider was closed by the request: %v", err)
			}
		})
	}
}
