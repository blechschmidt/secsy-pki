//go:build sqlite

package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/webhook"
)

// TestWebhookFiresOnRealIssuance is the integration proof that the durable
// webhook fan-out reacts to a REAL certificate lifecycle event — one produced by
// the actual issuance handler (with its real tenant resolution and audit-append),
// not a hand-crafted event. It issues a certificate through api.IssueCertificate
// and confirms the leader-elected fan-out enqueues and delivers a signed
// cert.issue webhook to a subscribed endpoint, and that a cross-tenant
// subscription receives nothing.
func TestWebhookFiresOnRealIssuance(t *testing.T) {
	api, db := tenantAPI(t)
	tn, root := quotaTenantWithRoot(t, api, db, "wh", models.TenantQuotas{})

	// A receiver that verifies the HMAC signature of each delivery.
	var mu sync.Mutex
	var received []string // event types received
	secret := "integration-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := webhook.Verify(secret, r.Header.Get(webhook.SignatureHeader), body, 0, time.Now()); err != nil {
			t.Errorf("receiver: invalid signature: %v", err)
		}
		mu.Lock()
		received = append(received, r.Header.Get("X-Secsy-Event"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Subscribe in the issuing tenant, and a decoy subscription in another tenant
	// that must NOT receive this tenant's event.
	if err := db.CreateWebhookSubscription(&models.WebhookSubscription{
		ID: "wh-int", TenantID: tn.ID, Scope: models.WebhookScopeTenant, URL: srv.URL,
		Secret: secret, Enabled: true, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateWebhookSubscription: %v", err)
	}
	if err := db.CreateTenant(&models.Tenant{ID: "other", Slug: "other", Name: "other", Status: models.TenantStatusActive}); err != nil {
		t.Fatalf("CreateTenant(other): %v", err)
	}
	if err := db.CreateWebhookSubscription(&models.WebhookSubscription{
		ID: "wh-other", TenantID: "other", Scope: models.WebhookScopeTenant, URL: srv.URL + "/other",
		Secret: secret, Enabled: true, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateWebhookSubscription(other): %v", err)
	}

	engine := webhook.New(db, webhook.Config{MaxAttempts: 3, Timeout: 2 * time.Second, AuditDeliveries: true})
	ctx := context.Background()
	// Seed the fan-out cursor at the current head so only the certificate we are
	// about to issue is delivered (mirrors production: future events only).
	engine.RunOnce(ctx)

	// Issue a certificate through the real handler: this appends a cert.issue audit
	// event with the CA's tenant, exactly as production does.
	rec := httptest.NewRecorder()
	body := `{"csr":` + jsonString(quotaCSR(t, "svc.example.com")) + `,"profile":"server"}`
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+root.ID+"/issue", rootUser(), root.ID, body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// Drive the fan-out + delivery over the real event log.
	engine.RunOnce(ctx)

	// The in-tenant subscription must have received exactly one cert.issue event.
	deliveries, err := db.ListWebhookDeliveries("wh-int", "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries: %v", err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("in-tenant subscription got %d deliveries, want 1", len(deliveries))
	}
	if deliveries[0].EventType != audit.ActionCertIssue {
		t.Errorf("delivered event = %q, want %q", deliveries[0].EventType, audit.ActionCertIssue)
	}
	if deliveries[0].Status != models.WebhookDeliveryDelivered {
		t.Errorf("delivery status = %q, want delivered", deliveries[0].Status)
	}

	// The cross-tenant subscription must have received nothing.
	if other, _ := db.ListWebhookDeliveries("wh-other", "", 0); len(other) != 0 {
		t.Errorf("cross-tenant subscription received %d deliveries — LEAK", len(other))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || received[0] != audit.ActionCertIssue {
		t.Errorf("receiver saw %v, want one %q", received, audit.ActionCertIssue)
	}
}

// jsonString quotes a string as a JSON string literal for inline request bodies.
func jsonString(s string) string {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			b = append(b, string(r)...)
		}
	}
	b = append(b, '"')
	return string(b)
}
