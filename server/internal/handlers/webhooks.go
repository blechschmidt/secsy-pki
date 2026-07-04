package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/webhook"
)

// Durable outbound webhook subscriptions (Task 116).
//
// These endpoints let an administrator register, list, test, enable/disable, and
// delete external endpoints that receive HMAC-signed certificate lifecycle
// events. Managing subscriptions is an administrative capability
// (webhook:manage, admin-only), tenant-scoped exactly like token:manage: a
// subscription egresses certificate data — subject names and serials — to an
// operator-chosen URL, so a platform (all-tenant) subscription requires a
// platform administrator while tenant admins manage their own tenant's.

// createWebhookRequest is the POST /api/webhooks body.
type createWebhookRequest struct {
	URL         string   `json:"url"`
	EventTypes  []string `json:"event_types,omitempty"` // empty = all lifecycle events
	Secret      string   `json:"secret,omitempty"`      // optional; generated when empty
	TenantID    string   `json:"tenant_id,omitempty"`   // id or slug; default tenant when empty
	Scope       string   `json:"scope,omitempty"`       // "tenant" (default) or "platform"
	Description string   `json:"description,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"` // default true
}

// webhookWithSecret carries a created subscription together with its signing
// secret, which is returned exactly once (the stored model's secret is json:"-").
type webhookWithSecret struct {
	*models.WebhookSubscription
	Secret string `json:"secret"`
}

// CreateWebhook registers a new subscription and returns its signing secret once.
func (a *API) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())

	var req createWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if err := validateWebhookURL(req.URL); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	eventTypes, err := normalizeWebhookEventTypes(req.EventTypes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Resolve scope, owning tenant, and the authorization required to grant them —
	// mirrors token creation.
	scope := strings.TrimSpace(req.Scope)
	if scope == "" {
		scope = models.WebhookScopeTenant
	}
	var tenantID string
	switch scope {
	case models.WebhookScopePlatform:
		if !a.isPlatformAdmin(user) {
			a.recordEvent(r, audit.ActionWebhookCreate, "", req.URL, audit.ResultDenied, "platform-scoped webhook requires a platform administrator")
			writeError(w, http.StatusForbidden, "creating a platform-scoped webhook requires a platform administrator")
			return
		}
		tenantID = models.DefaultTenantID
	case models.WebhookScopeTenant:
		resolved, ok := a.resolveTenantRef(w, req.TenantID)
		if !ok {
			return
		}
		tenantID = resolved
		middleware.SetTenant(r.Context(), tenantID)
		if !a.canInTenant(user, tenantID, rbac.ActionManageWebhooks) {
			a.recordEvent(r, audit.ActionWebhookCreate, "", req.URL, audit.ResultDenied, "webhook:manage capability required in tenant "+tenantID)
			writeError(w, http.StatusForbidden, "webhook:manage capability (admin role) required for tenant %q", tenantID)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "scope must be %q or %q", models.WebhookScopeTenant, models.WebhookScopePlatform)
		return
	}

	secret := strings.TrimSpace(req.Secret)
	if secret == "" {
		if secret, err = webhook.GenerateSecret(); err != nil {
			writeError(w, http.StatusInternalServerError, "generating signing secret: %v", err)
			return
		}
	}
	enabled := req.Enabled == nil || *req.Enabled

	sub := &models.WebhookSubscription{
		ID:          uuid.New().String(),
		TenantID:    tenantID,
		Scope:       scope,
		URL:         req.URL,
		Secret:      secret,
		EventTypes:  eventTypes,
		Enabled:     enabled,
		Description: strings.TrimSpace(req.Description),
		CreatedBy:   requestActor(r),
		CreatedAt:   time.Now().UTC(),
	}
	if err := a.db.CreateWebhookSubscription(sub); err != nil {
		a.recordEvent(r, audit.ActionWebhookCreate, sub.ID, sub.URL, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to create webhook: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionWebhookCreate, sub.ID, hostOfURL(sub.URL), audit.ResultSuccess,
		fmt.Sprintf("scope=%s tenant=%s events=%s enabled=%v", scope, tenantID, webhookEventsLabel(eventTypes), enabled))
	a.refreshWebhookGauge()

	writeJSON(w, http.StatusCreated, webhookWithSecret{WebhookSubscription: sub, Secret: secret})
}

// ListWebhooks returns the subscriptions the caller may manage: a platform
// administrator sees all (optionally filtered by ?tenant=); a tenant admin sees
// only the subscriptions of tenants it administers. Secrets are never included.
func (a *API) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	tenantFilter := r.URL.Query().Get("tenant")

	var out []models.WebhookSubscription
	if a.isPlatformAdmin(user) {
		list, err := a.db.ListWebhookSubscriptions(tenantFilter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list webhooks: %v", err)
			return
		}
		out = list
	} else {
		scopes := a.tenantsWithWebhookAdmin(user)
		if len(scopes) == 0 {
			writeError(w, http.StatusForbidden, "webhook:manage capability (admin role) required")
			return
		}
		for _, tid := range scopes {
			if tenantFilter != "" && tenantFilter != tid {
				continue
			}
			list, err := a.db.ListWebhookSubscriptions(tid)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to list webhooks: %v", err)
				return
			}
			out = append(out, list...)
		}
	}
	if out == nil {
		out = []models.WebhookSubscription{}
	}
	writeJSON(w, http.StatusOK, out)
}

// GetWebhook returns a single subscription (without its secret).
func (a *API) GetWebhook(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	sub, ok := a.authorizeWebhook(w, r, user)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

// DeleteWebhook removes a subscription and its delivery history.
func (a *API) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	sub, ok := a.authorizeWebhook(w, r, user)
	if !ok {
		return
	}
	changed, err := a.db.DeleteWebhookSubscription(sub.ID)
	if err != nil {
		a.recordEvent(r, audit.ActionWebhookDelete, sub.ID, hostOfURL(sub.URL), audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to delete webhook: %v", err)
		return
	}
	if !changed {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_deleted"})
		return
	}
	a.recordEvent(r, audit.ActionWebhookDelete, sub.ID, hostOfURL(sub.URL), audit.ResultSuccess, "scope="+sub.Scope)
	a.refreshWebhookGauge()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// EnableWebhook re-enables a disabled subscription.
func (a *API) EnableWebhook(w http.ResponseWriter, r *http.Request) { a.setWebhookEnabled(w, r, true) }

// DisableWebhook pauses a subscription and cancels its still-pending deliveries.
func (a *API) DisableWebhook(w http.ResponseWriter, r *http.Request) { a.setWebhookEnabled(w, r, false) }

func (a *API) setWebhookEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	user := middleware.GetUserInfo(r.Context())
	sub, ok := a.authorizeWebhook(w, r, user)
	if !ok {
		return
	}
	changed, err := a.db.SetWebhookSubscriptionEnabled(sub.ID, enabled)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update webhook: %v", err)
		return
	}
	// Disabling pauses the endpoint: cancel any still-pending deliveries so the
	// worker does not keep hammering an endpoint the operator has paused.
	if !enabled {
		if _, err := a.db.CancelPendingWebhookDeliveries(sub.ID); err != nil {
			// Non-fatal: the worker also cancels pending deliveries for a disabled
			// subscription when it next tries one.
			a.recordEvent(r, audit.ActionWebhookUpdate, sub.ID, hostOfURL(sub.URL), audit.ResultError, "canceling pending deliveries: "+err.Error())
		}
	}
	if changed {
		a.recordEvent(r, audit.ActionWebhookUpdate, sub.ID, hostOfURL(sub.URL), audit.ResultSuccess, fmt.Sprintf("enabled=%v", enabled))
		a.refreshWebhookGauge()
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": sub.ID, "enabled": enabled})
}

// TestWebhook enqueues a synthetic test delivery for the subscription, which the
// delivery worker sends (signed exactly like a real event). The operator watches
// the deliveries list for the outcome. When the delivery worker is disabled the
// response says so, since the queued delivery will not be sent.
func (a *API) TestWebhook(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	sub, ok := a.authorizeWebhook(w, r, user)
	if !ok {
		return
	}
	d, err := webhook.NewTestDelivery(sub, a.webhookMaxAttempts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "building test delivery: %v", err)
		return
	}
	if err := a.db.EnqueueWebhookDelivery(d); err != nil {
		writeError(w, http.StatusInternalServerError, "queuing test delivery: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionWebhookUpdate, sub.ID, hostOfURL(sub.URL), audit.ResultSuccess, "test delivery queued id="+d.ID)
	a.refreshWebhookGauge()
	resp := map[string]any{
		"delivery_id":    d.ID,
		"status":         "queued",
		"worker_enabled": a.webhookWorkerEnabled,
	}
	if !a.webhookWorkerEnabled {
		resp["note"] = "the webhook delivery worker is disabled (webhook.enabled); the test delivery is queued but will not be sent until it is enabled"
	}
	writeJSON(w, http.StatusAccepted, resp)
}

// ListWebhookDeliveries returns a subscription's delivery history, optionally
// filtered by ?status= and bounded by ?limit=.
func (a *API) ListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	sub, ok := a.authorizeWebhook(w, r, user)
	if !ok {
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	deliveries, err := a.db.ListWebhookDeliveries(sub.ID, status, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list deliveries: %v", err)
		return
	}
	if deliveries == nil {
		deliveries = []models.WebhookDelivery{}
	}
	writeJSON(w, http.StatusOK, deliveries)
}

// --- helpers ---

// authorizeWebhook loads the subscription named by {id} and enforces
// webhook:manage on its owning tenant (platform subscriptions require a platform
// admin). It writes the 4xx and returns ok=false on any failure, mirroring the
// token-scoped authorization so cross-tenant access is denied 403.
func (a *API) authorizeWebhook(w http.ResponseWriter, r *http.Request, user *models.UserInfo) (*models.WebhookSubscription, bool) {
	id := r.PathValue("id")
	sub, err := a.db.GetWebhookSubscription(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webhook lookup failed: %v", err)
		return nil, false
	}
	if sub == nil {
		writeError(w, http.StatusNotFound, "webhook not found")
		return nil, false
	}
	middleware.SetTenant(r.Context(), sub.TenantID)
	if !a.canManageWebhook(user, sub) {
		writeError(w, http.StatusForbidden, "webhook:manage capability (admin role) required")
		return nil, false
	}
	return sub, true
}

// canManageWebhook reports whether the user may administer a specific
// subscription: platform subscriptions require a platform admin; tenant
// subscriptions require webhook:manage within the subscription's tenant.
func (a *API) canManageWebhook(user *models.UserInfo, sub *models.WebhookSubscription) bool {
	if sub.IsPlatform() {
		return a.isPlatformAdmin(user)
	}
	return a.canInTenant(user, sub.TenantID, rbac.ActionManageWebhooks)
}

// tenantsWithWebhookAdmin returns the tenant ids in which the (non-platform-admin)
// user holds the webhook:manage capability.
func (a *API) tenantsWithWebhookAdmin(user *models.UserInfo) []string {
	if user == nil {
		return nil
	}
	var out []string
	for tid := range user.TenantRoles {
		if rbac.Can(tenantRolesFor(user, tid), rbac.ActionManageWebhooks) {
			out = append(out, tid)
		}
	}
	sort.Strings(out)
	return out
}

// refreshWebhookGauge republishes the active-subscription count after a lifecycle
// change. A read error is non-fatal — the gauge is advisory.
func (a *API) refreshWebhookGauge() {
	if subs, err := a.db.ListEnabledWebhookSubscriptions(); err == nil {
		metrics.SetWebhookSubscriptionsActive(len(subs))
	}
}

// validateWebhookURL requires an absolute http(s) URL with a host.
func validateWebhookURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("url must include a host")
	}
	return nil
}

// normalizeWebhookEventTypes validates, de-duplicates, and sorts a requested
// event-type filter. An empty list is valid (subscribe to all lifecycle events);
// an unknown type is rejected so a typo cannot silently subscribe to nothing.
func normalizeWebhookEventTypes(in []string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range in {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if !webhook.IsSupportedEventType(t) {
			return nil, fmt.Errorf("unsupported event type %q (supported: %s)", t, strings.Join(webhook.SupportedEventTypes(), ", "))
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out, nil
}

func webhookEventsLabel(events []string) string {
	if len(events) == 0 {
		return "*"
	}
	return strings.Join(events, ",")
}

// hostOfURL renders a URL's scheme+host for audit trails without leaking the full
// (possibly credential-bearing) path/query.
func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
