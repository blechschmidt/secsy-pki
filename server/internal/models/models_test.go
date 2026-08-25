// Unit tests for the remaining pure helpers on the model types: the two typed
// errors the protocol layers switch on to pick an HTTP status, and the two
// accessors that answer a routing/scheduling question from a stored field.
// They need no HSM, database, or network.
package models

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTenantSuspendedErrorMessage(t *testing.T) {
	err := &TenantSuspendedError{TenantID: "acme"}
	msg := err.Error()
	if !strings.Contains(msg, `"acme"`) || !strings.Contains(msg, "suspended") {
		t.Errorf("Error() = %q, want it to name the tenant and say it is suspended", msg)
	}
	// The protocol layers recover it with errors.As through wrapping, so the
	// message must survive as a typed error and not just a string.
	var target *TenantSuspendedError
	if !errors.As(fmt.Errorf("issuing: %w", err), &target) || target.TenantID != "acme" {
		t.Errorf("errors.As did not recover the wrapped TenantSuspendedError")
	}
}

func TestQuotaExceededErrorMessage(t *testing.T) {
	err := &QuotaExceededError{
		TenantID:   "globex",
		Quota:      QuotaSecretOpsPerDay,
		Limit:      500,
		RetryAfter: 90 * time.Minute,
	}
	msg := err.Error()
	for _, want := range []string{`"globex"`, QuotaSecretOpsPerDay, "500"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to contain %q", msg, want)
		}
	}
	var target *QuotaExceededError
	if !errors.As(fmt.Errorf("secret op: %w", err), &target) || target.RetryAfter != 90*time.Minute {
		t.Errorf("errors.As did not recover the wrapped QuotaExceededError with its RetryAfter")
	}
}

func TestWebhookSubscriptionIsPlatform(t *testing.T) {
	if !(&WebhookSubscription{Scope: WebhookScopePlatform}).IsPlatform() {
		t.Errorf("platform-scoped subscription reported not platform")
	}
	if (&WebhookSubscription{Scope: WebhookScopeTenant}).IsPlatform() {
		t.Errorf("tenant-scoped subscription reported platform")
	}
	// An unset scope must not fan every tenant's events out (fail closed).
	if (&WebhookSubscription{}).IsPlatform() {
		t.Errorf("scope-less subscription reported platform")
	}
}

func TestACMEAutoRenewalLifetime(t *testing.T) {
	if got := (ACMEAutoRenewal{LifetimeSeconds: 3600}).Lifetime(); got != time.Hour {
		t.Errorf("Lifetime() = %v, want %v", got, time.Hour)
	}
	if got := (ACMEAutoRenewal{}).Lifetime(); got != 0 {
		t.Errorf("zero LifetimeSeconds = %v, want 0", got)
	}
}
