package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/webhook"
)

// cmdWebhook implements `secsy-ca webhook <create|list|delete|enable|disable|
// test|deliveries>` — management of durable outbound webhook subscriptions (Task
// 116). Local CLI access is platform-operator level (it bypasses the API's RBAC),
// so the commands operate directly on the store; `test` performs a live signed
// POST for immediate feedback (the CLI runs standalone, without the delivery
// worker).
func cmdWebhook(db *database.DB, cfg *config.Config, args []string) error {
	if len(args) == 0 {
		webhookUsage()
		return fmt.Errorf("webhook: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdWebhookCreate(db, rest)
	case "list":
		return cmdWebhookList(db, rest)
	case "delete", "rm":
		return cmdWebhookDelete(db, rest)
	case "enable":
		return cmdWebhookSetEnabled(db, rest, true)
	case "disable":
		return cmdWebhookSetEnabled(db, rest, false)
	case "test":
		return cmdWebhookTest(db, cfg, rest)
	case "deliveries":
		return cmdWebhookDeliveries(db, rest)
	case "help", "-h", "--help":
		webhookUsage()
		return nil
	default:
		webhookUsage()
		return fmt.Errorf("webhook: unknown subcommand %q", sub)
	}
}

func webhookUsage() {
	fmt.Fprintf(os.Stderr, `Usage: secsy-ca webhook <subcommand> [flags]

Subcommands:
  create      Register an outbound webhook subscription (prints the signing secret once)
  list        List webhook subscriptions
  delete      Delete a subscription (and its delivery history) by id
  enable      Re-enable a disabled subscription
  disable     Pause a subscription (cancels its pending deliveries)
  test        Send a live signed test delivery to a subscription's endpoint
  deliveries  List a subscription's delivery history

Supported event types: %s
(an empty -events list subscribes to all of them)

Examples:
  secsy-ca webhook create -url https://example.com/hook -events cert.issue,cert.revoke
  secsy-ca webhook create -url https://example.com/hook -scope platform
  secsy-ca webhook list -tenant acme
  secsy-ca webhook test <id>
  secsy-ca webhook deliveries <id> -status dead -limit 50
  secsy-ca webhook delete <id>
`, strings.Join(webhook.SupportedEventTypes(), ", "))
}

func cmdWebhookCreate(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("webhook create", flag.ContinueOnError)
	urlFlag := fs.String("url", "", "endpoint URL to POST events to (required)")
	eventsCSV := fs.String("events", "", "comma-separated event types (empty = all lifecycle events)")
	secret := fs.String("secret", "", "HMAC signing secret (generated when empty)")
	tenant := fs.String("tenant", "", "owning tenant id or slug (default: the default tenant)")
	scope := fs.String("scope", models.WebhookScopeTenant, "subscription scope: tenant | platform")
	description := fs.String("description", "", "optional description")
	disabled := fs.Bool("disabled", false, "create the subscription in the disabled state")
	asJSON := fs.Bool("json", false, "emit the created subscription (including the secret) as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateCLIWebhookURL(*urlFlag); err != nil {
		return err
	}
	events, err := parseWebhookEvents(*eventsCSV)
	if err != nil {
		return err
	}

	sc := strings.TrimSpace(*scope)
	var tenantID string
	switch sc {
	case models.WebhookScopePlatform:
		tenantID = models.DefaultTenantID
	case models.WebhookScopeTenant:
		if tenantID, err = resolveTenant(db, *tenant); err != nil {
			return err
		}
	default:
		return fmt.Errorf("-scope must be %q or %q", models.WebhookScopeTenant, models.WebhookScopePlatform)
	}

	sec := strings.TrimSpace(*secret)
	if sec == "" {
		if sec, err = webhook.GenerateSecret(); err != nil {
			return fmt.Errorf("generating signing secret: %w", err)
		}
	}

	sub := &models.WebhookSubscription{
		ID:          uuid.New().String(),
		TenantID:    tenantID,
		Scope:       sc,
		URL:         strings.TrimSpace(*urlFlag),
		Secret:      sec,
		EventTypes:  events,
		Enabled:     !*disabled,
		Description: strings.TrimSpace(*description),
		CreatedBy:   cliActor(),
		CreatedAt:   time.Now().UTC(),
	}
	if err := db.CreateWebhookSubscription(sub); err != nil {
		return fmt.Errorf("creating webhook: %w", err)
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionWebhookCreate, Tenant: tenantID,
		Target: sub.ID, TargetName: sub.URL, Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("scope=%s events=%s enabled=%v via=cli", sc, webhookEventsLabelCLI(events), sub.Enabled),
	})

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(struct {
			*models.WebhookSubscription
			Secret string `json:"secret"`
		}{WebhookSubscription: sub, Secret: sec})
	}
	fmt.Printf("Webhook subscription created: %s\n", sub.ID)
	fmt.Printf("  url:     %s\n", sub.URL)
	fmt.Printf("  scope:   %s\n", sc)
	fmt.Printf("  tenant:  %s\n", tenantID)
	fmt.Printf("  events:  %s\n", webhookEventsLabelCLI(events))
	fmt.Printf("  enabled: %v\n", sub.Enabled)
	fmt.Println()
	fmt.Println("  Signing secret (shown ONCE — store it now, it cannot be recovered):")
	fmt.Printf("    %s\n", sec)
	fmt.Println()
	fmt.Println("  Deliveries carry an X-Secsy-Signature: t=<unix>,v1=<hmac> header;")
	fmt.Println("  verify it as HMAC-SHA256(secret, \"<unix>.<body>\").")
	return nil
}

func cmdWebhookList(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("webhook list", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "filter by tenant id or slug (default: all tenants)")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tenantID := ""
	if strings.TrimSpace(*tenant) != "" {
		var err error
		if tenantID, err = resolveTenant(db, *tenant); err != nil {
			return err
		}
	}
	subs, err := db.ListWebhookSubscriptions(tenantID)
	if err != nil {
		return err
	}
	if *asJSON {
		if subs == nil {
			subs = []models.WebhookSubscription{}
		}
		return json.NewEncoder(os.Stdout).Encode(subs)
	}
	if len(subs) == 0 {
		fmt.Println("No webhook subscriptions.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSCOPE\tTENANT\tENABLED\tEVENTS\tURL")
	for _, s := range subs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\t%s\n",
			s.ID, s.Scope, s.TenantID, s.Enabled, webhookEventsLabelCLI(s.EventTypes), s.URL)
	}
	return w.Flush()
}

func cmdWebhookDelete(db *database.DB, args []string) error {
	id, rest := splitIDAndFlags(args)
	fs := flag.NewFlagSet("webhook delete", flag.ContinueOnError)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return fmt.Errorf("usage: secsy-ca webhook delete <id>")
	}
	sub, err := db.GetWebhookSubscription(id)
	if err != nil {
		return err
	}
	if sub == nil {
		return fmt.Errorf("webhook %q not found", id)
	}
	changed, err := db.DeleteWebhookSubscription(id)
	if err != nil {
		return err
	}
	if !changed {
		fmt.Printf("Webhook %s was already deleted.\n", id)
		return nil
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionWebhookDelete, Tenant: sub.TenantID,
		Target: sub.ID, TargetName: sub.URL, Result: audit.ResultSuccess, Detail: "via=cli",
	})
	fmt.Printf("Webhook deleted: %s (%s)\n", sub.ID, sub.URL)
	return nil
}

func cmdWebhookSetEnabled(db *database.DB, args []string, enabled bool) error {
	verb := "enable"
	if !enabled {
		verb = "disable"
	}
	id, rest := splitIDAndFlags(args)
	fs := flag.NewFlagSet("webhook "+verb, flag.ContinueOnError)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return fmt.Errorf("usage: secsy-ca webhook %s <id>", verb)
	}
	sub, err := db.GetWebhookSubscription(id)
	if err != nil {
		return err
	}
	if sub == nil {
		return fmt.Errorf("webhook %q not found", id)
	}
	changed, err := db.SetWebhookSubscriptionEnabled(id, enabled)
	if err != nil {
		return err
	}
	if !enabled {
		if _, err := db.CancelPendingWebhookDeliveries(id); err != nil {
			return fmt.Errorf("canceling pending deliveries: %w", err)
		}
	}
	if changed {
		appendAudit(db, &audit.Event{
			Actor: cliActor(), Action: audit.ActionWebhookUpdate, Tenant: sub.TenantID,
			Target: sub.ID, TargetName: sub.URL, Result: audit.ResultSuccess,
			Detail: fmt.Sprintf("enabled=%v via=cli", enabled),
		})
		fmt.Printf("Webhook %sd: %s\n", verb, sub.ID)
	} else {
		fmt.Printf("Webhook %s already %sd.\n", sub.ID, verb)
	}
	return nil
}

func cmdWebhookTest(db *database.DB, cfg *config.Config, args []string) error {
	id, rest := splitIDAndFlags(args)
	fs := flag.NewFlagSet("webhook test", flag.ContinueOnError)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return fmt.Errorf("usage: secsy-ca webhook test <id>")
	}
	sub, err := db.GetWebhookSubscription(id)
	if err != nil {
		return err
	}
	if sub == nil {
		return fmt.Errorf("webhook %q not found", id)
	}
	fmt.Printf("Sending signed test delivery to %s ...\n", sub.URL)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Webhook.Timeout()+2*time.Second)
	defer cancel()
	status, postErr := webhook.SendTest(ctx, sub, cfg.Webhook.Timeout())

	result := audit.ResultSuccess
	detail := fmt.Sprintf("test via=cli status=%d", status)
	if postErr != nil {
		result = audit.ResultError
		detail = "test via=cli error=" + postErr.Error()
	} else if status < 200 || status >= 300 {
		result = audit.ResultError
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionWebhookDeliver, Tenant: sub.TenantID,
		Target: sub.ID, TargetName: sub.URL, Result: result, Detail: detail,
	})

	if postErr != nil {
		return fmt.Errorf("test delivery failed: %w", postErr)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("endpoint returned HTTP %d (expected 2xx)", status)
	}
	fmt.Printf("OK — endpoint acknowledged with HTTP %d.\n", status)
	return nil
}

func cmdWebhookDeliveries(db *database.DB, args []string) error {
	id, rest := splitIDAndFlags(args)
	fs := flag.NewFlagSet("webhook deliveries", flag.ContinueOnError)
	status := fs.String("status", "", "filter by status: pending | delivered | dead | canceled")
	limit := fs.Int("limit", 50, "maximum deliveries to show")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return fmt.Errorf("usage: secsy-ca webhook deliveries <id> [flags]")
	}
	deliveries, err := db.ListWebhookDeliveries(id, strings.TrimSpace(*status), *limit)
	if err != nil {
		return err
	}
	if *asJSON {
		if deliveries == nil {
			deliveries = []models.WebhookDelivery{}
		}
		return json.NewEncoder(os.Stdout).Encode(deliveries)
	}
	if len(deliveries) == 0 {
		fmt.Println("No deliveries.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tEVENT\tSTATUS\tATTEMPTS\tCODE\tNEXT-ATTEMPT\tLAST-ERROR")
	for _, d := range deliveries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d/%d\t%d\t%s\t%s\n",
			d.ID, d.EventType, d.Status, d.Attempts, d.MaxAttempts, d.LastStatusCode,
			webhookTimeLabel(&d.NextAttemptAt), truncateField(d.LastError, 48))
	}
	return w.Flush()
}

// --- helpers ---

func validateCLIWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("-url is required")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return fmt.Errorf("-url must be an http(s) URL")
	}
	return nil
}

func parseWebhookEvents(csv string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if !webhook.IsSupportedEventType(e) {
			return nil, fmt.Errorf("unsupported event type %q (supported: %s)", e, strings.Join(webhook.SupportedEventTypes(), ", "))
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out, nil
}

func webhookEventsLabelCLI(events []string) string {
	if len(events) == 0 {
		return "*(all)"
	}
	return strings.Join(events, ",")
}

func webhookTimeLabel(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}

func truncateField(s string, max int) string {
	if len(s) > max {
		return s[:max-1] + "…"
	}
	return s
}
