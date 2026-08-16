package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// resolveTenant maps a tenant selector (id or slug, empty for the default
// tenant) to a tenant ID, verifying the tenant exists so a CA is never created
// under a dangling tenant.
func resolveTenant(db *database.DB, selector string) (string, error) {
	t, err := lookupTenant(db, selector)
	if err != nil {
		return "", err
	}
	return t.ID, nil
}

// lookupTenant resolves a selector (id or slug; empty = default tenant) to its
// full tenant record.
func lookupTenant(db *database.DB, selector string) (*models.Tenant, error) {
	if selector == "" {
		selector = models.DefaultTenantID
	}
	t, err := db.GetTenant(selector)
	if err != nil {
		return nil, err
	}
	if t == nil {
		if t, err = db.GetTenantBySlug(selector); err != nil {
			return nil, err
		}
	}
	if t == nil {
		return nil, fmt.Errorf("unknown tenant %q", selector)
	}
	return t, nil
}

// cliActor labels audit events written by this locally-run CLI. Local database
// access is inherently platform-operator level (the CLI bypasses the API's
// RBAC), so the trail records the invoking OS user.
func cliActor() string {
	if u := os.Getenv("USER"); u != "" {
		return "cli:" + u
	}
	return "cli:local"
}

// cmdTenant implements `secsy-ca tenant <list|create|suspend|activate|quota|usage>`
// for managing the multi-tenant isolation boundaries locally. All mutating
// subcommands append tamper-evident audit events.
func cmdTenant(db *database.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secsy-ca tenant <list|create|suspend|activate|quota|usage>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdTenantList(db)
	case "create":
		return cmdTenantCreate(db, rest)
	case "suspend":
		return cmdTenantStatus(db, rest, models.TenantStatusSuspended)
	case "activate":
		return cmdTenantStatus(db, rest, models.TenantStatusActive)
	case "quota":
		return cmdTenantQuota(db, rest)
	case "usage":
		return cmdTenantUsage(db, rest)
	default:
		return fmt.Errorf("unknown tenant subcommand %q", sub)
	}
}

// fmtLimit renders a quota value, where zero means unlimited.
func fmtLimit(v int64) string {
	if v <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", v)
}

func cmdTenantList(db *database.DB) error {
	tenants, err := db.ListTenants()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "SLUG\tID\tNAME\tSTATUS\tKEK\tCERTS/DAY\tACTIVE-MAX\tSECRET-OPS/DAY\tRATE")
	for _, t := range tenants {
		kek := t.KEKLabel
		if kek == "" {
			kek = "-"
		}
		rate := "-"
		if t.Quotas.RateLimitPerSecond > 0 {
			rate = fmt.Sprintf("%g/%g", t.Quotas.RateLimitPerSecond, t.Quotas.RateLimitBurst)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			t.Slug, t.ID, t.Name, t.Status, kek,
			fmtLimit(t.Quotas.MaxCertsPerDay), fmtLimit(t.Quotas.MaxActiveCerts),
			fmtLimit(t.Quotas.MaxSecretOpsPerDay), rate)
	}
	return w.Flush()
}

func cmdTenantCreate(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("tenant create", flag.ContinueOnError)
	slug := fs.String("slug", "", "URL/CLI-friendly identifier (required, unique)")
	name := fs.String("name", "", "human-readable display name")
	kek := fs.String("kek-label", "", "optional per-tenant secret KEK label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" {
		return fmt.Errorf("-slug is required")
	}
	if existing, err := db.GetTenantBySlug(*slug); err != nil {
		return err
	} else if existing != nil {
		return fmt.Errorf("a tenant with slug %q already exists", *slug)
	}
	displayName := *name
	if displayName == "" {
		displayName = *slug
	}
	t := &models.Tenant{
		ID:       uuid.New().String(),
		Slug:     *slug,
		Name:     displayName,
		Status:   models.TenantStatusActive,
		KEKLabel: *kek,
	}
	if err := db.CreateTenant(t); err != nil {
		return err
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionTenantCreate, Tenant: t.ID,
		Target: t.ID, TargetName: t.Slug, Result: audit.ResultSuccess,
		Detail: "name=" + t.Name + " via=cli",
	})
	fmt.Printf("Tenant created: %s (id=%s)\n", t.Slug, t.ID)
	return nil
}

func cmdTenantStatus(db *database.DB, args []string, status string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: secsy-ca tenant %s <slug-or-id>",
			map[string]string{models.TenantStatusActive: "activate", models.TenantStatusSuspended: "suspend"}[status])
	}
	id, err := resolveTenant(db, args[0])
	if err != nil {
		return err
	}
	if id == models.DefaultTenantID && status == models.TenantStatusSuspended {
		return fmt.Errorf("the default tenant cannot be suspended")
	}
	if err := db.SetTenantStatus(id, status); err != nil {
		return err
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionTenantUpdate, Tenant: id,
		Target: id, Result: audit.ResultSuccess,
		Detail: "status=" + status + " via=cli",
	})
	fmt.Printf("Tenant %s is now %s\n", args[0], status)
	return nil
}

// cmdTenantQuota shows or sets a tenant's quotas. Without flags it prints the
// current quotas; with flags it updates only the given dimensions (0 clears a
// ceiling back to unlimited).
func cmdTenantQuota(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("tenant quota", flag.ContinueOnError)
	certsPerDay := fs.Int64("certs-per-day", -1, "max certificates issued per UTC day (0 = unlimited)")
	activeCerts := fs.Int64("active-certs", -1, "max unexpired, unrevoked certificates (0 = unlimited)")
	secretOps := fs.Int64("secret-ops-per-day", -1, "max envelope encrypt/decrypt operations per UTC day (0 = unlimited)")
	rate := fs.Float64("rate", -1, "per-tenant enrollment request rate in req/s (0 = inherit deployment default)")
	burst := fs.Float64("burst", -1, "per-tenant enrollment burst capacity (0 = inherit deployment default)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: secsy-ca tenant quota <slug-or-id> [flags]")
		fs.PrintDefaults()
	}
	if len(args) == 0 {
		fs.Usage()
		return fmt.Errorf("a tenant selector is required")
	}
	selector := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	t, err := lookupTenant(db, selector)
	if err != nil {
		return err
	}

	changed := false
	set := func(dst *int64, v int64) {
		if v >= 0 {
			*dst = v
			changed = true
		}
	}
	set(&t.Quotas.MaxCertsPerDay, *certsPerDay)
	set(&t.Quotas.MaxActiveCerts, *activeCerts)
	set(&t.Quotas.MaxSecretOpsPerDay, *secretOps)
	if *rate >= 0 {
		t.Quotas.RateLimitPerSecond = *rate
		changed = true
	}
	if *burst >= 0 {
		t.Quotas.RateLimitBurst = *burst
		changed = true
	}

	if changed {
		if err := db.UpdateTenant(t); err != nil {
			return err
		}
		appendAudit(db, &audit.Event{
			Actor: cliActor(), Action: audit.ActionTenantUpdate, Tenant: t.ID,
			Target: t.ID, TargetName: t.Slug, Result: audit.ResultSuccess,
			Detail: fmt.Sprintf("quotas={certs_per_day:%d active:%d secret_ops:%d rate:%g burst:%g} via=cli",
				t.Quotas.MaxCertsPerDay, t.Quotas.MaxActiveCerts, t.Quotas.MaxSecretOpsPerDay,
				t.Quotas.RateLimitPerSecond, t.Quotas.RateLimitBurst),
		})
		fmt.Printf("Quotas updated for tenant %s\n", t.Slug)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "certs/day:\t%s\n", fmtLimit(t.Quotas.MaxCertsPerDay))
	fmt.Fprintf(w, "active certs:\t%s\n", fmtLimit(t.Quotas.MaxActiveCerts))
	fmt.Fprintf(w, "secret ops/day:\t%s\n", fmtLimit(t.Quotas.MaxSecretOpsPerDay))
	if t.Quotas.RateLimitPerSecond > 0 {
		fmt.Fprintf(w, "rate limit:\t%g req/s (burst %g)\n", t.Quotas.RateLimitPerSecond, t.Quotas.RateLimitBurst)
	} else {
		fmt.Fprintf(w, "rate limit:\tdeployment default\n")
	}
	return w.Flush()
}

// cmdTenantUsage prints a tenant's usage report: live inventory counts plus a
// rolling window of daily accounting rows (newest first).
func cmdTenantUsage(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("tenant usage", flag.ContinueOnError)
	days := fs.Int("days", 7, "rolling window size in UTC days (1-90)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: secsy-ca tenant usage <slug-or-id> [-days N]")
		fs.PrintDefaults()
	}
	if len(args) == 0 {
		fs.Usage()
		return fmt.Errorf("a tenant selector is required")
	}
	selector := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *days < 1 || *days > 90 {
		return fmt.Errorf("-days must be between 1 and 90")
	}
	t, err := lookupTenant(db, selector)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	active, err := db.CountActiveCertificatesForTenant(t.ID, now)
	if err != nil {
		return fmt.Errorf("counting active certificates: %w", err)
	}
	total, revoked, err := db.TenantCertificateTotals(t.ID)
	if err != nil {
		return fmt.Errorf("reading certificate totals: %w", err)
	}
	cas, err := db.CountCAsForTenant(t.ID)
	if err != nil {
		return fmt.Errorf("counting CAs: %w", err)
	}
	since := database.UsageDay(now.AddDate(0, 0, -(*days - 1)))
	recorded, err := db.ListTenantUsageDays(t.ID, since)
	if err != nil {
		return fmt.Errorf("reading usage window: %w", err)
	}
	byDay := make(map[string]models.TenantUsageDay, len(recorded))
	for _, d := range recorded {
		byDay[d.Day] = d
	}

	fmt.Printf("Tenant %s (%s) — status: %s\n", t.Slug, t.ID, t.Status)
	fmt.Printf("CAs: %d   active certs: %d", cas, active)
	if t.Quotas.MaxActiveCerts > 0 {
		fmt.Printf(" / %d", t.Quotas.MaxActiveCerts)
	}
	fmt.Printf("   issued (lifetime): %d   revoked: %d\n\n", total, revoked)

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "DAY\tISSUED\tREVOKED\tSECRET-OPS")
	for i := 0; i < *days; i++ {
		day := database.UsageDay(now.AddDate(0, 0, -i))
		d := byDay[day] // zero row when absent
		issued := fmt.Sprintf("%d", d.CertsIssued)
		if t.Quotas.MaxCertsPerDay > 0 {
			issued = fmt.Sprintf("%d/%d", d.CertsIssued, t.Quotas.MaxCertsPerDay)
		}
		secretOps := fmt.Sprintf("%d", d.SecretOps)
		if t.Quotas.MaxSecretOpsPerDay > 0 {
			secretOps = fmt.Sprintf("%d/%d", d.SecretOps, t.Quotas.MaxSecretOpsPerDay)
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", day, issued, d.CertsRevoked, secretOps)
	}
	return w.Flush()
}
