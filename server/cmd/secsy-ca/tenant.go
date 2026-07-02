package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// resolveTenant maps a tenant selector (id or slug, empty for the default
// tenant) to a tenant ID, verifying the tenant exists so a CA is never created
// under a dangling tenant.
func resolveTenant(db *database.DB, selector string) (string, error) {
	if selector == "" {
		return models.DefaultTenantID, nil
	}
	t, err := db.GetTenant(selector)
	if err != nil {
		return "", err
	}
	if t == nil {
		if t, err = db.GetTenantBySlug(selector); err != nil {
			return "", err
		}
	}
	if t == nil {
		return "", fmt.Errorf("unknown tenant %q", selector)
	}
	return t.ID, nil
}

// cmdTenant implements `secsy-ca tenant <list|create|suspend|activate>` for
// managing the multi-tenant isolation boundaries locally.
func cmdTenant(db *database.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secsy-ca tenant <list|create|suspend|activate>")
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
	default:
		return fmt.Errorf("unknown tenant subcommand %q", sub)
	}
}

func cmdTenantList(db *database.DB) error {
	tenants, err := db.ListTenants()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "SLUG\tID\tNAME\tSTATUS\tKEK")
	for _, t := range tenants {
		kek := t.KEKLabel
		if kek == "" {
			kek = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t.Slug, t.ID, t.Name, t.Status, kek)
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
	fmt.Printf("Tenant %s is now %s\n", args[0], status)
	return nil
}
