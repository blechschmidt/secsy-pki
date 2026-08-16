package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// cmdToken implements `secsy-ca token <create|list|revoke>` — lifecycle
// management for native scoped API tokens / service accounts (Task 86). Local
// CLI access is platform-operator level (it bypasses the API's RBAC), so the
// commands operate directly on the store; the four-eyes gate still applies to a
// sensitive create when approvals are enabled.
func cmdToken(db *database.DB, cfg *config.Config, args []string) error {
	if len(args) == 0 {
		tokenUsage()
		return fmt.Errorf("token: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdTokenCreate(db, cfg, rest)
	case "list":
		return cmdTokenList(db, rest)
	case "revoke":
		return cmdTokenRevoke(db, rest)
	case "help", "-h", "--help":
		tokenUsage()
		return nil
	default:
		tokenUsage()
		return fmt.Errorf("token: unknown subcommand %q", sub)
	}
}

func tokenUsage() {
	fmt.Fprint(os.Stderr, `Usage: secsy-ca token <subcommand> [flags]

Subcommands:
  create   Mint a new scoped API token (prints the secret once)
  list     List API tokens
  revoke   Revoke an API token by id

Examples:
  secsy-ca token create -name ci-issuer -roles issuer -tenant acme -expires-days 90
  secsy-ca token create -name platform-bot -roles admin -scope platform
  secsy-ca token list -tenant acme
  secsy-ca token revoke <id>
`)
}

func cmdTokenCreate(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	name := fs.String("name", "", "human-readable token name (required)")
	rolesCSV := fs.String("roles", "", "comma-separated RBAC roles to grant (required): admin,issuer,signer,auditor,approver")
	tenant := fs.String("tenant", "", "owning tenant id or slug (default: the default tenant)")
	scope := fs.String("scope", models.TokenScopeTenant, "token scope: tenant | platform")
	expiresDays := fs.Int("expires-days", -1, "days until expiry (omit for policy default; 0 = never when uncapped)")
	description := fs.String("description", "", "optional description")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("-name is required")
	}
	roles, err := parseTokenRoles(*rolesCSV)
	if err != nil {
		return err
	}

	sc := strings.TrimSpace(*scope)
	var tenantID string
	switch sc {
	case models.TokenScopePlatform:
		tenantID = models.DefaultTenantID
	case models.TokenScopeTenant:
		tenantID, err = resolveTenant(db, *tenant)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("-scope must be %q or %q", models.TokenScopeTenant, models.TokenScopePlatform)
	}

	var reqDays *int
	if *expiresDays >= 0 {
		d := *expiresDays
		reqDays = &d
	}
	lifetimeDays, err := authn.ResolveTokenLifetimeDays(cfg.Auth.APITokenMaxLifetime(), reqDays)
	if err != nil {
		return err
	}

	// Four-eyes gate for a sensitive grant (privileged role or platform scope).
	if sc == models.TokenScopePlatform || anyPrivilegedRole(roles) {
		if err := guardCLI(db, cfg, approval.GuardRequest{
			Class:        approval.ClassTokenCreate,
			ResourceKey:  "token:new:" + tenantID + ":" + *name,
			ResourceName: *name,
			Summary:      fmt.Sprintf("Create %s-scoped API token %q with roles [%s]", sc, *name, strings.Join(roles, ",")),
			Params:       fmt.Sprintf("name=%s;scope=%s;tenant=%s;roles=%s;lifetime_days=%d", *name, sc, tenantID, strings.Join(roles, ","), lifetimeDays),
			Tenant:       tenantID,
		}); err != nil {
			return err
		}
	}

	secret, hash, prefix := authn.GenerateToken()
	var expiresAt *time.Time
	if lifetimeDays > 0 {
		t := time.Now().UTC().Add(time.Duration(lifetimeDays) * 24 * time.Hour)
		expiresAt = &t
	}
	tok := &models.APIToken{
		ID:          uuid.New().String(),
		TenantID:    tenantID,
		Name:        *name,
		Description: strings.TrimSpace(*description),
		Prefix:      prefix,
		TokenHash:   hash,
		Roles:       roles,
		Scope:       sc,
		CreatedBy:   cliActor(),
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   expiresAt,
	}
	if err := db.CreateAPIToken(tok); err != nil {
		return fmt.Errorf("creating token: %w", err)
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionTokenCreate, Tenant: tenantID,
		Target: tok.ID, TargetName: tok.Name, Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("scope=%s roles=%s expires=%s via=cli", sc, strings.Join(roles, ","), tokenExpiryLabel(expiresAt)),
	})

	if asJSON {
		return cliout.Emit(struct {
			*models.APIToken
			Secret string `json:"secret"`
		}{APIToken: tok, Secret: secret})
	}
	fmt.Printf("API token created: %s (id=%s)\n", tok.Name, tok.ID)
	fmt.Printf("  scope:   %s\n", sc)
	fmt.Printf("  tenant:  %s\n", tenantID)
	fmt.Printf("  roles:   %s\n", strings.Join(roles, ","))
	fmt.Printf("  expires: %s\n", tokenExpiryLabel(expiresAt))
	fmt.Println()
	fmt.Println("  Secret (shown ONCE — store it now, it cannot be recovered):")
	fmt.Printf("    %s\n", secret)
	fmt.Println()
	fmt.Println("  Use it as:  Authorization: Token <secret>")
	return nil
}

func cmdTokenList(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "filter by tenant id or slug (default: all tenants)")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}
	tenantID := ""
	if strings.TrimSpace(*tenant) != "" {
		if tenantID, err = resolveTenant(db, *tenant); err != nil {
			return err
		}
	}
	tokens, err := db.ListAPITokens(tenantID)
	if err != nil {
		return err
	}
	if asJSON {
		if tokens == nil {
			tokens = []models.APIToken{}
		}
		return cliout.Emit(tokens)
	}
	if len(tokens) == 0 {
		fmt.Println("No API tokens.")
		return nil
	}
	now := time.Now()
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSCOPE\tTENANT\tROLES\tSTATUS\tEXPIRES\tLAST-USED\tPREFIX")
	for _, tok := range tokens {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			tok.ID, tok.Name, tok.Scope, tok.TenantID, strings.Join(tok.Roles, ","),
			tok.Status(now), tokenExpiryLabel(tok.ExpiresAt), tokenTimeLabel(tok.LastUsedAt), tok.Prefix)
	}
	return w.Flush()
}

func cmdTokenRevoke(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	id, rest := splitIDAndFlags(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		return fmt.Errorf("usage: secsy-ca token revoke <id>")
	}
	tok, err := db.GetAPIToken(id)
	if err != nil {
		return err
	}
	if tok == nil {
		return fmt.Errorf("token %q not found", id)
	}
	changed, err := db.RevokeAPIToken(id, cliActor(), time.Now().UTC())
	if err != nil {
		return err
	}
	if !changed {
		fmt.Printf("Token %s was already revoked.\n", id)
		return nil
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionTokenRevoke, Tenant: tok.TenantID,
		Target: tok.ID, TargetName: tok.Name, Result: audit.ResultSuccess,
		Detail: "scope=" + tok.Scope + " via=cli",
	})
	fmt.Printf("Token revoked: %s (%s)\n", tok.Name, tok.ID)
	return nil
}

// parseTokenRoles splits and validates a comma-separated role list.
func parseTokenRoles(csv string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if !rbac.ValidRole(rbac.Role(name)) {
			return nil, fmt.Errorf("unknown role %q (valid: admin, issuer, signer, auditor, approver)", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("-roles is required (comma-separated)")
	}
	sort.Strings(out)
	return out, nil
}

func anyPrivilegedRole(roles []string) bool {
	for _, r := range roles {
		if rbac.IsPrivilegedRole(rbac.Role(r)) {
			return true
		}
	}
	return false
}

func tokenExpiryLabel(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339)
}

func tokenTimeLabel(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}
