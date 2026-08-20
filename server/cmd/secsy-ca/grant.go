// Resource-scoped grant administration on the command line (Task 191).
//
// The commands here operate directly on the store rather than through the REST
// API, like the rest of secsy-ca: they are the break-glass and bootstrap path,
// usable before any operator can log in and while the server is down. The
// authorization the API applies (rbac:manage in the tenant, or resource:delegate
// on the resource) does not apply to a local operator holding the database and
// the HSM PIN — that is already full control.
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

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// cmdGrant dispatches the "grant" command group: per-CA / per-key delegation to
// users and groups.
func cmdGrant(db *database.DB, cfg *config.Config, args []string) error {
	if len(args) == 0 {
		grantUsage()
		return fmt.Errorf("grant: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add", "grant":
		return cmdGrantAdd(db, rest)
	case "remove", "revoke":
		return cmdGrantRemove(db, rest)
	case "list":
		return cmdGrantList(db, cfg, rest)
	case "effective":
		return cmdGrantEffective(db, cfg, rest)
	case "roles":
		return cmdGrantRoles()
	case "help", "-h", "--help":
		grantUsage()
		return nil
	default:
		grantUsage()
		return fmt.Errorf("grant: unknown subcommand %q", sub)
	}
}

func grantUsage() {
	fmt.Fprint(os.Stderr, `Usage: secsy-ca grant <subcommand> [flags]

Delegate authority over ONE CA or key to a user or group, so that (for example)
a platform administrator keeps the root CA while a specific group administers a
single subordinate.

Subcommands:
  add         Grant a resource role to a user or group
  remove      Revoke a previously granted resource role
  list        List the grants recorded on a resource
  effective   Show what a subject may do at a resource, and why
  roles       Describe the available resource roles and their capabilities

A resource is written "<type>/<id>":
  ca/<ca-id>              an X.509 or SSH certification authority
  signing-key/<name>      a named HSM-backed signing key on the secret layer

Examples:
  secsy-ca grant add -resource ca/3f9c -role ca-manager -group pki-payments
  secsy-ca grant add -resource ca/3f9c -role ca-admin -user ops@example.com -scope subtree
  secsy-ca grant add -resource signing-key/release -role key-signer -group ci-release
  secsy-ca grant list -resource ca/3f9c
  secsy-ca grant effective -resource ca/3f9c -subject ops@example.com
  secsy-ca grant remove -resource ca/3f9c -role ca-manager -group pki-payments
`)
}

// grantTarget parses the -user/-group pair shared by add and remove, enforcing
// that exactly one is given: a grant binds one entity, and accepting both would
// hide which one the operator meant to change.
func grantTarget(user, group string) (entityType, entityID string, err error) {
	switch {
	case user != "" && group != "":
		return "", "", fmt.Errorf("give exactly one of -user or -group, not both")
	case user != "":
		return rbac.EntityUser, user, nil
	case group != "":
		return rbac.EntityGroup, group, nil
	default:
		return "", "", fmt.Errorf("one of -user or -group is required")
	}
}

func cmdGrantAdd(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("grant add", flag.ContinueOnError)
	resource := fs.String("resource", "", `resource to delegate, "<type>/<id>" (required)`)
	role := fs.String("role", "", "resource role to grant (see `secsy-ca grant roles`)")
	user := fs.String("user", "", "subject or verified email address to grant to")
	group := fs.String("group", "", "group identifier to grant to (internal or IdP group)")
	scope := fs.String("scope", string(rbac.ScopeSelf), `"self" (this resource) or "subtree" (this CA and every CA beneath it)`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *resource == "" || *role == "" {
		fs.Usage()
		return fmt.Errorf("grant add: -resource and -role are required")
	}
	res, err := rbac.ParseResource(*resource)
	if err != nil {
		return err
	}
	entityType, entityID, err := grantTarget(*user, *group)
	if err != nil {
		return err
	}

	entry := &models.ResourceGrant{
		ID:           uuid.New().String(),
		ResourceType: res.Type,
		ResourceID:   res.ID,
		EntityType:   entityType,
		EntityID:     entityID,
		Role:         rbac.ResourceRole(*role),
		Scope:        rbac.GrantScope(*scope),
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    "cli",
	}
	// Validate before touching the store so a typo reports the valid choices
	// instead of a constraint error.
	if err := entry.Grant().Validate(); err != nil {
		return err
	}
	// A grant on a CA that does not exist is inert and almost always a typo'd
	// ID, so it is refused rather than silently stored.
	if res.Type == rbac.ResourceCA {
		tenantID, err := db.GetCATenant(res.ID)
		if err != nil {
			return fmt.Errorf("looking up CA %s: %w", res.ID, err)
		}
		if tenantID == "" {
			return fmt.Errorf("no CA with id %q (use `secsy-ca list` to see the CA ids)", res.ID)
		}
	}
	if err := db.PutResourceGrant(entry); err != nil {
		return fmt.Errorf("storing grant: %w", err)
	}
	fmt.Printf("Granted %s on %s to %s:%s (scope %s)\n",
		entry.Role, res, entry.EntityType, entry.EntityID, entry.Scope)
	return nil
}

func cmdGrantRemove(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("grant remove", flag.ContinueOnError)
	resource := fs.String("resource", "", `resource, "<type>/<id>" (required)`)
	role := fs.String("role", "", "resource role to revoke (required)")
	user := fs.String("user", "", "subject or email the grant was made to")
	group := fs.String("group", "", "group the grant was made to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *resource == "" || *role == "" {
		fs.Usage()
		return fmt.Errorf("grant remove: -resource and -role are required")
	}
	res, err := rbac.ParseResource(*resource)
	if err != nil {
		return err
	}
	entityType, entityID, err := grantTarget(*user, *group)
	if err != nil {
		return err
	}
	removed, err := db.DeleteResourceGrant(res, entityType, entityID, rbac.ResourceRole(*role))
	if err != nil {
		return fmt.Errorf("revoking grant: %w", err)
	}
	if !removed {
		return fmt.Errorf("no %s grant for %s:%s on %s (a grant declared in rbac.grants must be removed from the config file)",
			*role, entityType, entityID, res)
	}
	fmt.Printf("Revoked %s on %s from %s:%s\n", *role, res, entityType, entityID)
	return nil
}

func cmdGrantList(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("grant list", flag.ContinueOnError)
	resource := fs.String("resource", "", `list grants on this resource; omit to list every grant`)
	if err := fs.Parse(args); err != nil {
		return err
	}

	stored, err := listStoredGrants(db, *resource)
	if err != nil {
		return err
	}
	configured, err := listConfiguredGrants(cfg, *resource)
	if err != nil {
		return err
	}
	if len(stored) == 0 && len(configured) == 0 {
		if *resource != "" {
			fmt.Printf("No grants on %s.\n", *resource)
		} else {
			fmt.Println("No resource grants configured or stored.")
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RESOURCE\tROLE\tENTITY\tSCOPE\tSOURCE")
	for _, g := range stored {
		rule := g.Grant()
		fmt.Fprintf(w, "%s\t%s\t%s:%s\t%s\tdatabase\n", rule.Resource, rule.Role, rule.EntityType, rule.EntityID, rule.Scope)
	}
	for _, g := range configured {
		fmt.Fprintf(w, "%s\t%s\t%s:%s\t%s\tconfig\n", g.Resource, g.Role, g.EntityType, g.EntityID, g.Scope)
	}
	return w.Flush()
}

// listStoredGrants returns the database grants, optionally narrowed to one
// resource.
func listStoredGrants(db *database.DB, resource string) ([]models.ResourceGrant, error) {
	if resource == "" {
		return db.ListAllResourceGrants()
	}
	res, err := rbac.ParseResource(resource)
	if err != nil {
		return nil, err
	}
	return db.ListResourceGrants(res)
}

// listConfiguredGrants returns the declarative grants, optionally narrowed to
// one resource. Showing both sources together is the point: an operator asking
// "who can administer this CA?" must not have to know where a rule lives.
func listConfiguredGrants(cfg *config.Config, resource string) ([]rbac.Grant, error) {
	if cfg == nil {
		return nil, nil
	}
	all, err := cfg.AllResourceGrants()
	if err != nil {
		return nil, err
	}
	if resource == "" {
		rbac.SortGrants(all)
		return all, nil
	}
	res, err := rbac.ParseResource(resource)
	if err != nil {
		return nil, err
	}
	var out []rbac.Grant
	for _, g := range all {
		if g.Resource == res {
			out = append(out, g)
		}
	}
	rbac.SortGrants(out)
	return out, nil
}

func cmdGrantEffective(db *database.DB, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("grant effective", flag.ContinueOnError)
	resource := fs.String("resource", "", `resource to evaluate, "<type>/<id>" (required)`)
	subject := fs.String("subject", "", "subject or verified email to evaluate (required)")
	groups := fs.String("groups", "", "comma-separated additional group identities to assume (e.g. IdP groups)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *resource == "" || *subject == "" {
		fs.Usage()
		return fmt.Errorf("grant effective: -resource and -subject are required")
	}
	res, err := rbac.ParseResource(*resource)
	if err != nil {
		return err
	}

	// Group identity: the subject's internal memberships, plus any IdP groups the
	// operator names. Directory groups are asserted at the subject's own login and
	// are unknowable here, so -groups makes a "what if" review possible.
	identity := rbac.Identity{Subject: *subject, Email: *subject, EmailVerified: true}
	if internal, err := db.GetUserGroups(*subject); err == nil {
		identity.Groups = append(identity.Groups, internal...)
	}
	for _, g := range strings.Split(*groups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			identity.Groups = append(identity.Groups, g)
		}
	}

	// Ancestry, so a subtree grant on a parent CA is accounted for.
	var ancestors []rbac.Resource
	if res.Type == rbac.ResourceCA {
		ids, err := db.GetCAAncestors(res.ID)
		if err != nil {
			return fmt.Errorf("resolving CA ancestry: %w", err)
		}
		for _, id := range ids {
			ancestors = append(ancestors, rbac.Resource{Type: rbac.ResourceCA, ID: id})
		}
	}

	stored, err := db.ListAllResourceGrants()
	if err != nil {
		return fmt.Errorf("listing grants: %w", err)
	}
	rules, err := listConfiguredGrants(cfg, "")
	if err != nil {
		return err
	}
	for i := range stored {
		rules = append(rules, stored[i].Grant())
	}
	gs := rbac.NewGrantSet(rules)

	roles := gs.RolesFor(res, ancestors, identity)
	fmt.Printf("Subject:  %s\n", *subject)
	fmt.Printf("Resource: %s\n", res)
	if len(identity.Groups) > 0 {
		fmt.Printf("Groups:   %s\n", strings.Join(identity.Groups, ", "))
	}
	if len(roles) == 0 {
		fmt.Println("\nNo resource grants apply. Any access this subject has here comes from")
		fmt.Println("its platform or tenant roles (see the rbac.subjects / rbac.groups config).")
		return nil
	}
	fmt.Printf("\nResource roles: %s\n", rbac.JoinResourceRoles(roles))

	actions := map[rbac.Action]bool{}
	for _, r := range roles {
		for _, a := range rbac.ResourceRoleActions(r) {
			actions[a] = true
		}
	}
	names := make([]string, 0, len(actions))
	for a := range actions {
		names = append(names, string(a))
	}
	sort.Strings(names)
	fmt.Printf("Capabilities at this resource: %s\n", strings.Join(names, ", "))

	fmt.Println("\nMatching grants:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  RESOURCE\tROLE\tENTITY\tSCOPE\tVIA")
	for _, g := range gs.All() {
		if !identity.Matches(g) {
			continue
		}
		via := "direct"
		if g.Resource != res {
			via = "inherited (subtree)"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s:%s\t%s\t%s\n", g.Resource, g.Role, g.EntityType, g.EntityID, g.Scope, via)
	}
	return w.Flush()
}

// cmdGrantRoles documents the resource-role vocabulary, so an operator choosing
// a delegation does not have to read the docs to see what each role confers.
func cmdGrantRoles() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ROLE\tAPPLIES TO\tCAPABILITIES")
	for _, role := range rbac.AllResourceRoles {
		var types []string
		for _, t := range rbac.AllResourceTypes {
			if rbac.ResourceRoleAppliesTo(role, t) {
				types = append(types, string(t))
			}
		}
		acts := rbac.ResourceRoleActions(role)
		names := make([]string, len(acts))
		for i, a := range acts {
			names[i] = string(a)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", role, strings.Join(types, ", "), strings.Join(names, ", "))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Print(`
Scope:
  self     the named resource only (default)
  subtree  the named CA and every CA beneath it, including ones created later

Grants are ADDITIVE: they widen what a user or group may do at one resource and
never remove authority a platform or tenant role already confers.
`)
	return nil
}
