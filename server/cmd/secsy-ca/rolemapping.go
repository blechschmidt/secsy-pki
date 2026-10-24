package main

// `secsy-ca role-mapping` — inspect and dry-run the claim/group -> RBAC role
// mappings (Task 214).
//
// Exact-value mappings are easy to reason about by reading the config file. CEL
// expressions are not: the question "which roles does this directory group
// actually produce?" has a definite answer that nobody should have to discover
// by logging in repeatedly and reading the audit log. This command answers it
// offline — no database, no HSM, no IdP — against the same compiled mappers the
// server builds at startup.
//
// It also evaluates an ad-hoc expression (-expression / -tenant-expression)
// against a synthetic identity, which is how an operator writes one in the
// first place.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/celexpr"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// rawMultiFlag collects a repeatable string flag verbatim. Unlike multiFlag it
// does NOT split on commas: a group identity is frequently a distinguished name
// ("CN=PKI-Admins,OU=Groups,DC=corp,DC=example,DC=com"), and splitting that
// would silently turn one group into five that match nothing.
type rawMultiFlag []string

func (m *rawMultiFlag) String() string { return strings.Join(*m, "; ") }

func (m *rawMultiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// cmdRoleMapping dispatches the `role-mapping` subcommands. It reads only the
// configuration file.
func cmdRoleMapping(cfg *config.Config, args []string) error {
	if len(args) == 0 {
		roleMappingUsage()
		return fmt.Errorf("role-mapping: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdRoleMappingList(cfg, rest)
	case "test":
		return cmdRoleMappingTest(cfg, rest)
	case "reference", "ref":
		return cmdRoleMappingReference(rest)
	case "help", "-h", "--help":
		roleMappingUsage()
		return nil
	default:
		roleMappingUsage()
		return fmt.Errorf("role-mapping: unknown subcommand %q", sub)
	}
}

func roleMappingUsage() {
	fmt.Fprint(os.Stderr, `secsy-ca role-mapping — inspect and dry-run claim/group -> RBAC role mappings

Usage:
  secsy-ca role-mapping list [-source NAME] [-json]
      List the configured role mappings, by source: each console OIDC provider
      (auth.oidc), each machine-token provider (oidc.providers), and the
      directory (auth.ldap).

  secsy-ca role-mapping test [identity flags] [-source NAME] [-json]
      Evaluate the configured mappings against a synthetic identity and report,
      per mapping, whether it matched, which tenants it resolved to, and the
      roles it granted.

  secsy-ca role-mapping test -expression EXPR [-tenant-expression EXPR] [identity flags]
      Evaluate an ad-hoc expression instead of the configured mappings — how an
      expression is written and checked before it goes into the config file.

  secsy-ca role-mapping reference [-json]
      Print the variables and functions an expression may use.

Identity flags (all optional; every variable defaults to empty/false):
  -subject ID            the authenticated subject ("sub")
  -email ADDR            the principal's e-mail address
  -email-verified        mark that address verified
  -name NAME             display name
  -username NAME         directory username / "preferred_username"
  -issuer URL            token issuer ("iss")
  -provider NAME         the provider name expressions see
  -group NAME            a group membership (repeatable, taken verbatim —
                         commas are part of a DN, not separators)
  -claims JSON|@FILE     the full claim set, as JSON

Reading the output: a mapping is reported MATCHED only when it actually grants
something. A mapping whose pattern fired but whose tenant expression resolved to
no usable tenant is reported as not matched, with the reason — that case grants
nothing, deliberately, rather than falling back to a platform-wide grant.
`)
}

// roleMappingSource is one configured mapper plus where it came from.
type roleMappingSource struct {
	Name        string
	Where       string
	GroupsClaim string
	Disabled    bool
	Mappings    []config.ClaimMappingConfig
	Mapper      *authn.ClaimMapper
}

// roleMappingSources builds every configured mapper, in the order an operator
// reads the config file. A source whose mappings do not compile is an error:
// the server would refuse to start on it too.
//
// Sources whose login mechanism is switched off are included, labelled
// disabled. Writing the mappings is normally the step before enabling the
// mechanism, and a tool that answered "nothing is configured" to a config file
// full of mappings would be useless exactly when it is needed.
func roleMappingSources(cfg *config.Config) ([]roleMappingSource, error) {
	var out []roleMappingSource
	add := func(name, where, groupsClaim string, disabled bool, mappings []config.ClaimMappingConfig) error {
		mapper, err := authn.NewClaimMapper(groupsClaim, buildCLIClaimMappings(mappings),
			authn.WithKnownTenants(cfg.TenantIDs()))
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if disabled {
			where += " [login disabled]"
		}
		out = append(out, roleMappingSource{
			Name: name, Where: where, GroupsClaim: mapper.GroupsClaim(), Disabled: disabled,
			Mappings: mappings, Mapper: mapper,
		})
		return nil
	}
	consoleDisabled := !cfg.Auth.OIDC.Enabled
	if providers := cfg.ConsoleOIDCProviders(); len(providers) > 0 {
		for _, pc := range providers {
			if err := add(pc.Name, fmt.Sprintf("auth.oidc (console provider %q)", pc.Name),
				pc.GroupsClaim, consoleDisabled, pc.RoleMappings); err != nil {
				return nil, err
			}
		}
	} else if len(cfg.Auth.OIDC.RoleMappings) > 0 {
		// Mappings written before an issuer is: no provider is synthesized from
		// them, but they are still what the console will use once one is.
		if err := add("console", "auth.oidc (no provider yet)",
			cfg.Auth.OIDC.GroupsClaim, consoleDisabled, cfg.Auth.OIDC.RoleMappings); err != nil {
			return nil, err
		}
	}
	for _, p := range cfg.BearerOIDCProviders() {
		if err := add(p.Name, fmt.Sprintf("oidc (machine-token provider %q)", p.Name),
			p.GroupsClaim, false, p.RoleMappings); err != nil {
			return nil, err
		}
	}
	if cfg.Auth.LDAP.Enabled || len(cfg.Auth.LDAP.RoleMappings) > 0 {
		if err := add("ldap", "auth.ldap", cfg.Auth.LDAP.GroupsClaim,
			!cfg.Auth.LDAP.Enabled, cfg.Auth.LDAP.RoleMappings); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// buildCLIClaimMappings translates config mappings into the authn form. It
// mirrors the server's buildClaimMappings — the CLI must not read a mapping
// differently from the process that enforces it.
func buildCLIClaimMappings(in []config.ClaimMappingConfig) []authn.ClaimMapping {
	out := make([]authn.ClaimMapping, 0, len(in))
	for _, m := range in {
		roles := make([]rbac.Role, 0, len(m.Roles))
		for _, r := range m.Roles {
			roles = append(roles, rbac.Role(strings.TrimSpace(r)))
		}
		out = append(out, authn.ClaimMapping{
			Claim:            m.Claim,
			Value:            m.Value,
			Expression:       m.Expression,
			Tenant:           m.Tenant,
			TenantExpression: m.TenantExpression,
			Roles:            roles,
		})
	}
	return out
}

// selectSources filters by -source, accepting a provider name or a source
// label.
func selectSources(all []roleMappingSource, want string) ([]roleMappingSource, error) {
	if want = strings.TrimSpace(want); want == "" {
		return all, nil
	}
	var out []roleMappingSource
	for _, s := range all {
		if strings.EqualFold(s.Name, want) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		names := make([]string, 0, len(all))
		for _, s := range all {
			names = append(names, s.Name)
		}
		return nil, fmt.Errorf("no configured mapping source named %q (have: %s)", want, strings.Join(names, ", "))
	}
	return out, nil
}

// cmdRoleMappingList prints the configured mappings per source.
func cmdRoleMappingList(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("role-mapping list", flag.ContinueOnError)
	source := fs.String("source", "", "limit to one provider / source name")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	all, err := roleMappingSources(cfg)
	if err != nil {
		return err
	}
	sources, err := selectSources(all, *source)
	if err != nil {
		return err
	}
	if *asJSON {
		type jsonSource struct {
			Name        string                      `json:"name"`
			Where       string                      `json:"where"`
			GroupsClaim string                      `json:"groups_claim"`
			Mappings    []config.ClaimMappingConfig `json:"mappings"`
			Active      []string                    `json:"active"`
		}
		out := make([]jsonSource, 0, len(sources))
		for _, s := range sources {
			js := jsonSource{Name: s.Name, Where: s.Where, GroupsClaim: s.GroupsClaim, Mappings: s.Mappings}
			for _, m := range s.Mapper.Mappings() {
				js.Active = append(js.Active, m.Describe())
			}
			out = append(out, js)
		}
		return emitJSON(out)
	}
	if len(sources) == 0 {
		fmt.Println("No authentication source with claim -> role mappings is configured.")
		return nil
	}
	for _, s := range sources {
		fmt.Printf("%s — groups claim %q\n", s.Where, s.GroupsClaim)
		active := s.Mapper.Mappings()
		if len(active) == 0 {
			fmt.Printf("  (no mappings)\n\n")
			continue
		}
		tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  #\tMATCH\tTENANT\tROLES")
		for i, m := range active {
			match := fmt.Sprintf("%s=%q", orDefault(m.Claim, s.GroupsClaim), m.Value)
			if m.Expression != "" {
				match = "CEL: " + truncate(oneLine(m.Expression), 64)
			}
			tenant := "<platform-wide>"
			switch {
			case m.TenantExpression != "":
				tenant = "CEL: " + truncate(oneLine(m.TenantExpression), 64)
			case m.Tenant != "":
				tenant = m.Tenant
			}
			fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\n", i, match, tenant, strings.Join(roleNames(m.Roles), ","))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if dropped := len(s.Mappings) - len(active); dropped > 0 {
			fmt.Printf("  note: %d configured mapping(s) are inert (no valid role, or nothing to match) and were dropped\n", dropped)
		}
		fmt.Println()
	}
	fmt.Println("Central rbac.subjects / rbac.groups assignments are unioned on top of these at login.")
	return nil
}

// roleMappingDecisionJSON is one mapping's outcome, for -json.
type roleMappingDecisionJSON struct {
	Index   int    `json:"index"`
	Mapping string `json:"mapping"`
	// Fired is the match half; Matched is whether anything was granted. They
	// differ exactly when a tenant expression resolved to no usable tenant.
	Fired    bool     `json:"fired"`
	Matched  bool     `json:"matched"`
	Tenants  []string `json:"tenants,omitempty"`
	Rejected []string `json:"rejected_tenants,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// roleMappingResultJSON is one source's evaluation, for -json. The identity is
// echoed per source rather than once: each source reads its own groups claim,
// so "the identity the expression saw" is a per-source answer.
type roleMappingResultJSON struct {
	Name          string                    `json:"name"`
	Where         string                    `json:"where"`
	GroupsClaim   string                    `json:"groups_claim"`
	Identity      map[string]interface{}    `json:"identity"`
	Decisions     []roleMappingDecisionJSON `json:"decisions"`
	PlatformRoles []string                  `json:"platform_roles,omitempty"`
	TenantRoles   map[string][]string       `json:"tenant_roles,omitempty"`
}

// cmdRoleMappingTest evaluates mappings against a synthetic identity.
func cmdRoleMappingTest(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("role-mapping test", flag.ContinueOnError)
	source := fs.String("source", "", "limit to one provider / source name")
	expression := fs.String("expression", "", "evaluate this ad-hoc CEL match expression instead of the configured mappings")
	tenantExpression := fs.String("tenant-expression", "", "ad-hoc CEL tenant expression (with -expression)")
	roles := fs.String("roles", "auditor", "roles the ad-hoc mapping grants (comma-separated)")
	subject := fs.String("subject", "", "the authenticated subject (\"sub\")")
	email := fs.String("email", "", "the principal's e-mail address")
	emailVerified := fs.Bool("email-verified", false, "mark the e-mail address verified")
	name := fs.String("name", "", "display name")
	username := fs.String("username", "", "directory username / \"preferred_username\"")
	issuer := fs.String("issuer", "", "token issuer (\"iss\")")
	provider := fs.String("provider", "", "provider name expressions see")
	claimsArg := fs.String("claims", "", "the claim set as JSON, or @FILE to read it from a file")
	asJSON := fs.Bool("json", false, "emit JSON")
	var groups rawMultiFlag
	fs.Var(&groups, "group", "a group membership (repeatable, taken verbatim)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantExpression != "" && *expression == "" {
		return fmt.Errorf("-tenant-expression requires -expression")
	}

	claims, err := parseClaimsArg(*claimsArg)
	if err != nil {
		return err
	}
	id := authn.Identity{
		Subject:       *subject,
		Email:         *email,
		EmailVerified: *emailVerified,
		Name:          *name,
		Username:      *username,
		Issuer:        *issuer,
		Provider:      *provider,
		Groups:        groups,
		Claims:        claims,
	}

	var sources []roleMappingSource
	if *expression != "" {
		// Ad-hoc mode: one synthetic source holding just this expression. The
		// mapper is built exactly as the server builds one, so an expression that
		// passes here passes there.
		var rs []rbac.Role
		for _, r := range strings.Split(*roles, ",") {
			if r = strings.TrimSpace(r); r == "" {
				continue
			}
			// Checked here rather than left to the mapper: a mapping with no valid
			// role is dropped as inert, and a dry-run that silently reported "no
			// mappings" for a misspelled role would be the one answer an operator
			// must not get from this command.
			if !rbac.ValidRole(rbac.Role(r)) {
				return fmt.Errorf("-roles: unknown role %q (want one of %s)", r, strings.Join(allRoleNames(), ", "))
			}
			rs = append(rs, rbac.Role(r))
		}
		if len(rs) == 0 {
			return fmt.Errorf("-roles must name at least one role")
		}
		mapper, err := authn.NewClaimMapper(cfg.Auth.OIDC.GroupsClaim, []authn.ClaimMapping{{
			Expression:       *expression,
			TenantExpression: *tenantExpression,
			Roles:            rs,
		}}, authn.WithKnownTenants(cfg.TenantIDs()))
		if err != nil {
			return err
		}
		sources = []roleMappingSource{{
			Name: "ad-hoc", Where: "-expression", GroupsClaim: mapper.GroupsClaim(), Mapper: mapper,
		}}
	} else {
		all, err := roleMappingSources(cfg)
		if err != nil {
			return err
		}
		if sources, err = selectSources(all, *source); err != nil {
			return err
		}
		if len(sources) == 0 {
			return fmt.Errorf("no authentication source with claim -> role mappings is configured " +
				"(use -expression to try one out)")
		}
	}

	results := make([]roleMappingResultJSON, 0, len(sources))
	anyMatch := false
	for _, s := range sources {
		res := roleMappingResultJSON{
			Name: s.Name, Where: s.Where, GroupsClaim: s.GroupsClaim,
			Identity: s.Mapper.Activation(id),
		}
		for _, d := range s.Mapper.Explain(id) {
			dj := roleMappingDecisionJSON{
				Index: d.Index, Mapping: d.Mapping.Describe(),
				Fired: d.Fired, Matched: d.Matched,
				Tenants: d.Tenants, Rejected: d.Rejected,
			}
			if d.Err != nil {
				dj.Error = d.Err.Error()
			}
			res.Decisions = append(res.Decisions, dj)
		}
		platform, tenant := s.Mapper.ResolveIdentity(id)
		res.PlatformRoles = roleNames(platform)
		if len(tenant) > 0 {
			res.TenantRoles = make(map[string][]string, len(tenant))
			for tid, rs := range tenant {
				res.TenantRoles[tid] = roleNames(rs)
			}
		}
		if len(res.PlatformRoles) > 0 || len(res.TenantRoles) > 0 {
			anyMatch = true
		}
		results = append(results, res)
	}

	if *asJSON {
		return emitJSON(struct {
			Sources []roleMappingResultJSON `json:"sources"`
		}{Sources: results})
	}

	for _, res := range results {
		fmt.Printf("%s — groups claim %q\n", res.Where, res.GroupsClaim)
		if len(res.Decisions) == 0 {
			fmt.Printf("  (no mappings)\n\n")
			continue
		}
		for _, d := range res.Decisions {
			status := "—      "
			switch {
			case d.Matched:
				status = "MATCHED"
			case d.Fired:
				// The match half applied and the mapping still granted nothing.
				// Distinguishing the two is the difference between "fix the
				// pattern" and "fix the tenant expression".
				status = "FIRED  "
			}
			fmt.Printf("  [%d] %s  %s\n", d.Index, status, d.Mapping)
			if len(d.Tenants) > 0 {
				fmt.Printf("        tenants: %s\n", strings.Join(d.Tenants, ", "))
			}
			for _, r := range d.Rejected {
				fmt.Printf("        refused tenant %q: not a declared tenant id, or not a usable one\n", r)
			}
			if d.Error != "" {
				fmt.Printf("        error (granted nothing): %s\n", d.Error)
			}
			if d.Fired && !d.Matched && len(d.Rejected) == 0 && d.Error == "" {
				fmt.Printf("        matched, but the tenant expression resolved to no tenant — " +
					"granted nothing (an empty tenant is never read as platform-wide)\n")
			}
		}
		fmt.Printf("  => platform roles: %s\n", joinOrNone(res.PlatformRoles))
		if len(res.TenantRoles) > 0 {
			tids := make([]string, 0, len(res.TenantRoles))
			for tid := range res.TenantRoles {
				tids = append(tids, tid)
			}
			sort.Strings(tids)
			for _, tid := range tids {
				fmt.Printf("  => tenant %q roles: %s\n", tid, joinOrNone(res.TenantRoles[tid]))
			}
		}
		fmt.Println()
	}
	if !anyMatch {
		fmt.Println("No mapping granted a role. Central rbac.subjects / rbac.groups assignments " +
			"are unioned on top of these at login and are not evaluated here.")
	}
	return nil
}

// cmdRoleMappingReference prints the expression vocabulary.
func cmdRoleMappingReference(args []string) error {
	fs := flag.NewFlagSet("role-mapping reference", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := celexpr.RoleMappingEnv()
	if err != nil {
		return err
	}
	if *asJSON {
		type jsonVar struct {
			Name string `json:"name"`
			Type string `json:"type"`
			Doc  string `json:"doc"`
		}
		vars := make([]jsonVar, 0, len(env.Vars()))
		for _, v := range env.Vars() {
			vars = append(vars, jsonVar{Name: v.Name(), Type: v.Type(), Doc: v.Doc()})
		}
		return emitJSON(struct {
			Variables []jsonVar `json:"variables"`
			Functions []string  `json:"functions"`
			CostLimit uint64    `json:"cost_limit"`
		}{Variables: vars, Functions: roleMappingFunctionHelp, CostLimit: celexpr.DefaultCostLimit})
	}
	fmt.Println("Variables an expression may reference:")
	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	for _, v := range env.Vars() {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", v.Name(), v.Type(), v.Doc())
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Println("\nFunctions and macros:")
	for _, f := range roleMappingFunctionHelp {
		fmt.Printf("  %s\n", f)
	}
	fmt.Printf("\nEvery evaluation is bounded at %d CEL cost units; exceeding that grants nothing.\n",
		celexpr.DefaultCostLimit)
	fmt.Println("A match expression must yield a bool; a tenant expression a string or a list of strings.")
	return nil
}

// roleMappingFunctionHelp is the operator-facing summary of the function
// library in internal/celexpr. It is help text, not the source of truth — the
// environment is (see celexpr.Functions).
var roleMappingFunctionHelp = []string{
	`comparison/logic: == != < <= > >= && || ! in, ternary a ? b : c`,
	`macros: has(claims.x), list.all(x, p), list.exists(x, p), list.exists_one(x, p), list.map(x, f), list.filter(x, p)`,
	`strings: size(s), s.contains(sub), s.startsWith(p), s.endsWith(p), s.matches(re2)`,
	`strings (ext): s.charAt(i), s.indexOf(sub), s.lastIndexOf(sub), s.lowerAscii(), s.upperAscii(),`,
	`              s.replace(old, new), s.split(sep), s.substring(i, j), s.trim(), s.reverse(),`,
	`              list.join(sep), strings.quote(s), s.format([args])`,
	`regex: regex.replace(s, re, repl), regex.extract(s, re) -> optional<string>, regex.extractAll(s, re)`,
	`       optional: opt.orValue(default), opt.hasValue(), opt.value()`,
	`sets: sets.contains(a, b), sets.equivalent(a, b), sets.intersects(a, b)`,
	`lists: list.distinct(), list.flatten(), list.reverse(), list.slice(i, j), list.sort(), list.sortBy(x, k),`,
	`       lists.range(n)`,
}

// parseClaimsArg reads the -claims value: inline JSON, or @FILE.
func parseClaimsArg(arg string) (map[string]interface{}, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return map[string]interface{}{}, nil
	}
	data := []byte(arg)
	if strings.HasPrefix(arg, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(arg, "@"))
		if err != nil {
			return nil, fmt.Errorf("reading -claims file: %w", err)
		}
		data = b
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("parsing -claims as a JSON object: %w", err)
	}
	return claims, nil
}

// allRoleNames lists the recognized roles, for an error message.
func allRoleNames() []string { return roleNames(rbac.AllRoles) }

// roleNames renders roles as sorted strings.
func roleNames(in []rbac.Role) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, string(r))
	}
	sort.Strings(out)
	return out
}

// joinOrNone renders a role list, or "(none)" when empty.
func joinOrNone(in []string) string {
	if len(in) == 0 {
		return "(none)"
	}
	return strings.Join(in, ", ")
}

// orDefault returns s, or def when s is empty.
func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// truncate shortens s for a table cell, marking that it did. The full text is
// always available from -json and from `role-mapping test`, so the table stays
// readable without hiding anything an operator cannot get at.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// oneLine collapses a multi-line expression (YAML block scalars are the natural
// way to write a long one) into a single display line.
func oneLine(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
