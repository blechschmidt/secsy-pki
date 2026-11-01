package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// secsy-ca issuance-policy — the CEL restriction engine's CLI half (Task 223).
//
// The console is where these rules are normally written, but an operator needs
// the same four things from a terminal: see what the policy is, write one, try it
// against a real CSR before switching it on, and read the expression vocabulary.
// The last two are what keep a fail-closed engine safe to operate — a rule that
// is wrong denies every certificate under its scope, so trying it first is not a
// nicety.

func cmdIssuancePolicy(db *database.DB, mgr *ca.Manager, args []string) error {
	if len(args) == 0 {
		issuancePolicyUsage()
		return fmt.Errorf("issuance-policy: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdPolicyList(db, rest)
	case "show":
		return cmdPolicyShow(db, rest)
	case "add":
		return cmdPolicyAdd(db, rest)
	case "update":
		return cmdPolicyUpdate(db, rest)
	case "enable":
		return cmdPolicySetEnabled(db, rest, true)
	case "disable":
		return cmdPolicySetEnabled(db, rest, false)
	case "delete", "remove":
		return cmdPolicyDelete(db, rest)
	case "test", "dry-run":
		return cmdPolicyTest(db, mgr, rest)
	case "reference", "vars":
		return cmdPolicyReference(rest)
	case "help", "-h", "--help":
		issuancePolicyUsage()
		return nil
	default:
		issuancePolicyUsage()
		return fmt.Errorf("issuance-policy: unknown subcommand %q", sub)
	}
}

func issuancePolicyUsage() {
	// os.Stderr.WriteString rather than fmt: the help text quotes a CEL example
	// containing "%d", which a formatting call would read as a directive.
	_, _ = os.Stderr.WriteString(`Usage: secsy-ca issuance-policy <subcommand> [flags]

Operator-written CEL rules that gate what this PKI's keys sign. Each rule is
evaluated before any HSM signature; a rule that refuses a request supplies the
reason the requester is given.

A rule has a kind, which decides what it restricts and which facts it sees:

  -kind certificate   (default) certificate generation: the rule reasons about
                      "request" and runs on every issuance surface
  -kind signing       the other signatures - an OpenSSH certificate, a CMS
                      artifact signature, a raw signature with a named key: the
                      rule reasons about "signing"

  list        List every rule in evaluation order (add -json for the raw rows)
  show        Show one rule, by id or by name
  add         Store a new rule
  update      Replace a rule's fields
  enable      Switch a rule on
  disable     Switch a rule off, keeping its text
  delete      Remove a rule
  test        Dry-run rules against a CSR or a JSON fact set, signing nothing
  reference   Print the variables, functions and worked examples

Writing a rule:

  secsy-ca issuance-policy add -name max-lifetime \
      -expr 'request.validity_days <= 90 ? "" :
             "requested %d days; this profile allows at most 90".format([request.validity_days])'

  secsy-ca issuance-policy add -name no-internal-names -effect deny \
      -expr 'request.dns_names.exists(d, d.endsWith(".internal"))' \
      -message 'internal-only names cannot be certified by this CA'

Trying it before switching it on:

  secsy-ca issuance-policy add -name draft -expr '...' -disabled
  secsy-ca issuance-policy test -rule draft -ca issuing -csr req.pem -validity-days 400

Restricting what a key signs (kind=signing):

  secsy-ca issuance-policy add -kind signing -name no-root-principals -effect deny \
      -expr 'signing.ssh.principals.exists(p, p.lowerAscii() == "root")' \
      -message 'an SSH certificate may not name root'

  secsy-ca issuance-policy add -kind signing -name release-key-is-ci-only \
      -keys release-signing -operations artifact \
      -expr 'has(jwt.repository) && string(jwt.repository) == "example/product"' \
      -message 'the release-signing key is reserved for the product release workflow'

  secsy-ca issuance-policy test -kind signing -all -facts signing-facts.json
  secsy-ca issuance-policy reference -kind signing

An expression may evaluate to a bool (the condition that must hold, or — with
-effect deny — must not), a string (the reason itself; "" means satisfied), or a
list of strings (one reason per offending name).
`)
}

// cmdPolicyList prints every rule in evaluation order.
func cmdPolicyList(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("issuance-policy list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	enabledOnly := fs.Bool("enabled", false, "list only the rules that are switched on")
	kindFlag := fs.String("kind", "", "list only one kind: certificate or signing (default: both)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rules, err := db.ListCELPolicyRules()
	if err != nil {
		return fmt.Errorf("listing issuance policies: %w", err)
	}
	if want := strings.TrimSpace(*kindFlag); want != "" {
		kind, err := parsePolicyKindFlag(want)
		if err != nil {
			return err
		}
		kept := make([]celpolicy.Rule, 0, len(rules))
		for _, r := range rules {
			if r.KindOrDefault() == kind {
				kept = append(kept, r)
			}
		}
		rules = kept
	}
	if *enabledOnly {
		kept := make([]celpolicy.Rule, 0, len(rules))
		for _, r := range rules {
			if r.Enabled {
				kept = append(kept, r)
			}
		}
		rules = kept
	}
	if *asJSON {
		if rules == nil {
			rules = []celpolicy.Rule{}
		}
		return emitJSON(rules)
	}
	if len(rules) == 0 {
		fmt.Println("No issuance-policy rules. Certificate generation is constrained only by the profiles, restriction sets, name constraints and CAA.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PRIORITY\tKIND\tNAME\tSTATE\tEFFECT\tMODE\tSCOPE\tEXPRESSION")
	for _, r := range rules {
		state := "enabled"
		if !r.Enabled {
			state = "disabled"
		}
		if r.FailOpen {
			state += ",fail-open"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Priority, r.KindOrDefault(), r.Name, state, r.EffectOrDefault(), r.ModeOrDefault(),
			policyScope(r), policyExprCell(r.Expression))
	}
	return tw.Flush()
}

// policyScope renders a rule's selectors in one cell.
func policyScope(r celpolicy.Rule) string {
	var parts []string
	if r.TenantID != "" {
		parts = append(parts, "tenant="+r.TenantID)
	}
	if len(r.Profiles) > 0 {
		parts = append(parts, "profiles="+strings.Join(r.Profiles, ","))
	}
	if len(r.CAs) > 0 {
		parts = append(parts, "cas="+strings.Join(r.CAs, ","))
	}
	if len(r.Keys) > 0 {
		parts = append(parts, "keys="+strings.Join(r.Keys, ","))
	}
	if len(r.Operations) > 0 {
		parts = append(parts, "operations="+strings.Join(r.Operations, ","))
	}
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}

// policyExprCell collapses an expression for a table cell, truncating a long one
// so the scope and state columns stay readable.
func policyExprCell(expr string) string {
	expr = oneLine(expr)
	if len(expr) > 70 {
		return expr[:67] + "..."
	}
	return expr
}

// cmdPolicyShow prints one rule in full.
func cmdPolicyShow(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("issuance-policy show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: secsy-ca issuance-policy show <id|name>")
	}
	rule, err := lookupPolicyRule(db, fs.Arg(0))
	if err != nil {
		return err
	}
	if *asJSON {
		return emitJSON(rule)
	}
	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Name:\t%s\n", rule.Name)
	fmt.Fprintf(tw, "ID:\t%s\n", rule.ID)
	fmt.Fprintf(tw, "Kind:\t%s\n", rule.KindOrDefault())
	if rule.Description != "" {
		fmt.Fprintf(tw, "Description:\t%s\n", rule.Description)
	}
	fmt.Fprintf(tw, "Enabled:\t%v\n", rule.Enabled)
	fmt.Fprintf(tw, "Effect:\t%s\n", rule.EffectOrDefault())
	fmt.Fprintf(tw, "Mode:\t%s\n", rule.ModeOrDefault())
	fmt.Fprintf(tw, "Priority:\t%d\n", rule.Priority)
	fmt.Fprintf(tw, "Fail open:\t%v\n", rule.FailOpen)
	fmt.Fprintf(tw, "Scope:\t%s\n", policyScope(*rule))
	if rule.Message != "" {
		fmt.Fprintf(tw, "Message:\t%s\n", rule.Message)
	}
	fmt.Fprintf(tw, "Created:\t%s by %s\n", rule.CreatedAt, orDash(rule.CreatedBy))
	fmt.Fprintf(tw, "Updated:\t%s by %s\n", rule.UpdatedAt, orDash(rule.UpdatedBy))
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Printf("\nExpression:\n%s\n", rule.Expression)
	return nil
}

// policyFlags are the fields add/update share.
type policyFlags struct {
	kind        *string
	name        *string
	description *string
	expr        *string
	exprFile    *string
	message     *string
	effect      *string
	mode        *string
	tenant      *string
	profiles    *string
	cas         *string
	keys        *string
	operations  *string
	priority    *int
	disabled    *bool
	failOpen    *bool
}

func registerPolicyFlags(fs *flag.FlagSet) policyFlags {
	return policyFlags{
		kind:        fs.String("kind", "", "what the rule restricts: certificate (default) or signing"),
		name:        fs.String("name", "", "rule name; it appears in the refusal the requester reads (required)"),
		description: fs.String("description", "", "what the rule is for"),
		expr:        fs.String("expr", "", "the CEL expression (or use -expr-file)"),
		exprFile:    fs.String("expr-file", "", "read the expression from a file ('-' for stdin)"),
		message:     fs.String("message", "", "the reason reported when a boolean rule denies"),
		effect:      fs.String("effect", "", "require (the condition must hold) or deny (it must not); default require"),
		mode:        fs.String("mode", "", "enforce (refuse) or monitor (record only); default enforce"),
		tenant:      fs.String("tenant", "", "restrict the rule to one tenant's CAs"),
		profiles:    fs.String("profiles", "", "comma-separated profile names or globs the rule applies to (default: all)"),
		cas:         fs.String("cas", "", "comma-separated CA ids/labels or globs the rule applies to (default: all)"),
		keys:        fs.String("keys", "", "signing rules only: comma-separated key/signer names or globs the rule applies to (default: all)"),
		operations:  fs.String("operations", "", "signing rules only: comma-separated operations the rule applies to — ssh-certificate, artifact, data (default: all)"),
		priority:    fs.Int("priority", 0, "evaluation order, ascending; it fixes the order the reasons are reported in"),
		disabled:    fs.Bool("disabled", false, "store the rule switched off, so it can be dry-run first"),
		failOpen:    fs.Bool("fail-open", false, "permit issuance when this rule's own evaluation fails (default: fail closed)"),
	}
}

// resolveExpression reads the expression from -expr or -expr-file.
func (p policyFlags) resolveExpression() (string, error) {
	inline := strings.TrimSpace(*p.expr)
	path := strings.TrimSpace(*p.exprFile)
	switch {
	case inline != "" && path != "":
		return "", fmt.Errorf("give either -expr or -expr-file, not both")
	case path != "":
		data, err := readInput(path)
		if err != nil {
			return "", fmt.Errorf("reading the expression: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	default:
		return inline, nil
	}
}

// apply folds the supplied flags onto a rule, leaving a field untouched when its
// flag was not given — so `update -priority 5` does not blank the expression.
func (p policyFlags) apply(fs *flag.FlagSet, rule *celpolicy.Rule) error {
	expr, err := p.resolveExpression()
	if err != nil {
		return err
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	if given["kind"] {
		kind, err := parsePolicyKindFlag(*p.kind)
		if err != nil {
			return err
		}
		// A stored rule's kind is fixed: reinterpreting an expression against the
		// other vocabulary would usually stop it compiling, i.e. turn it into a
		// rule that fails closed and refuses everything in its scope.
		if rule.Kind != "" && rule.Kind != kind {
			return fmt.Errorf("the kind of %q cannot be changed from %s to %s; delete it and create a %s rule",
				rule.Name, rule.Kind, kind, kind)
		}
		rule.Kind = kind
	}
	if given["name"] {
		rule.Name = strings.TrimSpace(*p.name)
	}
	if given["description"] {
		rule.Description = strings.TrimSpace(*p.description)
	}
	if expr != "" {
		rule.Expression = expr
	}
	if given["message"] {
		rule.Message = strings.TrimSpace(*p.message)
	}
	if given["effect"] {
		rule.Effect = celpolicy.Effect(strings.TrimSpace(*p.effect))
	}
	if given["mode"] {
		rule.Mode = celpolicy.Mode(strings.TrimSpace(*p.mode))
	}
	if given["tenant"] {
		rule.TenantID = strings.TrimSpace(*p.tenant)
	}
	if given["profiles"] {
		rule.Profiles = splitSelector(*p.profiles)
	}
	if given["cas"] {
		rule.CAs = splitSelector(*p.cas)
	}
	if given["keys"] {
		rule.Keys = splitSelector(*p.keys)
	}
	if given["operations"] {
		rule.Operations = splitSelector(*p.operations)
	}
	if given["priority"] {
		rule.Priority = *p.priority
	}
	if given["disabled"] {
		rule.Enabled = !*p.disabled
	}
	if given["fail-open"] {
		rule.FailOpen = *p.failOpen
	}
	return nil
}

func splitSelector(s string) []string {
	out := make([]string, 0)
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cmdPolicyAdd stores a new rule. The expression is compiled first, so a rule
// that would deny every certificate under its scope never reaches the store.
func cmdPolicyAdd(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("issuance-policy add", flag.ContinueOnError)
	flags := registerPolicyFlags(fs)
	asJSON := fs.Bool("json", false, "emit the stored rule as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rule := celpolicy.Rule{ID: uuid.New().String(), Enabled: true, CreatedBy: "cli", UpdatedBy: "cli"}
	if err := flags.apply(fs, &rule); err != nil {
		return err
	}
	rule.Kind = rule.Kind.OrDefault()
	if rule.Name == "" {
		fs.Usage()
		return fmt.Errorf("-name is required")
	}
	if rule.Expression == "" {
		fs.Usage()
		return fmt.Errorf("-expr or -expr-file is required")
	}
	if err := rule.Validate(); err != nil {
		return fmt.Errorf("the rule is not usable: %w", err)
	}
	existing, err := db.GetCELPolicyRuleByName(rule.Name)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("an issuance policy named %q already exists (id %s)", rule.Name, existing.ID)
	}
	if err := db.CreateCELPolicyRule(&rule); err != nil {
		return fmt.Errorf("storing the rule: %w", err)
	}
	if *asJSON {
		return emitJSON(rule)
	}
	state := "enabled"
	if !rule.Enabled {
		hint := "secsy-ca issuance-policy test -rule " + rule.Name
		if rule.KindOrDefault() == celpolicy.KindSigning {
			hint += " -kind signing"
		}
		state = "disabled — dry-run it with `" + hint + "`, then enable it"
	}
	fmt.Printf("Stored issuance policy %q (%s), %s.\n", rule.Name, rule.ID, state)
	return nil
}

// cmdPolicyUpdate replaces a rule's fields, leaving the ones not named alone.
func cmdPolicyUpdate(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("issuance-policy update", flag.ContinueOnError)
	flags := registerPolicyFlags(fs)
	ref := fs.String("rule", "", "the rule to update, by id or name (required)")
	asJSON := fs.Bool("json", false, "emit the updated rule as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*ref) == "" {
		fs.Usage()
		return fmt.Errorf("-rule is required")
	}
	rule, err := lookupPolicyRule(db, *ref)
	if err != nil {
		return err
	}
	if err := flags.apply(fs, rule); err != nil {
		return err
	}
	rule.UpdatedBy = "cli"
	if err := rule.Validate(); err != nil {
		return fmt.Errorf("the rule is not usable: %w", err)
	}
	ok, err := db.UpdateCELPolicyRule(rule)
	if err != nil {
		return fmt.Errorf("updating the rule: %w", err)
	}
	if !ok {
		return fmt.Errorf("no issuance policy %q", *ref)
	}
	if *asJSON {
		return emitJSON(rule)
	}
	fmt.Printf("Updated issuance policy %q.\n", rule.Name)
	return nil
}

// cmdPolicySetEnabled switches a rule on or off without touching its text.
func cmdPolicySetEnabled(db *database.DB, args []string, enabled bool) error {
	verb := "enable"
	if !enabled {
		verb = "disable"
	}
	fs := flag.NewFlagSet("issuance-policy "+verb, flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: secsy-ca issuance-policy %s <id|name>", verb)
	}
	rule, err := lookupPolicyRule(db, fs.Arg(0))
	if err != nil {
		return err
	}
	if _, err := db.SetCELPolicyRuleEnabled(rule.ID, enabled, "cli"); err != nil {
		return fmt.Errorf("%sing the rule: %w", verb, err)
	}
	fmt.Printf("Issuance policy %q is now %sd.\n", rule.Name, verb)
	return nil
}

// cmdPolicyDelete removes a rule.
func cmdPolicyDelete(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("issuance-policy delete", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: secsy-ca issuance-policy delete <id|name>")
	}
	rule, err := lookupPolicyRule(db, fs.Arg(0))
	if err != nil {
		return err
	}
	if _, err := db.DeleteCELPolicyRule(rule.ID); err != nil {
		return fmt.Errorf("deleting the rule: %w", err)
	}
	fmt.Printf("Deleted issuance policy %q.\n", rule.Name)
	return nil
}

// cmdPolicyTest dry-runs rules against a request, signing nothing.
//
// The facts come from a real CSR under a real CA and profile (the faithful mode:
// they are derived by the same code the gate uses), optionally overlaid with a
// JSON fact set that supplies what no CSR carries — the token's claims, the
// request URL, the body parameters, the caller's identity.
func cmdPolicyTest(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("issuance-policy test", flag.ContinueOnError)
	expr := fs.String("expr", "", "dry-run this ad-hoc expression instead of a stored rule")
	exprFile := fs.String("expr-file", "", "read the ad-hoc expression from a file ('-' for stdin)")
	effect := fs.String("effect", "", "effect for the ad-hoc expression (require|deny)")
	message := fs.String("message", "", "message for the ad-hoc expression")
	ruleRef := fs.String("rule", "", "dry-run one stored rule, by id or name (evaluated even when it is disabled)")
	allRules := fs.Bool("all", false, "dry-run every stored rule, including the disabled ones")
	caRef := fs.String("ca", "", "issuing CA id or label the request would go to")
	profile := fs.String("profile", "", "issuance profile (empty = the default profile)")
	csrPath := fs.String("csr", "", "PEM CSR to derive the request facts from ('-' for stdin)")
	validityDays := fs.Int("validity-days", 0, "requested validity in days (0 = the profile default)")
	factsPath := fs.String("facts", "", "JSON fact set to use or overlay: {\"request\":{…},\"jwt\":{…},\"url\":{…},\"body\":{…},\"principal\":{…}} — for -kind signing, {\"signing\":{…},…}")
	kindFlag := fs.String("kind", "", "which rules to dry-run: certificate (default) or signing")
	asJSON := fs.Bool("json", false, "emit the decision and the facts as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kind, err := parsePolicyKindFlag(*kindFlag)
	if err != nil {
		return err
	}

	rules, err := policyTestRuleSet(db, kind, *expr, *exprFile, *effect, *message, *ruleRef, *allRules)
	if err != nil {
		return err
	}
	if kind == celpolicy.KindSigning {
		return signingPolicyTest(rules, *csrPath, *factsPath, *asJSON)
	}
	in, err := policyTestInput(db, mgr, *caRef, *profile, *csrPath, *validityDays, *factsPath)
	if err != nil {
		return err
	}

	decision := celpolicy.Shared().Evaluate(rules, in)
	if *asJSON {
		return emitJSON(struct {
			Decision celpolicy.Decision `json:"decision"`
			Rules    []string           `json:"rules"`
			Input    celpolicy.Input    `json:"input"`
		}{Decision: decision, Rules: ruleNames(rules), Input: in})
	}
	printPolicyDecision(decision, rules, in)
	if !decision.Allowed {
		// A non-zero exit lets a pipeline gate on the verdict.
		return fmt.Errorf("the request would be refused")
	}
	return nil
}

// policyTestRuleSet resolves which rules of the given kind a dry-run evaluates.
func policyTestRuleSet(db *database.DB, kind celpolicy.Kind, expr, exprFile, effect, message, ruleRef string, all bool) ([]celpolicy.Rule, error) {
	inline := strings.TrimSpace(expr)
	if path := strings.TrimSpace(exprFile); path != "" {
		if inline != "" {
			return nil, fmt.Errorf("give either -expr or -expr-file, not both")
		}
		data, err := readInput(path)
		if err != nil {
			return nil, fmt.Errorf("reading the expression: %w", err)
		}
		inline = strings.TrimSpace(string(data))
	}
	switch {
	case inline != "":
		rule := celpolicy.Rule{
			Kind: kind.OrDefault(),
			Name: "ad-hoc", Expression: inline, Enabled: true,
			Effect: celpolicy.Effect(effect), Mode: celpolicy.Mode(""), Message: message,
		}
		if err := rule.Validate(); err != nil {
			return nil, err
		}
		return []celpolicy.Rule{rule}, nil
	case strings.TrimSpace(ruleRef) != "":
		rule, err := lookupPolicyRule(db, ruleRef)
		if err != nil {
			return nil, err
		}
		if rule.KindOrDefault() != kind.OrDefault() {
			return nil, fmt.Errorf("%q is a %s rule; dry-run it with -kind %s",
				rule.Name, rule.KindOrDefault(), rule.KindOrDefault())
		}
		// Trying a rule before switching it on is the point of the subcommand.
		rule.Enabled = true
		return []celpolicy.Rule{*rule}, nil
	default:
		rules, err := db.ListCELPolicyRules()
		if err != nil {
			return nil, fmt.Errorf("listing issuance policies: %w", err)
		}
		kept := make([]celpolicy.Rule, 0, len(rules))
		for _, r := range rules {
			// Only this kind: a certificate rule evaluated against signing facts
			// would not compile and would report every rule as broken.
			if r.KindOrDefault() != kind.OrDefault() {
				continue
			}
			if all {
				r.Enabled = true
			}
			if r.Enabled {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			return nil, fmt.Errorf("there are no %s rules to dry-run; give -expr, -rule, or -all", kind.OrDefault())
		}
		return kept, nil
	}
}

// policyTestInput assembles the fact set: derived from the CSR/CA/profile when
// those are given, overlaid with the JSON fact file.
func policyTestInput(db *database.DB, mgr *ca.Manager, caRef, profile, csrPath string, validityDays int, factsPath string) (celpolicy.Input, error) {
	var in celpolicy.Input
	if path := strings.TrimSpace(factsPath); path != "" {
		data, err := readInput(path)
		if err != nil {
			return in, fmt.Errorf("reading the fact set: %w", err)
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return in, fmt.Errorf("parsing the fact set: %w", err)
		}
	}
	if path := strings.TrimSpace(csrPath); path != "" {
		if strings.TrimSpace(caRef) == "" {
			return in, fmt.Errorf("-ca is required with -csr: the facts include the issuing authority and the profile's resolved usages")
		}
		csrPEM, err := readInput(path)
		if err != nil {
			return in, fmt.Errorf("reading the CSR: %w", err)
		}
		caID, err := resolveCA(db, caRef)
		if err != nil {
			return in, err
		}
		req, err := mgr.PolicyFactsFromCSR(ca.PreviewSpec{
			CAID:        caID,
			CSRPEM:      csrPEM,
			Profile:     profile,
			Validity:    time.Duration(validityDays) * 24 * time.Hour,
			RequestedBy: in.Principal.Subject,
		})
		if err != nil {
			return in, err
		}
		// The CSR-derived certificate facts win; the fact file's HTTP/identity
		// facts are kept, because no CSR carries them.
		in.Request = req
	}
	if in.Request.Source == "" {
		in.Request.Source = celpolicy.SourcePreview
	}
	if in.Request.Operation == "" {
		in.Request.Operation = celpolicy.OpPreview
	}
	if in.Request.MaxPathLen == 0 && !in.Request.IsCA {
		in.Request.MaxPathLen = -1
	}
	return in, nil
}

// signingPolicyTest dry-runs signing rules against a JSON fact set. There is
// nothing to seed the facts from — a signing request has no CSR whose
// resolution could be replayed — so they come from -facts, which is also what
// makes the subcommand scriptable: a pipeline can assert that its own request
// shape is still permitted.
func signingPolicyTest(rules []celpolicy.Rule, csrPath, factsPath string, asJSON bool) error {
	if strings.TrimSpace(csrPath) != "" {
		return fmt.Errorf("-csr describes a certificate request; a signing dry-run takes its facts from -facts")
	}
	var in celpolicy.SigningInput
	if path := strings.TrimSpace(factsPath); path != "" {
		data, err := readInput(path)
		if err != nil {
			return fmt.Errorf("reading the fact set: %w", err)
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return fmt.Errorf("parsing the fact set: %w", err)
		}
	}
	if in.Signing.Source == "" {
		in.Signing.Source = celpolicy.SourcePreview
	}
	decision := celpolicy.Shared().EvaluateSigning(rules, in)
	if asJSON {
		return emitJSON(struct {
			Decision celpolicy.Decision     `json:"decision"`
			Rules    []string               `json:"rules"`
			Input    celpolicy.SigningInput `json:"input"`
		}{Decision: decision, Rules: ruleNames(rules), Input: in})
	}
	printSigningDecision(decision, rules, in)
	if !decision.Allowed {
		return fmt.Errorf("the signature would be refused")
	}
	return nil
}

// printSigningDecision renders a signing dry-run verdict for a terminal.
func printSigningDecision(d celpolicy.Decision, rules []celpolicy.Rule, in celpolicy.SigningInput) {
	verdict := "WOULD SIGN"
	if !d.Allowed {
		verdict = "WOULD BE REFUSED"
	}
	fmt.Printf("%s — %d rule(s) evaluated, %d skipped (out of scope or disabled)\n",
		verdict, d.Evaluated, d.Skipped)
	fmt.Printf("Rules considered: %s\n", strings.Join(ruleNames(rules), ", "))
	printPolicyViolations(d)
	fmt.Println("\nFacts the rules saw:")
	sig := in.Signing
	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  operation / source\t%s / %s\n", orDash(sig.Operation), orDash(sig.Source))
	fmt.Fprintf(tw, "  key\t%s (%s, provider %s)\n", orDash(sig.Key.Name), orDash(sig.Key.Algorithm), orDash(sig.Key.Provider))
	fmt.Fprintf(tw, "  tenant\t%s\n", orDash(sig.Tenant))
	fmt.Fprintf(tw, "  requested by\t%s\n", orDash(sig.RequestedBy))
	fmt.Fprintf(tw, "  payload\t%d byte(s), %s%s\n", sig.Payload.Size, orDash(sig.Payload.DigestAlgorithm),
		map[bool]string{true: ", caller-supplied digest", false: ""}[sig.Payload.Prehashed])
	if sig.SSH.Present {
		fmt.Fprintf(tw, "  ssh\t%s cert for %s (key id %s)\n", orDash(sig.SSH.CertType),
			orDash(strings.Join(sig.SSH.Principals, ", ")), orDash(sig.SSH.KeyID))
		fmt.Fprintf(tw, "  ssh validity\t%s\n", sig.SSH.Validity)
		fmt.Fprintf(tw, "  ssh options\t%s\n", orDash(strings.Join(sig.SSH.CriticalOptions, ", ")))
	}
	if sig.Artifact.Present {
		fmt.Fprintf(tw, "  artifact\t%s (signer %s, level %s, timestamped %v)\n",
			orDash(sig.Artifact.Name), orDash(sig.Artifact.Signer), orDash(sig.Artifact.Level), sig.Artifact.Timestamped)
	}
	if sig.Data.Present {
		fmt.Fprintf(tw, "  data\t%s with %s (%s)\n", orDash(sig.Data.Key), orDash(sig.Data.Algorithm), orDash(sig.Data.Hash))
	}
	if sig.JWTSVID.Present {
		fmt.Fprintf(tw, "  jwt-svid\t%s for %s\n", orDash(sig.JWTSVID.SPIFFEID), orDash(strings.Join(sig.JWTSVID.Audience, ", ")))
		fmt.Fprintf(tw, "  jwt-svid ttl\t%s (%s)\n", sig.JWTSVID.TTL, orDash(sig.JWTSVID.Algorithm))
	}
	fmt.Fprintf(tw, "  jwt claims\t%s\n", orDash(strings.Join(policyFactKeys(in.JWT), ", ")))
	fmt.Fprintf(tw, "  body parameters\t%s\n", orDash(strings.Join(policyFactKeys(in.Body), ", ")))
	fmt.Fprintf(tw, "  url\t%s %s\n", orDash(in.URL.Method), orDash(in.URL.Path))
	fmt.Fprintf(tw, "  principal\t%s (roles: %s)\n", orDash(in.Principal.Subject), orDash(strings.Join(in.Principal.Roles, ", ")))
	_ = tw.Flush()
}

// printPolicyViolations lists a decision's reasons, shared by both dry-runs.
func printPolicyViolations(d celpolicy.Decision) {
	if len(d.Violations) == 0 {
		fmt.Println("No violations.")
		return
	}
	fmt.Println("\nReasons:")
	for _, v := range d.Violations {
		tag := ""
		if v.Mode == celpolicy.ModeMonitor {
			tag = " [monitor: would not block]"
		}
		fmt.Printf("  - %s%s: %s\n", v.Rule, tag, v.Message)
		if v.Error != "" {
			fmt.Printf("      rule error: %s\n", v.Error)
		}
	}
}

// printPolicyDecision renders a dry-run verdict for a terminal.
func printPolicyDecision(d celpolicy.Decision, rules []celpolicy.Rule, in celpolicy.Input) {
	verdict := "WOULD ISSUE"
	if !d.Allowed {
		verdict = "WOULD BE REFUSED"
	}
	fmt.Printf("%s — %d rule(s) evaluated, %d skipped (out of scope or disabled)\n",
		verdict, d.Evaluated, d.Skipped)
	fmt.Printf("Rules considered: %s\n", strings.Join(ruleNames(rules), ", "))
	printPolicyViolations(d)
	fmt.Println("\nFacts the rules saw:")
	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  source / operation\t%s / %s\n", in.Request.Source, in.Request.Operation)
	fmt.Fprintf(tw, "  profile\t%s\n", orDash(in.Request.Profile))
	fmt.Fprintf(tw, "  issuing CA\t%s\n", orDash(in.Request.CA.Label))
	fmt.Fprintf(tw, "  subject CN\t%s\n", orDash(in.Request.Subject.CommonName))
	fmt.Fprintf(tw, "  DNS names\t%s\n", orDash(strings.Join(in.Request.DNSNames, ", ")))
	fmt.Fprintf(tw, "  IP addresses\t%s\n", orDash(strings.Join(in.Request.IPAddresses, ", ")))
	fmt.Fprintf(tw, "  e-mail SANs\t%s\n", orDash(strings.Join(in.Request.EmailAddresses, ", ")))
	fmt.Fprintf(tw, "  URI SANs\t%s\n", orDash(strings.Join(in.Request.URIs, ", ")))
	fmt.Fprintf(tw, "  validity\t%s (%d days)\n", in.Request.Validity, in.Request.ValidityDays)
	fmt.Fprintf(tw, "  key\t%s %d %s\n", orDash(in.Request.Key.Algorithm), in.Request.Key.Size, in.Request.Key.Curve)
	fmt.Fprintf(tw, "  wildcard\t%v\n", in.Request.Wildcard)
	fmt.Fprintf(tw, "  jwt claims\t%s\n", orDash(strings.Join(policyFactKeys(in.JWT), ", ")))
	fmt.Fprintf(tw, "  body parameters\t%s\n", orDash(strings.Join(policyFactKeys(in.Body), ", ")))
	fmt.Fprintf(tw, "  url\t%s %s\n", orDash(in.URL.Method), orDash(in.URL.Path))
	fmt.Fprintf(tw, "  principal\t%s (roles: %s)\n", orDash(in.Principal.Subject), orDash(strings.Join(in.Principal.Roles, ", ")))
	_ = tw.Flush()
}

func ruleNames(rules []celpolicy.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Name)
	}
	return out
}

// policyFactKeys names the keys of a fact map, sorted, for the dry-run summary.
func policyFactKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// cmdPolicyReference prints the expression vocabulary: the same value the
// console renders, derived from the live environment rather than from a
// documentation page that could drift from it.
func cmdPolicyReference(args []string) error {
	fs := flag.NewFlagSet("issuance-policy reference", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	withExamples := fs.Bool("examples", true, "include the worked examples")
	kindFlag := fs.String("kind", "", "which vocabulary to print: certificate (default) or signing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kind, err := parsePolicyKindFlag(*kindFlag)
	if err != nil {
		return err
	}
	ref, err := celpolicy.BuildReferenceFor(kind)
	if err != nil {
		return err
	}
	if *asJSON {
		return emitJSON(ref)
	}
	fmt.Printf("Vocabulary for a %s rule.\n", ref.Kind)
	if len(ref.Operations) > 0 {
		fmt.Printf("Signing operations a rule may select on (-operations) and compare signing.operation against: %s\n",
			strings.Join(ref.Operations, ", "))
	}
	fmt.Println("\nVariables an expression may reference:")
	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	for _, v := range ref.Variables {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", v.Name, v.Type, v.Doc)
		for _, f := range v.Fields {
			fmt.Fprintf(tw, "    .%s\t%s\t\n", f.Name, f.Type)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Println("\nA rule's expression may evaluate to:")
	for _, r := range ref.Results {
		fmt.Printf("  %s\n", r)
	}
	fmt.Println("\nFunctions and macros:")
	for _, g := range ref.Functions {
		fmt.Printf("  %s:\n", g.Name)
		for _, f := range g.Functions {
			fmt.Printf("    %s\n", f)
		}
	}
	fmt.Printf("\nEvery evaluation is bounded at %d CEL cost units; exceeding that refuses the request.\n", ref.CostLimit)
	if *withExamples {
		fmt.Println("\nWorked examples:")
		for _, ex := range ref.Examples {
			fmt.Printf("\n  %s\n    %s\n", ex.Title, ex.Description)
			if ex.Effect != "" {
				fmt.Printf("    effect: %s\n", ex.Effect)
			}
			if ex.Message != "" {
				fmt.Printf("    message: %s\n", ex.Message)
			}
			fmt.Printf("    %s\n", strings.Join(strings.Fields(ex.Expression), " "))
		}
	}
	return nil
}

// parsePolicyKindFlag resolves a -kind value, defaulting to the certificate
// rules. An unknown value is an error rather than a silent default: an operator
// who typed -kind sign would otherwise store a certificate rule whose
// expression they wrote about signing.
func parsePolicyKindFlag(s string) (celpolicy.Kind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return celpolicy.KindCertificate, nil
	case string(celpolicy.KindCertificate), "cert":
		return celpolicy.KindCertificate, nil
	case string(celpolicy.KindSigning), "sign":
		return celpolicy.KindSigning, nil
	}
	return "", fmt.Errorf("-kind %q must be %q or %q", s, celpolicy.KindCertificate, celpolicy.KindSigning)
}

// lookupPolicyRule resolves a rule by id, falling back to its name — the handle
// a refusal message gives the requester.
func lookupPolicyRule(db *database.DB, ref string) (*celpolicy.Rule, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("an issuance-policy id or name is required")
	}
	rule, err := db.GetCELPolicyRule(ref)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		if rule, err = db.GetCELPolicyRuleByName(ref); err != nil {
			return nil, err
		}
	}
	if rule == nil {
		return nil, fmt.Errorf("no issuance policy %q", ref)
	}
	return rule, nil
}
