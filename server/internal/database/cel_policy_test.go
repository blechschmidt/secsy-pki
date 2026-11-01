//go:build sqlite

package database

import (
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
)

// Tests for the CEL issuance-restriction rule store (Task 223). The store's job
// is narrow but load-bearing: the issuance gate reads it on every certificate,
// so a row that round-trips wrong is a policy that silently does not apply —
// which for a restriction engine means a certificate that should not exist.

func policyDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mkRule(id, name, expr string) *celpolicy.Rule {
	return &celpolicy.Rule{ID: id, Name: name, Expression: expr, Enabled: true}
}

func TestCELPolicyRoundTrip(t *testing.T) {
	db := policyDB(t)
	want := &celpolicy.Rule{
		ID:          "r-1",
		TenantID:    "acme",
		Name:        "dns-suffix",
		Description: "names must sit under example.com",
		Expression:  `request.dns_names.all(d, d.endsWith(".example.com"))`,
		Message:     "that name is outside example.com",
		Effect:      celpolicy.EffectRequire,
		Mode:        celpolicy.ModeMonitor,
		Profiles:    []string{"server", "server-client"},
		CAs:         []string{"issuing", "staging-*"},
		Priority:    25,
		Enabled:     true,
		FailOpen:    true,
		CreatedBy:   "alice",
		UpdatedBy:   "alice",
	}
	if err := db.CreateCELPolicyRule(want); err != nil {
		t.Fatalf("CreateCELPolicyRule: %v", err)
	}
	if want.CreatedAt == "" || want.UpdatedAt == "" {
		t.Error("the create did not stamp the timestamps on the supplied rule")
	}

	got, err := db.GetCELPolicyRule("r-1")
	if err != nil || got == nil {
		t.Fatalf("GetCELPolicyRule: %v %v", got, err)
	}
	if got.TenantID != want.TenantID || got.Name != want.Name || got.Description != want.Description ||
		got.Expression != want.Expression || got.Message != want.Message {
		t.Errorf("text fields differ:\n got %+v\nwant %+v", got, want)
	}
	if got.Effect != celpolicy.EffectRequire || got.Mode != celpolicy.ModeMonitor {
		t.Errorf("effect/mode = %q/%q", got.Effect, got.Mode)
	}
	if got.Priority != 25 || !got.Enabled || !got.FailOpen {
		t.Errorf("flags lost: priority=%d enabled=%v fail_open=%v", got.Priority, got.Enabled, got.FailOpen)
	}
	if len(got.Profiles) != 2 || got.Profiles[0] != "server" || got.Profiles[1] != "server-client" {
		t.Errorf("profiles = %v", got.Profiles)
	}
	if len(got.CAs) != 2 || got.CAs[1] != "staging-*" {
		t.Errorf("cas = %v; a glob selector must survive the round trip verbatim", got.CAs)
	}
	if got.CreatedBy != "alice" || got.CreatedAt == "" {
		t.Errorf("provenance lost: %+v", got)
	}
}

// TestCELPolicyStoreRejectsUncompilableRules is the store's own fail-closed
// guard: a row whose expression does not compile would deny every certificate
// under its scope and could not be fixed by editing the text in place.
func TestCELPolicyStoreRejectsUncompilableRules(t *testing.T) {
	db := policyDB(t)
	bad := mkRule("r-bad", "broken", `request.dsn_names.size() == 0`)
	if err := db.CreateCELPolicyRule(bad); err == nil {
		t.Fatal("the store accepted an expression that does not compile")
	}
	if n, _, err := db.CountCELPolicyRules(); err != nil || n != 0 {
		t.Errorf("a rejected rule left a row behind: %d %v", n, err)
	}
	// The same guard applies to an update.
	good := mkRule("r-ok", "fine", `request.validity_days <= 90`)
	if err := db.CreateCELPolicyRule(good); err != nil {
		t.Fatal(err)
	}
	good.Expression = `request.nope`
	if _, err := db.UpdateCELPolicyRule(good); err == nil {
		t.Fatal("the store accepted an update to an expression that does not compile")
	}
	reread, _ := db.GetCELPolicyRule("r-ok")
	if reread.Expression != `request.validity_days <= 90` {
		t.Errorf("a rejected update changed the stored expression to %q", reread.Expression)
	}
	// And to a rule whose metadata is malformed.
	if err := db.CreateCELPolicyRule(&celpolicy.Rule{ID: "x", Name: "has space", Expression: `true`}); err == nil {
		t.Error("the store accepted a name with whitespace in it")
	}
}

func TestCELPolicyUpdatePreservesProvenance(t *testing.T) {
	db := policyDB(t)
	r := mkRule("r-1", "rule-one", `true`)
	r.CreatedBy = "alice"
	if err := db.CreateCELPolicyRule(r); err != nil {
		t.Fatal(err)
	}
	created := r.CreatedAt

	edit := mkRule("r-1", "rule-one", `request.validity_days <= 30`)
	edit.CreatedBy = "alice"
	edit.CreatedAt = created
	edit.UpdatedBy = "bob"
	ok, err := db.UpdateCELPolicyRule(edit)
	if err != nil || !ok {
		t.Fatalf("UpdateCELPolicyRule: %v %v", ok, err)
	}
	got, _ := db.GetCELPolicyRule("r-1")
	if got.Expression != `request.validity_days <= 30` {
		t.Errorf("expression = %q", got.Expression)
	}
	if got.CreatedBy != "alice" || got.UpdatedBy != "bob" {
		t.Errorf("created_by/updated_by = %q/%q; the first author must survive an edit", got.CreatedBy, got.UpdatedBy)
	}
	if got.CreatedAt != created {
		t.Errorf("created_at changed on update: %q -> %q", created, got.CreatedAt)
	}

	// Updating a row that is not there is reported, not invented.
	missing := mkRule("nope", "nope", `true`)
	if ok, err := db.UpdateCELPolicyRule(missing); err != nil || ok {
		t.Errorf("UpdateCELPolicyRule on a missing row = %v %v", ok, err)
	}
}

func TestCELPolicyEnableToggleTouchesNothingElse(t *testing.T) {
	db := policyDB(t)
	r := mkRule("r-1", "rule-one", `request.validity_days <= 30`)
	r.Message = "too long"
	if err := db.CreateCELPolicyRule(r); err != nil {
		t.Fatal(err)
	}
	ok, err := db.SetCELPolicyRuleEnabled("r-1", false, "bob")
	if err != nil || !ok {
		t.Fatalf("SetCELPolicyRuleEnabled: %v %v", ok, err)
	}
	got, _ := db.GetCELPolicyRule("r-1")
	if got.Enabled {
		t.Error("the rule is still enabled")
	}
	if got.Expression != `request.validity_days <= 30` || got.Message != "too long" {
		t.Errorf("the toggle rewrote the rule: %+v", got)
	}
	if got.UpdatedBy != "bob" {
		t.Errorf("updated_by = %q", got.UpdatedBy)
	}
	if ok, _ := db.SetCELPolicyRuleEnabled("missing", true, "bob"); ok {
		t.Error("toggling a missing rule reported success")
	}
}

func TestCELPolicyListIsInEvaluationOrder(t *testing.T) {
	db := policyDB(t)
	for _, r := range []*celpolicy.Rule{
		{ID: "a", Name: "zebra", Expression: `true`, Priority: 10, Enabled: true},
		{ID: "b", Name: "alpha", Expression: `true`, Priority: 10, Enabled: true},
		{ID: "c", Name: "first", Expression: `true`, Priority: 1, Enabled: false},
		{ID: "d", Name: "last", Expression: `true`, Priority: 99, Enabled: true},
	} {
		if err := db.CreateCELPolicyRule(r); err != nil {
			t.Fatal(err)
		}
	}
	rules, err := db.ListCELPolicyRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4 (including the disabled one)", len(rules))
	}
	want := []string{"first", "alpha", "zebra", "last"}
	for i, name := range want {
		if rules[i].Name != name {
			t.Fatalf("order = %v, want %v", names(rules), want)
		}
	}
}

func TestActiveCELPolicyRulesFiltersEnabledAndTenant(t *testing.T) {
	db := policyDB(t)
	for _, r := range []*celpolicy.Rule{
		{ID: "global", Name: "global", Expression: `true`, Enabled: true},
		{ID: "acme", Name: "acme-only", Expression: `true`, Enabled: true, TenantID: "acme"},
		{ID: "other", Name: "other-only", Expression: `true`, Enabled: true, TenantID: "other"},
		{ID: "off", Name: "disabled", Expression: `true`, Enabled: false},
		{ID: "offacme", Name: "disabled-acme", Expression: `true`, Enabled: false, TenantID: "acme"},
	} {
		if err := db.CreateCELPolicyRule(r); err != nil {
			t.Fatal(err)
		}
	}

	got, err := db.ActiveCELPolicyRules("acme")
	if err != nil {
		t.Fatal(err)
	}
	if n := names(got); len(n) != 2 || !contains(n, "global") || !contains(n, "acme-only") {
		t.Fatalf("ActiveCELPolicyRules(acme) = %v, want the global and the acme rule", n)
	}

	// A platform-level CA (no tenant) sees only the deployment-wide rules.
	got, err = db.ActiveCELPolicyRules("")
	if err != nil {
		t.Fatal(err)
	}
	if n := names(got); len(n) != 1 || n[0] != "global" {
		t.Fatalf("ActiveCELPolicyRules(\"\") = %v, want only the global rule", n)
	}

	total, enabled, err := db.CountCELPolicyRules()
	if err != nil || total != 5 || enabled != 3 {
		t.Errorf("CountCELPolicyRules = %d/%d (want 5/3): %v", total, enabled, err)
	}
}

func TestGetCELPolicyRuleByName(t *testing.T) {
	db := policyDB(t)
	if err := db.CreateCELPolicyRule(mkRule("r-1", "Lifetime-Cap", `true`)); err != nil {
		t.Fatal(err)
	}
	// The name is what a refusal message carries, so the lookup is
	// case-insensitive: an operator retypes it from an error, not from the row.
	for _, ref := range []string{"Lifetime-Cap", "lifetime-cap", "LIFETIME-CAP"} {
		got, err := db.GetCELPolicyRuleByName(ref)
		if err != nil || got == nil || got.ID != "r-1" {
			t.Errorf("GetCELPolicyRuleByName(%q) = %v, %v", ref, got, err)
		}
	}
	got, err := db.GetCELPolicyRuleByName("nope")
	if err != nil || got != nil {
		t.Errorf("a missing name resolved to %v, %v", got, err)
	}
}

func TestDeleteCELPolicyRule(t *testing.T) {
	db := policyDB(t)
	if err := db.CreateCELPolicyRule(mkRule("r-1", "rule-one", `true`)); err != nil {
		t.Fatal(err)
	}
	ok, err := db.DeleteCELPolicyRule("r-1")
	if err != nil || !ok {
		t.Fatalf("DeleteCELPolicyRule: %v %v", ok, err)
	}
	if got, _ := db.GetCELPolicyRule("r-1"); got != nil {
		t.Error("the row survived the delete")
	}
	if ok, _ := db.DeleteCELPolicyRule("r-1"); ok {
		t.Error("deleting a missing row reported success")
	}
}

func TestCELPolicyMissingRuleIsNotAnError(t *testing.T) {
	db := policyDB(t)
	got, err := db.GetCELPolicyRule("nope")
	if err != nil || got != nil {
		t.Errorf("GetCELPolicyRule(missing) = %v, %v", got, err)
	}
}

// TestCELPolicyNamesAreUnique relies on the unique index: two rules sharing a
// name would make a refusal message ambiguous.
func TestCELPolicyNamesAreUnique(t *testing.T) {
	db := policyDB(t)
	if err := db.CreateCELPolicyRule(mkRule("r-1", "dup", `true`)); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateCELPolicyRule(mkRule("r-2", "dup", `true`)); err == nil {
		t.Fatal("a second rule with the same name was stored")
	}
}

func TestCELPolicySelectorDecoding(t *testing.T) {
	cases := map[string][]string{
		``:                 nil,
		`null`:             nil,
		`[]`:               nil,
		`["a","b"]`:        {"a", "b"},
		`[" a ", "", "b"]`: {"a", "b"},
		`a,b`:              {"a", "b"}, // a hand-written column
		`  a , , b `:       {"a", "b"},
		`not json at [all`: {"not json at [all"},
	}
	for in, want := range cases {
		got := decodeSelector(in)
		if len(got) != len(want) {
			t.Errorf("decodeSelector(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("decodeSelector(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}

// TestCELPolicyEmptySelectorsStoreAsEmptyArrays keeps the column parseable
// rather than NULL, which is what lets decodeSelector stay strict.
func TestCELPolicyEmptySelectorsStoreAsEmptyArrays(t *testing.T) {
	db := policyDB(t)
	if err := db.CreateCELPolicyRule(mkRule("r-1", "rule-one", `true`)); err != nil {
		t.Fatal(err)
	}
	var profiles, cas string
	err := db.queryRow(`SELECT profiles, cas FROM cel_policy_rules WHERE id = ?`, "r-1").Scan(&profiles, &cas)
	if err != nil {
		t.Fatal(err)
	}
	if profiles != "[]" || cas != "[]" {
		t.Errorf("profiles/cas stored as %q/%q, want empty JSON arrays", profiles, cas)
	}
}

// TestCELPolicyRulesAreMigrated guards the store migration: a deployment that
// moves SQLite -> PostgreSQL must carry its restriction rules with it, or the
// migrated store would issue certificates the source store refused.
func TestCELPolicyRulesAreMigrated(t *testing.T) {
	found := false
	for _, table := range migrationTables {
		if table == "cel_policy_rules" {
			found = true
			break
		}
	}
	if !found {
		t.Error("cel_policy_rules is not in the store-migration table list")
	}
}

func names(rules []celpolicy.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Name)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// --- signing rules (Task 224) ---------------------------------------------
//
// One table holds both kinds, so the discriminator is load-bearing twice over:
// a signing rule read as a certificate rule would be evaluated against the
// wrong vocabulary (fail-closed: it would refuse every certificate under its
// scope), and a certificate rule read as a signing rule would refuse every
// signature. These tests pin the round-trip and both reads.

func mkSigningRule(id, name, expr string) *celpolicy.Rule {
	return &celpolicy.Rule{
		ID: id, Kind: celpolicy.KindSigning, Name: name, Expression: expr, Enabled: true,
	}
}

func TestSigningPolicyRoundTrip(t *testing.T) {
	db := policyDB(t)
	want := &celpolicy.Rule{
		ID:          "s-1",
		Kind:        celpolicy.KindSigning,
		TenantID:    "acme",
		Name:        "no-root-principals",
		Description: "an SSH certificate may not name root",
		Expression:  `signing.ssh.principals.exists(p, p == "root")`,
		Message:     "use a named account and sudo",
		Effect:      celpolicy.EffectDeny,
		Mode:        celpolicy.ModeEnforce,
		Profiles:    []string{"ssh-user-*"},
		CAs:         []string{"ssh-user-ca"},
		Keys:        []string{"ssh-user-ca", "ssh-*"},
		Operations:  []string{"ssh-certificate"},
		Priority:    10,
		Enabled:     true,
		FailOpen:    true,
		CreatedBy:   "ops@example.com",
		UpdatedBy:   "ops@example.com",
	}
	if err := db.CreateCELPolicyRule(want); err != nil {
		t.Fatalf("CreateCELPolicyRule: %v", err)
	}
	got, err := db.GetCELPolicyRule("s-1")
	if err != nil || got == nil {
		t.Fatalf("GetCELPolicyRule: %v (got %v)", err, got)
	}
	if got.Kind != celpolicy.KindSigning {
		t.Errorf("kind = %q, want signing", got.Kind)
	}
	if strings.Join(got.Keys, ",") != "ssh-user-ca,ssh-*" {
		t.Errorf("keys = %v", got.Keys)
	}
	if strings.Join(got.Operations, ",") != "ssh-certificate" {
		t.Errorf("operations = %v", got.Operations)
	}
	if got.Effect != celpolicy.EffectDeny || !got.FailOpen || got.Priority != 10 {
		t.Errorf("round-trip lost a field: %+v", got)
	}
	if got.Expression != want.Expression || got.Message != want.Message {
		t.Errorf("expression/message = %q / %q", got.Expression, got.Message)
	}
}

func TestActiveRulesAreSplitByKind(t *testing.T) {
	db := policyDB(t)
	if err := db.CreateCELPolicyRule(mkRule("c-1", "cert-rule", `request.dns_names.size() <= 2`)); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateCELPolicyRule(mkSigningRule("s-1", "sign-rule", `signing.key.name != "x"`)); err != nil {
		t.Fatal(err)
	}
	// A disabled signing rule must not reach the gate.
	off := mkSigningRule("s-2", "sign-off", `false`)
	off.Enabled = false
	if err := db.CreateCELPolicyRule(off); err != nil {
		t.Fatal(err)
	}

	certRules, err := db.ActiveCELPolicyRules("acme")
	if err != nil {
		t.Fatalf("ActiveCELPolicyRules: %v", err)
	}
	if got := names(certRules); len(got) != 1 || got[0] != "cert-rule" {
		t.Errorf("the issuance gate sees %v, want [cert-rule]", got)
	}

	signRules, err := db.ActiveSigningPolicyRules("acme")
	if err != nil {
		t.Fatalf("ActiveSigningPolicyRules: %v", err)
	}
	if got := names(signRules); len(got) != 1 || got[0] != "sign-rule" {
		t.Errorf("the signing gate sees %v, want [sign-rule]", got)
	}

	// Both kinds are listed together: one table is what an operator administers.
	all, err := db.ListCELPolicyRules()
	if err != nil {
		t.Fatalf("ListCELPolicyRules: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("the admin listing has %d rules, want 3", len(all))
	}
}

func TestSigningPolicyTenantScope(t *testing.T) {
	db := policyDB(t)
	mine := mkSigningRule("s-1", "acme-only", `signing.key.name != "x"`)
	mine.TenantID = "acme"
	theirs := mkSigningRule("s-2", "other-only", `signing.key.name != "y"`)
	theirs.TenantID = "other"
	global := mkSigningRule("s-3", "everyone", `signing.key.name != "z"`)
	for _, r := range []*celpolicy.Rule{mine, theirs, global} {
		if err := db.CreateCELPolicyRule(r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.ActiveSigningPolicyRules("acme")
	if err != nil {
		t.Fatalf("ActiveSigningPolicyRules: %v", err)
	}
	if n := names(got); len(n) != 2 || !contains(n, "acme-only") || !contains(n, "everyone") {
		t.Errorf("acme sees %v, want its own rule plus the deployment-wide one", n)
	}
}

func TestSigningPolicyCounts(t *testing.T) {
	db := policyDB(t)
	if err := db.CreateCELPolicyRule(mkRule("c-1", "cert-rule", `true`)); err != nil {
		t.Fatal(err)
	}
	on := mkSigningRule("s-1", "sign-on", `true`)
	off := mkSigningRule("s-2", "sign-off", `true`)
	off.Enabled = false
	for _, r := range []*celpolicy.Rule{on, off} {
		if err := db.CreateCELPolicyRule(r); err != nil {
			t.Fatal(err)
		}
	}
	total, enabled, err := db.CountSigningPolicyRules()
	if err != nil {
		t.Fatalf("CountSigningPolicyRules: %v", err)
	}
	if total != 2 || enabled != 1 {
		t.Errorf("signing counts = %d/%d, want 2/1", total, enabled)
	}
	allTotal, allEnabled, err := db.CountCELPolicyRules()
	if err != nil {
		t.Fatalf("CountCELPolicyRules: %v", err)
	}
	if allTotal != 3 || allEnabled != 2 {
		t.Errorf("total counts = %d/%d, want 3/2", allTotal, allEnabled)
	}
}

func TestSigningPolicyUpdateKeepsKindAndSelectors(t *testing.T) {
	db := policyDB(t)
	rule := mkSigningRule("s-1", "sign-rule", `signing.key.name != "x"`)
	rule.Keys = []string{"release-signing"}
	rule.Operations = []string{"artifact"}
	if err := db.CreateCELPolicyRule(rule); err != nil {
		t.Fatal(err)
	}
	rule.Expression = `signing.artifact.timestamped`
	rule.Operations = []string{"artifact", "data"}
	if ok, err := db.UpdateCELPolicyRule(rule); err != nil || !ok {
		t.Fatalf("UpdateCELPolicyRule: %v (ok=%v)", err, ok)
	}
	got, err := db.GetCELPolicyRule("s-1")
	if err != nil || got == nil {
		t.Fatalf("GetCELPolicyRule: %v", err)
	}
	if got.Kind != celpolicy.KindSigning {
		t.Errorf("kind = %q after update", got.Kind)
	}
	if strings.Join(got.Operations, ",") != "artifact,data" {
		t.Errorf("operations = %v", got.Operations)
	}
	if got.Expression != `signing.artifact.timestamped` {
		t.Errorf("expression = %q", got.Expression)
	}
	// Still only visible to the signing gate.
	signRules, err := db.ActiveSigningPolicyRules("")
	if err != nil || len(signRules) != 1 {
		t.Fatalf("ActiveSigningPolicyRules: %v (%d rules)", err, len(signRules))
	}
}

func TestSigningPolicyStoreRejectsUncompilableRules(t *testing.T) {
	db := policyDB(t)
	// A certificate field in a signing rule: the store compiles the expression in
	// the rule's own environment, so this never reaches a gate.
	if err := db.CreateCELPolicyRule(mkSigningRule("s-1", "wrong-vocabulary", `request.dns_names.size() == 0`)); err == nil {
		t.Error("a signing rule referencing request.* must be rejected by the store")
	}
	// And the converse.
	if err := db.CreateCELPolicyRule(mkRule("c-1", "wrong-vocabulary-2", `signing.key.name == "x"`)); err == nil {
		t.Error("a certificate rule referencing signing.* must be rejected by the store")
	}
}

// TestLegacyRowsReadAsCertificateRules proves the upgrade path: a row written
// before the kind column existed (simulated by clearing it) must still be a
// certificate rule, not a signing rule nothing consults.
func TestLegacyRowsReadAsCertificateRules(t *testing.T) {
	db := policyDB(t)
	if err := db.CreateCELPolicyRule(mkRule("c-1", "legacy", `request.dns_names.size() <= 2`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.exec(`UPDATE cel_policy_rules SET kind = '' WHERE id = ?`, "c-1"); err != nil {
		t.Fatalf("clearing the kind: %v", err)
	}
	got, err := db.GetCELPolicyRule("c-1")
	if err != nil || got == nil {
		t.Fatalf("GetCELPolicyRule: %v", err)
	}
	if got.Kind != celpolicy.KindCertificate {
		t.Errorf("a row with no kind read as %q, want certificate", got.Kind)
	}
	active, err := db.ActiveCELPolicyRules("")
	if err != nil {
		t.Fatalf("ActiveCELPolicyRules: %v", err)
	}
	if len(active) != 1 {
		t.Errorf("the issuance gate sees %d rules, want the legacy one", len(active))
	}
	signing, err := db.ActiveSigningPolicyRules("")
	if err != nil {
		t.Fatalf("ActiveSigningPolicyRules: %v", err)
	}
	if len(signing) != 0 {
		t.Errorf("the signing gate must not see a legacy certificate rule (saw %d)", len(signing))
	}
}
