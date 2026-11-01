package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
)

// CEL issuance-restriction rules (Task 223).
//
// One row per operator-written rule. The rules live in the database rather than
// in the configuration file for one reason: the task they serve is editing them
// — a policy that needs a file edit, a config reload and a deploy is a policy an
// operator cannot iterate on, and the console is where they are written, tried
// against a sample request, and switched on. The table is the single source of
// truth, read on every issuance by the pre-issuance gate (see
// ca.Manager.checkCELPolicy), where it costs one indexed query and a cache hit
// per rule.
//
// Scope selectors (profiles, cas) are JSON-encoded TEXT, matching how the
// restriction-set details store their allowlists. created_at/updated_at are
// written explicitly in UTC (never a column DEFAULT), so ordering round-trips
// identically across SQLite and PostgreSQL.

const celPolicyColumns = `id, tenant_id, name, description, expression, message, effect, mode,
	profiles, cas, priority, enabled, fail_open, created_by, updated_by, created_at, updated_at,
	kind, sign_keys, operations`

// celPolicyPlaceholders matches celPolicyColumns.
const celPolicyPlaceholders = `?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?`

// certificateKindPredicate matches the rows a certificate rule is read from:
// the explicit kind, plus the rows written before the column existed, whose
// absent kind means what it always meant (Task 224 added signing rules; every
// row that predates it restricts certificate generation).
const certificateKindPredicate = `(kind IS NULL OR kind = '' OR kind = 'certificate')`

// CreateCELPolicyRule inserts a rule. The caller is expected to have validated
// the rule (celpolicy.Rule.Validate) — the store will not persist an expression
// that does not compile, because a row that denies every certificate and cannot
// be fixed by editing its text is not a state an operator should be able to
// reach through the API.
func (db *DB) CreateCELPolicyRule(r *celpolicy.Rule) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("invalid policy rule: %w", err)
	}
	now := time.Now().UTC()
	r.CreatedAt = now.Format(time.RFC3339Nano)
	r.UpdatedAt = r.CreatedAt
	sel := encodeSelectors(r)
	_, err := db.exec(
		`INSERT INTO cel_policy_rules (`+celPolicyColumns+`) VALUES (`+celPolicyPlaceholders+`)`,
		r.ID, r.TenantID, r.Name, r.Description, r.Expression, r.Message,
		string(r.EffectOrDefault()), string(r.ModeOrDefault()),
		sel.profiles, sel.cas, r.Priority, r.Enabled, r.FailOpen,
		r.CreatedBy, r.UpdatedBy, now, now,
		string(r.KindOrDefault()), sel.keys, sel.operations,
	)
	return err
}

// UpdateCELPolicyRule replaces a rule's editable fields, reporting whether the
// row existed. created_at and created_by are preserved: the audit trail of who
// first wrote a policy survives every later edit.
func (db *DB) UpdateCELPolicyRule(r *celpolicy.Rule) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, fmt.Errorf("invalid policy rule: %w", err)
	}
	now := time.Now().UTC()
	sel := encodeSelectors(r)
	res, err := db.exec(
		`UPDATE cel_policy_rules SET tenant_id = ?, name = ?, description = ?, expression = ?,
			message = ?, effect = ?, mode = ?, profiles = ?, cas = ?, priority = ?, enabled = ?,
			fail_open = ?, updated_by = ?, updated_at = ?, kind = ?, sign_keys = ?, operations = ?
			WHERE id = ?`,
		r.TenantID, r.Name, r.Description, r.Expression, r.Message,
		string(r.EffectOrDefault()), string(r.ModeOrDefault()),
		sel.profiles, sel.cas, r.Priority, r.Enabled, r.FailOpen, r.UpdatedBy, now,
		string(r.KindOrDefault()), sel.keys, sel.operations, r.ID,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	r.UpdatedAt = now.Format(time.RFC3339Nano)
	return n > 0, nil
}

// SetCELPolicyRuleEnabled flips a rule's enabled flag, reporting whether the row
// existed. It is a separate operation from a full update so the console's toggle
// cannot accidentally rewrite an expression it did not mean to touch.
func (db *DB) SetCELPolicyRuleEnabled(id string, enabled bool, by string) (bool, error) {
	res, err := db.exec(
		`UPDATE cel_policy_rules SET enabled = ?, updated_by = ?, updated_at = ? WHERE id = ?`,
		enabled, by, time.Now().UTC(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// GetCELPolicyRule returns one rule, or (nil, nil) when there is no such row.
func (db *DB) GetCELPolicyRule(id string) (*celpolicy.Rule, error) {
	r, err := scanCELPolicyRule(db.queryRow(
		`SELECT `+celPolicyColumns+` FROM cel_policy_rules WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// GetCELPolicyRuleByName returns the rule with the given (case-insensitive)
// name, or (nil, nil) when there is none. Names are what appear in a refusal
// message, so the API resolves them for an operator who has the message but not
// the id.
func (db *DB) GetCELPolicyRuleByName(name string) (*celpolicy.Rule, error) {
	rules, err := db.ListCELPolicyRules()
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if strings.EqualFold(rules[i].Name, name) {
			return &rules[i], nil
		}
	}
	return nil, nil
}

// ListCELPolicyRules returns every rule in evaluation order (priority ascending,
// then name), including the disabled ones — the console lists what exists, not
// only what is live.
func (db *DB) ListCELPolicyRules() ([]celpolicy.Rule, error) {
	rows, err := db.query(`SELECT ` + celPolicyColumns + ` FROM cel_policy_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []celpolicy.Rule
	for rows.Next() {
		r, err := scanCELPolicyRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortCELPolicyRules(out)
	return out, nil
}

// ActiveCELPolicyRules returns the enabled rules that could apply to a CA in the
// given tenant: the tenant's own rules plus the deployment-wide ones. The
// profile/CA selectors are matched in the engine (celpolicy.Rule.Applies) rather
// than in SQL, because they are glob patterns — pushing them into a LIKE would
// mean two implementations of one matching rule, and the one that disagreed
// would be the one that let a certificate through.
func (db *DB) ActiveCELPolicyRules(tenantID string) ([]celpolicy.Rule, error) {
	return db.activePolicyRules(tenantID, certificateKindPredicate)
}

// ActiveSigningPolicyRules returns the enabled signing rules (Task 224) that
// could apply to an operation in the given tenant: the tenant's own rules plus
// the deployment-wide ones. The kind is filtered here rather than in the engine
// so a deployment with a hundred certificate rules and one signing rule does
// not load the hundred on every signature.
func (db *DB) ActiveSigningPolicyRules(tenantID string) ([]celpolicy.Rule, error) {
	return db.activePolicyRules(tenantID, `kind = 'signing'`)
}

// activePolicyRules is the shared read: enabled rows of one kind, scoped to a
// tenant or deployment-wide.
func (db *DB) activePolicyRules(tenantID, kindPredicate string) ([]celpolicy.Rule, error) {
	rows, err := db.query(
		`SELECT `+celPolicyColumns+` FROM cel_policy_rules
		 WHERE enabled = `+db.trueLiteral()+` AND `+kindPredicate+`
		   AND (tenant_id = '' OR tenant_id IS NULL OR tenant_id = ?)`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []celpolicy.Rule
	for rows.Next() {
		r, err := scanCELPolicyRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortCELPolicyRules(out)
	return out, nil
}

// DeleteCELPolicyRule removes a rule, reporting whether a row was deleted.
func (db *DB) DeleteCELPolicyRule(id string) (bool, error) {
	res, err := db.exec(`DELETE FROM cel_policy_rules WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CountCELPolicyRules returns the total and enabled rule counts across both
// kinds, for the doctor check and the console's summary line.
func (db *DB) CountCELPolicyRules() (total, enabled int, err error) {
	if err = db.queryRow(`SELECT COUNT(*) FROM cel_policy_rules`).Scan(&total); err != nil {
		return 0, 0, err
	}
	err = db.queryRow(`SELECT COUNT(*) FROM cel_policy_rules WHERE enabled = ` + db.trueLiteral()).Scan(&enabled)
	return total, enabled, err
}

// CountSigningPolicyRules returns the total and enabled signing-rule counts, so
// the doctor check can report the two kinds separately — a deployment that
// wrote signing rules and never enabled one should be told so.
func (db *DB) CountSigningPolicyRules() (total, enabled int, err error) {
	if err = db.queryRow(`SELECT COUNT(*) FROM cel_policy_rules WHERE kind = 'signing'`).Scan(&total); err != nil {
		return 0, 0, err
	}
	err = db.queryRow(`SELECT COUNT(*) FROM cel_policy_rules WHERE kind = 'signing' AND enabled = ` +
		db.trueLiteral()).Scan(&enabled)
	return total, enabled, err
}

// sortCELPolicyRules puts rules in evaluation order. The order is fixed here
// rather than in SQL so SQLite and PostgreSQL cannot disagree about the
// collation of a rule name, which would reorder the reasons a requester reads.
func sortCELPolicyRules(rules []celpolicy.Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].Name < rules[j].Name
	})
}

// trueLiteral is the SQL literal for boolean true on the active backend. SQLite
// stores the flag as 0/1 INTEGER and PostgreSQL as BOOLEAN, and only the latter
// accepts TRUE in a comparison.
func (db *DB) trueLiteral() string {
	if db.isPostgres() {
		return "TRUE"
	}
	return "1"
}

// encodedSelectors is the JSON-encoded scope of one rule.
type encodedSelectors struct {
	profiles, cas, keys, operations string
}

// encodeSelectors renders the scope selectors as JSON arrays.
func encodeSelectors(r *celpolicy.Rule) encodedSelectors {
	return encodedSelectors{
		profiles:   encodeSelector(r.Profiles),
		cas:        encodeSelector(r.CAs),
		keys:       encodeSelector(r.Keys),
		operations: encodeSelector(r.Operations),
	}
}

func encodeSelector(s []string) string {
	b, _ := json.Marshal(orEmptySelector(s))
	return string(b)
}

func orEmptySelector(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func scanCELPolicyRule(s scanner) (*celpolicy.Rule, error) {
	var (
		r                                  celpolicy.Rule
		tenant, desc, msg, effect, mode    sql.NullString
		profiles, cas, createdBy, updateBy sql.NullString
		kind, keys, operations             sql.NullString
		enabled, failOpen                  bool
		createdAt, updatedAt               time.Time
	)
	if err := s.Scan(&r.ID, &tenant, &r.Name, &desc, &r.Expression, &msg, &effect, &mode,
		&profiles, &cas, &r.Priority, &enabled, &failOpen,
		&createdBy, &updateBy, &createdAt, &updatedAt,
		&kind, &keys, &operations); err != nil {
		return nil, err
	}
	r.TenantID = tenant.String
	r.Description = desc.String
	r.Message = msg.String
	r.Effect = celpolicy.Effect(effect.String)
	r.Mode = celpolicy.Mode(mode.String)
	// An absent kind is a certificate rule: that is what every row written
	// before the column existed is, and reading it as anything else would turn
	// a working issuance restriction into a signing rule nothing consults.
	r.Kind = celpolicy.Kind(kind.String).OrDefault()
	r.Profiles = decodeSelector(profiles.String)
	r.CAs = decodeSelector(cas.String)
	r.Keys = decodeSelector(keys.String)
	r.Operations = decodeSelector(operations.String)
	r.Enabled = enabled
	r.FailOpen = failOpen
	r.CreatedBy = createdBy.String
	r.UpdatedBy = updateBy.String
	r.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
	r.UpdatedAt = updatedAt.UTC().Format(time.RFC3339Nano)
	return &r, nil
}

// decodeSelector parses a JSON-encoded selector list, tolerating a legacy or
// hand-written comma-separated value. An unparseable column yields no selectors,
// which is the widest scope — but a rule's scope only ever *adds* restrictions,
// so widening it cannot let a certificate through that a narrower reading would
// have blocked.
func decodeSelector(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err == nil {
		return trimNonEmpty(out)
	}
	return trimNonEmpty(strings.Split(s, ","))
}

func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
