package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/celexpr"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// CEL issuance-restriction rule administration (Task 223).
//
// The endpoints behind the console's Issuance Policy view: list, create, edit,
// enable/disable and delete rules, validate an expression before saving it,
// dry-run the rule set against a sample request or a real CSR, and read the
// expression vocabulary.
//
// Editing is gated on ca:configure — the same capability that governs profiles
// and restriction sets, which is what these rules extend. Reading is open to any
// role, because an issuer who gets refused needs to be able to look up the rule
// that refused them.
//
// Every mutation is audited with the rule's name and, when the text changed, the
// expression itself: a restriction engine is only as trustworthy as the record
// of who changed it.

// policyRuleRequest is the JSON body of a create/update. It mirrors
// celpolicy.Rule minus the server-owned fields.
type policyRuleRequest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Expression  string           `json:"expression"`
	Message     string           `json:"message"`
	Effect      celpolicy.Effect `json:"effect"`
	Mode        celpolicy.Mode   `json:"mode"`
	TenantID    string           `json:"tenant_id"`
	Profiles    []string         `json:"profiles"`
	CAs         []string         `json:"cas"`
	Priority    int              `json:"priority"`
	Enabled     *bool            `json:"enabled"`
	FailOpen    bool             `json:"fail_open"`
}

// rule converts the body into a rule, defaulting Enabled to true: an operator
// who writes a restriction and omits the flag meant to switch it on, and the
// alternative default silently does nothing.
func (b policyRuleRequest) rule() celpolicy.Rule {
	enabled := true
	if b.Enabled != nil {
		enabled = *b.Enabled
	}
	return celpolicy.Rule{
		Name:        strings.TrimSpace(b.Name),
		Description: strings.TrimSpace(b.Description),
		Expression:  strings.TrimSpace(b.Expression),
		Message:     strings.TrimSpace(b.Message),
		Effect:      b.Effect,
		Mode:        b.Mode,
		TenantID:    strings.TrimSpace(b.TenantID),
		Profiles:    trimAll(b.Profiles),
		CAs:         trimAll(b.CAs),
		Priority:    b.Priority,
		Enabled:     enabled,
		FailOpen:    b.FailOpen,
	}
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ListIssuancePolicies returns every restriction rule in evaluation order.
func (a *API) ListIssuancePolicies(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	rules, err := a.db.ListCELPolicyRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list issuance policies: %v", err)
		return
	}
	if rules == nil {
		rules = []celpolicy.Rule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

// GetIssuancePolicy returns one restriction rule, by id or by name — the name is
// what a refusal message carries, so an operator holding only that can still
// look the rule up.
func (a *API) GetIssuancePolicy(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	rule, err := a.lookupPolicyRule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read issuance policy: %v", err)
		return
	}
	if rule == nil {
		writeError(w, http.StatusNotFound, "no issuance policy %q", r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// lookupPolicyRule resolves a rule by id, falling back to its name.
func (a *API) lookupPolicyRule(ref string) (*celpolicy.Rule, error) {
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, nil
	}
	if rule, err := a.db.GetCELPolicyRule(ref); err != nil || rule != nil {
		return rule, err
	}
	return a.db.GetCELPolicyRuleByName(ref)
}

// CreateIssuancePolicy stores a new restriction rule. The expression is compiled
// before the row is written, so a rule that cannot be evaluated never reaches
// the issuance path.
func (a *API) CreateIssuancePolicy(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionConfigureCA) {
		a.recordEvent(r, audit.ActionPolicyRuleCreate, "", "", audit.ResultDenied, "ca:configure capability required")
		writeError(w, http.StatusForbidden, "ca:configure capability required (admin role)")
		return
	}
	var body policyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	rule := body.rule()
	rule.ID = uuid.New().String()
	rule.CreatedBy = user.Subject
	rule.UpdatedBy = user.Subject
	if err := rule.Validate(); err != nil {
		a.recordEvent(r, audit.ActionPolicyRuleCreate, rule.ID, rule.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	existing, err := a.db.GetCELPolicyRuleByName(rule.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check for an existing policy: %v", err)
		return
	}
	if existing != nil {
		writeError(w, http.StatusConflict, "an issuance policy named %q already exists", rule.Name)
		return
	}
	if err := a.db.CreateCELPolicyRule(&rule); err != nil {
		a.recordEvent(r, audit.ActionPolicyRuleCreate, rule.ID, rule.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to create issuance policy: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionPolicyRuleCreate, rule.ID, rule.Name, audit.ResultSuccess, policyRuleDetail(rule))
	writeJSON(w, http.StatusCreated, rule)
}

// UpdateIssuancePolicy replaces a rule's editable fields.
func (a *API) UpdateIssuancePolicy(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionConfigureCA) {
		a.recordEvent(r, audit.ActionPolicyRuleUpdate, r.PathValue("id"), "", audit.ResultDenied, "ca:configure capability required")
		writeError(w, http.StatusForbidden, "ca:configure capability required (admin role)")
		return
	}
	existing, err := a.lookupPolicyRule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read issuance policy: %v", err)
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "no issuance policy %q", r.PathValue("id"))
		return
	}
	var body policyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	rule := body.rule()
	rule.ID = existing.ID
	rule.CreatedBy = existing.CreatedBy
	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedBy = user.Subject
	if rule.Name == "" {
		rule.Name = existing.Name
	}
	if rule.Expression == "" {
		rule.Expression = existing.Expression
	}
	if err := rule.Validate(); err != nil {
		a.recordEvent(r, audit.ActionPolicyRuleUpdate, rule.ID, rule.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	// A rename must not collide with another rule: the name is the handle a
	// refusal message gives the requester, so two rules sharing one would make a
	// refusal ambiguous.
	if !strings.EqualFold(rule.Name, existing.Name) {
		clash, err := a.db.GetCELPolicyRuleByName(rule.Name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to check for an existing policy: %v", err)
			return
		}
		if clash != nil && clash.ID != rule.ID {
			writeError(w, http.StatusConflict, "an issuance policy named %q already exists", rule.Name)
			return
		}
	}
	ok, err := a.db.UpdateCELPolicyRule(&rule)
	if err != nil {
		a.recordEvent(r, audit.ActionPolicyRuleUpdate, rule.ID, rule.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to update issuance policy: %v", err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no issuance policy %q", rule.ID)
		return
	}
	a.recordEvent(r, audit.ActionPolicyRuleUpdate, rule.ID, rule.Name, audit.ResultSuccess, policyRuleDetail(rule))
	writeJSON(w, http.StatusOK, rule)
}

// SetIssuancePolicyEnabled flips a rule on or off. It is a dedicated endpoint so
// the console's toggle cannot rewrite an expression it did not mean to touch.
func (a *API) SetIssuancePolicyEnabled(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionConfigureCA) {
		a.recordEvent(r, audit.ActionPolicyRuleUpdate, r.PathValue("id"), "", audit.ResultDenied, "ca:configure capability required")
		writeError(w, http.StatusForbidden, "ca:configure capability required (admin role)")
		return
	}
	existing, err := a.lookupPolicyRule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read issuance policy: %v", err)
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "no issuance policy %q", r.PathValue("id"))
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if _, err := a.db.SetCELPolicyRuleEnabled(existing.ID, body.Enabled, user.Subject); err != nil {
		a.recordEvent(r, audit.ActionPolicyRuleUpdate, existing.ID, existing.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to update issuance policy: %v", err)
		return
	}
	state := "disabled"
	if body.Enabled {
		state = "enabled"
	}
	a.recordEvent(r, audit.ActionPolicyRuleUpdate, existing.ID, existing.Name, audit.ResultSuccess, state)
	existing.Enabled = body.Enabled
	writeJSON(w, http.StatusOK, existing)
}

// DeleteIssuancePolicy removes a rule.
func (a *API) DeleteIssuancePolicy(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionConfigureCA) {
		a.recordEvent(r, audit.ActionPolicyRuleDelete, r.PathValue("id"), "", audit.ResultDenied, "ca:configure capability required")
		writeError(w, http.StatusForbidden, "ca:configure capability required (admin role)")
		return
	}
	existing, err := a.lookupPolicyRule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read issuance policy: %v", err)
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "no issuance policy %q", r.PathValue("id"))
		return
	}
	if _, err := a.db.DeleteCELPolicyRule(existing.ID); err != nil {
		a.recordEvent(r, audit.ActionPolicyRuleDelete, existing.ID, existing.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "failed to delete issuance policy: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionPolicyRuleDelete, existing.ID, existing.Name, audit.ResultSuccess,
		"expression="+existing.Expression)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": existing.ID, "name": existing.Name})
}

// ValidateIssuancePolicy compiles an expression without storing anything, so the
// console can tell an operator their rule is wrong — with the offending column —
// while they are still writing it.
func (a *API) ValidateIssuancePolicy(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	var body struct {
		Expression string `json:"expression"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if strings.TrimSpace(body.Expression) == "" {
		writeError(w, http.StatusBadRequest, "expression is required")
		return
	}
	prog, err := celpolicy.Compile(body.Expression)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "error": err.Error()})
		return
	}
	kind, static := prog.Kind()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":       true,
		"result_type": policyResultTypeName(kind, static),
	})
}

// policyResultTypeName names the result shape the compiler deduced, so the
// editor can tell the operator whether their rule will report its own reason or
// fall back to the rule's message.
func policyResultTypeName(kind celexpr.ResultKind, static bool) string {
	if !static {
		return "dyn (resolved at evaluation)"
	}
	switch kind {
	case celexpr.KindString:
		return "string"
	case celexpr.KindStrings:
		return "list(string)"
	default:
		return "bool"
	}
}

// policyTestRequest is the dry-run body. Supply either an ad-hoc expression, a
// stored rule by id/name, or neither (which evaluates the whole active rule set).
// The facts come from `input`, optionally seeded from a real CSR under a real CA
// and profile — the most faithful test, because the facts are then derived by the
// same code the issuance path uses.
type policyTestRequest struct {
	Expression string           `json:"expression,omitempty"`
	Effect     celpolicy.Effect `json:"effect,omitempty"`
	Message    string           `json:"message,omitempty"`
	Mode       celpolicy.Mode   `json:"mode,omitempty"`
	FailOpen   bool             `json:"fail_open,omitempty"`
	Rule       string           `json:"rule,omitempty"`
	AllRules   bool             `json:"all_rules,omitempty"`

	// CSR, CAID, Profile and ValidityDays seed the request facts from a real
	// pre-issuance preview instead of from hand-written JSON.
	CSR          string `json:"csr,omitempty"`
	CAID         string `json:"ca_id,omitempty"`
	Profile      string `json:"profile,omitempty"`
	ValidityDays int    `json:"validity_days,omitempty"`

	Input celpolicy.Input `json:"input"`
}

// policyTestResponse is the dry-run result: the decision, plus the facts the
// rules actually saw. Echoing the facts is what makes a surprising verdict
// diagnosable — the usual cause is a fact the operator assumed would be present.
type policyTestResponse struct {
	Decision celpolicy.Decision `json:"decision"`
	Rules    []string           `json:"rules"`
	Input    celpolicy.Input    `json:"input"`
}

// TestIssuancePolicy dry-runs rules against a sample request without issuing
// anything.
func (a *API) TestIssuancePolicy(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	var body policyTestRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	rules, err := a.policyTestRules(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	in := body.Input
	if strings.TrimSpace(body.CSR) != "" {
		seeded, err := a.policyFactsFromCSR(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		// Hand-written facts still win over the seeded ones where they were given,
		// so an operator can take a real CSR and then ask "what if the token also
		// carried this claim".
		seeded.JWT = firstMap(in.JWT, seeded.JWT)
		seeded.Body = firstMap(in.Body, seeded.Body)
		if in.Principal.Subject != "" || in.Principal.Authenticated {
			seeded.Principal = in.Principal
		}
		if in.URL.Present {
			seeded.URL = in.URL
		}
		in = seeded
	}
	if in.Request.Source == "" {
		in.Request.Source = celpolicy.SourcePreview
	}
	if in.Request.Operation == "" {
		in.Request.Operation = celpolicy.OpPreview
	}

	decision := celpolicy.Shared().Evaluate(rules, in)
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, rule.Name)
	}
	writeJSON(w, http.StatusOK, policyTestResponse{Decision: decision, Rules: names, Input: in})
}

// policyTestRules resolves which rules a dry-run evaluates.
func (a *API) policyTestRules(body policyTestRequest) ([]celpolicy.Rule, error) {
	switch {
	case strings.TrimSpace(body.Expression) != "":
		rule := celpolicy.Rule{
			Name:       "ad-hoc",
			Expression: strings.TrimSpace(body.Expression),
			Message:    body.Message,
			Effect:     body.Effect,
			Mode:       body.Mode,
			FailOpen:   body.FailOpen,
			Enabled:    true,
		}
		if err := rule.Validate(); err != nil {
			return nil, err
		}
		return []celpolicy.Rule{rule}, nil
	case strings.TrimSpace(body.Rule) != "":
		stored, err := a.lookupPolicyRule(body.Rule)
		if err != nil {
			return nil, fmt.Errorf("reading issuance policy: %w", err)
		}
		if stored == nil {
			return nil, fmt.Errorf("no issuance policy %q", body.Rule)
		}
		// A dry-run of a named rule evaluates it even when it is switched off:
		// trying a rule before enabling it is the point.
		stored.Enabled = true
		return []celpolicy.Rule{*stored}, nil
	default:
		rules, err := a.db.ListCELPolicyRules()
		if err != nil {
			return nil, fmt.Errorf("listing issuance policies: %w", err)
		}
		if !body.AllRules {
			active := make([]celpolicy.Rule, 0, len(rules))
			for _, rule := range rules {
				if rule.Enabled {
					active = append(active, rule)
				}
			}
			return active, nil
		}
		for i := range rules {
			rules[i].Enabled = true
		}
		return rules, nil
	}
}

// policyFactsFromCSR derives the request facts from a real CSR under a real CA
// and profile, by running the pre-issuance preview and reading the request the
// gate would have seen. Nothing is signed and nothing is stored.
func (a *API) policyFactsFromCSR(body policyTestRequest) (celpolicy.Input, error) {
	caID := strings.TrimSpace(body.CAID)
	if caID == "" {
		return celpolicy.Input{}, errors.New("ca_id is required when a csr is supplied")
	}
	mgr := ca.NewManager(a.db, a.keyProvider)
	req, err := mgr.PolicyFactsFromCSR(ca.PreviewSpec{
		CAID:        caID,
		CSRPEM:      []byte(body.CSR),
		Profile:     body.Profile,
		Validity:    daysToDuration(body.ValidityDays),
		RequestedBy: body.Input.Principal.Subject,
	})
	if err != nil {
		return celpolicy.Input{}, err
	}
	return celpolicy.Input{Request: req}, nil
}

func firstMap(primary, fallback map[string]interface{}) map[string]interface{} {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

// IssuancePolicyReference returns the expression vocabulary: the variables with
// the fields of each object, the function library, the result shapes, the cost
// ceiling, and worked examples. The console renders it directly, so the reference
// an operator reads while writing a rule cannot drift from the environment the
// rule is compiled in.
func (a *API) IssuancePolicyReference(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	ref, err := celpolicy.BuildReference()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build the policy reference: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, ref)
}

// policyRuleDetail renders a rule for an audit event.
func policyRuleDetail(rule celpolicy.Rule) string {
	parts := []string{
		"effect=" + string(rule.EffectOrDefault()),
		"mode=" + string(rule.ModeOrDefault()),
		fmt.Sprintf("enabled=%v", rule.Enabled),
		fmt.Sprintf("priority=%d", rule.Priority),
	}
	if len(rule.Profiles) > 0 {
		parts = append(parts, "profiles="+strings.Join(rule.Profiles, ","))
	}
	if len(rule.CAs) > 0 {
		parts = append(parts, "cas="+strings.Join(rule.CAs, ","))
	}
	if rule.TenantID != "" {
		parts = append(parts, "tenant="+rule.TenantID)
	}
	parts = append(parts, "expression="+rule.Expression)
	return strings.Join(parts, " ")
}

// writePolicyDenyError maps a CEL-policy refusal to a 422 whose body carries
// every reason as structured data, and reports whether it handled err.
//
// 422 Unprocessable Content rather than 403: the caller's credentials were
// accepted and their permission to issue was not in question — the *content* of
// the request is what policy refused. A client that distinguishes the two can
// retry with a different request rather than go hunting for a missing role. The
// reasons are both in `error` (one sentence, for a human or a CLI) and in
// `violations` (per rule, for a client that renders them).
func writePolicyDenyError(w http.ResponseWriter, err error) bool {
	var deny *celpolicy.DenyError
	if !errors.As(err, &deny) {
		return false
	}
	writeJSON(w, http.StatusUnprocessableEntity, models.PolicyDeniedResponse{
		Error:      deny.Error(),
		Code:       "policy_denied",
		Violations: policyViolations(deny.Violations()),
	})
	return true
}

// policyViolations converts engine violations to the API shape.
func policyViolations(in []celpolicy.Violation) []models.PolicyViolation {
	out := make([]models.PolicyViolation, 0, len(in))
	for _, v := range in {
		out = append(out, models.PolicyViolation{Rule: v.Rule, Message: v.Message, Mode: string(v.Mode)})
	}
	return out
}
