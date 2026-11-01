package metrics

// CEL issuance-restriction gate metrics (Task 223).
//
// The gate is the one pre-issuance check whose logic an operator writes, so it
// is also the one whose behaviour they most need to watch. Three series answer
// the three questions a policy rollout asks: is the gate running, which rules
// are firing, and is a rule broken.

var (
	// CertificatePolicyChecks counts every run of the gate by outcome: "result"
	// is pass|deny|monitor|error (monitor = a monitor-mode rule produced a
	// finding but the certificate was issued; error = the rule set could not be
	// loaded, which fails closed).
	CertificatePolicyChecks = NewCounter(Default,
		"secsy_certificate_policy_checks_total",
		"Pre-issuance CEL policy evaluations, partitioned by outcome (pass|deny|monitor|error).",
		"result")

	// CertificatePolicyViolations counts individual violations by the rule that
	// produced them, so a dashboard shows which policy is actually refusing
	// traffic — and, right after an edit, whether a rule that should be refusing
	// nothing is refusing everything.
	CertificatePolicyViolations = NewCounter(Default,
		"secsy_certificate_policy_violations_total",
		"Pre-issuance CEL policy violations, partitioned by rule name and mode.",
		"rule", "mode")

	// CertificatePolicyRuleErrors counts rules that could not be compiled or
	// evaluated, by rule name. It is the series to alert on: a non-zero rate
	// means a rule is denying (or, if it is fail-open, silently not enforcing)
	// for a reason that has nothing to do with the requests.
	CertificatePolicyRuleErrors = NewCounter(Default,
		"secsy_certificate_policy_rule_errors_total",
		"CEL policy rules that failed to compile or evaluate, partitioned by rule name.",
		"rule")
)

// CEL signing-restriction gate metrics (Task 224).
//
// Mirrors the three certificate series above, so one dashboard panel per
// question works for both halves of the engine. The operation label is what the
// certificate series does not need: a deployment signs certificates, SSH
// certificates, artifacts and raw data with different keys and different
// policies, and "which of them is being refused" is the first question a
// rollout asks.
var (
	// SigningPolicyChecks counts every run of the signing gate: "operation" is
	// ssh-certificate|artifact|data and "result" pass|deny|monitor|error.
	SigningPolicyChecks = NewCounter(Default,
		"secsy_signing_policy_checks_total",
		"Pre-signing CEL policy evaluations, partitioned by operation and outcome (pass|deny|monitor|error).",
		"operation", "result")

	// SigningPolicyViolations counts individual violations by the rule that
	// produced them and its mode.
	SigningPolicyViolations = NewCounter(Default,
		"secsy_signing_policy_violations_total",
		"Pre-signing CEL policy violations, partitioned by rule name and mode.",
		"rule", "mode")

	// SigningPolicyRuleErrors counts signing rules that could not be compiled or
	// evaluated, by rule name — the series to alert on, since a non-zero rate
	// means a rule is refusing (or, if fail-open, silently not enforcing) for a
	// reason unrelated to the requests.
	SigningPolicyRuleErrors = NewCounter(Default,
		"secsy_signing_policy_rule_errors_total",
		"Signing CEL policy rules that failed to compile or evaluate, partitioned by rule name.",
		"rule")
)
