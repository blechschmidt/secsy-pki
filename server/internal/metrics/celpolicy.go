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
