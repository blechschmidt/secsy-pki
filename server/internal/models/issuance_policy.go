package models

// The API shape of a CEL issuance-policy refusal (Task 223).
//
// A policy refusal is the one 4xx in this API whose *body* is the product: the
// engine exists so that "your request asks for 400 days and this profile allows
// 90" reaches the requester instead of a bare "forbidden". So the reasons travel
// twice — once as a sentence in `error`, which a CLI or a human reads, and once
// per rule in `violations`, which a client renders or matches on.

// PolicyViolation is one reason an issuance was refused by an operator-written
// restriction rule.
type PolicyViolation struct {
	// Rule is the rule's name, which an operator can look up through
	// GET /api/issuance-policies/{name}.
	Rule string `json:"rule"`
	// Message is the reason, in the operator's own wording.
	Message string `json:"message"`
	// Mode is "enforce" or "monitor". A monitor-mode violation never appears in a
	// refusal (it does not block); the field is present so one response shape
	// serves the refusal and the dry-run.
	Mode string `json:"mode,omitempty"`
}

// PolicyDeniedResponse is the body of a 422 Unprocessable Content returned when
// the CEL restriction engine refuses a certificate request.
//
// The status is deliberately not 403: the caller's credentials were accepted and
// their permission to issue was never in question — the content of the request
// is what policy refused. A client that tells the two apart can fix the request
// rather than go looking for a missing role.
type PolicyDeniedResponse struct {
	Error      string            `json:"error"`
	Code       string            `json:"code"`
	Violations []PolicyViolation `json:"violations,omitempty"`
}
