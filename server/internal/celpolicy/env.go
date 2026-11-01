package celpolicy

import (
	"sync"

	"github.com/blechschmidt/secsy-pki/server/internal/celexpr"
)

// The issuance-restriction environment.
//
// One environment is shared by every place a rule is touched — the console and
// CLI editors that validate it, the dry-run that explains it, and the
// pre-issuance gate that enforces it — because the alternative is the worst bug
// this feature could have: a rule that validates in the editor and then behaves
// differently (or not at all) when a certificate is actually requested.

// Vars returns the variables a restriction rule may reference, in the order they
// are documented.
//
// The three structured facts (request, url, principal) are declared as typed
// objects, so `request.dsn_names` is a compile error with a column in it rather
// than a runtime failure at signing time. The two open-ended ones (jwt, body)
// are maps, because their shape belongs to the identity provider and the API
// caller respectively: CEL's map semantics make the absence of a key explicit,
// so `has(jwt.groups) && "pki-wildcard" in jwt.groups` cannot be mistaken for a
// rule that silently passed because the claim was missing.
func Vars() []celexpr.Var {
	return []celexpr.Var{
		celexpr.ObjectVar(VarRequest, "celpolicy.CertRequest",
			"the certificate request: subject, SANs, validity, key, profile and issuing CA"),
		celexpr.MapVar(VarJWT,
			"every verified claim of the presented token, by name — guard a lookup with has(jwt.x); empty when the caller presented no token"),
		celexpr.ObjectVar(VarURL, "celpolicy.RequestURL",
			"the HTTP request as an object: method, scheme, host, port, path, segments, query, client_ip, present"),
		celexpr.StringVar(VarPath,
			"the full request path, the same value as url.path; empty for a request that did not arrive over HTTP"),
		celexpr.MapVar(VarBody,
			"the decoded request body parameters, by name — guard a lookup with has(body.x)"),
		celexpr.ObjectVar(VarPrincipal, "celpolicy.Principal",
			"the authenticated caller: subject, email, roles, tenant_roles, tenants, groups, is_root, authenticated"),
		celexpr.TimestampVar(VarNow,
			"evaluation time, in UTC — compare it against request.not_after to reason about a lifetime"),
	}
}

// prototypes are the Go structs the environment reflects over. Every nested
// struct must be listed: cel-go reflects one type at a time, and a field whose
// type was not registered is not reachable from an expression.
func prototypes() []any {
	return []any{
		CertRequest{},
		CAInfo{},
		Subject{},
		KeyInfo{},
		Principal{},
		RequestURL{},
	}
}

var (
	envOnce sync.Once
	envInst *celexpr.Env
	envErr  error
)

// Env returns the shared restriction-rule environment. It is built once and is
// safe for concurrent use.
func Env() (*celexpr.Env, error) {
	envOnce.Do(func() {
		envInst, envErr = celexpr.NewObjectEnv(prototypes(), Vars()...)
	})
	return envInst, envErr
}

// Compile compiles one rule expression. The accepted result types are bool,
// string and list(string) — see Rule for what each means — and anything else is
// a compile error naming the type it deduced, so a rule that would never have
// fired is rejected when it is written rather than trusted in production.
func Compile(expr string) (*celexpr.AnyProgram, error) {
	env, err := Env()
	if err != nil {
		return nil, err
	}
	return env.CompileAny(expr)
}

// Validate compiles an expression and discards the result, so an editor (the
// console, the CLI, the REST validator) can reject a bad rule — with the
// offending column — at the moment an operator writes it.
func Validate(expr string) error {
	_, err := Compile(expr)
	return err
}
