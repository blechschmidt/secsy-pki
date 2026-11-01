package celpolicy

import (
	"fmt"
	"sync"

	"github.com/blechschmidt/secsy-pki/server/internal/celexpr"
)

// The restriction environments, one per rule kind.
//
// One environment per kind is shared by every place a rule of that kind is
// touched — the console and CLI editors that validate it, the dry-run that
// explains it, and the gate that enforces it — because the alternative is the
// worst bug this feature could have: a rule that validates in the editor and
// then behaves differently (or not at all) when a certificate is actually
// requested.
//
// The kinds are separate environments rather than one environment with both
// vocabularies (Task 224). A signing rule that mentions `request.dns_names`
// must fail to *compile*; in a merged environment it would compile and then
// evaluate against an empty certificate request, which reads as a rule that
// works and is in fact a rule that never fires.

// Vars returns the variables a certificate-restriction rule may reference, in
// the order they are documented.
//
// The three structured facts (request, url, principal) are declared as typed
// objects, so `request.dsn_names` is a compile error with a column in it rather
// than a runtime failure at signing time. The two open-ended ones (jwt, body)
// are maps, because their shape belongs to the identity provider and the API
// caller respectively: CEL's map semantics make the absence of a key explicit,
// so `has(jwt.groups) && "pki-wildcard" in jwt.groups` cannot be mistaken for a
// rule that silently passed because the claim was missing.
func Vars() []celexpr.Var {
	return append([]celexpr.Var{
		celexpr.ObjectVar(VarRequest, "celpolicy.CertRequest",
			"the certificate request: subject, SANs, validity, key, profile and issuing CA"),
	}, requestVars()...)
}

// SigningVars returns the variables a signing-restriction rule may reference.
// Everything but the first is shared with Vars: the token, the URL, the body,
// the caller and the clock are facts of the *request*, and an operator who has
// learned them once knows them for both kinds.
func SigningVars() []celexpr.Var {
	return append([]celexpr.Var{
		celexpr.ObjectVar(VarSigning, "celpolicy.SigningRequest",
			"the signing operation: what is being signed, with which key, and the per-operation facts (ssh, artifact, data)"),
	}, requestVars()...)
}

// requestVars are the fact sets both kinds share.
func requestVars() []celexpr.Var {
	return []celexpr.Var{
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

// prototypes are the Go structs the certificate environment reflects over.
// Every nested struct must be listed: cel-go reflects one type at a time, and a
// field whose type was not registered is not reachable from an expression.
func prototypes() []any {
	return append([]any{
		CertRequest{},
		Subject{},
		KeyInfo{},
	}, sharedPrototypes()...)
}

// signingPrototypes are the Go structs the signing environment reflects over.
func signingPrototypes() []any {
	return append([]any{
		SigningRequest{},
		SigningKeyInfo{},
		PayloadInfo{},
		SSHCertInfo{},
		SSHKeyInfo{},
		ArtifactInfo{},
		SignerCertInfo{},
		DataInfo{},
		JWTSVIDInfo{},
	}, sharedPrototypes()...)
}

// sharedPrototypes are reachable from both kinds.
func sharedPrototypes() []any {
	return []any{
		CAInfo{},
		Principal{},
		RequestURL{},
	}
}

// environment is one kind's lazily built environment.
type environment struct {
	once sync.Once
	env  *celexpr.Env
	err  error
}

var (
	certEnv environment
	signEnv environment
)

// Env returns the shared certificate-restriction environment. It is built once
// and is safe for concurrent use.
func Env() (*celexpr.Env, error) {
	certEnv.once.Do(func() {
		certEnv.env, certEnv.err = celexpr.NewObjectEnv(prototypes(), Vars()...)
	})
	return certEnv.env, certEnv.err
}

// SigningEnv returns the shared signing-restriction environment.
func SigningEnv() (*celexpr.Env, error) {
	signEnv.once.Do(func() {
		signEnv.env, signEnv.err = celexpr.NewObjectEnv(signingPrototypes(), SigningVars()...)
	})
	return signEnv.env, signEnv.err
}

// EnvFor returns the environment a rule of the given kind compiles in. An empty
// kind is the certificate environment — that is what a rule stored before the
// kinds existed means — but an unrecognized one is an error rather than the
// same default: compiling "sign" in the certificate environment would reject
// the very expression its author wrote, and blame their syntax for it.
func EnvFor(kind Kind) (*celexpr.Env, error) {
	switch kind {
	case KindSigning:
		return SigningEnv()
	case "", KindCertificate:
		return Env()
	}
	return nil, fmt.Errorf("unknown policy rule kind %q (want %q or %q)", kind, KindCertificate, KindSigning)
}

// Compile compiles one certificate-rule expression. The accepted result types
// are bool, string and list(string) — see Rule for what each means — and
// anything else is a compile error naming the type it deduced, so a rule that
// would never have fired is rejected when it is written rather than trusted in
// production.
func Compile(expr string) (*celexpr.AnyProgram, error) {
	return CompileFor(KindCertificate, expr)
}

// CompileSigning compiles one signing-rule expression.
func CompileSigning(expr string) (*celexpr.AnyProgram, error) {
	return CompileFor(KindSigning, expr)
}

// CompileFor compiles an expression in the environment of the given kind.
func CompileFor(kind Kind, expr string) (*celexpr.AnyProgram, error) {
	env, err := EnvFor(kind)
	if err != nil {
		return nil, err
	}
	return env.CompileAny(expr)
}

// Validate compiles a certificate-rule expression and discards the result, so
// an editor (the console, the CLI, the REST validator) can reject a bad rule —
// with the offending column — at the moment an operator writes it.
func Validate(expr string) error {
	return ValidateFor(KindCertificate, expr)
}

// ValidateFor compiles an expression of the given kind and discards the result.
func ValidateFor(kind Kind, expr string) error {
	_, err := CompileFor(kind, expr)
	return err
}
