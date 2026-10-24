package celexpr

import (
	"fmt"
	"sync"
)

// The role-mapping environment (Task 214).
//
// One environment is shared by every place a role mapping is touched — config
// validation at load, the mapper that runs at login, and the `secsy-ca
// role-mapping` dry-run command — because the alternative is the worst kind of
// bug this feature could have: an expression that validates at startup and then
// behaves differently (or not at all) when someone actually logs in.

// Role-mapping variable names, exported so a caller building an activation
// cannot misspell one. CEL rejects an undeclared variable at compile time but
// an activation missing a *declared* variable only fails at evaluation, which
// would be a denial at login.
const (
	VarSubject = "subject"
	VarEmail   = "email"
	// VarEmailVerified is named for the claim it carries, not camel-cased, so an
	// expression reads the same as the token it reasons about.
	VarEmailVerified = "email_verified"
	VarName          = "name"
	VarUsername      = "username"
	VarIssuer        = "issuer"
	VarProvider      = "provider"
	VarGroups        = "groups"
	VarClaims        = "claims"
)

// RoleMappingVars returns the variables a role-mapping expression may
// reference, in the order they are documented.
//
// The scalar identity fields are declared as plain strings that default to the
// empty string rather than as claim lookups, so the common expression
// (`email.endsWith("@example.com")`) needs no has() guard and cannot fail at
// login merely because an IdP omitted an optional claim. Anything outside that
// fixed set is reached through `claims`, where CEL's map semantics make the
// absence explicit: `has(claims.department) && claims.department == "pki"`.
func RoleMappingVars() []Var {
	return []Var{
		StringVar(VarSubject, "the authenticated subject — the OIDC 'sub' claim, or the directory subject"),
		StringVar(VarEmail, "the principal's e-mail address, empty when the IdP asserted none"),
		BoolVar(VarEmailVerified, "whether the IdP (or the directory) vouched for that address"),
		StringVar(VarName, "the principal's display name, empty when the IdP asserted none"),
		StringVar(VarUsername, "the directory username / 'preferred_username' claim, empty when there is none"),
		StringVar(VarIssuer, "the token issuer ('iss'), empty for a directory login"),
		StringVar(VarProvider, "the configured name of the provider that authenticated this principal"),
		StringListVar(VarGroups, "the principal's group memberships: the configured groups claim, the directory groups, and the internal groups"),
		MapVar(VarClaims, "every verified claim, by name — guard a lookup with has(claims.x)"),
	}
}

var (
	roleMappingOnce sync.Once
	roleMappingEnv  *Env
	roleMappingErr  error
)

// RoleMappingEnv returns the shared role-mapping environment. It is built once
// and is safe for concurrent use.
func RoleMappingEnv() (*Env, error) {
	roleMappingOnce.Do(func() {
		roleMappingEnv, roleMappingErr = NewEnv(RoleMappingVars()...)
	})
	return roleMappingEnv, roleMappingErr
}

// CompileRoleMappingMatch compiles a role mapping's match expression, which
// must yield a bool: true grants the mapping's roles, false and every runtime
// error grant nothing.
func CompileRoleMappingMatch(expr string) (*BoolProgram, error) {
	env, err := RoleMappingEnv()
	if err != nil {
		return nil, err
	}
	return env.CompileBool(expr)
}

// CompileRoleMappingTenant compiles a role mapping's tenant expression, which
// must yield a tenant id (a string) or a list of them — a principal whose
// groups encode several tenants gets the mapping's roles in each. An empty
// result grants nothing: an expression that extracted nothing must never read
// as "platform-wide", which is what the empty tenant means in static
// configuration.
func CompileRoleMappingTenant(expr string) (*StringsProgram, error) {
	env, err := RoleMappingEnv()
	if err != nil {
		return nil, err
	}
	return env.CompileStrings(expr)
}

// RoleMappingInput is the identity a role-mapping expression is evaluated
// against. Build the activation with Activation so every declared variable is
// present — a missing one is an evaluation error, i.e. a denied login.
type RoleMappingInput struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Username      string
	Issuer        string
	Provider      string
	Groups        []string
	Claims        map[string]interface{}
}

// Activation renders the input as a CEL activation. Every variable declared by
// RoleMappingVars is populated, with the zero value where the identity carries
// nothing: an expression is a function of a complete input, never of a partial
// one.
func (in RoleMappingInput) Activation() map[string]interface{} {
	groups := in.Groups
	if groups == nil {
		groups = []string{}
	}
	claims := in.Claims
	if claims == nil {
		claims = map[string]interface{}{}
	}
	return map[string]interface{}{
		VarSubject:       in.Subject,
		VarEmail:         in.Email,
		VarEmailVerified: in.EmailVerified,
		VarName:          in.Name,
		VarUsername:      in.Username,
		VarIssuer:        in.Issuer,
		VarProvider:      in.Provider,
		VarGroups:        groups,
		VarClaims:        claims,
	}
}

// ValidateRoleMapping compiles a role mapping's expressions without keeping the
// result, so a configuration loader can report a bad expression (with its
// position) at load instead of at the first login. An empty expression is not
// an error here: whether one is required is the caller's rule.
func ValidateRoleMapping(match, tenant string) error {
	if match != "" {
		if _, err := CompileRoleMappingMatch(match); err != nil {
			return fmt.Errorf("expression: %w", err)
		}
	}
	if tenant != "" {
		if _, err := CompileRoleMappingTenant(tenant); err != nil {
			return fmt.Errorf("tenant_expression: %w", err)
		}
	}
	return nil
}
