package secret

// Exec injection (Task 73): resolving stored secrets into a child process's
// environment and argv without the plaintext ever touching disk. The library
// half is pure — it turns an ExecSpec plus a SecretSource into the final
// (argv, env) — so it is testable without an HSM; the secsy-secret CLI wires
// a SecretSource backed by the registry and the KEK ring, then spawns the
// child.
//
// Two injection styles compose:
//
//   - direct env injection: a secret reference becomes the entire value of an
//     environment variable (SecretEnv). This is the preferred style — the
//     plaintext is visible only in the child's environment.
//   - templating: argv tokens and explicit VAR=value env templates may embed
//     {{secret:REF}} placeholders, which are replaced by the secret's
//     plaintext. Argv templating is convenient but the expanded argv is
//     world-visible in /proc/<pid>/cmdline; prefer env injection for anything
//     long-lived.
//
// A reference is "name" or "name@version": the tenant-scoped stored-secret
// name, optionally pinned to a value-history version (the current version
// otherwise).

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// execTemplateRe matches one {{secret:REF}} placeholder. REF must not contain
// whitespace or braces.
var execTemplateRe = regexp.MustCompile(`\{\{\s*secret:([^{}\s]+)\s*\}\}`)

// envVarNameRe is the portable environment-variable name shape.
var envVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// SecretSource resolves a secret reference ("name" or "name@version") to its
// plaintext. Implementations perform the registry lookup and HSM-backed
// envelope decryption; BuildExecEnv calls it once per distinct reference.
type SecretSource func(ref string) ([]byte, error)

// SecretEnv injects one secret as the entire value of one environment
// variable. An empty Var derives the variable name from the reference's
// secret name (upper-cased, non-alphanumerics folded to '_').
type SecretEnv struct {
	Ref string
	Var string
}

// EnvTemplate sets one environment variable to a literal value that may embed
// {{secret:REF}} placeholders.
type EnvTemplate struct {
	Var   string
	Value string
}

// ExecSpec describes the child invocation to build.
type ExecSpec struct {
	// Argv is the command and its arguments; tokens may embed {{secret:REF}}
	// placeholders. Argv[0] is the program.
	Argv []string
	// Secrets are the direct secret→variable injections.
	Secrets []SecretEnv
	// EnvTemplates are explicit VAR=template assignments.
	EnvTemplates []EnvTemplate
	// BaseEnv is the environment inherited by the child (typically
	// os.Environ(), or nil for a clean environment). Injected variables
	// override inherited ones of the same name.
	BaseEnv []string
}

// ParseSecretRef splits a reference into its secret name and pinned version
// (0 when unpinned, meaning the current version).
func ParseSecretRef(ref string) (name string, version int, err error) {
	name = ref
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		name = ref[:at]
		v, convErr := strconv.Atoi(ref[at+1:])
		if convErr != nil || v < 1 {
			return "", 0, fmt.Errorf("secret: invalid version in reference %q (want name@N with N >= 1)", ref)
		}
		version = v
	}
	if strings.TrimSpace(name) == "" {
		return "", 0, fmt.Errorf("secret: empty secret name in reference %q", ref)
	}
	return name, version, nil
}

// ParseSecretEnv parses a CLI -secret argument: "ref" or "ref:VAR".
func ParseSecretEnv(s string) (SecretEnv, error) {
	ref, varName := s, ""
	if i := strings.LastIndex(s, ":"); i >= 0 {
		ref, varName = s[:i], s[i+1:]
		if !envVarNameRe.MatchString(varName) {
			return SecretEnv{}, fmt.Errorf("secret: invalid environment variable name %q in -secret %q", varName, s)
		}
	}
	if _, _, err := ParseSecretRef(ref); err != nil {
		return SecretEnv{}, err
	}
	return SecretEnv{Ref: ref, Var: varName}, nil
}

// ParseEnvTemplate parses a CLI -env argument: "VAR=value" where value may
// embed {{secret:REF}} placeholders.
func ParseEnvTemplate(s string) (EnvTemplate, error) {
	i := strings.Index(s, "=")
	if i <= 0 {
		return EnvTemplate{}, fmt.Errorf("secret: -env wants VAR=value, got %q", s)
	}
	name := s[:i]
	if !envVarNameRe.MatchString(name) {
		return EnvTemplate{}, fmt.Errorf("secret: invalid environment variable name %q in -env %q", name, s)
	}
	return EnvTemplate{Var: name, Value: s[i+1:]}, nil
}

// DeriveEnvVar maps a secret reference to a conventional environment-variable
// name: the secret name (version suffix dropped) upper-cased with every
// non-alphanumeric folded to '_', prefixed with '_' if it would start with a
// digit. "db-password@3" becomes "DB_PASSWORD".
func DeriveEnvVar(ref string) string {
	name, _, err := ParseSecretRef(ref)
	if err != nil {
		name = ref
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || (out[0] >= '0' && out[0] <= '9') {
		out = "_" + out
	}
	return out
}

// BuildExecEnv resolves an ExecSpec into the final argv and environment. Each
// distinct secret reference is resolved exactly once through source; the
// sorted list of references used is returned so callers can audit WHICH
// secrets were injected (never their values). Environment values cannot carry
// NUL bytes, so a binary secret is refused rather than silently truncated.
func BuildExecEnv(spec ExecSpec, source SecretSource) (argv []string, env []string, usedRefs []string, err error) {
	if len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return nil, nil, nil, fmt.Errorf("secret: exec spec has no command")
	}

	cache := make(map[string]string)
	resolve := func(ref string) (string, error) {
		if v, ok := cache[ref]; ok {
			return v, nil
		}
		plaintext, err := source(ref)
		if err != nil {
			return "", fmt.Errorf("secret: resolving %q: %w", ref, err)
		}
		if strings.IndexByte(string(plaintext), 0) >= 0 {
			return "", fmt.Errorf("secret: %q contains NUL bytes and cannot be injected into an environment or argv", ref)
		}
		cache[ref] = string(plaintext)
		return cache[ref], nil
	}
	expand := func(s string) (string, error) {
		var expandErr error
		out := execTemplateRe.ReplaceAllStringFunc(s, func(m string) string {
			if expandErr != nil {
				return m
			}
			ref := execTemplateRe.FindStringSubmatch(m)[1]
			v, err := resolve(ref)
			if err != nil {
				expandErr = err
				return m
			}
			return v
		})
		return out, expandErr
	}

	// Injected variables, in declaration order; duplicate targets are an error
	// (silently keeping one of two injections would be surprising either way).
	injected := make(map[string]string)
	var injectedOrder []string
	setVar := func(name, value string) error {
		if _, dup := injected[name]; dup {
			return fmt.Errorf("secret: environment variable %q injected more than once", name)
		}
		injected[name] = value
		injectedOrder = append(injectedOrder, name)
		return nil
	}
	for _, se := range spec.Secrets {
		varName := se.Var
		if varName == "" {
			varName = DeriveEnvVar(se.Ref)
		}
		if !envVarNameRe.MatchString(varName) {
			return nil, nil, nil, fmt.Errorf("secret: derived environment variable name %q for %q is not portable; use ref:VAR to name it explicitly", varName, se.Ref)
		}
		v, err := resolve(se.Ref)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := setVar(varName, v); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, et := range spec.EnvTemplates {
		v, err := expand(et.Value)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := setVar(et.Var, v); err != nil {
			return nil, nil, nil, err
		}
	}

	argv = make([]string, len(spec.Argv))
	for i, a := range spec.Argv {
		v, err := expand(a)
		if err != nil {
			return nil, nil, nil, err
		}
		argv[i] = v
	}

	// Base environment minus any variable we are about to inject.
	env = make([]string, 0, len(spec.BaseEnv)+len(injectedOrder))
	for _, kv := range spec.BaseEnv {
		name := kv
		if i := strings.Index(kv, "="); i >= 0 {
			name = kv[:i]
		}
		if _, shadowed := injected[name]; !shadowed {
			env = append(env, kv)
		}
	}
	for _, name := range injectedOrder {
		env = append(env, name+"="+injected[name])
	}

	usedRefs = make([]string, 0, len(cache))
	for ref := range cache {
		usedRefs = append(usedRefs, ref)
	}
	sort.Strings(usedRefs)
	return argv, env, usedRefs, nil
}
