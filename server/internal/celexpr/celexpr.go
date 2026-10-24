// Package celexpr compiles and evaluates CEL (Common Expression Language)
// expressions written in configuration.
//
// Configuration in this system is deliberately declarative: a role mapping says
// "this group gets issuer in this tenant" and nothing more. That holds right up
// to the point where an organization's group names *encode* the structure —
// `pki-issuers-acme`, `CN=PKI-Admins-emea,OU=Groups,DC=corp,DC=example,DC=com`,
// one group per team per environment. Enumerating those by hand means a config
// change (and a deploy) for every new team, and the enumeration drifts from the
// directory the moment someone adds a group.
//
// A CEL expression closes that gap without becoming a scripting language in the
// configuration file. CEL is non-Turing-complete by construction: no loops, no
// recursion, no I/O, no mutation. An expression is a *total function of the
// inputs it is handed*, it terminates, and its cost is bounded before it runs.
// Those properties are what make it safe to evaluate an operator-written
// expression on the authentication path, where the alternative (an embedded
// interpreter) would be a remote-code-execution surface.
//
// This package wraps github.com/google/cel-go (now cel.dev/cel-go) with the
// three things every call site here needs and none of them should re-decide:
//
//   - A fixed function library (see Functions), so an expression that works in
//     one place works in all of them and the documented vocabulary is the
//     actual vocabulary.
//   - Result-typed compilation (CompileBool, CompileStrings), so an expression
//     whose type is wrong — a tenant expression that yields a bool, say — is a
//     load error with a position in it, not a silent non-match at login time.
//   - A cost ceiling on every evaluation, so a pathological comprehension over
//     an attacker-influenced claim cannot spend unbounded CPU inside an
//     authentication request.
//
// Compiled programs are immutable and safe for concurrent use; compile once at
// startup and evaluate per request.
package celexpr

import (
	"fmt"
	"regexp"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
)

// DefaultCostLimit bounds the interpreter cost of a single evaluation.
//
// CEL's cost model charges per operation, with string and list operations
// charged in proportion to their size, so the limit is an abstract budget
// rather than a time or a memory figure. Measured against this package's own
// environment: an anchored `groups.exists(g, g.matches(…))` costs ~10 units per
// group inspected, and the heaviest shape a role mapping has reason to write —
// filter the groups, regex-extract a tenant id out of each survivor, drop the
// misses — costs ~87 units per group, so ~44,000 over a 500-group principal.
// Half a million therefore leaves an order of magnitude of headroom for every
// legitimate expression while capping the worst case at a fraction of a second
// of CPU.
//
// What it stops is the shape that has no legitimate use on this path: a
// quadratic comprehension over a claim whose size the caller controls
// (`groups.all(a, groups.all(b, …))` over a thousand groups), which would
// otherwise burn CPU inside the request that is still deciding whether the
// caller may log in at all. Exceeding the limit aborts the evaluation with an
// error, which every caller must treat as "did not match".
const DefaultCostLimit uint64 = 500_000

// Env is a compiled CEL environment: a fixed set of declared variables plus the
// function library from Functions. It is immutable and safe for concurrent use.
type Env struct {
	env  *cel.Env
	vars []Var
}

// Var declares one variable an expression may reference. Use the constructors
// (StringVar, StringListVar, MapVar) rather than building one directly: they are
// what keep cel-go's type objects from leaking into every caller.
type Var struct {
	name string
	typ  *cel.Type
	doc  string
}

// Name returns the variable's name as an expression references it.
func (v Var) Name() string { return v.name }

// Doc returns the one-line description of the variable, for help output.
func (v Var) Doc() string { return v.doc }

// Type returns the variable's CEL type as written in CEL's type syntax
// (`string`, `list(string)`, `map(string, dyn)`), for help output.
func (v Var) Type() string { return v.typ.String() }

// StringVar declares a string variable. A string variable is always present —
// absent inputs are the empty string, never an error — so an expression over
// one needs no has() guard.
func StringVar(name, doc string) Var {
	return Var{name: name, typ: cel.StringType, doc: doc}
}

// BoolVar declares a boolean variable. An absent input is false.
func BoolVar(name, doc string) Var {
	return Var{name: name, typ: cel.BoolType, doc: doc}
}

// StringListVar declares a list-of-strings variable, which is the shape of a
// group membership. An absent input is the empty list.
func StringListVar(name, doc string) Var {
	return Var{name: name, typ: cel.ListType(cel.StringType), doc: doc}
}

// MapVar declares a string-keyed map of dynamically typed values — the shape of
// a decoded JWT claim set. Indexing a key that is not present is a runtime
// error by CEL's design, so expressions over a map must guard with
// has(m.key) (or use one of the string variables, which cannot be absent).
func MapVar(name, doc string) Var {
	return Var{name: name, typ: cel.MapType(cel.StringType, cel.DynType), doc: doc}
}

// identPattern is the CEL identifier syntax a declared variable must satisfy.
// cel-go itself accepts an empty or malformed declaration name and then simply
// never resolves it, which would present as every expression failing to
// compile for no stated reason.
var identPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// NewEnv builds an environment declaring exactly vars, with the standard
// function library available to every expression.
func NewEnv(vars ...Var) (*Env, error) {
	opts := make([]cel.EnvOption, 0, len(vars)+8)
	opts = append(opts, Functions()...)
	seen := make(map[string]bool, len(vars))
	for _, v := range vars {
		if !identPattern.MatchString(v.name) {
			return nil, fmt.Errorf("celexpr: %q is not a usable variable name", v.name)
		}
		if seen[v.name] {
			return nil, fmt.Errorf("celexpr: variable %q is declared twice", v.name)
		}
		seen[v.name] = true
		opts = append(opts, cel.VariableWithDoc(v.name, v.typ, v.doc))
	}
	// Declarations are validated eagerly so a programming error in the variable
	// set surfaces here rather than at the first compile.
	opts = append(opts, cel.EagerlyValidateDeclarations(true))
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("celexpr: building environment: %w", err)
	}
	return &Env{env: env, vars: append([]Var(nil), vars...)}, nil
}

// Vars returns the declared variables, in declaration order.
func (e *Env) Vars() []Var {
	if e == nil {
		return nil
	}
	return append([]Var(nil), e.vars...)
}

// Functions returns the function library every expression in this system sees.
//
// It is the CEL standard library (comparison and boolean operators, the
// has/all/exists/exists_one/map/filter macros, size(), and the standard string
// functions contains / startsWith / endsWith / matches) plus four of the
// upstream extension libraries:
//
//   - strings: charAt, indexOf, lastIndexOf, lowerAscii, upperAscii, replace,
//     split, substring, trim, join, reverse, format, strings.quote.
//   - regex: regex.replace, regex.extract, regex.extractAll — RE2 search and
//     replace with capture-group references, which is what turns a structured
//     group name into the tenant id it encodes.
//   - sets: sets.contains, sets.equivalent, sets.intersects.
//   - lists: distinct, flatten, reverse, slice, sort, sortBy, lists.range.
//
// Optional types are enabled because regex.extract yields an optional<string>
// (no match is a none, not an error), which gives the expression an explicit
// .orValue("…") rather than a surprise.
//
// Everything outside that list is deliberately absent. In particular there is
// no way for an expression to read a file, open a socket, read the clock, or
// reach any state other than the variables it was handed: an expression is a
// function of its inputs, which is what makes it reviewable in a config file.
func Functions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.OptionalTypes(),
		ext.Strings(),
		ext.Regex(),
		ext.Sets(),
		ext.Lists(),
	}
}

// BoolProgram is a compiled expression that yields a bool.
type BoolProgram struct {
	prog   cel.Program
	source string
}

// StringsProgram is a compiled expression that yields a string or a list of
// strings, normalized to a string slice on evaluation.
type StringsProgram struct {
	prog   cel.Program
	source string
}

// Source returns the expression text the program was compiled from.
func (p *BoolProgram) Source() string {
	if p == nil {
		return ""
	}
	return p.source
}

// Source returns the expression text the program was compiled from.
func (p *StringsProgram) Source() string {
	if p == nil {
		return ""
	}
	return p.source
}

// CompileBool compiles expr, requiring its result type to be bool (or dyn,
// which is what an expression ending in a dynamic map lookup deduces to and
// which is checked again at evaluation).
func (e *Env) CompileBool(expr string) (*BoolProgram, error) {
	prog, err := e.compile(expr, "bool", cel.BoolType)
	if err != nil {
		return nil, err
	}
	return &BoolProgram{prog: prog, source: strings.TrimSpace(expr)}, nil
}

// CompileStrings compiles expr, requiring its result type to be string,
// list(string), or dyn — or an optional of either, since a bare
// regex.extract(…) is the most natural way to write "the tenant encoded in this
// group name" and an unmatched pattern is then a none rather than an error.
func (e *Env) CompileStrings(expr string) (*StringsProgram, error) {
	prog, err := e.compile(expr, "string or list(string)",
		cel.StringType,
		cel.ListType(cel.StringType),
		types.NewOptionalType(cel.StringType),
		types.NewOptionalType(cel.ListType(cel.StringType)))
	if err != nil {
		return nil, err
	}
	return &StringsProgram{prog: prog, source: strings.TrimSpace(expr)}, nil
}

// compile parses, type-checks, and plans expr, requiring the deduced result
// type to be one of want (dyn always passes: a lookup into a map(string, dyn)
// deduces to dyn, and rejecting that would rule out the most common shape of
// expression; such a result is type-checked again when it is evaluated).
func (e *Env) compile(expr string, wantDesc string, want ...*cel.Type) (cel.Program, error) {
	if e == nil || e.env == nil {
		return nil, fmt.Errorf("celexpr: nil environment")
	}
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("celexpr: expression is empty")
	}
	ast, iss := e.env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		// The issue text carries the offending column and a caret line; keep it.
		return nil, fmt.Errorf("celexpr: %w", iss.Err())
	}
	if got := ast.OutputType(); !typeAllowed(got, want) {
		return nil, fmt.Errorf("celexpr: expression must evaluate to %s, not %s: %s",
			wantDesc, got.String(), strings.TrimSpace(expr))
	}
	prog, err := e.env.Program(ast,
		cel.CostLimit(DefaultCostLimit),
		cel.EvalOptions(cel.OptTrackCost),
	)
	if err != nil {
		return nil, fmt.Errorf("celexpr: planning expression: %w", err)
	}
	return prog, nil
}

// typeAllowed reports whether the deduced output type is acceptable. Dyn and
// the error/unknown placeholders pass the static gate and are caught at
// evaluation; everything else must match one of the wanted types exactly.
func typeAllowed(got *cel.Type, want []*cel.Type) bool {
	if got == nil {
		return false
	}
	switch got.Kind() {
	case types.DynKind, types.AnyKind:
		return true
	}
	for _, w := range want {
		if got.IsExactType(w) {
			return true
		}
	}
	return false
}

// Eval evaluates the program against vars and returns its boolean result. A
// non-boolean result, a missing variable, or a runtime error (an invalid regex,
// an out-of-range index, a cost overrun) is returned as an error and must be
// treated by the caller as "did not match" — never as a match.
func (p *BoolProgram) Eval(vars map[string]interface{}) (bool, error) {
	if p == nil || p.prog == nil {
		return false, fmt.Errorf("celexpr: nil program")
	}
	out, _, err := p.prog.Eval(vars)
	if err != nil {
		return false, fmt.Errorf("evaluating %q: %w", p.source, err)
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("evaluating %q: result is %s, not bool", p.source, out.Type().TypeName())
	}
	return b, nil
}

// Eval evaluates the program against vars and returns its result as a string
// slice: a string result yields one element, a list(string) result yields its
// elements, and an optional yields zero or one element. Empty strings are
// dropped — an expression that extracted nothing must not read as a result.
func (p *StringsProgram) Eval(vars map[string]interface{}) ([]string, error) {
	if p == nil || p.prog == nil {
		return nil, fmt.Errorf("celexpr: nil program")
	}
	out, _, err := p.prog.Eval(vars)
	if err != nil {
		return nil, fmt.Errorf("evaluating %q: %w", p.source, err)
	}
	vals, err := stringsOf(out)
	if err != nil {
		return nil, fmt.Errorf("evaluating %q: %w", p.source, err)
	}
	cleaned := make([]string, 0, len(vals))
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			cleaned = append(cleaned, v)
		}
	}
	return cleaned, nil
}

// stringsOf converts a CEL result into a string slice, accepting a string, a
// list of strings, and an optional of either.
func stringsOf(out ref.Val) ([]string, error) {
	if opt, ok := out.(*types.Optional); ok {
		if !opt.HasValue() {
			return nil, nil
		}
		return stringsOf(opt.GetValue())
	}
	switch v := out.Value().(type) {
	case string:
		return []string{v}, nil
	case []string:
		return v, nil
	}
	lister, ok := out.(traitsLister)
	if !ok {
		return nil, fmt.Errorf("result is %s, not a string or a list of strings", out.Type().TypeName())
	}
	n := lister.Size()
	size, ok := n.Value().(int64)
	if !ok {
		return nil, fmt.Errorf("result is %s, not a string or a list of strings", out.Type().TypeName())
	}
	outVals := make([]string, 0, size)
	for i := int64(0); i < size; i++ {
		elem := lister.Get(types.Int(i))
		s, ok := elem.Value().(string)
		if !ok {
			return nil, fmt.Errorf("result list element %d is %s, not a string", i, elem.Type().TypeName())
		}
		outVals = append(outVals, s)
	}
	return outVals, nil
}

// traitsLister is the subset of the CEL lister trait this package needs. It is
// declared locally so the conversion above does not drag cel-go's traits
// package into every file that touches a result.
type traitsLister interface {
	Size() ref.Val
	Get(index ref.Val) ref.Val
}
