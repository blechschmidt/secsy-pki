package celexpr

import (
	"fmt"
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
)

// Object-typed environments and verdict-shaped results, added for the issuance
// restriction engine (see internal/celpolicy).
//
// A role mapping reasons about a handful of strings and one claim map, so the
// map-shaped vocabulary in celexpr.go is the whole of what it needs. A
// certificate request is a *structure* — names nested under a subject, a key
// under an algorithm, a URL under its segments — and expressing that as
// map(string, dyn) costs the expression author the one thing CEL is good at:
// a field typo like `request.dns_name` would compile and then be a runtime
// error on the signing path, i.e. a denied issuance discovered in production.
//
// Declaring the request as a native Go struct instead gives the compiler the
// field set, so the typo is a load-time error with a column in it, and
// `request.not_after` is known to be a timestamp before anyone issues anything.

// ObjectVar declares a variable whose type is one of the Go structs registered
// with an environment through NewObjectEnv. typeName is the CEL name of that
// struct: its Go package name and type name joined by a dot, e.g.
// "celpolicy.CertRequest" for celpolicy.CertRequest.
//
// Unlike MapVar, every field of an object variable is always present (a struct
// has no absent fields), so an expression over one needs no has() guard; a
// field that was not populated reads as its zero value.
func ObjectVar(name, typeName, doc string) Var {
	return Var{name: name, typ: cel.ObjectType(typeName), doc: doc}
}

// TimestampVar declares a timestamp variable, which CEL compares with the
// standard operators and offsets with a duration. It is how evaluation time
// enters an expression: the clock is read by the caller and handed in, never
// read by the expression (see Functions).
func TimestampVar(name, doc string) Var {
	return Var{name: name, typ: cel.TimestampType, doc: doc}
}

// NewObjectEnv builds an environment that additionally understands the Go
// structs in prototypes, so a Var declared with ObjectVar can name one.
//
// Pass one zero value per struct type the expressions may traverse, including
// the nested ones — cel-go reflects over each registered type's own fields, and
// a field whose type was not registered is not reachable. Field names come from
// the `cel:"…"` struct tag where present, so the vocabulary an operator writes
// is chosen deliberately (snake_case, matching the JSON an API caller sees)
// rather than inherited from Go's exported-identifier casing.
func NewObjectEnv(prototypes []any, vars ...Var) (*Env, error) {
	if len(prototypes) == 0 {
		return nil, fmt.Errorf("celexpr: NewObjectEnv needs at least one prototype")
	}
	native, err := nativeTypeOption(prototypes)
	if err != nil {
		return nil, err
	}
	return newEnv([]cel.EnvOption{native}, vars)
}

// nativeTypeOption builds the cel-go native-type provider for prototypes,
// keeping the ext/reflect imports out of every caller. cel-go reflects over a
// reflect.Type or reflect.Value, so a plain zero value is wrapped here rather
// than at every call site.
func nativeTypeOption(prototypes []any) (cel.EnvOption, error) {
	args := make([]any, 0, len(prototypes)+1)
	args = append(args, ext.ParseStructTags(true))
	for _, p := range prototypes {
		switch v := p.(type) {
		case reflect.Type, reflect.Value:
			args = append(args, v)
		case nil:
			return nil, fmt.Errorf("celexpr: nil prototype")
		default:
			args = append(args, reflect.ValueOf(p))
		}
	}
	opt := ext.NativeTypes(args...)
	if opt == nil {
		return nil, fmt.Errorf("celexpr: building native type provider")
	}
	return opt, nil
}

// ResultKind names which of the three shapes an AnyProgram produced.
type ResultKind int

const (
	// KindBool is a bool result: the expression stated a condition.
	KindBool ResultKind = iota
	// KindString is a string result: the expression stated a message, with the
	// empty string meaning "nothing to say".
	KindString
	// KindStrings is a list-of-strings result: the expression stated zero or
	// more messages.
	KindStrings
)

// Result is the value an AnyProgram evaluated to. Exactly one of the fields is
// meaningful, named by Kind.
type Result struct {
	Kind    ResultKind
	Bool    bool
	Strings []string
}

// AnyProgram is a compiled expression whose result may be a bool, a string, or
// a list of strings — the three shapes a policy rule has reason to produce. A
// rule that states a condition returns a bool; a rule that wants to *explain
// itself* returns the explanation, and returns nothing to say when it is
// satisfied. Deciding between them per rule, rather than per engine, is what
// lets one rule read `request.validity_days <= 90` and the next produce
// "requested 400 days; this profile allows at most 90".
type AnyProgram struct {
	prog   cel.Program
	source string
	kind   ResultKind
	// static is true when the compiler deduced the result type exactly, so Eval
	// cannot see a different shape. A dyn result (a lookup into a claim map) is
	// resolved per evaluation instead.
	static bool
}

// Source returns the expression text the program was compiled from.
func (p *AnyProgram) Source() string {
	if p == nil {
		return ""
	}
	return p.source
}

// Kind returns the result shape the compiler deduced, and whether it did so
// statically. A non-static kind is KindBool by convention and is overridden by
// whatever the evaluation actually produces.
func (p *AnyProgram) Kind() (ResultKind, bool) {
	if p == nil {
		return KindBool, false
	}
	return p.kind, p.static
}

// CompileAny compiles expr, accepting a bool, a string, or a list(string)
// result (or dyn, which is resolved at evaluation). Any other deduced type is a
// compile error naming what it got, so a rule that accidentally yields an int
// is a load-time failure rather than a rule that silently never fires.
func (e *Env) CompileAny(expr string) (*AnyProgram, error) {
	prog, err := e.compile(expr, "bool, string or list(string)",
		cel.BoolType,
		cel.StringType,
		cel.ListType(cel.StringType),
		types.NewOptionalType(cel.StringType),
		types.NewOptionalType(cel.ListType(cel.StringType)))
	if err != nil {
		return nil, err
	}
	p := &AnyProgram{prog: prog, source: trimExpr(expr)}
	p.kind, p.static = deducedKind(e, expr)
	return p, nil
}

// deducedKind re-reads the compiled output type to classify the result shape.
// It is a second, cheap compile rather than a change to compile's signature so
// the existing result-typed entry points stay untouched.
func deducedKind(e *Env, expr string) (ResultKind, bool) {
	ast, iss := e.env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return KindBool, false
	}
	got := ast.OutputType()
	switch {
	case got.IsExactType(cel.BoolType):
		return KindBool, true
	case got.IsExactType(cel.StringType), got.IsExactType(types.NewOptionalType(cel.StringType)):
		return KindString, true
	case got.IsExactType(cel.ListType(cel.StringType)),
		got.IsExactType(types.NewOptionalType(cel.ListType(cel.StringType))):
		return KindStrings, true
	}
	return KindBool, false
}

// Eval evaluates the program against vars and classifies its result. A result
// that is none of the three accepted shapes — which only a dyn-typed expression
// can produce, since the others were rejected at compile time — is an error, and
// every caller must treat an error as a policy failure rather than a pass.
func (p *AnyProgram) Eval(vars map[string]interface{}) (Result, error) {
	if p == nil || p.prog == nil {
		return Result{}, fmt.Errorf("celexpr: nil program")
	}
	out, _, err := p.prog.Eval(vars)
	if err != nil {
		return Result{}, fmt.Errorf("evaluating %q: %w", p.source, err)
	}
	res, err := classify(out)
	if err != nil {
		return Result{}, fmt.Errorf("evaluating %q: %w", p.source, err)
	}
	return res, nil
}

// classify maps a CEL value onto a Result. An optional is unwrapped: an absent
// optional is the empty message list, which reads as "nothing to say".
func classify(out ref.Val) (Result, error) {
	if opt, ok := out.(*types.Optional); ok {
		if !opt.HasValue() {
			return Result{Kind: KindStrings}, nil
		}
		return classify(opt.GetValue())
	}
	if b, ok := out.Value().(bool); ok {
		return Result{Kind: KindBool, Bool: b}, nil
	}
	if s, ok := out.Value().(string); ok {
		return Result{Kind: KindString, Strings: []string{s}}, nil
	}
	vals, err := stringsOf(out)
	if err != nil {
		return Result{}, fmt.Errorf("result is %s, not a bool, a string or a list of strings",
			out.Type().TypeName())
	}
	return Result{Kind: KindStrings, Strings: vals}, nil
}
