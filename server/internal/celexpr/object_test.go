package celexpr

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Tests for the object-typed environment and the three-shape result program.
//
// These exist for the same reason the feature does: a map-shaped vocabulary
// lets `x.feild` compile and fail later, and "later" on this layer's call sites
// means a denied certificate or a denied login. So the headline assertions are
// that a field typo is a COMPILE error, and that every result an expression can
// produce is either classified or refused — never quietly misread.

// sample is the struct the tests expose to CEL. The `cel` tags fix the
// vocabulary at snake_case, which is the property NewObjectEnv is asked to
// honor.
type sample struct {
	Name     string            `cel:"name"`
	Count    int               `cel:"count"`
	Ratio    float64           `cel:"ratio"`
	Enabled  bool              `cel:"enabled"`
	Tags     []string          `cel:"tags"`
	Labels   map[string]string `cel:"labels"`
	When     time.Time         `cel:"when"`
	Window   time.Duration     `cel:"window"`
	Nested   nested            `cel:"nested"`
	Untagged string
	hidden   string //nolint:unused // asserts an unexported field is unreachable
}

type nested struct {
	Inner string `cel:"inner"`
}

func sampleEnv(t *testing.T) *Env {
	t.Helper()
	env, err := NewObjectEnv(
		[]any{sample{}, nested{}},
		ObjectVar("s", "celexpr.sample", "the sample object"),
		TimestampVar("now", "evaluation time"),
	)
	if err != nil {
		t.Fatalf("NewObjectEnv: %v", err)
	}
	return env
}

func sampleActivation() map[string]interface{} {
	return map[string]interface{}{
		"s": sample{
			Name:     "alpha",
			Count:    7,
			Ratio:    1.5,
			Enabled:  true,
			Tags:     []string{"a", "b"},
			Labels:   map[string]string{"k": "v"},
			When:     time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
			Window:   90 * 24 * time.Hour,
			Nested:   nested{Inner: "deep"},
			Untagged: "u",
			hidden:   "no",
		},
		"now": time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
	}
}

func TestObjectEnvResolvesEveryFieldKind(t *testing.T) {
	env := sampleEnv(t)
	act := sampleActivation()
	for _, expr := range []string{
		`s.name == "alpha"`,
		`s.count == 7`,
		`s.ratio > 1.0`,
		`s.enabled`,
		`s.tags.size() == 2 && "a" in s.tags`,
		`s.labels["k"] == "v"`,
		`s.when < now`,
		`s.window == duration("2160h")`,
		`s.nested.inner == "deep"`,
		// A field without a `cel` tag keeps its Go name, which is the documented
		// fallback — and is why every field this system exposes carries a tag.
		`s.Untagged == "u"`,
	} {
		prog, err := env.CompileBool(expr)
		if err != nil {
			t.Errorf("compile %q: %v", expr, err)
			continue
		}
		got, err := prog.Eval(act)
		if err != nil {
			t.Errorf("eval %q: %v", expr, err)
			continue
		}
		if !got {
			t.Errorf("%q evaluated false", expr)
		}
	}
}

// TestObjectEnvRejectsUnknownFields is the point of the whole file: a typo is a
// load error with a position in it.
func TestObjectEnvRejectsUnknownFields(t *testing.T) {
	env := sampleEnv(t)
	for _, expr := range []string{
		`s.nmae == "alpha"`,   // transposed
		`s.Name == "alpha"`,   // the tag renamed it to lowercase
		`s.hidden == "no"`,    // unexported
		`s.nested.innr == ""`, // nested typo
	} {
		_, err := env.CompileBool(expr)
		if err == nil {
			t.Errorf("%q compiled; an unknown field must be a load error", expr)
			continue
		}
		if !strings.Contains(err.Error(), "1:") {
			t.Errorf("%q: the error carries no position: %v", expr, err)
		}
	}
}

func TestObjectVarNeedsARegisteredType(t *testing.T) {
	// Declaring an object variable whose type was not registered leaves the
	// field set unknown, so an expression over it cannot compile. The failure
	// must surface at compile time, not at evaluation.
	env, err := NewObjectEnv([]any{nested{}}, ObjectVar("s", "celexpr.sample", "unregistered"))
	if err != nil {
		t.Fatalf("NewObjectEnv: %v", err)
	}
	if _, err := env.CompileBool(`s.name == "x"`); err == nil {
		t.Error("an expression over an unregistered object type compiled")
	}
}

func TestNewObjectEnvRejectsBadPrototypes(t *testing.T) {
	if _, err := NewObjectEnv(nil, StringVar("x", "")); err == nil {
		t.Error("NewObjectEnv accepted an empty prototype list")
	}
	if _, err := NewObjectEnv([]any{nil}, StringVar("x", "")); err == nil {
		t.Error("NewObjectEnv accepted a nil prototype")
	}
	// A reflect.Type or reflect.Value may be passed directly.
	if _, err := NewObjectEnv([]any{reflect.TypeOf(sample{}), reflect.ValueOf(nested{})},
		ObjectVar("s", "celexpr.sample", "")); err != nil {
		t.Errorf("NewObjectEnv rejected reflect.Type/Value prototypes: %v", err)
	}
	// A declaration mistake is reported the same way as through NewEnv.
	if _, err := NewObjectEnv([]any{sample{}}, StringVar("", "no name")); err == nil {
		t.Error("NewObjectEnv accepted a variable with no name")
	}
}

func TestTimestampVarIsNotAClock(t *testing.T) {
	env := sampleEnv(t)
	for _, v := range env.Vars() {
		if v.Name() != "now" {
			continue
		}
		if v.Type() != "google.protobuf.Timestamp" {
			t.Errorf("now has CEL type %q", v.Type())
		}
	}
	// The variable is supplied by the caller; the environment still exposes no
	// now() function, so an expression cannot read the clock itself.
	if _, err := env.CompileBool(`now() > now`); err == nil {
		t.Error("now() compiled; the environment must expose no clock")
	}
}

// --- CompileAny / the three result shapes ---

func TestCompileAnyAcceptsTheThreeShapes(t *testing.T) {
	env := sampleEnv(t)
	cases := []struct {
		expr string
		kind ResultKind
		boo  bool
		strs []string
	}{
		{`s.count > 3`, KindBool, true, nil},
		{`s.count > 30`, KindBool, false, nil},
		{`"a reason"`, KindString, false, []string{"a reason"}},
		{`""`, KindString, false, []string{""}},
		{`s.tags`, KindStrings, false, []string{"a", "b"}},
		{`s.tags.filter(x, false)`, KindStrings, false, []string{}},
		{`s.count > 3 ? "too many" : ""`, KindString, false, []string{"too many"}},
		// An optional unwraps, and an absent one is "nothing to say".
		{`regex.extract(s.name, "^(al)")`, KindString, false, []string{"al"}},
		{`regex.extract(s.name, "^(zz)")`, KindStrings, false, nil},
	}
	for _, c := range cases {
		prog, err := env.CompileAny(c.expr)
		if err != nil {
			t.Errorf("compile %q: %v", c.expr, err)
			continue
		}
		res, err := prog.Eval(sampleActivation())
		if err != nil {
			t.Errorf("eval %q: %v", c.expr, err)
			continue
		}
		if res.Kind != c.kind {
			t.Errorf("%q: kind = %d, want %d", c.expr, res.Kind, c.kind)
			continue
		}
		if c.kind == KindBool {
			if res.Bool != c.boo {
				t.Errorf("%q: bool = %v, want %v", c.expr, res.Bool, c.boo)
			}
			continue
		}
		if len(res.Strings) != len(c.strs) {
			t.Errorf("%q: strings = %v, want %v", c.expr, res.Strings, c.strs)
			continue
		}
		for i := range c.strs {
			if res.Strings[i] != c.strs[i] {
				t.Errorf("%q: strings = %v, want %v", c.expr, res.Strings, c.strs)
				break
			}
		}
	}
}

func TestCompileAnyRejectsOtherResultTypes(t *testing.T) {
	env := sampleEnv(t)
	for _, expr := range []string{
		`s.count`,  // int
		`s.ratio`,  // double
		`s.when`,   // timestamp
		`s.window`, // duration
		`s.nested`, // object
		`s.labels`, // map
		`[1, 2]`,   // list(int)
		`[]`,       // untyped list
	} {
		if _, err := env.CompileAny(expr); err == nil {
			t.Errorf("%q compiled; only bool, string and list(string) are usable", expr)
		}
	}
}

func TestCompileAnyReportsTheDeducedKind(t *testing.T) {
	env := sampleEnv(t)
	cases := map[string]struct {
		kind   ResultKind
		static bool
	}{
		`s.count > 3`:                {KindBool, true},
		`"x"`:                        {KindString, true},
		`s.tags`:                     {KindStrings, true},
		`regex.extract(s.name, "x")`: {KindString, true},
		// A dyn result (a lookup into a dynamic map) is resolved at evaluation.
		`dyn(s.labels)["k"]`: {KindBool, false},
	}
	for expr, want := range cases {
		prog, err := env.CompileAny(expr)
		if err != nil {
			t.Errorf("compile %q: %v", expr, err)
			continue
		}
		kind, static := prog.Kind()
		if kind != want.kind || static != want.static {
			t.Errorf("%q: kind/static = %d/%v, want %d/%v", expr, kind, static, want.kind, want.static)
		}
		if prog.Source() != expr {
			t.Errorf("%q: Source() = %q", expr, prog.Source())
		}
	}
}

// TestCompileAnyDynResultIsClassifiedAtEvaluation: a dyn-typed expression gets
// past the static gate, so the classification happens on the value — and a value
// that is none of the three shapes is an error rather than a silent misreading.
func TestCompileAnyDynResultIsClassifiedAtEvaluation(t *testing.T) {
	env, err := NewObjectEnv([]any{sample{}, nested{}},
		ObjectVar("s", "celexpr.sample", ""),
		MapVar("m", "a dynamic map"))
	if err != nil {
		t.Fatal(err)
	}
	prog, err := env.CompileAny(`m.v`)
	if err != nil {
		t.Fatalf("a dyn expression must compile: %v", err)
	}
	cases := []struct {
		val  interface{}
		kind ResultKind
		ok   bool
	}{
		{true, KindBool, true},
		{"why not", KindString, true},
		{[]string{"a", "b"}, KindStrings, true},
		{[]interface{}{"a"}, KindStrings, true},
		{42, 0, false},                          // an int result is unusable
		{map[string]string{"a": "b"}, 0, false}, // so is a map
		{[]interface{}{1, 2}, 0, false},         // and so is a list of non-strings
	}
	for _, c := range cases {
		res, err := prog.Eval(map[string]interface{}{
			"s": sample{}, "m": map[string]interface{}{"v": c.val},
		})
		if c.ok {
			if err != nil {
				t.Errorf("%#v: Eval failed: %v", c.val, err)
				continue
			}
			if res.Kind != c.kind {
				t.Errorf("%#v: kind = %d, want %d", c.val, res.Kind, c.kind)
			}
			continue
		}
		if err == nil {
			t.Errorf("%#v: Eval accepted an unusable result as %+v", c.val, res)
			continue
		}
		if !strings.Contains(err.Error(), "not a bool, a string or a list of strings") {
			t.Errorf("%#v: the error does not say what was wrong: %v", c.val, err)
		}
	}
}

func TestCompileAnyRuntimeErrorsAreReported(t *testing.T) {
	env := sampleEnv(t)
	prog, err := env.CompileAny(`s.tags[99] == "x"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := prog.Eval(sampleActivation()); err == nil {
		t.Fatal("an out-of-range index evaluated successfully")
	} else if !strings.Contains(err.Error(), "evaluating") {
		t.Errorf("the error does not name the evaluation: %v", err)
	}
}

func TestCompileAnyCostCeilingApplies(t *testing.T) {
	env, err := NewObjectEnv([]any{sample{}, nested{}}, ObjectVar("s", "celexpr.sample", ""))
	if err != nil {
		t.Fatal(err)
	}
	prog, err := env.CompileAny(`s.tags.all(a, s.tags.all(b, a != b || a == b))`)
	if err != nil {
		t.Fatal(err)
	}
	big := make([]string, 400)
	for i := range big {
		big[i] = "tag"
	}
	_, err = prog.Eval(map[string]interface{}{"s": sample{Tags: big}})
	if err == nil {
		t.Fatal("a quadratic comprehension over 400 elements stayed inside the budget")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "cost") {
		t.Errorf("the error does not mention the cost limit: %v", err)
	}
}

func TestAnyProgramNilSafety(t *testing.T) {
	var p *AnyProgram
	if p.Source() != "" {
		t.Error("a nil program reported a source")
	}
	if kind, static := p.Kind(); kind != KindBool || static {
		t.Errorf("a nil program reported kind %d/static %v", kind, static)
	}
	if _, err := p.Eval(nil); err == nil {
		t.Error("evaluating a nil program succeeded")
	}
	if _, err := (&AnyProgram{}).Eval(nil); err == nil {
		t.Error("evaluating a program with no plan succeeded")
	}
}

// TestObjectEnvSharesTheFunctionLibrary: an object environment is not a
// different dialect. Every function the map-shaped environment exposes is
// available here too, because an expression that works in one place must work
// in all of them.
func TestObjectEnvSharesTheFunctionLibrary(t *testing.T) {
	env := sampleEnv(t)
	for _, expr := range []string{
		`s.name.upperAscii() == "ALPHA"`,
		`regex.replace(s.name, "^al", "be") == "bepha"`,
		`sets.contains(s.tags, ["a"])`,
		`s.tags.distinct().size() == 2`,
		`math.greatest(s.count, 1) == 7`,
		`cidr("10.0.0.0/8").containsIP("10.1.2.3")`,
		`base64.encode(b"ab") == "YWI="`,
		`cel.bind(n, s.count, n == 7)`,
		`s.tags.all(i, x, i >= 0 && x != "")`,
	} {
		prog, err := env.CompileBool(expr)
		if err != nil {
			t.Errorf("compile %q: %v", expr, err)
			continue
		}
		got, err := prog.Eval(sampleActivation())
		if err != nil || !got {
			t.Errorf("%q: got %v, err %v", expr, got, err)
		}
	}
}
