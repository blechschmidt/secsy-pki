package secret

// Unit tests for the `secsy-secret exec` injection layer (execenv.go).
//
// Everything here is pure: the parsers turn operator/CI-supplied strings into an
// ExecSpec and BuildExecEnv turns that spec plus a SecretSource into the exact
// (argv, env) a child process is started with. A parsing slip therefore injects
// the wrong secret into a child, leaks one into an unrelated variable, or splices
// an extra variable into the environment — so the tables below lean on malformed
// and adversarial input, and the assertions check the *whole* resulting
// environment rather than just the variable under test.

import (
	"fmt"
	"strings"
	"testing"
)

// recordingSource is a SecretSource over a fixed map that records every lookup,
// so a test can prove which references were resolved (and which were not —
// resolving a secret that should never have been fetched is itself a finding).
type recordingSource struct {
	values map[string]string
	errs   map[string]error
	calls  []string
}

func (r *recordingSource) fn() SecretSource {
	return func(ref string) ([]byte, error) {
		r.calls = append(r.calls, ref)
		if err, ok := r.errs[ref]; ok {
			return nil, err
		}
		v, ok := r.values[ref]
		if !ok {
			return nil, fmt.Errorf("recordingSource: no secret named %q", ref)
		}
		return []byte(v), nil
	}
}

func (r *recordingSource) callCount(ref string) int {
	n := 0
	for _, c := range r.calls {
		if c == ref {
			n++
		}
	}
	return n
}

// envValues indexes an environment slice by variable name, keeping every
// occurrence so duplicate assignments (which the child's runtime would silently
// resolve one way or the other) are visible to assertions.
func envValues(env []string) map[string][]string {
	out := map[string][]string{}
	for _, kv := range env {
		name, value := kv, ""
		if i := strings.Index(kv, "="); i >= 0 {
			name, value = kv[:i], kv[i+1:]
		}
		out[name] = append(out[name], value)
	}
	return out
}

// envOnce returns the single value of name, failing if it is absent or assigned
// more than once.
func envOnce(t *testing.T, env []string, name string) string {
	t.Helper()
	vals := envValues(env)[name]
	switch len(vals) {
	case 1:
		return vals[0]
	case 0:
		t.Fatalf("environment has no %s (env=%q)", name, env)
	default:
		t.Fatalf("environment assigns %s %d times (%q); a child would pick one at random", name, len(vals), vals)
	}
	return ""
}

// countContaining reports how many entries of env contain needle.
func countContaining(env []string, needle string) int {
	n := 0
	for _, kv := range env {
		n += strings.Count(kv, needle)
	}
	return n
}

// TestParseSecretRef exhausts the "name[@version]" grammar. A reference names
// which stored secret (and which historical version of it) ends up in a child
// process, so every malformed form must be rejected outright rather than
// silently reinterpreted, and an accepted name must come back byte-for-byte —
// any truncation or trimming would resolve a *different* secret than the
// operator asked for.
func TestParseSecretRef(t *testing.T) {
	long := strings.Repeat("a", 4096)
	cases := []struct {
		name    string
		in      string
		wantRef string
		wantVer int
		wantErr bool
	}{
		{"unpinned", "db-password", "db-password", 0, false},
		{"pinned", "db-password@3", "db-password", 3, false},
		{"version one", "db@1", "db", 1, false},
		{"large version", "db@2147483647", "db", 2147483647, false},
		{"empty string", "", "", 0, true},
		{"separator only", "@", "", 0, true},
		{"empty name with version", "@3", "", 0, true},
		{"empty version", "db@", "", 0, true},
		{"zero version", "db@0", "", 0, true},
		{"negative version", "db@-1", "", 0, true},
		{"non numeric version", "db@abc", "", 0, true},
		{"trailing junk in version", "db@3x", "", 0, true},
		{"space in version", "db@ 3", "", 0, true},
		{"overflowing version", "db@99999999999999999999", "", 0, true},
		{"whitespace only name", "   ", "", 0, true},
		// An @ inside the name is only tolerated when what follows the LAST @ is
		// a valid version; an e-mail-shaped name is rejected rather than being
		// silently truncated to "user".
		{"email shaped name", "user@example.com", "", 0, true},
		{"last separator wins", "db@3@4", "db@3", 4, false},
		{"degenerate name kept", "@@2", "@", 2, false},
		// Whitespace is NOT trimmed off an accepted name: trimming would look up
		// a different secret than the one the operator typed.
		{"surrounding space preserved", " db ", " db ", 0, false},
		// '=' and ':' are ordinary name bytes here; only DeriveEnvVar/
		// ParseSecretEnv give them meaning.
		{"embedded equals", "db=x", "db=x", 0, false},
		{"embedded colon", "team:db", "team:db", 0, false},
		// A NUL must not truncate the name (a C-string truncation bug here would
		// silently resolve the secret "db" for the reference "db\x00evil").
		{"embedded NUL", "db\x00evil", "db\x00evil", 0, false},
		{"non utf8 name", "db-\xff\xfe", "db-\xff\xfe", 0, false},
		{"very long name", long, long, 0, false},
		{"very long name pinned", long + "@7", long, 7, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotRef, gotVer, err := ParseSecretRef(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSecretRef(%q) = (%q, %d, nil), want an error", tc.in, gotRef, gotVer)
				}
				// A rejected reference must not hand back a usable name or
				// version that a careless caller could still act on.
				if gotRef != "" || gotVer != 0 {
					t.Errorf("rejected ParseSecretRef(%q) returned (%q, %d), want (\"\", 0)", tc.in, gotRef, gotVer)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSecretRef(%q): unexpected error %v", tc.in, err)
			}
			if gotRef != tc.wantRef {
				t.Errorf("ParseSecretRef(%q) name = %q, want %q", tc.in, gotRef, tc.wantRef)
			}
			if gotVer != tc.wantVer {
				t.Errorf("ParseSecretRef(%q) version = %d, want %d", tc.in, gotVer, tc.wantVer)
			}
		})
	}
}

// TestParseSecretEnv covers the CLI -secret grammar "ref[:VAR]". The VAR half
// becomes an environment variable name verbatim, so anything that could splice a
// second assignment into the child's environment ('=', newline, NUL) must be
// refused, and a rejected argument must yield the zero SecretEnv.
func TestParseSecretEnv(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantRef string
		wantVar string
		wantErr bool
	}{
		{"ref only", "db-password", "db-password", "", false},
		{"ref and var", "db-password:DB_PASS", "db-password", "DB_PASS", false},
		{"pinned ref and var", "db-password@2:DB_PASS", "db-password@2", "DB_PASS", false},
		{"underscore prefixed var", "db:_DB", "db", "_DB", false},
		{"lowercase var allowed", "db:db_pass", "db", "db_pass", false},
		{"digits after first char", "db:DB2_PASS", "db", "DB2_PASS", false},
		// The last colon separates, so a colon-bearing secret name still works.
		{"colon in name", "team:db:DB_PASS", "team:db", "DB_PASS", false},
		{"empty string", "", "", "", true},
		{"empty var", "db:", "", "", true},
		{"empty ref", ":DB_PASS", "", "", true},
		{"trailing colon after var", "db:DB_PASS:", "", "", true},
		{"leading digit var", "db:1DB", "", "", true},
		{"dash in var", "db:DB-PASS", "", "", true},
		{"space in var", "db:DB PASS", "", "", true},
		{"dot in var", "db:DB.PASS", "", "", true},
		// Splicing attempts: each of these would, unchecked, turn one injected
		// variable into two (or corrupt an unrelated one).
		{"equals in var", "db:DB_PASS=EVIL", "", "", true},
		{"newline in var", "db:DB_PASS\nEVIL", "", "", true},
		{"carriage return in var", "db:DB_PASS\rEVIL", "", "", true},
		{"NUL in var", "db:DB_PASS\x00", "", "", true},
		{"non utf8 var", "db:DB_\xff", "", "", true},
		{"bad version with var", "db@0:DB_PASS", "", "", true},
		{"bad version without var", "db@x", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSecretEnv(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSecretEnv(%q) = %+v, nil; want an error", tc.in, got)
				}
				if got != (SecretEnv{}) {
					t.Errorf("rejected ParseSecretEnv(%q) returned %+v, want the zero value", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSecretEnv(%q): unexpected error %v", tc.in, err)
			}
			if got.Ref != tc.wantRef || got.Var != tc.wantVar {
				t.Errorf("ParseSecretEnv(%q) = {Ref:%q Var:%q}, want {Ref:%q Var:%q}", tc.in, got.Ref, got.Var, tc.wantRef, tc.wantVar)
			}
		})
	}
}

// TestParseEnvTemplate covers the CLI -env grammar "VAR=value". The split is on
// the FIRST '=' so values that legitimately contain '=' (base64, DSNs) survive
// intact, and the name half is held to the portable charset so it cannot carry a
// second assignment.
func TestParseEnvTemplate(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantVar   string
		wantValue string
		wantErr   bool
	}{
		{"simple", "DSN=postgres://h/db", "DSN", "postgres://h/db", false},
		{"empty value allowed", "DSN=", "DSN", "", false},
		// First '=' splits: the remainder, equals signs and all, is the value.
		{"equals in value", "TOKEN=a=b==", "TOKEN", "a=b==", false},
		{"placeholder value", "DSN=pg://u:{{secret:db}}@h/db", "DSN", "pg://u:{{secret:db}}@h/db", false},
		{"lowercase name", "dsn=x", "dsn", "x", false},
		{"underscore name", "_DSN=x", "_DSN", "x", false},
		{"digits in name", "DSN2=x", "DSN2", "x", false},
		{"newline in value kept", "DSN=a\nb", "DSN", "a\nb", false},
		{"empty string", "", "", "", true},
		{"no separator", "DSN", "", "", true},
		{"empty name", "=value", "", "", true},
		{"leading digit name", "1DSN=x", "", "", true},
		{"dash in name", "MY-DSN=x", "", "", true},
		{"space in name", "MY DSN=x", "", "", true},
		{"leading space in name", " DSN=x", "", "", true},
		{"trailing space in name", "DSN =x", "", "", true},
		{"newline in name", "DSN\nEVIL=x", "", "", true},
		{"NUL in name", "DSN\x00=x", "", "", true},
		{"non utf8 name", "DS\xffN=x", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEnvTemplate(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseEnvTemplate(%q) = %+v, nil; want an error", tc.in, got)
				}
				if got != (EnvTemplate{}) {
					t.Errorf("rejected ParseEnvTemplate(%q) returned %+v, want the zero value", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnvTemplate(%q): unexpected error %v", tc.in, err)
			}
			if got.Var != tc.wantVar || got.Value != tc.wantValue {
				t.Errorf("ParseEnvTemplate(%q) = {Var:%q Value:%q}, want {Var:%q Value:%q}", tc.in, got.Var, got.Value, tc.wantVar, tc.wantValue)
			}
		})
	}
}

// TestDeriveEnvVarShape checks the derived name for the shapes real secret names
// take. The load-bearing property is the last assertion of every case: whatever
// comes out MUST be a portable environment-variable name, because BuildExecEnv
// refuses to inject anything else.
func TestDeriveEnvVarShape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"db-password@3", "DB_PASSWORD"}, // the documented example
		{"db-password", "DB_PASSWORD"},
		{"db.password", "DB_PASSWORD"},
		{"db password", "DB_PASSWORD"},
		{"db/password", "DB_PASSWORD"},
		{"DB_PASSWORD", "DB_PASSWORD"},
		{"lower", "LOWER"},
		{"api-key-2", "API_KEY_2"},
		// A leading digit is not a portable start character, so it is prefixed.
		{"3db", "_3DB"},
		{"9", "_9"},
		// Degenerate references still produce a usable name rather than "".
		{"", "_"},
		{"@", "_"},
		{"-", "_"},
		// An unparseable version suffix stays part of the folded name (only a
		// VALID @N suffix is stripped), so "db@2" and "db@abc" differ.
		{"db@2", "DB"},
		{"db@abc", "DB_ABC"},
		// One '_' per rune, not per UTF-8 byte: a multi-byte character must not
		// silently expand into several underscores.
		{"café", "CAF_"},
		{"db\x00evil", "DB_EVIL"},
		{"\xff", "_"},
		{"a=b", "A_B"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := DeriveEnvVar(tc.in)
			if got != tc.want {
				t.Errorf("DeriveEnvVar(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if !envVarNameRe.MatchString(got) {
				t.Errorf("DeriveEnvVar(%q) = %q, which is not a portable environment variable name", tc.in, got)
			}
		})
	}
}

// TestDeriveEnvVarAlwaysPortable is the property behind the table above: no
// reference, however hostile, may derive a name that could splice a second
// assignment into the child's environment or start with a digit.
func TestDeriveEnvVarAlwaysPortable(t *testing.T) {
	refs := []string{
		"", " ", "\t", "@", "@@", "@1", "a@1", "0", "007", "-x", "_", "__",
		"a=b", "a\nb", "a\x00b", "a\rb", "PATH=", "=PATH", "\xff\xfe\x00",
		"каф", "ß", "\U0001F600", strings.Repeat("-", 64),
		"very-long-" + strings.Repeat("x", 300), "a.b.c", "a b c", "a/b\\c",
		"{{secret:x}}", "db@2147483648", "db@+2", "db@007",
	}
	for _, ref := range refs {
		got := DeriveEnvVar(ref)
		if !envVarNameRe.MatchString(got) {
			t.Errorf("DeriveEnvVar(%q) = %q, which is not a portable environment variable name", ref, got)
		}
		if strings.ContainsAny(got, "=\n\r\x00") {
			t.Errorf("DeriveEnvVar(%q) = %q, which can splice an extra assignment into the environment", ref, got)
		}
	}
}

// TestDeriveEnvVarCollisionsFailClosed pins down what happens when two DIFFERENT
// secret names fold to the SAME environment variable. Folding every
// non-alphanumeric to '_' makes such collisions unavoidable by construction
// ("a-b", "a_b" and "a.b" are all A_B), so the safety property cannot be
// "derivation is injective" — it has to be "BuildExecEnv refuses the ambiguous
// spec". Silently keeping one of the two would inject one secret under a name
// the operator expects to hold the other.
func TestDeriveEnvVarCollisionsFailClosed(t *testing.T) {
	similar := []string{"a-b", "a_b", "a.b", "a b", "a/b", "A-B", "a-B"}
	for _, ref := range similar {
		if got := DeriveEnvVar(ref); got != "A_B" {
			t.Fatalf("DeriveEnvVar(%q) = %q, want A_B (this test's premise)", ref, got)
		}
	}

	src := &recordingSource{values: map[string]string{"a-b": "first-secret", "a_b": "second-secret"}}
	_, env, _, err := BuildExecEnv(ExecSpec{
		Argv:    []string{"/bin/true"},
		Secrets: []SecretEnv{{Ref: "a-b"}, {Ref: "a_b"}},
	}, src.fn())
	if err == nil {
		t.Fatalf("two references deriving the same variable were accepted; env=%q", env)
	}
	if env != nil {
		t.Errorf("failed BuildExecEnv returned a non-nil environment: %q", env)
	}
	if !strings.Contains(err.Error(), "A_B") {
		t.Errorf("error should name the colliding variable, got: %v", err)
	}

	// The same guard must cover a derived name colliding with an explicitly
	// named one, in either declaration order.
	for _, spec := range []ExecSpec{
		{Argv: []string{"/bin/true"}, Secrets: []SecretEnv{{Ref: "a-b"}, {Ref: "other", Var: "A_B"}}},
		{Argv: []string{"/bin/true"}, Secrets: []SecretEnv{{Ref: "other", Var: "A_B"}, {Ref: "a-b"}}},
	} {
		src := &recordingSource{values: map[string]string{"a-b": "x", "other": "y"}}
		if _, _, _, err := BuildExecEnv(spec, src.fn()); err == nil {
			t.Errorf("explicit/derived collision on A_B was accepted for %+v", spec.Secrets)
		}
	}

	// And an injected secret colliding with an -env template target.
	src = &recordingSource{values: map[string]string{"a-b": "x"}}
	if _, _, _, err := BuildExecEnv(ExecSpec{
		Argv:         []string{"/bin/true"},
		Secrets:      []SecretEnv{{Ref: "a-b"}},
		EnvTemplates: []EnvTemplate{{Var: "A_B", Value: "literal"}},
	}, src.fn()); err == nil {
		t.Error("a secret and an -env template targeting A_B were both accepted")
	}
}

// TestBuildExecEnvInjectsAndPreserves is the happy path, asserted over the whole
// resulting environment: inherited variables survive byte-for-byte, injected
// ones appear exactly once, templates and argv expand, and the audit list of
// used references is deduplicated and sorted.
func TestBuildExecEnvInjectsAndPreserves(t *testing.T) {
	const apiKey = "AKIA-not-a-real-key"
	const dbPass = "pa$$w0rd:with/punct"
	src := &recordingSource{values: map[string]string{"api-key": apiKey, "db-pass": dbPass}}
	base := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/root",
		"LANG=C.UTF-8",
		"EMPTY=",
		"WEIRD",                  // an inherited entry with no '=' at all
		"ODD=a=b",                // a value containing '='
		"MULTILINE=line1\nline2", // a value containing a newline
	}

	argv, env, usedRefs, err := BuildExecEnv(ExecSpec{
		Argv:         []string{"/usr/bin/app", "--token={{secret:api-key}}", "plain", "{{ secret:db-pass }}"},
		Secrets:      []SecretEnv{{Ref: "api-key"}, {Ref: "db-pass@2", Var: "DB_PASSWORD"}},
		EnvTemplates: []EnvTemplate{{Var: "DSN", Value: "postgres://u:{{secret:db-pass}}@h/db"}},
		BaseEnv:      base,
	}, func(ref string) ([]byte, error) {
		// "db-pass@2" is a distinct reference from "db-pass" and must be
		// resolved separately (a pinned version is a different value).
		if ref == "db-pass@2" {
			src.calls = append(src.calls, ref)
			return []byte("pinned-v2"), nil
		}
		return src.fn()(ref)
	})
	if err != nil {
		t.Fatalf("BuildExecEnv: %v", err)
	}

	// Inherited variables are untouched, still exactly once each.
	for _, kv := range base {
		name := kv
		if i := strings.Index(kv, "="); i >= 0 {
			name = kv[:i]
		}
		vals := envValues(env)[name]
		if len(vals) != 1 {
			t.Fatalf("inherited %s appears %d times, want 1 (env=%q)", name, len(vals), env)
		}
	}
	if got := envOnce(t, env, "PATH"); got != "/usr/bin:/bin" {
		t.Errorf("PATH = %q, want the inherited value", got)
	}
	if got := envOnce(t, env, "ODD"); got != "a=b" {
		t.Errorf("ODD = %q, want %q", got, "a=b")
	}
	if got := envOnce(t, env, "MULTILINE"); got != "line1\nline2" {
		t.Errorf("MULTILINE = %q, want the inherited value", got)
	}
	if got := envOnce(t, env, "WEIRD"); got != "" {
		t.Errorf("inherited entry without '=' became %q", got)
	}

	// Injected variables: derived name for the first, explicit for the second.
	if got := envOnce(t, env, "API_KEY"); got != apiKey {
		t.Errorf("API_KEY = %q, want the secret value", got)
	}
	if got := envOnce(t, env, "DB_PASSWORD"); got != "pinned-v2" {
		t.Errorf("DB_PASSWORD = %q, want the pinned version's value", got)
	}
	if got := envOnce(t, env, "DSN"); got != "postgres://u:"+dbPass+"@h/db" {
		t.Errorf("DSN = %q, want the expanded template", got)
	}

	// The plaintext lands in exactly one variable — no accidental second copy.
	if n := countContaining(env, apiKey); n != 1 {
		t.Errorf("the api-key plaintext appears in %d environment entries, want exactly 1 (env=%q)", n, env)
	}
	if n := countContaining(env, dbPass); n != 1 {
		t.Errorf("the db-pass plaintext appears in %d environment entries, want exactly 1", n)
	}

	// Argv expansion, including a spaced placeholder; untouched tokens stay put.
	want := []string{"/usr/bin/app", "--token=" + apiKey, "plain", dbPass}
	if len(argv) != len(want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}

	// Each distinct reference is resolved exactly once even though "api-key" and
	// "db-pass" are each used twice (env + argv / env + template).
	if n := src.callCount("api-key"); n != 1 {
		t.Errorf("api-key resolved %d times, want 1 (caching prevents extra HSM round-trips)", n)
	}
	if n := src.callCount("db-pass"); n != 1 {
		t.Errorf("db-pass resolved %d times, want 1", n)
	}
	// usedRefs is the audit record: deduplicated, sorted, and covering argv-only
	// uses too.
	wantRefs := []string{"api-key", "db-pass", "db-pass@2"}
	if strings.Join(usedRefs, ",") != strings.Join(wantRefs, ",") {
		t.Errorf("usedRefs = %q, want %q", usedRefs, wantRefs)
	}
}

// TestBuildExecEnvOverridesDeterministically: an injected variable must shadow
// every inherited assignment of the same name, leaving exactly one entry, so the
// child cannot pick up a stale value depending on how it walks its environment.
func TestBuildExecEnvOverridesDeterministically(t *testing.T) {
	src := &recordingSource{values: map[string]string{"api-key": "fresh"}}
	_, env, _, err := BuildExecEnv(ExecSpec{
		Argv:         []string{"/bin/true"},
		Secrets:      []SecretEnv{{Ref: "api-key"}},
		EnvTemplates: []EnvTemplate{{Var: "TOKEN", Value: "new-token"}},
		BaseEnv: []string{
			"API_KEY=stale-one",
			"KEEP=kept",
			"API_KEY=stale-two", // a duplicate inherited assignment
			"API_KEY",           // and a bare name with no value
			"TOKEN=stale-token",
		},
	}, src.fn())
	if err != nil {
		t.Fatalf("BuildExecEnv: %v", err)
	}
	if got := envOnce(t, env, "API_KEY"); got != "fresh" {
		t.Errorf("API_KEY = %q, want the injected value", got)
	}
	if got := envOnce(t, env, "TOKEN"); got != "new-token" {
		t.Errorf("TOKEN = %q, want the template value", got)
	}
	if got := envOnce(t, env, "KEEP"); got != "kept" {
		t.Errorf("KEEP = %q, want it untouched", got)
	}
	if countContaining(env, "stale") != 0 {
		t.Errorf("a shadowed inherited value survived: %q", env)
	}

	// A nil BaseEnv yields exactly the injected variables and nothing else.
	_, clean, _, err := BuildExecEnv(ExecSpec{
		Argv:    []string{"/bin/true"},
		Secrets: []SecretEnv{{Ref: "api-key"}},
	}, src.fn())
	if err != nil {
		t.Fatalf("BuildExecEnv (clean env): %v", err)
	}
	if len(clean) != 1 || clean[0] != "API_KEY=fresh" {
		t.Errorf("clean environment = %q, want exactly [API_KEY=fresh]", clean)
	}
}

// TestBuildExecEnvFailsClosed: every rejection path must return nothing at all.
// Handing back a partially built environment — in particular a variable set to
// the empty string after a failed lookup — would let a child treat an empty
// password as a valid one.
func TestBuildExecEnvFailsClosed(t *testing.T) {
	inherited := []string{"PATH=/usr/bin", "DB_PASSWORD=inherited-value"}

	t.Run("lookup failure", func(t *testing.T) {
		src := &recordingSource{
			values: map[string]string{"ok": "value"},
			errs:   map[string]error{"missing": fmt.Errorf("no such secret")},
		}
		argv, env, refs, err := BuildExecEnv(ExecSpec{
			Argv:    []string{"/bin/true"},
			Secrets: []SecretEnv{{Ref: "ok", Var: "OK"}, {Ref: "missing", Var: "DB_PASSWORD"}},
			BaseEnv: inherited,
		}, src.fn())
		if err == nil {
			t.Fatalf("a failed lookup was tolerated; env=%q", env)
		}
		if argv != nil || env != nil || refs != nil {
			t.Fatalf("failed BuildExecEnv returned argv=%q env=%q refs=%q, want all nil", argv, env, refs)
		}
		if !strings.Contains(err.Error(), "missing") {
			t.Errorf("error should name the reference that failed, got: %v", err)
		}
	})

	t.Run("NUL in secret value", func(t *testing.T) {
		src := &recordingSource{values: map[string]string{"binary": "abc\x00def"}}
		_, env, _, err := BuildExecEnv(ExecSpec{
			Argv:    []string{"/bin/true"},
			Secrets: []SecretEnv{{Ref: "binary", Var: "BIN"}},
			BaseEnv: inherited,
		}, src.fn())
		if err == nil {
			t.Fatalf("a NUL-bearing secret was injected instead of refused; env=%q", env)
		}
		if env != nil {
			t.Fatalf("failed BuildExecEnv returned env=%q, want nil", env)
		}
		if countContaining(env, "abc") != 0 {
			t.Error("a truncated prefix of the binary secret leaked into the environment")
		}
	})

	t.Run("NUL through a template placeholder", func(t *testing.T) {
		// The same guard must apply when the secret arrives via {{secret:...}}
		// rather than a direct injection.
		src := &recordingSource{values: map[string]string{"binary": "abc\x00def"}}
		if _, env, _, err := BuildExecEnv(ExecSpec{
			Argv:         []string{"/bin/true"},
			EnvTemplates: []EnvTemplate{{Var: "BIN", Value: "x{{secret:binary}}y"}},
		}, src.fn()); err == nil {
			t.Fatalf("a NUL-bearing secret was templated into the environment; env=%q", env)
		}
		// And when it arrives through argv, where it would be truncated by execve.
		if _, _, _, err := BuildExecEnv(ExecSpec{
			Argv: []string{"/bin/true", "{{secret:binary}}"},
		}, src.fn()); err == nil {
			t.Fatal("a NUL-bearing secret was expanded into argv")
		}
	})

	t.Run("no command", func(t *testing.T) {
		src := &recordingSource{values: map[string]string{"api-key": "v"}}
		for _, argv := range [][]string{nil, {}, {""}, {"", "arg"}} {
			_, env, _, err := BuildExecEnv(ExecSpec{
				Argv:    argv,
				Secrets: []SecretEnv{{Ref: "api-key"}},
				BaseEnv: inherited,
			}, src.fn())
			if err == nil {
				t.Errorf("BuildExecEnv accepted argv=%q; env=%q", argv, env)
			}
		}
		// Nothing may be decrypted before the spec is known to be runnable.
		if len(src.calls) != 0 {
			t.Errorf("secrets were resolved for an unrunnable spec: %q", src.calls)
		}
	})

	t.Run("unportable explicit variable name", func(t *testing.T) {
		// ParseSecretEnv normally screens these, so this covers a programmatic
		// caller (server handler, another CLI) building the spec directly.
		// An empty Var is NOT in this list: it legitimately means "derive the
		// name from the reference" (see the happy-path test).
		src := &recordingSource{values: map[string]string{"api-key": "v"}}
		for _, bad := range []string{"BAD-NAME", "1BAD", "BAD NAME", "BAD=EVIL", "PATH\nEVIL", "BAD\x00"} {
			_, env, _, err := BuildExecEnv(ExecSpec{
				Argv:    []string{"/bin/true"},
				Secrets: []SecretEnv{{Ref: "api-key", Var: bad}},
				BaseEnv: inherited,
			}, src.fn())
			if err == nil {
				t.Errorf("BuildExecEnv accepted the variable name %q; env=%q", bad, env)
			}
		}
		// The name is vetted before the secret is fetched: a doomed request must
		// not cost an HSM decryption (or an audit-worthy access).
		if len(src.calls) != 0 {
			t.Errorf("secrets were resolved for a spec with an invalid variable name: %q", src.calls)
		}
	})

	t.Run("duplicate explicit target", func(t *testing.T) {
		src := &recordingSource{values: map[string]string{"a": "1", "b": "2"}}
		_, env, _, err := BuildExecEnv(ExecSpec{
			Argv:    []string{"/bin/true"},
			Secrets: []SecretEnv{{Ref: "a", Var: "TOKEN"}, {Ref: "b", Var: "TOKEN"}},
			BaseEnv: inherited,
		}, src.fn())
		if err == nil {
			t.Fatalf("two secrets injected into TOKEN were accepted; env=%q", env)
		}
		if env != nil {
			t.Errorf("failed BuildExecEnv returned env=%q, want nil", env)
		}
	})

	t.Run("duplicate template target", func(t *testing.T) {
		src := &recordingSource{}
		if _, _, _, err := BuildExecEnv(ExecSpec{
			Argv:         []string{"/bin/true"},
			EnvTemplates: []EnvTemplate{{Var: "TOKEN", Value: "a"}, {Var: "TOKEN", Value: "b"}},
		}, src.fn()); err == nil {
			t.Error("two -env templates targeting TOKEN were accepted (last-wins would be silent)")
		}
	})

	t.Run("failure inside a template", func(t *testing.T) {
		src := &recordingSource{errs: map[string]error{"missing": fmt.Errorf("gone")}}
		argv, env, refs, err := BuildExecEnv(ExecSpec{
			Argv:         []string{"/bin/true"},
			EnvTemplates: []EnvTemplate{{Var: "DSN", Value: "pg://{{secret:missing}}@h"}},
			BaseEnv:      inherited,
		}, src.fn())
		if err == nil {
			t.Fatalf("a failed placeholder lookup was tolerated; env=%q", env)
		}
		if argv != nil || env != nil || refs != nil {
			t.Errorf("failed BuildExecEnv returned argv=%q env=%q refs=%q, want all nil", argv, env, refs)
		}
	})

	t.Run("failure inside argv", func(t *testing.T) {
		src := &recordingSource{errs: map[string]error{"missing": fmt.Errorf("gone")}}
		argv, env, _, err := BuildExecEnv(ExecSpec{
			Argv:    []string{"/bin/true", "--t={{secret:missing}}"},
			BaseEnv: inherited,
		}, src.fn())
		if err == nil {
			t.Fatalf("a failed argv placeholder lookup was tolerated; argv=%q", argv)
		}
		if argv != nil || env != nil {
			t.Errorf("failed BuildExecEnv returned argv=%q env=%q, want nil", argv, env)
		}
	})
}

// TestBuildExecEnvNoRecursiveExpansion: a secret's plaintext is substituted
// literally. If the result were re-scanned, a secret whose value happens to
// contain "{{secret:other}}" would pull an unrelated secret into the child (an
// exfiltration primitive for anyone who can write one secret's value), and a
// value containing regexp replacement syntax like $1 would be mangled.
func TestBuildExecEnvNoRecursiveExpansion(t *testing.T) {
	src := &recordingSource{values: map[string]string{
		"evil":           "{{secret:admin-password}}",
		"admin-password": "SUPER-SECRET",
		"dollars":        "$1$0${VAR}\\1",
	}}
	_, env, usedRefs, err := BuildExecEnv(ExecSpec{
		Argv:         []string{"/bin/true"},
		Secrets:      []SecretEnv{{Ref: "evil", Var: "EVIL"}, {Ref: "dollars", Var: "DOLLARS"}},
		EnvTemplates: []EnvTemplate{{Var: "NESTED", Value: "<{{secret:evil}}>"}},
	}, src.fn())
	if err != nil {
		t.Fatalf("BuildExecEnv: %v", err)
	}
	if got := envOnce(t, env, "EVIL"); got != "{{secret:admin-password}}" {
		t.Errorf("EVIL = %q, want the literal placeholder text", got)
	}
	if got := envOnce(t, env, "NESTED"); got != "<{{secret:admin-password}}>" {
		t.Errorf("NESTED = %q, want the placeholder substituted once, not recursively", got)
	}
	if got := envOnce(t, env, "DOLLARS"); got != "$1$0${VAR}\\1" {
		t.Errorf("DOLLARS = %q, want the value verbatim (no regexp expansion)", got)
	}
	if countContaining(env, "SUPER-SECRET") != 0 {
		t.Fatalf("a nested placeholder pulled an unrelated secret into the environment: %q", env)
	}
	if src.callCount("admin-password") != 0 {
		t.Errorf("admin-password was resolved via a nested placeholder: calls=%q", src.calls)
	}
	for _, ref := range usedRefs {
		if ref == "admin-password" {
			t.Errorf("usedRefs claims admin-password was injected: %q", usedRefs)
		}
	}
}

// TestBuildExecEnvUnmatchedPlaceholders documents how near-miss placeholder
// syntax is treated: text that does not match the placeholder grammar is left
// alone, exactly like any other literal. It is asserted here so a future change
// to the template regexp cannot silently start (or stop) expanding one of these
// forms.
func TestBuildExecEnvUnmatchedPlaceholders(t *testing.T) {
	src := &recordingSource{values: map[string]string{"db": "PLAINTEXT"}}
	spec := ExecSpec{
		Argv: []string{"/bin/true"},
		EnvTemplates: []EnvTemplate{
			{Var: "EMPTY_REF", Value: "{{secret:}}"},
			{Var: "SPACED_COLON", Value: "{{secret : db}}"},
			{Var: "WRONG_PREFIX", Value: "{{secrets:db}}"},
			{Var: "SINGLE_BRACE", Value: "{secret:db}"},
			{Var: "UNCLOSED", Value: "{{secret:db"},
			{Var: "MATCHED", Value: "{{secret:db}}"},
		},
	}
	_, env, _, err := BuildExecEnv(spec, src.fn())
	if err != nil {
		t.Fatalf("BuildExecEnv: %v", err)
	}
	for _, tc := range []struct{ name, want string }{
		{"EMPTY_REF", "{{secret:}}"},
		{"SPACED_COLON", "{{secret : db}}"},
		{"WRONG_PREFIX", "{{secrets:db}}"},
		{"SINGLE_BRACE", "{secret:db}"},
		{"UNCLOSED", "{{secret:db"},
		{"MATCHED", "PLAINTEXT"},
	} {
		if got := envOnce(t, env, tc.name); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, got, tc.want)
		}
	}
	if src.callCount("db") != 1 {
		t.Errorf("db resolved %d times, want 1 (only the well-formed placeholder counts)", src.callCount("db"))
	}
}

// TestBuildExecEnvRejectsUnportableTemplateVarName covers the -env counterpart
// of the explicit-variable-name check on injected secrets. An EnvTemplate whose
// Var carries an '=' would be emitted as "PATH=/evil=x": the shadowing pass
// compares only the part before the FIRST '=', so the inherited PATH survives
// too and the child sees two conflicting PATH entries (os/exec keeps the last
// one — the injected one). A name with a newline is just as bad. ParseEnvTemplate
// screens CLI input, so this is the guard for any programmatic caller.
func TestBuildExecEnvRejectsUnportableTemplateVarName(t *testing.T) {
	src := &recordingSource{}
	for _, bad := range []string{"PATH=/evil", "PATH\nEVIL", "1BAD", "BAD NAME", "", "BAD-NAME", "BAD\x00"} {
		argv, env, _, err := BuildExecEnv(ExecSpec{
			Argv:         []string{"/bin/true"},
			EnvTemplates: []EnvTemplate{{Var: bad, Value: "x"}},
			BaseEnv:      []string{"PATH=/usr/bin"},
		}, src.fn())
		if err == nil {
			t.Errorf("BuildExecEnv accepted the -env variable name %q: argv=%q env=%q", bad, argv, env)
			continue
		}
		if env != nil {
			t.Errorf("rejected -env name %q still produced env=%q", bad, env)
		}
	}
}
