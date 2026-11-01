package celpolicy

import (
	"reflect"
	"sort"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/celexpr"
)

// The operator-facing vocabulary, as data.
//
// A restriction engine whose vocabulary lives only in a documentation page is a
// trap: the page drifts, and the operator discovers the drift when a rule they
// wrote from the page fails to compile — or worse, compiles and means something
// else. So the reference is derived from the environment and the Go structs the
// engine actually evaluates against, and the console, the CLI and the docs all
// render the same value.

// VarDoc describes one variable an expression may reference.
type VarDoc struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Doc  string `json:"doc"`
	// Fields lists the object's fields, for a variable declared as a typed
	// object. Empty for a scalar or a map.
	Fields []FieldDoc `json:"fields,omitempty"`
}

// FieldDoc describes one field of an object variable.
type FieldDoc struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// FunctionGroup is one labelled block of the function library.
type FunctionGroup struct {
	Name      string   `json:"name"`
	Functions []string `json:"functions"`
}

// Example is a ready-to-use rule an operator can start from. The console offers
// these in its editor, which is how the common restrictions get written
// correctly the first time.
type Example struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Expression  string `json:"expression"`
	Effect      Effect `json:"effect,omitempty"`
	Message     string `json:"message,omitempty"`
}

// Reference is the whole vocabulary: variables (with the fields of each object),
// the function library, the result shapes, the cost ceiling, and worked examples.
type Reference struct {
	Variables []VarDoc        `json:"variables"`
	Functions []FunctionGroup `json:"functions"`
	Results   []string        `json:"results"`
	Effects   []string        `json:"effects"`
	Modes     []string        `json:"modes"`
	CostLimit uint64          `json:"cost_limit"`
	Examples  []Example       `json:"examples"`
}

// BuildReference assembles the vocabulary reference from the live environment.
func BuildReference() (Reference, error) {
	env, err := Env()
	if err != nil {
		return Reference{}, err
	}
	ref := Reference{
		Functions: FunctionGroups(),
		Results:   resultShapes,
		Effects:   []string{string(EffectRequire), string(EffectDeny)},
		Modes:     []string{string(ModeEnforce), string(ModeMonitor)},
		CostLimit: celexpr.DefaultCostLimit,
		Examples:  Examples(),
	}
	objects := objectFields()
	for _, v := range env.Vars() {
		doc := VarDoc{Name: v.Name(), Type: celTypeSpelling(v.Type()), Doc: v.Doc()}
		doc.Fields = objects[v.Type()]
		ref.Variables = append(ref.Variables, doc)
	}
	return ref, nil
}

// celTypeSpelling renders a declared type the way an operator writes it. cel-go
// names its well-known types by their protobuf message name, and an operator who
// read "google.protobuf.Timestamp" in the console would have no idea that
// `now > request.not_before` is the thing they wanted.
func celTypeSpelling(t string) string {
	switch t {
	case "google.protobuf.Timestamp":
		return "timestamp"
	case "google.protobuf.Duration":
		return "duration"
	}
	return t
}

// objectFields reflects the registered prototypes into their CEL field names and
// types, keyed by the CEL type name a variable declares. Reading the fields off
// the Go structs — rather than listing them again here — is what keeps the
// reference honest when a fact is added to the engine.
func objectFields() map[string][]FieldDoc {
	out := make(map[string][]FieldDoc)
	for _, proto := range prototypes() {
		t := reflect.TypeOf(proto)
		if t == nil || t.Kind() != reflect.Struct {
			continue
		}
		name := celTypeName(t)
		fields := make([]FieldDoc, 0, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue // unexported: not reachable from an expression
			}
			fields = append(fields, FieldDoc{Name: celFieldName(f), Type: celFieldType(f.Type)})
		}
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		out[name] = fields
	}
	return out
}

// celTypeName renders a Go struct type the way cel-go's native provider names
// it: the package's short name and the type name, joined by a dot.
func celTypeName(t reflect.Type) string {
	pkg := t.PkgPath()
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	if pkg == "" {
		return t.Name()
	}
	return pkg + "." + t.Name()
}

// celFieldName is the name an expression uses for a field: the `cel` tag when
// present (which is how this package fixes the vocabulary at snake_case), the Go
// field name otherwise.
func celFieldName(f reflect.StructField) string {
	if tag := f.Tag.Get("cel"); tag != "" {
		if name := strings.Split(tag, ",")[0]; name != "" {
			return name
		}
	}
	return f.Name
}

// celFieldType renders a Go type in CEL's type syntax, which is what an operator
// needs to know to write a comparison against it.
func celFieldType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Bool:
		return "bool"
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
		return "int"
	case reflect.Int64:
		if t.PkgPath() == "time" && t.Name() == "Duration" {
			return "duration"
		}
		return "int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Float32, reflect.Float64:
		return "double"
	case reflect.Slice, reflect.Array:
		return "list(" + celFieldType(t.Elem()) + ")"
	case reflect.Map:
		return "map(" + celFieldType(t.Key()) + ", " + celFieldType(t.Elem()) + ")"
	case reflect.Ptr:
		return celFieldType(t.Elem())
	case reflect.Struct:
		if t.PkgPath() == "time" && t.Name() == "Time" {
			return "timestamp"
		}
		return celTypeName(t)
	}
	return "dyn"
}

// resultShapes documents what a rule's expression may evaluate to.
var resultShapes = []string{
	`bool — the condition the request must satisfy (effect "require") or must not match (effect "deny"); the reason reported is the rule's message`,
	`string — the reason itself: "" means satisfied, any other text denies and is shown to the requester`,
	`list(string) — several reasons at once (one per offending name); an empty list means satisfied`,
}

// FunctionGroups is the operator-facing summary of the function library every
// rule sees. It is help text, not the source of truth — the environment is (see
// celexpr.Functions) — and the engine's own test suite evaluates one expression
// per line here so a renamed or dropped upstream function cannot leave a lie in
// the console.
func FunctionGroups() []FunctionGroup {
	return []FunctionGroup{
		{Name: "operators and macros", Functions: []string{
			`== != < <= > >= && || ! in, ternary a ? b : c`,
			`has(jwt.x), size(x)`,
			`list.all(x, p), list.exists(x, p), list.exists_one(x, p), list.map(x, f), list.filter(x, p)`,
			`list.all(i, x, p), list.exists(i, x, p), list.existsOne(i, x, p), list.transformList(i, x, f), list.transformMap(i, x, f)`,
			`cel.bind(name, init, expr)`,
		}},
		{Name: "strings", Functions: []string{
			`s.contains(sub), s.startsWith(p), s.endsWith(p), s.matches(re2)`,
			`s.charAt(i), s.indexOf(sub), s.lastIndexOf(sub), s.lowerAscii(), s.upperAscii()`,
			`s.replace(old, new), s.split(sep), s.substring(i, j), s.trim(), s.reverse()`,
			`list.join(sep), strings.quote(s), "fmt %s %d".format([args])`,
		}},
		{Name: "regex", Functions: []string{
			`regex.replace(s, re, repl), regex.extract(s, re) -> optional<string>, regex.extractAll(s, re)`,
			`optional: opt.orValue(default), opt.hasValue(), opt.value()`,
		}},
		{Name: "lists and sets", Functions: []string{
			`list.distinct(), list.flatten(), list.reverse(), list.slice(i, j), list.sort(), list.sortBy(x, k)`,
			`lists.range(n)`,
			`sets.contains(a, b), sets.equivalent(a, b), sets.intersects(a, b)`,
		}},
		{Name: "math", Functions: []string{
			`math.greatest(a, b, …), math.least(a, b, …), math.abs(x), math.sign(x)`,
			`math.ceil(x), math.floor(x), math.round(x), math.trunc(x)`,
			`math.isInf(x), math.isNaN(x), math.isFinite(x)`,
			`math.bitAnd(a, b), math.bitOr(a, b), math.bitXor(a, b), math.bitNot(a), math.bitShiftLeft(a, n), math.bitShiftRight(a, n)`,
		}},
		{Name: "network (IP and CIDR)", Functions: []string{
			`isIP(s), ip(s), ip.isCanonical(s)`,
			`<ip>.family(), <ip>.isLoopback(), <ip>.isGlobalUnicast(), <ip>.isLinkLocalUnicast(), <ip>.isLinkLocalMulticast(), <ip>.isUnspecified()`,
			`isCIDR(s), cidr(s), <cidr>.containsIP(x), <cidr>.containsCIDR(x), <cidr>.ip(), <cidr>.masked(), <cidr>.isMask(), <cidr>.prefixLength()`,
		}},
		{Name: "encoding", Functions: []string{
			`base64.encode(bytes), base64.decode(s)`,
		}},
		{Name: "time", Functions: []string{
			`now, request.not_after, request.not_before are timestamps; request.validity is a duration`,
			`timestamp("2026-01-01T00:00:00Z"), duration("90m"), t + duration("24h"), t1 - t2`,
			`t.getFullYear(), t.getMonth(), t.getDayOfWeek(), t.getHours() — add a UTC offset argument to shift the zone`,
		}},
	}
}

// Examples are worked rules covering the restrictions an enterprise asks for
// first. Each one is evaluated by the test suite, so an example an operator
// copies out of the console compiles.
func Examples() []Example {
	return []Example{
		{
			Title:       "Restrict DNS names to a suffix",
			Description: "Every DNS SAN must sit under a domain this CA is allowed to certify, and the rule names the ones that do not.",
			Expression: `request.dns_names.filter(d, !(d.endsWith(".example.com") || d == "example.com"))` +
				`.map(d, "DNS name " + d + " is outside example.com, which this CA may not certify")`,
		},
		{
			Title:       "Cap the requested lifetime",
			Description: "A lifetime ceiling that tells the requester the number it exceeded instead of refusing silently.",
			Expression: `request.validity_days <= 90 ? "" : ` +
				`"requested %d days of validity; this profile allows at most 90".format([request.validity_days])`,
		},
		{
			Title:       "Wildcards need an entitlement in the token",
			Description: "A wildcard certificate is issued only to a caller whose verified token carries the entitlement.",
			Expression:  `!request.wildcard || (has(jwt.entitlements) && "pki.wildcard" in jwt.entitlements)`,
			Message:     "a wildcard certificate requires the pki.wildcard entitlement in your token",
		},
		{
			Title:       "Forbid internal names on a public CA",
			Description: "A deny-effect blocklist: the rule states what must not appear.",
			Expression:  `request.dns_names.exists(d, d.endsWith(".internal") || d.endsWith(".local")) || request.subject.common_name.endsWith(".internal")`,
			Effect:      EffectDeny,
			Message:     "internal-only names (.internal, .local) cannot be certified by a publicly trusted CA",
		},
		{
			Title:       "IP SANs must be inside the corporate range",
			Description: "Address containment written with the network library rather than string comparison.",
			Expression: `request.ip_addresses.filter(a, !(cidr("10.0.0.0/8").containsIP(a) || cidr("192.168.0.0/16").containsIP(a)))` +
				`.map(a, "IP address " + a + " is outside the corporate ranges 10.0.0.0/8 and 192.168.0.0/16")`,
		},
		{
			Title:       "The subject organization must match the tenant",
			Description: "A cross-fact rule: the requested O= has to agree with the CA's tenant.",
			Expression: `request.ca.tenant == "" || request.subject.organization.exists(o, o.lowerAscii() == request.ca.tenant.lowerAscii())` +
				` ? "" : "subject organization %s does not match the tenant %s this CA issues for".format([request.subject.organization.join(", "), request.ca.tenant])`,
		},
		{
			Title:       "Minimum key strength",
			Description: "RSA below 3072 bits is refused; an elliptic-curve key is held to 256.",
			Expression: `(request.key.algorithm == "RSA" && request.key.size >= 3072) ||` +
				` (request.key.algorithm == "ECDSA" && request.key.size >= 256) ||` +
				` request.key.algorithm == "Ed25519"`,
			Message: "this profile requires RSA ≥ 3072 bits, an ECDSA key on P-256 or larger, or Ed25519",
		},
		{
			Title:       "Service accounts may only name their own host",
			Description: "The group name encodes the namespace the caller owns; a regex extracts it and the DNS names must sit under it.",
			Expression: `cel.bind(ns, ` +
				`has(jwt.groups) ? jwt.groups.map(g, regex.extract(g, "^pki-ns-([a-z0-9-]+)$").orValue("")).filter(s, s != "") : [],` +
				` ns.size() == 0 ? "your token carries no pki-ns-<namespace> group, so no name can be certified for you"` +
				` : (request.dns_names.all(d, ns.exists(n, d.endsWith("." + n + ".svc.cluster.local"))) ? ""` +
				` : "every DNS name must sit under one of your namespaces: " + ns.join(", ")))`,
		},
		{
			Title:       "Only the console may ask for a CA certificate",
			Description: "A rule over the request URL and the caller's roles rather than over the certificate.",
			Expression:  `!request.is_ca || (principal.authenticated && ("admin" in principal.roles || principal.is_root))`,
			Message:     "minting a subordinate CA requires the admin role",
		},
		{
			Title:       "Automated enrollment may not request long-lived client certificates",
			Description: "Reads request.source, which names the protocol the request arrived on.",
			Expression:  `request.source in ["rest", "grpc", "cli"] || request.validity_days <= 30`,
			Message:     "an automated enrollment (ACME/EST/SCEP/CMP) is limited to 30 days of validity",
		},
		{
			Title:       "The body must carry a change ticket",
			Description: "A request parameter the API accepts but the certificate does not carry: the engine still sees it.",
			Expression:  `has(body.reason) && string(body.reason).matches("^(CHG|INC)-[0-9]{4,}$")`,
			Message:     `the "reason" parameter must name a change or incident ticket, e.g. CHG-10482`,
		},
	}
}
