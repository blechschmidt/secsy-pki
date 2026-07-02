package nameconstraints

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
)

// Identity is the set of names a candidate leaf certificate would assert: its
// subject alternative names plus its subject distinguished name. The evaluator
// checks every one against the issuing CA's constraints.
type Identity struct {
	DNSNames []string
	IPs      []net.IP
	Emails   []string
	URIs     []string
	Subject  pkix.Name
}

// Violation describes a single name that a Name Constraints extension forbids.
type Violation struct {
	// Type is the general-name form ("dns", "ip", "email", "uri", "dirname").
	Type string
	// Name is the offending value.
	Name string
	// Reason is "excluded" (the name fell inside an excluded subtree) or
	// "not-permitted" (a permitted set existed for the form but the name matched
	// none of its subtrees).
	Reason string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s:%s %s", v.Type, v.Name, v.Reason)
}

// Result is the outcome of evaluating an Identity against Constraints.
type Result struct {
	Violations []Violation
}

// Permitted reports whether the identity is within the CA's constraints.
func (r Result) Permitted() bool { return len(r.Violations) == 0 }

// Summary renders the violations compactly for an audit event or error message.
func (r Result) Summary() string {
	if r.Permitted() {
		return "within name constraints"
	}
	parts := make([]string, 0, len(r.Violations))
	for _, v := range r.Violations {
		parts = append(parts, v.String())
	}
	return "name-constraint violations: " + strings.Join(parts, ", ")
}

// Validate evaluates an identity against the constraints, collecting every
// violation. A leaf is rejected (fail-closed) whenever any name falls inside an
// excluded subtree, or outside the permitted subtrees for a name form that has
// any permitted subtree. Name forms with no permitted subtree are unconstrained
// except by exclusions, matching RFC 5280 §4.2.1.10.
func (c Constraints) Validate(id Identity) Result {
	var res Result

	// A CN that syntactically looks like a hostname is evaluated as a DNS name,
	// mirroring the legacy behavior of common path validators (and OpenSSL) so a
	// subject CN cannot smuggle an out-of-scope hostname past DNS constraints.
	dnsNames := append([]string(nil), id.DNSNames...)
	if cn := strings.TrimSpace(id.Subject.CommonName); looksLikeHostname(cn) {
		dnsNames = append(dnsNames, cn)
	}

	for _, name := range dnsNames {
		res.check("dns", name, c.Excluded.DNS, c.Permitted.DNS, matchDomain)
	}
	for _, e := range id.Emails {
		res.check("email", e, c.Excluded.Email, c.Permitted.Email, matchEmail)
	}
	for _, u := range id.URIs {
		res.check("uri", u, c.Excluded.URI, c.Permitted.URI, matchURI)
	}
	for _, ip := range id.IPs {
		res.checkIP(ip, c.Excluded.IP, c.Permitted.IP)
	}
	// The leaf's subject DN is a directoryName evaluated against dirName subtrees.
	if len(c.Excluded.DirNames) > 0 || len(c.Permitted.DirNames) > 0 {
		res.checkDir(id.Subject, c.Excluded.DirNames, c.Permitted.DirNames)
	}
	return res
}

// check applies excluded-then-permitted matching for a single string name.
func (r *Result) check(typ, name string, excluded, permitted []string, match func(name, constraint string) bool) {
	for _, ex := range excluded {
		if match(name, ex) {
			r.Violations = append(r.Violations, Violation{Type: typ, Name: name, Reason: "excluded"})
			return
		}
	}
	if len(permitted) == 0 {
		return
	}
	for _, p := range permitted {
		if match(name, p) {
			return
		}
	}
	r.Violations = append(r.Violations, Violation{Type: typ, Name: name, Reason: "not-permitted"})
}

// checkIP applies excluded-then-permitted matching for an IP address.
func (r *Result) checkIP(ip net.IP, excluded, permitted []*net.IPNet) {
	name := ip.String()
	for _, ex := range excluded {
		if ex.Contains(ip) {
			r.Violations = append(r.Violations, Violation{Type: "ip", Name: name, Reason: "excluded"})
			return
		}
	}
	if len(permitted) == 0 {
		return
	}
	for _, p := range permitted {
		if p.Contains(ip) {
			return
		}
	}
	r.Violations = append(r.Violations, Violation{Type: "ip", Name: name, Reason: "not-permitted"})
}

// checkDir applies excluded-then-permitted matching for the subject DN.
func (r *Result) checkDir(subject pkix.Name, excluded, permitted []pkix.Name) {
	name := subject.String()
	for _, ex := range excluded {
		if dirContains(ex, subject) {
			r.Violations = append(r.Violations, Violation{Type: "dirname", Name: name, Reason: "excluded"})
			return
		}
	}
	if len(permitted) == 0 {
		return
	}
	for _, p := range permitted {
		if dirContains(p, subject) {
			return
		}
	}
	r.Violations = append(r.Violations, Violation{Type: "dirname", Name: name, Reason: "not-permitted"})
}

// matchDomain reports whether a DNS name (or URI host) falls within a domain
// constraint. An empty constraint matches everything; otherwise the name must
// equal the constraint or be a subdomain of it, compared case-insensitively at a
// label boundary.
func matchDomain(name, constraint string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	constraint = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(constraint, "."), "."))
	if constraint == "" {
		return true
	}
	if name == constraint {
		return true
	}
	return strings.HasSuffix(name, "."+constraint)
}

// matchEmail reports whether an e-mail address falls within an rfc822 constraint.
func matchEmail(addr, constraint string) bool {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return false
	}
	mailbox := addr[:at]
	host := strings.ToLower(addr[at+1:])

	if strings.Contains(constraint, "@") {
		// Full-mailbox constraint: local-part case-sensitive, host case-insensitive.
		cAt := strings.LastIndex(constraint, "@")
		return mailbox == constraint[:cAt] && host == strings.ToLower(constraint[cAt+1:])
	}
	c := strings.ToLower(constraint)
	if strings.HasPrefix(c, ".") {
		// Domain constraint: any host within the domain (subdomains only).
		return strings.HasSuffix(host, c)
	}
	// Bare-host constraint: exactly that host, no subdomains.
	return host == c
}

// matchURI reports whether a URI falls within a URI constraint. The constraint
// applies to the URI's host component, using the same domain rules as DNS.
func matchURI(uri, constraint string) bool {
	host := uriHost(uri)
	if host == "" {
		return false
	}
	return matchDomain(host, constraint)
}

// uriHost extracts the host (without port or userinfo) from a URI. It avoids
// net/url for robustness against the authority-less forms that appear in SANs.
func uriHost(uri string) string {
	if i := strings.Index(uri, "://"); i >= 0 {
		uri = uri[i+3:]
	}
	// Strip path/query/fragment.
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(uri, sep); i >= 0 {
			uri = uri[:i]
		}
	}
	// Strip userinfo.
	if i := strings.LastIndex(uri, "@"); i >= 0 {
		uri = uri[i+1:]
	}
	// Strip a port, taking care not to mangle bracketed IPv6 literals.
	if strings.HasPrefix(uri, "[") {
		if i := strings.Index(uri, "]"); i >= 0 {
			return uri[1:i]
		}
	}
	if i := strings.LastIndex(uri, ":"); i >= 0 {
		uri = uri[:i]
	}
	return uri
}

// dirContains reports whether a directoryName constraint matches a subject: every
// attribute (type and value) named in the constraint must appear in the subject.
// This provides organization/geography scoping without depending on RDN ordering.
func dirContains(constraint, subject pkix.Name) bool {
	subjectAttrs := attributePairs(subject)
	for _, c := range attributePairs(constraint) {
		found := false
		for _, s := range subjectAttrs {
			if c.oid == s.oid && strings.EqualFold(strings.TrimSpace(c.value), strings.TrimSpace(s.value)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type attrPair struct {
	oid   string
	value string
}

// attributePairs flattens a distinguished name into (attribute-OID, value) pairs.
func attributePairs(name pkix.Name) []attrPair {
	var out []attrPair
	seq := name.ToRDNSequence()
	for _, rdn := range seq {
		for _, atv := range rdn {
			v, _ := atv.Value.(string)
			out = append(out, attrPair{oid: atv.Type.String(), value: v})
		}
	}
	return out
}

// looksLikeHostname reports whether s is plausibly a DNS hostname (contains a dot,
// no spaces, only host-legal characters), so a subject CN can be evaluated as a
// DNS name. A non-hostname CN (e.g. "Acme Device 7") is left to dirName rules.
func looksLikeHostname(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t") || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '*' || r == '_':
		default:
			return false
		}
	}
	return true
}
