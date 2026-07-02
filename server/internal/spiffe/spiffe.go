// Package spiffe implements SPIFFE X.509-SVID workload identity on top of the
// HSM-backed CA. It provides:
//
//   - Parsing and strict validation of SPIFFE IDs (spiffe://trust-domain/path),
//     per the SPIFFE ID specification.
//   - A trust-domain allowlist (Policy) so issuance is restricted to explicitly
//     permitted trust domains, optionally per authenticated subject.
//   - Construction of a SPIFFE trust bundle in the JWKS-style format consumed by
//     SPIRE and go-spiffe clients (see bundle.go).
//
// The actual X.509-SVID leaf is minted by the ca package through the short-lived
// "spiffe-svid" issuance profile; this package supplies the identity model,
// validation, and bundle encoding around it.
package spiffe

import (
	"fmt"
	"net/url"
	"strings"
)

// maxTrustDomainLen bounds a trust-domain name per the SPIFFE ID spec (the host
// component is limited to 255 characters).
const maxTrustDomainLen = 255

// maxIDLen bounds a whole SPIFFE ID (scheme + trust domain + path) per the spec.
const maxIDLen = 2048

// ID is a validated SPIFFE identity: a trust domain plus an optional workload
// path. Its String/URI forms round-trip to a canonical spiffe:// URI usable as
// the sole URI SAN of an X.509-SVID.
type ID struct {
	trustDomain string // e.g. "example.org" (lowercase, no scheme, no port)
	path        string // e.g. "/ns/prod/sa/web" ("" for a trust-domain ID)
}

// TrustDomain returns the trust-domain component (e.g. "example.org").
func (id ID) TrustDomain() string { return id.trustDomain }

// Path returns the workload path component, including its leading slash
// (e.g. "/ns/prod/sa/web"). It is empty for a bare trust-domain ID.
func (id ID) Path() string { return id.path }

// String returns the canonical spiffe:// URI form of the identity.
func (id ID) String() string { return "spiffe://" + id.trustDomain + id.path }

// URI is an alias for String, named for its use as a certificate URI SAN.
func (id ID) URI() string { return id.String() }

// IsZero reports whether the ID is the zero value (no trust domain).
func (id ID) IsZero() bool { return id.trustDomain == "" }

// MakeID builds and validates a SPIFFE ID from a trust domain and workload path.
// The path may be given with or without a leading slash; an empty path yields a
// bare trust-domain ID. Both components are validated per the SPIFFE ID spec.
func MakeID(trustDomain, path string) (ID, error) {
	td, err := validateTrustDomain(trustDomain)
	if err != nil {
		return ID{}, err
	}
	p, err := normalizeAndValidatePath(path)
	if err != nil {
		return ID{}, err
	}
	id := ID{trustDomain: td, path: p}
	if len(id.String()) > maxIDLen {
		return ID{}, fmt.Errorf("spiffe id exceeds %d characters", maxIDLen)
	}
	return id, nil
}

// ParseID parses and validates a full spiffe:// URI into an ID. It enforces the
// SPIFFE ID spec: the scheme must be exactly "spiffe", the authority must be a
// bare trust domain (no userinfo, no port), and the path must contain no empty
// or dot segments and no query or fragment.
func ParseID(raw string) (ID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ID{}, fmt.Errorf("empty spiffe id")
	}
	if len(raw) > maxIDLen {
		return ID{}, fmt.Errorf("spiffe id exceeds %d characters", maxIDLen)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ID{}, fmt.Errorf("invalid spiffe id %q: %w", raw, err)
	}
	if !strings.EqualFold(u.Scheme, "spiffe") {
		return ID{}, fmt.Errorf("spiffe id %q: scheme must be \"spiffe\", got %q", raw, u.Scheme)
	}
	// The SPIFFE ID authority is a bare trust domain: no userinfo and no port.
	if u.User != nil {
		return ID{}, fmt.Errorf("spiffe id %q: must not contain userinfo", raw)
	}
	if u.Port() != "" {
		return ID{}, fmt.Errorf("spiffe id %q: must not contain a port", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return ID{}, fmt.Errorf("spiffe id %q: must not contain a query or fragment", raw)
	}
	// url.Parse lowercases nothing; the trust domain is case-insensitive and must
	// be canonicalized to lowercase. u.Host holds the authority (already without
	// any port, which we rejected above).
	return MakeID(u.Host, u.Path)
}

// validateTrustDomain canonicalizes and validates a trust-domain name. Allowed
// characters are lowercase letters, digits, and the separators '.', '-', '_'
// (the SPIFFE trust-domain character set). The name is lowercased before
// validation so callers may pass mixed case.
func validateTrustDomain(td string) (string, error) {
	td = strings.ToLower(strings.TrimSpace(td))
	if td == "" {
		return "", fmt.Errorf("trust domain is required")
	}
	if len(td) > maxTrustDomainLen {
		return "", fmt.Errorf("trust domain %q exceeds %d characters", td, maxTrustDomainLen)
	}
	if strings.Contains(td, "/") {
		return "", fmt.Errorf("trust domain %q must not contain a path separator", td)
	}
	for i := 0; i < len(td); i++ {
		c := td[i]
		if !isTrustDomainChar(c) {
			return "", fmt.Errorf("trust domain %q contains invalid character %q", td, string(c))
		}
	}
	return td, nil
}

// isTrustDomainChar reports whether c is allowed in a SPIFFE trust domain.
func isTrustDomainChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '.' || c == '-' || c == '_':
		return true
	default:
		return false
	}
}

// normalizeAndValidatePath validates a workload path and returns it in canonical
// form (leading slash, no trailing slash). An empty input yields an empty path
// (a bare trust-domain ID). Each segment must be non-empty, must not be "." or
// "..", and may contain only the SPIFFE path character set (letters, digits, and
// '.', '-', '_'). The character set is intentionally stricter than RFC 3986 to
// avoid ambiguity in the URI SAN.
func normalizeAndValidatePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return "", nil
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("spiffe path %q must not end with a trailing slash", path)
	}
	// Split on '/'; the leading slash produces an empty first element we skip.
	segments := strings.Split(path[1:], "/")
	for _, seg := range segments {
		if seg == "" {
			return "", fmt.Errorf("spiffe path %q must not contain empty segments", path)
		}
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("spiffe path %q must not contain relative (\".\"/\"..\") segments", path)
		}
		for i := 0; i < len(seg); i++ {
			if !isPathChar(seg[i]) {
				return "", fmt.Errorf("spiffe path %q contains invalid character %q", path, string(seg[i]))
			}
		}
	}
	return path, nil
}

// isPathChar reports whether c is allowed in a SPIFFE path segment.
func isPathChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '.' || c == '-' || c == '_':
		return true
	default:
		return false
	}
}
