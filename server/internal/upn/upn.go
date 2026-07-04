// Package upn validates User Principal Names (UPNs) for Microsoft smartcard-
// logon and Kerberos PKINIT client-authentication certificate issuance.
//
// A UPN has the form "local@REALM" (e.g. "alice@EXAMPLE.COM" or
// "alice@corp.example.com"). It is carried in a certificate as an otherName
// subject-alternative-name with type-id id-ms-UPN (1.3.6.1.4.1.311.20.2.3),
// whose value is a UTF8String. Active Directory matches the UPN SAN against a
// user's userPrincipalName attribute (case-insensitively) to authenticate a
// smartcard logon, and a Kerberos KDC matches it for PKINIT.
//
// Validation is deliberately conservative: the UPN is preserved byte-for-byte
// as enrolled (only surrounding whitespace is trimmed) so the certificate
// carries exactly what the subscriber presented, while the realm is validated
// as an LDH-plus-dots label sequence and matched case-insensitively against the
// realm allowlists. Two UPNs are compared for identity case-insensitively (the
// real-world AD interpretation), so allowlist and de-duplication checks are not
// defeated by case games.
package upn

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// maxUPNOctets bounds the whole "local@realm" string. Active Directory's
	// userPrincipalName tolerates far more, but real UPNs are short; the cap
	// rejects abusive inputs while passing every practical principal name.
	maxUPNOctets = 255
	// maxRealmOctets / maxLabelOctets follow the DNS limits, since UPN realms are
	// DNS-domain-shaped (an AD UPN suffix or a Kerberos realm).
	maxRealmOctets = 253
	maxLabelOctets = 63
	maxLocalOctets = 128
)

// UPN is a validated User Principal Name. Value is the address exactly as
// enrolled (whitespace-trimmed); Local and Realm are its two halves. Realm is
// preserved in its enrolled case but compared case-insensitively.
type UPN struct {
	// Value is the full "local@realm" string carried in the id-ms-UPN otherName.
	Value string
	// Local is the principal part (before the '@').
	Local string
	// Realm is the realm/domain part (after the '@').
	Realm string
}

// Equal reports whether two UPNs identify the same principal, folding ASCII case
// across the whole address (Active Directory logon matching is case-insensitive).
func (u UPN) Equal(o UPN) bool { return strings.EqualFold(u.Value, o.Value) }

// Parse validates raw as a "local@REALM" User Principal Name and returns its
// structured form. It rejects empty parts, embedded whitespace or control
// characters, more than one '@', and a realm that is not a valid LDH-plus-dots
// label sequence. The address is otherwise preserved as given.
func Parse(raw string) (UPN, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return UPN{}, fmt.Errorf("user principal name is empty")
	}
	if !utf8.ValidString(v) {
		return UPN{}, fmt.Errorf("user principal name %q is not valid UTF-8", raw)
	}
	if len(v) > maxUPNOctets {
		return UPN{}, fmt.Errorf("user principal name %q exceeds %d octets", raw, maxUPNOctets)
	}
	// Reject control characters and any embedded whitespace: a UPN is a single
	// token, and control bytes in a UTF8String SAN are interoperability poison.
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return UPN{}, fmt.Errorf("user principal name %q contains a control character", raw)
		}
		if r == ' ' || r == '\t' {
			return UPN{}, fmt.Errorf("user principal name %q contains embedded whitespace", raw)
		}
	}
	if strings.Count(v, "@") != 1 {
		return UPN{}, fmt.Errorf("user principal name %q must contain exactly one '@'", raw)
	}
	at := strings.IndexByte(v, '@')
	local, realm := v[:at], v[at+1:]
	if local == "" {
		return UPN{}, fmt.Errorf("user principal name %q has an empty local part", raw)
	}
	if len(local) > maxLocalOctets {
		return UPN{}, fmt.Errorf("user principal name %q local part exceeds %d octets", raw, maxLocalOctets)
	}
	if err := validateRealm(realm); err != nil {
		return UPN{}, fmt.Errorf("user principal name %q: %w", raw, err)
	}
	return UPN{Value: v, Local: local, Realm: realm}, nil
}

// validateRealm enforces that a UPN realm is a non-empty sequence of LDH
// (letter/digit/hyphen) labels separated by dots — the shape of both an Active
// Directory UPN suffix and a Kerberos realm. A single-label realm is permitted
// (Kerberos realms may be single-label); IP literals and other punctuation are
// rejected.
func validateRealm(realm string) error {
	realm = strings.TrimSuffix(realm, ".") // tolerate a fully-qualified spelling
	if realm == "" {
		return fmt.Errorf("realm is empty")
	}
	if len(realm) > maxRealmOctets {
		return fmt.Errorf("realm exceeds %d octets", maxRealmOctets)
	}
	for _, label := range strings.Split(realm, ".") {
		if label == "" {
			return fmt.Errorf("realm has an empty label")
		}
		if len(label) > maxLabelOctets {
			return fmt.Errorf("realm has a label longer than %d octets", maxLabelOctets)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("realm label %q must not start or end with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			switch {
			case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '-':
			default:
				return fmt.Errorf("realm label %q contains invalid character %q (realms are letters, digits, hyphens, and dots)", label, string(b))
			}
		}
	}
	return nil
}

// NormalizeAll validates every UPN, rejecting the first invalid one, and
// de-duplicates while preserving the caller's order. Duplicates are compared
// case-insensitively; the first spelling wins.
func NormalizeAll(raws []string) ([]UPN, error) {
	out := make([]UPN, 0, len(raws))
	for _, r := range raws {
		u, err := Parse(r)
		if err != nil {
			return nil, err
		}
		dup := false
		for _, seen := range out {
			if seen.Equal(u) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, u)
		}
	}
	return out, nil
}

// RealmAllowlist restricts which UPN realms a profile (or tenant) may certify.
// Entries are either an exact realm ("EXAMPLE.COM") or a wildcard
// ("*.example.com") matching any strict subdomain but not the apex; list both
// to cover a realm tree. Matching is case-insensitive.
type RealmAllowlist struct {
	exact    map[string]bool // canonical (lowercase) realm
	suffixes []string        // ".example.com" (lowercase) — matches strict subdomains
}

// NewRealmAllowlist parses and normalizes allowlist entries. An empty entry list
// yields an allowlist whose Empty method reports true (callers treat that as "no
// restriction").
func NewRealmAllowlist(entries []string) (*RealmAllowlist, error) {
	al := &RealmAllowlist{exact: make(map[string]bool, len(entries))}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(e, "*."); ok {
			if err := validateRealm(rest); err != nil {
				return nil, fmt.Errorf("realm allowlist entry %q: %w", e, err)
			}
			al.suffixes = append(al.suffixes, "."+canonicalRealm(rest))
			continue
		}
		if err := validateRealm(e); err != nil {
			return nil, fmt.Errorf("realm allowlist entry %q: %w", e, err)
		}
		al.exact[canonicalRealm(e)] = true
	}
	return al, nil
}

// Empty reports whether the allowlist carries no entries (no restriction).
func (a *RealmAllowlist) Empty() bool {
	return a == nil || (len(a.exact) == 0 && len(a.suffixes) == 0)
}

// Allows reports whether realm matches the allowlist. An empty allowlist allows
// every realm. Matching is case-insensitive.
func (a *RealmAllowlist) Allows(realm string) bool {
	if a.Empty() {
		return true
	}
	c := canonicalRealm(realm)
	if a.exact[c] {
		return true
	}
	for _, suf := range a.suffixes {
		if strings.HasSuffix(c, suf) && len(c) > len(suf) {
			return true
		}
	}
	return false
}

// canonicalRealm folds a realm to its case-insensitive comparison form: a
// trailing dot stripped and ASCII lowercased.
func canonicalRealm(realm string) string {
	return strings.ToLower(strings.TrimSuffix(realm, "."))
}
