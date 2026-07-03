// Package smime validates and normalizes e-mail addresses for S/MIME
// (id-kp-emailProtection) certificate issuance.
//
// An address destined for an rfc822Name subject-alternative-name must be a
// bare RFC 5321 addr-spec ("local@domain" — no display name, no angle
// brackets) whose domain is a registrable DNS name. Internationalized domains
// (RFC 6531 / SMTPUTF8) are accepted and folded to their punycode A-label form,
// because rfc822Name is an IA5String and cannot carry non-ASCII octets (RFC
// 8398 §3: internationalized addresses use the A-label form there).
// Internationalized *local parts* have no A-label equivalent — representing
// them requires the SmtpUTF8Mailbox otherName, which this PKI does not issue —
// so they are rejected with a distinct error rather than silently mangled.
//
// Normalization is deliberately conservative: the domain is lowercased and
// punycoded, the local part is preserved byte-for-byte (RFC 5321 §2.4: the
// local part is case-sensitive at the receiving host; a CA must not rewrite
// it). Two addresses are compared for identity via Mailbox.Equal, which folds
// only local-part ASCII case — the common real-world interpretation — so
// allowlist and subject/SAN consistency checks are not defeated by case games,
// while the certificate itself carries exactly what the subscriber enrolled.
package smime

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

const (
	// maxLocalPartOctets is the RFC 5321 §4.5.3.1.1 limit on the local part.
	maxLocalPartOctets = 64
	// maxDomainOctets is the RFC 5321 §4.5.3.1.2 / DNS limit on the domain.
	maxDomainOctets = 253
	// maxAddressOctets is the RFC 5321 (errata 1690) limit on a mailbox address.
	maxAddressOctets = 254
	// maxLabelOctets is the DNS limit on a single label.
	maxLabelOctets = 63
)

// Mailbox is a validated, normalized e-mail address: the local part exactly as
// enrolled and the domain in lowercase A-label (punycode) form.
type Mailbox struct {
	Local  string
	Domain string
}

// Address renders the mailbox as the "local@domain" string carried in an
// rfc822Name SAN.
func (m Mailbox) Address() string { return m.Local + "@" + m.Domain }

// Equal reports whether two mailboxes identify the same mailbox, folding
// ASCII case in the local part (domains are already normalized).
func (m Mailbox) Equal(o Mailbox) bool {
	return m.Domain == o.Domain && strings.EqualFold(m.Local, o.Local)
}

// NormalizeEmail validates addr as a bare RFC 5321 addr-spec and returns its
// normalized form. The domain is lowercased and converted to A-labels
// (punycode); a single trailing dot is stripped. The local part must be
// ASCII dot-atom text and is preserved as given. Errors describe the first
// violation found, suitable for returning to an enrolling client.
func NormalizeEmail(addr string) (Mailbox, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return Mailbox{}, fmt.Errorf("email address is empty")
	}
	if strings.ContainsAny(trimmed, "<>") {
		return Mailbox{}, fmt.Errorf("email address %q must be a bare address without a display name or angle brackets", addr)
	}
	// A quoted local part is the only way an addr-spec can carry more than one
	// '@', and quoted local parts are not accepted for certificates (they are
	// interoperability poison and no public CA issues them).
	if strings.Count(trimmed, "@") != 1 {
		return Mailbox{}, fmt.Errorf("email address %q must contain exactly one '@'", addr)
	}
	at := strings.IndexByte(trimmed, '@')
	local, domain := trimmed[:at], trimmed[at+1:]

	if err := validateLocalPart(local); err != nil {
		return Mailbox{}, fmt.Errorf("email address %q: %w", addr, err)
	}
	normDomain, err := NormalizeDomain(domain)
	if err != nil {
		return Mailbox{}, fmt.Errorf("email address %q: %w", addr, err)
	}
	if len(local)+1+len(normDomain) > maxAddressOctets {
		return Mailbox{}, fmt.Errorf("email address %q exceeds %d octets", addr, maxAddressOctets)
	}
	return Mailbox{Local: local, Domain: normDomain}, nil
}

// validateLocalPart enforces RFC 5322 dot-atom syntax on the local part.
func validateLocalPart(local string) error {
	if local == "" {
		return fmt.Errorf("local part is empty")
	}
	if len(local) > maxLocalPartOctets {
		return fmt.Errorf("local part exceeds %d octets", maxLocalPartOctets)
	}
	if strings.HasPrefix(local, `"`) {
		return fmt.Errorf("quoted local parts are not supported in certificates")
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return fmt.Errorf("local part must be dot-atom text (no leading, trailing, or consecutive dots)")
	}
	for i := 0; i < len(local); i++ {
		b := local[i]
		if b >= 0x80 {
			return fmt.Errorf("internationalized (non-ASCII) local parts cannot be represented in an rfc822Name SAN (RFC 8398 requires the SmtpUTF8Mailbox otherName, which is not supported)")
		}
		if b == '.' || isAtext(b) {
			continue
		}
		return fmt.Errorf("local part contains invalid character %q", string(b))
	}
	return nil
}

// isAtext reports whether b is RFC 5322 §3.2.3 atext: printable ASCII
// excluding the "specials".
func isAtext(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
		return true
	}
	return false
}

// NormalizeDomain validates an e-mail domain and returns its lowercase A-label
// (punycode) form. It rejects address literals ("[192.0.2.1]"), single-label
// domains, and anything the IDNA lookup profile refuses (non-LDH characters,
// misplaced hyphens, invalid punycode, bidi violations).
func NormalizeDomain(domain string) (string, error) {
	domain = strings.TrimSuffix(domain, ".") // accept the fully-qualified spelling
	if domain == "" {
		return "", fmt.Errorf("domain is empty")
	}
	if strings.HasPrefix(domain, "[") {
		return "", fmt.Errorf("address-literal domains (IP addresses) are not permitted in certificates")
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("domain %q is not a valid DNS name: %w", domain, err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > maxDomainOctets {
		return "", fmt.Errorf("domain %q exceeds %d octets", domain, maxDomainOctets)
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain %q must be a registrable name with at least two labels", domain)
	}
	for _, l := range labels {
		if l == "" {
			return "", fmt.Errorf("domain %q contains an empty label", domain)
		}
		if len(l) > maxLabelOctets {
			return "", fmt.Errorf("domain %q contains a label longer than %d octets", domain, maxLabelOctets)
		}
	}
	return ascii, nil
}

// NormalizeAll normalizes every address, rejecting the first invalid one, and
// de-duplicates while preserving the caller's order. Duplicates are compared
// with Mailbox.Equal (local-part case folded), and the first spelling wins.
func NormalizeAll(addrs []string) ([]Mailbox, error) {
	out := make([]Mailbox, 0, len(addrs))
	for _, a := range addrs {
		m, err := NormalizeEmail(a)
		if err != nil {
			return nil, err
		}
		dup := false
		for _, seen := range out {
			if seen.Equal(m) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, m)
		}
	}
	return out, nil
}

// DomainAllowlist restricts which e-mail domains a profile (or tenant) may
// certify. Entries are either an exact domain ("example.com") or a wildcard
// ("*.example.com") matching any subdomain but not the apex; list both to
// cover a domain tree. Entries are normalized like e-mail domains, so an
// operator may configure U-labels ("bücher.example") and match punycoded
// requests.
type DomainAllowlist struct {
	exact    map[string]bool
	suffixes []string // ".example.com" — matches any strict subdomain
}

// NewDomainAllowlist parses and normalizes allowlist entries. An empty entry
// list yields an allowlist whose Empty method reports true (callers treat that
// as "no restriction").
func NewDomainAllowlist(entries []string) (*DomainAllowlist, error) {
	al := &DomainAllowlist{exact: make(map[string]bool, len(entries))}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(e, "*."); ok {
			norm, err := NormalizeDomain(rest)
			if err != nil {
				return nil, fmt.Errorf("allowlist entry %q: %w", e, err)
			}
			al.suffixes = append(al.suffixes, "."+norm)
			continue
		}
		norm, err := NormalizeDomain(e)
		if err != nil {
			return nil, fmt.Errorf("allowlist entry %q: %w", e, err)
		}
		al.exact[norm] = true
	}
	return al, nil
}

// Empty reports whether the allowlist carries no entries (no restriction).
func (a *DomainAllowlist) Empty() bool {
	return a == nil || (len(a.exact) == 0 && len(a.suffixes) == 0)
}

// Allows reports whether the (normalized) domain matches the allowlist. An
// empty allowlist allows every domain.
func (a *DomainAllowlist) Allows(domain string) bool {
	if a.Empty() {
		return true
	}
	if a.exact[domain] {
		return true
	}
	for _, suf := range a.suffixes {
		if strings.HasSuffix(domain, suf) && len(domain) > len(suf) {
			return true
		}
	}
	return false
}
