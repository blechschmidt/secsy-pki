// Package certlint runs pre-issuance, zlint-style structural and policy checks
// on a to-be-signed certificate (or precertificate) before an issuing CA signs
// it. It encodes the essentials of the CA/Browser Forum Baseline Requirements —
// validity-period caps, serial-number entropy, required/forbidden extensions,
// EKU/KU consistency, SAN vs CN handling, and public-vs-internal name rules —
// as individually addressable checks.
//
// The linter is deliberately provider-agnostic: it operates on a parsed
// *x509.Certificate, so the same code lints the template built during issuance
// (via CertificateFromLeaf, before any HSM signature) and an already-issued
// certificate supplied on the command line (`secsy-ca lint <cert.pem>`).
//
// Each check is mapped through a Policy to an enforcement Mode: an enforce-mode
// finding blocks issuance (fail-closed), a warn-mode finding is reported but
// does not block. Policies are configured per issuance profile.
package certlint

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Mode is the enforcement mode of a check (or of a policy as a whole).
type Mode string

const (
	// ModeEnforce makes a failing check block issuance (fail-closed). It is the
	// default when a policy does not specify a mode.
	ModeEnforce Mode = "enforce"
	// ModeWarn makes a failing check report but not block issuance.
	ModeWarn Mode = "warn"
)

// Check codes. Each identifies one lint check and is stable so it can be
// referenced from per-profile overrides, audit detail, and metrics labels.
const (
	CheckSerialPositive   = "serial_positive"
	CheckSerialEntropy    = "serial_entropy"
	CheckValidityOrder    = "validity_order"
	CheckValidityCap      = "validity_cap"
	CheckValidityTLSMax   = "validity_tls_max"
	CheckLeafNotCA        = "leaf_not_ca"
	CheckKeyUsagePresent  = "key_usage_present"
	CheckKeyUsageLeaf     = "key_usage_leaf"
	CheckEKUKUConsistency = "eku_ku_consistency"
	CheckSANPresent       = "san_present"
	CheckCNInSAN          = "cn_in_san"
	CheckInternalName     = "internal_name"
	CheckReservedIP       = "reserved_ip"
	CheckWildcard         = "wildcard"
)

const (
	// MinSerialEntropyBits is the CA/Browser Forum minimum amount of entropy a
	// certificate serial number must carry (BR §7.1). Measured here as the bit
	// length of the (positive) serial integer — a conservative proxy that flags
	// small/sequential serials while passing CSPRNG-generated ones.
	MinSerialEntropyBits = 64
	// MaxTLSValidity is the CA/Browser Forum maximum validity period for a
	// publicly-trusted TLS server certificate (398 days). Applied only under a
	// public policy.
	MaxTLSValidity = 398 * 24 * time.Hour
	// validityGrace absorbs the small NotBefore backdating (issuance clock-skew)
	// so a certificate minted at exactly the profile maximum is not flagged for
	// the extra few minutes of backdated validity.
	validityGrace = time.Hour
)

// Policy configures a lint run. It is typically derived from an issuance
// profile.
type Policy struct {
	// Mode is the default enforcement mode applied to every check. Empty means
	// ModeEnforce.
	Mode Mode
	// Public applies CA/Browser-Forum public-trust rules: subjectAltName is
	// required, the common name must appear in the SAN, DNS names must be
	// publicly resolvable (no reserved TLDs, single-label names, or
	// underscores), IP SANs must be globally routable, and the 398-day TLS cap
	// applies. Leave false for an internal-only PKI.
	Public bool
	// MaxValidity caps the certificate validity period. Zero means the profile
	// imposes no cap of its own (the public TLS cap still applies when Public).
	MaxValidity time.Duration
	// Overrides sets the enforcement mode for individual checks by code,
	// overriding Mode. A check absent from the map uses Mode.
	Overrides map[string]Mode
	// SMIME, when non-nil, applies the CA/B Forum S/MIME Baseline Requirements
	// rule set for mailbox-validated certificates (rfc822Name SAN presence and
	// syntax, EKU exclusivity, key-usage split, class validity caps). See
	// SMIMEPolicy.
	SMIME *SMIMEPolicy
}

// modeFor resolves the effective enforcement mode for a check code.
func (p Policy) modeFor(code string) Mode {
	if p.Overrides != nil {
		if m, ok := p.Overrides[code]; ok && m != "" {
			return m
		}
	}
	if p.Mode != "" {
		return p.Mode
	}
	return ModeEnforce
}

// Finding is a single lint issue, tagged with the effective enforcement mode.
type Finding struct {
	Code        string `json:"code"`
	Mode        Mode   `json:"mode"`
	Description string `json:"description"`
}

// Result is the outcome of a lint run.
type Result struct {
	Findings []Finding `json:"findings,omitempty"`
}

// issue is an internal, mode-free lint hit; Lint tags it with a Mode.
type issue struct {
	code string
	desc string
}

// OK reports whether the certificate produced no findings at all.
func (r Result) OK() bool { return len(r.Findings) == 0 }

// HasErrors reports whether any finding is in enforce mode (i.e. blocks
// issuance).
func (r Result) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Mode == ModeEnforce {
			return true
		}
	}
	return false
}

// Errors returns the enforce-mode findings.
func (r Result) Errors() []Finding { return r.filter(ModeEnforce) }

// Warnings returns the warn-mode findings.
func (r Result) Warnings() []Finding { return r.filter(ModeWarn) }

func (r Result) filter(mode Mode) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Mode == mode {
			out = append(out, f)
		}
	}
	return out
}

// codes returns the sorted, de-duplicated check codes for the given mode.
func (r Result) codes(mode Mode) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range r.Findings {
		if f.Mode == mode && !seen[f.code()] {
			seen[f.code()] = true
			out = append(out, f.Code)
		}
	}
	sort.Strings(out)
	return out
}

func (f Finding) code() string { return f.Code }

// Summary renders a compact, audit-friendly one-line description of the run.
func (r Result) Summary() string {
	if r.OK() {
		return "lint=ok"
	}
	errs := r.Errors()
	warns := r.Warnings()
	s := "lint=fail"
	if !r.HasErrors() {
		s = "lint=warn"
	}
	s += fmt.Sprintf(" errors=%d warnings=%d", len(errs), len(warns))
	if len(errs) > 0 {
		s += " error_checks=[" + strings.Join(r.codes(ModeEnforce), " ") + "]"
	}
	if len(warns) > 0 {
		s += " warn_checks=[" + strings.Join(r.codes(ModeWarn), " ") + "]"
	}
	return s
}

// Err returns a non-nil error describing the enforce-mode findings, or nil when
// none block issuance.
func (r Result) Err() error {
	if !r.HasErrors() {
		return nil
	}
	parts := make([]string, 0, len(r.Findings))
	for _, f := range r.Errors() {
		parts = append(parts, f.Code+": "+f.Description)
	}
	return fmt.Errorf("%s", strings.Join(parts, "; "))
}

// Lint runs every check against cert and returns the findings tagged with the
// enforcement mode resolved from policy.
func Lint(cert *x509.Certificate, policy Policy) Result {
	var issues []issue
	add := func(code, format string, args ...interface{}) {
		issues = append(issues, issue{code: code, desc: fmt.Sprintf(format, args...)})
	}

	checkSerial(cert, add)
	checkValidity(cert, policy, add)
	checkBasicConstraints(cert, add)
	checkKeyUsage(cert, policy, add)
	checkEKUKUConsistency(cert, add)
	if policy.Public {
		checkSAN(cert, add)
		checkCNInSAN(cert, add)
		checkNames(cert, add)
	}
	if policy.SMIME != nil {
		checkSMIME(cert, *policy.SMIME, add)
	}

	res := Result{}
	for _, is := range issues {
		res.Findings = append(res.Findings, Finding{
			Code:        is.code,
			Mode:        policy.modeFor(is.code),
			Description: is.desc,
		})
	}
	return res
}

// CertificateFromLeaf builds the *x509.Certificate view of a to-be-signed leaf
// request so the same checks that run on a parsed certificate can run on the
// template before it is signed. It mirrors the field mapping performed by
// pki.CreateLeafCertificate; only the fields the linter inspects are populated.
func CertificateFromLeaf(req pki.LeafCertRequest) (*x509.Certificate, error) {
	uris := make([]*url.URL, 0, len(req.URIs))
	for _, raw := range req.URIs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid URI SAN %q: %w", raw, err)
		}
		uris = append(uris, u)
	}
	cert := &x509.Certificate{
		SerialNumber:          req.Serial,
		Subject:               req.Subject,
		PublicKey:             req.PublicKey,
		NotBefore:             req.NotBefore,
		NotAfter:              req.NotAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
		EmailAddresses:        req.EmailAddresses,
		URIs:                  uris,
		IsCA:                  req.IsCA,
		BasicConstraintsValid: true,
	}
	return cert, nil
}

type adder func(code, format string, args ...interface{})

// checkSerial enforces a positive serial number carrying sufficient entropy.
func checkSerial(cert *x509.Certificate, add adder) {
	s := cert.SerialNumber
	if s == nil || s.Sign() <= 0 {
		add(CheckSerialPositive, "serial number must be a positive integer")
		return
	}
	if bits := s.BitLen(); bits < MinSerialEntropyBits {
		add(CheckSerialEntropy,
			"serial number carries only %d bits; CA/Browser Forum requires >= %d bits of entropy",
			bits, MinSerialEntropyBits)
	}
}

// checkValidity enforces validity ordering and the profile / public caps.
func checkValidity(cert *x509.Certificate, policy Policy, add adder) {
	if !cert.NotAfter.After(cert.NotBefore) {
		add(CheckValidityOrder, "notAfter (%s) must be after notBefore (%s)",
			cert.NotAfter.UTC().Format(time.RFC3339), cert.NotBefore.UTC().Format(time.RFC3339))
		return
	}
	span := cert.NotAfter.Sub(cert.NotBefore)
	if policy.MaxValidity > 0 && span > policy.MaxValidity+validityGrace {
		add(CheckValidityCap, "validity period %s exceeds profile maximum %s",
			roundDays(span), roundDays(policy.MaxValidity))
	}
	if policy.Public && span > MaxTLSValidity+validityGrace {
		add(CheckValidityTLSMax, "validity period %s exceeds the CA/Browser Forum TLS maximum of %s",
			roundDays(span), roundDays(MaxTLSValidity))
	}
}

// checkBasicConstraints forbids a leaf certificate from asserting CA.
func checkBasicConstraints(cert *x509.Certificate, add adder) {
	if cert.IsCA {
		add(CheckLeafNotCA, "end-entity certificate must not assert the CA basic constraint")
	}
}

// checkKeyUsage forbids CA-only key usages on a leaf and, under a public policy,
// requires a key-usage extension to be present.
func checkKeyUsage(cert *x509.Certificate, policy Policy, add adder) {
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		add(CheckKeyUsageLeaf, "end-entity certificate must not carry the keyCertSign key usage")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		add(CheckKeyUsageLeaf, "end-entity certificate must not carry the cRLSign key usage")
	}
	if policy.Public && cert.KeyUsage == 0 {
		add(CheckKeyUsagePresent, "certificate must define a key-usage extension")
	}
}

// checkEKUKUConsistency flags extended key usages whose required key-usage bits
// are absent. Certificates with no key-usage bits at all are handled by
// checkKeyUsage; this check only fires when a key usage is present but wrong.
func checkEKUKUConsistency(cert *x509.Certificate, add adder) {
	ku := cert.KeyUsage
	if ku == 0 {
		return
	}
	const tlsBits = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
	const mailBits = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageContentCommitment
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth:
			if ku&tlsBits == 0 {
				add(CheckEKUKUConsistency,
					"serverAuth/clientAuth EKU requires digitalSignature, keyEncipherment, or keyAgreement key usage")
			}
		case x509.ExtKeyUsageCodeSigning:
			if ku&x509.KeyUsageDigitalSignature == 0 {
				add(CheckEKUKUConsistency, "codeSigning EKU requires the digitalSignature key usage")
			}
		case x509.ExtKeyUsageEmailProtection:
			if ku&mailBits == 0 {
				add(CheckEKUKUConsistency,
					"emailProtection EKU requires digitalSignature, keyEncipherment, keyAgreement, or contentCommitment key usage")
			}
		case x509.ExtKeyUsageOCSPSigning:
			if ku&x509.KeyUsageDigitalSignature == 0 {
				add(CheckEKUKUConsistency, "ocspSigning EKU requires the digitalSignature key usage")
			}
		}
	}
}

// checkSAN requires at least one subjectAltName (public policy).
func checkSAN(cert *x509.Certificate, add adder) {
	if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs) == 0 {
		add(CheckSANPresent, "certificate must include at least one subjectAltName")
	}
}

// checkCNInSAN requires that a DNS/IP-shaped common name also appear in the SAN
// (public policy).
func checkCNInSAN(cert *x509.Certificate, add adder) {
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn == "" {
		return
	}
	if ip := net.ParseIP(cn); ip != nil {
		for _, sip := range cert.IPAddresses {
			if sip.Equal(ip) {
				return
			}
		}
		add(CheckCNInSAN, "common name %q (an IP address) is not present in the subjectAltName extension", cn)
		return
	}
	for _, d := range cert.DNSNames {
		if strings.EqualFold(d, cn) {
			return
		}
	}
	add(CheckCNInSAN, "common name %q is not present among the dNSName subjectAltNames", cn)
}

// internalTLDs are top-level labels reserved for special/internal use and never
// valid in a publicly-trusted certificate (RFC 6761, RFC 2606, and common
// internal conventions).
var internalTLDs = map[string]bool{
	"local":       true,
	"localhost":   true,
	"localdomain": true,
	"internal":    true,
	"intranet":    true,
	"lan":         true,
	"corp":        true,
	"home":        true,
	"test":        true,
	"example":     true,
	"invalid":     true,
	"onion":       true,
}

// checkNames enforces public-trust DNS and IP naming rules (public policy).
func checkNames(cert *x509.Certificate, add adder) {
	for _, raw := range cert.DNSNames {
		name := raw
		if strings.HasPrefix(name, "*.") {
			rest := name[2:]
			if strings.Contains(rest, "*") {
				add(CheckWildcard, "only a single leftmost wildcard label is permitted: %q", raw)
			}
			name = rest
		} else if strings.Contains(name, "*") {
			add(CheckWildcard, "a wildcard is only permitted as the leftmost label: %q", raw)
			name = strings.ReplaceAll(name, "*", "")
		}
		labels := strings.Split(name, ".")
		if len(labels) < 2 || labels[len(labels)-1] == "" {
			add(CheckInternalName, "single-label / unqualified DNS name is not publicly valid: %q", raw)
			continue
		}
		if internalTLDs[strings.ToLower(labels[len(labels)-1])] {
			add(CheckInternalName, "reserved/internal TLD is not publicly valid: %q", raw)
		}
		if strings.Contains(name, "_") {
			add(CheckInternalName, "DNS name contains an underscore, not valid for public TLS: %q", raw)
		}
	}
	for _, ip := range cert.IPAddresses {
		if isReservedIP(ip) {
			add(CheckReservedIP, "reserved / non-globally-routable IP address is not publicly valid: %q", ip.String())
		}
	}
}

// reservedNets are IP ranges that are not globally routable and thus never valid
// in a publicly-trusted certificate.
var reservedNets = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918 private
		"100.64.0.0/10",                                     // RFC 6598 CGNAT
		"169.254.0.0/16",                                    // link-local
		"192.0.0.0/24",                                      // IETF protocol assignments
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", // documentation
		"198.18.0.0/15",  // benchmarking
		"240.0.0.0/4",    // reserved
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"2001:db8::/32",  // documentation
		"64:ff9b:1::/48", // local-use translation
	}
	var nets []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// isReservedIP reports whether ip is loopback, unspecified, multicast, or falls
// in a reserved / private / documentation range.
func isReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// roundDays renders a duration as whole days when it is a clean multiple,
// otherwise as the duration itself, for readable messages.
func roundDays(d time.Duration) string {
	const day = 24 * time.Hour
	if d%day == 0 {
		return fmt.Sprintf("%dd", d/day)
	}
	return d.String()
}
