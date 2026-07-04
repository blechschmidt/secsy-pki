// Package certvalidate implements a read-only, HSM-independent certificate
// chain/path validation engine (Task 123).
//
// Given a supplied leaf certificate (and optional intermediates), it builds and
// validates a certification path against a set of configured trust anchors and
// returns a structured verdict: whether a chain was built (with the resolved
// chain), the effective validity window, per-certificate live revocation status
// (via an injected resolver backed by the same store OCSP and the CRL consult,
// including the reversible on-hold state), name-constraint and certificate-policy
// conformance, weak-signature and weak-key/compromised-key flags, and an overall
// pass/fail with human-readable reasons.
//
// The engine performs no signing and holds no private keys. It reuses the same
// building blocks as the issuance path — Go's crypto/x509 path builder, the
// internal/nameconstraints evaluator, and the internal/keycheck weak-key gate —
// so a validation verdict cannot silently drift from issuance policy. All I/O
// (revocation lookups) is behind the RevocationResolver interface, keeping the
// core a pure function that is exercised entirely with in-process certificates.
package certvalidate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
)

// RevocationState is the resolved live revocation status of a single certificate.
type RevocationState string

const (
	// RevocationGood — the issuing CA has a record of the serial and it is not revoked.
	RevocationGood RevocationState = "good"
	// RevocationRevoked — the serial is permanently revoked.
	RevocationRevoked RevocationState = "revoked"
	// RevocationHeld — the serial is on reversible hold (RFC 5280 certificateHold).
	RevocationHeld RevocationState = "held"
	// RevocationUnknown — this PKI has no record of the serial under the resolved issuer.
	RevocationUnknown RevocationState = "unknown"
)

// RevocationStatus is the live status of one certificate as reported by the
// authority's revocation store (the same source OCSP and the CRL are built from).
type RevocationStatus struct {
	State      RevocationState `json:"state"`
	RevokedAt  time.Time       `json:"revoked_at,omitempty"`
	Reason     int             `json:"reason,omitempty"`
	ReasonText string          `json:"reason_text,omitempty"`
	// Source describes where the status came from (e.g. "internal revocation store").
	Source string `json:"source,omitempty"`
}

// RevocationResolver looks up the live revocation status of a certificate. cert
// is the certificate whose status is wanted; issuer is the certificate directly
// above it in the resolved path (used to locate the issuing CA). A nil resolver
// disables revocation checking. Implementations must not return an error for a
// serial that is simply unknown — they return RevocationUnknown instead; an error
// is reserved for a genuine lookup failure (e.g. a database error).
type RevocationResolver interface {
	Revocation(cert, issuer *x509.Certificate) (RevocationStatus, error)
}

// CheckStatus is the disposition of a single validation dimension.
type CheckStatus string

const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckWarn    CheckStatus = "warn"
	CheckSkipped CheckStatus = "skipped"
)

// Check is one validation dimension's verdict (chain, validity, revocation,
// name_constraints, certificate_policy, key_usage, weak_key, weak_signature).
type Check struct {
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Detail   string      `json:"detail"`
	Findings []string    `json:"findings,omitempty"`
}

// CertInfo is the analyzed view of one certificate in (or supplied to) the path.
type CertInfo struct {
	Position           int       `json:"position"` // 0 = leaf; increases toward the anchor
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsCA               bool      `json:"is_ca"`
	IsTrustAnchor      bool      `json:"is_trust_anchor"`
	SelfSigned         bool      `json:"self_signed"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KeySize            int       `json:"key_size,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	Fingerprint        string    `json:"fingerprint"` // "sha256:<hex>"
	SubjectKeyID       string    `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string    `json:"authority_key_id,omitempty"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	ExtKeyUsage        []string  `json:"ext_key_usage,omitempty"`
	Policies           []string  `json:"policies,omitempty"`

	Expired       bool `json:"expired"`
	NotYetValid   bool `json:"not_yet_valid"`
	WeakKey       bool `json:"weak_key"`
	WeakSignature bool `json:"weak_signature"`

	WeakKeyReasons []string          `json:"weak_key_reasons,omitempty"`
	Revocation     *RevocationStatus `json:"revocation,omitempty"`
}

// Report is the structured verdict returned by Validate. It serializes directly
// as the REST/CLI response, so its JSON shape is part of the API surface.
type Report struct {
	// TrustAnchor labels the anchor set the path was validated against.
	TrustAnchor string `json:"trust_anchor,omitempty"`
	// ChainBuilt reports whether a path to a configured trust anchor was found.
	ChainBuilt bool `json:"chain_built"`
	// Valid is the overall verdict: true only when no dimension failed.
	Valid bool `json:"valid"`
	// Decision renders the overall verdict as a single word ("valid"/"invalid").
	Decision string `json:"decision"`
	// Now is the instant validation was evaluated at.
	Now time.Time `json:"evaluated_at"`
	// ValidFrom/ValidUntil is the effective validity window of the resolved chain
	// (the intersection of every certificate's window).
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	// Chain is the resolved path, leaf first (Position 0) and the trust anchor
	// last. When no chain built it holds the supplied certificates for reference.
	Chain []CertInfo `json:"chain"`
	// Checks is the per-dimension verdict list.
	Checks []Check `json:"checks"`
	// Reasons enumerates, in human-readable form, every reason the chain is not
	// valid. Empty when Valid is true.
	Reasons []string `json:"reasons,omitempty"`
	// Warnings enumerates non-fatal observations.
	Warnings []string `json:"warnings,omitempty"`
}

// decisionWord renders an overall verdict as a single word.
func decisionWord(valid bool) string {
	if valid {
		return "valid"
	}
	return "invalid"
}

// Options configures a validation run.
type Options struct {
	// Roots are the configured trust anchors the path must terminate at.
	Roots []*x509.Certificate
	// Intermediates are additional CA certificates available to bridge the path
	// (typically the anchor CA's own intermediate lineage). Caller-supplied
	// intermediates are added on top of these.
	Intermediates []*x509.Certificate
	// Now is the validation instant; the zero value means time.Now().
	Now time.Time
	// KeyCheck selects the weak/compromised-key policy; the zero value uses
	// keycheck.DefaultPolicy(nil).
	KeyCheck keycheck.Policy
	// Revocation, when non-nil, resolves live per-certificate revocation status.
	Revocation RevocationResolver
	// TrustAnchorLabel is copied into Report.TrustAnchor for display.
	TrustAnchorLabel string
}

// oidAnyPolicy is the anyPolicy OID (RFC 5280 §4.2.1.4).
var oidAnyPolicy = asn1.ObjectIdentifier{2, 5, 29, 32, 0}

// Validate builds and validates a certification path for leaf (with supplied
// intermediates) against opts.Roots, collecting a structured verdict. It never
// panics on malformed input and never performs a signing operation.
func Validate(opts Options, leaf *x509.Certificate, supplied []*x509.Certificate) *Report {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	kcPolicy := opts.KeyCheck
	if (kcPolicy == keycheck.Policy{}) {
		kcPolicy = keycheck.DefaultPolicy(nil)
	}

	rep := &Report{TrustAnchor: opts.TrustAnchorLabel, Now: now}

	// Candidate parents for path building: the anchor CA's own intermediate lineage
	// plus any caller-supplied bridging certificates.
	intermediates := append(append([]*x509.Certificate(nil), opts.Intermediates...), supplied...)

	builtChain, reachedAnchor := buildPath(leaf, opts.Roots, intermediates)
	rep.ChainBuilt = reachedAnchor

	// The certificate set the report analyzes: the resolved path (which may be a
	// best-effort partial path when no anchor was reached, so the leaf and any
	// intermediates are still inspected).
	chainCerts := builtChain
	if len(chainCerts) == 0 {
		chainCerts = append([]*x509.Certificate{leaf}, supplied...)
	}

	// Effective validity window: the intersection of every certificate's window.
	rep.ValidFrom, rep.ValidUntil = leaf.NotBefore, leaf.NotAfter
	for _, c := range chainCerts {
		if c.NotBefore.After(rep.ValidFrom) {
			rep.ValidFrom = c.NotBefore
		}
		if c.NotAfter.Before(rep.ValidUntil) {
			rep.ValidUntil = c.NotAfter
		}
	}

	// Per-certificate analysis.
	anchorIdx := -1
	if rep.ChainBuilt {
		anchorIdx = len(chainCerts) - 1
	}
	for i, c := range chainCerts {
		ci := analyzeCert(i, c, now, kcPolicy)
		ci.IsTrustAnchor = i == anchorIdx
		if opts.Revocation != nil && !ci.IsTrustAnchor {
			if issuer := issuerOf(chainCerts, i); issuer != nil {
				if rs, err := opts.Revocation.Revocation(c, issuer); err != nil {
					ci.Revocation = &RevocationStatus{State: RevocationUnknown, Source: "revocation lookup error: " + err.Error()}
				} else {
					ci.Revocation = &rs
				}
			}
		}
		rep.Chain = append(rep.Chain, ci)
	}

	// Run every dimension. Each appends a Check and, on failure, a Reason.
	checkChain(rep, opts, chainCerts)
	checkValidity(rep, now)
	checkRevocation(rep, opts)
	checkNameConstraints(rep, chainCerts)
	checkCertificatePolicy(rep, chainCerts)
	checkKeyUsage(rep, chainCerts)
	checkWeakKey(rep)
	checkWeakSignature(rep)

	// Overall verdict: valid only when no dimension failed.
	rep.Valid = true
	for _, c := range rep.Checks {
		if c.Status == CheckFail {
			rep.Valid = false
			break
		}
	}
	rep.Decision = decisionWord(rep.Valid)
	return rep
}

// buildPath builds a certification path from leaf up toward a configured trust
// anchor. It is a deliberately tolerant, structural builder: it matches each
// certificate to a candidate parent by issuer/subject DN and by verifying the
// child's signature with the parent's key, but it does NOT enforce validity
// windows, name constraints, key usage, or signature strength — those are each
// reported by a dedicated dimension so a merely expired, name-constraint-
// violating, or weak chain is still resolved and diagnosed precisely rather than
// collapsing into an opaque "path build failed".
//
// It returns the resolved path (leaf first, anchor last) and whether it actually
// terminated at a configured trust anchor. When no anchor is reachable it returns
// the deepest partial path found, with false, so the caller can still show and
// analyze the supplied material.
func buildPath(leaf *x509.Certificate, anchors, intermediates []*x509.Certificate) ([]*x509.Certificate, bool) {
	anchorSet := make(map[string]bool, len(anchors))
	for _, a := range anchors {
		anchorSet[fingerprint(a)] = true
	}
	// A parent may be either an anchor or an intermediate.
	candidates := append(append([]*x509.Certificate(nil), anchors...), intermediates...)

	var best []*x509.Certificate
	var dfs func(cur *x509.Certificate, path []*x509.Certificate, seen map[string]bool) ([]*x509.Certificate, bool)
	dfs = func(cur *x509.Certificate, path []*x509.Certificate, seen map[string]bool) ([]*x509.Certificate, bool) {
		if anchorSet[fingerprint(cur)] {
			return path, true
		}
		if len(path) > len(best) {
			best = append([]*x509.Certificate(nil), path...)
		}
		for _, p := range candidates {
			fp := fingerprint(p)
			if seen[fp] || !signedBy(cur, p) {
				continue
			}
			seen[fp] = true
			next := append(append([]*x509.Certificate(nil), path...), p)
			if res, ok := dfs(p, next, seen); ok {
				return res, true
			}
			delete(seen, fp)
		}
		return path, false
	}

	best = []*x509.Certificate{leaf}
	if res, ok := dfs(leaf, []*x509.Certificate{leaf}, map[string]bool{fingerprint(leaf): true}); ok {
		return res, true
	}
	return best, false
}

// signedBy reports whether parent plausibly issued child: their issuer/subject
// DNs match and parent's key verifies child's signature. A deprecated (SHA-1/MD5)
// signature that Go refuses to verify on strength grounds is still accepted as a
// structural match — the weak_signature dimension flags it — so a real-world weak
// chain is diagnosed rather than reported as an unknown issuer.
func signedBy(child, parent *x509.Certificate) bool {
	if !bytesEqual(child.RawIssuer, parent.RawSubject) {
		return false
	}
	err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	if err == nil {
		return true
	}
	var insecure x509.InsecureAlgorithmError
	return errors.As(err, &insecure)
}

// fingerprint is a stable per-certificate identity (SHA-256 of the DER) used to
// detect anchors and prevent cycles during path building.
func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return string(sum[:])
}

// issuerOf returns the certificate directly above index i in the resolved chain,
// or nil when i is the top of the chain.
func issuerOf(chain []*x509.Certificate, i int) *x509.Certificate {
	if i+1 < len(chain) {
		return chain[i+1]
	}
	return nil
}

// --- per-dimension checks ---

func checkChain(rep *Report, opts Options, chain []*x509.Certificate) {
	if rep.ChainBuilt {
		anchor := chain[len(chain)-1]
		rep.addCheck(Check{Name: "chain", Status: CheckPass,
			Detail: fmt.Sprintf("built a %d-certificate path to trust anchor %q", len(chain), shortName(anchor.Subject))})
		return
	}
	reason := "could not build a certification path from the supplied certificate to a configured trust anchor (unknown or untrusted issuer)"
	if len(opts.Roots) == 0 {
		reason = "no trust anchors were configured to validate against"
	}
	rep.fail(Check{Name: "chain", Status: CheckFail, Detail: reason})
}

func checkValidity(rep *Report, now time.Time) {
	switch {
	case now.Before(rep.ValidFrom):
		detail := fmt.Sprintf("not yet valid: the chain is valid from %s", fmtTime(rep.ValidFrom))
		if leaf := rep.leaf(); leaf != nil && leaf.NotYetValid {
			detail = fmt.Sprintf("the leaf certificate is not valid until %s", fmtTime(leaf.NotBefore))
		}
		rep.fail(Check{Name: "validity", Status: CheckFail, Detail: detail})
	case now.After(rep.ValidUntil):
		detail := fmt.Sprintf("expired: the chain validity ended %s", fmtTime(rep.ValidUntil))
		if leaf := rep.leaf(); leaf != nil && leaf.Expired {
			detail = fmt.Sprintf("the leaf certificate expired on %s", fmtTime(leaf.NotAfter))
		}
		rep.fail(Check{Name: "validity", Status: CheckFail, Detail: detail})
	default:
		rep.addCheck(Check{Name: "validity", Status: CheckPass,
			Detail: fmt.Sprintf("within the validity window %s .. %s", fmtTime(rep.ValidFrom), fmtTime(rep.ValidUntil))})
	}
}

func checkRevocation(rep *Report, opts Options) {
	if opts.Revocation == nil {
		rep.addCheck(Check{Name: "revocation", Status: CheckSkipped, Detail: "live revocation checking was not requested"})
		return
	}
	var revoked, held, unknown, good []string
	for _, ci := range rep.Chain {
		if ci.IsTrustAnchor || ci.Revocation == nil {
			continue
		}
		switch ci.Revocation.State {
		case RevocationRevoked:
			revoked = append(revoked, ci.SerialNumber)
		case RevocationHeld:
			held = append(held, ci.SerialNumber)
		case RevocationUnknown:
			unknown = append(unknown, ci.SerialNumber)
		default:
			good = append(good, ci.SerialNumber)
		}
	}
	switch {
	case len(revoked) > 0:
		rep.fail(Check{Name: "revocation", Status: CheckFail,
			Detail:   fmt.Sprintf("%d certificate(s) revoked", len(revoked)),
			Findings: revokedFindings(rep, revoked)})
	case len(held) > 0:
		rep.fail(Check{Name: "revocation", Status: CheckFail,
			Detail:   fmt.Sprintf("%d certificate(s) suspended (certificateHold)", len(held)),
			Findings: revokedFindings(rep, held)})
	default:
		detail := fmt.Sprintf("all %d checked certificate(s) are good", len(good))
		if len(unknown) > 0 {
			detail += fmt.Sprintf("; %d not found in this PKI's revocation store (reported unknown)", len(unknown))
		}
		rep.addCheck(Check{Name: "revocation", Status: CheckPass, Detail: detail})
	}
}

// revokedFindings renders a per-serial explanation (with revocation time/reason)
// for the certificates named in serials.
func revokedFindings(rep *Report, serials []string) []string {
	want := make(map[string]bool, len(serials))
	for _, s := range serials {
		want[s] = true
	}
	var out []string
	for _, ci := range rep.Chain {
		if ci.Revocation == nil || !want[ci.SerialNumber] {
			continue
		}
		msg := fmt.Sprintf("%s (serial %s): %s", shortName(ci.Subject), ci.SerialNumber, ci.Revocation.State)
		if !ci.Revocation.RevokedAt.IsZero() {
			msg += " at " + fmtTime(ci.Revocation.RevokedAt)
		}
		if ci.Revocation.ReasonText != "" {
			msg += " (" + ci.Revocation.ReasonText + ")"
		}
		out = append(out, msg)
	}
	return out
}

func checkNameConstraints(rep *Report, chain []*x509.Certificate) {
	if !rep.ChainBuilt || len(chain) < 2 {
		rep.addCheck(Check{Name: "name_constraints", Status: CheckSkipped, Detail: "no CA in the resolved path carries name constraints to evaluate"})
		return
	}
	var findings []string
	constrained := false
	// A CA at position j constrains every certificate below it (0..j-1).
	for j := 1; j < len(chain); j++ {
		caCert := chain[j]
		cons, present, err := nameconstraints.FromExtensions(caCert.Extensions)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: unparseable name constraints: %v", shortName(caCert.Subject), err))
			continue
		}
		if !present {
			continue
		}
		constrained = true
		for k := 0; k < j; k++ {
			sub := chain[k]
			res := cons.Validate(identityOf(sub))
			for _, v := range res.Violations {
				findings = append(findings, fmt.Sprintf("%s violates the name constraints asserted by %s: %s",
					shortName(sub.Subject), shortName(caCert.Subject), v.String()))
			}
		}
	}
	switch {
	case len(findings) > 0:
		rep.fail(Check{Name: "name_constraints", Status: CheckFail,
			Detail: "one or more certificates fall outside their issuer's name constraints", Findings: findings})
	case constrained:
		rep.addCheck(Check{Name: "name_constraints", Status: CheckPass, Detail: "all names lie within every issuer's name constraints"})
	default:
		rep.addCheck(Check{Name: "name_constraints", Status: CheckSkipped, Detail: "no CA in the resolved path carries name constraints"})
	}
}

// checkCertificatePolicy reports certificate-policy conformance across the chain.
// It computes the common policy set (treating anyPolicy, and a certificate that
// asserts no policy, as a wildcard) and reports it. A concrete, non-empty common
// set passes; an empty set where distinct concrete policies were asserted is a
// warning (an inconsistent policy path) rather than a hard failure, matching the
// lenient posture typical of internal PKIs.
func checkCertificatePolicy(rep *Report, chain []*x509.Certificate) {
	if !rep.ChainBuilt {
		rep.addCheck(Check{Name: "certificate_policy", Status: CheckSkipped, Detail: "no chain to evaluate"})
		return
	}
	anyConcrete := false
	common := map[string]bool(nil) // nil = unconstrained so far (wildcard)
	for _, c := range chain {
		pols := policyOIDs(c)
		concrete := withoutAnyPolicy(pols)
		if len(concrete) == 0 {
			// anyPolicy or no policy: this certificate does not restrict the set.
			continue
		}
		anyConcrete = true
		set := make(map[string]bool, len(concrete))
		for _, p := range concrete {
			set[p] = true
		}
		if common == nil {
			common = set
			continue
		}
		for p := range common {
			if !set[p] {
				delete(common, p)
			}
		}
	}
	if !anyConcrete {
		rep.addCheck(Check{Name: "certificate_policy", Status: CheckSkipped, Detail: "no certificate policies asserted in the chain"})
		return
	}
	if len(common) == 0 {
		rep.warn(Check{Name: "certificate_policy", Status: CheckWarn,
			Detail: "certificate policies do not form a common set across the chain (no policy is valid for the full path)"})
		return
	}
	rep.addCheck(Check{Name: "certificate_policy", Status: CheckPass,
		Detail:   "a consistent certificate-policy path exists",
		Findings: sortedKeys(common)})
}

// checkKeyUsage reports structural key-usage / basic-constraints conformance:
// every CA in the path must be a CA that may sign certificates, and the leaf must
// not claim the certificate-signing usage. These are reported as warnings, not
// hard failures — the path builder already enforces basic-constraints for chain
// construction; this dimension surfaces the finer-grained key-usage posture.
func checkKeyUsage(rep *Report, chain []*x509.Certificate) {
	if !rep.ChainBuilt {
		rep.addCheck(Check{Name: "key_usage", Status: CheckSkipped, Detail: "no chain to evaluate"})
		return
	}
	var findings []string
	leaf := chain[0]
	if !leaf.IsCA && leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		findings = append(findings, fmt.Sprintf("%s (leaf) asserts keyCertSign but is not a CA", shortName(leaf.Subject)))
	}
	for j := 1; j < len(chain); j++ {
		ca := chain[j]
		if !ca.IsCA {
			findings = append(findings, fmt.Sprintf("%s occupies a CA position but lacks basicConstraints CA=TRUE", shortName(ca.Subject)))
		}
		if ca.KeyUsage != 0 && ca.KeyUsage&x509.KeyUsageCertSign == 0 {
			findings = append(findings, fmt.Sprintf("%s is a CA but its keyUsage omits keyCertSign", shortName(ca.Subject)))
		}
	}
	if len(findings) > 0 {
		rep.warn(Check{Name: "key_usage", Status: CheckWarn, Detail: "key-usage / basic-constraints anomalies", Findings: findings})
		return
	}
	rep.addCheck(Check{Name: "key_usage", Status: CheckPass, Detail: "CA and leaf key-usage / basic-constraints are consistent"})
}

func checkWeakKey(rep *Report) {
	var findings []string
	for _, ci := range rep.Chain {
		if ci.WeakKey {
			findings = append(findings, fmt.Sprintf("%s (serial %s): %s", shortName(ci.Subject), ci.SerialNumber, strings.Join(ci.WeakKeyReasons, "; ")))
		}
	}
	if len(findings) > 0 {
		rep.fail(Check{Name: "weak_key", Status: CheckFail, Detail: "one or more certificates carry a weak or compromised public key", Findings: findings})
		return
	}
	rep.addCheck(Check{Name: "weak_key", Status: CheckPass, Detail: "no weak or known-compromised public keys in the chain"})
}

// checkWeakSignature flags SHA-1/MD5 certificate signatures. A weak signature on
// a leaf or intermediate is a hard failure; a self-signed trust anchor signed
// with a weak algorithm is only a warning, since an anchor is trusted by explicit
// configuration rather than by verifying its own signature.
func checkWeakSignature(rep *Report) {
	var hard, soft []string
	for _, ci := range rep.Chain {
		if !ci.WeakSignature {
			continue
		}
		msg := fmt.Sprintf("%s (serial %s): %s", shortName(ci.Subject), ci.SerialNumber, ci.SignatureAlgorithm)
		if ci.IsTrustAnchor && ci.SelfSigned {
			soft = append(soft, msg)
		} else {
			hard = append(hard, msg)
		}
	}
	switch {
	case len(hard) > 0:
		rep.fail(Check{Name: "weak_signature", Status: CheckFail,
			Detail: "one or more certificates use a deprecated (SHA-1/MD5) signature algorithm", Findings: append(hard, soft...)})
	case len(soft) > 0:
		rep.warn(Check{Name: "weak_signature", Status: CheckWarn,
			Detail: "the self-signed trust anchor uses a deprecated signature algorithm (trusted by configuration, not by its own signature)", Findings: soft})
	default:
		rep.addCheck(Check{Name: "weak_signature", Status: CheckPass, Detail: "no deprecated signature algorithms in the chain"})
	}
}

// --- Report mutation helpers ---

func (r *Report) addCheck(c Check) { r.Checks = append(r.Checks, c) }

// fail records a failing check and its detail as a top-level reason.
func (r *Report) fail(c Check) {
	r.addCheck(c)
	reason := c.Detail
	if len(c.Findings) > 0 {
		reason = c.Detail + ": " + strings.Join(c.Findings, "; ")
	}
	r.Reasons = append(r.Reasons, reason)
}

// warn records a warning check and its detail as a top-level warning.
func (r *Report) warn(c Check) {
	r.addCheck(c)
	warning := c.Detail
	if len(c.Findings) > 0 {
		warning = c.Detail + ": " + strings.Join(c.Findings, "; ")
	}
	r.Warnings = append(r.Warnings, warning)
}

func (r *Report) leaf() *CertInfo {
	if len(r.Chain) == 0 {
		return nil
	}
	return &r.Chain[0]
}

// --- certificate analysis + rendering helpers ---

func analyzeCert(pos int, c *x509.Certificate, now time.Time, kc keycheck.Policy) CertInfo {
	alg, size := keyDetails(c)
	fp := sha256.Sum256(c.Raw)
	ci := CertInfo{
		Position:           pos,
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialNumber:       serialString(c.SerialNumber),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		IsCA:               c.IsCA,
		SelfSigned:         bytesEqual(c.RawSubject, c.RawIssuer),
		KeyAlgorithm:       alg,
		KeySize:            size,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		Fingerprint:        "sha256:" + hex.EncodeToString(fp[:]),
		SubjectKeyID:       hex.EncodeToString(c.SubjectKeyId),
		AuthorityKeyID:     hex.EncodeToString(c.AuthorityKeyId),
		KeyUsage:           keyUsageNames(c.KeyUsage),
		ExtKeyUsage:        extKeyUsageNames(c),
		Policies:           policyOIDs(c),
		Expired:            now.After(c.NotAfter),
		NotYetValid:        now.Before(c.NotBefore),
	}
	if res := keycheck.Inspect(c.PublicKey, kc); !res.OK() {
		ci.WeakKey = true
		for _, f := range res.Findings {
			ci.WeakKeyReasons = append(ci.WeakKeyReasons, fmt.Sprintf("%s: %s", f.Code, f.Detail))
		}
	}
	ci.WeakSignature = isDeprecatedSignature(c.SignatureAlgorithm)
	return ci
}

func identityOf(c *x509.Certificate) nameconstraints.Identity {
	uris := make([]string, 0, len(c.URIs))
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	return nameconstraints.Identity{
		DNSNames: c.DNSNames,
		IPs:      c.IPAddresses,
		Emails:   c.EmailAddresses,
		URIs:     uris,
		Subject:  c.Subject,
	}
}

// keyDetails returns a certificate's public-key algorithm name and size in bits.
func keyDetails(c *x509.Certificate) (string, int) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			return "ECDSA", pub.Curve.Params().BitSize
		}
		return "ECDSA", 0
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return c.PublicKeyAlgorithm.String(), 0
	}
}

// isDeprecatedSignature reports whether a signature algorithm relies on SHA-1 or
// MD5/MD2, all disallowed for certificate signatures.
func isDeprecatedSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// keyUsageNames renders an x509.KeyUsage bitmask as its named usages, in the
// canonical RFC 5280 order.
func keyUsageNames(ku x509.KeyUsage) []string {
	all := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var out []string
	for _, u := range all {
		if ku&u.bit != 0 {
			out = append(out, u.name)
		}
	}
	return out
}

// extKeyUsageNames renders a certificate's extended key usages (both the known
// enum values and any unknown OIDs) as strings.
func extKeyUsageNames(c *x509.Certificate) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "any",
		x509.ExtKeyUsageServerAuth:                 "serverAuth",
		x509.ExtKeyUsageClientAuth:                 "clientAuth",
		x509.ExtKeyUsageCodeSigning:                "codeSigning",
		x509.ExtKeyUsageEmailProtection:            "emailProtection",
		x509.ExtKeyUsageIPSECEndSystem:             "ipsecEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                "ipsecTunnel",
		x509.ExtKeyUsageIPSECUser:                  "ipsecUser",
		x509.ExtKeyUsageTimeStamping:               "timeStamping",
		x509.ExtKeyUsageOCSPSigning:                "ocspSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "microsoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "netscapeServerGatedCrypto",
	}
	var out []string
	for _, e := range c.ExtKeyUsage {
		if n, ok := names[e]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("eku(%d)", int(e)))
		}
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return out
}

// policyOIDs renders a certificate's certificate-policy OIDs as dotted strings.
func policyOIDs(c *x509.Certificate) []string {
	var out []string
	for _, oid := range c.PolicyIdentifiers {
		out = append(out, oid.String())
	}
	return out
}

func withoutAnyPolicy(pols []string) []string {
	var out []string
	for _, p := range pols {
		if p != oidAnyPolicy.String() {
			out = append(out, p)
		}
	}
	return out
}

func serialString(s *big.Int) string {
	if s == nil {
		return ""
	}
	return s.String()
}

// shortName renders the CN of a distinguished name (falling back to the full DN)
// for compact messages.
func shortName(dn interface{}) string {
	s := fmt.Sprintf("%v", dn)
	if m := strings.Index(s, "CN="); m >= 0 {
		rest := s[m+3:]
		if comma := strings.Index(rest, ","); comma >= 0 {
			return strings.TrimSpace(rest[:comma])
		}
		return strings.TrimSpace(rest)
	}
	if len(s) > 60 {
		return s[:59] + "…"
	}
	return s
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
