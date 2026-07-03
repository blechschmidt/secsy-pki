// Package fips implements the FIPS 140-3 crypto policy (Task 65). It has two
// independent halves that operators combine for a FIPS deployment:
//
//   - The *module* state reports whether the binary is running on the Go
//     Cryptographic Module (built with GOFIPS140, or forced with
//     GODEBUG=fips140=on). That is a build/runtime property of the Go
//     toolchain; this package only observes it.
//
//   - The *policy* is secsy-pki's own fail-closed algorithm allowlist, enabled
//     by `security.fips: true` in the configuration. When enforced, key
//     generation, certificate issuance, and the secret envelope layer reject
//     algorithms outside the approved set below with ErrNotApproved.
//
// The two are deliberately decoupled: GODEBUG=fips140=on alone does NOT block
// non-approved algorithms (only fips140=only does, and that mode panics deep
// inside libraries), so the policy layer is what actually guarantees "no
// Ed25519 leaves, no SHA-1, no RSA<2048, no software PQC" — and it also works
// on a non-FIPS build for staging rehearsals. A deployment claiming FIPS 140-3
// operation needs both: the FIPS build (validated module boundary) and the
// policy (approved algorithms only). See docs/fips.md.
//
// Approved by the policy:
//
//   - RSA with modulus >= 2048 bits
//   - ECDSA over NIST P-256 / P-384 / P-521
//   - SHA-224 / SHA-256 / SHA-384 / SHA-512 (and SHA-512/224, SHA-512/256)
//
// Rejected (fail closed — anything not listed above is also rejected):
//
//   - Ed25519. It is present in the Go module, but FIPS 186-5 EdDSA support
//     across validated HSMs, protocols, and relying parties is inconsistent;
//     the policy takes the conservative interoperable subset.
//   - ML-DSA (FIPS 204) and hybrid certificates. The implementation is
//     CIRCL, software outside the validated module boundary.
//   - SHA-1 and MD5 anywhere, including the SoftHSM RSA-OAEP SHA-1 fallback
//     in the secret layer.
//
// The policy is process-global, set once at configuration load (config.Load
// mirrors security.fips into SetPolicy), matching how custom certificate
// profiles are installed. Enforcement points call the Check* wrappers, which
// are free no-ops until the policy is enforced.
package fips

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
)

// ErrNotApproved is wrapped by every policy rejection so callers can classify
// FIPS-policy failures with errors.Is.
var ErrNotApproved = errors.New("not approved by the FIPS 140-3 crypto policy (security.fips)")

// policyEnforced is the process-global policy switch. It is set once at
// configuration load; tests toggle it via SetPolicy with a cleanup.
var policyEnforced atomic.Bool

// SetPolicy turns fail-closed algorithm enforcement on or off. config.Load
// calls it with the value of security.fips; nothing else should flip it in
// production code.
func SetPolicy(on bool) { policyEnforced.Store(on) }

// PolicyEnforced reports whether the fail-closed algorithm policy is active.
func PolicyEnforced() bool { return policyEnforced.Load() }

// ModuleEnabled reports whether this process is running on the Go
// Cryptographic Module (FIPS 140-3 mode) — true for binaries built with
// GOFIPS140 (whose default GODEBUG includes fips140=on) and for any binary
// started with GODEBUG=fips140=on.
func ModuleEnabled() bool { return fips140.Enabled() }

// ModuleVersion returns the GOFIPS140 module selection the binary was built
// with ("latest", "v1.0.0", …), or "" when it was not built as a FIPS binary.
// Note a non-FIPS build can still run with GODEBUG=fips140=on; ModuleEnabled
// is the runtime truth, ModuleVersion identifies the frozen module snapshot.
func ModuleVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "GOFIPS140" {
			return s.Value
		}
	}
	return ""
}

// Summary renders the module and policy state for startup logs, /healthz build
// info, and `-version` output, e.g. "fips140=on (GOFIPS140=latest) policy=enforced".
func Summary() string {
	module := "off"
	if ModuleEnabled() {
		module = "on"
	}
	if v := ModuleVersion(); v != "" {
		module += " (GOFIPS140=" + v + ")"
	}
	policy := "off"
	if PolicyEnforced() {
		policy = "enforced"
	}
	return fmt.Sprintf("fips140=%s policy=%s", module, policy)
}

// --- unconditional validators -----------------------------------------------
//
// The Approved* functions evaluate regardless of the global policy switch.
// Configuration validation uses them (the config being validated carries its
// own security.fips flag); runtime enforcement points use the policy-gated
// Check* wrappers below.

// ApprovedPublicKey validates a subject or issuer public key against the
// policy: RSA >= 2048 bits or ECDSA on P-256/P-384/P-521. Anything else —
// Ed25519, ML-DSA, small RSA, exotic curves, unknown types — is rejected.
func ApprovedPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < 2048 {
			return fmt.Errorf("RSA-%d key: modulus below 2048 bits is %w", bits, ErrNotApproved)
		}
		return nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		name := "unknown"
		if k.Curve != nil && k.Curve.Params() != nil {
			name = k.Curve.Params().Name
		}
		return fmt.Errorf("ECDSA curve %s is %w", name, ErrNotApproved)
	case ed25519.PublicKey:
		return fmt.Errorf("Ed25519 key is %w", ErrNotApproved)
	default:
		return fmt.Errorf("%T key is %w", pub, ErrNotApproved)
	}
}

// ApprovedHash validates a hash function against the policy (SHA-2 family
// only). SHA-1 and MD5 are explicitly rejected; unknown hashes fail closed.
func ApprovedHash(h crypto.Hash) error {
	switch h {
	case crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512,
		crypto.SHA512_224, crypto.SHA512_256:
		return nil
	default:
		return fmt.Errorf("hash %v is %w", h, ErrNotApproved)
	}
}

// ApprovedHashName is ApprovedHash for configuration strings ("sha256", ...).
// It exists so the config package can validate hash names without depending on
// each subsystem's name-to-hash table.
func ApprovedHashName(name string) error {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sha224", "sha-224", "sha256", "sha-256", "sha384", "sha-384", "sha512", "sha-512":
		return nil
	default:
		return fmt.Errorf("hash %q is %w", name, ErrNotApproved)
	}
}

// ApprovedSignatureAlgorithm validates an X.509 signature algorithm: RSA
// (PKCS#1 v1.5 or PSS) and ECDSA with a SHA-2 digest. SHA-1-based algorithms,
// pure Ed25519, DSA, and MD variants are rejected.
func ApprovedSignatureAlgorithm(alg x509.SignatureAlgorithm) error {
	switch alg {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return nil
	default:
		return fmt.Errorf("signature algorithm %v is %w", alg, ErrNotApproved)
	}
}

// ApprovedKeyType validates a key-generation type string. It understands the
// canonical keyprovider vocabulary plus the common aliases NormalizeKeyType
// accepts, without importing keyprovider (which imports this package):
// "rsa-<bits>" parses the modulus, "ec"/"ecdsa"/"p256…p521" map to NIST
// curves, and anything Ed25519- or ML-DSA-shaped is rejected. Unknown strings
// fail closed.
func ApprovedKeyType(keyType string) error {
	kt := strings.ToLower(strings.TrimSpace(keyType))
	switch kt {
	case "":
		// Callers apply their own defaults (which are approved types); an empty
		// string here means "default", not "unknown".
		return nil
	case "ed25519", "ssh-ed25519":
		return fmt.Errorf("key type %q (Ed25519) is %w", keyType, ErrNotApproved)
	case "ecdsa", "ec",
		"ecdsa-p256", "p256", "ecdsa-sha2-nistp256", "nistp256",
		"ecdsa-p384", "p384", "ecdsa-sha2-nistp384", "nistp384",
		"ecdsa-p521", "p521", "ecdsa-sha2-nistp521", "nistp521":
		return nil
	}
	if strings.HasPrefix(kt, "ml-dsa") || strings.HasPrefix(kt, "mldsa") || strings.HasPrefix(kt, "dilithium") {
		return fmt.Errorf("key type %q (ML-DSA via the software CIRCL implementation) is outside the validated module and %w", keyType, ErrNotApproved)
	}
	if kt == "rsa" {
		return nil // providers default plain "rsa" to 2048
	}
	if rest, ok := strings.CutPrefix(kt, "rsa-"); ok || strings.HasPrefix(kt, "rsa") {
		if !ok {
			rest = strings.TrimPrefix(kt, "rsa")
		}
		bits, err := strconv.Atoi(rest)
		if err != nil {
			return fmt.Errorf("key type %q is %w", keyType, ErrNotApproved)
		}
		if bits < 2048 {
			return fmt.Errorf("key type %q: RSA below 2048 bits is %w", keyType, ErrNotApproved)
		}
		return nil
	}
	return fmt.Errorf("key type %q is %w", keyType, ErrNotApproved)
}

// --- policy-gated enforcement points -----------------------------------------
//
// The Check* wrappers are the runtime gates: they pass everything through
// until the policy is enforced, so call sites stay unconditional one-liners.

// CheckPublicKey is ApprovedPublicKey gated on the policy.
func CheckPublicKey(pub crypto.PublicKey) error {
	if !PolicyEnforced() {
		return nil
	}
	return ApprovedPublicKey(pub)
}

// CheckHash is ApprovedHash gated on the policy.
func CheckHash(h crypto.Hash) error {
	if !PolicyEnforced() {
		return nil
	}
	return ApprovedHash(h)
}

// CheckSignatureAlgorithm is ApprovedSignatureAlgorithm gated on the policy.
func CheckSignatureAlgorithm(alg x509.SignatureAlgorithm) error {
	if !PolicyEnforced() {
		return nil
	}
	return ApprovedSignatureAlgorithm(alg)
}

// CheckKeyType is ApprovedKeyType gated on the policy. Key providers call it
// on every GenerateKey, making key generation the single chokepoint that keeps
// non-approved key material from ever existing in a FIPS deployment.
func CheckKeyType(keyType string) error {
	if !PolicyEnforced() {
		return nil
	}
	return ApprovedKeyType(keyType)
}

// CheckIssuance gates certificate creation: both the issuing key and the
// subject key must be approved. pki's certificate constructors call it, so
// every X.509 signing path (root/intermediate/cross-sign/leaf) is covered —
// including legacy non-approved CA keys created before the policy was enabled.
func CheckIssuance(issuerPub, subjectPub crypto.PublicKey) error {
	if !PolicyEnforced() {
		return nil
	}
	if err := ApprovedPublicKey(issuerPub); err != nil {
		return fmt.Errorf("issuer key: %w", err)
	}
	if err := ApprovedPublicKey(subjectPub); err != nil {
		return fmt.Errorf("subject key: %w", err)
	}
	return nil
}
