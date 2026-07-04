package certvalidate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// --- test certificate factory -------------------------------------------------

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return k
}

// issue signs tmpl with (parent, priv) for the subject public key pub and returns
// the parsed certificate. When parent is nil the certificate is self-signed.
func issue(t *testing.T, tmpl, parent *x509.Certificate, priv, pub any) *x509.Certificate {
	t.Helper()
	signee := parent
	if signee == nil {
		signee = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signee, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", tmpl.Subject.CommonName, err)
	}
	return cert
}

var serialSeq int64

func nextSerial() *big.Int {
	serialSeq++
	return big.NewInt(1000 + serialSeq)
}

func caTemplate(cn string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func leafTemplate(cn string, notBefore, notAfter time.Time, dnsNames ...string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
}

// --- fake revocation resolver -------------------------------------------------

type fakeResolver struct {
	bySerial map[string]RevocationStatus
}

func (f fakeResolver) Revocation(cert, _ *x509.Certificate) (RevocationStatus, error) {
	if s, ok := f.bySerial[cert.SerialNumber.String()]; ok {
		return s, nil
	}
	return RevocationStatus{State: RevocationGood, Source: "fake"}, nil
}

// --- helpers ------------------------------------------------------------------

func checkStatus(r *Report, name string) CheckStatus {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return ""
}

// --- tests --------------------------------------------------------------------

func TestValidateValidChain(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Test Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())

	leafKey := newECKey(t)
	leaf := issue(t, leafTemplate("valid.example.com", now.Add(-time.Minute), now.Add(24*time.Hour), "valid.example.com"),
		root, rootKey, leafKey.Public())

	rep := Validate(Options{
		Roots:      []*x509.Certificate{root},
		Now:        now,
		Revocation: fakeResolver{},
	}, leaf, nil)

	if !rep.ChainBuilt {
		t.Fatalf("chain did not build: %v", rep.Reasons)
	}
	if !rep.Valid {
		t.Fatalf("expected valid chain, got invalid: %v", rep.Reasons)
	}
	if len(rep.Chain) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf + root)", len(rep.Chain))
	}
	if !rep.Chain[1].IsTrustAnchor {
		t.Errorf("top of chain not marked as trust anchor")
	}
	for _, name := range []string{"chain", "validity", "revocation"} {
		if got := checkStatus(rep, name); got != CheckPass {
			t.Errorf("check %q = %q, want pass", name, got)
		}
	}
	if rep.Decision != "valid" {
		t.Errorf("decision = %q, want valid", rep.Decision)
	}
}

func TestValidateExpiredLeaf(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Test Root", now.Add(-2*time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())

	leafKey := newECKey(t)
	// Leaf expired an hour ago.
	leaf := issue(t, leafTemplate("expired.example.com", now.Add(-48*time.Hour), now.Add(-time.Hour), "expired.example.com"),
		root, rootKey, leafKey.Public())

	rep := Validate(Options{Roots: []*x509.Certificate{root}, Now: now}, leaf, nil)

	if !rep.ChainBuilt {
		t.Fatalf("expired leaf should still resolve a path; reasons=%v", rep.Reasons)
	}
	if rep.Valid {
		t.Fatalf("expired leaf must be invalid")
	}
	if got := checkStatus(rep, "validity"); got != CheckFail {
		t.Errorf("validity check = %q, want fail", got)
	}
	if !rep.Chain[0].Expired {
		t.Errorf("leaf not flagged expired")
	}
}

func TestValidateNotYetValidLeaf(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Test Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())
	leafKey := newECKey(t)
	leaf := issue(t, leafTemplate("future.example.com", now.Add(24*time.Hour), now.Add(48*time.Hour), "future.example.com"),
		root, rootKey, leafKey.Public())

	rep := Validate(Options{Roots: []*x509.Certificate{root}, Now: now}, leaf, nil)
	if rep.Valid {
		t.Fatalf("not-yet-valid leaf must be invalid")
	}
	if !rep.Chain[0].NotYetValid {
		t.Errorf("leaf not flagged not-yet-valid")
	}
	if got := checkStatus(rep, "validity"); got != CheckFail {
		t.Errorf("validity check = %q, want fail", got)
	}
}

func TestValidateRevokedLeaf(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Test Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())
	leafKey := newECKey(t)
	leaf := issue(t, leafTemplate("revoked.example.com", now.Add(-time.Minute), now.Add(24*time.Hour), "revoked.example.com"),
		root, rootKey, leafKey.Public())

	res := fakeResolver{bySerial: map[string]RevocationStatus{
		leaf.SerialNumber.String(): {State: RevocationRevoked, RevokedAt: now.Add(-time.Minute), Reason: 1, ReasonText: "keyCompromise", Source: "test"},
	}}
	rep := Validate(Options{Roots: []*x509.Certificate{root}, Now: now, Revocation: res}, leaf, nil)

	if rep.Valid {
		t.Fatalf("revoked leaf must be invalid")
	}
	if got := checkStatus(rep, "revocation"); got != CheckFail {
		t.Errorf("revocation check = %q, want fail", got)
	}
	if rep.Chain[0].Revocation == nil || rep.Chain[0].Revocation.State != RevocationRevoked {
		t.Errorf("leaf revocation state = %+v, want revoked", rep.Chain[0].Revocation)
	}
}

func TestValidateHeldLeaf(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Test Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())
	leafKey := newECKey(t)
	leaf := issue(t, leafTemplate("held.example.com", now.Add(-time.Minute), now.Add(24*time.Hour), "held.example.com"),
		root, rootKey, leafKey.Public())

	res := fakeResolver{bySerial: map[string]RevocationStatus{
		leaf.SerialNumber.String(): {State: RevocationHeld, RevokedAt: now.Add(-time.Minute), Reason: 6, ReasonText: "certificateHold", Source: "test"},
	}}
	rep := Validate(Options{Roots: []*x509.Certificate{root}, Now: now, Revocation: res}, leaf, nil)

	if rep.Valid {
		t.Fatalf("on-hold leaf must be invalid while suspended")
	}
	if got := checkStatus(rep, "revocation"); got != CheckFail {
		t.Errorf("revocation check = %q, want fail (held)", got)
	}
}

func TestValidateUnknownIssuer(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Trusted Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())

	// A leaf issued by an entirely different root the validator does not trust.
	otherKey := newECKey(t)
	other := issue(t, caTemplate("Untrusted Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, otherKey, otherKey.Public())
	leafKey := newECKey(t)
	leaf := issue(t, leafTemplate("stranger.example.com", now.Add(-time.Minute), now.Add(24*time.Hour), "stranger.example.com"),
		other, otherKey, leafKey.Public())

	rep := Validate(Options{Roots: []*x509.Certificate{root}, Now: now}, leaf, nil)

	if rep.ChainBuilt {
		t.Fatalf("chain should NOT build to an untrusted root")
	}
	if rep.Valid {
		t.Fatalf("unknown-issuer leaf must be invalid")
	}
	if got := checkStatus(rep, "chain"); got != CheckFail {
		t.Errorf("chain check = %q, want fail", got)
	}
}

func TestValidateNameConstraintViolation(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("NC Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())

	// Intermediate permits only *.example.com.
	interTmpl := caTemplate("NC Intermediate", now.Add(-time.Hour), now.Add(5*365*24*time.Hour))
	interTmpl.PermittedDNSDomains = []string{"example.com"}
	interTmpl.PermittedDNSDomainsCritical = true
	interKey := newECKey(t)
	inter := issue(t, interTmpl, root, rootKey, interKey.Public())

	// Leaf asserts evil.com — outside the permitted subtree.
	leafKey := newECKey(t)
	leaf := issue(t, leafTemplate("nc-leaf", now.Add(-time.Minute), now.Add(24*time.Hour), "evil.com"),
		inter, interKey, leafKey.Public())

	rep := Validate(Options{
		Roots:         []*x509.Certificate{root},
		Intermediates: []*x509.Certificate{inter},
		Now:           now,
	}, leaf, nil)

	if !rep.ChainBuilt {
		t.Fatalf("chain should build structurally despite the name-constraint violation; reasons=%v", rep.Reasons)
	}
	if rep.Valid {
		t.Fatalf("name-constraint-violating leaf must be invalid")
	}
	if got := checkStatus(rep, "name_constraints"); got != CheckFail {
		t.Errorf("name_constraints check = %q, want fail", got)
	}

	// Control: a leaf inside the permitted subtree passes.
	goodKey := newECKey(t)
	good := issue(t, leafTemplate("good-leaf", now.Add(-time.Minute), now.Add(24*time.Hour), "host.example.com"),
		inter, interKey, goodKey.Public())
	repOK := Validate(Options{
		Roots:         []*x509.Certificate{root},
		Intermediates: []*x509.Certificate{inter},
		Now:           now,
	}, good, nil)
	if !repOK.Valid {
		t.Fatalf("permitted leaf should be valid: %v", repOK.Reasons)
	}
	if got := checkStatus(repOK, "name_constraints"); got != CheckPass {
		t.Errorf("name_constraints check for permitted leaf = %q, want pass", got)
	}
}

// TestValidateSuppliedIntermediate proves the caller can supply the bridging
// intermediate at validation time instead of pre-registering it.
func TestValidateSuppliedIntermediate(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())
	interKey := newECKey(t)
	inter := issue(t, caTemplate("Intermediate", now.Add(-time.Hour), now.Add(5*365*24*time.Hour)), root, rootKey, interKey.Public())
	leafKey := newECKey(t)
	leaf := issue(t, leafTemplate("leaf.example.com", now.Add(-time.Minute), now.Add(24*time.Hour), "leaf.example.com"),
		inter, interKey, leafKey.Public())

	// Only the root is a configured anchor; the intermediate arrives as "supplied".
	rep := Validate(Options{Roots: []*x509.Certificate{root}, Now: now}, leaf, []*x509.Certificate{inter})
	if !rep.ChainBuilt || !rep.Valid {
		t.Fatalf("chain with supplied intermediate should be valid: built=%v reasons=%v", rep.ChainBuilt, rep.Reasons)
	}
	if len(rep.Chain) != 3 {
		t.Fatalf("chain length = %d, want 3", len(rep.Chain))
	}
}

func TestValidateWeakKey(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())

	// A 1024-bit RSA leaf key is below the 2048-bit floor.
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak RSA key: %v", err)
	}
	leaf := issue(t, leafTemplate("weak.example.com", now.Add(-time.Minute), now.Add(24*time.Hour), "weak.example.com"),
		root, rootKey, weakKey.Public())

	rep := Validate(Options{Roots: []*x509.Certificate{root}, Now: now}, leaf, nil)
	if rep.Valid {
		t.Fatalf("weak-key leaf must be invalid")
	}
	if got := checkStatus(rep, "weak_key"); got != CheckFail {
		t.Errorf("weak_key check = %q, want fail", got)
	}
	if !rep.Chain[0].WeakKey {
		t.Errorf("leaf not flagged weak_key")
	}
}

func TestValidateNoAnchors(t *testing.T) {
	now := time.Now()
	rootKey := newECKey(t)
	root := issue(t, caTemplate("Root", now.Add(-time.Hour), now.Add(10*365*24*time.Hour)), nil, rootKey, rootKey.Public())
	leafKey := newECKey(t)
	leaf := issue(t, leafTemplate("leaf.example.com", now.Add(-time.Minute), now.Add(24*time.Hour), "leaf.example.com"),
		root, rootKey, leafKey.Public())

	rep := Validate(Options{Now: now}, leaf, nil)
	if rep.ChainBuilt || rep.Valid {
		t.Fatalf("no anchors: expected chain-not-built and invalid")
	}
	if got := checkStatus(rep, "chain"); got != CheckFail {
		t.Errorf("chain check = %q, want fail", got)
	}
}
