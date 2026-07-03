package fips

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// withPolicy runs the test body with the global policy set, restoring the
// previous state afterwards. Policy tests must not run in parallel.
func withPolicy(t *testing.T, on bool) {
	t.Helper()
	prev := PolicyEnforced()
	SetPolicy(on)
	t.Cleanup(func() { SetPolicy(prev) })
}

func TestApprovedPublicKey(t *testing.T) {
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skipf("cannot generate RSA-1024 probe key in this mode: %v", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := ApprovedPublicKey(&rsa2048.PublicKey); err != nil {
		t.Errorf("RSA-2048 rejected: %v", err)
	}
	if err := ApprovedPublicKey(&p256.PublicKey); err != nil {
		t.Errorf("P-256 rejected: %v", err)
	}
	for name, pub := range map[string]any{
		"rsa-1024": &rsa1024.PublicKey,
		"p-224":    &p224.PublicKey,
		"ed25519":  edPub,
		"unknown":  struct{}{},
	} {
		err := ApprovedPublicKey(pub)
		if !errors.Is(err, ErrNotApproved) {
			t.Errorf("%s: want ErrNotApproved, got %v", name, err)
		}
	}
}

func TestApprovedHashAndSignatureAlgorithm(t *testing.T) {
	for _, name := range []string{"sha256", "SHA-384", " sha512 "} {
		if err := ApprovedHashName(name); err != nil {
			t.Errorf("hash name %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"sha1", "sha-1", "md5", "blake2b", ""} {
		if err := ApprovedHashName(name); !errors.Is(err, ErrNotApproved) {
			t.Errorf("hash name %q: want ErrNotApproved, got %v", name, err)
		}
	}

	good := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA384,
	}
	for _, alg := range good {
		if err := ApprovedSignatureAlgorithm(alg); err != nil {
			t.Errorf("%v rejected: %v", alg, err)
		}
	}
	bad := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.PureEd25519,
		x509.MD5WithRSA, x509.DSAWithSHA256, x509.UnknownSignatureAlgorithm,
	}
	for _, alg := range bad {
		if err := ApprovedSignatureAlgorithm(alg); !errors.Is(err, ErrNotApproved) {
			t.Errorf("%v: want ErrNotApproved, got %v", alg, err)
		}
	}
}

func TestApprovedKeyType(t *testing.T) {
	ok := []string{
		"", "rsa", "rsa-2048", "rsa-4096", "rsa4096", "rsa-3072",
		"ecdsa", "ecdsa-p256", "ecdsa-sha2-nistp384", "p521", "P256",
	}
	for _, kt := range ok {
		if err := ApprovedKeyType(kt); err != nil {
			t.Errorf("key type %q rejected: %v", kt, err)
		}
	}
	bad := []string{
		"ed25519", "ssh-ed25519", "rsa-1024", "rsa1024", "rsa-512",
		"ml-dsa-65", "mldsa87", "dilithium3", "x25519", "dsa", "gibberish",
	}
	for _, kt := range bad {
		if err := ApprovedKeyType(kt); !errors.Is(err, ErrNotApproved) {
			t.Errorf("key type %q: want ErrNotApproved, got %v", kt, err)
		}
	}
	// The ML-DSA rejection names the module-boundary reason.
	if err := ApprovedKeyType("ml-dsa-65"); err == nil || !strings.Contains(err.Error(), "outside the validated module") {
		t.Errorf("ml-dsa-65 rejection should explain the module boundary, got: %v", err)
	}
}

func TestPolicyGating(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	withPolicy(t, false)
	if err := CheckPublicKey(edPub); err != nil {
		t.Errorf("policy off: CheckPublicKey should pass, got %v", err)
	}
	if err := CheckKeyType("ml-dsa-65"); err != nil {
		t.Errorf("policy off: CheckKeyType should pass, got %v", err)
	}
	if err := CheckIssuance(edPub, edPub); err != nil {
		t.Errorf("policy off: CheckIssuance should pass, got %v", err)
	}

	SetPolicy(true)
	if err := CheckPublicKey(edPub); !errors.Is(err, ErrNotApproved) {
		t.Errorf("policy on: want ErrNotApproved, got %v", err)
	}
	if err := CheckKeyType("ed25519"); !errors.Is(err, ErrNotApproved) {
		t.Errorf("policy on: want ErrNotApproved, got %v", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckIssuance(&p256.PublicKey, edPub); err == nil || !strings.Contains(err.Error(), "subject key") {
		t.Errorf("policy on: CheckIssuance should name the offending key, got %v", err)
	}
	if err := CheckIssuance(&p256.PublicKey, &p256.PublicKey); err != nil {
		t.Errorf("policy on: approved issuance rejected: %v", err)
	}
}

func TestSummary(t *testing.T) {
	withPolicy(t, true)
	s := Summary()
	if !strings.Contains(s, "policy=enforced") || !strings.Contains(s, "fips140=") {
		t.Errorf("Summary() = %q, want module and policy state", s)
	}
}
