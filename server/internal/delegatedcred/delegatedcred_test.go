package delegatedcred

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// makeLeaf builds a self-signed end-entity certificate of the given key type that
// is eligible to authorize delegated credentials (DelegationUsage +
// digitalSignature). It returns the parsed certificate and its private key.
func makeLeaf(t *testing.T, keyType string, notBefore time.Time) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := GenerateKey(keyType)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", keyType, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:       notBefore,
		NotAfter:        notBefore.Add(30 * 24 * time.Hour),
		DNSNames:        []string{"leaf.example.com"},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{pki.DelegationUsageExtension()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

// TestMintVerifyRoundTrip exercises every supported leaf-key type through a full
// mint -> wire -> parse -> verify round trip, for both endpoint roles, and
// confirms the wire form is stable.
func TestMintVerifyRoundTrip(t *testing.T) {
	leafTypes := []string{"ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "rsa-2048", "ed25519"}
	dcTypes := []string{"ecdsa-p256", "rsa-2048", "ed25519"}
	now := time.Now()

	for _, lt := range leafTypes {
		for _, dt := range dcTypes {
			for _, endpoint := range []Endpoint{ServerEndpoint, ClientEndpoint} {
				name := lt + "-leaf/" + dt + "-dc"
				if endpoint == ClientEndpoint {
					name += "/client"
				}
				t.Run(name, func(t *testing.T) {
					// Fresh certificate so valid_time stays under the 7-day cap.
					cert, leafKey := makeLeaf(t, lt, now.Add(-time.Minute))
					dcKey, err := GenerateKey(dt)
					if err != nil {
						t.Fatalf("GenerateKey(%s): %v", dt, err)
					}

					res, err := Mint(MintRequest{
						LeafCert:    cert,
						LeafKey:     leafKey,
						DCPublicKey: dcKey.Public(),
						ValidFor:    24 * time.Hour,
						Endpoint:    endpoint,
						Now:         now,
					})
					if err != nil {
						t.Fatalf("Mint: %v", err)
					}

					// The credential is signed by the leaf key and verifies.
					if err := res.DelegatedCredential.Verify(cert, endpoint); err != nil {
						t.Fatalf("Verify (in-memory): %v", err)
					}

					// Wire round-trip: parse and verify the serialized form.
					parsed, err := Parse(res.Wire)
					if err != nil {
						t.Fatalf("Parse: %v", err)
					}
					if err := parsed.Verify(cert, endpoint); err != nil {
						t.Fatalf("Verify (parsed): %v", err)
					}
					// Re-marshaling the parsed DC reproduces the exact wire bytes.
					if rewire, err := parsed.Marshal(); err != nil {
						t.Fatalf("Marshal(parsed): %v", err)
					} else if !bytes.Equal(rewire, res.Wire) {
						t.Errorf("re-marshaled wire differs from original")
					}

					// The delegated public key round-trips to the one we supplied.
					gotPub, err := parsed.DelegatedPublicKey()
					if err != nil {
						t.Fatalf("DelegatedPublicKey: %v", err)
					}
					if err := publicKeyMatches(gotPub, dcKey.Public()); err != nil {
						t.Errorf("delegated public key mismatch: %v", err)
					}

					// The credential is valid now and invalid after its expiry.
					if !parsed.ValidAt(cert, now) {
						t.Error("ValidAt(now) = false, want true")
					}
					if parsed.ValidAt(cert, res.NotAfter.Add(time.Second)) {
						t.Error("ValidAt(after expiry) = true, want false")
					}
				})
			}
		}
	}
}

// TestVerifyRejectsWrongEndpoint proves the endpoint context string is bound into
// the signature: a server DC must not verify as a client DC.
func TestVerifyRejectsWrongEndpoint(t *testing.T) {
	now := time.Now()
	cert, leafKey := makeLeaf(t, "ecdsa-p256", now.Add(-time.Minute))
	dcKey, _ := GenerateKey("ecdsa-p256")
	res, err := Mint(MintRequest{
		LeafCert: cert, LeafKey: leafKey, DCPublicKey: dcKey.Public(),
		ValidFor: time.Hour, Endpoint: ServerEndpoint, Now: now,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := res.DelegatedCredential.Verify(cert, ServerEndpoint); err != nil {
		t.Fatalf("Verify(server): %v", err)
	}
	if err := res.DelegatedCredential.Verify(cert, ClientEndpoint); err == nil {
		t.Error("Verify(client) accepted a server-context delegated credential")
	}
}

// TestVerifyDetectsTampering proves a modified credential (public key or
// signature) fails verification.
func TestVerifyDetectsTampering(t *testing.T) {
	now := time.Now()
	cert, leafKey := makeLeaf(t, "ecdsa-p256", now.Add(-time.Minute))
	dcKey, _ := GenerateKey("ecdsa-p256")
	res, err := Mint(MintRequest{
		LeafCert: cert, LeafKey: leafKey, DCPublicKey: dcKey.Public(),
		ValidFor: time.Hour, Now: now,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Tamper with the signature.
	bad := *res.DelegatedCredential
	bad.Signature = append([]byte(nil), res.DelegatedCredential.Signature...)
	bad.Signature[len(bad.Signature)-1] ^= 0xff
	if err := bad.Verify(cert, ServerEndpoint); err == nil {
		t.Error("Verify accepted a credential with a tampered signature")
	}

	// Tamper with valid_time (the signature covers cred, so this must fail).
	bad2 := *res.DelegatedCredential
	bad2.Cred.ValidTime = res.DelegatedCredential.Cred.ValidTime - 1
	if err := bad2.Verify(cert, ServerEndpoint); err == nil {
		t.Error("Verify accepted a credential with a tampered valid_time")
	}

	// A different certificate (thus a different key) must not verify it.
	otherCert, _ := makeLeaf(t, "ecdsa-p256", now.Add(-time.Minute))
	if err := res.DelegatedCredential.Verify(otherCert, ServerEndpoint); err == nil {
		t.Error("Verify accepted a credential against an unrelated certificate")
	}
}

// TestMintEnforcesValidTimeCap proves the RFC 9345 seven-day maximum is enforced,
// both by an over-long ValidFor and by a stale certificate notBefore.
func TestMintEnforcesValidTimeCap(t *testing.T) {
	now := time.Now()
	dcKey, _ := GenerateKey("ecdsa-p256")

	// Over-long request on a fresh certificate.
	fresh, leafKey := makeLeaf(t, "ecdsa-p256", now.Add(-time.Minute))
	if _, err := Mint(MintRequest{
		LeafCert: fresh, LeafKey: leafKey, DCPublicKey: dcKey.Public(),
		ValidFor: MaxValidTime + time.Hour, Now: now,
	}); err == nil {
		t.Error("Mint accepted a valid_for exceeding the 7-day maximum")
	}

	// A modest request but a stale certificate: notBefore + valid_time exceeds the
	// cap because the certificate is already old.
	stale, staleKey := makeLeaf(t, "ecdsa-p256", now.Add(-6*24*time.Hour))
	if _, err := Mint(MintRequest{
		LeafCert: stale, LeafKey: staleKey, DCPublicKey: dcKey.Public(),
		ValidFor: 3 * 24 * time.Hour, Now: now,
	}); err == nil {
		t.Error("Mint accepted a credential whose valid_time exceeds the cap due to a stale certificate")
	}

	// Exactly the maximum, from a certificate whose notBefore is the same whole
	// second as Now, is accepted (valid_time == 604800). Whole-second times avoid
	// the sub-second notBefore truncation X.509 applies on parse.
	base := now.Truncate(time.Second)
	atNow, atNowKey := makeLeaf(t, "ecdsa-p256", base)
	res, err := Mint(MintRequest{
		LeafCert: atNow, LeafKey: atNowKey, DCPublicKey: dcKey.Public(),
		ValidFor: MaxValidTime, Now: base,
	})
	if err != nil {
		t.Errorf("Mint rejected an exactly-7-day credential from a same-instant notBefore: %v", err)
	} else if res.ValidTime != uint32(MaxValidTime/time.Second) {
		t.Errorf("valid_time = %d, want %d", res.ValidTime, uint32(MaxValidTime/time.Second))
	}
}

// TestMintRejectsIneligibleAndMismatched covers the eligibility and key-match
// guards.
func TestMintRejectsIneligibleAndMismatched(t *testing.T) {
	now := time.Now()
	dcKey, _ := GenerateKey("ecdsa-p256")

	// Certificate without the DelegationUsage extension.
	ineligibleKey, _ := GenerateKey("ecdsa-p256")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "plain.example.com"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, ineligibleKey.Public(), ineligibleKey)
	ineligible, _ := x509.ParseCertificate(der)
	if _, err := Mint(MintRequest{
		LeafCert: ineligible, LeafKey: ineligibleKey, DCPublicKey: dcKey.Public(), ValidFor: time.Hour, Now: now,
	}); err == nil {
		t.Error("Mint accepted an ineligible certificate (no DelegationUsage extension)")
	}

	// Eligible certificate but a leaf key that is not the certificate's key.
	eligible, _ := makeLeaf(t, "ecdsa-p256", now.Add(-time.Minute))
	wrongKey, _ := GenerateKey("ecdsa-p256")
	if _, err := Mint(MintRequest{
		LeafCert: eligible, LeafKey: wrongKey, DCPublicKey: dcKey.Public(), ValidFor: time.Hour, Now: now,
	}); err == nil {
		t.Error("Mint accepted a leaf key that does not match the certificate")
	}
}

// TestSchemeResolutionAndOverrides checks default scheme derivation and override
// validation, including the RFC 9345 rejection of RSA PKCS#1 v1.5.
func TestSchemeResolutionAndOverrides(t *testing.T) {
	now := time.Now()
	leaf, leafKey := makeLeaf(t, "rsa-2048", now.Add(-time.Minute))
	dcKey, _ := GenerateKey("ecdsa-p384")

	// Default: RSA leaf -> rsa_pss_rsae_sha256; P-384 DC -> ecdsa_secp384r1_sha384.
	res, err := Mint(MintRequest{
		LeafCert: leaf, LeafKey: leafKey, DCPublicKey: dcKey.Public(), ValidFor: time.Hour, Now: now,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if res.Algorithm != RSAPSSWithSHA256 {
		t.Errorf("default leaf algorithm = %s, want rsa_pss_rsae_sha256", res.Algorithm)
	}
	if res.ExpectedCertVerifyAlgorithm != ECDSAWithP384AndSHA384 {
		t.Errorf("default DC algorithm = %s, want ecdsa_secp384r1_sha384", res.ExpectedCertVerifyAlgorithm)
	}

	// Explicit RSA-PSS-SHA512 override on the leaf is honored.
	res, err = Mint(MintRequest{
		LeafCert: leaf, LeafKey: leafKey, DCPublicKey: dcKey.Public(), ValidFor: time.Hour, Now: now,
		Algorithm: RSAPSSWithSHA512,
	})
	if err != nil {
		t.Fatalf("Mint (override): %v", err)
	}
	if res.Algorithm != RSAPSSWithSHA512 {
		t.Errorf("overridden algorithm = %s, want rsa_pss_rsae_sha512", res.Algorithm)
	}
	if err := res.DelegatedCredential.Verify(leaf, ServerEndpoint); err != nil {
		t.Errorf("Verify with SHA-512 override: %v", err)
	}

	// A curve-mismatched ECDSA override is rejected.
	ecLeaf, ecKey := makeLeaf(t, "ecdsa-p256", now.Add(-time.Minute))
	if _, err := Mint(MintRequest{
		LeafCert: ecLeaf, LeafKey: ecKey, DCPublicKey: dcKey.Public(), ValidFor: time.Hour, Now: now,
		Algorithm: ECDSAWithP384AndSHA384,
	}); err == nil {
		t.Error("Mint accepted a P-384 scheme override for a P-256 leaf key")
	}
}

// TestSchemeFromName covers name and hex-code-point parsing.
func TestSchemeFromName(t *testing.T) {
	cases := map[string]SignatureScheme{
		"ecdsa_secp256r1_sha256": ECDSAWithP256AndSHA256,
		"rsa_pss_rsae_sha384":    RSAPSSWithSHA384,
		"ed25519":                Ed25519,
		"0x0403":                 ECDSAWithP256AndSHA256,
	}
	for name, want := range cases {
		got, err := SchemeFromName(name)
		if err != nil {
			t.Errorf("SchemeFromName(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("SchemeFromName(%q) = %s, want %s", name, got, want)
		}
	}
	for _, bad := range []string{"", "rsa_pkcs1_sha256", "0x9999", "nonsense"} {
		if _, err := SchemeFromName(bad); err == nil {
			t.Errorf("SchemeFromName(%q) = nil error, want error", bad)
		}
	}
}

// TestWireLayout is a known-answer test for the RFC 9345 wire encoding: it locks
// the field widths and byte order (uint32 valid_time, uint16 scheme, uint24-
// prefixed SPKI, uint16 algorithm, uint16-prefixed signature).
func TestWireLayout(t *testing.T) {
	spki := []byte{0xAA, 0xBB, 0xCC}
	cred := Credential{
		ValidTime:                   0x01020304,
		ExpectedCertVerifyAlgorithm: ECDSAWithP256AndSHA256, // 0x0403
		SubjectPublicKeyInfo:        spki,
	}
	wantCred := []byte{
		0x01, 0x02, 0x03, 0x04, // valid_time (big-endian uint32)
		0x04, 0x03, // expected_cert_verify_algorithm
		0x00, 0x00, 0x03, // SPKI length (uint24)
		0xAA, 0xBB, 0xCC, // SPKI
	}
	got, err := cred.marshal()
	if err != nil {
		t.Fatalf("cred.marshal: %v", err)
	}
	if !bytes.Equal(got, wantCred) {
		t.Errorf("credential wire =\n  % x\nwant\n  % x", got, wantCred)
	}

	dc := &DelegatedCredential{Cred: cred, Algorithm: RSAPSSWithSHA256 /*0x0804*/, Signature: []byte{0xDE, 0xAD}}
	wantDC := append(append([]byte(nil), wantCred...),
		0x08, 0x04, // algorithm
		0x00, 0x02, // signature length (uint16)
		0xDE, 0xAD, // signature
	)
	gotDC, err := dc.Marshal()
	if err != nil {
		t.Fatalf("dc.Marshal: %v", err)
	}
	if !bytes.Equal(gotDC, wantDC) {
		t.Errorf("delegated credential wire =\n  % x\nwant\n  % x", gotDC, wantDC)
	}
	// Parse must recover the exact fields.
	parsed, err := Parse(gotDC)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Cred.ValidTime != 0x01020304 || parsed.Cred.ExpectedCertVerifyAlgorithm != ECDSAWithP256AndSHA256 ||
		parsed.Algorithm != RSAPSSWithSHA256 || !bytes.Equal(parsed.Cred.SubjectPublicKeyInfo, spki) ||
		!bytes.Equal(parsed.Signature, []byte{0xDE, 0xAD}) {
		t.Errorf("parsed fields do not match: %+v", parsed)
	}
}

// TestParseRejectsMalformed covers wire-decoding failure modes.
func TestParseRejectsMalformed(t *testing.T) {
	now := time.Now()
	cert, leafKey := makeLeaf(t, "ecdsa-p256", now.Add(-time.Minute))
	dcKey, _ := GenerateKey("ecdsa-p256")
	res, _ := Mint(MintRequest{
		LeafCert: cert, LeafKey: leafKey, DCPublicKey: dcKey.Public(), ValidFor: time.Hour, Now: now,
	})

	// Truncation at various points must be rejected.
	for _, n := range []int{0, 1, 4, 6, 8} {
		if _, err := Parse(res.Wire[:n]); err == nil {
			t.Errorf("Parse(wire[:%d]) accepted a truncated credential", n)
		}
	}
	// Trailing garbage must be rejected.
	if _, err := Parse(append(append([]byte(nil), res.Wire...), 0x00)); err == nil {
		t.Error("Parse accepted a credential with trailing data")
	}
	// The full wire must still parse.
	if _, err := Parse(res.Wire); err != nil {
		t.Errorf("Parse(full wire): %v", err)
	}
}
