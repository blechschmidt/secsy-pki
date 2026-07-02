package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// ---- configuration / policy ------------------------------------------------

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{"": ModeOff, "off": ModeOff, "PERMISSIVE": ModePermissive, "require": ModeRequire}
	for in, want := range cases {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseMode("bogus"); err == nil {
		t.Error("ParseMode(bogus) should error")
	}
}

func TestNewVerifier_RequireNeedsRoots(t *testing.T) {
	if _, err := NewVerifier(Options{DefaultMode: ModeRequire}); err == nil {
		t.Fatal("require mode without trusted roots should be rejected")
	}
	if _, err := NewVerifier(Options{DefaultMode: ModeOff}); err != nil {
		t.Fatalf("off mode without roots should be fine: %v", err)
	}
}

func TestVerifier_ModeResolution(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModePermissive, map[string]Mode{"strict": ModeRequire, "lax": ModeOff})
	if got := v.Mode("strict"); got != ModeRequire {
		t.Errorf("Mode(strict) = %q", got)
	}
	if got := v.Mode("lax"); got != ModeOff {
		t.Errorf("Mode(lax) = %q", got)
	}
	if got := v.Mode("unlisted"); got != ModePermissive {
		t.Errorf("Mode(unlisted) = %q (want default permissive)", got)
	}
	var nilV *Verifier
	if got := nilV.Mode("x"); got != ModeOff {
		t.Errorf("nil verifier Mode = %q, want off", got)
	}
}

// ---- CBOR round-trip -------------------------------------------------------

func TestCBORRoundTrip(t *testing.T) {
	blob := cborEncode(cborMap(
		kv("fmt", "tpm"),
		kv("n", int64(-257)),
		kv("bytes", []byte{1, 2, 3}),
		kv("arr", cborArr("a", int64(7))),
	))
	v, err := decodeCBOR(blob)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[interface{}]interface{})
	if s, _ := cborMapGet(m, "fmt"); s != "tpm" {
		t.Errorf("fmt = %v", s)
	}
	if n, _ := cborMapGet(m, "n"); n != int64(-257) {
		t.Errorf("n = %v", n)
	}
	if b, _ := cborMapGet(m, "bytes"); string(b.([]byte)) != "\x01\x02\x03" {
		t.Errorf("bytes = %v", b)
	}
}

// ---- EST/SCEP PKCS#10 attestation ------------------------------------------

func makeCSRWithBundle(t *testing.T, deviceKey crypto.Signer, chain []*x509.Certificate) *x509.CertificateRequest {
	t.Helper()
	var exts []pkix.Extension
	if len(chain) > 0 {
		oid, val, err := BuildCSRAttestationExtension(chain)
		if err != nil {
			t.Fatal(err)
		}
		exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier(oid), Value: val})
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-01"}, ExtraExtensions: exts}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestVerifyEnrollment_YubiKeyVerified(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeRequire, nil)

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := pki.yubicoAttestationLeaf(t, deviceKey.Public(), 12345678)
	// The bundle carries only the leaf; the intermediate comes from config.
	csr := makeCSRWithBundle(t, deviceKey, []*x509.Certificate{leaf})

	dec := v.VerifyEnrollment("default", csr)
	if !dec.Allow {
		t.Fatalf("expected allow, got deny: %s", dec.Detail)
	}
	if dec.Result == nil || !dec.Result.Verified {
		t.Fatalf("expected verified result: %+v", dec.Result)
	}
	if dec.Result.Format != FormatYubiKeyPIV {
		t.Errorf("format = %q, want %q", dec.Result.Format, FormatYubiKeyPIV)
	}
	if dec.Result.Serial != "12345678" {
		t.Errorf("serial = %q", dec.Result.Serial)
	}
	if !dec.Result.HardwareResident || !dec.Result.NonExportable {
		t.Errorf("expected hardware-resident, non-exportable: %+v", dec.Result)
	}
}

func TestVerifyEnrollment_MissingUnderRequireVsPermissive(t *testing.T) {
	pki := newTestPKI(t)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := makeCSRWithBundle(t, deviceKey, nil) // no attestation bundle

	// require: fail closed.
	vReq := pki.verifier(t, ModeRequire, nil)
	if dec := vReq.VerifyEnrollment("default", csr); dec.Allow || !dec.Missing {
		t.Fatalf("require+missing should deny; got allow=%v missing=%v", dec.Allow, dec.Missing)
	}
	// permissive: allow but record missing.
	vPerm := pki.verifier(t, ModePermissive, nil)
	if dec := vPerm.VerifyEnrollment("default", csr); !dec.Allow || !dec.Missing {
		t.Fatalf("permissive+missing should allow; got allow=%v missing=%v", dec.Allow, dec.Missing)
	}
	// off: allow, no evaluation.
	vOff := pki.verifier(t, ModeOff, nil)
	if dec := vOff.VerifyEnrollment("default", csr); !dec.Allow {
		t.Fatalf("off should always allow")
	}
}

func TestVerifyEnrollment_KeyBindingMismatch(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeRequire, nil)

	// Attestation certifies a DIFFERENT key than the one in the CSR.
	attestedKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := pki.yubicoAttestationLeaf(t, attestedKey.Public(), 42)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := makeCSRWithBundle(t, csrKey, []*x509.Certificate{leaf})

	dec := v.VerifyEnrollment("default", csr)
	if dec.Allow {
		t.Fatal("mismatched attested key must be denied under require")
	}
	if dec.Result == nil || dec.Result.Verified {
		t.Fatalf("expected unverified result: %+v", dec.Result)
	}
}

func TestVerifyEnrollment_UntrustedRoot(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeRequire, nil)

	// A leaf issued by a DIFFERENT manufacturer PKI the verifier does not trust.
	rogue := newTestPKI(t)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := rogue.yubicoAttestationLeaf(t, deviceKey.Public(), 7)
	csr := makeCSRWithBundle(t, deviceKey, []*x509.Certificate{leaf, rogue.inter})

	dec := v.VerifyEnrollment("default", csr)
	if dec.Allow {
		t.Fatal("attestation chaining to an untrusted root must be denied")
	}
}

func TestVerifyEnrollment_GenericCertChain(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeRequire, nil)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := pki.genericAttestationLeaf(t, deviceKey.Public())
	csr := makeCSRWithBundle(t, deviceKey, []*x509.Certificate{leaf})

	dec := v.VerifyEnrollment("default", csr)
	if !dec.Allow || dec.Result == nil || !dec.Result.Verified {
		t.Fatalf("generic trusted attestation should verify: %+v (%s)", dec.Result, dec.Detail)
	}
	if dec.Result.Format != FormatCertChain {
		t.Errorf("format = %q, want %q", dec.Result.Format, FormatCertChain)
	}
}

// ---- ACME device-attest-01: Apple ------------------------------------------

func TestVerifyACME_Apple(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeRequire, nil)
	const keyAuth = "token.thumbprint"

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj := pki.buildAppleAttObj(t, deviceKey.Public(), keyAuth)

	dec := v.VerifyACMEDeviceAttest("default", attObj, keyAuth)
	if !dec.Allow || dec.Result == nil || !dec.Result.Verified {
		t.Fatalf("apple attestation should verify: %+v (%s)", dec.Result, dec.Detail)
	}
	if dec.Result.Format != FormatApple {
		t.Errorf("format = %q, want apple", dec.Result.Format)
	}

	// Wrong key authorization (nonce commits to a different challenge) must fail.
	if dec := v.VerifyACMEDeviceAttest("default", attObj, "wrong.keyauth"); dec.Allow {
		t.Fatal("apple attestation with wrong keyAuth must be denied")
	}

	// Missing attestation under require fails closed.
	if dec := v.VerifyACMEDeviceAttest("default", nil, keyAuth); dec.Allow || !dec.Missing {
		t.Fatalf("missing apple attestation should deny under require: allow=%v", dec.Allow)
	}
}

func TestVerifyACME_AppleTamperedNonce(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeRequire, nil)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj := pki.buildAppleAttObj(t, deviceKey.Public(), "keyauth")

	// Flip a byte in the CBOR blob's authData/nonce region.
	tampered := append([]byte(nil), attObj...)
	tampered[len(tampered)-5] ^= 0xff
	if dec := v.VerifyACMEDeviceAttest("default", tampered, "keyauth"); dec.Allow {
		t.Fatal("tampered apple attestation must be denied")
	}
}

// ---- ACME device-attest-01: TPM --------------------------------------------

func TestVerifyACME_TPM(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeRequire, nil)
	const keyAuth = "tpm.token.thumb"

	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	attObj := pki.buildTPMAttObj(t, &deviceKey.PublicKey, keyAuth)

	dec := v.VerifyACMEDeviceAttest("default", attObj, keyAuth)
	if !dec.Allow || dec.Result == nil || !dec.Result.Verified {
		t.Fatalf("tpm attestation should verify: %+v (%s)", dec.Result, dec.Detail)
	}
	if dec.Result.Format != FormatTPM {
		t.Errorf("format = %q, want tpm", dec.Result.Format)
	}

	// Wrong keyAuth must break the extraData commitment.
	if dec := v.VerifyACMEDeviceAttest("default", attObj, "different"); dec.Allow {
		t.Fatal("tpm attestation with wrong keyAuth must be denied")
	}
}

func TestVerifyACME_TPMTamperedSignature(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeRequire, nil)
	deviceKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	attObj := pki.buildTPMAttObj(t, &deviceKey.PublicKey, "kauth")

	tampered := append([]byte(nil), attObj...)
	tampered[len(tampered)/2] ^= 0xff
	if dec := v.VerifyACMEDeviceAttest("default", tampered, "kauth"); dec.Allow {
		t.Fatal("tampered tpm attestation must be denied")
	}
}

func TestVerifyACME_OffAllowsWithoutEvidence(t *testing.T) {
	pki := newTestPKI(t)
	v := pki.verifier(t, ModeOff, nil)
	if dec := v.VerifyACMEDeviceAttest("default", nil, "x"); !dec.Allow {
		t.Fatal("off mode should allow without evidence")
	}
}
