package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// harness is a software-backed signing stack: a self-signed CA, an ECDSA and an
// RSA code-signing identity, and an RSA TSA — no HSM required.
type harness struct {
	provider  keyprovider.Provider
	caSigner  keyprovider.Signer
	caCert    *x509.Certificate
	tsaCert   *x509.Certificate
	authority *tsa.Authority
	serial    int64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	provider, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "ca", KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	t.Cleanup(func() { caSigner.Close() })
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "Signing Test Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-4 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	h := &harness{provider: provider, caSigner: caSigner, caCert: caCert, serial: 10}

	// RSA TSA (the CMS TSA token path is RSA-only), valid well around "now" so
	// backdated genTime tests still chain.
	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "tsa", KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, err := asn1.Marshal([]asn1.ObjectIdentifier{tsa.OIDExtKeyUsageTimeStamping})
	if err != nil {
		t.Fatal(err)
	}
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "Signing Test TSA"},
		PublicKey: tsaInfo.PublicKey,
		Serial:    big.NewInt(2),
		NotBefore: time.Now().Add(-4 * time.Hour),
		NotAfter:  time.Now().Add(12 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuVal},
		},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate (TSA): %v", err)
	}
	h.tsaCert, err = x509.ParseCertificate(tsaDER)
	if err != nil {
		t.Fatal(err)
	}
	h.authority, err = tsa.New(nil, provider, tsa.Config{
		KeyLabel:    "tsa",
		Certificate: h.tsaCert,
		Chain:       []*x509.Certificate{h.tsaCert, caCert},
	})
	if err != nil {
		t.Fatalf("tsa.New: %v", err)
	}
	return h
}

// issueCodeSigningCert generates a provider key under label and issues a
// code-signing certificate (or a differently-shaped one for negative tests).
func (h *harness) issueCodeSigningCert(t *testing.T, label, keyType string, notBefore, notAfter time.Time, ekus []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	info, err := h.provider.GenerateKey(context.Background(), keyprovider.KeySpec{Label: label, KeyType: keyType})
	if err != nil {
		t.Fatalf("generate key %q: %v", label, err)
	}
	h.serial++
	der, err := pki.CreateLeafCertificate(h.caSigner, h.caCert, pki.LeafCertRequest{
		Subject:     pkix.Name{CommonName: label},
		PublicKey:   info.PublicKey,
		Serial:      big.NewInt(h.serial),
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: ekus,
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate (%s): %v", label, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func codeSigningEKU() []x509.ExtKeyUsage { return []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} }

func (h *harness) service(t *testing.T, signers ...SignerConfig) *Service {
	t.Helper()
	svc, err := NewService(h.provider, h.authority, signers)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	h := newHarness(t)
	artifact := []byte("v1.2.3 release tarball bytes")

	for _, tc := range []struct{ name, keyType string }{
		{"ecdsa", keyprovider.KeyTypeECDSAP256},
		{"rsa", keyprovider.KeyTypeRSA2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			label := "codesign-" + tc.name
			cert := h.issueCodeSigningCert(t, label, tc.keyType,
				time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
			svc := h.service(t, SignerConfig{
				Name:               "release",
				KeyLabel:           label,
				Certificate:        cert,
				Chain:              []*x509.Certificate{cert, h.caCert},
				TimestampByDefault: true,
			})

			res, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !res.Timestamped || res.TimestampSerial == nil {
				t.Fatal("signature not timestamped despite TimestampByDefault")
			}
			wantDigest := sha256.Sum256(artifact)
			if !bytes.Equal(res.ArtifactDigest, wantDigest[:]) {
				t.Error("ArtifactDigest mismatch")
			}

			// Content verification.
			v, err := Verify(VerifyRequest{
				Signature: res.Signature,
				Content:   artifact,
				Roots:     []*x509.Certificate{h.caCert},
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !v.Timestamped || !v.VerifiedAt.Equal(v.TimestampGenTime) {
				t.Error("verification did not adopt the timestamp genTime")
			}
			if v.SignerCertificate.Subject.CommonName != label {
				t.Errorf("signer CN = %q", v.SignerCertificate.Subject.CommonName)
			}
			if len(v.Chain) < 2 {
				t.Errorf("verified chain length %d, want >= 2", len(v.Chain))
			}
			if v.TSACertificate == nil || len(v.TimestampToken) == 0 {
				t.Error("timestamp details missing from result")
			}

			// Digest verification and RequireTimestamp on a stamped signature.
			if _, err := Verify(VerifyRequest{
				Signature:        res.Signature,
				Digest:           wantDigest[:],
				Roots:            []*x509.Certificate{h.caCert},
				RequireTimestamp: true,
			}); err != nil {
				t.Fatalf("Verify by digest: %v", err)
			}

			// Tampered artifact must fail.
			if _, err := Verify(VerifyRequest{
				Signature: res.Signature,
				Content:   append([]byte("x"), artifact...),
				Roots:     []*x509.Certificate{h.caCert},
			}); err == nil {
				t.Fatal("Verify accepted a tampered artifact")
			}

			// A different trust anchor must fail chain building.
			other := h.issueCodeSigningCert(t, label+"-other", tc.keyType,
				time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
			if _, err := Verify(VerifyRequest{
				Signature: res.Signature,
				Content:   artifact,
				Roots:     []*x509.Certificate{other},
			}); err == nil {
				t.Fatal("Verify accepted an untrusted chain")
			}
		})
	}
}

func TestSignByDigestAndTimestampOverride(t *testing.T) {
	h := newHarness(t)
	cert := h.issueCodeSigningCert(t, "codesign-digest", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
	svc := h.service(t, SignerConfig{
		Name:        "release",
		KeyLabel:    "codesign-digest",
		Certificate: cert,
		Chain:       []*x509.Certificate{cert, h.caCert},
		// TimestampByDefault false; opt in per request below.
	})

	artifact := []byte("a very large artifact, represented by its digest")
	digest := sha256.Sum256(artifact)

	// Digest input + explicit timestamp opt-in.
	yes := true
	res, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Digest: digest[:], Timestamp: &yes})
	if err != nil {
		t.Fatalf("Sign by digest: %v", err)
	}
	if !res.Timestamped {
		t.Fatal("explicit Timestamp=true did not countersign")
	}
	// The signature verifies against the full content even though signing never
	// saw it.
	if _, err := Verify(VerifyRequest{Signature: res.Signature, Content: artifact, Roots: []*x509.Certificate{h.caCert}}); err != nil {
		t.Fatalf("Verify content after digest signing: %v", err)
	}

	// Opt-out: no timestamp, and RequireTimestamp then rejects it.
	no := false
	res2, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact, Timestamp: &no})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res2.Timestamped {
		t.Fatal("explicit Timestamp=false still countersigned")
	}
	if _, err := Verify(VerifyRequest{
		Signature:        res2.Signature,
		Content:          artifact,
		Roots:            []*x509.Certificate{h.caCert},
		RequireTimestamp: true,
	}); err == nil {
		t.Fatal("RequireTimestamp accepted an unstamped signature")
	}

	// Wrong digest length is rejected at sign time.
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Digest: digest[:16]}); err == nil {
		t.Fatal("Sign accepted a truncated digest")
	}
	// Unknown signer.
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "nope", Content: artifact}); err == nil {
		t.Fatal("Sign accepted an unknown signer")
	}
	// Content and digest together are ambiguous.
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact, Digest: digest[:]}); err == nil {
		t.Fatal("Sign accepted both content and digest")
	}
}

func TestNewServiceRejectsMisconfiguration(t *testing.T) {
	h := newHarness(t)

	// Wrong EKU (clientAuth instead of codeSigning).
	wrong := h.issueCodeSigningCert(t, "wrong-eku", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if _, err := NewService(h.provider, h.authority, []SignerConfig{{
		Name: "bad", KeyLabel: "wrong-eku", Certificate: wrong,
	}}); err == nil || !strings.Contains(err.Error(), "codeSigning") {
		t.Fatalf("NewService accepted a non-code-signing certificate (err=%v)", err)
	}

	// Timestamp-by-default without a TSA.
	good := h.issueCodeSigningCert(t, "good", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
	if _, err := NewService(h.provider, nil, []SignerConfig{{
		Name: "release", KeyLabel: "good", Certificate: good, TimestampByDefault: true,
	}}); err == nil {
		t.Fatal("NewService accepted timestamp-by-default without a TSA")
	}

	// Duplicate names.
	if _, err := NewService(h.provider, h.authority, []SignerConfig{
		{Name: "release", KeyLabel: "good", Certificate: good},
		{Name: "release", KeyLabel: "good", Certificate: good},
	}); err == nil {
		t.Fatal("NewService accepted duplicate signer names")
	}
}

func TestSignRejectsKeyCertMismatch(t *testing.T) {
	h := newHarness(t)
	cert := h.issueCodeSigningCert(t, "match-a", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
	// Reference a different key under the service while presenting match-a's cert.
	if _, err := h.provider.GenerateKey(context.Background(), keyprovider.KeySpec{
		Label: "match-b", KeyType: keyprovider.KeyTypeECDSAP256,
	}); err != nil {
		t.Fatal(err)
	}
	svc := h.service(t, SignerConfig{Name: "release", KeyLabel: "match-b", Certificate: cert})
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x")}); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Sign did not detect key/cert mismatch (err=%v)", err)
	}
}

func TestSignRefusesExpiredCertificate(t *testing.T) {
	h := newHarness(t)
	expired := h.issueCodeSigningCert(t, "expired", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), codeSigningEKU())
	svc := h.service(t, SignerConfig{Name: "release", KeyLabel: "expired", Certificate: expired})
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x")}); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("Sign used an expired certificate (err=%v)", err)
	}
}

// TestTimestampExtendsVerifiability is the reason the countersignature exists:
// a signature made while the signer certificate was valid — witnessed by a TSA
// token from that time — still verifies after the certificate expires, while
// the same signature without the token does not.
func TestTimestampExtendsVerifiability(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Signer certificate valid only in the past: [-2h, -1h].
	cert := h.issueCodeSigningCert(t, "past-signer", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), codeSigningEKU())
	signer, err := h.provider.Signer(ctx, keyprovider.KeyRef{Label: "past-signer"})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()

	// The TSA witnessed the signature at -90m, inside the signer's window.
	genTime := time.Now().Add(-90 * time.Minute)
	h.authority.SetClock(func() time.Time { return genTime })

	artifact := []byte("artifact signed in the past")
	scv2, err := cms.SigningCertificateV2Attribute([]*x509.Certificate{cert, h.caCert})
	if err != nil {
		t.Fatal(err)
	}
	build := func(stamp bool) []byte {
		opts := cms.SignedDataOpts{
			Content:      artifact,
			Detached:     true,
			SignerCert:   cert,
			Signer:       signer,
			Certificates: []*x509.Certificate{cert, h.caCert},
			ExtraAttrs:   []cms.Attribute{scv2},
		}
		if stamp {
			opts.UnauthAttrsFunc = func(sig []byte) ([]cms.Attribute, error) {
				sum := sha256.Sum256(sig)
				reqDER, err := tsa.MakeRequest(crypto.SHA256, sum[:], &tsa.RequestOptions{CertReq: true})
				if err != nil {
					return nil, err
				}
				res, err := h.authority.Stamp(ctx, reqDER)
				if err != nil {
					return nil, err
				}
				token, err := tsa.ExtractToken(res.Response)
				if err != nil {
					return nil, err
				}
				return []cms.Attribute{{Type: OIDTimeStampToken, Value: asn1.RawValue{FullBytes: token}}}, nil
			}
		}
		der, err := cms.BuildSignedData(opts)
		if err != nil {
			t.Fatalf("BuildSignedData: %v", err)
		}
		return der
	}

	stamped := build(true)
	v, err := Verify(VerifyRequest{Signature: stamped, Content: artifact, Roots: []*x509.Certificate{h.caCert}})
	if err != nil {
		t.Fatalf("Verify(stamped, expired signer): %v", err)
	}
	if !v.Timestamped || !v.VerifiedAt.Equal(v.TimestampGenTime) {
		t.Error("verification did not evaluate the chain at the token genTime")
	}

	unstamped := build(false)
	if _, err := Verify(VerifyRequest{Signature: unstamped, Content: artifact, Roots: []*x509.Certificate{h.caCert}}); err == nil {
		t.Fatal("Verify accepted an unstamped signature from an expired signer")
	}
}
