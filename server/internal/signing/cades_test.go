package signing

import (
	"context"
	"crypto"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// stubRevocation is a RevocationSource backed by the harness CA: it produces an
// OCSP response for the signer leaf (good, or revoked when its serial is listed)
// and a CRL from the CA listing any revoked serials.
type stubRevocation struct {
	caSigner keyprovider.Signer
	caCert   *x509.Certificate
	revoked  []*big.Int // serials to mark revoked in both the OCSP and the CRL
	empty    bool       // return nothing (to exercise the no-material failure)
}

func (s *stubRevocation) CollectRevocation(_ context.Context, chain []*x509.Certificate) ([][]byte, [][]byte, error) {
	if s.empty {
		return nil, nil, nil
	}
	leaf := chain[0]
	status := pki.OCSPGood
	var revokedAt time.Time
	for _, r := range s.revoked {
		if r.Cmp(leaf.SerialNumber) == 0 {
			status = pki.OCSPRevoked
			revokedAt = time.Now().Add(-time.Hour)
		}
	}
	ocspDER, err := pki.CreateOCSPResponse(s.caSigner, s.caCert, pki.OCSPResponseSpec{
		Serial:     leaf.SerialNumber,
		Status:     status,
		RevokedAt:  revokedAt,
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		IssuerHash: crypto.SHA256,
	})
	if err != nil {
		return nil, nil, err
	}
	entries := make([]pki.RevokedEntry, 0, len(s.revoked))
	for _, r := range s.revoked {
		entries = append(entries, pki.RevokedEntry{Serial: r, RevokedAt: time.Now().Add(-time.Hour)})
	}
	crlDER, err := pki.CreateCRL(s.caSigner, s.caCert, pki.CRLRequest{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		Revoked:    entries,
	})
	if err != nil {
		return nil, nil, err
	}
	return [][]byte{ocspDER}, [][]byte{crlDER}, nil
}

func TestParseLevel(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Level
		ok   bool
	}{
		{"", "", true},
		{"b", LevelB, true},
		{"T", LevelT, true},
		{"lt", LevelLT, true},
		{"CAdES-LT", LevelLT, true},
		{"baseline-b", LevelB, true},
		{"lta", "", false},
		{"x", "", false},
	} {
		got, err := ParseLevel(tc.in)
		if tc.ok != (err == nil) {
			t.Errorf("ParseLevel(%q) err=%v, wantOK=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && got != tc.want {
			t.Errorf("ParseLevel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if LevelB.rank() >= LevelT.rank() || LevelT.rank() >= LevelLT.rank() {
		t.Fatal("level rank ordering is wrong")
	}
}

// ltHarness builds a signer plus a revocation source over the harness CA.
func ltHarness(t *testing.T, revoked ...*big.Int) (*harness, *Service, *x509.Certificate) {
	t.Helper()
	h := newHarness(t)
	cert := h.issueCodeSigningCert(t, "cades-signer", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
	svc := h.service(t, SignerConfig{
		Name:        "release",
		KeyLabel:    "cades-signer",
		Certificate: cert,
		Chain:       []*x509.Certificate{cert, h.caCert},
	})
	svc.SetRevocationSource(&stubRevocation{caSigner: h.caSigner, caCert: h.caCert, revoked: revoked})
	return h, svc, cert
}

func TestSignLevels(t *testing.T) {
	artifact := []byte("multi-level release artifact")

	for _, level := range []Level{LevelB, LevelT, LevelLT} {
		t.Run(string(level), func(t *testing.T) {
			h, svc, _ := ltHarness(t)
			res, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact, Level: level})
			if err != nil {
				t.Fatalf("Sign(%s): %v", level, err)
			}
			if res.Level != level {
				t.Fatalf("result level = %q, want %q", res.Level, level)
			}
			wantTimestamp := level != LevelB
			if res.Timestamped != wantTimestamp {
				t.Fatalf("level %s: timestamped=%v, want %v", level, res.Timestamped, wantTimestamp)
			}
			wantLTV := level == LevelLT
			if (res.EmbeddedCRLs > 0) != wantLTV || (res.EmbeddedOCSPs > 0) != wantLTV {
				t.Fatalf("level %s: crls=%d ocsps=%d, wantLTV=%v", level, res.EmbeddedCRLs, res.EmbeddedOCSPs, wantLTV)
			}

			// The signature must parse; the crls field is populated only for LT.
			p, err := cms.ParseSignedData(res.Signature)
			if err != nil {
				t.Fatalf("ParseSignedData: %v", err)
			}
			embeddedCRLs := len(p.EmbeddedCRLs())
			if (embeddedCRLs > 0) != wantLTV {
				t.Fatalf("level %s: SignedData crls field has %d CRLs, wantLTV=%v", level, embeddedCRLs, wantLTV)
			}
			_, hasRevVals := p.UnauthenticatedAttribute(cms.OIDRevocationValues)
			if hasRevVals != wantLTV {
				t.Fatalf("level %s: revocation-values attr present=%v, want %v", level, hasRevVals, wantLTV)
			}

			// Verify reports the achieved level.
			v, err := Verify(VerifyRequest{Signature: res.Signature, Content: artifact, Roots: []*x509.Certificate{h.caCert}})
			if err != nil {
				t.Fatalf("Verify(%s): %v", level, err)
			}
			if v.Level != level {
				t.Fatalf("verified level = %q, want %q", v.Level, level)
			}
			if level == LevelLT {
				if v.RevocationCRLs != 1 || v.RevocationOCSPs != 1 {
					t.Fatalf("LT verify counts: crls=%d ocsps=%d, want 1/1", v.RevocationCRLs, v.RevocationOCSPs)
				}
			}
		})
	}
}

func TestVerifyRequireLevel(t *testing.T) {
	artifact := []byte("require-level artifact")
	h, svc, _ := ltHarness(t)

	tRes, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact, Level: LevelT})
	if err != nil {
		t.Fatalf("Sign T: %v", err)
	}
	// A T signature satisfies a B or T floor but not LT.
	for _, floor := range []Level{LevelB, LevelT} {
		if _, err := Verify(VerifyRequest{Signature: tRes.Signature, Content: artifact, Roots: []*x509.Certificate{h.caCert}, RequireLevel: floor}); err != nil {
			t.Fatalf("RequireLevel %s on a T signature: %v", floor, err)
		}
	}
	if _, err := Verify(VerifyRequest{Signature: tRes.Signature, Content: artifact, Roots: []*x509.Certificate{h.caCert}, RequireLevel: LevelLT}); err == nil {
		t.Fatal("RequireLevel LT accepted a T signature")
	}

	ltRes, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact, Level: LevelLT})
	if err != nil {
		t.Fatalf("Sign LT: %v", err)
	}
	if _, err := Verify(VerifyRequest{Signature: ltRes.Signature, Content: artifact, Roots: []*x509.Certificate{h.caCert}, RequireLevel: LevelLT}); err != nil {
		t.Fatalf("RequireLevel LT on an LT signature: %v", err)
	}
}

func TestVerifyFailsClosedOnRevokedLTV(t *testing.T) {
	artifact := []byte("artifact signed by a to-be-revoked key")
	h := newHarness(t)
	cert := h.issueCodeSigningCert(t, "revoked-signer", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
	svc := h.service(t, SignerConfig{
		Name:        "release",
		KeyLabel:    "revoked-signer",
		Certificate: cert,
		Chain:       []*x509.Certificate{cert, h.caCert},
	})
	// The revocation source reports the signer serial as revoked, so the embedded
	// material must make verification fail closed.
	svc.SetRevocationSource(&stubRevocation{caSigner: h.caSigner, caCert: h.caCert, revoked: []*big.Int{cert.SerialNumber}})

	res, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact, Level: LevelLT})
	if err != nil {
		t.Fatalf("Sign LT: %v", err)
	}
	if _, err := Verify(VerifyRequest{Signature: res.Signature, Content: artifact, Roots: []*x509.Certificate{h.caCert}}); err == nil {
		t.Fatal("Verify accepted a signature whose embedded revocation material revokes the signer")
	}
}

func TestLTRequiresRevocationSource(t *testing.T) {
	h := newHarness(t)
	cert := h.issueCodeSigningCert(t, "no-rev", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
	svc := h.service(t, SignerConfig{
		Name:        "release",
		KeyLabel:    "no-rev",
		Certificate: cert,
		Chain:       []*x509.Certificate{cert, h.caCert},
	})
	// No revocation source wired: LT must be refused as unavailable.
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x"), Level: LevelLT}); err == nil {
		t.Fatal("Sign LT succeeded without a revocation source")
	}

	// An empty revocation result is likewise a failure — an LT claim with no
	// material is hollow.
	svc.SetRevocationSource(&stubRevocation{caSigner: h.caSigner, caCert: h.caCert, empty: true})
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x"), Level: LevelLT}); err == nil {
		t.Fatal("Sign LT succeeded with an empty revocation result")
	}
}

func TestSignerDefaultLevel(t *testing.T) {
	artifact := []byte("default-level artifact")
	h := newHarness(t)
	cert := h.issueCodeSigningCert(t, "default-lt", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
	svc := h.service(t, SignerConfig{
		Name:         "release",
		KeyLabel:     "default-lt",
		Certificate:  cert,
		Chain:        []*x509.Certificate{cert, h.caCert},
		DefaultLevel: LevelLT,
	})
	svc.SetRevocationSource(&stubRevocation{caSigner: h.caSigner, caCert: h.caCert})

	// No level in the request → the signer's default (LT) applies.
	res, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.Level != LevelLT {
		t.Fatalf("default level not applied: got %q", res.Level)
	}
	// An explicit request level overrides the default downwards.
	res, err = svc.Sign(context.Background(), SignRequest{Signer: "release", Content: artifact, Level: LevelB})
	if err != nil {
		t.Fatalf("Sign B override: %v", err)
	}
	if res.Level != LevelB || res.Timestamped {
		t.Fatalf("request level did not override default: level=%q timestamped=%v", res.Level, res.Timestamped)
	}
}
