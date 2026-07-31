//go:build sqlite

package anchor

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/timesource"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// anchorFakeTimeProvider injects a fixed host-minus-source offset as a
// timesource.Provider, so a real timesource.Checker can be driven to pass or
// fail closed without any network access.
type anchorFakeTimeProvider struct{ offset time.Duration }

func (f anchorFakeTimeProvider) Now(context.Context) (timesource.Reading, error) {
	return timesource.Reading{Time: time.Now().Add(-f.offset), Offset: f.offset}, nil
}

func (f anchorFakeTimeProvider) Name() string { return "fake-trusted-time" }

func anchorDriftChecker(offset time.Duration) *timesource.Checker {
	return timesource.NewChecker(
		[]timesource.Provider{anchorFakeTimeProvider{offset: offset}},
		timesource.CheckerOptions{Threshold: 10 * time.Second, SourceType: "fake"},
	)
}

// TestSoftHSMAnchorTrustedTimeFailClosed provisions the anchor TSA key on
// SoftHSM and puts a real timesource.Checker in front of the anchor service
// (Task 163). Within the drift threshold the head is anchored with an HSM-signed
// token as usual; beyond the threshold AnchorOnce fails closed — it returns an
// error, requests no token, and persists no anchor — so a compromised host clock
// cannot mint a falsely-dated anchor. Skipped unless the SoftHSM environment is
// exported (eval "$(scripts/setup-softhsm.sh --export-env)").
func TestSoftHSMAnchorTrustedTimeFailClosed(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	provider, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
		ModulePath: module,
		Pin:        pin,
		TokenLabel: token,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	ctx := context.Background()
	suffix := time.Now().Format("150405") + "-" + anchorRandHex(t)
	caLabel := "test-anchorts-ca-" + suffix
	tsaLabel := "test-anchorts-tsa-" + suffix

	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: caLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: caLabel})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM Anchor-TS Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: tsaLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, _ := asn1.Marshal([]asn1.ObjectIdentifier{tsa.OIDExtKeyUsageTimeStamping})
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM Anchor-TS"},
		PublicKey: tsaInfo.PublicKey,
		Serial:    big.NewInt(2),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(12 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuVal},
		},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	tsaCert, _ := x509.ParseCertificate(tsaDER)

	authority, err := tsa.New(nil, provider, tsa.Config{
		KeyLabel:    tsaLabel,
		Certificate: tsaCert,
		Chain:       []*x509.Certificate{tsaCert, caCert},
		Accuracy:    tsa.Accuracy{Seconds: 1},
	})
	if err != nil {
		t.Fatalf("tsa.New: %v", err)
	}

	db, _ := anchorTestDB(t)
	appendEvents(t, db, 4)

	// 1. Trusted clock within the threshold: anchoring proceeds with an HSM token.
	svc := NewService(db, NewAuthorityTimestamper(authority))
	svc.SetTrustedClock(anchorDriftChecker(2 * time.Second))
	res, err := svc.AnchorOnce(ctx, false)
	if err != nil {
		t.Fatalf("AnchorOnce within threshold: %v", err)
	}
	if res.Skipped || res.Anchor == nil {
		t.Fatalf("expected an anchor within the threshold, got %+v", res)
	}

	anchorsAfterOK, err := db.ListAuditAnchorsAsc()
	if err != nil {
		t.Fatal(err)
	}

	// 2. Trusted clock drifted beyond the threshold: AnchorOnce fails closed and
	//    persists nothing new.
	svc.SetTrustedClock(anchorDriftChecker(90 * time.Second))
	_, err = svc.AnchorOnce(ctx, true) // force, to isolate the trusted-time gate
	if err == nil {
		t.Fatal("AnchorOnce must fail closed when the host clock drift exceeds the threshold")
	}
	if !strings.Contains(err.Error(), "trusted-time") {
		t.Fatalf("error = %v, want a trusted-time failure", err)
	}
	var de *timesource.DriftError
	if !errors.As(err, &de) {
		t.Fatalf("expected a wrapped *timesource.DriftError, got %v", err)
	}

	anchorsAfterDrift, err := db.ListAuditAnchorsAsc()
	if err != nil {
		t.Fatal(err)
	}
	if len(anchorsAfterDrift) != len(anchorsAfterOK) {
		t.Fatalf("a fail-closed anchor must persist nothing: had %d anchors, now %d",
			len(anchorsAfterOK), len(anchorsAfterDrift))
	}
}
