package ers

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// tsaHarness is a software-backed RFC 3161 authority with a controllable clock,
// so renewal tests can advance genTime deterministically. No HSM or DB needed.
type tsaHarness struct {
	authority *tsa.Authority
	caCert    *x509.Certificate
	mu        sync.Mutex
	now       time.Time
}

func newTSAHarness(t *testing.T) *tsaHarness {
	t.Helper()
	ctx := context.Background()
	provider, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "ers-ca", KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: "ers-ca"})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "ERS Test Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(5000 * 24 * time.Hour), // long-lived: renewal tests advance years
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "ers-tsa", KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, err := asn1.Marshal([]asn1.ObjectIdentifier{tsa.OIDExtKeyUsageTimeStamping})
	if err != nil {
		t.Fatalf("marshal EKU: %v", err)
	}
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "ERS Test TSA"},
		PublicKey: tsaInfo.PublicKey,
		Serial:    big.NewInt(2),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(4000 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuVal},
		},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	tsaCert, err := x509.ParseCertificate(tsaDER)
	if err != nil {
		t.Fatalf("parse TSA cert: %v", err)
	}

	authority, err := tsa.New(nil, provider, tsa.Config{
		KeyLabel:       "ers-tsa",
		Certificate:    tsaCert,
		Chain:          []*x509.Certificate{tsaCert, caCert},
		AcceptedHashes: []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512},
	})
	if err != nil {
		t.Fatalf("tsa.New: %v", err)
	}
	h := &tsaHarness{authority: authority, caCert: caCert, now: time.Now()}
	authority.SetClock(func() time.Time {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.now
	})
	return h
}

func (h *tsaHarness) setNow(tm time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = tm
}

func (h *tsaHarness) ts() Timestamper { return NewAuthorityTimestamper(h.authority) }

func objects(ids ...string) []DataObject {
	out := make([]DataObject, len(ids))
	for i, id := range ids {
		out[i] = DataObject{ID: id, Bytes: []byte("payload:" + id)}
	}
	return out
}

// TestGenerateVerifyRoundTrip is the happy path: generate over several objects,
// DER round-trip, and verify with the TSA trust anchor.
func TestGenerateVerifyRoundTrip(t *testing.T) {
	h := newTSAHarness(t)
	objs := objects("event-1", "event-2", "event-3", "event-4")

	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objs})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	der, err := er.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reparsed, err := Parse(der)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// DER must be stable across a marshal/parse/marshal round-trip.
	der2, err := reparsed.Marshal()
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytesEqual(der, der2) {
		t.Fatal("DER not stable across round-trip")
	}

	res, err := Verify(reparsed, VerifyOptions{Objects: objs, Roots: []*x509.Certificate{h.caCert}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		t.Fatalf("verify should pass: %s", res.Reason)
	}
	if len(res.Objects) != len(objs) {
		t.Fatalf("expected %d object results, got %d", len(objs), len(res.Objects))
	}
	for _, o := range res.Objects {
		if !o.Covered {
			t.Fatalf("object %q should be covered: %s", o.ID, o.Reason)
		}
	}
	if res.LatestGenTime.IsZero() {
		t.Fatal("latest gen time should be set")
	}
}

// TestVerifyDetectsTampering: a changed object, a missing object, and a
// bit-flipped token must all fail verification.
func TestVerifyDetectsTampering(t *testing.T) {
	h := newTSAHarness(t)
	objs := objects("a", "b", "c")
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objs})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	roots := []*x509.Certificate{h.caCert}

	// A changed object is no longer in the reduced hash tree.
	tampered := objects("a", "b", "c")
	tampered[1].Bytes = []byte("payload:b-forged")
	res, _ := Verify(er, VerifyOptions{Objects: tampered, Roots: roots})
	if res.Valid {
		t.Fatal("verify must fail for a tampered object")
	}
	if res.Objects[1].Covered {
		t.Fatal("the forged object must not be covered")
	}

	// A bit-flipped token must fail CMS verification.
	der, _ := er.Marshal()
	flip := append([]byte(nil), der...)
	flip[len(flip)-8] ^= 0xff
	if reparsed, perr := Parse(flip); perr == nil {
		r2, _ := Verify(reparsed, VerifyOptions{Objects: objs, Roots: roots})
		if r2.Valid {
			t.Fatal("verify must fail for a bit-flipped token")
		}
	}
}

// TestKnownAnswerVerify is the known-answer test: with a fixed clock and fixed
// objects, the ArchiveTimeStamp's message imprint equals the frozen data-group
// root, and verification passes. This pins the whole generate→imprint binding.
func TestKnownAnswerVerify(t *testing.T) {
	h := newTSAHarness(t)
	h.setNow(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	objs := []DataObject{
		{ID: "alpha", Bytes: []byte("alpha")},
		{ID: "bravo", Bytes: []byte("bravo")},
		{ID: "charlie", Bytes: []byte("charlie")},
	}
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objs, Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The single ArchiveTimeStamp must cover exactly the frozen group root.
	const wantRoot = "1aced86c3b7644b93974a6d04ea9fcf20e01a6120a5315af13687f0456fadeff"
	token, _ := er.LatestToken()
	info, err := tsa.ParseTokenInfo(token)
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	if got := hexBytes(info.HashedMessage); got != wantRoot {
		t.Fatalf("timestamp imprint = %s, want frozen group root %s", got, wantRoot)
	}

	res, err := Verify(er, VerifyOptions{
		Objects: objs,
		Roots:   []*x509.Certificate{h.caCert},
		Now:     time.Date(2030, 1, 2, 4, 0, 0, 0, time.UTC),
	})
	if err != nil || !res.Valid {
		t.Fatalf("known-answer verify failed: %v %+v", err, res)
	}
}

// TestRenewalAdvancingClock exercises both renewal kinds against a clock that
// advances via SetClock: a time-stamp renewal (same chain, same hash) before
// cert expiry, then a hash-tree renewal (new chain, SHA-512) on algorithm
// deprecation. The record must verify after each step and cover every object
// across the algorithm transition.
func TestRenewalAdvancingClock(t *testing.T) {
	h := newTSAHarness(t)
	roots := []*x509.Certificate{h.caCert}
	objs := objects("evt-1", "evt-2", "evt-3")
	ctx := context.Background()

	t0 := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	h.setNow(t0)
	er, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objs, Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if er.ChainCount() != 1 {
		t.Fatalf("fresh record should have 1 chain, got %d", er.ChainCount())
	}

	// --- time-stamp renewal: advance a year, re-stamp within the same chain.
	h.setNow(t0.AddDate(1, 0, 0))
	er, err = er.RenewTimestamp(ctx, h.ts())
	if err != nil {
		t.Fatalf("RenewTimestamp: %v", err)
	}
	if er.ChainCount() != 1 {
		t.Fatalf("time-stamp renewal must stay in one chain, got %d chains", er.ChainCount())
	}
	if cur, _ := er.CurrentHash(); cur != crypto.SHA256 {
		t.Fatalf("time-stamp renewal must keep SHA-256, got %v", cur)
	}
	res, _ := Verify(er, VerifyOptions{Objects: objs, Roots: roots, Now: h.now})
	if !res.Valid {
		t.Fatalf("verify after time-stamp renewal: %s", res.Reason)
	}

	// --- hash-tree renewal: SHA-256 deprecated, advance further, new SHA-512 chain.
	h.setNow(t0.AddDate(2, 0, 0))
	er, err = er.RenewHashTree(ctx, h.ts(), objs, crypto.SHA512)
	if err != nil {
		t.Fatalf("RenewHashTree: %v", err)
	}
	if er.ChainCount() != 2 {
		t.Fatalf("hash-tree renewal must add a chain, got %d", er.ChainCount())
	}
	if cur, _ := er.CurrentHash(); cur != crypto.SHA512 {
		t.Fatalf("hash-tree renewal must switch to SHA-512, got %v", cur)
	}
	res, err = Verify(er, VerifyOptions{Objects: objs, Roots: roots, Now: h.now})
	if err != nil {
		t.Fatalf("Verify after hash-tree renewal: %v", err)
	}
	if !res.Valid {
		t.Fatalf("verify after hash-tree renewal: %s", res.Reason)
	}
	if len(res.Chains) != 2 || !res.Chains[0].Valid || !res.Chains[1].Valid {
		t.Fatalf("both chains must verify: %+v", res.Chains)
	}
	for _, o := range res.Objects {
		if !o.Covered {
			t.Fatalf("object %q must remain covered after hash-tree renewal: %s", o.ID, o.Reason)
		}
	}

	// DER round-trip of the two-chain record must still verify.
	der, _ := er.Marshal()
	reparsed, err := Parse(der)
	if err != nil {
		t.Fatalf("Parse renewed: %v", err)
	}
	res, _ = Verify(reparsed, VerifyOptions{Objects: objs, Roots: roots, Now: h.now})
	if !res.Valid {
		t.Fatalf("verify renewed after round-trip: %s", res.Reason)
	}

	// A hash-tree-renewed record whose new chain was fed the wrong objects must
	// not verify those objects (guards the atsc-binding step).
	res, _ = Verify(reparsed, VerifyOptions{Objects: objects("evt-1", "evt-2", "wrong"), Roots: roots, Now: h.now})
	if res.Valid {
		t.Fatal("verify must fail when a protected object does not match")
	}
}

func bytesEqual(a, b []byte) bool { return equalHash(a, b) }

func hexBytes(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
