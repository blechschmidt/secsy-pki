package hsmaudit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// The freshness tests build genuine RFC 3161 tokens rather than stubbing the
// verification out. A fake that returned "valid" would test nothing: the whole
// claim rests on a signature by a third party, so a test that never produces one
// cannot distinguish a working verifier from one that always says yes.

// oidSHA256 and oidTSTInfo are the two OIDs a TSTInfo needs.
var (
	testOIDSHA256  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	testOIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	testOIDPolicy  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
)

// tstInfo is the RFC 3161 TSTInfo layout, marshaling side.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint testImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
}

type testImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// testTSA is an in-test RFC 3161 authority: a self-signed timestamping
// certificate plus enough of the token format to be parsed and verified by the
// production code path.
type testTSA struct {
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	root   *x509.Certificate
	source string
	// now supplies genTime, so a test can mint a deliberately old attestation.
	now func() time.Time
	// serial increments per token.
	serial int64
}

func newTestTSA(t *testing.T, source string) *testTSA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating TSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test TSA"},
		// Wide validity: the chain is checked at the token's genTime, so a
		// deliberately old attestation must still fall inside it — otherwise the
		// staleness test would be satisfied by an expiry error instead.
		NotBefore:   time.Now().Add(-3 * 365 * 24 * time.Hour),
		NotAfter:    time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		// Self-signed and self-issued, so it can serve as its own trust anchor in
		// the -tsa-roots position without a separate root.
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating TSA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing TSA certificate: %v", err)
	}
	return &testTSA{key: key, cert: cert, root: cert, source: source, now: time.Now}
}

func (ts *testTSA) Source() string { return ts.source }

func (ts *testTSA) Timestamp(ctx context.Context, digest []byte) ([]byte, time.Time, error) {
	ts.serial++
	// Second precision: GeneralizedTime carries no sub-second field here, and the
	// verifier compares the recorded genTime against the token's at that
	// resolution.
	genTime := ts.now().UTC().Truncate(time.Second)
	info := tstInfo{
		Version: 1,
		Policy:  testOIDPolicy,
		MessageImprint: testImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: testOIDSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: digest,
		},
		SerialNumber: big.NewInt(ts.serial),
		GenTime:      genTime,
	}
	content, err := asn1.Marshal(info)
	if err != nil {
		return nil, time.Time{}, err
	}
	token, err := cms.BuildSignedData(cms.SignedDataOpts{
		Content:      content,
		ContentType:  testOIDTSTInfo,
		SignerCert:   ts.cert,
		Signer:       ts.key,
		Digest:       crypto.SHA256,
		Certificates: []*x509.Certificate{ts.cert},
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return token, genTime, nil
}

// TestTimestampAttestsCurrentHead is the happy path: the service obtains a
// token over the head it actually holds, and the bundle it exports verifies as
// current.
func TestTimestampAttestsCurrentHead(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	p, err := svc.Timestamp(context.Background(), ts)
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	if p.Head.Signatures != 2 {
		t.Fatalf("attested %d signatures, want 2", p.Head.Signatures)
	}
	// Entry 1 is the reset sentinel, 2 the key's creation, 3 and 4 the two
	// signatures.
	if p.Head.DeviceNumber != 4 {
		t.Fatalf("attested device entry %d, want 4", p.Head.DeviceNumber)
	}
	if p.Head.LedgerSeq != 2 {
		t.Fatalf("attested ledger seq %d, want 2", p.Head.LedgerSeq)
	}

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		ExpectedSerial: "31650425",
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}, RequireIndependentTSA: true},
	})
	if !res.OK {
		t.Fatalf("attested bundle rejected: %v", res.Err())
	}
	if res.Freshness.Verified != 1 {
		t.Fatalf("verified %d proofs, want 1", res.Freshness.Verified)
	}
	if res.Freshness.Stale {
		t.Fatal("a just-obtained attestation was reported stale")
	}
	if !strings.Contains(res.Summary, "current as of") {
		t.Fatalf("summary does not state the attested instant: %q", res.Summary)
	}
}

// The headline property of this feature: a bundle whose newest attestation is
// old must be rejected, because it cannot bound what the HSM signed since.
func TestVerifyRejectsStaleBundle(t *testing.T) {
	b, ts := attestedBundle(t, func(tsa *testTSA) {
		tsa.now = func() time.Time { return time.Now().Add(-30 * 24 * time.Hour) }
	})
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if res.OK {
		t.Fatal("a month-old attestation passed the freshness check")
	}
	if !res.Freshness.Stale {
		t.Fatal("result does not report the bundle as stale")
	}
	if !strings.Contains(res.Err().Error(), "outdated snapshot") {
		t.Fatalf("finding does not explain the staleness: %v", res.Err())
	}
}

// A bundle with no attestations at all is the default state of a deployment
// that never configured a TSA. It must fail rather than quietly report OK, since
// "verified" would then mean "verified as of some unknown date".
func TestVerifyRejectsBundleWithoutProofs(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	addLedger(t, store, attestedKeyID, "aa")
	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{ExpectedAnchor: testAnchor})
	if res.OK {
		t.Fatal("a bundle with no freshness proof verified")
	}
	if !strings.Contains(res.Err().Error(), "no freshness proofs") {
		t.Fatalf("finding does not name the missing proofs: %v", res.Err())
	}
}

// A genuine token over an invented head must not pass. This is the attack the
// head-binding layer exists for: the CA can always get a real timestamp, so the
// question is whether it can get one over a state it never had.
func TestVerifyRejectsProofOverForeignHead(t *testing.T) {
	b, ts := attestedBundle(t, nil)
	// Re-point the proof at a signature count the log does not support, and
	// re-derive its digest so the token/record consistency check is not what
	// catches it.
	b.Freshness[0].Head.Signatures = 99
	b.Freshness[0].HeadDigest = b.Freshness[0].Head.Digest()

	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if res.OK {
		t.Fatal("a proof over a head the bundle does not contain verified")
	}
	// The token now covers a different head, so it no longer matches — either
	// finding is the correct rejection.
	if e := res.Err().Error(); !strings.Contains(e, "does not cover this proof's head") &&
		!strings.Contains(e, "does not match the exported one") {
		t.Fatalf("finding does not explain the head mismatch: %v", res.Err())
	}
}

// Editing a device log entry that an attestation already covered must be
// detected: the token commits to the entry's chain digest.
func TestVerifyDetectsLogRewriteBehindAttestation(t *testing.T) {
	b, ts := attestedBundle(t, nil)
	for i := range b.LogEntries {
		if b.LogEntries[i].Number == 2 {
			b.LogEntries[i].Hash = strings.Repeat("cc", DigestLen)
		}
	}
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if res.OK {
		t.Fatal("a log rewritten behind an attestation verified")
	}
}

// Trust anchors are what separate "some authority signed this" from "an
// authority you trust signed this". A token from an unrelated TSA must not
// satisfy roots the auditor pinned.
func TestVerifyRejectsUntrustedTSA(t *testing.T) {
	b, _ := attestedBundle(t, nil)
	other := newTestTSA(t, "https://other.example/tsr")
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{other.root}},
	})
	if res.OK {
		t.Fatal("a token from an untrusted authority verified against pinned roots")
	}
	if !strings.Contains(res.Err().Error(), "TSA certificate chain") {
		t.Fatalf("finding does not name the chain failure: %v", res.Err())
	}
}

// The in-process TSA signs with the HSM under audit, so it cannot establish
// freshness against an operator holding that HSM. The verifier must say so, and
// reject it outright when asked to.
func TestInternalTSAIsFlaggedAndRejectable(t *testing.T) {
	b, ts := attestedBundle(t, func(tsa *testTSA) { tsa.source = "" })

	lenient := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if !lenient.OK {
		t.Fatalf("an internally attested bundle was rejected by default: %v", lenient.Err())
	}
	if lenient.Freshness.IndependentTSA {
		t.Fatal("an in-process attestation was reported as independent")
	}
	if len(lenient.Freshness.Notes) == 0 {
		t.Fatal("no note warns that the attestation is not independent")
	}

	strict := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		Freshness: FreshnessOptions{
			Roots:                 []*x509.Certificate{ts.root},
			RequireIndependentTSA: true,
		},
	})
	if strict.OK {
		t.Fatal("-require-external-tsa accepted an in-process attestation")
	}
}

// Replaying an older head at a later time would let an abandoned log look
// maintained, so the sequence must be rejected when it goes backwards.
func TestVerifyRejectsReAttestedEarlierHead(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	if _, err := svc.Timestamp(context.Background(), ts); err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	if _, err := svc.Timestamp(context.Background(), ts); err != nil {
		t.Fatalf("second attestation: %v", err)
	}
	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Rewind the second proof's head to a state before the first's.
	b.Freshness[1].Head.Signatures = 0
	b.Freshness[1].Head.DeviceNumber = 1
	b.Freshness[1].Head.DeviceDigest = testAnchor
	b.Freshness[1].Head.LedgerSeq = 0
	b.Freshness[1].Head.LedgerHash = ""
	b.Freshness[1].HeadDigest = b.Freshness[1].Head.Digest()

	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if res.OK {
		t.Fatal("a re-attested earlier head verified")
	}
}

// Two exports taken around an interval must bracket it in trusted-clock terms,
// which is what turns "no abuse so far" into "no abuse during this window".
func TestContinuationReportsAttestedInterval(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	addLedger(t, store, attestedKeyID, "aa")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	ts.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	if _, err := svc.Timestamp(context.Background(), ts); err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	first, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("first export: %v", err)
	}

	// One more signature, then a later attestation.
	dev.entries = keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
		t.Fatalf("second collect: %v", err)
	}
	addLedger(t, store, attestedKeyID, "bb")
	ts.now = time.Now
	if _, err := svc.Timestamp(context.Background(), ts); err != nil {
		t.Fatalf("second attestation: %v", err)
	}
	second, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("second export: %v", err)
	}

	cont := VerifyContinuation(first, second)
	if !cont.OK {
		t.Fatalf("genuine continuation rejected: %v", cont.Err())
	}
	if cont.NewSignatures != 1 {
		t.Fatalf("reported %d new signatures, want 1", cont.NewSignatures)
	}
	if !strings.Contains(cont.Interval, "attested interval") {
		t.Fatalf("interval is not stated in trusted-clock terms: %q", cont.Interval)
	}
}

// Deleting an attestation the CA already published would let it disown an
// interval it had committed to.
func TestContinuationDetectsDroppedAttestation(t *testing.T) {
	first, ts := attestedBundle(t, nil)
	second := *first
	second.Freshness = nil
	cont := VerifyContinuation(first, &second)
	if cont.OK {
		t.Fatal("an export that dropped a published attestation was accepted")
	}
	if !strings.Contains(cont.Err().Error(), "attestations were deleted") {
		t.Fatalf("finding does not name the deletion: %v", cont.Err())
	}
	_ = ts
}

// The head digest is what the TSA actually signed, so a record whose stored
// digest disagrees with its own fields is an edited row.
func TestVerifyDetectsEditedProofRecord(t *testing.T) {
	b, ts := attestedBundle(t, nil)
	b.Freshness[0].HeadDigest = strings.Repeat("ab", sha256.Size)
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		Freshness:      FreshnessOptions{Roots: []*x509.Certificate{ts.root}},
	})
	if res.OK {
		t.Fatal("a proof whose stored digest does not match its head verified")
	}
	if !strings.Contains(res.Err().Error(), "the record was altered") {
		t.Fatalf("finding does not name the alteration: %v", res.Err())
	}
}

// attestedBundle builds a provisioned, collected, attested bundle. tweak, when
// non-nil, adjusts the test TSA before the attestation is taken.
func attestedBundle(t *testing.T, tweak func(*testTSA)) (*Bundle, *testTSA) {
	t.Helper()
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	if _, err := NewCollector(dev, store, 0, discardLogger()).Collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	ts := newTestTSA(t, "https://tsa.example/tsr")
	if tweak != nil {
		tweak(ts)
	}
	if _, err := svc.Timestamp(context.Background(), ts); err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return b, ts
}
