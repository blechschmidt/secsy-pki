package ers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

// oidSHA1 is a digest OID this package deliberately does not implement, used to
// drive the "unsupported chain algorithm" branches.
var oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

// rebuild returns a new EvidenceRecord whose ArchiveTimeStampSequence is the
// result of applying fn to a deep copy of er's. It is the tamper vehicle for the
// tables below: every mutation an attacker with the stored DER could make.
func rebuild(er *EvidenceRecord, fn func(seq []archiveTimeStampChain)) *EvidenceRecord {
	seq := make([]archiveTimeStampChain, len(er.wire.ArchiveTimeStampSequence))
	for i, chain := range er.wire.ArchiveTimeStampSequence {
		nc := make(archiveTimeStampChain, len(chain))
		for j, ats := range chain {
			cp := ats
			cp.ReducedHashtree = clonePartials(ats.ReducedHashtree)
			cp.TimeStamp = asn1.RawValue{FullBytes: append([]byte(nil), ats.TimeStamp.FullBytes...)}
			nc[j] = cp
		}
		seq[i] = nc
	}
	fn(seq)
	algs := append([]pkix.AlgorithmIdentifier(nil), er.wire.DigestAlgorithms...)
	return &EvidenceRecord{wire: evidenceRecord{
		Version:                  er.wire.Version,
		DigestAlgorithms:         algs,
		ArchiveTimeStampSequence: seq,
	}}
}

// TestVerifyStructureOnlyWithoutObjects is the regression test for the
// index-out-of-range panic in checkReduction: VerifyOptions.Objects is documented
// as optional ("only the structural integrity ... is checked"), and POST
// /api/ers/verify reaches Verify with no objects for a standalone record, so the
// no-objects path must be a supported, non-panicking code path.
func TestVerifyStructureOnlyWithoutObjects(t *testing.T) {
	h := newTSAHarness(t)
	h.setNow(time.Date(2030, 5, 5, 12, 0, 0, 0, time.UTC))
	objs := objects("a", "b", "c", "d")
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objs})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	now := time.Date(2030, 5, 5, 13, 0, 0, 0, time.UTC)

	res, err := Verify(er, VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("Verify without objects: %v", err)
	}
	if !res.Valid {
		t.Fatalf("a sound record must pass the structure-only check: %s", res.Reason)
	}
	if len(res.Objects) != 0 {
		t.Fatalf("no objects were supplied, so none may be reported: %+v", res.Objects)
	}
	if len(res.Chains) != 1 || !res.Chains[0].Valid {
		t.Fatalf("chain result = %+v", res.Chains)
	}
	if res.LatestGenTime.IsZero() {
		t.Fatal("structure-only verification must still report the genTime")
	}

	// Same after a DER round-trip, and after both renewal kinds — the sequence the
	// endpoint actually sees.
	der, _ := er.Marshal()
	reparsed, err := Parse(der)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res, err = Verify(reparsed, VerifyOptions{Now: now}); err != nil || !res.Valid {
		t.Fatalf("round-tripped record, no objects: err=%v reason=%s", err, res.Reason)
	}

	h.setNow(now)
	renewed, err := er.RenewTimestamp(context.Background(), h.ts())
	if err != nil {
		t.Fatalf("RenewTimestamp: %v", err)
	}
	renewed, err = renewed.RenewHashTree(context.Background(), h.ts(), objs, crypto.SHA512)
	if err != nil {
		t.Fatalf("RenewHashTree: %v", err)
	}
	if res, err = Verify(renewed, VerifyOptions{Now: now.Add(time.Hour)}); err != nil || !res.Valid {
		t.Fatalf("renewed record, no objects: err=%v reason=%s", err, res.Reason)
	}
}

// TestVerifyStructureOnlyStillChecksTheReduction makes sure the no-objects path
// is not a free pass: the reduced hash tree must still recompute to the token
// imprint, so a record whose tree was edited is rejected even with nothing to
// prove membership for.
func TestVerifyStructureOnlyStillChecksTheReduction(t *testing.T) {
	h := newTSAHarness(t)
	h.setNow(time.Date(2030, 5, 5, 12, 0, 0, 0, time.UTC))
	objs := objects("a", "b", "c")
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objs})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	now := time.Date(2030, 5, 5, 13, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		mutate func(seq []archiveTimeStampChain)
	}{
		{"leaf byte flipped", func(seq []archiveTimeStampChain) {
			seq[0][0].ReducedHashtree[0][1] = flipByte(seq[0][0].ReducedHashtree[0][1], 0)
		}},
		{"extra leaf injected", func(seq []archiveTimeStampChain) {
			seq[0][0].ReducedHashtree[0] = append(seq[0][0].ReducedHashtree[0], leafHash(crypto.SHA256, []byte("extra")))
		}},
		{"leaf removed", func(seq []archiveTimeStampChain) {
			seq[0][0].ReducedHashtree[0] = seq[0][0].ReducedHashtree[0][1:]
		}},
		{"reduced hash tree dropped entirely", func(seq []archiveTimeStampChain) {
			seq[0][0].ReducedHashtree = nil
		}},
		{"reduced hash tree emptied", func(seq []archiveTimeStampChain) {
			seq[0][0].ReducedHashtree = []partialHashtree{{}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Verify(rebuild(er, tc.mutate), VerifyOptions{Now: now})
			if err != nil {
				return
			}
			if res.Valid {
				t.Fatalf("structure-only verification accepted a tampered reduced hash tree")
			}
		})
	}
}

// TestVerifyRevokesObjectCoverageWhenAChainFailsEarly is the regression test for
// the per-object result of a chain that fails before the coverage fold: an
// unsupported chain digest algorithm (or any entry-leaf failure) used to leave
// every object reported as Covered:true, i.e. claiming a proof that was never
// checked. The code's own invariant is "a chain that fails structurally revokes
// coverage for every object".
func TestVerifyRevokesObjectCoverageWhenAChainFailsEarly(t *testing.T) {
	h := newTSAHarness(t)
	objs := objects("a", "b")
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objs})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(seq []archiveTimeStampChain)
	}{
		{"unsupported chain digest algorithm", func(seq []archiveTimeStampChain) {
			seq[0][0].DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidSHA1}
		}},
		{"chain with no archive timestamps", func(seq []archiveTimeStampChain) {
			seq[0] = archiveTimeStampChain{}
		}},
		{"timestamp token replaced by garbage", func(seq []archiveTimeStampChain) {
			seq[0][0].DigestAlgorithm = pkix.AlgorithmIdentifier{}
			seq[0][0].TimeStamp = asn1.RawValue{FullBytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Verify(rebuild(er, tc.mutate), VerifyOptions{Objects: objs})
			if err != nil {
				t.Fatalf("Verify returned an error rather than a result: %v", err)
			}
			if res.Valid {
				t.Fatal("a broken chain must not verify")
			}
			if len(res.Objects) != len(objs) {
				t.Fatalf("expected %d object results, got %d", len(objs), len(res.Objects))
			}
			for _, o := range res.Objects {
				if o.Covered {
					t.Fatalf("object %q reported as covered by a chain that did not verify", o.ID)
				}
				if o.Reason == "" {
					t.Fatalf("object %q reported uncovered without a reason", o.ID)
				}
			}
		})
	}
}

// TestVerifyRejectsRecordTampering walks every single-mutation an attacker
// holding the stored DER could make to a two-chain, three-timestamp record and
// asserts verification rejects each one. A verifier that accepted everything
// would pass every happy-path test in this package; only this table proves it
// actually checks.
func TestVerifyRejectsRecordTampering(t *testing.T) {
	h := newTSAHarness(t)
	roots := []*x509.Certificate{h.caCert}
	objs := objects("evt-1", "evt-2", "evt-3")
	ctx := context.Background()

	t0 := time.Date(2030, 2, 1, 0, 0, 0, 0, time.UTC)
	h.setNow(t0)
	er, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objs})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	h.setNow(t0.AddDate(0, 1, 0))
	er, err = er.RenewTimestamp(ctx, h.ts())
	if err != nil {
		t.Fatalf("RenewTimestamp: %v", err)
	}
	h.setNow(t0.AddDate(0, 2, 0))
	er, err = er.RenewHashTree(ctx, h.ts(), objs, crypto.SHA512)
	if err != nil {
		t.Fatalf("RenewHashTree: %v", err)
	}
	now := t0.AddDate(0, 3, 0)

	// A second, unrelated record supplies "foreign" tokens for the swap cases.
	other := objects("other-1", "other-2")
	foreign, err := Generate(ctx, h.ts(), GenerateOptions{Objects: other})
	if err != nil {
		t.Fatalf("Generate foreign: %v", err)
	}
	foreignToken, _ := foreign.LatestToken()

	// Baseline: the untouched record must verify, else the table proves nothing.
	if res, err := Verify(er, VerifyOptions{Objects: objs, Roots: roots, Now: now}); err != nil || !res.Valid {
		t.Fatalf("baseline record must verify: err=%v reason=%s", err, res.Reason)
	}

	tests := []struct {
		name   string
		mutate func(seq []archiveTimeStampChain)
	}{
		{"chain 0 leaf byte flipped", func(seq []archiveTimeStampChain) {
			seq[0][0].ReducedHashtree[0][0] = flipByte(seq[0][0].ReducedHashtree[0][0], 31)
		}},
		{"chain 1 leaf byte flipped", func(seq []archiveTimeStampChain) {
			seq[1][0].ReducedHashtree[0][2] = flipByte(seq[1][0].ReducedHashtree[0][2], 7)
		}},
		{"chain 0 leaves reordered into a second list", func(seq []archiveTimeStampChain) {
			list := seq[0][0].ReducedHashtree[0]
			seq[0][0].ReducedHashtree = []partialHashtree{list[:1], list[1:]}
		}},
		{"extra leaf appended to chain 0", func(seq []archiveTimeStampChain) {
			seq[0][0].ReducedHashtree[0] = append(seq[0][0].ReducedHashtree[0], leafHash(crypto.SHA256, []byte("intruder")))
		}},
		{"chain 0 renewal token swapped for a foreign one", func(seq []archiveTimeStampChain) {
			seq[0][1].TimeStamp = asn1.RawValue{FullBytes: foreignToken}
		}},
		{"chain 0 first token swapped for a foreign one", func(seq []archiveTimeStampChain) {
			seq[0][0].TimeStamp = asn1.RawValue{FullBytes: foreignToken}
		}},
		{"chain 1 token swapped for chain 0's", func(seq []archiveTimeStampChain) {
			seq[1][0].TimeStamp = seq[0][0].TimeStamp
		}},
		{"chain 0 timestamps transposed", func(seq []archiveTimeStampChain) {
			seq[0][0], seq[0][1] = seq[0][1], seq[0][0]
		}},
		{"chain 0 renewal timestamp dropped", func(seq []archiveTimeStampChain) {
			seq[0] = seq[0][:1]
		}},
		{"chain 0 first timestamp dropped", func(seq []archiveTimeStampChain) {
			seq[0] = seq[0][1:]
		}},
		{"renewal linkage rebound to a foreign token", func(seq []archiveTimeStampChain) {
			seq[0][1].ReducedHashtree = groupReducedTree([][]byte{leafHash(crypto.SHA256, foreignToken)})
		}},
		{"chain 1 digest algorithm downgraded to the chain 0 algorithm", func(seq []archiveTimeStampChain) {
			seq[1][0].DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
		}},
		{"chain 0 digest algorithm upgraded to SHA-512", func(seq []archiveTimeStampChain) {
			seq[0][0].DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidSHA512}
		}},
		{"chains transposed (hash-tree renewal order reversed)", func(seq []archiveTimeStampChain) {
			seq[0], seq[1] = seq[1], seq[0]
		}},
		{"chain 1 removed (dropping the algorithm migration)", func(seq []archiveTimeStampChain) {
			// Truncating the sequence to just chain 0 is a legitimate earlier state of
			// the same record, so it is covered separately; here the *first* chain is
			// dropped instead, orphaning chain 1's binding to the prior sequence.
			seq[0] = seq[1]
		}},
		{"token bytes bit-flipped in chain 1", func(seq []archiveTimeStampChain) {
			tok := seq[1][0].TimeStamp.FullBytes
			seq[1][0].TimeStamp = asn1.RawValue{FullBytes: flipByte(tok, len(tok)-12)}
		}},
		{"token removed from chain 1", func(seq []archiveTimeStampChain) {
			seq[1][0].TimeStamp = asn1.RawValue{}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := rebuild(er, tc.mutate)
			res, err := Verify(tampered, VerifyOptions{Objects: objs, Roots: roots, Now: now})
			if err != nil {
				return
			}
			if res.Valid {
				t.Fatalf("tampered record verified as valid")
			}
			// An invalid record must never report every object as still covered:
			// that is the field an operator reads as "this object is proven".
			allCovered := len(res.Objects) == len(objs)
			for _, o := range res.Objects {
				if !o.Covered {
					allCovered = false
				}
			}
			if allCovered {
				t.Fatalf("an invalid record reported every object as covered: %+v", res.Objects)
			}
		})
	}

	// Truncating the sequence back to chain 0 is not tampering — it is the record
	// before its hash-tree renewal — and must still verify. This is the
	// "an earlier proof survives later additions" property.
	prefix := rebuild(er, func(seq []archiveTimeStampChain) {})
	prefix.wire.ArchiveTimeStampSequence = prefix.wire.ArchiveTimeStampSequence[:1]
	if res, err := Verify(prefix, VerifyOptions{Objects: objs, Roots: roots, Now: now}); err != nil || !res.Valid {
		t.Fatalf("the pre-renewal prefix of a record must still verify: err=%v reason=%s", err, res.Reason)
	}
}

// TestVerifyRejectsWrongTrustAnchor: a token that verifies on its own must still
// be refused when the supplied trust anchor is not the one that issued the TSA
// certificate.
func TestVerifyRejectsWrongTrustAnchor(t *testing.T) {
	h := newTSAHarness(t)
	stranger := newTSAHarness(t)
	objs := objects("a", "b")
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objs})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// No roots: token integrity only, must pass.
	if res, _ := Verify(er, VerifyOptions{Objects: objs}); !res.Valid {
		t.Fatalf("token integrity alone must pass: %s", res.Reason)
	}
	// Correct root: must pass.
	if res, _ := Verify(er, VerifyOptions{Objects: objs, Roots: []*x509.Certificate{h.caCert}}); !res.Valid {
		t.Fatalf("the issuing root must validate: %s", res.Reason)
	}
	// A foreign root: must fail.
	res, _ := Verify(er, VerifyOptions{Objects: objs, Roots: []*x509.Certificate{stranger.caCert}})
	if res.Valid {
		t.Fatal("a token must not validate against an unrelated trust anchor")
	}
}

// TestVerifyRejectsFutureAndBackwardsGenTimes covers the two temporal rules: a
// token may not be dated in the verifier's future, and genTimes may not run
// backwards across the ArchiveTimeStampSequence (which would let a stale token be
// spliced in after a newer one).
func TestVerifyRejectsFutureAndBackwardsGenTimes(t *testing.T) {
	ctx := context.Background()
	objs := objects("a", "b")

	t.Run("genTime in the verifier's future", func(t *testing.T) {
		h := newTSAHarness(t)
		gen := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
		h.setNow(gen)
		er, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objs})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		// Inside the 5-minute skew allowance: accepted.
		if res, _ := Verify(er, VerifyOptions{Objects: objs, Now: gen.Add(-time.Minute)}); !res.Valid {
			t.Fatalf("a token within the clock-skew allowance must be accepted: %s", res.Reason)
		}
		// Well beyond it: refused.
		res, err := Verify(er, VerifyOptions{Objects: objs, Now: gen.Add(-24 * time.Hour)})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if res.Valid {
			t.Fatal("a token dated a day in the verifier's future must be refused")
		}
	})

	t.Run("genTime running backwards across chains", func(t *testing.T) {
		h := newTSAHarness(t)
		late := time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC)
		h.setNow(late)
		er, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objs})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		// The hash-tree renewal is stamped *earlier* than the chain it renews — the
		// shape a spliced-in stale token would have.
		h.setNow(late.AddDate(-2, 0, 0))
		er, err = er.RenewHashTree(ctx, h.ts(), objs, crypto.SHA512)
		if err != nil {
			t.Fatalf("RenewHashTree: %v", err)
		}
		res, err := Verify(er, VerifyOptions{Objects: objs, Now: late.AddDate(1, 0, 0)})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if res.Valid {
			t.Fatal("a sequence whose genTimes run backwards must be refused")
		}
	})
}

// TestVerifyEmptySequenceIsRejected: a record with no ArchiveTimeStamp proves
// nothing and must be reported invalid (not silently valid, and not an error).
func TestVerifyEmptySequenceIsRejected(t *testing.T) {
	empty := &EvidenceRecord{wire: evidenceRecord{Version: Version}}
	res, err := Verify(empty, VerifyOptions{Objects: objects("a")})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("an empty sequence must not verify")
	}
	if res.Reason == "" {
		t.Fatal("an invalid result must carry a reason")
	}
	if _, err := empty.CurrentHash(); err != ErrNoTimestamp {
		t.Fatalf("CurrentHash on an empty record = %v, want ErrNoTimestamp", err)
	}
	if _, ok := empty.LatestToken(); ok {
		t.Fatal("an empty record has no latest token")
	}
	if _, ok := empty.LatestGenTime(); ok {
		t.Fatal("an empty record has no latest genTime")
	}
	if _, ok := empty.LatestSignerNotAfter(); ok {
		t.Fatal("an empty record has no TSA certificate expiry")
	}
	if _, err := empty.RenewTimestamp(context.Background(), nil); err != ErrNoTimestamp {
		t.Fatalf("RenewTimestamp on an empty record = %v, want ErrNoTimestamp", err)
	}
}

// TestCheckReductionTable unit-tests the reduction/imprint gate directly, with
// the imprint computed by crypto/sha256 rather than by the package under test.
func TestCheckReductionTable(t *testing.T) {
	const hash = crypto.SHA256
	a := leafHash(hash, []byte("a"))
	b := leafHash(hash, []byte("b"))
	c := leafHash(hash, []byte("c"))
	tree := groupReducedTree([][]byte{a, b, c})
	// Independent imprint: SHA-256 over the binary-ascending concatenation.
	sum := sha256.Sum256(oracleSortedConcat([][]byte{a, b, c}))
	imprint := sum[:]
	if !bytes.Equal(imprint, groupRoot(hash, [][]byte{a, b, c})) {
		t.Fatal("test setup: oracle and implementation disagree on the group root")
	}
	wrongImprint := flipByte(imprint, 0)

	tests := []struct {
		name    string
		reduced []partialHashtree
		members [][]byte
		imprint []byte
		wantErr bool
	}{
		{"all three members", tree, [][]byte{a, b, c}, imprint, false},
		{"one member", tree, [][]byte{b}, imprint, false},
		{"no members (structure only)", tree, nil, imprint, false},
		{"no members, wrong root", tree, nil, wrongImprint, true},
		{"valid proof against the wrong root", tree, [][]byte{a}, wrongImprint, true},
		{"member absent from the tree", tree, [][]byte{leafHash(hash, []byte("z"))}, imprint, true},
		{"one of several members absent", tree, [][]byte{a, leafHash(hash, []byte("z"))}, imprint, true},
		{"empty first partial list", []partialHashtree{{}}, [][]byte{a}, imprint, true},
		{"empty first partial list, no members", []partialHashtree{{}}, nil, imprint, true},
		{"no reduced tree, single member matching the imprint", nil, [][]byte{imprint}, imprint, false},
		{"no reduced tree, single member not matching", nil, [][]byte{a}, imprint, true},
		{"no reduced tree, several members", nil, [][]byte{a, b}, imprint, true},
		{"no reduced tree, no members", nil, nil, imprint, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkReduction(hash, clonePartials(tc.reduced), tc.members, tc.imprint)
			if tc.wantErr && err == nil {
				t.Fatal("expected checkReduction to reject")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected checkReduction to accept, got %v", err)
			}
		})
	}
}

// TestVerifyErrorFormatting pins the operator-facing error rendering and the
// errors.Unwrap chain VerifyError participates in.
func TestVerifyErrorFormatting(t *testing.T) {
	inner := &UnsupportedHashError{Hash: crypto.MD5}
	if got := inner.Error(); !bytes.Contains([]byte(got), []byte("SHA-256/384/512 only")) {
		t.Fatalf("UnsupportedHashError.Error() = %q", got)
	}

	e := verifyErr(2, "event:17", "root mismatch", inner)
	got := e.Error()
	for _, want := range []string{"ers: verification failed", `for object "event:17"`, "(chain 2)", "root mismatch"} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("VerifyError.Error() = %q, missing %q", got, want)
		}
	}
	if e.Unwrap() != error(inner) {
		t.Fatalf("Unwrap() = %v, want the wrapped UnsupportedHashError", e.Unwrap())
	}

	// A whole-record failure (chain -1) with no object and no wrapped error must
	// not render an empty "(chain -1)"/object clause.
	bare := verifyErr(-1, "", "no archive timestamp", nil)
	if got := bare.Error(); got != "ers: verification failed: no archive timestamp" {
		t.Fatalf("bare VerifyError.Error() = %q", got)
	}
}
