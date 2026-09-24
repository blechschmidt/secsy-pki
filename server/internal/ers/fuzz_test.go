package ers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

// Evidence Records arrive from outside the deployment: POST /api/ers/verify takes
// a base64 DER record from any read-capable caller, `secsy-ca ers verify -in`
// takes a file, and a record can have been sitting in an archive for years. Parse
// and Verify therefore run over fully attacker-chosen bytes before any signature
// is checked, so neither may panic and Parse must not bless a structure its
// callers would then dereference blindly.

// syntheticRecord builds a structurally well-formed EvidenceRecord DER without a
// TSA: the embedded token is a placeholder SEQUENCE. It is the shape seed for the
// parser targets (the token's validity is irrelevant to DER decoding) and lets the
// fuzz corpus be built from a *testing.F.
func syntheticRecord(tb testing.TB, chains int, stampsPerChain int) []byte {
	tb.Helper()
	placeholder, err := asn1.Marshal(struct {
		OID  asn1.ObjectIdentifier
		Blob []byte
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, []byte("not-a-real-token")})
	if err != nil {
		tb.Fatal(err)
	}
	var seq []archiveTimeStampChain
	for c := 0; c < chains; c++ {
		var chain archiveTimeStampChain
		for s := 0; s < stampsPerChain; s++ {
			chain = append(chain, archiveTimeStamp{
				DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
				ReducedHashtree: groupReducedTree([][]byte{
					leafHash(crypto.SHA256, []byte{byte(c), byte(s), 1}),
					leafHash(crypto.SHA256, []byte{byte(c), byte(s), 2}),
					leafHash(crypto.SHA256, []byte{byte(c), byte(s), 3}),
				}),
				TimeStamp: asn1.RawValue{FullBytes: placeholder},
			})
		}
		seq = append(seq, chain)
	}
	der, err := marshalEvidenceRecord(&evidenceRecord{
		Version:                  Version,
		DigestAlgorithms:         []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		ArchiveTimeStampSequence: seq,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

// malformedRecords are the DER shapes that most often break a length-driven
// parser, plus the semantically wrong-but-well-formed records.
func malformedRecords(tb testing.TB) map[string][]byte {
	tb.Helper()
	good := syntheticRecord(tb, 1, 1)
	wrongVersion := func(v int) []byte {
		der, err := marshalEvidenceRecord(&evidenceRecord{
			Version:                  v,
			DigestAlgorithms:         []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
			ArchiveTimeStampSequence: []archiveTimeStampChain{{archiveTimeStamp{TimeStamp: asn1.RawValue{FullBytes: []byte{0x30, 0x00}}}}},
		})
		if err != nil {
			tb.Fatal(err)
		}
		return der
	}
	noChains, err := marshalEvidenceRecord(&evidenceRecord{
		Version:          Version,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
	})
	if err != nil {
		tb.Fatal(err)
	}
	deep := []byte{}
	for i := 0; i < 96; i++ {
		deep = append([]byte{0x30, byte(len(deep))}, deep...)
	}
	return map[string][]byte{
		"nil":                    nil,
		"empty":                  {},
		"empty SEQUENCE":         {0x30, 0x00},
		"length claims 64KiB":    {0x30, 0x82, 0xff, 0xff},
		"BER indefinite length":  {0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00},
		"ASN.1 NULL":             {0x05, 0x00},
		"bare INTEGER":           {0x02, 0x01, 0x01},
		"OCTET STRING":           {0x04, 0x03, 0x01, 0x02, 0x03},
		"not DER at all":         []byte("this is not an evidence record"),
		"deeply nested SEQUENCE": deep,
		"trailing byte":          append(append([]byte{}, good...), 0x00),
		"trailing SEQUENCE":      append(append([]byte{}, good...), 0x30, 0x00),
		"version 0":              wrongVersion(0),
		"version 2":              wrongVersion(2),
		"no archive timestamps":  noChains,
		"first byte corrupted":   flipByte(good, 0),
		"length byte corrupted":  flipByte(good, 1),
	}
}

// TestParseRejectsMalformedDER: every malformed or semantically invalid input
// must come back as an error with a nil record, and never as a panic.
func TestParseRejectsMalformedDER(t *testing.T) {
	for name, der := range malformedRecords(t) {
		t.Run(name, func(t *testing.T) {
			er, err := Parse(der)
			if err == nil {
				t.Fatalf("Parse accepted %q (%d bytes)", name, len(der))
			}
			if er != nil {
				t.Fatalf("Parse returned a record alongside error %v", err)
			}
		})
	}
	// The well-formed shape must parse, so the table above is not passing merely
	// because Parse rejects everything.
	if _, err := Parse(syntheticRecord(t, 2, 2)); err != nil {
		t.Fatalf("Parse rejected a well-formed synthetic record: %v", err)
	}
}

// TestParseTruncationPrefixes feeds every prefix of a real, TSA-signed record to
// Parse, and whatever Parse blesses straight on to Verify, Info and the renewal
// entry points. A truncated store read or a clipped upload must produce an error,
// never a crash.
func TestParseTruncationPrefixes(t *testing.T) {
	h := newTSAHarness(t)
	objs := objects("a", "b", "c")
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objs})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, err := er.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	accepted := 0
	for n := 0; n < len(der); n++ {
		parsed, perr := Parse(der[:n])
		if perr != nil {
			continue
		}
		accepted++
		// Everything Parse accepts must survive the full read-only surface.
		if _, verr := Verify(parsed, VerifyOptions{Objects: objs, Now: time.Now()}); verr != nil {
			t.Fatalf("prefix %d: Verify errored: %v", n, verr)
		}
		if _, verr := Verify(parsed, VerifyOptions{}); verr != nil {
			t.Fatalf("prefix %d: structure-only Verify errored: %v", n, verr)
		}
		_ = parsed.Info()
		_ = parsed.ChainCount()
		_, _ = parsed.CurrentHash()
		_, _ = parsed.LatestToken()
		_, _ = parsed.LatestGenTime()
		_, _ = parsed.LatestSignerNotAfter()
		if _, merr := parsed.Marshal(); merr != nil {
			t.Fatalf("prefix %d: Marshal errored: %v", n, merr)
		}
	}
	// The full record is not a prefix here, so a strict DER parser should reject
	// every one of them; the loop above exists to prove no prefix panics.
	if accepted > 0 {
		t.Logf("%d of %d truncated prefixes parsed (all survived the read-only surface)", accepted, len(der))
	}
}

// TestParseRejectsTrailingData: DER is definite-length, so a record with bytes
// after it has been tampered with or concatenated; accepting it would let two
// different byte strings carry the same "verified" record.
func TestParseRejectsTrailingData(t *testing.T) {
	h := newTSAHarness(t)
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objects("a")})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, _ := er.Marshal()
	for _, suffix := range [][]byte{{0x00}, {0x30, 0x00}, []byte("junk")} {
		if _, err := Parse(append(append([]byte{}, der...), suffix...)); err == nil {
			t.Fatalf("Parse accepted %d trailing bytes", len(suffix))
		}
	}
}

// FuzzParseEvidenceRecord drives the DER decoder. A successful parse must satisfy
// the invariants parseEvidenceRecord promises its callers — version 1 and at
// least one ArchiveTimeStampChain — because Info/CurrentHash/renewal all index
// into the sequence on that basis.
func FuzzParseEvidenceRecord(f *testing.F) {
	f.Add(syntheticRecord(f, 1, 1))
	f.Add(syntheticRecord(f, 2, 3))
	for _, der := range malformedRecords(f) {
		f.Add(der)
	}

	f.Fuzz(func(t *testing.T, der []byte) {
		er, err := Parse(der)
		if err != nil {
			if er != nil {
				t.Fatalf("Parse returned a record alongside error %v", err)
			}
			return
		}
		if er == nil {
			t.Fatal("Parse returned (nil, nil)")
		}
		if er.wire.Version != Version {
			t.Fatalf("Parse accepted version %d", er.wire.Version)
		}
		if er.ChainCount() == 0 {
			t.Fatal("Parse accepted a record with no ArchiveTimeStampChain")
		}
		// Re-encoding what was accepted must round-trip: a record whose DER cannot
		// be reproduced cannot be re-hashed for hash-tree renewal.
		out, merr := er.Marshal()
		if merr != nil {
			t.Fatalf("Marshal of a parsed record failed: %v", merr)
		}
		again, aerr := Parse(out)
		if aerr != nil {
			t.Fatalf("re-Parse of a marshalled record failed: %v", aerr)
		}
		out2, _ := again.Marshal()
		if !bytes.Equal(out, out2) {
			t.Fatal("marshal is not stable across a parse round-trip")
		}
	})
}

// FuzzVerifyEvidenceRecord drives the whole verification pipeline — chain hash
// resolution, the reduced-tree reduction, the CMS/TSTInfo token parsers and the
// certificate-path step — over attacker-chosen records, with and without
// protected objects. It must always return a result or an error, never panic, and
// must never report a bogus record as valid.
func FuzzVerifyEvidenceRecord(f *testing.F) {
	f.Add(syntheticRecord(f, 1, 1))
	f.Add(syntheticRecord(f, 3, 2))
	for _, der := range malformedRecords(f) {
		f.Add(der)
	}

	objs := []DataObject{{ID: "o0", Bytes: []byte("payload-0")}, {ID: "o1", Bytes: []byte("payload-1")}}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, der []byte) {
		er, err := Parse(der)
		if err != nil {
			return
		}
		for _, opts := range []VerifyOptions{
			{Now: now},
			{Objects: objs, Now: now},
			{Objects: objs},
		} {
			res, verr := Verify(er, opts)
			if verr != nil {
				continue
			}
			if res == nil {
				t.Fatal("Verify returned (nil, nil)")
			}
			// No synthetic/fuzzed record carries a genuine TSA signature, so none may
			// ever be reported valid.
			if res.Valid {
				t.Fatalf("Verify accepted an unsigned record as valid: %+v", res)
			}
			if res.Reason == "" {
				t.Fatal("an invalid result must carry a reason")
			}
			for _, o := range res.Objects {
				if o.Covered {
					t.Fatalf("object %q reported covered by an unsigned record", o.ID)
				}
			}
		}
		_ = er.Info()
	})
}
