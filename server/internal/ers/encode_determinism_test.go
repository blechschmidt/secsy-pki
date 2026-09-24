package ers

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// Every stored proof in this package is a hash over an encoding produced here:
// previousSequenceBytes feeds the atsc binding of a hash-tree renewal, and
// auditObjectBytes is the leaf preimage of an audit-scope record. If either
// encoding is not byte-for-byte reproducible the proof stops verifying the moment
// it is re-checked, silently and permanently. These tests assert the encodings are
// deterministic and that no field rearrangement can collide.

// synthChain builds a chain of stamps with fixed, non-random contents so its DER
// is a pure function of its inputs.
func synthChain(t testing.TB, hash crypto.Hash, stamps int, tag byte) archiveTimeStampChain {
	t.Helper()
	oid, ok := oidForDigest(hash)
	if !ok {
		t.Fatalf("no OID for %v", hash)
	}
	var chain archiveTimeStampChain
	for i := 0; i < stamps; i++ {
		chain = append(chain, archiveTimeStamp{
			DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
			ReducedHashtree: groupReducedTree([][]byte{
				leafHash(hash, []byte{tag, byte(i), 'a'}),
				leafHash(hash, []byte{tag, byte(i), 'b'}),
			}),
			TimeStamp: asn1.RawValue{FullBytes: []byte{0x30, 0x03, 0x02, 0x01, byte(i + 1)}},
		})
	}
	return chain
}

// TestMarshalEvidenceRecordIsDeterministic: repeated encodings of the same
// structure must be byte-identical, and Marshal must agree with the internal
// encoder. Anything that leaked a map iteration order or a wall-clock read into
// the DER would show up here.
func TestMarshalEvidenceRecordIsDeterministic(t *testing.T) {
	wire := evidenceRecord{
		Version: Version,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: oidSHA256}, {Algorithm: oidSHA512},
		},
		ArchiveTimeStampSequence: []archiveTimeStampChain{
			synthChain(t, crypto.SHA256, 2, 'x'),
			synthChain(t, crypto.SHA512, 1, 'y'),
		},
	}
	first, err := marshalEvidenceRecord(&wire)
	if err != nil {
		t.Fatalf("marshalEvidenceRecord: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("marshalEvidenceRecord produced no bytes")
	}
	for i := 0; i < 50; i++ {
		again, err := marshalEvidenceRecord(&wire)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("iteration %d: DER changed between encodings", i)
		}
	}
	// The exported path must produce exactly the same bytes.
	viaExported, err := (&EvidenceRecord{wire: wire}).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(first, viaExported) {
		t.Fatal("Marshal and marshalEvidenceRecord disagree")
	}
	// And it must survive a parse round-trip unchanged.
	parsed, err := Parse(first)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	again, _ := parsed.Marshal()
	if !bytes.Equal(first, again) {
		t.Fatal("DER is not stable across a parse round-trip")
	}
}

// TestMarshalEvidenceRecordReportsEncodingErrors: an unencodable structure must
// surface as a wrapped error rather than empty output that would be stored as a
// "record".
func TestMarshalEvidenceRecordReportsEncodingErrors(t *testing.T) {
	// A single-arc OBJECT IDENTIFIER is not encodable in DER.
	bad := evidenceRecord{
		Version:                  Version,
		DigestAlgorithms:         []pkix.AlgorithmIdentifier{{Algorithm: asn1.ObjectIdentifier{7}}},
		ArchiveTimeStampSequence: []archiveTimeStampChain{synthChain(t, crypto.SHA256, 1, 'z')},
	}
	der, err := marshalEvidenceRecord(&bad)
	if err == nil {
		t.Fatalf("expected an encoding error, got %d bytes", len(der))
	}
	if der != nil {
		t.Fatal("an encoding error must not come with output bytes")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("ers: encoding evidence record")) {
		t.Fatalf("error not wrapped with package context: %v", err)
	}
}

// TestDigestAlgorithmsOrderIsStable: digestAlgorithms dedups through a map, so the
// emitted order must come from the sequence, not from map iteration. The field is
// part of the DER that later renewals re-hash, so an unstable order would break
// the atsc binding non-deterministically.
func TestDigestAlgorithmsOrderIsStable(t *testing.T) {
	seq := []archiveTimeStampChain{
		synthChain(t, crypto.SHA512, 1, 'a'),
		synthChain(t, crypto.SHA256, 1, 'b'),
		synthChain(t, crypto.SHA384, 2, 'c'),
		synthChain(t, crypto.SHA256, 1, 'd'), // duplicate, must be deduped
	}
	want := []string{oidSHA512.String(), oidSHA256.String(), oidSHA384.String()}
	for iter := 0; iter < 200; iter++ {
		algs, err := digestAlgorithms(seq)
		if err != nil {
			t.Fatalf("iteration %d: %v", iter, err)
		}
		if len(algs) != len(want) {
			t.Fatalf("iteration %d: %d algorithms, want %d", iter, len(algs), len(want))
		}
		for i, w := range want {
			if algs[i].Algorithm.String() != w {
				t.Fatalf("iteration %d: algorithm %d = %s, want %s (order is not stable)",
					iter, i, algs[i].Algorithm, w)
			}
		}
	}
	// An unsupported chain algorithm must be an error, not a silently dropped entry.
	broken := []archiveTimeStampChain{{archiveTimeStamp{
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA1},
		TimeStamp:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
	}}}
	if _, err := digestAlgorithms(broken); err == nil {
		t.Fatal("digestAlgorithms accepted an unsupported chain algorithm")
	}
}

// TestPreviousSequenceBytesIsTheChainConcatenation pins the atsc(i) input of a
// hash-tree renewal: the concatenation of each prior chain's DER, in order. The
// generate and verify sides both hash exactly this, so it must be reproducible and
// must change whenever any covered chain changes.
func TestPreviousSequenceBytesIsTheChainConcatenation(t *testing.T) {
	chains := []archiveTimeStampChain{
		synthChain(t, crypto.SHA256, 2, 'p'),
		synthChain(t, crypto.SHA384, 1, 'q'),
	}
	got, err := previousSequenceBytes(chains)
	if err != nil {
		t.Fatalf("previousSequenceBytes: %v", err)
	}
	var want []byte
	for i, c := range chains {
		der, err := marshalChain(c)
		if err != nil {
			t.Fatalf("marshalChain %d: %v", i, err)
		}
		want = append(want, der...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("previousSequenceBytes is not the ordered concatenation of the chain DERs\n got=%x\nwant=%x", got, want)
	}

	// Deterministic across calls.
	for i := 0; i < 20; i++ {
		again, _ := previousSequenceBytes(chains)
		if !bytes.Equal(got, again) {
			t.Fatalf("iteration %d: previousSequenceBytes changed", i)
		}
	}
	// Order matters: swapping the chains must change the binding.
	swapped, _ := previousSequenceBytes([]archiveTimeStampChain{chains[1], chains[0]})
	if bytes.Equal(got, swapped) {
		t.Fatal("previousSequenceBytes must depend on chain order")
	}
	// A prefix must differ from the whole.
	prefix, _ := previousSequenceBytes(chains[:1])
	if bytes.Equal(got, prefix) {
		t.Fatal("previousSequenceBytes must depend on how many chains it covers")
	}
	// Zero chains is the initial-chain case: no prior sequence.
	if empty, err := previousSequenceBytes(nil); err != nil || len(empty) != 0 {
		t.Fatalf("previousSequenceBytes(nil) = %x, %v", empty, err)
	}
}

// TestAuditObjectBytesIsCanonical: the leaf preimage of an audit-scope record must
// be a pure function of the immutable event row, reproducible from a later read of
// the append-only log.
func TestAuditObjectBytesIsCanonical(t *testing.T) {
	ev := audit.Event{
		Seq: 4242, ID: "id-1", Timestamp: time.Date(2027, 3, 4, 5, 6, 7, 890123456, time.UTC),
		Actor: "alice", ActorName: "Alice A", ActorRoles: "admin,issuer",
		Action: audit.ActionCertIssue, Tenant: "t1", Target: "cert-1", TargetName: "example.com",
		Result: audit.ResultSuccess, Detail: "issued", PrevHash: "aa", Hash: "bb",
	}
	base := auditObjectBytes(ev)
	for i := 0; i < 20; i++ {
		if !bytes.Equal(base, auditObjectBytes(ev)) {
			t.Fatalf("iteration %d: auditObjectBytes is not deterministic", i)
		}
	}

	// The timestamp is normalised to UTC, so the location a driver hands back must
	// not change the bytes.
	loc := time.FixedZone("UTC+5", 5*3600)
	shifted := ev
	shifted.Timestamp = ev.Timestamp.In(loc)
	if !bytes.Equal(base, auditObjectBytes(shifted)) {
		t.Fatal("auditObjectBytes must not depend on the timestamp's location")
	}
	// …but a different instant must.
	later := ev
	later.Timestamp = ev.Timestamp.Add(time.Nanosecond)
	if bytes.Equal(base, auditObjectBytes(later)) {
		t.Fatal("a one-nanosecond timestamp change must change the leaf preimage")
	}

	// Every field must be bound: changing any one of them changes the bytes.
	mutations := map[string]func(e *audit.Event){
		"seq":         func(e *audit.Event) { e.Seq++ },
		"id":          func(e *audit.Event) { e.ID += "x" },
		"actor":       func(e *audit.Event) { e.Actor = "bob" },
		"actor_name":  func(e *audit.Event) { e.ActorName = "Bob" },
		"actor_roles": func(e *audit.Event) { e.ActorRoles = "auditor" },
		"action":      func(e *audit.Event) { e.Action = audit.ActionCertRevoke },
		"tenant":      func(e *audit.Event) { e.Tenant = "t2" },
		"target":      func(e *audit.Event) { e.Target = "cert-2" },
		"target_name": func(e *audit.Event) { e.TargetName = "other.example" },
		"result":      func(e *audit.Event) { e.Result = audit.ResultError },
		"detail":      func(e *audit.Event) { e.Detail = "denied" },
		"prev_hash":   func(e *audit.Event) { e.PrevHash = "cc" },
		"hash":        func(e *audit.Event) { e.Hash = "dd" },
	}
	for name, mut := range mutations {
		changed := ev
		mut(&changed)
		if bytes.Equal(base, auditObjectBytes(changed)) {
			t.Fatalf("changing %s did not change the leaf preimage", name)
		}
	}

	// Length prefixing must make field boundaries unambiguous: moving a character
	// across a boundary is a different event and must hash differently.
	left, right := ev, ev
	left.Actor, left.ActorName = "ab", "c"
	right.Actor, right.ActorName = "a", "bc"
	if bytes.Equal(auditObjectBytes(left), auditObjectBytes(right)) {
		t.Fatal("field values shifted across a boundary collided: the encoding is not injective")
	}
}

// TestAuditObjectBytesLayout decodes the encoding back by hand — 8-byte
// big-endian seq followed by thirteen 32-bit-length-prefixed strings — so a
// reordered or dropped field is caught, not just a changed digest.
func TestAuditObjectBytesLayout(t *testing.T) {
	ev := audit.Event{
		Seq: 0x0102030405060708, ID: "id", Timestamp: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
		Actor: "a", ActorName: "an", ActorRoles: "ar", Action: "act", Tenant: "tn",
		Target: "tg", TargetName: "tgn", Result: "res", Detail: "det", PrevHash: "ph", Hash: "h",
	}
	b := auditObjectBytes(ev)
	if len(b) < 8 {
		t.Fatalf("encoding is %d bytes", len(b))
	}
	if got := binary.BigEndian.Uint64(b[:8]); got != uint64(ev.Seq) {
		t.Fatalf("seq prefix = %#x, want %#x", got, uint64(ev.Seq))
	}
	off := 8
	var fields []string
	for off < len(b) {
		if off+4 > len(b) {
			t.Fatalf("truncated length prefix at offset %d", off)
		}
		n := int(binary.BigEndian.Uint32(b[off : off+4]))
		off += 4
		if off+n > len(b) {
			t.Fatalf("length prefix %d at offset %d overruns the %d-byte encoding", n, off-4, len(b))
		}
		fields = append(fields, string(b[off:off+n]))
		off += n
	}
	want := []string{
		"id", ev.Timestamp.UTC().Format(time.RFC3339Nano), "a", "an", "ar",
		"act", "tn", "tg", "tgn", "res", "det", "ph", "h",
	}
	if len(fields) != len(want) {
		t.Fatalf("decoded %d fields, want %d: %q", len(fields), len(want), fields)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Fatalf("field %d = %q, want %q (field order changed)", i, fields[i], want[i])
		}
	}
}

// TestHashNameRoundTrip covers the config/CLI hash-name mapping in both
// directions, including the spelling variants operators actually type.
func TestHashNameRoundTrip(t *testing.T) {
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		name := HashName(h)
		if got := HashByName(name); got != h {
			t.Fatalf("HashByName(HashName(%v)) = %v", h, got)
		}
		bits := h.Size() * 8
		for _, variant := range []string{
			fmt.Sprintf("sha%d", bits), fmt.Sprintf("sha-%d", bits),
			fmt.Sprintf("SHA%d", bits), fmt.Sprintf("SHA-%d", bits),
		} {
			if got := HashByName(variant); got != h {
				t.Fatalf("HashByName(%q) = %v, want %v", variant, got, h)
			}
		}
		if _, err := algorithmIdentifier(h); err != nil {
			t.Fatalf("algorithmIdentifier(%v): %v", h, err)
		}
	}
	for _, unknown := range []string{"", "sha1", "sha-1", "md5", "sha3-256", "Sha256", "sha 256"} {
		if got := HashByName(unknown); got != 0 {
			t.Fatalf("HashByName(%q) = %v, want 0 (unknown)", unknown, got)
		}
	}
	if got := HashName(crypto.SHA1); got != "unknown" {
		t.Fatalf("HashName(SHA-1) = %q, want \"unknown\"", got)
	}
	if _, err := algorithmIdentifier(crypto.SHA1); err == nil {
		t.Fatal("algorithmIdentifier must refuse an algorithm outside the SHA-2 family")
	}
	// hashRank must order the family so "weaker than the target" is well defined.
	if !(hashRank(crypto.SHA256) < hashRank(crypto.SHA384) && hashRank(crypto.SHA384) < hashRank(crypto.SHA512)) {
		t.Fatal("hashRank must order SHA-256 < SHA-384 < SHA-512")
	}
	if hashRank(crypto.SHA1) != 0 {
		t.Fatal("an unranked algorithm must rank 0 so anything supported outranks it")
	}
}

// TestDigestOIDMappingIsBijective guards the OID table both ways: a wrong OID here
// would make every token's algorithm identifier unreadable to other implementations.
func TestDigestOIDMappingIsBijective(t *testing.T) {
	want := map[crypto.Hash]string{
		crypto.SHA256: "2.16.840.1.101.3.4.2.1",
		crypto.SHA384: "2.16.840.1.101.3.4.2.2",
		crypto.SHA512: "2.16.840.1.101.3.4.2.3",
	}
	for h, oidStr := range want {
		oid, ok := oidForDigest(h)
		if !ok || oid.String() != oidStr {
			t.Fatalf("oidForDigest(%v) = %v/%t, want %s", h, oid, ok, oidStr)
		}
		back, ok := digestForOID(oid)
		if !ok || back != h {
			t.Fatalf("digestForOID(%s) = %v/%t, want %v", oidStr, back, ok, h)
		}
	}
	if _, ok := digestForOID(oidSHA1); ok {
		t.Fatal("SHA-1 must not map to a usable hash-tree algorithm")
	}
	if _, ok := oidForDigest(crypto.MD5); ok {
		t.Fatal("MD5 must not map to a digest OID")
	}
	// The RFC 4998 id-aa-er-internal attribute OID must not drift.
	if got := OIDEvidenceRecord.String(); got != "1.2.840.113549.1.9.16.2.49" {
		t.Fatalf("OIDEvidenceRecord = %s", got)
	}
}

// TestLeafHashIsPlainH pins the leaf construction to a single application of H
// with no prefix or domain separator, which is what RFC 4998 §4.2 specifies and
// what any other implementation will recompute.
func TestLeafHashIsPlainH(t *testing.T) {
	// SHA-256("abc"), the FIPS 180-4 known answer.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := hex.EncodeToString(leafHash(crypto.SHA256, []byte("abc"))); got != want {
		t.Fatalf("leafHash(SHA-256, \"abc\") = %s, want %s", got, want)
	}
	if got := hex.EncodeToString(hashNode(crypto.SHA256, []byte("abc"))); got != want {
		t.Fatalf("hashNode must be the same single application of H: %s", got)
	}
}
