//go:build sqlite

package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// An anchor is the only evidence that defeats a store writer who can re-seal the
// whole hash chain. Its value is entirely in what it REJECTS, so the tests below
// mutate one thing at a time — the anchored seq, the anchored hash, the token, the
// covered events — and require verification to fail every time.

// mintAnchor anchors the current head of db and returns the persisted anchor.
func mintAnchor(t *testing.T, db *database.DB, h *tsaHarness, force bool) audit.Anchor {
	t.Helper()
	svc := NewService(db, NewAuthorityTimestamper(h.authority))
	res, err := svc.AnchorOnce(context.Background(), force)
	if err != nil {
		t.Fatalf("AnchorOnce: %v", err)
	}
	if res.Skipped || res.Anchor == nil {
		t.Fatalf("expected an anchor, got %+v", res)
	}
	return *res.Anchor
}

// TestVerifyAnchorTokenNegatives mutates a genuine anchor one field at a time. The
// token binds (seq, head hash) through its message imprint, so every one of these
// must be rejected.
func TestVerifyAnchorTokenNegatives(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 4)
	a := mintAnchor(t, db, h, false)
	roots := []*x509.Certificate{h.caCert}
	now := time.Now()

	// Baseline, with and without trust anchors.
	if err := VerifyAnchorToken(a, nil, now); err != nil {
		t.Fatalf("baseline anchor must verify: %v", err)
	}
	if err := VerifyAnchorToken(a, roots, now); err != nil {
		t.Fatalf("baseline anchor must chain to the test root: %v", err)
	}
	// The head hash compares case-insensitively, because chain hashes are hex.
	upper := a
	upper.HeadHash = strings.ToUpper(a.HeadHash)
	if err := VerifyAnchorToken(upper, roots, now); err != nil {
		t.Fatalf("an uppercase head hash must still verify (canonical lowercasing): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(x *audit.Anchor)
		want   string
	}{
		{"sequence number incremented", func(x *audit.Anchor) { x.Seq++ }, "does not cover"},
		{"sequence number decremented", func(x *audit.Anchor) { x.Seq-- }, "does not cover"},
		{"sequence number zeroed", func(x *audit.Anchor) { x.Seq = 0 }, "does not cover"},
		{"head hash nibble changed", func(x *audit.Anchor) {
			b := []byte(x.HeadHash)
			if b[0] == 'a' {
				b[0] = 'b'
			} else {
				b[0] = 'a'
			}
			x.HeadHash = string(b)
		}, "does not cover"},
		{"head hash truncated", func(x *audit.Anchor) { x.HeadHash = x.HeadHash[:len(x.HeadHash)-1] }, "does not cover"},
		{"head hash emptied", func(x *audit.Anchor) { x.HeadHash = "" }, "does not cover"},
		{"head hash replaced wholesale", func(x *audit.Anchor) { x.HeadHash = strings.Repeat("cd", 32) }, "does not cover"},
		{"token emptied", func(x *audit.Anchor) { x.Token = nil }, "parsing timestamp token"},
		{"token bit-flipped in the RSA signature", func(x *audit.Anchor) {
			x.Token = flipByte(x.Token, tokenOffset(t, x.Token, signatureOf(t, x.Token)))
		}, "signature"},
		{"token bit-flipped in the embedded imprint", func(x *audit.Anchor) {
			x.Token = flipByte(x.Token, tokenOffset(t, x.Token, imprintOf(t, x.Token)))
		}, ""},
		{"token bit-flipped in the embedded genTime", func(x *audit.Anchor) {
			x.Token = flipByte(x.Token, tokenOffset(t, x.Token, genTimeBytesOf(t, x.Token)))
		}, ""},
		{"token truncated by one byte", func(x *audit.Anchor) { x.Token = x.Token[:len(x.Token)-1] }, ""},
		{"token with a trailing byte", func(x *audit.Anchor) { x.Token = append(append([]byte{}, x.Token...), 0x00) }, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			forged := a
			forged.Token = append([]byte(nil), a.Token...)
			tc.mutate(&forged)
			err := VerifyAnchorToken(forged, roots, now)
			if err == nil {
				t.Fatal("a tampered anchor must not verify")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	// A token dated in the verifier's future is refused, but the 5-minute skew
	// allowance is honoured.
	info, err := tsa.ParseTokenInfo(a.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAnchorToken(a, nil, info.GenTime.Add(-clockSkew/2)); err != nil {
		t.Fatalf("a token inside the skew allowance must be accepted: %v", err)
	}
	err = VerifyAnchorToken(a, nil, info.GenTime.Add(-24*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("a token dated a day in the verifier's future must be refused, got %v", err)
	}

	// An unrelated trust anchor must not validate the TSA certificate.
	stranger := newTSAHarness(t)
	err = VerifyAnchorToken(a, []*x509.Certificate{stranger.caCert}, now)
	if err == nil || !strings.Contains(err.Error(), "TSA certificate chain") {
		t.Fatalf("a foreign trust anchor must be refused, got %v", err)
	}
}

// TestAnchorTokensAreNotInterchangeable is the cross-anchor swap: two anchors over
// different heads, each other's token. Both must fail, because the imprint binds
// the token to one (seq, head hash) and nothing else.
func TestAnchorTokensAreNotInterchangeable(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 3)
	first := mintAnchor(t, db, h, false)
	appendEvents(t, db, 3)
	second := mintAnchor(t, db, h, false)
	if first.Seq == second.Seq {
		t.Fatalf("test setup: both anchors cover seq %d", first.Seq)
	}
	now := time.Now()

	swappedFirst := first
	swappedFirst.Token = second.Token
	if err := VerifyAnchorToken(swappedFirst, nil, now); err == nil {
		t.Fatal("the second anchor's token must not attest the first anchor's head")
	}
	swappedSecond := second
	swappedSecond.Token = first.Token
	if err := VerifyAnchorToken(swappedSecond, nil, now); err == nil {
		t.Fatal("the first anchor's token must not attest the second anchor's head")
	}
	// Re-pointing one anchor's metadata at the other's head is the same attack from
	// the other side.
	relabelled := first
	relabelled.Seq, relabelled.HeadHash = second.Seq, second.HeadHash
	if err := VerifyAnchorToken(relabelled, nil, now); err == nil {
		t.Fatal("an anchor row re-pointed at another head must not verify")
	}
	// Both untouched anchors still verify, so the swaps above proved something.
	for i, a := range []audit.Anchor{first, second} {
		if err := VerifyAnchorToken(a, nil, now); err != nil {
			t.Fatalf("anchor %d must verify untouched: %v", i, err)
		}
	}
}

// TestAnchorImprintIsOverTheCanonicalMessage recomputes the expected imprint with
// crypto/sha256 directly, independently of AnchorDigest, so a change to the
// canonical layout (which would strand every previously minted token) is caught.
func TestAnchorImprintIsOverTheCanonicalMessage(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 6)
	a := mintAnchor(t, db, h, false)

	want := sha256.Sum256([]byte(fmt.Sprintf("secsy-pki-audit-anchor-v1\nseq=%d\nhead=%s\n", a.Seq, strings.ToLower(a.HeadHash))))
	info, err := tsa.ParseTokenInfo(a.Token)
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	if string(info.HashedMessage) != string(want[:]) {
		t.Fatalf("token imprint = %x, want the canonical anchor digest %x", info.HashedMessage, want)
	}
	// The domain separator matters: a bare "seq|hash" digest must not match.
	naive := sha256.Sum256([]byte(fmt.Sprintf("%d|%s", a.Seq, a.HeadHash)))
	if string(info.HashedMessage) == string(naive[:]) {
		t.Fatal("the imprint must be domain-separated, not a bare seq|hash digest")
	}
}

// TestAnchorSurvivesLaterEventsButNotRewrittenOnes is the core temporal property:
// an anchor attests the chain as of its own point, so later activity must never
// invalidate it — while any change to the history it covers must.
func TestAnchorSurvivesLaterEventsButNotRewrittenOnes(t *testing.T) {
	h := newTSAHarness(t)
	db, path := anchorTestDB(t)
	roots := []*x509.Certificate{h.caCert}

	appendEvents(t, db, 3)
	early := mintAnchor(t, db, h, false) // covers seq 3; its own record becomes seq 4

	// Lots of later activity, and a second anchor on top.
	appendEvents(t, db, 20)
	later := mintAnchor(t, db, h, false)
	appendEvents(t, db, 5)

	chainRes, checks := verifyAll(t, db, roots)
	if !chainRes.Valid {
		t.Fatalf("chain must verify: %+v", chainRes)
	}
	if len(checks) != 2 {
		t.Fatalf("expected 2 anchors, got %d", len(checks))
	}
	for i, c := range checks {
		if !c.Valid {
			t.Fatalf("anchor %d must survive later appends: %s", i, c.Reason)
		}
	}
	if checks[0].Seq != early.Seq || checks[1].Seq != later.Seq {
		t.Fatalf("anchors are not in ascending order: %d then %d", checks[0].Seq, checks[1].Seq)
	}

	// Now rewrite a single event the EARLY anchor covers, re-sealing the whole chain
	// from there so plain chain verification still passes. Both anchors must fail:
	// the early one because its covered head hash moved, the later one for the same
	// reason further along.
	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatal(err)
	}
	raw := rawConn(t, path)
	events[1].Detail = "backdated"
	prev := events[0].Hash
	for i := 1; i < len(events); i++ {
		e := &events[i]
		e.PrevHash = prev
		e.Hash = audit.ComputeHash(e, prev)
		if _, err := raw.Exec(`UPDATE event_log SET detail = ?, prev_hash = ?, hash = ? WHERE seq = ?`,
			e.Detail, e.PrevHash, e.Hash, e.Seq); err != nil {
			t.Fatal(err)
		}
		prev = e.Hash
	}

	chainRes, checks = verifyAll(t, db, roots)
	if !chainRes.Valid {
		t.Fatalf("the re-sealed chain must still pass plain verification (that is the attack): %+v", chainRes)
	}
	for i, c := range checks {
		if c.Valid {
			t.Fatalf("anchor %d must catch the rewrite of an event it covers: %+v", i, c)
		}
		if !strings.Contains(c.Reason, "rewritten") {
			t.Errorf("anchor %d reason should name the rewrite: %q", i, c.Reason)
		}
	}
}

// TestAnchorDetectsEventAlterationsAtItsOwnSeq drills into the single-row cases the
// full-rewrite test does not isolate: the anchored row's hash edited in place, the
// anchored row deleted, and rows after it deleted.
func TestAnchorDetectsEventAlterationsAtItsOwnSeq(t *testing.T) {
	h := newTSAHarness(t)
	roots := []*x509.Certificate{h.caCert}

	tests := []struct {
		name   string
		mutate func(t *testing.T, raw *sql.DB, anchored int64)
		want   string
	}{
		{
			name: "the anchored row's hash is edited",
			mutate: func(t *testing.T, raw *sql.DB, anchored int64) {
				if _, err := raw.Exec(`UPDATE event_log SET hash = ? WHERE seq = ?`, strings.Repeat("11", 32), anchored); err != nil {
					t.Fatal(err)
				}
			},
			want: "rewritten",
		},
		{
			name: "the anchored row is deleted",
			mutate: func(t *testing.T, raw *sql.DB, anchored int64) {
				if _, err := raw.Exec(`DELETE FROM event_log WHERE seq = ?`, anchored); err != nil {
					t.Fatal(err)
				}
			},
			want: "missing",
		},
		{
			name: "every row at or after the anchored one is deleted",
			mutate: func(t *testing.T, raw *sql.DB, anchored int64) {
				if _, err := raw.Exec(`DELETE FROM event_log WHERE seq >= ?`, anchored); err != nil {
					t.Fatal(err)
				}
			},
			want: "truncated",
		},
		{
			name: "the whole log is wiped",
			mutate: func(t *testing.T, raw *sql.DB, anchored int64) {
				if _, err := raw.Exec(`DELETE FROM event_log`); err != nil {
					t.Fatal(err)
				}
			},
			want: "truncated or replaced",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, path := anchorTestDB(t)
			appendEvents(t, db, 5)
			a := mintAnchor(t, db, h, false)
			appendEvents(t, db, 2)

			if _, checks := verifyAll(t, db, roots); len(checks) != 1 || !checks[0].Valid {
				t.Fatalf("the anchor must verify before tampering: %+v", checks)
			}
			tc.mutate(t, rawConn(t, path), a.Seq)

			_, checks := verifyAll(t, db, roots)
			if len(checks) != 1 {
				t.Fatalf("expected 1 anchor, got %d", len(checks))
			}
			if checks[0].Valid {
				t.Fatalf("the anchor must catch this: %+v", checks[0])
			}
			if !strings.Contains(checks[0].Reason, tc.want) {
				t.Fatalf("reason = %q, want it to mention %q", checks[0].Reason, tc.want)
			}
		})
	}
}

// TestAnchorSurvivesEventsInsertedAfterIt: appending events after the anchored seq
// must leave the anchor valid; the anchor only claims what the log looked like up to
// its own point.
func TestAnchorSurvivesEventsInsertedAfterIt(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	roots := []*x509.Certificate{h.caCert}
	appendEvents(t, db, 2)
	a := mintAnchor(t, db, h, false)

	for round := 0; round < 5; round++ {
		appendEvents(t, db, 3)
		chainRes, checks := verifyAll(t, db, roots)
		if !chainRes.Valid {
			t.Fatalf("round %d: chain must verify: %+v", round, chainRes)
		}
		if len(checks) != 1 || !checks[0].Valid {
			t.Fatalf("round %d: the earlier anchor must remain valid: %+v", round, checks)
		}
		if checks[0].Seq != a.Seq {
			t.Fatalf("round %d: anchored seq drifted to %d", round, checks[0].Seq)
		}
	}
}

// TestVerifyAnchorsReportShape covers the per-anchor report: ordering preserved,
// the "internal" TSA label defaulted, a structurally invalid anchor reported rather
// than skipped, and a zero `now` defaulted instead of failing every token.
func TestVerifyAnchorsReportShape(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 3)
	good := mintAnchor(t, db, h, false)
	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatal(err)
	}

	if got := VerifyAnchors(events, nil, nil, time.Now()); len(got) != 0 {
		t.Fatalf("no anchors must give no results, got %d", len(got))
	}
	// A zero `now` must default to the wall clock, not reject every token as future.
	if got := VerifyAnchors(events, []audit.Anchor{good}, nil, time.Time{}); len(got) != 1 || !got[0].Valid {
		t.Fatalf("a zero verification instant must default to now: %+v", got)
	}

	external := good
	external.ID, external.TSASource = "ext", "https://tsa.example/tsa"
	broken := audit.Anchor{ID: "broken", Seq: 0, HeadHash: "zz"}
	unsigned := audit.Anchor{ID: "unsigned", Seq: good.Seq, HeadHash: good.HeadHash, Token: []byte("nope")}

	got := VerifyAnchors(events, []audit.Anchor{good, external, broken, unsigned}, nil, time.Now())
	if len(got) != 4 {
		t.Fatalf("expected 4 results, got %d", len(got))
	}
	if got[0].ID != "ext" && got[0].ID != good.ID {
		t.Fatalf("results must keep input order: %+v", got)
	}
	if got[0].TSA != "internal" {
		t.Fatalf("an empty TSA source must render as \"internal\", got %q", got[0].TSA)
	}
	if got[1].TSA != "https://tsa.example/tsa" {
		t.Fatalf("an external source must be reported verbatim, got %q", got[1].TSA)
	}
	if !got[0].Valid || !got[1].Valid {
		t.Fatalf("both copies of a sound anchor must verify: %+v %+v", got[0], got[1])
	}
	if got[2].Valid || !strings.Contains(got[2].Reason, "invalid sequence number") {
		t.Fatalf("a seq-0 anchor must be reported invalid: %+v", got[2])
	}
	if got[3].Valid || got[3].Reason == "" {
		t.Fatalf("an unsigned token must be reported invalid with a reason: %+v", got[3])
	}
	// An anchor beyond the tail of an empty log is the extreme truncation.
	for _, c := range VerifyAnchors(nil, []audit.Anchor{good}, nil, time.Now()) {
		if c.Valid {
			t.Fatalf("no anchor may verify against an empty log: %+v", c)
		}
	}
}

// TestVerifyAnchorTokenSurvivesGarbage table-tests the untrusted-input surface:
// anchor tokens come out of a database an operator may have restored from anywhere,
// so the parser must reject, never panic.
func TestVerifyAnchorTokenSurvivesGarbage(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 2)
	a := mintAnchor(t, db, h, false)

	cases := map[string][]byte{
		"nil":                   nil,
		"empty":                 {},
		"empty SEQUENCE":        {0x30, 0x00},
		"length claims 64KiB":   {0x30, 0x82, 0xff, 0xff},
		"BER indefinite length": {0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00},
		"ASN.1 NULL":            {0x05, 0x00},
		"bare INTEGER":          {0x02, 0x01, 0x00},
		"text":                  []byte("not-a-token"),
	}
	deep := []byte{}
	for i := 0; i < 96; i++ {
		deep = append([]byte{0x30, byte(len(deep))}, deep...)
	}
	cases["deeply nested SEQUENCE"] = deep

	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			forged := a
			forged.Token = tok
			if err := VerifyAnchorToken(forged, nil, time.Now()); err == nil {
				t.Fatal("garbage must not verify")
			}
		})
	}

	// Every truncation of a real token must be rejected without panicking.
	for n := 0; n < len(a.Token); n++ {
		forged := a
		forged.Token = a.Token[:n]
		if err := VerifyAnchorToken(forged, nil, time.Now()); err == nil {
			t.Fatalf("a %d-byte prefix of the token verified", n)
		}
	}
}

// TestTokenAttestationIsImmutableUnderMutation sweeps every single-byte mutation of
// a real token. A CMS SignedData deliberately carries unsigned baggage — the
// certificate bag, the redundant digestAlgorithms copy, version numbers, NULL
// algorithm parameters — so demanding that every byte be signature-detectable would
// assert a property CMS does not provide. The property the anchor actually depends
// on is narrower and stronger: a mutated token is either REJECTED, or still attests
// exactly the same message imprint, genTime, imprint algorithm and serial number —
// so an anchor's claim can never be silently changed.
func TestTokenAttestationIsImmutableUnderMutation(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 2)
	a := mintAnchor(t, db, h, false)
	roots := []*x509.Certificate{h.caCert}
	now := time.Now()

	base, err := tsa.ParseTokenInfo(a.Token)
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}

	accepted := 0
	for i := 0; i < len(a.Token); i++ {
		forged := a
		forged.Token = flipByte(a.Token, i)
		if err := VerifyAnchorToken(forged, roots, now); err != nil {
			continue
		}
		accepted++
		got, perr := tsa.ParseTokenInfo(forged.Token)
		if perr != nil {
			t.Fatalf("offset %d: accepted a token whose TSTInfo no longer parses: %v", i, perr)
		}
		if !bytes.Equal(got.HashedMessage, base.HashedMessage) {
			t.Fatalf("offset %d: accepted a token attesting a different imprint %x", i, got.HashedMessage)
		}
		if !got.GenTime.Equal(base.GenTime) {
			t.Fatalf("offset %d: accepted a token attesting a different genTime %s", i, got.GenTime)
		}
		if got.Hash != base.Hash {
			t.Fatalf("offset %d: accepted a token claiming imprint algorithm %v", i, got.Hash)
		}
		if base.SerialNumber.Cmp(got.SerialNumber) != 0 {
			t.Fatalf("offset %d: accepted a token with serial %s", i, got.SerialNumber)
		}
	}
	if accepted == len(a.Token) {
		t.Fatal("every mutation was accepted: the token is not being verified at all")
	}
	if accepted == 0 {
		t.Log("no mutation was accepted at all")
	}

	// The regions that carry the attestation and its authenticity must be protected
	// byte for byte, both with and without trust anchors.
	parsed, err := cms.ParseSignedData(a.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatal(err)
	}
	regions := []struct {
		name string
		blob []byte
	}{
		{"message imprint", base.HashedMessage},
		{"genTime", genTimeBytesOf(t, a.Token)},
		{"TSTInfo serial number", base.SerialNumber.Bytes()},
		{"RSA signature", parsed.Signature()},
	}
	for _, r := range regions {
		at := tokenOffset(t, a.Token, r.blob)
		for i := at; i < at+len(r.blob); i++ {
			for _, rs := range [][]*x509.Certificate{nil, roots} {
				forged := a
				forged.Token = flipByte(a.Token, i)
				if err := VerifyAnchorToken(forged, rs, now); err == nil {
					t.Fatalf("flipping byte %d of the %s was accepted (roots=%d)", i, r.name, len(rs))
				}
			}
		}
	}

	// The signer certificate is in the (unsigned) certificate bag, so only the
	// certificate-path step can police it. With trust anchors supplied, every byte of
	// it must therefore be protected.
	signerRaw := parsed.SignerCertificate().Raw
	at := tokenOffset(t, a.Token, signerRaw)
	for i := at; i < at+len(signerRaw); i++ {
		forged := a
		forged.Token = flipByte(a.Token, i)
		if err := VerifyAnchorToken(forged, roots, now); err == nil {
			t.Fatalf("flipping byte %d of the signer certificate was accepted despite a trust anchor", i)
		}
	}
}

// tokenOffset locates blob inside token, failing the test when it is absent or
// ambiguous — either would make a region-targeted mutation meaningless.
func tokenOffset(t *testing.T, token, blob []byte) int {
	t.Helper()
	if len(blob) == 0 {
		t.Fatal("empty region")
	}
	at := bytes.Index(token, blob)
	if at < 0 {
		t.Fatalf("a %d-byte region is not present in the token", len(blob))
	}
	if bytes.Index(token[at+1:], blob) >= 0 {
		t.Fatalf("a %d-byte region occurs more than once in the token", len(blob))
	}
	return at
}

func imprintOf(t *testing.T, token []byte) []byte {
	t.Helper()
	info, err := tsa.ParseTokenInfo(token)
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	return info.HashedMessage
}

// genTimeBytesOf returns the GeneralizedTime bytes the token carries, which live
// inside the signed eContent.
func genTimeBytesOf(t *testing.T, token []byte) []byte {
	t.Helper()
	info, err := tsa.ParseTokenInfo(token)
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	return []byte(info.GenTime.UTC().Format("20060102150405") + "Z")
}

func signatureOf(t *testing.T, token []byte) []byte {
	t.Helper()
	parsed, err := cms.ParseSignedData(token)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	return parsed.Signature()
}

// FuzzVerifyAnchorToken drives the whole token pipeline — CMS SignedData, TSTInfo,
// the imprint comparison and the X.509 path build — over attacker-chosen bytes. It
// must never panic and must never accept an unsigned token.
func FuzzVerifyAnchorToken(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})
	f.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00})
	f.Add([]byte{0x05, 0x00})
	f.Add([]byte{0x02, 0x01, 0x00})
	f.Add([]byte("not-der-at-all"))

	f.Fuzz(func(t *testing.T, token []byte) {
		a := audit.Anchor{ID: "fuzz", Seq: 1, HeadHash: "abcdef", Token: token}
		if err := VerifyAnchorToken(a, nil, time.Unix(1<<31, 0).UTC()); err == nil {
			t.Fatalf("VerifyAnchorToken accepted a %d-byte unsigned token", len(token))
		}
		// The report path must survive the same input, including the chain check.
		for _, c := range VerifyAnchors(nil, []audit.Anchor{a}, nil, time.Time{}) {
			if c.Valid {
				t.Fatal("VerifyAnchors reported an unsigned anchor as valid")
			}
		}
	})
}

func flipByte(b []byte, i int) []byte {
	cp := append([]byte(nil), b...)
	if len(cp) == 0 {
		return cp
	}
	cp[i%len(cp)] ^= 0xff
	return cp
}
