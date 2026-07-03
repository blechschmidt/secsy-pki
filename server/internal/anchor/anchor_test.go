//go:build sqlite

package anchor

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// tsaHarness is a software-backed RFC 3161 authority: a self-signed RSA CA and
// a TSA certificate with the id-kp-timeStamping EKU. No HSM needed.
type tsaHarness struct {
	authority *tsa.Authority
	tsaCert   *x509.Certificate
	caCert    *x509.Certificate
}

func newTSAHarness(t *testing.T) *tsaHarness {
	t.Helper()
	ctx := context.Background()
	provider, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "anchor-ca", KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: "anchor-ca"})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "Anchor Test Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "anchor-tsa", KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, err := asn1.Marshal([]asn1.ObjectIdentifier{tsa.OIDExtKeyUsageTimeStamping})
	if err != nil {
		t.Fatalf("marshal EKU: %v", err)
	}
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "Anchor Test TSA"},
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
	tsaCert, err := x509.ParseCertificate(tsaDER)
	if err != nil {
		t.Fatalf("parse TSA cert: %v", err)
	}

	authority, err := tsa.New(nil, provider, tsa.Config{
		KeyLabel:    "anchor-tsa",
		Certificate: tsaCert,
		Chain:       []*x509.Certificate{tsaCert, caCert},
	})
	if err != nil {
		t.Fatalf("tsa.New: %v", err)
	}
	return &tsaHarness{authority: authority, tsaCert: tsaCert, caCert: caCert}
}

// anchorTestDB opens a file-backed SQLite store so a second raw connection can
// tamper with rows the way an attacker editing the database would.
func anchorTestDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchor.db")
	db, err := database.New("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func appendEvents(t *testing.T, db *database.DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: "e", Actor: "alice", Action: audit.ActionCertIssue, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// rawConn opens a second, direct connection to the store for tampering.
func rawConn(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	return raw
}

// verifyAll loads the full log and anchors and runs both verification layers.
func verifyAll(t *testing.T, db *database.DB, roots []*x509.Certificate) (audit.VerifyResult, []CheckResult) {
	t.Helper()
	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := db.ListAuditAnchorsAsc()
	if err != nil {
		t.Fatal(err)
	}
	return audit.VerifyFullChain(events), VerifyAnchors(events, anchors, roots, time.Now())
}

func TestAnchorMessageCanonical(t *testing.T) {
	// The canonical anchor bytes are versioned and case-insensitive on the hash;
	// a silent change here would strand every previously minted token.
	got := string(audit.AnchorMessage(42, "ABCdef"))
	want := "secsy-pki-audit-anchor-v1\nseq=42\nhead=abcdef\n"
	if got != want {
		t.Fatalf("AnchorMessage = %q, want %q", got, want)
	}
	if len(audit.AnchorDigest(42, "abcdef")) != 32 {
		t.Fatal("AnchorDigest must be SHA-256 (32 bytes)")
	}
}

// TestAnchorOnceHappyPath anchors a live head against the software TSA and
// verifies the full picture: anchor persisted with a verifiable token, the
// audit.anchor event appended, idle re-runs skipped, and -force overriding.
func TestAnchorOnceHappyPath(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 5)

	svc := NewService(db, NewAuthorityTimestamper(h.authority))
	res, err := svc.AnchorOnce(context.Background(), false)
	if err != nil {
		t.Fatalf("AnchorOnce: %v", err)
	}
	if res.Skipped || res.Anchor == nil {
		t.Fatalf("expected an anchor, got %+v", res)
	}
	if res.Anchor.Seq != 5 {
		t.Fatalf("anchored seq = %d, want 5", res.Anchor.Seq)
	}
	if res.Anchor.TSASource != "" {
		t.Fatalf("internal TSA source should be empty, got %q", res.Anchor.TSASource)
	}

	// The anchor's own audit record is the new head.
	seq, _, action, err := db.EventLogHead()
	if err != nil {
		t.Fatal(err)
	}
	if seq != 6 || action != audit.ActionAuditAnchor {
		t.Fatalf("head = (%d, %s), want (6, audit.anchor)", seq, action)
	}

	// Chain and anchors verify, including the TSA chain to the test root.
	chainRes, checks := verifyAll(t, db, []*x509.Certificate{h.caCert})
	if !chainRes.Valid {
		t.Fatalf("chain should verify: %+v", chainRes)
	}
	if len(checks) != 1 || !checks[0].Valid {
		t.Fatalf("anchor should verify: %+v", checks)
	}

	// An idle log is not re-anchored (the only new event is the anchor record)…
	res2, err := svc.AnchorOnce(context.Background(), false)
	if err != nil {
		t.Fatalf("second AnchorOnce: %v", err)
	}
	if !res2.Skipped {
		t.Fatalf("idle log should skip, got %+v", res2)
	}
	// …unless forced.
	res3, err := svc.AnchorOnce(context.Background(), true)
	if err != nil {
		t.Fatalf("forced AnchorOnce: %v", err)
	}
	if res3.Skipped || res3.Anchor.Seq != 6 {
		t.Fatalf("forced anchor should cover seq 6, got %+v", res3)
	}

	// New activity re-arms anchoring without force.
	appendEvents(t, db, 1)
	res4, err := svc.AnchorOnce(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if res4.Skipped {
		t.Fatalf("new events must be anchored, got skip: %s", res4.Reason)
	}
}

// TestVerifyDetectsWholeChainRewrite is the attack the hash chain alone cannot
// catch: the attacker edits an event and re-seals every later entry, leaving an
// internally consistent chain. The anchored head hash no longer matches, so
// anchor verification fails while plain chain verification passes.
func TestVerifyDetectsWholeChainRewrite(t *testing.T) {
	h := newTSAHarness(t)
	db, path := anchorTestDB(t)
	appendEvents(t, db, 5)

	svc := NewService(db, NewAuthorityTimestamper(h.authority))
	if _, err := svc.AnchorOnce(context.Background(), false); err != nil {
		t.Fatal(err)
	}

	// Rewrite history: change event 3's detail and recompute the chain from
	// there to the tail, exactly as an attacker with store access would.
	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatal(err)
	}
	events[2].Detail = "laundered"
	raw := rawConn(t, path)
	prev := events[1].Hash
	for i := 2; i < len(events); i++ {
		e := &events[i]
		e.PrevHash = prev
		e.Hash = audit.ComputeHash(e, prev)
		if _, err := raw.Exec(`UPDATE event_log SET detail = ?, prev_hash = ?, hash = ? WHERE seq = ?`,
			e.Detail, e.PrevHash, e.Hash, e.Seq); err != nil {
			t.Fatal(err)
		}
		prev = e.Hash
	}

	chainRes, checks := verifyAll(t, db, []*x509.Certificate{h.caCert})
	if !chainRes.Valid {
		t.Fatalf("re-sealed chain must pass plain verification (that is the point): %+v", chainRes)
	}
	if len(checks) != 1 || checks[0].Valid {
		t.Fatalf("anchor must catch the rewrite: %+v", checks)
	}
	if !strings.Contains(checks[0].Reason, "rewritten") {
		t.Errorf("reason should name the rewrite: %q", checks[0].Reason)
	}
}

// TestVerifyDetectsTruncation drops the newest events behind an anchor point.
// The remaining prefix is a perfectly valid chain; only the anchor proves the
// log used to extend further.
func TestVerifyDetectsTruncation(t *testing.T) {
	h := newTSAHarness(t)
	db, path := anchorTestDB(t)
	svc := NewService(db, NewAuthorityTimestamper(h.authority))

	appendEvents(t, db, 3)
	if _, err := svc.AnchorOnce(context.Background(), false); err != nil { // covers seq 3, event 4
		t.Fatal(err)
	}
	appendEvents(t, db, 2)                                                 // seq 5, 6
	if _, err := svc.AnchorOnce(context.Background(), false); err != nil { // covers seq 6, event 7
		t.Fatal(err)
	}

	// Truncate the log back to seq 4 (keeping the first anchor's coverage).
	raw := rawConn(t, path)
	if _, err := raw.Exec(`DELETE FROM event_log WHERE seq > 4`); err != nil {
		t.Fatal(err)
	}

	chainRes, checks := verifyAll(t, db, []*x509.Certificate{h.caCert})
	if !chainRes.Valid {
		t.Fatalf("truncated prefix must still pass plain verification (that is the point): %+v", chainRes)
	}
	if len(checks) != 2 {
		t.Fatalf("expected 2 anchors, got %d", len(checks))
	}
	if !checks[0].Valid {
		t.Fatalf("first anchor (seq 3) should still verify: %+v", checks[0])
	}
	if checks[1].Valid {
		t.Fatalf("second anchor (seq 6) must catch the truncation: %+v", checks[1])
	}
	if !strings.Contains(checks[1].Reason, "truncated") {
		t.Errorf("reason should name the truncation: %q", checks[1].Reason)
	}

	// Wiping the whole log is the extreme truncation.
	if _, err := raw.Exec(`DELETE FROM event_log`); err != nil {
		t.Fatal(err)
	}
	_, checks = verifyAll(t, db, nil)
	for _, c := range checks {
		if c.Valid {
			t.Fatalf("no anchor may verify against an emptied log: %+v", c)
		}
	}
}

// TestVerifyDetectsTokenTamper corrupts the stored evidence itself: a modified
// anchor row (head hash) no longer matches its token's imprint, and a modified
// token fails CMS signature verification.
func TestVerifyDetectsTokenTamper(t *testing.T) {
	h := newTSAHarness(t)
	db, path := anchorTestDB(t)
	appendEvents(t, db, 4)
	svc := NewService(db, NewAuthorityTimestamper(h.authority))
	if _, err := svc.AnchorOnce(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	anchors, err := db.ListAuditAnchorsAsc()
	if err != nil {
		t.Fatal(err)
	}
	a := anchors[0]

	// Re-pointing the anchor at a different (attacker-chosen) head hash breaks
	// the token imprint linkage: the token only ever covers the head it was
	// minted for.
	forged := a
	forged.HeadHash = strings.Repeat("ab", 32)
	if err := VerifyAnchorToken(forged, nil, time.Now()); err == nil {
		t.Fatal("token must not cover a forged head hash")
	}

	// Bit-flip the stored token: the CMS signature (or parse) must fail.
	raw := rawConn(t, path)
	tampered := append([]byte(nil), a.Token...)
	tampered[len(tampered)-10] ^= 0xff
	if _, err := raw.Exec(`UPDATE audit_anchors SET token = ? WHERE id = ?`, tampered, a.ID); err != nil {
		t.Fatal(err)
	}
	_, checks := verifyAll(t, db, nil)
	if len(checks) != 1 || checks[0].Valid {
		t.Fatalf("tampered token must fail verification: %+v", checks)
	}
}

// TestHTTPTimestamper drives the external-TSA path against an httptest server
// speaking the RFC 3161 HTTP transport, and confirms the anchor records its
// external source.
func TestHTTPTimestamper(t *testing.T) {
	h := newTSAHarness(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/timestamp-query" {
			http.Error(w, "content type "+ct, http.StatusUnsupportedMediaType)
			return
		}
		res, err := h.authority.Stamp(r.Context(), body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(res.Response)
	}))
	defer srv.Close()

	db, _ := anchorTestDB(t)
	appendEvents(t, db, 2)

	svc := NewService(db, NewHTTPTimestamper(srv.URL, 5*time.Second))
	res, err := svc.AnchorOnce(context.Background(), false)
	if err != nil {
		t.Fatalf("AnchorOnce over HTTP: %v", err)
	}
	if res.Skipped || res.Anchor.TSASource != srv.URL {
		t.Fatalf("anchor should record the external TSA URL, got %+v", res)
	}
	_, checks := verifyAll(t, db, []*x509.Certificate{h.caCert})
	if len(checks) != 1 || !checks[0].Valid {
		t.Fatalf("external-TSA anchor should verify: %+v", checks)
	}

	// A rejecting TSA surfaces as an error and an audit.anchor error event.
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	defer badSrv.Close()
	appendEvents(t, db, 1)
	svcBad := NewService(db, NewHTTPTimestamper(badSrv.URL, 2*time.Second))
	if _, err := svcBad.AnchorOnce(context.Background(), false); err == nil {
		t.Fatal("a failing TSA must surface as an error")
	}
	seq, _, action, err := db.EventLogHead()
	if err != nil {
		t.Fatal(err)
	}
	if action != audit.ActionAuditAnchor {
		t.Fatalf("failure must append an audit.anchor event, head is (%d, %s)", seq, action)
	}
}

// TestAnchorEmptyLogSkips: with nothing to attest, anchoring is a no-op rather
// than an error.
func TestAnchorEmptyLogSkips(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	svc := NewService(db, NewAuthorityTimestamper(h.authority))
	res, err := svc.AnchorOnce(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped {
		t.Fatalf("empty log must skip, got %+v", res)
	}
}
