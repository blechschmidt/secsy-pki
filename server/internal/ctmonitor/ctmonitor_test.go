//go:build sqlite

package ctmonitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/cryptobyte"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/ct"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
)

// --- reference RFC 6962 Merkle tree the fake log uses to serve correct proofs --

func leafHashOf(input []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(input)
	return h.Sum(nil)
}

func nodeHashOf(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func pow2Below(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func merkleRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leaves[0]
	}
	k := pow2Below(len(leaves))
	return nodeHashOf(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
}

func merkleAuditPath(m int, leaves [][]byte) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := pow2Below(len(leaves))
	if m < k {
		return append(merkleAuditPath(m, leaves[:k]), merkleRoot(leaves[k:]))
	}
	return append(merkleAuditPath(m-k, leaves[k:]), merkleRoot(leaves[:k]))
}

// --- fake RFC 6962 CT log: add-pre-chain, get-sth, get-proof-by-hash ----------

type fakeLog struct {
	key         *ecdsa.PrivateKey
	issuer      *x509.Certificate
	timestampMS uint64
	honest      bool // when false, add-pre-chain issues an SCT but never merges the leaf

	mu   sync.Mutex
	tree [][]byte // leaf hashes, in insertion order
}

func newFakeLog(t *testing.T, issuer *x509.Certificate, timestampMS uint64, honest bool) *fakeLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeLog{key: key, issuer: issuer, timestampMS: timestampMS, honest: honest}
}

func (f *fakeLog) logID() [32]byte {
	spki, _ := x509.MarshalPKIXPublicKey(f.key.Public())
	return sha256.Sum256(spki)
}

func (f *fakeLog) publicKeyPEM(t *testing.T) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
}

// addFiller appends n unrelated leaves so audit paths have real depth.
func (f *fakeLog) addFiller(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < n; i++ {
		f.tree = append(f.tree, leafHashOf([]byte(fmt.Sprintf("filler-%d-%d", len(f.tree), i))))
	}
}

func (f *fakeLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/ct/v1/add-pre-chain":
		f.serveAddPreChain(w, r)
	case r.URL.Path == "/ct/v1/get-sth":
		f.serveGetSTH(w, r)
	case r.URL.Path == "/ct/v1/get-proof-by-hash":
		f.serveGetProof(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *fakeLog) serveAddPreChain(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Chain []string `json:"chain"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.Chain) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	precertDER, err := base64.StdEncoding.DecodeString(req.Chain[0])
	if err != nil {
		http.Error(w, "bad precert", http.StatusBadRequest)
		return
	}
	tbs, err := ct.TBSWithoutExtension(precertDER, ct.OIDPoison)
	if err != nil {
		http.Error(w, "cannot parse precert", http.StatusBadRequest)
		return
	}
	ikh := sha256.Sum256(f.issuer.RawSubjectPublicKeyInfo)

	var b cryptobyte.Builder
	b.AddUint8(0)
	b.AddUint8(0)
	b.AddUint64(f.timestampMS)
	b.AddUint16(1)
	b.AddBytes(ikh[:])
	b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {})
	input, _ := b.Bytes()

	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	var sb cryptobyte.Builder
	sb.AddUint8(4) // sha256
	sb.AddUint8(3) // ecdsa
	sb.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sig) })
	ds, _ := sb.Bytes()

	// Merge the entry into the tree — unless this log is misbehaving.
	if f.honest {
		f.mu.Lock()
		f.tree = append(f.tree, leafHashOf(input))
		f.mu.Unlock()
	}

	id := f.logID()
	resp := map[string]interface{}{
		"sct_version": 0,
		"id":          base64.StdEncoding.EncodeToString(id[:]),
		"timestamp":   f.timestampMS,
		"signature":   base64.StdEncoding.EncodeToString(ds),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeLog) serveGetSTH(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	tree := append([][]byte(nil), f.tree...)
	f.mu.Unlock()

	var root [32]byte
	copy(root[:], merkleRoot(tree))
	ts := f.timestampMS + 1

	var b cryptobyte.Builder
	b.AddUint8(0) // version v1
	b.AddUint8(1) // tree_hash
	b.AddUint64(ts)
	b.AddUint64(uint64(len(tree)))
	b.AddBytes(root[:])
	input, _ := b.Bytes()
	digest := sha256.Sum256(input)
	sig, _ := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	var sb cryptobyte.Builder
	sb.AddUint8(4)
	sb.AddUint8(3)
	sb.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sig) })
	ds, _ := sb.Bytes()

	resp := map[string]interface{}{
		"tree_size":           len(tree),
		"timestamp":           ts,
		"sha256_root_hash":    base64.StdEncoding.EncodeToString(root[:]),
		"tree_head_signature": base64.StdEncoding.EncodeToString(ds),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeLog) serveGetProof(w http.ResponseWriter, r *http.Request) {
	hashB64 := r.URL.Query().Get("hash")
	target, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		http.Error(w, "bad hash", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	tree := append([][]byte(nil), f.tree...)
	f.mu.Unlock()

	idx := -1
	for i, h := range tree {
		if string(h) == string(target) {
			idx = i
			break
		}
	}
	if idx < 0 {
		http.Error(w, "leaf not found", http.StatusNotFound)
		return
	}
	path := merkleAuditPath(idx, tree)
	encoded := make([]string, len(path))
	for i, p := range path {
		encoded[i] = base64.StdEncoding.EncodeToString(p)
	}
	resp := map[string]interface{}{"leaf_index": idx, "audit_path": encoded}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// --- issuance helpers ---------------------------------------------------------

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CT Monitor Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(72 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// buildLeaf builds a leaf under the CA carrying the given trailing extension.
// The validity window is passed in (not read from the clock) so a precertificate
// and its final certificate — built in two calls — are byte-identical apart from
// the poison↔SCT-list extension, the invariant the embedded SCTs rely on.
func buildLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, leafPub interface{}, serial *big.Int, nb, na time.Time, extra pkix.Extension) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:        []string{"leaf.example.com"},
		NotBefore:       nb,
		NotAfter:        na,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{extra},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// issueWithSCT builds a precertificate, submits it to the named log to get an
// SCT, and returns the final certificate (SCT embedded) as PEM plus the SCT count.
func issueWithSCT(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, sub *ct.Submitter, logName string, serial int64) (string, int) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sn := big.NewInt(serial)
	nb := time.Now().Add(-time.Hour).Truncate(time.Second)
	na := nb.Add(48 * time.Hour)
	precertDER := buildLeaf(t, caCert, caKey, leafKey.Public(), sn, nb, na, ct.PoisonExtension())
	res, err := sub.Submit(context.Background(), ct.SubmitRequest{
		Logs: []string{logName}, PrecertDER: precertDER, Issuer: caCert,
		IssuerChainDER: [][]byte{caCert.Raw}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("submit to %s: %v", logName, err)
	}
	if len(res.SCTs) != 1 {
		t.Fatalf("submit to %s produced %d SCTs, want 1 (%+v)", logName, len(res.SCTs), res.Results)
	}
	ext, err := ct.SCTListExtension(res.SCTs)
	if err != nil {
		t.Fatal(err)
	}
	finalDER := buildLeaf(t, caCert, caKey, leafKey.Public(), sn, nb, na, ext)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: finalDER})), len(res.SCTs)
}

// leafHashFromFinal computes the RFC 6962 Merkle leaf hash a log stores for the
// certificate — derived from the final certificate exactly as the monitor does —
// so a test can inject the entry into the fake log's tree to simulate a merge.
func leafHashFromFinal(t *testing.T, caCert *x509.Certificate, finalPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(finalPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var sctExtValue []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(ct.OIDSCTList) {
			sctExtValue = e.Value
		}
	}
	scts, err := ct.ParseSCTListExtension(sctExtValue)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := ct.TBSWithoutExtension(leaf.Raw, ct.OIDSCTList)
	if err != nil {
		t.Fatal(err)
	}
	lh, err := ct.PrecertLeafHash(scts[0], caCert, tbs)
	if err != nil {
		t.Fatal(err)
	}
	return lh[:]
}

// syntheticSCTCert builds a final certificate carrying an SCT from a log id that
// is not in any registry, for the unknown-log path.
func syntheticSCTCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, tsMS uint64) string {
	t.Helper()
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	sct := &ct.SCT{Version: 0, LogID: id, Timestamp: tsMS, Signature: []byte{4, 3, 0, 0}}
	ext, err := ct.SCTListExtension([]*ct.SCT{sct})
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nb := time.Now().Add(-time.Hour).Truncate(time.Second)
	der := buildLeaf(t, caCert, caKey, leafKey.Public(), big.NewInt(serial), nb, nb.Add(48*time.Hour), ext)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// --- test notifier ------------------------------------------------------------

type captureNotifier struct {
	mu     sync.Mutex
	events []monitor.CTMisbehavior
}

func (c *captureNotifier) NotifyCTMisbehavior(_ context.Context, events []monitor.CTMisbehavior) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, events...)
}

func (c *captureNotifier) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// --- the test -----------------------------------------------------------------

func storeCert(t *testing.T, db *database.DB, caID string, serial int64, pemStr string, sctCount int) {
	t.Helper()
	if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID:          uuid.New().String(),
		CAID:        caID,
		Serial:      fmt.Sprintf("%d", serial),
		Subject:     "CN=leaf.example.com",
		CommonName:  "leaf.example.com",
		Profile:     "tls",
		Certificate: pemStr,
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(48 * time.Hour),
		Status:      models.CertStatusValid,
		CTStatus:    models.CTStatusSubmitted,
		SCTCount:    sctCount,
	}); err != nil {
		t.Fatalf("RecordIssuedCertificate: %v", err)
	}
}

func TestMonitorInclusion(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "ctmon.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	caCert, caKey := testCA(t)
	caID := "ca1"
	if err := db.CreateCA(&models.CA{
		ID: caID, TenantID: models.DefaultTenantID, Label: "issuing", PKCS11URI: "pkcs11:token=ca1",
		KeyType: "ecdsa", PublicKey: "x",
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	oldTS := uint64(time.Now().Add(-48 * time.Hour).UnixMilli()) // past MMD (24h default)
	recentTS := uint64(time.Now().UnixMilli())                   // MMD not yet elapsed

	// Honest log that merges entries; misbehaving log that never does; a fresh
	// honest log whose MMD has not elapsed.
	honest := newFakeLog(t, caCert, oldTS, true)
	honest.addFiller(2)
	bad := newFakeLog(t, caCert, oldTS, false)
	bad.addFiller(3)
	fresh := newFakeLog(t, caCert, recentTS, true)

	srvHonest := httptest.NewServer(honest)
	defer srvHonest.Close()
	srvBad := httptest.NewServer(bad)
	defer srvBad.Close()
	srvFresh := httptest.NewServer(fresh)
	defer srvFresh.Close()

	sub, err := ct.NewSubmitter([]ct.LogConfig{
		{Name: "honest", URL: srvHonest.URL, PublicKeyPEM: honest.publicKeyPEM(t)},
		{Name: "bad", URL: srvBad.URL, PublicKeyPEM: bad.publicKeyPEM(t)},
		{Name: "fresh", URL: srvFresh.URL, PublicKeyPEM: fresh.publicKeyPEM(t)},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}

	// Issue one certificate per scenario.
	includedPEM, n1 := issueWithSCT(t, caCert, caKey, sub, "honest", 1001)
	honest.addFiller(1) // grow the tree so the audit path is non-trivial
	failedPEM, n2 := issueWithSCT(t, caCert, caKey, sub, "bad", 1002)
	pendingPEM, n3 := issueWithSCT(t, caCert, caKey, sub, "fresh", 1003)
	unknownPEM := syntheticSCTCert(t, caCert, caKey, 1004, oldTS)

	storeCert(t, db, caID, 1001, includedPEM, n1)
	storeCert(t, db, caID, 1002, failedPEM, n2)
	storeCert(t, db, caID, 1003, pendingPEM, n3)
	storeCert(t, db, caID, 1004, unknownPEM, 1)

	notifier := &captureNotifier{}
	cfg := config.CTInclusionMonitorConfig{Enabled: true}
	m, err := New(db, sub, cfg, notifier, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New monitor: %v", err)
	}

	res := m.RunOnce(context.Background())
	if res.Err != nil {
		t.Fatalf("scan error: %v", res.Err)
	}
	if res.Included != 1 || res.Failed != 1 || res.Pending != 1 || res.UnknownLog != 1 {
		t.Fatalf("unexpected scan tallies: included=%d failed=%d pending=%d unknown=%d (checked=%d certs=%d)",
			res.Included, res.Failed, res.Pending, res.UnknownLog, res.Checked, res.Certs)
	}
	if res.NewMisbehavior != 1 {
		t.Fatalf("NewMisbehavior = %d, want 1", res.NewMisbehavior)
	}
	if notifier.count() != 1 {
		t.Fatalf("notifier received %d misbehavior events, want 1", notifier.count())
	}

	assertStatus := func(serial int64, logID [32]byte, want string) {
		t.Helper()
		rec, err := db.GetSCTInclusion(caID, fmt.Sprintf("%d", serial), fmt.Sprintf("%x", logID))
		if err != nil || rec == nil {
			t.Fatalf("GetSCTInclusion(%d): %v (rec=%v)", serial, err, rec)
		}
		if rec.Status != want {
			t.Fatalf("cert %d: status = %q, want %q (last_error=%q)", serial, rec.Status, want, rec.LastError)
		}
	}
	assertStatus(1001, honest.logID(), models.SCTInclusionIncluded)
	assertStatus(1002, bad.logID(), models.SCTInclusionFailed)
	assertStatus(1003, fresh.logID(), models.SCTInclusionPending)

	// The included proof recorded a tree size and leaf index.
	inc, _ := db.GetSCTInclusion(caID, "1001", fmt.Sprintf("%x", honest.logID()))
	if inc.TreeSize == 0 || inc.IncludedAt == nil {
		t.Fatalf("included record missing proof metadata: %+v", inc)
	}

	// A second scan must not re-alert the standing failure (alert-once), and the
	// included/pending states are unchanged.
	res2 := m.RunOnce(context.Background())
	if res2.NewMisbehavior != 0 {
		t.Fatalf("second scan re-alerted: NewMisbehavior=%d", res2.NewMisbehavior)
	}
	if notifier.count() != 1 {
		t.Fatalf("second scan produced extra alerts: total=%d, want 1", notifier.count())
	}
	// The failed cert is still re-examined (its SCT is not 'included'); the
	// already-included cert has dropped out of the pending-inclusion scan.
	if res2.Failed != 1 {
		t.Fatalf("second scan: failed=%d, want 1", res2.Failed)
	}
	if res2.Included != 0 {
		t.Fatalf("second scan: included=%d, want 0 (the included cert is no longer pending)", res2.Included)
	}

	// The scan recorded a ct.inclusion audit event.
	events, _, err := db.ListEvents(audit.ActionCTInclusion, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("expected >=2 ct.inclusion audit events, got %d", len(events))
	}
}

// TestMonitorRecoversLateInclusion confirms a log that merges an entry after an
// earlier miss flips the SCT from failed back to included on a later scan.
func TestMonitorRecoversLateInclusion(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "ctmon-recover.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	caCert, caKey := testCA(t)
	caID := "ca1"
	if err := db.CreateCA(&models.CA{
		ID: caID, TenantID: models.DefaultTenantID, Label: "issuing", PKCS11URI: "pkcs11:token=ca1",
		KeyType: "ecdsa", PublicKey: "x",
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	oldTS := uint64(time.Now().Add(-48 * time.Hour).UnixMilli())
	slow := newFakeLog(t, caCert, oldTS, false) // starts out not merging
	slow.addFiller(2)
	srv := httptest.NewServer(slow)
	defer srv.Close()

	sub, err := ct.NewSubmitter([]ct.LogConfig{
		{Name: "slow", URL: srv.URL, PublicKeyPEM: slow.publicKeyPEM(t)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pemStr, n := issueWithSCT(t, caCert, caKey, sub, "slow", 2001)
	storeCert(t, db, caID, 2001, pemStr, n)

	m, err := New(db, sub, config.CTInclusionMonitorConfig{Enabled: true}, &captureNotifier{}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}

	// First scan: not merged → failed.
	m.RunOnce(context.Background())
	rec, _ := db.GetSCTInclusion(caID, "2001", fmt.Sprintf("%x", slow.logID()))
	if rec == nil || rec.Status != models.SCTInclusionFailed {
		t.Fatalf("first scan: status = %v, want failed", rec)
	}

	// The log finally merges the entry: inject the certificate's leaf hash.
	slow.mu.Lock()
	slow.tree = append(slow.tree, leafHashFromFinal(t, caCert, pemStr))
	slow.mu.Unlock()

	// Second scan: now included.
	m.RunOnce(context.Background())
	rec, _ = db.GetSCTInclusion(caID, "2001", fmt.Sprintf("%x", slow.logID()))
	if rec == nil || rec.Status != models.SCTInclusionIncluded {
		t.Fatalf("second scan: status = %v, want included (err=%q)", rec.Status, rec.LastError)
	}
}
