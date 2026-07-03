//go:build sqlite

package ca

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// gatedProvider wraps a real provider with a switch simulating an HSM outage:
// while down, every operation that would reach the token fails. Cached
// pre-signed material must keep the responder serving through it.
type gatedProvider struct {
	keyprovider.Provider
	mu   sync.Mutex
	down bool
}

func (g *gatedProvider) setDown(down bool) {
	g.mu.Lock()
	g.down = down
	g.mu.Unlock()
}

func (g *gatedProvider) check() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.down {
		return fmt.Errorf("simulated HSM outage: token unavailable")
	}
	return nil
}

func (g *gatedProvider) Signer(ctx context.Context, ref keyprovider.KeyRef) (keyprovider.Signer, error) {
	if err := g.check(); err != nil {
		return nil, err
	}
	return g.Provider.Signer(ctx, ref)
}

func (g *gatedProvider) FindKey(ctx context.Context, ref keyprovider.KeyRef) (*keyprovider.KeyInfo, error) {
	if err := g.check(); err != nil {
		return nil, err
	}
	return g.Provider.FindKey(ctx, ref)
}

func (g *gatedProvider) GenerateKey(ctx context.Context, spec keyprovider.KeySpec) (*keyprovider.KeyInfo, error) {
	if err := g.check(); err != nil {
		return nil, err
	}
	return g.Provider.GenerateKey(ctx, spec)
}

// TestOCSPPresignBatch pre-signs a CA's full serial population (good, revoked,
// and a recently queried unknown serial) and verifies every response parses,
// is signed by the CA, attests the right status, and lands in the cache with
// its own NextUpdate as expiry.
func TestOCSPPresignBatch(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runPresignBatch(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runPresignBatch(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, "presign-"+tag)
	rootCert := mustParse(t, root.Certificate)

	good := issueLeaf(t, mgr, root.ID, "good.example.com")
	revoked := issueLeaf(t, mgr, root.ID, "revoked.example.com")
	if _, err := mgr.RevokeCertificate(ctx, root.ID, revoked.Serial.String(), "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	cache := NewOCSPCache(time.Hour)
	recent := NewRecentSerialTracker(16)
	recent.Record(root.ID, "424242424242") // queried but unknown to the store

	validity := 6 * time.Hour
	p := NewOCSPPresigner(mgr, OCSPPresignerConfig{
		Validity: validity,
		Cache:    cache,
		Recent:   recent,
	})

	stats, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// good + revoked + the recent unknown serial. (The root's own certificate is
	// not in the issued table; only leaves are.)
	if stats.Signed != 3 {
		t.Fatalf("stats.Signed = %d, want 3", stats.Signed)
	}
	if stats.CAs != 1 {
		t.Fatalf("stats.CAs = %d, want 1", stats.CAs)
	}

	wantStatus := map[string]int{
		good.Serial.String():    pki.OCSPGood,
		revoked.Serial.String(): pki.OCSPRevoked,
		"424242424242":          pki.OCSPUnknown,
	}
	latest := p.Latest(root.ID)
	if len(latest) != len(wantStatus) {
		t.Fatalf("Latest returned %d responses, want %d", len(latest), len(wantStatus))
	}
	now := time.Now()
	for _, r := range latest {
		want, ok := wantStatus[r.Serial]
		if !ok {
			t.Fatalf("unexpected pre-signed serial %s", r.Serial)
		}
		if r.Status != want {
			t.Errorf("serial %s: status = %d, want %d", r.Serial, r.Status, want)
		}
		// The response must be a valid, CA-signed OCSP response.
		parsed, err := ocsp.ParseResponse(r.DER, rootCert)
		if err != nil {
			t.Fatalf("serial %s: ParseResponse: %v", r.Serial, err)
		}
		if parsed.Status != want {
			t.Errorf("serial %s: parsed status = %d, want %d", r.Serial, parsed.Status, want)
		}
		if parsed.SerialNumber.String() != r.Serial {
			t.Errorf("serial %s: response is for %s", r.Serial, parsed.SerialNumber)
		}
		if got := parsed.NextUpdate.Sub(now); got < validity-15*time.Minute || got > validity+15*time.Minute {
			t.Errorf("serial %s: NextUpdate %s from now, want ~%s", r.Serial, got, validity)
		}
		// And it must be servable from the shared cache.
		cached, hit := cache.Get(root.ID, r.Serial)
		if !hit {
			t.Fatalf("serial %s: not in cache", r.Serial)
		}
		if string(cached) != string(r.DER) {
			t.Errorf("serial %s: cache holds different bytes", r.Serial)
		}
	}
	if n := cache.PresignedCount(); n != len(wantStatus) {
		t.Errorf("PresignedCount = %d, want %d", n, len(wantStatus))
	}
	if parsed, err := ocsp.ParseResponse(mustCacheGet(t, cache, root.ID, revoked.Serial.String()), rootCert); err != nil {
		t.Fatalf("revoked response: %v", err)
	} else if parsed.RevocationReason != ocsp.KeyCompromise {
		t.Errorf("revocation reason = %d, want KeyCompromise", parsed.RevocationReason)
	}
}

func mustCacheGet(t *testing.T, c *OCSPCache, caID, serial string) []byte {
	t.Helper()
	der, ok := c.Get(caID, serial)
	if !ok {
		t.Fatalf("cache miss for %s", serial)
	}
	return der
}

// TestOCSPPresignDelegated verifies pre-signed responses can be produced under
// the delegated OCSP-signing certificate, embedding it for path building —
// matching what the online responder serves.
func TestOCSPPresignDelegated(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "presign-delegated")
	rootCert := mustParse(t, root.Certificate)
	leaf := issueLeaf(t, mgr, root.ID, "delegated.example.com")

	p := NewOCSPPresigner(mgr, OCSPPresignerConfig{
		Validity:  time.Hour,
		Delegated: NewDelegatedResponderCache(0, ""),
	})
	responses, err := p.PresignCA(ctx, root.ID)
	if err != nil {
		t.Fatalf("PresignCA: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("got %d responses, want 1", len(responses))
	}
	parsed, err := ocsp.ParseResponse(responses[0].DER, rootCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if parsed.Certificate == nil {
		t.Fatal("delegated response embeds no responder certificate")
	}
	if err := parsed.Certificate.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("responder certificate not signed by CA: %v", err)
	}
	if parsed.SerialNumber.String() != leaf.Serial.String() {
		t.Errorf("response serial = %s, want %s", parsed.SerialNumber, leaf.Serial)
	}
}

// TestOCSPPresignSurvivesHSMOutage is the headline DR property: pre-signed
// responses keep being served from the cache — still verifying against the CA
// — while the HSM is entirely unavailable, and fresh signing resumes when it
// returns. Runs against SoftHSM (skipped if unconfigured) and the software
// provider.
func TestOCSPPresignSurvivesHSMOutage(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runPresignOutage(t, &gatedProvider{Provider: mk(t)}, name)
		})
	}
}

func runPresignOutage(t *testing.T, gated *gatedProvider, tag string) {
	ctx := context.Background()
	mgr := newTestManager(t, gated)
	root := newRoot(t, mgr, "presign-outage-"+tag)
	rootCert := mustParse(t, root.Certificate)
	leaf := issueLeaf(t, mgr, root.ID, "outage.example.com")

	cache := NewOCSPCache(time.Hour)
	p := NewOCSPPresigner(mgr, OCSPPresignerConfig{Validity: 2 * time.Hour, Cache: cache})
	if _, err := p.Run(ctx); err != nil {
		t.Fatalf("initial presign: %v", err)
	}

	// The HSM goes away.
	gated.setDown(true)

	// Fresh signing must fail — proving the outage is real...
	reqDER, err := pki.BuildOCSPRequest(leaf.Certificate, rootCert)
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}
	if _, err := mgr.OCSPRespondWithOptions(ctx, root.ID, reqDER, OCSPRespondOptions{}); err == nil {
		t.Fatal("fresh OCSP signing unexpectedly succeeded during the simulated outage")
	}
	if _, err := p.Run(ctx); err == nil {
		t.Fatal("presign batch unexpectedly succeeded during the simulated outage")
	}

	// ...while the pre-signed response keeps being served and keeps verifying.
	der, ok := cache.Get(root.ID, leaf.Serial.String())
	if !ok {
		t.Fatal("pre-signed response missing from cache during outage")
	}
	parsed, err := ocsp.ParseResponse(der, rootCert)
	if err != nil {
		t.Fatalf("cached response no longer parses/verifies: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("cached status = %d, want good", parsed.Status)
	}
	if !parsed.NextUpdate.After(time.Now()) {
		t.Error("cached response is expired; it must remain valid across the outage window")
	}

	// HSM comes back: fresh signing and a new batch succeed again.
	gated.setDown(false)
	if _, err := mgr.OCSPRespondWithOptions(ctx, root.ID, reqDER, OCSPRespondOptions{}); err != nil {
		t.Fatalf("fresh signing after recovery: %v", err)
	}
	if _, err := p.Run(ctx); err != nil {
		t.Fatalf("presign after recovery: %v", err)
	}
}

// TestOCSPPresignSkipsExpiredLeaves verifies the expired-grace window: a serial
// stays in the pre-signed set through the grace period after its NotAfter and
// drops out beyond it. The presigner clock is advanced rather than the stored
// certificate rewritten.
func TestOCSPPresignSkipsExpiredLeaves(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "presign-expiry")
	leaf := issueLeaf(t, mgr, root.ID, "short.example.com")
	notAfter := leaf.Certificate.NotAfter

	p := NewOCSPPresigner(mgr, OCSPPresignerConfig{Validity: time.Hour, ExpiredGrace: 24 * time.Hour})

	// Just inside the grace window: still pre-signed.
	fake := notAfter.Add(23 * time.Hour)
	p.now = func() time.Time { return fake }
	responses, err := p.PresignCA(ctx, root.ID)
	if err != nil {
		t.Fatalf("PresignCA (within grace): %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("recently expired leaf not pre-signed within grace: %d responses", len(responses))
	}

	// Beyond the grace window: dropped from the batch.
	fake = notAfter.Add(25 * time.Hour)
	responses, err = p.PresignCA(ctx, root.ID)
	if err != nil {
		t.Fatalf("PresignCA (beyond grace): %v", err)
	}
	if len(responses) != 0 {
		t.Fatalf("expired leaf still pre-signed beyond grace: %d responses", len(responses))
	}
}

// TestRecentSerialTracker covers the LRU bound and the recency window.
func TestRecentSerialTracker(t *testing.T) {
	tr := NewRecentSerialTracker(3)
	base := time.Now()
	now := base
	tr.now = func() time.Time { return now }

	tr.Record("ca1", "1")
	now = now.Add(time.Minute)
	tr.Record("ca1", "2")
	now = now.Add(time.Minute)
	tr.Record("ca2", "9")
	now = now.Add(time.Minute)
	tr.Record("ca1", "3") // evicts ("ca1","1"), the LRU entry

	if got := tr.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3", got)
	}
	got := tr.Recent("ca1", base)
	if len(got) != 2 {
		t.Fatalf("Recent(ca1) = %v, want serials 3 and 2", got)
	}
	if got[0] != "3" || got[1] != "2" {
		t.Fatalf("Recent(ca1) = %v, want [3 2] (most recent first)", got)
	}
	// A tighter window excludes older observations.
	if got := tr.Recent("ca1", base.Add(3*time.Minute)); len(got) != 1 || got[0] != "3" {
		t.Fatalf("windowed Recent(ca1) = %v, want [3]", got)
	}
	// Re-observing refreshes recency instead of duplicating.
	now = now.Add(time.Minute)
	tr.Record("ca1", "2")
	if got := tr.Recent("ca1", base.Add(4*time.Minute)); len(got) != 1 || got[0] != "2" {
		t.Fatalf("after re-record, Recent = %v, want [2]", got)
	}
	if tr.Len() != 3 {
		t.Fatalf("Len after re-record = %d, want 3", tr.Len())
	}
}

// TestOCSPCachePresignEviction verifies pre-signed entries outlive a flood of
// demand-filled entries: eviction under pressure drops expired then
// demand-filled entries before touching pre-signed ones.
func TestOCSPCachePresignEviction(t *testing.T) {
	c, clock := newTestCache(time.Hour)
	c.maxSize = 4
	until := clock.now().Add(30 * time.Minute)
	c.PutUntil("ca", "presigned-1", []byte("p1"), until)
	c.PutUntil("ca", "presigned-2", []byte("p2"), until)
	c.Put("ca", "demand-1", []byte("d1"))
	c.Put("ca", "demand-2", []byte("d2"))

	// Overflow: the demand-filled entries are the casualties.
	c.Put("ca", "demand-3", []byte("d3"))
	for _, serial := range []string{"presigned-1", "presigned-2"} {
		if _, ok := c.Get("ca", serial); !ok {
			t.Fatalf("pre-signed entry %s evicted under pressure", serial)
		}
	}
	if _, ok := c.Get("ca", "demand-3"); !ok {
		t.Fatal("newly inserted entry missing after eviction")
	}

	// PutUntil expiry is honored: entries vanish at their NextUpdate.
	clock.advance(31 * time.Minute)
	if _, ok := c.Get("ca", "presigned-1"); ok {
		t.Fatal("pre-signed entry served past its NextUpdate")
	}

	// EnsureCapacity grows the bound (never shrinks).
	c.EnsureCapacity(10)
	if c.maxSize != 10 {
		t.Fatalf("maxSize = %d, want 10", c.maxSize)
	}
	c.EnsureCapacity(5)
	if c.maxSize != 10 {
		t.Fatalf("EnsureCapacity shrank the bound to %d", c.maxSize)
	}
}
