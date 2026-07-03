package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestHashFracDeterministicAndBounded(t *testing.T) {
	seen := make(map[float64]bool)
	for _, seed := range []string{"a", "b", "serial-123/web", "serial-124/web", "serial-123/api"} {
		v := hashFrac(seed)
		if v < 0 || v >= 1 {
			t.Fatalf("hashFrac(%q) = %v out of [0,1)", seed, v)
		}
		if v != hashFrac(seed) {
			t.Fatalf("hashFrac(%q) not deterministic", seed)
		}
		seen[v] = true
	}
	if len(seen) < 4 {
		t.Errorf("hashFrac shows poor dispersion: %v", seen)
	}
}

func TestLifetimeRenewTime(t *testing.T) {
	ca := newTestCA(t, "Sched Root")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lifetime := 90 * 24 * time.Hour
	leaf := ca.issueFor(t, key.Public(), "x", []string{"x.example.test"},
		issueOpts{notBefore: notBefore, notAfter: notBefore.Add(lifetime)})

	fraction, jitter := 2.0/3.0, 0.05
	renewAt := lifetimeRenewTime(leaf, fraction, jitter, "seed")
	earliest := notBefore.Add(time.Duration(fraction * float64(lifetime)))
	latest := notBefore.Add(time.Duration((fraction + jitter) * float64(lifetime)))
	if renewAt.Before(earliest) || renewAt.After(latest) {
		t.Errorf("renewAt %s outside [%s, %s]", renewAt, earliest, latest)
	}
	if got := lifetimeRenewTime(leaf, fraction, jitter, "seed"); !got.Equal(renewAt) {
		t.Errorf("renewal time not stable across calls: %s vs %s", got, renewAt)
	}
	if got := lifetimeRenewTime(leaf, fraction, jitter, "other-seed"); got.Equal(renewAt) {
		t.Log("note: two seeds mapped to the same instant (possible but unlikely)")
	}

	// A fraction+jitter that would land past expiry is capped before NotAfter.
	capped := lifetimeRenewTime(leaf, 0.999, 0.5, "seed")
	if !capped.Before(leaf.NotAfter) {
		t.Errorf("capped renewal %s not before expiry %s", capped, leaf.NotAfter)
	}
}

func TestSelectARITime(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	sel := selectARITime(start, end, "certid/web")
	if sel.Before(start) || !sel.Before(end) {
		t.Errorf("selected %s outside window [%s, %s)", sel, start, end)
	}
	if got := selectARITime(start, end, "certid/web"); !got.Equal(sel) {
		t.Errorf("ARI selection not deterministic")
	}
	// Inverted/empty window (forced renewal) selects the end.
	if got := selectARITime(end, start, "x"); !got.Equal(start) {
		t.Errorf("empty window selection = %s, want %s", got, start)
	}
}

// newScheduleAgent builds an agent whose EST cert is already installed, for
// pure evaluate() tests.
func newScheduleAgent(t *testing.T, ca *testCA, lifetime time.Duration) (*Agent, *CertSpec) {
	t.Helper()
	fake := &fakeEST{ca: ca, username: "u", password: "p", validity: lifetime}
	a, spec, _ := newESTAgent(t, fake, nil)

	// Install by running one real pass at "now".
	report, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := report.Renewed(); len(got) != 1 {
		t.Fatalf("initial pass renewed %v, want [web]", got)
	}
	return a, spec
}

func TestEvaluateLifecycle(t *testing.T) {
	ca := newTestCA(t, "Sched Root")
	a, spec := newScheduleAgent(t, ca, 24*time.Hour)

	base := time.Now()

	// Freshly installed: not due.
	dec := a.evaluate(context.Background(), spec, base, false)
	if dec.due {
		t.Fatalf("fresh cert reported due: %+v", dec)
	}
	if dec.source != "lifetime" {
		t.Fatalf("EST cert should use lifetime scheduling, got %q", dec.source)
	}

	// Past the fraction point: due.
	late := base.Add(20 * time.Hour) // > 2/3+jitter of 24h
	dec = a.evaluate(context.Background(), spec, late, false)
	if !dec.due || dec.source != "lifetime" {
		t.Fatalf("cert at 20h/24h should be due via lifetime, got %+v", dec)
	}

	// Past expiry: due with the expiry trigger.
	dec = a.evaluate(context.Background(), spec, base.Add(25*time.Hour), false)
	if !dec.due || dec.source != "trigger" {
		t.Fatalf("expired cert should trigger, got %+v", dec)
	}

	// SAN drift: adding a name makes it due immediately.
	spec.DNSNames = append(spec.DNSNames, "extra.example.test")
	dec = a.evaluate(context.Background(), spec, base, false)
	if !dec.due || dec.source != "trigger" {
		t.Fatalf("SAN drift should trigger, got %+v", dec)
	}
	spec.DNSNames = spec.DNSNames[:1]

	// Key-type drift.
	spec.KeyType = "rsa-2048"
	dec = a.evaluate(context.Background(), spec, base, false)
	if !dec.due || dec.source != "trigger" {
		t.Fatalf("key-type drift should trigger, got %+v", dec)
	}
	spec.KeyType = "ecdsa-p256"

	// Missing file.
	certPath := spec.CertFile
	spec.CertFile = filepath.Join(t.TempDir(), "missing.crt")
	dec = a.evaluate(context.Background(), spec, base, false)
	if !dec.due || dec.reason != "not yet installed" {
		t.Fatalf("missing cert should report not installed, got %+v", dec)
	}
	spec.CertFile = certPath
}

// TestARIDecision drives ariDecision against a fake renewal-info endpoint.
func TestARIDecision(t *testing.T) {
	ca := newTestCA(t, "ARI Root")
	now := time.Now()

	var window struct {
		start, end time.Time
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /acme/directory", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"newNonce":    base + "/acme/new-nonce",
			"newAccount":  base + "/acme/new-account",
			"newOrder":    base + "/acme/new-order",
			"renewalInfo": base + "/acme/renewal-info",
		})
	})
	var lastCertID string
	mux.HandleFunc("GET /acme/renewal-info/{certid}", func(w http.ResponseWriter, r *http.Request) {
		lastCertID = r.PathValue("certid")
		w.Header().Set("Retry-After", "21600")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"suggestedWindow": map[string]string{
				"start": window.start.UTC().Format(time.RFC3339),
				"end":   window.end.UTC().Format(time.RFC3339),
			},
		})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dir := t.TempDir()
	bundle := pemFile(t, dir, "trust.pem", encodeChainPEM([]*x509.Certificate{ca.cert}))
	spec := &CertSpec{
		Name:     "ari",
		Enroll:   EnrollACME,
		DNSNames: []string{"ari.example.test"},
		KeyFile:  filepath.Join(dir, "ari.key"),
		CertFile: filepath.Join(dir, "ari.crt"),
	}
	cfg := &Config{
		StateDir:     filepath.Join(dir, "state"),
		Trust:        TrustConfig{BundleFile: bundle},
		ACME:         ACMEConfig{Directory: ts.URL + "/acme/directory"},
		Certificates: []*CertSpec{spec},
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close() //nolint:errcheck

	// Install a leaf by hand (the ACME enrollment path is exercised in e2e).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.issueFor(t, key.Public(), "ari.example.test", []string{"ari.example.test"},
		issueOpts{notBefore: now.Add(-time.Hour), notAfter: now.Add(23 * time.Hour)})
	keyPEM, _ := encodeKeyPEM(key)
	if err := writeFileAtomic(spec.KeyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(spec.CertFile, encodeCertPEM(leaf.Raw), 0o644); err != nil {
		t.Fatal(err)
	}

	// Window in the future: not due, source=ari, renewAt inside window.
	window.start = now.Add(10 * time.Hour)
	window.end = now.Add(12 * time.Hour)
	dec := a.evaluate(context.Background(), spec, now, false)
	if dec.due || dec.source != "ari" {
		t.Fatalf("future window should not be due (source ari), got %+v", dec)
	}
	if dec.renewAt.Before(window.start) || !dec.renewAt.Before(window.end) {
		t.Fatalf("renewAt %s outside window", dec.renewAt)
	}
	wantID, _ := ariCertID(leaf)
	if lastCertID != wantID {
		t.Fatalf("server saw certID %q, want %q", lastCertID, wantID)
	}

	// The response is cached: moving the window server-side does not change
	// the decision within Retry-After...
	first := dec.renewAt
	window.start = now.Add(-2 * time.Hour)
	window.end = now.Add(-1 * time.Hour)
	dec = a.evaluate(context.Background(), spec, now, false)
	if dec.due || !dec.renewAt.Equal(first) {
		t.Fatalf("cached ARI window should hold, got %+v", dec)
	}

	// ...but a fetch after cache expiry sees the immediate window → due.
	a.state.cert(spec.Name).ARI.FetchedAt = now.Add(-7 * time.Hour)
	dec = a.evaluate(context.Background(), spec, now, false)
	if !dec.due || dec.source != "ari" {
		t.Fatalf("past window should be due via ari, got %+v", dec)
	}

	// Offline evaluation with a cached window works without refetching.
	dec = a.evaluate(context.Background(), spec, now, true)
	if !dec.due || dec.source != "ari" {
		t.Fatalf("offline eval should use cached window, got %+v", dec)
	}
}
