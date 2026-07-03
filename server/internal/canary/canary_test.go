//go:build sqlite

// Package canary's tests exercise the synthetic issuance canary end to end
// against a real store, both key providers (software and SoftHSM/PKCS#11), a
// real HSM-signed CA hierarchy, and the real OCSP/CRL code paths — plus the
// failure-injection cases: an HSM outage at issuance (the gatedProvider
// pattern from the ca package) and an outage mid-probe, which must still
// clean up the already-issued probe certificate.
package canary

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
)

// testLogger keeps canary chatter out of the test output unless -v is set.
func testLogger(t *testing.T) *log.Logger {
	t.Helper()
	if testing.Verbose() {
		return log.Default()
	}
	return log.New(io.Discard, "", 0)
}

// newTestDB opens a fresh sqlite store.
func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "canary-test.db"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// softwareProvider returns a keystore-backed provider in a temp directory.
func softwareProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	p, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// pkcs11Provider returns a SoftHSM-backed provider, or skips if not configured.
func pkcs11Provider(t *testing.T) keyprovider.Provider {
	t.Helper()
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: run eval \"$(scripts/setup-softhsm.sh --export-env)\"")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderPKCS11,
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath: module,
			Pin:        pin,
			TokenLabel: token,
		},
	})
	if err != nil {
		t.Fatalf("pkcs11 provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// uniqueLabel avoids CKA_LABEL collisions across runs against a persistent
// SoftHSM token (see the pkcs11-duplicate-label invariant).
func uniqueLabel(t *testing.T, base string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "canarytest-" + base + "-" + hex.EncodeToString(b[:])
}

// bootstrapHierarchy creates a root plus an intermediate on the provider and
// returns both.
func bootstrapHierarchy(t *testing.T, mgr *ca.Manager, tag string) (root, inter *models.CA) {
	t.Helper()
	ctx := context.Background()
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, tag+"-root"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Canary Test Root"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err = mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID: root.ID,
		Label:    uniqueLabel(t, tag+"-inter"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Canary Test Intermediate"}),
		Validity: 2 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	return root, inter
}

// captureNotifier records the failures dispatched by RunOnce.
type captureNotifier struct {
	mu       sync.Mutex
	failures []monitor.CanaryFailure
	calls    int
}

func (c *captureNotifier) NotifyCanaryFailures(_ context.Context, fs []monitor.CanaryFailure) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.failures = append(c.failures, fs...)
}

func (c *captureNotifier) all() []monitor.CanaryFailure {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]monitor.CanaryFailure(nil), c.failures...)
}

// wantStages is the stage sequence of a fully successful probe.
var wantStages = []string{StageResolve, StageIssue, StageChain, StageOCSPGood, StageCRL, StageRevoke, StageOCSPRevoked}

func assertStageOrder(t *testing.T, res *Result, want []string) {
	t.Helper()
	got := make([]string, len(res.Stages))
	for i, s := range res.Stages {
		got[i] = s.Stage
		if s.Duration < 0 {
			t.Errorf("stage %s has negative duration %s", s.Stage, s.Duration)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("stage order = %v, want %v (err: %v)", got, want, res.Err)
	}
}

// metricsText renders the process-global registry for presence assertions.
func metricsText(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := metrics.Default.WriteTo(&buf); err != nil {
		t.Fatalf("rendering metrics: %v", err)
	}
	return buf.String()
}

// TestCanaryProbeLifecycle proves a full probe cycle succeeds against a real
// hierarchy — CA referenced by label and by id — and that the probe leaves the
// store in the documented state: a canary-marked, revoked certificate and a
// success audit event. Runs against both the software keystore and SoftHSM.
func TestCanaryProbeLifecycle(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runProbeLifecycle(t, mk(t), name)
		})
	}
}

func runProbeLifecycle(t *testing.T, provider keyprovider.Provider, tag string) {
	ctx := context.Background()
	db := newTestDB(t)
	mgr := ca.NewManager(db, provider)
	root, inter := bootstrapHierarchy(t, mgr, tag)

	notifier := &captureNotifier{}
	prober, err := New(mgr, db, config.CanaryConfig{
		Enabled:        true,
		CAs:            []string{inter.Label, root.ID}, // one by label, one by id
		TimeoutSeconds: 60,
	}, notifier, testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	results := prober.RunOnce(ctx)
	if len(results) != 2 {
		t.Fatalf("RunOnce returned %d results, want 2", len(results))
	}
	for _, res := range results {
		if !res.OK() {
			t.Fatalf("probe of %s failed at %s: %v", res.CALabel, res.FailedStage, res.Err)
		}
		assertStageOrder(t, res, wantStages)
		if res.Serial == "" {
			t.Fatalf("probe of %s recorded no serial", res.CALabel)
		}

		// The probe certificate must be marked, profiled, and end up revoked.
		rec, err := db.GetIssuedCertificate(res.CAID, res.Serial)
		if err != nil || rec == nil {
			t.Fatalf("probe certificate not on record: %v", err)
		}
		if rec.Marker != models.CertMarkerCanary {
			t.Errorf("probe certificate marker = %q, want %q", rec.Marker, models.CertMarkerCanary)
		}
		if rec.Profile != "canary" {
			t.Errorf("probe certificate profile = %q, want canary", rec.Profile)
		}
		if rec.Status != models.CertStatusRevoked {
			t.Errorf("probe certificate status = %q, want revoked", rec.Status)
		}
		revoked, err := db.GetRevokedCertificate(res.CAID, res.Serial)
		if err != nil || revoked == nil {
			t.Fatalf("probe certificate missing from revocation store: %v", err)
		}
	}

	if len(notifier.all()) != 0 {
		t.Fatalf("successful probes must not notify, got %v", notifier.all())
	}

	// One success audit event per probed CA.
	events, _, err := db.ListEvents(audit.ActionCanaryProbe, "", "", 10, 0)
	if err != nil {
		t.Fatalf("listing canary.probe events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d canary.probe events, want 2", len(events))
	}
	for _, e := range events {
		if e.Result != audit.ResultSuccess {
			t.Errorf("audit event for %s: result = %q, want success (%s)", e.TargetName, e.Result, e.Detail)
		}
		if !strings.Contains(e.Detail, "stages=") {
			t.Errorf("audit detail missing stage timings: %s", e.Detail)
		}
	}

	// Metrics: last-success gauge and stage histogram series exist.
	text := metricsText(t)
	if !strings.Contains(text, `secsy_canary_last_success_timestamp_seconds{ca="`+inter.Label+`"}`) {
		t.Errorf("metrics missing canary last-success gauge for %s", inter.Label)
	}
	if !strings.Contains(text, `secsy_canary_stage_duration_seconds_bucket{stage="issue"`) {
		t.Errorf("metrics missing canary stage-duration histogram")
	}
}

// gatedProvider wraps a real provider with a switch simulating an HSM outage
// (the ca package's presign-test pattern): while down, every operation that
// would reach the token fails. failAfterSigner additionally arms a one-way
// trip wire: allow that many more Signer openings, then go down — which lets a
// probe issue successfully and then lose the HSM mid-probe.
type gatedProvider struct {
	keyprovider.Provider
	mu              sync.Mutex
	down            bool
	failAfterSigner int // -1 = disarmed
}

func newGatedProvider(p keyprovider.Provider) *gatedProvider {
	return &gatedProvider{Provider: p, failAfterSigner: -1}
}

func (g *gatedProvider) setDown(down bool) {
	g.mu.Lock()
	g.down = down
	g.mu.Unlock()
}

// armSignerTripwire lets n more Signer openings through, then simulates an
// outage for everything after.
func (g *gatedProvider) armSignerTripwire(n int) {
	g.mu.Lock()
	g.failAfterSigner = n
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
	g.mu.Lock()
	if g.failAfterSigner == 0 {
		g.down = true
	} else if g.failAfterSigner > 0 {
		g.failAfterSigner--
	}
	down := g.down
	g.mu.Unlock()
	if down {
		return nil, fmt.Errorf("simulated HSM outage: token unavailable")
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

// TestCanaryFailureInjection proves the canary detects an HSM outage — the
// probe fails at the issue stage, the failure is dispatched to the notifier
// and audited as an error — and recovers cleanly once the HSM returns. Runs
// against both providers so the SoftHSM path exercises real PKCS#11 failures.
func TestCanaryFailureInjection(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runFailureInjection(t, mk(t), name)
		})
	}
}

func runFailureInjection(t *testing.T, provider keyprovider.Provider, tag string) {
	ctx := context.Background()
	db := newTestDB(t)
	gated := newGatedProvider(provider)
	mgr := ca.NewManager(db, gated)
	root, _ := bootstrapHierarchy(t, mgr, tag+"-fi")

	notifier := &captureNotifier{}
	prober, err := New(mgr, db, config.CanaryConfig{
		Enabled:        true,
		CAs:            []string{root.ID},
		TimeoutSeconds: 60,
	}, notifier, testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Healthy baseline.
	if res := prober.RunOnce(ctx); !res[0].OK() {
		t.Fatalf("baseline probe failed at %s: %v", res[0].FailedStage, res[0].Err)
	}

	// Outage: the probe must fail at the issue stage and alert.
	gated.setDown(true)
	results := prober.RunOnce(ctx)
	if results[0].OK() {
		t.Fatal("probe succeeded during simulated HSM outage")
	}
	if results[0].FailedStage != StageIssue {
		t.Fatalf("failed stage = %s, want %s (err: %v)", results[0].FailedStage, StageIssue, results[0].Err)
	}
	failures := notifier.all()
	if len(failures) != 1 {
		t.Fatalf("notifier received %d failures, want 1", len(failures))
	}
	if failures[0].Stage != StageIssue || failures[0].CAID != root.ID {
		t.Fatalf("unexpected failure notification: %+v", failures[0])
	}
	events, _, err := db.ListEvents(audit.ActionCanaryProbe, "", "", 1, 0)
	if err != nil || len(events) == 0 {
		t.Fatalf("listing canary.probe events: %v", err)
	}
	if events[0].Result != audit.ResultError || !strings.Contains(events[0].Detail, "failed_stage="+StageIssue) {
		t.Fatalf("newest audit event = %q / %q, want error at issue", events[0].Result, events[0].Detail)
	}

	// Recovery: the HSM returns and the next probe passes end to end.
	gated.setDown(false)
	if res := prober.RunOnce(ctx); !res[0].OK() {
		t.Fatalf("post-recovery probe failed at %s: %v", res[0].FailedStage, res[0].Err)
	}
}

// TestCanaryMidProbeOutageCleansUp injects the outage after issuance (the
// signer trip wire lets exactly one more HSM signing through): the probe must
// fail at the OCSP stage, and the cleanup path must still revoke the orphaned
// probe certificate — revocation is a store write and works without the HSM.
func TestCanaryMidProbeOutageCleansUp(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	gated := newGatedProvider(softwareProvider(t))
	mgr := ca.NewManager(db, gated)
	root, _ := bootstrapHierarchy(t, mgr, "midfail")

	notifier := &captureNotifier{}
	prober, err := New(mgr, db, config.CanaryConfig{
		Enabled:        true,
		CAs:            []string{root.ID},
		TimeoutSeconds: 60,
	}, notifier, testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Allow the leaf-signing Signer open, then take the HSM down.
	gated.armSignerTripwire(1)
	results := prober.RunOnce(ctx)
	res := results[0]
	if res.OK() {
		t.Fatal("probe succeeded despite mid-probe HSM outage")
	}
	if res.FailedStage != StageOCSPGood {
		t.Fatalf("failed stage = %s, want %s (err: %v)", res.FailedStage, StageOCSPGood, res.Err)
	}
	if res.Serial == "" {
		t.Fatal("probe issued no certificate before failing")
	}

	// The orphaned probe certificate must have been revoked by cleanup even
	// though the HSM is still down.
	revoked, err := db.GetRevokedCertificate(root.ID, res.Serial)
	if err != nil {
		t.Fatalf("reading revocation store: %v", err)
	}
	if revoked == nil {
		t.Fatal("mid-probe failure left the probe certificate unrevoked")
	}
	if failures := notifier.all(); len(failures) != 1 || failures[0].Serial != res.Serial {
		t.Fatalf("expected one failure notification carrying the serial, got %+v", failures)
	}
}

// TestCanaryUnresolvableCA proves a misconfigured CA reference surfaces as a
// failed probe at the resolve stage rather than being silently skipped.
func TestCanaryUnresolvableCA(t *testing.T) {
	db := newTestDB(t)
	mgr := ca.NewManager(db, softwareProvider(t))

	notifier := &captureNotifier{}
	prober, err := New(mgr, db, config.CanaryConfig{
		Enabled: true,
		CAs:     []string{"no-such-ca"},
	}, notifier, testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	results := prober.RunOnce(context.Background())
	if results[0].OK() || results[0].FailedStage != StageResolve {
		t.Fatalf("expected resolve-stage failure, got %+v (err: %v)", results[0], results[0].Err)
	}
	if failures := notifier.all(); len(failures) != 1 || failures[0].Stage != StageResolve {
		t.Fatalf("expected a resolve failure notification, got %+v", failures)
	}
}

// TestCanaryConstructorValidation covers New's fail-fast paths.
func TestCanaryConstructorValidation(t *testing.T) {
	db := newTestDB(t)
	mgr := ca.NewManager(db, softwareProvider(t))

	if _, err := New(mgr, db, config.CanaryConfig{}, nil, testLogger(t)); err == nil {
		t.Fatal("New accepted a config without CAs")
	}
	if _, err := New(mgr, db, config.CanaryConfig{CAs: []string{"x"}, Profile: "no-such-profile"}, nil, testLogger(t)); err == nil {
		t.Fatal("New accepted an unknown profile")
	}
	if _, err := New(nil, db, config.CanaryConfig{CAs: []string{"x"}}, nil, testLogger(t)); err == nil {
		t.Fatal("New accepted a nil PKI")
	}
}
