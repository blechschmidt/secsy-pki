//go:build sqlite

package handlers

// Tests for the static-artifact publishing REST surface (Task 198). The
// load-bearing properties:
//
//   - publish then verify: a snapshot written through the endpoint is re-readable
//     and every artifact matches the digest its manifest recorded, proved by the
//     verify endpoint rather than by re-reading the files here.
//   - verify needs nothing but the destination: no HSM, no key provider, no CA —
//     which is what makes it usable during an outage.
//   - two publishes cannot interleave against one destination.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
)

// publishFixture is an API with a software-keyed root CA and a publish
// destination under t.TempDir().
type publishFixture struct {
	api *API
	db  *database.DB
	// root is the seeded publishable CA (nil when the fixture seeded none).
	root *models.CA
	// dest is the configured publish destination; keystore backs the role-scoped
	// providers so they resolve the same CA key.
	dest     string
	keystore string
}

// newPublishFixture builds the API, provisions a root CA, and points the
// configured publish destination at a temp directory. seedCA=false leaves the
// store without any publishable CA.
func newPublishFixture(t *testing.T, seedCA bool) *publishFixture {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keystore := t.TempDir()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: keystore})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })

	f := &publishFixture{
		api:      NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, ""),
		db:       db,
		dest:     t.TempDir(),
		keystore: keystore,
	}
	if seedCA {
		root, rerr := ca.NewManager(db, prov).InitRoot(t.Context(), ca.RootSpec{
			Label:    "publish-api-root",
			KeyType:  keyprovider.KeyTypeECDSAP256,
			Subject:  ca.PKIXName(models.CASubject{CommonName: "Publish API Root"}),
			Validity: 365 * 24 * time.Hour,
		})
		if rerr != nil {
			t.Fatalf("InitRoot: %v", rerr)
		}
		f.root = root
	}
	f.setOps(t, config.PublishConfig{Dir: config.PublishDirConfig{Path: f.dest, KeepSnapshots: 2}})
	return f
}

// setOps installs the operations dependencies over a publish configuration,
// handing out fresh software providers over the same keystore (as the server hands
// out role-scoped providers the handler owns and closes).
func (f *publishFixture) setOps(t *testing.T, pub config.PublishConfig) {
	t.Helper()
	keystore := f.keystore
	f.api.SetOps(&OpsDeps{
		Config:     &config.Config{Publish: pub},
		ConfigPath: "/etc/secsy/publish-test.yaml",
		ProviderFor: func(string) (keyprovider.Provider, error) {
			return keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: keystore})
		},
	})
}

func publishSnapshot(api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.PublishSnapshot(rec, reqAs(http.MethodPost, "/api/publish", user, "", body))
	return rec
}

func publishVerify(api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.VerifyPublishedSnapshot(rec, reqAs(http.MethodPost, "/api/publish/verify", user, "", body))
	return rec
}

// TestPublishAuthz pins both gates. Publishing replaces the revocation and trust
// artifacts every relying party consumes, across every tenant's CAs, so it is
// held at platform ca:configure (admin) and no tenant-scoped role reaches it.
// Verifying is a read-only audit of artifacts a CDN already serves to the world,
// so it is held at platform audit:read — deliberately lower, because its value is
// being available when the signing path is not.
func TestPublishAuthz(t *testing.T) {
	f := newPublishFixture(t, true)
	// Publish once up front so verify has a snapshot to audit for every principal,
	// making the expectations independent of subtest order.
	if rec := publishSnapshot(f.api, rootUser(), `{"skip_ocsp":true}`); rec.Code != http.StatusOK {
		t.Fatalf("seeding a snapshot: got %d; body=%s", rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		name            string
		user            *models.UserInfo
		publish, verify int
	}{
		{"unauthenticated", nil, 403, 403},
		{"roleless", &models.UserInfo{Subject: "nobody"}, 403, 403},
		// An auditor may audit the published snapshot but never replace it.
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, 403, 200},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, 403, 200},
		{"tenant admin", tenantUser("tadmin", "a", "admin"), 403, 403},
		{"platform admin", platformAdmin(), 200, 200},
		{"root", rootUser(), 200, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := publishSnapshot(f.api, tc.user, `{}`); rec.Code != tc.publish {
				t.Errorf("publish: got %d, want %d; body=%s", rec.Code, tc.publish, rec.Body.String())
			}
			if rec := publishVerify(f.api, tc.user, `{}`); rec.Code != tc.verify {
				t.Errorf("verify: got %d, want %d; body=%s", rec.Code, tc.verify, rec.Body.String())
			}
		})
	}
}

// TestPublishWithoutOpsDeps proves both endpoints degrade to 503 rather than
// panicking when the server was started without the operations dependencies, and
// that authorization is decided first.
func TestPublishWithoutOpsDeps(t *testing.T) {
	f := newPublishFixture(t, true)
	f.api.SetOps(nil)

	for _, tc := range []struct {
		name string
		call func(*models.UserInfo) *httptest.ResponseRecorder
	}{
		{"publish", func(u *models.UserInfo) *httptest.ResponseRecorder { return publishSnapshot(f.api, u, `{}`) }},
		{"verify", func(u *models.UserInfo) *httptest.ResponseRecorder { return publishVerify(f.api, u, `{}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := tc.call(rootUser()); rec.Code != http.StatusServiceUnavailable {
				t.Errorf("capable caller: got %d, want 503; body=%s", rec.Code, rec.Body.String())
			}
			if rec := tc.call(&models.UserInfo{Subject: "nobody"}); rec.Code != http.StatusForbidden {
				t.Errorf("roleless caller: got %d, want 403 (authz before wiring); body=%s",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestPublishThenVerify is the happy path: publish a snapshot to a temp
// destination, then prove the verify endpoint re-reads every artifact it reported
// and finds each digest intact.
func TestPublishThenVerify(t *testing.T) {
	f := newPublishFixture(t, true)

	rec := publishSnapshot(f.api, rootUser(), `{"skip_ocsp":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var pub PublishResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pub); err != nil {
		t.Fatalf("decode publish: %v; body=%s", err, rec.Body.String())
	}
	if pub.Backend != "dir" || pub.Destination != f.dest {
		t.Errorf("target = %s:%s, want dir:%s", pub.Backend, pub.Destination, f.dest)
	}
	if pub.CACount != 1 || len(pub.CAs) != 1 || pub.CAs[0].ID != f.root.ID {
		t.Fatalf("cas = %+v, want the one seeded CA", pub.CAs)
	}
	if pub.IncludeOCSP {
		t.Error("include_ocsp = true despite skip_ocsp")
	}
	if pub.ArtifactCount != len(pub.Artifacts) || pub.ArtifactCount == 0 {
		t.Fatalf("artifact_count = %d with %d artifacts", pub.ArtifactCount, len(pub.Artifacts))
	}
	// The CRLs, the chain, and the CA certificate are what a CDN must be able to
	// serve; each carries the digest a consumer can check.
	kinds := map[string]int{}
	for _, art := range pub.Artifacts {
		kinds[art.Kind]++
		if art.SHA256 == "" || art.Size == 0 || art.Path == "" {
			t.Errorf("artifact %+v is missing its integrity record", art)
		}
		if _, err := os.Stat(filepath.Join(f.dest, "current", filepath.FromSlash(art.Path))); err != nil {
			t.Errorf("artifact %s is not readable at the destination: %v", art.Path, err)
		}
	}
	for _, kind := range []string{publish.KindCRL, publish.KindDeltaCRL, publish.KindChain, publish.KindCACert} {
		if kinds[kind] == 0 {
			t.Errorf("no %s artifact in the snapshot (kinds=%v)", kind, kinds)
		}
	}
	if kinds[publish.KindOCSP] != 0 {
		t.Errorf("skip_ocsp still published %d OCSP artifacts", kinds[publish.KindOCSP])
	}
	if pub.EarliestExpiry == nil || !pub.EarliestExpiry.After(time.Now()) {
		t.Errorf("earliest_expiry = %v, want a future horizon", pub.EarliestExpiry)
	}

	// Verify: the same manifest, every artifact re-read and digest-checked.
	rec = publishVerify(f.api, rootUser(), `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var ver PublishVerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ver); err != nil {
		t.Fatalf("decode verify: %v; body=%s", err, rec.Body.String())
	}
	if !ver.OK || ver.Error != "" {
		t.Fatalf("verify = ok:%v error:%q, want a clean audit", ver.OK, ver.Error)
	}
	if ver.VerifiedArtifacts != pub.ArtifactCount || ver.CACount != pub.CACount {
		t.Errorf("verify covered %d artifacts / %d CAs, want the %d / %d that were published",
			ver.VerifiedArtifacts, ver.CACount, pub.ArtifactCount, pub.CACount)
	}
	if ver.GeneratedAt == nil || !ver.GeneratedAt.Equal(pub.GeneratedAt) {
		t.Errorf("verify reports snapshot %v, want the one just published (%v)", ver.GeneratedAt, pub.GeneratedAt)
	}

	// The publish is audited under the action the CA manager already uses for
	// revocation-artifact publication, attributed to the operator.
	events, _, err := f.db.ListEvents(audit.ActionCRLPublish, "", "", 50, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var sawSnapshot bool
	for _, e := range events {
		if strings.Contains(e.Detail, "publish=snapshot") && strings.Contains(e.Detail, "via=api") {
			sawSnapshot = e.Result == audit.ResultSuccess && e.Actor == "root"
		}
	}
	if !sawSnapshot {
		t.Errorf("crl.publish events = %+v, want an operator-attributed snapshot record", events)
	}
}

// TestPublishVerifyDetectsTampering proves the audit is real: corrupt one
// published artifact and the endpoint reports the finding (200 with ok=false — a
// finding is data, like a doctor check) without rewriting anything.
func TestPublishVerifyDetectsTampering(t *testing.T) {
	f := newPublishFixture(t, true)
	if rec := publishSnapshot(f.api, rootUser(), `{"skip_ocsp":true}`); rec.Code != http.StatusOK {
		t.Fatalf("publish: got %d; body=%s", rec.Code, rec.Body.String())
	}

	crl := filepath.Join(f.dest, "current", f.root.ID, "crl.der")
	original, err := os.ReadFile(crl)
	if err != nil {
		t.Fatalf("reading published CRL: %v", err)
	}
	if err := os.WriteFile(crl, append([]byte{0x00}, original...), 0o644); err != nil {
		t.Fatalf("tampering with the published CRL: %v", err)
	}

	rec := publishVerify(f.api, rootUser(), `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: got %d, want 200 (a finding is data); body=%s", rec.Code, rec.Body.String())
	}
	var ver PublishVerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ver); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ver.OK {
		t.Fatal("verify reported OK over a tampered artifact")
	}
	if !strings.Contains(ver.Error, "crl.der") {
		t.Errorf("error = %q, want it to name the corrupted artifact", ver.Error)
	}
	// Read-only: the tampered bytes are still there, untouched by the audit.
	if now, rerr := os.ReadFile(crl); rerr != nil || len(now) != len(original)+1 {
		t.Errorf("verify modified the destination (len %d, want %d): %v", len(now), len(original)+1, rerr)
	}
}

// TestPublishRejectsUnknownCA refuses to publish a partial snapshot because a CA
// name was mistyped, and does not write anything.
func TestPublishRejectsUnknownCA(t *testing.T) {
	f := newPublishFixture(t, true)

	rec := publishSnapshot(f.api, rootUser(), `{"cas":["no-such-ca"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no-such-ca") {
		t.Errorf("error does not name the unknown CA: %s", rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(f.dest, "current")); !os.IsNotExist(err) {
		t.Errorf("a rejected publish still wrote a snapshot: %v", err)
	}

	for _, body := range []string{`{`, `{"skip_ocsp":"yes"}`, `{"timeout_seconds":-1}`} {
		if rec := publishSnapshot(f.api, rootUser(), body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: got %d, want 400; body=%s", body, rec.Code, rec.Body.String())
		}
	}
}

// TestPublishWithNoPublishableCA reports the deployment state rather than writing
// an empty snapshot over a good one.
func TestPublishWithNoPublishableCA(t *testing.T) {
	f := newPublishFixture(t, false)

	rec := publishSnapshot(f.api, rootUser(), `{}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no publishable X.509 CA") {
		t.Errorf("error = %s, want it to explain there is nothing to publish", rec.Body.String())
	}
}

// TestPublishReportsSkippedCAs shows an operator why a CA is absent from the
// snapshot instead of silently leaving it out.
func TestPublishReportsSkippedCAs(t *testing.T) {
	f := newPublishFixture(t, true)
	// An SSH-only signing key (no CA certificate) and an expired X.509 CA.
	expired := time.Now().Add(-24 * time.Hour)
	for _, c := range []models.CA{
		{ID: "ssh-only", Label: "ssh-only", PKCS11URI: "software:ssh-only", KeyType: "ed25519", PublicKey: "k"},
		{ID: "expired-ca", Label: "expired-ca", PKCS11URI: "software:expired-ca", KeyType: "ecdsa-p256",
			PublicKey: "k", Certificate: "PEM", NotAfter: &expired},
	} {
		cc := c
		if err := f.db.CreateCA(&cc); err != nil {
			t.Fatalf("CreateCA(%s): %v", c.ID, err)
		}
	}

	rec := publishSnapshot(f.api, rootUser(), `{"skip_ocsp":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var pub PublishResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pub); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pub.CACount != 1 {
		t.Fatalf("published %d CAs, want only the usable one", pub.CACount)
	}
	reasons := map[string]string{}
	for _, s := range pub.Skipped {
		reasons[s.ID] = s.Reason
	}
	if reasons["ssh-only"] != "not an X.509 CA" || reasons["expired-ca"] != "CA certificate expired" {
		t.Errorf("skipped = %+v, want both CAs reported with their reason", pub.Skipped)
	}
}

// TestPublishConcurrentIsRejected proves two publishes cannot interleave against
// the shared destination: the second caller is told to retry.
func TestPublishConcurrentIsRejected(t *testing.T) {
	f := newPublishFixture(t, true)

	// Hold the guard as an in-flight publish would, then prove a request sees 409.
	publishMu.Lock()
	rec := publishSnapshot(f.api, rootUser(), `{}`)
	publishMu.Unlock()
	if rec.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409 while another publish holds the destination; body=%s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), f.dest) {
		t.Errorf("the 409 does not name the contended destination: %s", rec.Body.String())
	}

	// With the guard free, concurrent callers serialize: exactly one 200 per
	// completed publish, never a torn snapshot.
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = publishSnapshot(f.api, rootUser(), `{"skip_ocsp":true}`).Code
		}(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK && code != http.StatusConflict {
			t.Errorf("concurrent publish %d: got %d, want 200 or 409", i, code)
		}
	}
	if rec := publishVerify(f.api, rootUser(), `{}`); rec.Code != http.StatusOK {
		t.Fatalf("the destination is not a valid snapshot after concurrent publishes: %s", rec.Body.String())
	}
}

// TestPublishLockIsSharedWithTheBackgroundLoop closes the gap the file header used
// to deny. The comment claimed the leader-elected publish loop "lives in another
// process/goroutine tree", but in the single-binary server that loop is
// elector.Register("artifact-publish", …) in THIS process — so the endpoint's guard
// and the loop's exclusion were the same property with only one participant.
//
// TryPublishLock is what the loop now takes (cmd/server/presign_publish.go), and it
// has to be the SAME guard the endpoint takes, not a second one beside it: holding
// it must make POST /api/publish answer 409, and the endpoint holding it must make
// the loop's TryPublishLock fail. Both directions are asserted, because a guard that
// only excludes in one direction excludes nothing.
func TestPublishLockIsSharedWithTheBackgroundLoop(t *testing.T) {
	f := newPublishFixture(t, true)

	// Loop side holds it -> the endpoint is refused.
	release, ok := TryPublishLock()
	if !ok {
		t.Fatal("the publish guard was already held at the start of the test")
	}
	if _, free := TryPublishLock(); free {
		t.Error("TryPublishLock handed out the guard twice")
	}
	if rec := publishSnapshot(f.api, rootUser(), `{}`); rec.Code != http.StatusConflict {
		t.Fatalf("publish while the loop holds the guard: got %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	release()

	// Endpoint side holds it -> the loop's acquisition is refused. publishMu is the
	// guard the endpoint takes, so holding it directly is how an in-flight publish
	// looks to the loop.
	publishMu.Lock()
	if _, free := TryPublishLock(); free {
		t.Error("the background loop acquired the guard while a publish holds it")
	}
	publishMu.Unlock()

	// It is released after a completed publish, not leaked on the success path.
	if rec := publishSnapshot(f.api, rootUser(), `{"skip_ocsp":true}`); rec.Code != http.StatusOK {
		t.Fatalf("publish: got %d; body=%s", rec.Code, rec.Body.String())
	}
	if release, free := TryPublishLock(); !free {
		t.Error("the guard is still held after a completed publish")
	} else {
		release()
	}
}

// TestPublishReusesServingKeyProvider is the HSM session-budget invariant: a
// publish must NOT open a second key provider for the CA role the server already
// holds.
//
// On PKCS#11 a second provider is a second session pool. A YubiHSM 2 caps the
// device at 16 concurrent sessions and the serving provider holds eight, so a
// publish opening eight more sits at the limit and two concurrent ones starve live
// CA signing — while the CLI's own rule (providerForRole) has always been to reuse
// the provider when the role resolves to the same backend. The counter is the
// assertion: the role factory must not be called at all, and the snapshot must
// still be complete and verifiable, proving the shared provider really signed it.
func TestPublishReusesServingKeyProvider(t *testing.T) {
	f := newPublishFixture(t, true)
	calls := 0
	f.api.SetOps(&OpsDeps{
		Config:     &config.Config{Publish: config.PublishConfig{Dir: config.PublishDirConfig{Path: f.dest, KeepSnapshots: 2}}},
		ConfigPath: "/etc/secsy/publish-test.yaml",
		ProviderFor: func(role string) (keyprovider.Provider, error) {
			calls++
			return keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: f.keystore})
		},
	})

	if rec := publishSnapshot(f.api, rootUser(), `{"skip_ocsp":true}`); rec.Code != http.StatusOK {
		t.Fatalf("publish: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Errorf("publish opened %d extra key provider(s); the CA role is the serving provider and must be reused", calls)
	}
	// It signed with the shared provider for real: the snapshot verifies.
	if rec := publishVerify(f.api, rootUser(), `{}`); rec.Code != http.StatusOK {
		t.Fatalf("verify after publish: got %d; body=%s", rec.Code, rec.Body.String())
	}
	// And the serving provider is still usable afterwards — release() must be the
	// no-op for a shared provider, never a Close of the server's own.
	if _, err := f.api.keyProvider.FindKey(t.Context(), keyprovider.KeyRef{Label: f.root.Label}); err != nil {
		t.Errorf("the serving key provider was closed by the publish: %v", err)
	}
}

// TestPublishWithoutDestination refuses to invent a destination relative to the
// server's working directory, unlike the one-shot CLI.
func TestPublishWithoutDestination(t *testing.T) {
	f := newPublishFixture(t, true)
	f.setOps(t, config.PublishConfig{}) // no dir.path, no s3.bucket

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"publish": publishSnapshot(f.api, rootUser(), `{}`),
		"verify":  publishVerify(f.api, rootUser(), `{}`),
	} {
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: got %d, want 503; body=%s", name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "publish.dir.path") {
			t.Errorf("%s: error should name the missing setting: %s", name, rec.Body.String())
		}
	}
}
