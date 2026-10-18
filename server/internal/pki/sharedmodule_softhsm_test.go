package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"testing"
)

// Regression suite for the day-2-operations hazard: a short-lived PKCS#11 user
// in the same process as a long-lived one.
//
// The operator console's Operations page calls GET /api/doctor, which builds a
// second key provider per signing role, probes it, and closes it. Every helper
// involved used to load the module itself and tear it all the way down on the
// way out — C_Logout, C_Finalize, dlclose — all three of which are
// process-global, not per-handle. One sweep against a live server therefore
// deauthenticated the serving session pool and then finalized the module out
// from under it: /api/inventory/keys started answering with an empty list and
// secret decryption failed with CKR_OBJECT_HANDLE_INVALID until a restart. The
// token itself was fine the whole time, which is what made it look like an HSM
// fault.
//
// Each test below opens a "server" pool, performs the day-2 action against the
// same token, and then requires the server pool to still enumerate its keys and
// sign — the two observable symptoms, asserted directly.

// sharedModuleCfg builds the SoftHSM config from the SECSY_* variables
// scripts/setup-softhsm.sh --export-env emits, skipping when there is no token.
func sharedModuleCfg(t *testing.T) PKCS11Config {
	t.Helper()
	module, token := os.Getenv("SECSY_PKCS11_MODULE"), os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL " +
			"(run: eval \"$(scripts/setup-softhsm.sh --export-env)\")")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	return PKCS11Config{ModulePath: module, Pin: pin, TokenLabel: token}
}

// servingPool stands in for the running server: a live pool holding an
// authenticated session and a resolved key, plus the label of a key it owns.
func servingPool(t *testing.T, cfg PKCS11Config) (*SessionPool, string) {
	t.Helper()
	return servingPoolN(t, cfg, 2)
}

// servingPoolN is servingPool with an explicit session count, for the tests
// that care how many login references the serving side holds.
func servingPoolN(t *testing.T, cfg PKCS11Config, size int) (*SessionPool, string) {
	t.Helper()
	pool, err := NewSessionPool(cfg, size)
	if err != nil {
		t.Fatalf("opening the serving session pool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	label := "test-day2-" + hex.EncodeToString(b[:])
	if _, err := pool.GenerateSignKey(context.Background(), label, "ecdsa-sha2-nistp256"); err != nil {
		t.Fatalf("generating the serving key: %v", err)
	}
	return pool, label
}

// requireServing asserts the serving pool is still usable: its key is visible
// (a logout hides every private object) and it can still sign with the handle
// it resolved earlier (a finalize or logout invalidates it).
func requireServing(t *testing.T, pool *SessionPool, label, when string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Resolve(ctx, LabelLocator(label)); err != nil {
		t.Errorf("%s: the serving pool can no longer resolve its own key %q: %v", when, label, err)
	}
	digest := sha256.Sum256([]byte("day-2 operations must not disturb the key provider"))
	if _, err := pool.Sign(ctx, LabelLocator(label), digest[:], crypto.SHA256); err != nil {
		t.Errorf("%s: the serving pool can no longer sign: %v", when, err)
	}
}

// A second provider — what GET /api/doctor builds for each signing role — must
// be openable and closable without touching the serving pool. Closing it used
// to issue C_Logout, which on a per-application-login token hid every private
// key object from the sessions that remained.
func TestSecondPoolCloseLeavesServingPoolAuthenticated(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)
	requireServing(t, pool, label, "baseline")

	before, err := pool.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("baseline ListKeys: %v", err)
	}

	doctor, err := NewSessionPool(cfg, 1)
	if err != nil {
		t.Fatalf("opening the diagnostic pool: %v", err)
	}
	if err := doctor.Ping(context.Background()); err != nil {
		t.Fatalf("diagnostic pool Ping: %v", err)
	}
	if err := doctor.Close(); err != nil {
		t.Fatalf("closing the diagnostic pool: %v", err)
	}

	after, err := pool.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("after the diagnostic sweep, ListKeys: %v", err)
	}
	// Directional on purpose. The symptom is the list collapsing — a logged-out
	// session sees no private objects at all — while the count may legitimately
	// grow, because opening the diagnostic pool's session makes SoftHSM re-scan
	// the token directory and surface objects other tests created through
	// sessions that have since closed.
	if len(after) < len(before) {
		t.Errorf("the serving pool now sees %d key(s), was %d: the diagnostic pool's Close logged the application out",
			len(after), len(before))
	}
	requireServing(t, pool, label, "after a second pool opened and closed")
}

// Probe is the readiness probe and the doctor's keyprovider.* reachability
// check. Against a token this process is already logged in to it used to fail
// outright with CKR_USER_ALREADY_LOGGED_IN — a false "HSM unreachable" — and
// then finalize the module on the way out of the failure path.
func TestProbeWhileServingPoolIsLive(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)

	if err := Probe(cfg); err != nil {
		t.Fatalf("Probe against a token the serving pool holds open: %v", err)
	}
	requireServing(t, pool, label, "after Probe")
}

// The remaining one-shot helpers take the same path. ListKeys is what
// `secsy-ca inventory keys` and the console's HSM inventory call; the generate
// helpers are the CLI key-ceremony entry points. None may finalize the module.
func TestOneShotHelpersWhileServingPoolIsLive(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)

	if _, err := ListKeys(cfg); err != nil {
		t.Fatalf("one-shot ListKeys: %v", err)
	}
	requireServing(t, pool, label, "after one-shot ListKeys")

	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKeyOnHSM(cfg, "test-day2-gen-"+hex.EncodeToString(b[:]), "ecdsa-sha2-nistp256"); err != nil {
		t.Fatalf("one-shot GenerateKeyOnHSM: %v", err)
	}
	requireServing(t, pool, label, "after one-shot GenerateKeyOnHSM")

	signer, err := NewPKCS11Signer(cfg, label)
	if err != nil {
		t.Fatalf("NewPKCS11Signer: %v", err)
	}
	signer.Close()
	requireServing(t, pool, label, "after a standalone signer was opened and closed")
}

// Closing a holder twice must not release a reference it no longer owns. The
// serving pool here holds exactly ONE login reference, so an unguarded second
// Close takes the count to zero and logs the token out from under it — the
// original bug, reintroduced by a double Close instead of by the teardown.
func TestSignerCloseIsIdempotent(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPoolN(t, cfg, 1)

	signer, err := NewPKCS11Signer(cfg, label)
	if err != nil {
		t.Fatalf("NewPKCS11Signer: %v", err)
	}
	signer.Close()
	signer.Close()
	signer.Close()
	requireServing(t, pool, label, "after a signer was closed three times")
}

// Sharing the login must not turn a wrong PIN into "credentials OK". A token
// that is already logged in answers the next C_Login with
// CKR_USER_ALREADY_LOGGED_IN without looking at the PIN at all, so a diagnostic
// asked about a mis-configured PIN while the server is running would otherwise
// report the configuration healthy — and the operator would find out at the
// next restart, when nothing comes up.
func TestWrongPINIsStillRejectedWhileServingPoolIsLive(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)

	wrong := cfg
	wrong.Pin = cfg.Pin + "-wrong"
	if err := Probe(wrong); err == nil {
		t.Error("Probe accepted a wrong PIN because the token was already logged in")
	}
	if _, err := NewSessionPool(wrong, 1); err == nil {
		t.Error("a second pool opened with a wrong PIN because the token was already logged in")
	}

	// The refusal must cost the serving pool nothing — a failed login still
	// unwinds through the same refcounted release path.
	requireServing(t, pool, label, "after a wrong-PIN login was refused")

	// And the right PIN still joins.
	if err := Probe(cfg); err != nil {
		t.Errorf("Probe with the correct PIN: %v", err)
	}
	requireServing(t, pool, label, "after a correct-PIN probe")
}

// Under the race detector, with the serving pool signing throughout: the module
// and login refcounts are shared mutable state, so the interleaving of a
// diagnostic sweep with live traffic is the case that has to hold.
func TestConcurrentProbesDuringServingTraffic(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Live traffic.
	digest := sha256.Sum256([]byte("steady state"))
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if _, err := pool.Sign(context.Background(), LabelLocator(label), digest[:], crypto.SHA256); err != nil {
					t.Errorf("signing during concurrent diagnostics: %v", err)
					return
				}
			}
		}()
	}

	// Concurrent day-2 sweeps.
	var sweeps sync.WaitGroup
	for i := 0; i < 4; i++ {
		sweeps.Add(1)
		go func() {
			defer sweeps.Done()
			for j := 0; j < 3; j++ {
				if err := Probe(cfg); err != nil {
					t.Errorf("concurrent Probe: %v", err)
					return
				}
			}
		}()
	}
	sweeps.Wait()
	cancel()
	wg.Wait()

	requireServing(t, pool, label, "after concurrent diagnostics")
}
