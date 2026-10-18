//go:build sqlite

package handlers

// Acceptance test for the day-2 operations page against a real token.
//
// The console's Operations page calls GET /api/doctor on load, and the
// diagnostics suite builds its own key provider per signing role so it can
// report on the configuration as it is on disk. Until the PKCS#11 layer
// reference-counted the module and the login (internal/pki), that second
// provider's teardown was process-global: closing it logged the application out
// of the token and finalized the module, so the SERVING provider — the one
// every certificate and secret operation goes through — lost its sessions.
// After one visit to the Operations page, /api/inventory/keys answered with an
// empty list and secret decryption failed with CKR_OBJECT_HANDLE_INVALID until
// the process was restarted.
//
// This test drives the real route and then requires the serving provider to
// still work. It is the end-to-end form of the regressions pinned at the
// Cryptoki layer in internal/pki/sharedmodule_softhsm_test.go.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// softHSMSettings reads the SoftHSM coordinates scripts/setup-softhsm.sh
// --export-env emits, skipping when there is no token to talk to.
func softHSMSettings(t *testing.T) keyprovider.PKCS11Settings {
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
	return keyprovider.PKCS11Settings{ModulePath: module, TokenLabel: token, Pin: pin}
}

func TestDoctorEndpointLeavesTheServingKeyProviderUsable(t *testing.T) {
	ctx := context.Background()
	settings := softHSMSettings(t)

	// The serving provider: what NewAPI holds and every issuance path uses.
	serving, err := keyprovider.NewPKCS11Provider(settings)
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { _ = serving.Close() })
	instrumented := keyprovider.Instrument(serving)

	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	label := "test-day2-api-" + hex.EncodeToString(b[:])
	if _, err := instrumented.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyprovider.KeyTypeECDSAP256}); err != nil {
		t.Fatalf("generating the serving key: %v", err)
	}

	// signOK exercises the serving provider the way an issuance request does:
	// resolve the key, then sign with it on the token.
	signOK := func(when string) {
		t.Helper()
		if _, err := instrumented.FindKey(ctx, keyprovider.KeyRef{Label: label}); err != nil {
			t.Errorf("%s: the serving provider can no longer find its CA key: %v", when, err)
			return
		}
		signer, err := instrumented.Signer(ctx, keyprovider.KeyRef{Label: label})
		if err != nil {
			t.Errorf("%s: the serving provider cannot open a signer: %v", when, err)
			return
		}
		defer signer.Close()
		digest := sha256.Sum256([]byte("post-diagnostics issuance"))
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			t.Errorf("%s: the serving provider cannot sign: %v", when, err)
		}
	}
	signOK("baseline")

	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	api := NewAPI(db, instrumented, nil, hsm.Config{}, true, "")

	// An on-disk config naming the same token, and the per-role factory
	// cmd/server/main.go installs: each call builds a NEW provider, which the
	// diagnostics suite owns and closes when the sweep ends.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := fmt.Sprintf(`server:
  host: 127.0.0.1
  port: 8443
root_user:
  password: doctor-day2-test
database:
  driver: sqlite
  dsn: %s
key_provider:
  type: pkcs11
pkcs11:
  module_path: %s
  token_label: %q
  pin: %q
`, filepath.Join(dir, "doctor.db"), settings.ModulePath, settings.TokenLabel, settings.Pin)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	var built int
	api.SetOps(&OpsDeps{
		Config:     &config.Config{},
		ConfigPath: cfgPath,
		ProviderFor: func(string) (keyprovider.Provider, error) {
			built++
			p, perr := keyprovider.NewPKCS11Provider(settings)
			if perr != nil {
				return nil, perr
			}
			return keyprovider.Instrument(p), nil
		},
	})

	// Two sweeps: the console reloads the page, and a second visit must be as
	// harmless as the first (a refcount that leaks one reference per run would
	// only show up on a later pass).
	for i := 1; i <= 2; i++ {
		doctorIsolateEnv(t)
		rec := doctorRun(api, rootUser(), "?no_listener=true&timeout=60")
		resp := doctorDecode(t, rec)
		kp := doctorFindCheck(t, resp, "keyprovider.ca")
		if kp.Status != "pass" {
			t.Errorf("sweep %d: keyprovider.ca = %s (%s), want pass", i, kp.Status, kp.Message)
		}
		signOK(fmt.Sprintf("after diagnostics sweep %d", i))
	}
	if built == 0 {
		t.Fatal("the diagnostics suite never built a provider; the test proved nothing")
	}
}
