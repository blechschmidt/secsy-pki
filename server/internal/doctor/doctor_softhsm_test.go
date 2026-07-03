//go:build sqlite

package doctor_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestDoctorSoftHSM is the Task 59 acceptance test against a real PKCS#11
// token (SoftHSM): it provisions an HSM-keyed deployment, proves the doctor
// reports it healthy end to end (module/PIN reachability, per-CA and TSA
// sign/verify self-tests on the token, store, audit chain, expiry, listener
// TLS), then injects deliberate faults — a stale CRL, a CA row whose key is
// missing from the token, and a wrong PIN — and proves each one is caught
// with the right severity.
//
// It is gated on the SECSY_* environment emitted by
// scripts/setup-softhsm.sh --export-env, like the rest of the HSM suite.
func TestDoctorSoftHSM(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: run  eval \"$(scripts/setup-softhsm.sh --export-env)\"  first")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	// From here on the config file is the single source of truth; ambient
	// SECSY_* overrides would defeat the failure injections below.
	isolateEnv(t)

	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "doctor-hsm.db")
	cfgPath := filepath.Join(dir, "config.yaml")
	suffix := randHex(t, 4)

	db, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	provider, err := keyprovider.New(keyprovider.Config{
		Type:   keyprovider.ProviderPKCS11,
		PKCS11: keyprovider.PKCS11Settings{ModulePath: module, Pin: pin, TokenLabel: token},
	})
	if err != nil {
		t.Fatalf("connecting to SoftHSM: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	// Root CA keyed on the token (unique label per run — see the
	// pkcs11-duplicate-label invariant).
	rootLabel := "doctor-root-" + suffix
	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    rootLabel,
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Doctor SoftHSM Root"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("provisioning HSM root CA: %v", err)
	}

	// An RSA TSA signing key on the token, exercising the RSA self-test path.
	tsaLabel := "doctor-tsa-" + suffix
	if _, err := provider.GenerateKey(ctx, keyprovider.KeySpec{
		Label:   tsaLabel,
		KeyType: keyprovider.KeyTypeRSA2048,
		Usage:   keyprovider.KeyUsageSign,
	}); err != nil {
		t.Fatalf("provisioning TSA key: %v", err)
	}
	// The TSA certificate file just needs a valid certificate with headroom;
	// the root's own certificate serves (the key check is separate).
	tsaCertPath := filepath.Join(dir, "tsa.pem")
	if err := os.WriteFile(tsaCertPath, []byte(root.Certificate), 0o600); err != nil {
		t.Fatal(err)
	}

	seedAuditEvents(t, db)
	tlsCert, tlsKey := writeSelfSignedTLS(t, dir, 365*24*time.Hour)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	writeCfg := func(pinValue string) {
		cfg := fmt.Sprintf(`server:
  host: 127.0.0.1
  port: %d
  tls_cert: %s
  tls_key: %s
root_user:
  password: doctor-test
database:
  driver: sqlite
  dsn: %s
key_provider:
  type: pkcs11
pkcs11:
  module_path: %s
  token_label: %q
  pin: %q
tsa:
  key_label: %s
  certificate_file: %s
`, port, tlsCert, tlsKey, dbPath, module, token, pinValue, tsaLabel, tsaCertPath)
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg(pin)

	runDoctor := func() *doctor.Report {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		return doctor.Run(ctx, doctor.Options{ConfigPath: cfgPath, BuildProvider: buildTestProvider, Deep: true})
	}

	// Sub-tests share the fixture and run in order: each fault is injected,
	// asserted, and reverted so the next starts from a healthy deployment.

	t.Run("HealthyHSMDeployment", func(t *testing.T) {
		r := runDoctor()
		for name, want := range map[string]doctor.Status{
			"config.parse":     doctor.StatusPass,
			"keyprovider.ca":   doctor.StatusPass,
			"keyprovider.tsa":  doctor.StatusPass, // shares the pkcs11 backend
			"db.connectivity":  doctor.StatusPass,
			"db.schema":        doctor.StatusPass,
			"keys.ca":          doctor.StatusPass,
			"keys.tsa":         doctor.StatusPass,
			"audit.chain_head": doctor.StatusPass,
			"db.integrity":     doctor.StatusPass,
			"certs.ca_expiry":  doctor.StatusPass,
			"certs.tsa_expiry": doctor.StatusPass,
			"clock.skew":       doctor.StatusPass,
			"listener.tls":     doctor.StatusPass,
		} {
			assertStatus(t, r, name, want)
		}
		if code := r.ExitCode(); code != doctor.ExitOK {
			t.Errorf("exit code = %d, want %d; report: %+v", code, doctor.ExitOK, r.Checks)
		}
		// The CA self-test must have signed on the PKCS#11 backend.
		if c := findCheck(t, r, "keys.ca"); !strings.Contains(c.Detail, "pkcs11") {
			t.Errorf("keys.ca detail %q does not attribute the self-test to pkcs11", c.Detail)
		}
	})

	t.Run("StaleCRL", func(t *testing.T) {
		now := time.Now()
		// Allocate a real CRL number so the monotonic-counter invariant (which
		// the -deep integrity gate enforces) holds for the seeded artifact.
		staleNum, err := db.NextCRLNumber(root.ID)
		if err != nil {
			t.Fatal(err)
		}
		stale := &database.PublishedCRL{
			CAID: root.ID, Scope: "full", Kind: "base",
			Number: staleNum, BaseNumber: staleNum,
			ThisUpdate:  now.Add(-48 * time.Hour),
			NextUpdate:  now.Add(-24 * time.Hour),
			GeneratedAt: now.Add(-48 * time.Hour),
			DER:         []byte{0x30, 0x00},
		}
		if err := db.UpsertPublishedCRL(stale); err != nil {
			t.Fatalf("seeding stale CRL: %v", err)
		}
		r := runDoctor()
		c := assertStatus(t, r, "crl.freshness", doctor.StatusWarn)
		if !strings.Contains(c.Detail, "expired") {
			t.Errorf("crl.freshness detail %q does not mention expiry", c.Detail)
		}
		if code := r.ExitCode(); code != doctor.ExitWarn {
			t.Errorf("exit code = %d, want %d", code, doctor.ExitWarn)
		}

		// Refresh the CRL so later sub-tests start healthy again.
		freshNum, err := db.NextCRLNumber(root.ID)
		if err != nil {
			t.Fatal(err)
		}
		fresh := *stale
		fresh.Number = freshNum
		fresh.BaseNumber = freshNum
		fresh.ThisUpdate = now
		fresh.NextUpdate = now.Add(24 * time.Hour)
		fresh.GeneratedAt = now
		if err := db.UpsertPublishedCRL(&fresh); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("MissingKeyOnToken", func(t *testing.T) {
		ghost := &models.CA{
			ID:        "doctor-ghost-" + suffix,
			Label:     "doctor-ghost-" + suffix,
			PKCS11URI: fmt.Sprintf("pkcs11:token=%s;object=doctor-ghost-%s;type=private", token, suffix),
			KeyType:   keyprovider.KeyTypeECDSAP256,
			PublicKey: "ecdsa-sha2-nistp256 placeholder",
		}
		if err := db.CreateCA(ghost); err != nil {
			t.Fatalf("inserting ghost CA: %v", err)
		}
		defer func() {
			if err := db.DeleteCA(ghost.ID); err != nil {
				t.Errorf("removing ghost CA: %v", err)
			}
		}()

		r := runDoctor()
		c := assertStatus(t, r, "keys.ca", doctor.StatusFail)
		if !strings.Contains(c.Detail, ghost.Label) {
			t.Errorf("keys.ca detail %q does not name the missing key", c.Detail)
		}
		// The healthy root key must still have been counted as verified before
		// the ghost failed the check ("1/2 ... failed").
		if !strings.Contains(c.Detail, "1/2") {
			t.Errorf("keys.ca detail %q does not show 1 of 2 keys failing", c.Detail)
		}
		if code := r.ExitCode(); code != doctor.ExitFail {
			t.Errorf("exit code = %d, want %d", code, doctor.ExitFail)
		}
	})

	t.Run("WrongPIN", func(t *testing.T) {
		writeCfg("999999")
		defer writeCfg(pin)

		r := runDoctor()
		c := assertStatus(t, r, "keyprovider.ca", doctor.StatusFail)
		if !strings.Contains(strings.ToLower(c.Detail), "pkcs11") {
			t.Errorf("keyprovider.ca detail %q does not identify the pkcs11 backend", c.Detail)
		}
		// Key self-tests cannot succeed without a token login either.
		if k := findCheck(t, r, "keys.ca"); k.Status == doctor.StatusPass {
			t.Errorf("keys.ca unexpectedly passed with a wrong PIN: %s", k.Detail)
		}
		if code := r.ExitCode(); code != doctor.ExitFail {
			t.Errorf("exit code = %d, want %d", code, doctor.ExitFail)
		}
	})

	t.Run("RecoveredAfterFaults", func(t *testing.T) {
		r := runDoctor()
		if code := r.ExitCode(); code != doctor.ExitOK {
			t.Errorf("exit code = %d, want %d after reverting faults; report: %+v", code, doctor.ExitOK, r.Checks)
		}
	})
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// TestDoctorSoftHSMHATokens exercises the hsm.ha_tokens check against a real
// two-token SoftHSM HA set: both tokens reachable passes; replacing the backup
// with a nonexistent token label degrades to warn (the primary still carries
// the set); making both bogus fails the provider reachability check outright.
func TestDoctorSoftHSMHATokens(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	if module == "" {
		t.Skip("SoftHSM not configured: run  eval \"$(scripts/setup-softhsm.sh --export-env)\"  first")
	}
	if os.Getenv("SOFTHSM2_CONF") == "" {
		t.Skip("SOFTHSM2_CONF not set; cannot create HA tokens")
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not found on PATH")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	soPin := os.Getenv("SECSY_SO_PIN")
	if soPin == "" {
		soPin = "5678"
	}
	isolateEnv(t)

	suffix := randHex(t, 4)
	tokenA := "doctor-ha-a-" + suffix
	tokenB := "doctor-ha-b-" + suffix
	for _, label := range []string{tokenA, tokenB} {
		out, err := exec.Command("softhsm2-util", "--init-token", "--free",
			"--label", label, "--pin", pin, "--so-pin", soPin).CombinedOutput()
		if err != nil {
			t.Fatalf("init token %q: %v\n%s", label, err, out)
		}
	}
	t.Cleanup(func() {
		for _, label := range []string{tokenA, tokenB} {
			_ = exec.Command("softhsm2-util", "--delete-token", "--token", label).Run()
		}
	})

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ha.db")
	db, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // the doctor opens its own handle; an empty schema-complete store suffices
	tlsCert, tlsKey := writeSelfSignedTLS(t, dir, 365*24*time.Hour)

	cfgPath := filepath.Join(dir, "config.yaml")
	writeCfg := func(labelA, labelB string) {
		cfg := fmt.Sprintf(`server:
  host: 127.0.0.1
  port: 39443
  tls_cert: %s
  tls_key: %s
root_user:
  password: doctor-test
database:
  driver: sqlite
  dsn: %s
key_provider:
  type: pkcs11
pkcs11:
  module_path: %s
  pin: %q
  failure_threshold: 1
  tokens:
    - name: tokA
      token_label: %q
    - name: tokB
      token_label: %q
`, tlsCert, tlsKey, dbPath, module, pin, labelA, labelB)
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runDoctor := func() *doctor.Report {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		return doctor.Run(ctx, doctor.Options{ConfigPath: cfgPath, BuildProvider: buildTestProvider, SkipListener: true})
	}

	t.Run("BothTokensHealthy", func(t *testing.T) {
		writeCfg(tokenA, tokenB)
		r := runDoctor()
		assertStatus(t, r, "keyprovider.ca", doctor.StatusPass)
		c := assertStatus(t, r, "hsm.ha_tokens", doctor.StatusPass)
		if !strings.Contains(c.Detail, "all 2 HA tokens") {
			t.Errorf("hsm.ha_tokens detail %q does not cover both tokens", c.Detail)
		}
	})

	t.Run("BackupTokenDown", func(t *testing.T) {
		writeCfg(tokenA, "doctor-ha-gone-"+suffix)
		r := runDoctor()
		// The set is still serviceable through the primary…
		assertStatus(t, r, "keyprovider.ca", doctor.StatusPass)
		// …but the dead backup must surface as a warning naming the token.
		c := assertStatus(t, r, "hsm.ha_tokens", doctor.StatusWarn)
		if !strings.Contains(c.Detail, "tokB") {
			t.Errorf("hsm.ha_tokens detail %q does not name the unreachable token", c.Detail)
		}
		if code := r.ExitCode(); code != doctor.ExitWarn {
			t.Errorf("exit code = %d, want %d; report: %+v", code, doctor.ExitWarn, r.Checks)
		}
	})

	t.Run("AllTokensDown", func(t *testing.T) {
		writeCfg("doctor-ha-gone1-"+suffix, "doctor-ha-gone2-"+suffix)
		r := runDoctor()
		assertStatus(t, r, "keyprovider.ca", doctor.StatusFail)
		assertStatus(t, r, "hsm.ha_tokens", doctor.StatusFail)
		if code := r.ExitCode(); code != doctor.ExitFail {
			t.Errorf("exit code = %d, want %d", code, doctor.ExitFail)
		}
	})
}
