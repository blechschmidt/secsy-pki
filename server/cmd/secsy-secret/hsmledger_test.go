//go:build sqlite

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// The secret layer signs, generates keys, decrypts and draws randomness on the
// same HSM the CA does, and until the ledger wiring landed it did all of that
// anonymously. These tests cover the three properties that makes or breaks:
// recording is off when there is nothing to record against, it is on once a
// device has been commissioned, and a recorded signature actually reaches the
// ledger — because an unrecorded one is what Reconcile calls key abuse.

// secretLedgerDB returns a config pointing at a fresh SQLite store, plus an
// open handle on it. commissioned pins an audit state, which is what
// hsmaudit.EnableRecording gates on.
func secretLedgerDB(t *testing.T, commissioned bool) (*config.Config, *database.DB) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "secret-ledger.db")
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if commissioned {
		if err := db.SaveAuditState(context.Background(), &hsmaudit.AuditState{
			DeviceSerial:  "31650425",
			Anchor:        "27caf4edc279c4b514bfc61fc6638677",
			ProvisionedAt: time.Now().UTC(),
			Tail:          hsmaudit.Tail{Number: 1, Digest: "27caf4edc279c4b514bfc61fc6638677"},
		}); err != nil {
			t.Fatalf("pinning the audit state: %v", err)
		}
	}

	cfg := &config.Config{}
	cfg.Database.Driver = "sqlite"
	cfg.Database.DSN = dsn
	return cfg, db
}

// resetLedgerState isolates a test from the package-level hooks the real run()
// installs once per process.
func resetLedgerState(t *testing.T) {
	t.Helper()
	prev := signatureRecorder
	hsmUsed.Store(false)
	t.Cleanup(func() {
		signatureRecorder = prev
		hsmUsed.Store(false)
	})
	signatureRecorder = nil
}

// startLedger installs the wiring and schedules its teardown with the drain
// suppressed.
//
// Suppressing it is the whole reason this helper exists. setupHSMLedger's
// teardown drains the device log through the native driver, which is correct in
// production and wrong in a unit test: these tests sign with a software
// provider, so letting the drain run would have `go test ./...` reach for
// whichever YubiHSM happens to be plugged into the machine — acknowledging, and
// thereby destroying, log entries belonging to whatever deployment owns it.
func startLedger(t *testing.T, cfg *config.Config) {
	t.Helper()
	teardown := setupHSMLedger(cfg)
	t.Cleanup(func() {
		hsmUsed.Store(false)
		teardown()
	})
}

// A deployment that never commissioned a device has no pinned anchor, so a
// ledger would reconcile against nothing. Recording must stay off and the
// provider must come back untouched — not merely unused, but unwrapped, so an
// ordinary software-backed secret store pays nothing at all.
func TestSecretLedgerIsOffWithoutACommissionedDevice(t *testing.T) {
	resetLedgerState(t)
	cfg, _ := secretLedgerDB(t, false)
	startLedger(t, cfg)

	if signatureRecorder != nil {
		t.Error("recording was enabled although no device is commissioned")
	}
	p := softwareProvider(t)
	if got := recordSignatures(p); got != p {
		t.Error("the provider was wrapped although recording is off")
	}
}

// Nor can a missing database turn into a failure: secsy-secret has always been
// usable with a bare KEK and no store, and the ledger lives in that store.
func TestSecretLedgerIsOffWithoutADatabase(t *testing.T) {
	resetLedgerState(t)

	startLedger(t, &config.Config{})

	if signatureRecorder != nil {
		t.Error("recording was enabled although no database is configured")
	}
}

// With a commissioned device the wrapper has to be installed *and* a signature
// through it has to land in the ledger. The second half is the one that
// matters: a wrapper that records nothing leaves exactly the unattributed
// device log entry the subsystem reads as abuse.
func TestSecretLedgerRecordsASignature(t *testing.T) {
	resetLedgerState(t)
	cfg, db := secretLedgerDB(t, true)
	startLedger(t, cfg)

	if signatureRecorder == nil {
		t.Fatal("recording is off although the device is commissioned")
	}

	ctx := context.Background()
	raw := softwareProvider(t)
	p := recordSignatures(raw)
	if p == raw {
		t.Fatal("the provider was not wrapped although recording is on")
	}
	// The secret layer unwraps data keys with an on-device RSA-OAEP decryption,
	// so losing the Decrypter capability to the wrapper would break every
	// `secsy-secret decrypt`. Record re-exposes it; check that it survived.
	if _, ok := p.(keyprovider.DecrypterProvider); !ok {
		if _, wasDecrypter := raw.(keyprovider.DecrypterProvider); wasDecrypter {
			t.Error("wrapping removed the Decrypter capability the secret layer needs")
		}
	}

	const label = "t202-secret-signing-key"
	if _, err := p.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyprovider.KeyTypeECDSAP256}); err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: label})
	if err != nil {
		t.Fatalf("opening a signer: %v", err)
	}
	defer func() { _ = signer.Close() }()
	digest := sha256.Sum256([]byte("secsy-secret sign"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("signing: %v", err)
	}

	ledger, err := db.Ledger(ctx)
	if err != nil {
		t.Fatalf("reading the ledger: %v", err)
	}
	if len(ledger) != 1 {
		t.Fatalf("the ledger holds %d row(s) after one secret-layer signature, want 1", len(ledger))
	}
	if got := ledger[0].KeyLabel; got != label {
		t.Errorf("the ledger row names key %q, want %q", got, label)
	}
	if want := hex.EncodeToString(digest[:]); ledger[0].Digest != want {
		t.Errorf("the ledger recorded digest %q, want %q — an auditor recomputes this from the "+
			"signed artifact, so a wrong value is worse than a missing row", ledger[0].Digest, want)
	}
	// Every operation also has to announce itself, so the device log entry it
	// produced gets drained before the 62-entry ring overflows.
	if !hsmUsed.Load() {
		t.Error("no operation was announced, so nothing would drain the device log entries they produced")
	}
}

func softwareProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	p, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
