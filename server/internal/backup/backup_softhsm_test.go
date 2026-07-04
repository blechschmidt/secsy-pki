//go:build sqlite

package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"

	"os"
)

// softHSMProvider builds a PKCS#11 provider from the SECSY_* environment
// variables emitted by scripts/setup-softhsm.sh --export-env, skipping when
// SoftHSM is not configured so a plain `go test` stays green. It mirrors
// internal/secret's pkcs11Provider helper.
func softHSMProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: eval \"$(scripts/setup-softhsm.sh --export-env)\"")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
		ModulePath: module,
		Pin:        pin,
		TokenLabel: token,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func uniqueKEKLabel(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "backup-kek-" + hex.EncodeToString(b[:])
}

// TestScheduledBackupCycleSoftHSM runs the full backup cycle with the artifact
// encrypted under an RSA KEK on a real SoftHSM token — the DEK is unwrapped on
// the device (C_Decrypt), the KEK private key never leaves it — and verifies the
// published artifact decrypts and restores to a fingerprint-matching store. This
// exercises the exact HSM-backed encryption path the server uses in production.
func TestScheduledBackupCycleSoftHSM(t *testing.T) {
	ctx := context.Background()
	provider := softHSMProvider(t)

	kekLabel := uniqueKEKLabel(t)
	if _, err := secret.ProvisionKEK(ctx, provider, kekLabel, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("provision KEK on SoftHSM: %v", err)
	}

	db, _ := newTestDB(t)
	srcFP, err := db.VerifyStoreIntegrity()
	if err != nil {
		t.Fatalf("source fingerprint: %v", err)
	}

	store, err := publish.NewDirStore(t.TempDir(), 3)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(Source{DB: db, Provider: provider}, store, backupCfg(3, 0), kekLabel, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	runner.RunOnce(ctx)

	// Decrypt the published artifact via a ring bound to the SoftHSM KEK.
	blob, err := store.Fetch(ctx, ArtifactName)
	if err != nil {
		t.Fatalf("fetch artifact: %v", err)
	}
	if indexOf(blob, []byte("ciphertext")) < 0 || leaksPlaintext(blob) {
		t.Fatal("published artifact is not properly encrypted")
	}
	versions, err := db.ListKEKVersions(kekLabel)
	if err != nil {
		t.Fatalf("list KEK versions: %v", err)
	}
	ring, err := secret.LoadRing(ctx, provider, kekLabel, versions)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	archive, err := Decrypt(ctx, ring, blob)
	if err != nil {
		t.Fatalf("decrypt via SoftHSM KEK: %v", err)
	}

	// Restore and confirm the DR fingerprint matches the source.
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	if err := archive.RestoreSQLite(restoredPath); err != nil {
		t.Fatalf("restore sqlite: %v", err)
	}
	restored, err := database.OpenExisting("sqlite", restoredPath)
	if err != nil {
		t.Fatalf("open restored db: %v", err)
	}
	defer restored.Close()

	rfp, err := restored.VerifyStoreIntegrity()
	if err != nil {
		t.Fatalf("restored fingerprint: %v", err)
	}
	if !rfp.OK {
		t.Fatalf("restored store failed integrity: %+v", rfp.Checks)
	}
	if rfp.Fingerprint.AuditHeadHash != srcFP.Fingerprint.AuditHeadHash {
		t.Fatalf("restored audit head %s != source %s", rfp.Fingerprint.AuditHeadHash, srcFP.Fingerprint.AuditHeadHash)
	}
	if ca, err := restored.GetCA("root-ca"); err != nil || ca == nil {
		t.Fatalf("seeded CA missing from restored SoftHSM-encrypted backup: ca=%v err=%v", ca, err)
	}
}
