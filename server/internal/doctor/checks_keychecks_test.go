//go:build sqlite

package doctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// keyCheckResults runs checkKeyChecks and returns the two results by name.
func keyCheckResults(t *testing.T, cfg *config.Config, db *database.DB, schemaOK bool) (blocklist, profiles Result) {
	t.Helper()
	r := &Report{OK: true}
	checkKeyChecks(r, cfg, db, schemaOK)
	if len(r.Checks) != 2 {
		t.Fatalf("checkKeyChecks produced %d results, want 2: %+v", len(r.Checks), r.Checks)
	}
	for _, c := range r.Checks {
		switch c.Name {
		case "keychecks.blocklist":
			blocklist = c
		case "keychecks.profiles":
			profiles = c
		default:
			t.Fatalf("unexpected check %q", c.Name)
		}
	}
	return blocklist, profiles
}

func TestCheckKeyChecks_Blocklist(t *testing.T) {
	db, err := database.New("sqlite", t.TempDir()+"/kc.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	// No blocklist configured: pass, and it says the structural checks still run.
	bl, _ := keyCheckResults(t, &config.Config{}, db, true)
	if bl.Status != StatusPass {
		t.Fatalf("no-blocklist = %s (%s), want pass", bl.Status, bl.Detail)
	}

	// A valid blocklist file loads and the operator blocklist count is reported.
	dir := t.TempDir()
	file := filepath.Join(dir, "weak.txt")
	if err := os.WriteFile(file, []byte("0123456789abcdef0123456789abcdef01234567\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddBlockedKey(&models.BlockedKey{Fingerprint: "SHA256:x"}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.KeyChecks.WeakKeyBlocklistPaths = []string{file}
	bl, _ = keyCheckResults(t, cfg, db, true)
	if bl.Status != StatusPass {
		t.Fatalf("valid-blocklist = %s (%s), want pass", bl.Status, bl.Detail)
	}

	// A missing blocklist path is fatal at startup → the check fails.
	bad := &config.Config{}
	bad.KeyChecks.WeakKeyBlocklistPaths = []string{filepath.Join(dir, "does-not-exist")}
	bl, _ = keyCheckResults(t, bad, db, true)
	if bl.Status != StatusFail {
		t.Fatalf("missing-blocklist-path = %s, want fail (fail-closed)", bl.Status)
	}
}

func TestCheckKeyChecks_Profiles(t *testing.T) {
	db, err := database.New("sqlite", t.TempDir()+"/kc2.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	// All profiles enforce → pass.
	enforced := &config.Config{Profiles: []config.ProfileConfig{{Name: "a"}, {Name: "b"}}}
	if _, p := keyCheckResults(t, enforced, db, true); p.Status != StatusPass {
		t.Fatalf("all-enforced = %s (%s), want pass", p.Status, p.Detail)
	}

	// A disabled or warn-mode profile warns.
	weakened := &config.Config{Profiles: []config.ProfileConfig{
		{Name: "strict"},
		{Name: "loose", KeyChecks: config.ProfileKeyChecksConfig{Disabled: true}},
		{Name: "soft", KeyChecks: config.ProfileKeyChecksConfig{Mode: "warn"}},
	}}
	_, p := keyCheckResults(t, weakened, db, true)
	if p.Status != StatusWarn {
		t.Fatalf("weakened = %s, want warn", p.Status)
	}
}
