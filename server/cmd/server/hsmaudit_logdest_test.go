//go:build sqlite

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// The configured destination for the device audit log is opened at startup
// whether or not the device has been commissioned.
//
// Before, it was opened inside the branch that builds the collector, which only
// runs once `hsm-audit provision` has pinned an anchor. A deployment that set
// the path — in the config file or, in a container, through
// SECSY_YUBIHSM_AUDIT_LOG_FILE — and commissioned the device later therefore
// learned about an unwritable path (a read-only mount, a volume owned by
// another uid, a typo) at the first drain rather than at the first boot. That
// is the worst possible moment: a force-audited device is by then minting log
// entries that have nowhere to go.
func TestAuditLogDestinationIsOpenedWithoutAProvisionedDevice(t *testing.T) {
	prevCol, prevRec := hsmAuditCollector, signatureRecorder
	t.Cleanup(func() { hsmAuditCollector, signatureRecorder = prevCol, prevRec })
	hsmAuditCollector, signatureRecorder = nil, nil

	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// No connector URL and no auth key id: warnUncollectedForcedAudit must not
	// go looking for whichever YubiHSM happens to be plugged into the machine
	// running the tests.
	path := filepath.Join(t.TempDir(), "audit", "device-log.jsonl")
	setupHSMAudit(&config.Config{YubiHSM: config.YubiHSMConfig{AuditLogFile: path}}, db)

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the configured audit-log destination was not created: %v", err)
	}
	// The header record, written by OpenLogFile, is what makes the file a
	// verifiable artifact from its first byte rather than an empty path.
	if st.Size() == 0 {
		t.Error("the destination was created but carries no header record")
	}
	if hsmAuditCollector != nil {
		t.Error("a collector was built for a device that has not been commissioned")
	}
}
