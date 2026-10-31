package keyprovider

// The PKCS#11 inspector through the provider layer, against SoftHSM.
//
// internal/pki proves the Cryptoki reading itself. What can only be proven here
// is the plumbing an operator actually goes through: the view survives the
// wrappers every deployment installs, an HA set reports one view per replica
// rather than one view of whichever replica answered, and an object dump
// prompts the device-log drain the force-audit path depends on.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// softhsmInspectSettings builds PKCS11Settings from the SECSY_* variables
// scripts/setup-softhsm.sh --export-env emits, skipping without a token.
func softhsmInspectSettings(t *testing.T) PKCS11Settings {
	t.Helper()
	module, token := os.Getenv("SECSY_PKCS11_MODULE"), os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL " +
			"(run: eval \"$(scripts/setup-softhsm.sh --export-env)\")")
	}
	return PKCS11Settings{
		ModulePath:      module,
		TokenLabel:      token,
		Pin:             envOr("SECSY_USER_PIN", "1234"),
		SessionPoolSize: 1,
	}
}

// The inspector must survive the wrapper stack a real server builds:
// Instrument for metrics, and Record for the signature ledger.
func TestInspectThroughTheWrapperStack(t *testing.T) {
	s := softhsmInspectSettings(t)
	base, err := NewPKCS11Provider(s)
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	var drains int
	stack := Record(Instrument(base), noopRecorder{}, OnOperation(func() { drains++ }))
	ins, ok := stack.(PKCS11Inspector)
	if !ok {
		t.Fatal("the wrapped provider is not an inspector")
	}

	// The module view is session-free, so it must NOT look like a device
	// operation: nothing was asked of the token, and prompting a device-log
	// drain for it would be noise.
	views, err := ins.InspectPKCS11Module(context.Background(), pki.InspectOptions{SkipMechanisms: true})
	if err != nil {
		t.Fatalf("InspectPKCS11Module: %v", err)
	}
	if len(views) != 1 || views[0].Module == nil {
		t.Fatalf("module view = %+v", views)
	}
	if views[0].Module.LibraryDescription == "" {
		t.Error("the module view came back without C_GetInfo data")
	}
	if drains != 0 {
		t.Errorf("the module view prompted %d device-log drain(s); it opens no session", drains)
	}

	// The object dump IS a sequence of device commands — C_FindObjects is the
	// YubiHSM's own ListObjects, and every attribute read is a GetObjectInfo —
	// so on a force-audited device it consumes log entries and has to prompt
	// the same drain a signature does. A full device log is a device that
	// refuses to sign.
	views, err = ins.InspectPKCS11(context.Background(), pki.InspectOptions{MaxObjects: 5, SkipMechanisms: true})
	if err != nil {
		t.Fatalf("InspectPKCS11: %v", err)
	}
	if len(views) != 1 || views[0].Objects == nil {
		t.Fatalf("object view = %+v", views)
	}
	if len(views[0].Objects.Objects) == 0 {
		t.Error("no objects enumerated through the wrapper stack")
	}
	if drains != 1 {
		t.Errorf("an object dump prompted %d device-log drain(s), want exactly 1", drains)
	}
	// A single-token deployment names no member and reports no rotation health.
	if views[0].Token != "" || views[0].Healthy != nil {
		t.Errorf("a single-token view carries HA fields: %+v", views[0])
	}
}

// An HA set must report every replica, named, with its rotation health —
// because replicas deliberately share key labels, so a view that merged them
// (or answered from whichever token was healthy) could not tell an operator
// WHICH device holds an object. Inspection is the one operation that must not
// fail over.
func TestInspectHASetReportsEveryReplica(t *testing.T) {
	s := softhsmInspectSettings(t)
	if os.Getenv("SOFTHSM2_CONF") == "" {
		t.Skip("SOFTHSM2_CONF not set; cannot create matching HA tokens (run setup-softhsm.sh --export-env)")
	}
	pin, soPin := envOr("SECSY_USER_PIN", "1234"), envOr("SECSY_SO_PIN", "5678")
	suffix := randSuffix(t)
	labelA, labelB := "insp-tokA-"+suffix, "insp-tokB-"+suffix
	initToken(t, labelA, pin, soPin)
	initToken(t, labelB, pin, soPin)
	t.Cleanup(func() { deleteToken(labelA) })
	t.Cleanup(func() { deleteToken(labelB) })

	p, err := NewPKCS11HAProvider(PKCS11Settings{
		ModulePath:       s.ModulePath,
		Pin:              pin,
		SelectionPolicy:  string(PolicyPrimaryBackup),
		FailureThreshold: 1,
		ProbeInterval:    time.Hour, // no background probing during the test
		SessionPoolSize:  1,
		Tokens: []TokenSettings{
			{Name: "primary-" + suffix, TokenLabel: labelA},
			{Name: "standby-" + suffix, TokenLabel: labelB},
		},
	})
	if err != nil {
		t.Fatalf("NewPKCS11HAProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	views, err := p.InspectPKCS11(context.Background(), pki.InspectOptions{SkipMechanisms: true})
	if err != nil {
		t.Fatalf("InspectPKCS11: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("got %d view(s) for a two-token set", len(views))
	}
	for i, v := range views {
		if v.Token != p.TokenName(i) {
			t.Errorf("view %d names token %q, want %q (configured order)", i, v.Token, p.TokenName(i))
		}
		if v.Healthy == nil {
			t.Errorf("view %d reports no rotation health", i)
		}
		if v.Error != "" {
			t.Errorf("view %d failed: %s", i, v.Error)
		}
		if v.Objects == nil || v.Module == nil {
			t.Fatalf("view %d is incomplete: %+v", i, v)
		}
	}
	// The two views must describe different tokens — the whole point.
	if a, b := views[0].Objects.TokenLabel, views[1].Objects.TokenLabel; a == b {
		t.Errorf("both views describe token %q; the replicas were not told apart", a)
	}

	// A replica that cannot be reached becomes a view carrying its error, not a
	// failed request: a degraded set still owes the operator the other token's
	// contents, and which one is down.
	p.FailTokenForTest(0, true)
	t.Cleanup(func() { p.FailTokenForTest(0, false) })
	views, err = p.InspectPKCS11(context.Background(), pki.InspectOptions{SkipMechanisms: true})
	if err != nil {
		t.Fatalf("InspectPKCS11 with one token down: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("got %d view(s) with one token down", len(views))
	}
	if views[1].Error != "" || views[1].Objects == nil {
		t.Errorf("the healthy replica's view was lost: %+v", views[1])
	}
}
