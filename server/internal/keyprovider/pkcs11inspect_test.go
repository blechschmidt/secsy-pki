package keyprovider

// Capability-plumbing tests for the PKCS#11 inspector. No token needed: what
// is asserted is which providers claim the capability and what the ones without
// it answer — the part that decides whether a console shows "this backend has
// no PKCS#11 view" or an empty object table that reads as an empty token.

import (
	"context"
	"errors"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// The software backend has no slots, no CKA_* and no object handles, so it must
// not claim the capability at all.
func TestSoftwareProviderIsNotAnInspector(t *testing.T) {
	p, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	defer p.Close()
	if _, ok := any(p).(PKCS11Inspector); ok {
		t.Error("the software provider claims a PKCS#11 view")
	}
}

// The wrappers must implement the capability unconditionally — otherwise
// wrapping a PKCS#11 provider (which every deployment does, at least for
// metrics) would silently remove the inspector. The cost of that is that the
// "no view" answer arrives as ErrInspectUnsupported from the call rather than
// as a failed type assertion, so callers have to recognise it.
func TestWrappersForwardTheCapabilityAndReportItsAbsence(t *testing.T) {
	soft, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	defer soft.Close()

	wrapped := map[string]Provider{
		"instrumented": Instrument(soft),
		"recording":    Record(soft, noopRecorder{}),
	}
	for name, p := range wrapped {
		t.Run(name, func(t *testing.T) {
			ins, ok := p.(PKCS11Inspector)
			if !ok {
				t.Fatalf("the %s wrapper does not implement PKCS11Inspector; wrapping a PKCS#11 provider would lose the inspector", name)
			}
			for _, call := range []struct {
				what string
				fn   func() ([]TokenView, error)
			}{
				{"module", func() ([]TokenView, error) {
					return ins.InspectPKCS11Module(context.Background(), pki.InspectOptions{})
				}},
				{"objects", func() ([]TokenView, error) { return ins.InspectPKCS11(context.Background(), pki.InspectOptions{}) }},
			} {
				views, err := call.fn()
				if !errors.Is(err, ErrInspectUnsupported) {
					t.Errorf("%s over a software backend: err = %v, want ErrInspectUnsupported", call.what, err)
				}
				if views != nil {
					t.Errorf("%s returned %d view(s) alongside the error; an empty view reads as an empty token", call.what, len(views))
				}
			}
		})
	}
}

// noopRecorder satisfies the ledger interface Record requires without storing
// anything: these tests exercise capability forwarding, not the ledger.
type noopRecorder struct{}

func (noopRecorder) RecordSignature(context.Context, SignatureRecord) error { return nil }

// A PKCS#11 provider claims the capability without needing a reachable token:
// the assertion is about the type, and the construction is lazy.
func TestPKCS11ProvidersClaimTheCapability(t *testing.T) {
	// A module path that does not exist is fine — nothing is loaded until the
	// first operation.
	p, err := NewPKCS11Provider(PKCS11Settings{ModulePath: "/nonexistent/module.so", Pin: "0000"})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	if _, ok := any(p).(PKCS11Inspector); !ok {
		t.Error("PKCS11Provider does not implement PKCS11Inspector")
	}
	if _, ok := Instrument(p).(PKCS11Inspector); !ok {
		t.Error("the instrumented wrapper around a PKCS#11 provider is not an inspector")
	}

	// The module view reports the module's own failure rather than a nil view,
	// so an operator with a mis-typed module_path is told that, which is the
	// case the module view exists to diagnose.
	views, err := p.InspectPKCS11Module(context.Background(), pki.InspectOptions{})
	if err == nil {
		t.Error("inspecting through a nonexistent module succeeded")
	}
	if views != nil {
		t.Errorf("got %d view(s) for an unloadable module", len(views))
	}
}
