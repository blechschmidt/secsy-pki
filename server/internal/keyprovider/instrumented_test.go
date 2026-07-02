package keyprovider

import (
	"context"
	"testing"
)

func TestSoftwareProviderPing(t *testing.T) {
	p, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Errorf("Ping on a valid keystore dir failed: %v", err)
	}
}

// TestInstrumentPreservesCapabilities ensures wrapping a provider keeps its
// Prober and DecrypterProvider capabilities reachable through the returned
// interface value — the readiness probe and envelope decryption rely on this.
func TestInstrumentPreservesCapabilities(t *testing.T) {
	base, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	wrapped := Instrument(base)

	prober, ok := wrapped.(Prober)
	if !ok {
		t.Fatal("wrapped provider does not expose Prober")
	}
	if err := prober.Ping(context.Background()); err != nil {
		t.Errorf("wrapped Ping failed: %v", err)
	}

	if _, ok := wrapped.(DecrypterProvider); !ok {
		t.Error("wrapped provider does not expose DecrypterProvider")
	}

	if got := wrapped.Name(); got != string(ProviderSoftware) {
		t.Errorf("Name() = %q, want %q", got, ProviderSoftware)
	}
}

func TestInstrumentNil(t *testing.T) {
	if Instrument(nil) != nil {
		t.Error("Instrument(nil) should return nil")
	}
}
