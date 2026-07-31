package doctor

import (
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// TestDescribeBackendGCP verifies the doctor renders the Google Cloud KMS backend
// with its project/location/key-ring, so the keyprovider.<role> and kms.backend
// diagnostics name the concrete target rather than a generic "cloud KMS".
func TestDescribeBackendGCP(t *testing.T) {
	cfg := &config.Config{
		KeyProvider: config.KeyProviderConfig{
			Type: "kms",
			KMS: config.KMSProviderConfig{
				Backend: keyprovider.KMSBackendGCP,
				GCP: config.GCPProviderConfig{
					Project:  "my-proj",
					Location: "europe-west1",
					KeyRing:  "pki",
				},
			},
		},
	}
	got := describeBackend(cfg, string(keyprovider.ProviderKMS))
	for _, want := range []string{"Google Cloud KMS", "my-proj", "europe-west1", "pki"} {
		if !strings.Contains(got, want) {
			t.Errorf("describeBackend = %q, want it to contain %q", got, want)
		}
	}
}

// TestDescribeBackendGCPPinSourceExternal confirms a Google Cloud Secret Manager
// PIN source is classified as external, so the doctor pin.source check probes it
// for reachability rather than skipping it as an inline PIN.
func TestDescribeBackendGCPPinSourceExternal(t *testing.T) {
	for _, typ := range []string{"gcp", "gcpsm"} {
		if !keyprovider.PinSourceIsExternal(typ) {
			t.Errorf("pin_source type %q should be external", typ)
		}
	}
}
