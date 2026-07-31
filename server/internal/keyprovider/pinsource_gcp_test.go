package keyprovider

import (
	"context"
	"strings"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeGCPSecretsClient is an in-memory Google Cloud Secret Manager double: it
// serves secret payloads by resource name and returns gRPC NotFound for anything
// else, so the gcpPinSource fail-closed paths are exercised without cloud access.
type fakeGCPSecretsClient struct {
	secrets map[string][]byte
}

func (f *fakeGCPSecretsClient) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	data, ok := f.secrets[req.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "secret version %q not found", req.GetName())
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Name:    req.GetName(),
		Payload: &secretmanagerpb.SecretPayload{Data: data},
	}, nil
}

func (f *fakeGCPSecretsClient) Close() error { return nil }

var _ gcpSecretsClient = (*fakeGCPSecretsClient)(nil)

// newFakeGCPPinSource builds a gcpPinSource wired to an injected fake client.
func newFakeGCPPinSource(t *testing.T, settings GCPPinSourceSettings, secrets map[string][]byte) *gcpPinSource {
	t.Helper()
	src, err := newGCPPinSource(settings)
	if err != nil {
		t.Fatalf("newGCPPinSource: %v", err)
	}
	gs := src.(*gcpPinSource)
	gs.client = &fakeGCPSecretsClient{secrets: secrets}
	return gs
}

func TestGCPPinSource(t *testing.T) {
	const name = "projects/proj/secrets/hsm-pin/versions/latest"
	src := newFakeGCPPinSource(t, GCPPinSourceSettings{Project: "proj", Secret: "hsm-pin"}, map[string][]byte{
		name: []byte("gcppin\n"),
	})
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "gcppin" { // trailing newline trimmed by extractPin
		t.Errorf("got %q, want gcppin", got)
	}
	// Both aliases select the GCP source and are external.
	for _, typ := range []string{"gcp", "gcpsm"} {
		if !pinSourceIsExternal(typ) {
			t.Errorf("type %q should be external", typ)
		}
		if _, err := newPinSource(PinSourceSettings{Type: typ, GCP: GCPPinSourceSettings{Project: "proj", Secret: "hsm-pin"}}, ""); err != nil {
			t.Errorf("newPinSource(%q): %v", typ, err)
		}
	}
	if !strings.Contains(src.Describe(), "secretmanager") {
		t.Errorf("describe %q lacks secretmanager", src.Describe())
	}
}

func TestGCPPinSourceJSONField(t *testing.T) {
	const name = "projects/proj/secrets/hsm/versions/3"
	src := newFakeGCPPinSource(t, GCPPinSourceSettings{Project: "proj", Secret: "hsm", Version: "3", Field: "pin"}, map[string][]byte{
		name: []byte(`{"pin":"json-pin","other":"x"}`),
	})
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "json-pin" {
		t.Errorf("got %q, want json-pin", got)
	}
}

func TestGCPPinSourceMissingAndEmpty(t *testing.T) {
	// A resource name that is not present fails closed.
	missing := newFakeGCPPinSource(t, GCPPinSourceSettings{Project: "proj", Secret: "absent"}, map[string][]byte{})
	if _, err := missing.Resolve(context.Background()); err == nil {
		t.Error("expected error for missing secret")
	}

	// An empty payload fails closed.
	const name = "projects/proj/secrets/empty/versions/latest"
	empty := newFakeGCPPinSource(t, GCPPinSourceSettings{Project: "proj", Secret: "empty"}, map[string][]byte{name: {}})
	if _, err := empty.Resolve(context.Background()); err == nil {
		t.Error("expected error for empty payload")
	}
}

func TestGCPPinSourceFullResourceName(t *testing.T) {
	// A full resource name (with a pinned version) is honored verbatim.
	const name = "projects/p/secrets/s/versions/7"
	src := newFakeGCPPinSource(t, GCPPinSourceSettings{Secret: name}, map[string][]byte{name: []byte("full")})
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "full" {
		t.Errorf("got %q, want full", got)
	}
}

func TestGCPSecretResourceName(t *testing.T) {
	for _, tc := range []struct {
		project, secret, version, want, errsub string
	}{
		{"p", "s", "", "projects/p/secrets/s/versions/latest", ""},
		{"p", "s", "5", "projects/p/secrets/s/versions/5", ""},
		{"", "projects/p/secrets/s", "9", "projects/p/secrets/s/versions/9", ""},
		{"", "projects/p/secrets/s/versions/2", "9", "projects/p/secrets/s/versions/2", ""},
		{"", "s", "", "", "project is required"},
		{"p", "", "", "", "secret is required"},
	} {
		got, err := gcpSecretResourceName(tc.project, tc.secret, tc.version)
		if tc.errsub != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errsub) {
				t.Errorf("gcpSecretResourceName(%q,%q,%q) err = %v, want containing %q", tc.project, tc.secret, tc.version, err, tc.errsub)
			}
			continue
		}
		if err != nil {
			t.Errorf("gcpSecretResourceName(%q,%q,%q): %v", tc.project, tc.secret, tc.version, err)
		}
		if got != tc.want {
			t.Errorf("gcpSecretResourceName(%q,%q,%q) = %q, want %q", tc.project, tc.secret, tc.version, got, tc.want)
		}
	}
}
