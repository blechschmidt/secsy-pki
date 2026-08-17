package publish

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func testArtifacts() []Artifact {
	return []Artifact{
		{Path: "ca-1/crl.der", Data: []byte("crl-bytes"), ContentType: "application/pkix-crl", Kind: KindCRL, NotAfter: time.Now().Add(48 * time.Hour)},
		{Path: "ca-1/chain.pem", Data: []byte("chain-bytes"), ContentType: "application/x-pem-file", Kind: KindChain},
		{Path: "ca-1/ocsp/by-serial/42.der", Data: []byte("ocsp-bytes"), ContentType: "application/ocsp-response", Kind: KindOCSP, NotAfter: time.Now().Add(time.Hour)},
	}
}

func testCAs() []ManifestCA {
	return []ManifestCA{{ID: "ca-1", Label: "test", OCSPResponses: 1}}
}

// TestDirStorePublishVerifySwap covers the directory backend end to end:
// layout under current/, manifest integrity via Verify, atomic re-publish
// (current flips), and snapshot pruning.
func TestDirStorePublishVerifySwap(t *testing.T) {
	root := t.TempDir()
	store, err := NewDirStore(root, 2)
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	pub := NewPublisher(store)
	ctx := context.Background()

	manifest, err := pub.Publish(ctx, testCAs(), testArtifacts())
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(manifest.Artifacts) != 3 {
		t.Fatalf("manifest has %d artifacts, want 3", len(manifest.Artifacts))
	}
	if manifest.EarliestExpiry == nil || time.Until(*manifest.EarliestExpiry) > 2*time.Hour {
		t.Fatalf("EarliestExpiry = %v, want the OCSP horizon (~1h)", manifest.EarliestExpiry)
	}

	// The published tree is reachable through the stable current/ path.
	got, err := os.ReadFile(filepath.Join(root, "current", "ca-1", "crl.der"))
	if err != nil || string(got) != "crl-bytes" {
		t.Fatalf("current/ca-1/crl.der = %q, %v", got, err)
	}
	if _, err := Verify(ctx, store); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Republishing flips current atomically and retains only `keep` snapshots.
	for i := 0; i < 3; i++ {
		arts := testArtifacts()
		arts[0].Data = []byte(fmt.Sprintf("crl-bytes-v%d", i))
		if _, err := pub.Publish(ctx, testCAs(), arts); err != nil {
			t.Fatalf("re-publish %d: %v", i, err)
		}
	}
	got, err = os.ReadFile(filepath.Join(root, "current", "ca-1", "crl.der"))
	if err != nil || string(got) != "crl-bytes-v2" {
		t.Fatalf("current after republish = %q, %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "snapshots"))
	if err != nil {
		t.Fatalf("reading snapshots: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("retained %d snapshots, want 2", len(entries))
	}
	// The live snapshot must be among the retained ones.
	live, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatalf("readlink current: %v", err)
	}
	found := false
	for _, e := range entries {
		if filepath.Join("snapshots", e.Name()) == live {
			found = true
		}
	}
	if !found {
		t.Fatalf("current -> %s not among retained snapshots", live)
	}
}

// TestVerifyDetectsCorruption flips a byte in a published artifact and expects
// the integrity check to fail loudly.
func TestVerifyDetectsCorruption(t *testing.T) {
	root := t.TempDir()
	store, err := NewDirStore(root, 2)
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	ctx := context.Background()
	if _, err := NewPublisher(store).Publish(ctx, testCAs(), testArtifacts()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	target := filepath.Join(root, "current", "ca-1", "crl.der")
	if err := os.WriteFile(target, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tampering: %v", err)
	}
	if _, err := Verify(ctx, store); err == nil {
		t.Fatal("Verify accepted a tampered artifact")
	} else if !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPublisherRejectsBadPaths ensures artifacts cannot escape the snapshot
// root or collide with the manifest.
func TestPublisherRejectsBadPaths(t *testing.T) {
	store, err := NewDirStore(t.TempDir(), 1)
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	pub := NewPublisher(store)
	for _, bad := range []string{"../escape", "/abs", "a/../../b", "manifest.json", "a//b", ""} {
		_, err := pub.Publish(context.Background(), nil, []Artifact{{Path: bad, Data: []byte("x")}})
		if err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
	// Duplicates are rejected too.
	if _, err := pub.Publish(context.Background(), nil, []Artifact{
		{Path: "a/b", Data: []byte("x")},
		{Path: "a/b", Data: []byte("y")},
	}); err == nil {
		t.Error("duplicate path accepted")
	}
}

// fakeS3 is an in-memory S3-compatible endpoint: PUT/GET on /<bucket>/<key>,
// MD5 ETags, and SigV4 header presence checks.
//
// Every field is guarded by mu, and the test body must reach them through the
// accessors below rather than touching them directly: a failed publish cancels
// its sibling uploads, so the handler goroutines serving those abandoned
// requests are still storing objects after Publish has returned to the test.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	badETag bool
	puts    int
}

// object reads a stored object, mirroring a map lookup.
func (f *fakeS3) object(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, ok := f.objects[key]
	return body, ok
}

// keys lists every stored key, sorted, for failure messages.
func (f *fakeS3) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// setBadETag makes subsequent PUTs answer with a wrong ETag, standing in for
// bit rot or a broken middlebox.
func (f *fakeS3) setBadETag(bad bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.badETag = bad
}

func (f *fakeS3) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
			t.Errorf("request not SigV4 signed: %q", auth)
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		if r.Header.Get("x-amz-content-sha256") == "" {
			t.Error("missing x-amz-content-sha256")
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			f.puts++
			f.objects[r.URL.Path] = body
			sum := md5.Sum(body)
			etag := hex.EncodeToString(sum[:])
			if f.badETag {
				etag = strings.Repeat("0", 32)
			}
			w.Header().Set("ETag", `"`+etag+`"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, ok := f.objects[r.URL.Path]
			if !ok {
				http.Error(w, "no such key", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}
}

// TestS3StorePublishVerify publishes to a fake S3-compatible endpoint and
// verifies key layout (bucket/prefix), manifest-last ordering guarantees via
// Verify, and the ETag integrity check.
func TestS3StorePublishVerify(t *testing.T) {
	fake := &fakeS3{objects: make(map[string][]byte)}
	ts := httptest.NewServer(fake.handler(t))
	defer ts.Close()

	ctx := context.Background()
	store, err := NewS3Store(ctx, S3Config{
		Endpoint:        ts.URL,
		Region:          "us-east-1",
		Bucket:          "pki",
		Prefix:          "rev/prod",
		AccessKeyID:     "test-access",
		SecretAccessKey: "test-secret",
		Concurrency:     4,
		HTTPClient:      ts.Client(),
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	manifest, err := NewPublisher(store).Publish(ctx, testCAs(), testArtifacts())
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(manifest.Artifacts) != 3 {
		t.Fatalf("manifest artifacts = %d, want 3", len(manifest.Artifacts))
	}

	// Keys are laid out under /<bucket>/<prefix>/.
	if _, ok := fake.object("/pki/rev/prod/ca-1/crl.der"); !ok {
		t.Fatalf("expected key /pki/rev/prod/ca-1/crl.der, have %v", fake.keys())
	}
	stored, ok := fake.object("/pki/rev/prod/manifest.json")
	if !ok {
		t.Fatalf("manifest not stored, have %v", fake.keys())
	}
	var m Manifest
	if err := json.Unmarshal(stored, &m); err != nil {
		t.Fatalf("stored manifest invalid: %v", err)
	}
	if _, err := Verify(ctx, store); err != nil {
		t.Fatalf("Verify over S3: %v", err)
	}

	// A backend returning a wrong ETag (bit rot, broken middlebox) fails the
	// publish rather than silently storing corrupt revocation data.
	fake.setBadETag(true)
	if _, err := NewPublisher(store).Publish(ctx, testCAs(), testArtifacts()); err == nil {
		t.Fatal("publish succeeded despite ETag mismatch")
	} else if !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestS3StoreManifestLast ensures no manifest is written when any artifact
// upload fails, so consumers keyed off the manifest never see a partial
// snapshot.
func TestS3StoreManifestLast(t *testing.T) {
	fake := &fakeS3{objects: make(map[string][]byte)}
	mux := http.NewServeMux()
	inner := fake.handler(t)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/chain.pem") {
			http.Error(w, "backend exploded", http.StatusBadRequest) // non-retryable
			return
		}
		inner(w, r)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx := context.Background()
	store, err := NewS3Store(ctx, S3Config{
		Endpoint:        ts.URL,
		Bucket:          "pki",
		AccessKeyID:     "a",
		SecretAccessKey: "s",
		HTTPClient:      ts.Client(),
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	if _, err := NewPublisher(store).Publish(ctx, testCAs(), testArtifacts()); err == nil {
		t.Fatal("publish succeeded despite a failed artifact upload")
	}
	if _, ok := fake.object("/pki/manifest.json"); ok {
		t.Fatal("manifest was written despite a failed artifact upload")
	}
}
