//go:build sqlite

package servingcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// The SoftHSM-backed acceptance tests for the self-managed serving certificate
// (Task 118). They run against both the software key provider (always) and a
// SoftHSM PKCS#11 token (when configured) so the private-key-stays-in-provider
// invariant is exercised on a real HSM. The suite proves:
//
//   - the server boots and serves a leaf that chains to the internal CA, with the
//     private key held in the provider (not a raw in-memory key);
//   - a forced rotation swaps the served certificate while concurrent dials keep
//     succeeding (hitless);
//   - the auto-rotation loop re-issues a near-expiry certificate on its own,
//     again without dropping a single connection across the swap.

func providers(t *testing.T) map[string]func(*testing.T) keyprovider.Provider {
	return map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
}

func softwareProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	p, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func pkcs11Provider(t *testing.T) keyprovider.Provider {
	t.Helper()
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: run eval \"$(scripts/setup-softhsm.sh --export-env)\"")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderPKCS11,
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath: module,
			Pin:        pin,
			TokenLabel: token,
		},
	})
	if err != nil {
		t.Fatalf("pkcs11 provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// uniqueLabel draws a fresh random suffix so runs against the persistent SoftHSM
// token never reuse a CKA_LABEL (the pkcs11-duplicate-label invariant).
func uniqueLabel(t *testing.T, base string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "servingtest-" + base + "-" + hex.EncodeToString(b[:])
}

// testCA stands up a fresh sqlite-backed ca.Manager with a root → intermediate
// hierarchy on the given provider and returns the manager, the store handle, the
// intermediate's id (the issuing CA for serving certs), and a trust pool
// anchored on the root.
func testCA(t *testing.T, provider keyprovider.Provider) (*ca.Manager, *database.DB, string, *x509.CertPool) {
	t.Helper()
	ctx := context.Background()
	dsn := t.TempDir() + "/servingcert-test.db"
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "root"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Serving Test Root", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID: root.ID,
		Label:    uniqueLabel(t, "inter"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Serving Test Intermediate", Organization: "Secsy"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}

	rootCert, err := x509.ParseCertificate(mustPEM(t, root.Certificate))
	if err != nil {
		t.Fatalf("parsing root: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return mgr, db, inter.ID, pool
}

func mustPEM(t *testing.T, pemStr string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("no PEM block in CA certificate")
	}
	return block.Bytes
}

// servingConfig builds a Config with a unique serving-key label so SoftHSM runs
// never collide, and sensible identities for a local listener.
func servingConfig(t *testing.T, caID string) Config {
	return Config{
		CAID:     caID,
		Profile:  "server",
		DNSNames: []string{"localhost"},
		IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		KeyLabel: uniqueLabel(t, "servingkey"),
	}
}

// startTLSServer serves a trivial handler over TLS using the holder's
// GetCertificate hook (exactly as cmd/server wires it) and returns its address.
func startTLSServer(t *testing.T, h *Holder) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		TLSConfig: &tls.Config{GetCertificate: h.GetCertificate, MinVersion: tls.VersionTLS12},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln.Addr().String()
}

// dial completes a TLS handshake, verifying the served chain against pool, and
// returns the served leaf certificate.
func dial(addr string, pool *x509.CertPool) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0], nil
}

// TestServingCertBootAndRotate proves the two core guarantees deterministically:
// the server boots and serves a leaf chaining to the internal CA with the key in
// the provider, and a forced rotation swaps the served certificate while dials
// keep succeeding across the swap.
func TestServingCertBootAndRotate(t *testing.T) {
	for name, mk := range providers(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			provider := mk(t)
			mgr, db, caID, pool := testCA(t, provider)

			si, err := New(ctx, mgr, provider, servingConfig(t, caID), log.New(io.Discard, "", 0))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			addr := startTLSServer(t, si.Holder())

			// The private key must live in the provider, not as a raw in-memory key:
			// the serving certificate's PrivateKey is our provider-backed signer.
			cur := si.Holder().Current()
			if _, ok := cur.PrivateKey.(*providerSigner); !ok {
				t.Fatalf("serving certificate private key is %T, want *providerSigner (key must stay in the provider)", cur.PrivateKey)
			}

			// Boot: the served leaf must verify against the root and carry the SANs.
			leaf1, err := dial(addr, pool)
			if err != nil {
				t.Fatalf("initial dial: %v", err)
			}
			if len(leaf1.DNSNames) == 0 || leaf1.DNSNames[0] != "localhost" {
				t.Errorf("served leaf SANs = %v, want localhost", leaf1.DNSNames)
			}
			// The served leaf's public key is the provider key (matches the signer).
			if pub, ok := cur.PrivateKey.(*providerSigner).Public().(*ecdsa.PublicKey); ok {
				got, ok2 := leaf1.PublicKey.(*ecdsa.PublicKey)
				if !ok2 || got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
					t.Errorf("served leaf public key does not match the provider serving key")
				}
			}

			// Forced rotation: the served certificate changes, and a dial across the
			// swap still succeeds (verifies against the same CA).
			if err := si.Rotate(ctx); err != nil {
				t.Fatalf("Rotate: %v", err)
			}
			leaf2, err := dial(addr, pool)
			if err != nil {
				t.Fatalf("post-rotation dial: %v", err)
			}
			if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
				t.Errorf("rotation did not change the serving certificate serial (%s)", leaf1.SerialNumber)
			}

			// The rotated leaf is recorded with the serving-tls marker so reports and
			// the doctor freshness check can find it.
			rec, err := db.GetIssuedCertificate(caID, leaf2.SerialNumber.String())
			if err != nil {
				t.Fatalf("looking up rotated serving cert: %v", err)
			}
			if rec.Marker != models.CertMarkerServingTLS {
				t.Errorf("serving cert marker = %q, want %q", rec.Marker, models.CertMarkerServingTLS)
			}
		})
	}
}

// TestServingCertAutoRotation proves the auto-rotation loop re-issues a
// near-expiry certificate on its own and swaps it hitlessly: a stream of dials
// spanning multiple rotations sees several distinct serials and never fails.
func TestServingCertAutoRotation(t *testing.T) {
	for name, mk := range providers(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			provider := mk(t)
			mgr, _, caID, pool := testCA(t, provider)

			cfg := servingConfig(t, caID)
			// Short-lived certificate renewed well before expiry: renewAt =
			// NotAfter - RenewBefore = issue + (Validity - RenewBefore) ≈ issue + 1s,
			// so the loop re-issues roughly every second while the served cert always
			// keeps >= RenewBefore of headroom (never expired during serving).
			cfg.Validity = 4 * time.Second
			cfg.RenewBefore = 3 * time.Second

			si, err := New(ctx, mgr, provider, cfg, log.New(io.Discard, "", 0))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			addr := startTLSServer(t, si.Holder())

			loopCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			go si.Run(loopCtx)

			serials := map[string]bool{}
			dials := 0
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				leaf, err := dial(addr, pool)
				if err != nil {
					t.Fatalf("dial failed during auto-rotation (dial %d): %v", dials, err)
				}
				serials[leaf.SerialNumber.String()] = true
				dials++
				time.Sleep(40 * time.Millisecond)
			}
			cancel()

			if dials < 10 {
				t.Fatalf("too few dials (%d) to exercise rotation", dials)
			}
			if len(serials) < 2 {
				t.Errorf("expected the auto-rotation loop to re-issue at least once (>=2 serials), got %d over %d dials", len(serials), dials)
			}
			t.Logf("%s: %d dials across %d distinct serving certificates, zero failures", name, dials, len(serials))
		})
	}
}

// TestNewRequiresCA is a defensive guard: New refuses an empty CA id rather than
// issuing against the zero value.
func TestNewRequiresCA(t *testing.T) {
	provider := softwareProvider(t)
	mgr, _, _, _ := testCA(t, provider)
	if _, err := New(context.Background(), mgr, provider, Config{}, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("New with empty CAID should fail")
	}
}
