package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// testCA is a lightweight in-memory CA for unit tests (no HSM, no database).
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	return &testCA{key: key, cert: cert}
}

// issueOpts tweaks a test issuance.
type issueOpts struct {
	notBefore, notAfter time.Time
	serial              int64
}

// issue signs a leaf for the CSR's subject and SANs.
func (ca *testCA) issue(t *testing.T, csr *x509.CertificateRequest, opts issueOpts) *x509.Certificate {
	t.Helper()
	if opts.serial == 0 {
		opts.serial = time.Now().UnixNano()
	}
	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Minute)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = opts.notBefore.Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(opts.serial),
		Subject:        csr.Subject,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		NotBefore:      opts.notBefore,
		NotAfter:       opts.notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issuing leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	return cert
}

// issueFor signs a leaf for a public key with explicit names (no CSR).
func (ca *testCA) issueFor(t *testing.T, pub crypto.PublicKey, cn string, dnsNames []string, opts issueOpts) *x509.Certificate {
	t.Helper()
	csr := &x509.CertificateRequest{
		Subject:   pkix.Name{CommonName: cn},
		DNSNames:  dnsNames,
		PublicKey: pub,
	}
	return ca.issue(t, csr, opts)
}

// pemFile writes PEM material to a temp file and returns its path.
func pemFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// fakeEST implements just enough of RFC 7030 for client tests: Basic-auth
// checked simpleenroll/simplereenroll and cacerts, both returning base64
// certs-only PKCS#7 like the real server.
type fakeEST struct {
	ca       *testCA
	username string
	password string
	// validity of issued leaves.
	validity time.Duration
	// enrolls counts issuance calls per endpoint.
	enrolls, reenrolls int
}

func (f *fakeEST) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/est/cacerts", func(w http.ResponseWriter, r *http.Request) {
		writeCertsOnly(t, w, []*x509.Certificate{f.ca.cert})
	})
	enroll := func(reenroll bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != f.username || pass != f.password {
				w.Header().Set("WWW-Authenticate", `Basic realm="est"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read error", http.StatusBadRequest)
				return
			}
			der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
			if err != nil {
				http.Error(w, "bad base64", http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				http.Error(w, "bad csr", http.StatusBadRequest)
				return
			}
			if err := csr.CheckSignature(); err != nil {
				http.Error(w, "bad csr signature", http.StatusBadRequest)
				return
			}
			validity := f.validity
			if validity == 0 {
				validity = 24 * time.Hour
			}
			now := time.Now().Add(-time.Minute)
			leaf := f.ca.issue(t, csr, issueOpts{notBefore: now, notAfter: now.Add(validity)})
			if reenroll {
				f.reenrolls++
			} else {
				f.enrolls++
			}
			writeCertsOnly(t, w, []*x509.Certificate{leaf})
		}
	}
	mux.HandleFunc("POST /.well-known/est/simpleenroll", enroll(false))
	mux.HandleFunc("POST /.well-known/est/simplereenroll", enroll(true))
	return mux
}

// writeCertsOnly mirrors the real EST server's response encoding: base64
// (line-wrapped) certs-only PKCS#7.
func writeCertsOnly(t *testing.T, w http.ResponseWriter, certs []*x509.Certificate) {
	der, err := cms.DegenerateCertsOnly(certs)
	if err != nil {
		t.Errorf("building certs-only PKCS#7: %v", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	for len(b64) > 64 {
		w.Write([]byte(b64[:64] + "\r\n")) //nolint:errcheck
		b64 = b64[64:]
	}
	w.Write([]byte(b64 + "\r\n")) //nolint:errcheck
}

// newESTAgent builds an Agent configured against a fake EST server with a
// file trust bundle, one EST cert spec, and an isolated state dir.
func newESTAgent(t *testing.T, fake *fakeEST, mutate func(*Config)) (*Agent, *CertSpec, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(fake.handler(t))
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	bundlePath := pemFile(t, dir, "trust.pem", encodeChainPEM([]*x509.Certificate{fake.ca.cert}))
	spec := &CertSpec{
		Name:     "web",
		Enroll:   EnrollEST,
		DNSNames: []string{"web.example.test"},
		KeyFile:  filepath.Join(dir, "web.key"),
		CertFile: filepath.Join(dir, "web.crt"),
	}
	cfg := &Config{
		StateDir: filepath.Join(dir, "state"),
		Trust:    TrustConfig{BundleFile: bundlePath},
		EST: ESTConfig{
			URL:      ts.URL + "/.well-known/est",
			Username: fake.username,
			Password: fake.password,
		},
		Certificates: []*CertSpec{spec},
	}
	cfg.applyDefaults()
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { a.Close() }) //nolint:errcheck
	return a, spec, ts
}
