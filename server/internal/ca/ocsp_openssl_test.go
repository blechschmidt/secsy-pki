//go:build sqlite

package ca

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestOCSPOpenSSLInterop verifies our OCSP responses against the reference
// `openssl ocsp` client: it generates a nonce-bearing request with openssl,
// feeds the DER to our responder, and asks openssl to verify the signed
// response (signature, certID match, status, and — crucially — that the echoed
// response-level nonce matches the request nonce). This is the authoritative
// interop check that our hand-built response with response-level response
// extensions is wire-correct, since golang.org/x/crypto/ocsp does not surface
// those extensions. It runs both the CA-signed and delegated-responder paths.
func TestOCSPOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}

	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "ocsp-openssl")
	leaf := issueLeaf(t, mgr, root.ID, "openssl.example.com")

	dir := t.TempDir()
	caPEM := filepath.Join(dir, "ca.pem")
	leafPEM := filepath.Join(dir, "leaf.pem")
	writeFile(t, caPEM, []byte(root.Certificate))
	writeFile(t, leafPEM, pki.EncodeCertificatePEM(leaf.Certificate.Raw))

	// openssl builds an OCSP request (nonce included by default) for the leaf.
	reqDER := filepath.Join(dir, "req.der")
	run(t, openssl, "ocsp", "-issuer", caPEM, "-sha1", "-cert", leafPEM, "-reqout", reqDER)

	reqBytes, err := os.ReadFile(reqDER)
	if err != nil {
		t.Fatalf("reading request: %v", err)
	}
	// Confirm openssl actually included a nonce so the interop check is meaningful.
	reqNonce, err := pki.ExtractOCSPNonce(reqBytes)
	if err != nil {
		t.Fatalf("ExtractOCSPNonce: %v", err)
	}
	if len(reqNonce) == 0 {
		t.Fatal("openssl request carried no nonce; cannot verify nonce interop")
	}

	cases := []struct {
		name      string
		delegated bool
	}{
		{"ca-signed", false},
		{"delegated", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := OCSPRespondOptions{Nonce: reqNonce}
			if tc.delegated {
				cache := NewDelegatedResponderCache(0, "")
				cert, ref, err := cache.Responder(ctx, mgr, root.ID)
				if err != nil {
					t.Fatalf("delegated Responder: %v", err)
				}
				opts.Responder = cert
				opts.ResponderKeyRef = &ref
			}
			respDER, err := mgr.OCSPRespondWithOptions(ctx, root.ID, reqBytes, opts)
			if err != nil {
				t.Fatalf("OCSPRespondWithOptions: %v", err)
			}
			respPath := filepath.Join(dir, tc.name+"-resp.der")
			writeFile(t, respPath, respDER)

			// openssl verifies signature + certID + status, and (because we pass
			// both -reqin and -respin) checks the nonce matches.
			out := runCombined(t, openssl, "ocsp",
				"-reqin", reqDER,
				"-respin", respPath,
				"-issuer", caPEM,
				"-CAfile", caPEM,
				"-VAfile", caPEM,
			)
			if !strings.Contains(out, "Response verify OK") {
				t.Errorf("openssl did not confirm response verification:\n%s", out)
			}
			// Confirm the status the responder attested to. openssl only prints a
			// per-serial status line when -cert is given (not with -reqin), so the
			// status is checked with a second openssl invocation that supplies the
			// leaf certificate.
			statusOut := runCombined(t, openssl, "ocsp",
				"-respin", respPath, "-issuer", caPEM, "-cert", leafPEM,
				"-CAfile", caPEM, "-VAfile", caPEM, "-no_nonce",
			)
			if !strings.Contains(statusOut, ": good") {
				t.Errorf("openssl did not report 'good' status:\n%s", statusOut)
			}
			// A nonce mismatch makes openssl print "Nonce Verify error"; its
			// absence (plus verify OK) means the echoed nonce matched.
			if strings.Contains(out, "Nonce Verify error") || strings.Contains(out, "nonce values do not match") {
				t.Errorf("openssl reported a nonce mismatch:\n%s", out)
			}
			if strings.Contains(out, "WARNING: no nonce in response") {
				t.Errorf("response omitted the nonce (openssl warning):\n%s", out)
			}
		})
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func runCombined(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput() // openssl exits non-zero on verify failure; inspect text
	return string(out)
}
