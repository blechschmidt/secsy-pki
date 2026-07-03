//go:build sqlite

package est

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
)

// makeEmailCSRDER builds a DER CSR with an rfc822Name SAN on a fresh RSA key
// (the built-in smime dual-use profile expects RSA subject keys).
func makeEmailCSRDER(t *testing.T, cn string, emails []string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		EmailAddresses: emails,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestEST_SMIMEEnroll proves the EST enrollment path honors an S/MIME profile
// (Task 66): a mailbox CSR enrolls with normalized rfc822Name SANs and the
// emailProtection EKU, while a SAN-less request is blocked by the pre-issuance
// lint gate before anything is signed.
func TestEST_SMIMEEnroll(t *testing.T) {
	_, ts, caCert := newTestEST(t, Config{
		Users: map[string]User{"mailer": {Password: "pw", Profile: "smime"}},
	}, false)

	enroll := func(csrDER []byte) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simpleenroll",
			strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
		req.Header.Set("Content-Type", "application/pkcs10")
		req.SetBasicAuth("mailer", "pw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}

	// Mailbox CSR (unnormalized domain case) enrolls under the smime profile.
	resp, body := enroll(makeEmailCSRDER(t, "Mail Device", []string{"device@MAIL.Example.COM"}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("smime enrollment status %d: %s", resp.StatusCode, body)
	}
	leaf := parseEnrollResponse(t, body)
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
	if len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "device@mail.example.com" {
		t.Fatalf("SAN = %v, want the normalized [device@mail.example.com]", leaf.EmailAddresses)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageEmailProtection {
		t.Fatalf("EKU = %v, want exactly emailProtection", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Fatalf("KU = %v, want digitalSignature|keyEncipherment", leaf.KeyUsage)
	}

	// A SAN-less CSR is rejected by the S/MIME lint gate, fail-closed.
	resp, body = enroll(makeEmailCSRDER(t, "no-mailbox-device", nil))
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("SAN-less enrollment should be rejected, got 200: %s", body)
	}
}
