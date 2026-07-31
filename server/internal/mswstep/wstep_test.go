//go:build sqlite

package mswstep

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestRST_Issue drives a PKCS#10 -> issued-certificate round trip through the
// MS-WSTEP RequestSecurityToken endpoint against both the software provider and,
// when configured, SoftHSM, and checks the SOAP framing and that the issued leaf
// chains to the CA.
func TestRST_Issue(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t, mk(t), "", nil)
			secret := env.mintToken(t, models.DefaultTenantID, models.TokenScopeTenant, "issuer")

			_, csrDER := makeCSR(t, "win-machine-1")
			const msgID = "urn:uuid:22222222-2222-2222-2222-222222222222"
			body := rstEnvelope(msgID, base64.StdEncoding.EncodeToString(csrDER), "")
			status, respBody := postSOAP(t, env.ts.URL+"/mswstep/enroll", body, tokenAuth(secret))
			if status != 200 {
				t.Fatalf("status = %d, want 200\n%s", status, respBody)
			}

			// SOAP framing: RSTRC action, echoed MessageID.
			if !strings.Contains(string(respBody), actionRSTRC) {
				t.Errorf("response missing RSTRC action")
			}
			rstr := parseRSTR(t, respBody)
			if rstr.Header.RelatesTo != msgID {
				t.Errorf("RelatesTo = %q, want %q", rstr.Header.RelatesTo, msgID)
			}
			if rstr.Body.Coll.Resp.TokenType != valueTypePKCS7 {
				t.Errorf("TokenType = %q, want %q", rstr.Body.Coll.Resp.TokenType, valueTypePKCS7)
			}
			if rstr.Body.Coll.Resp.RequestID == "" {
				t.Error("RSTR carried no RequestID")
			}

			leaf := rstr.issuedCert(t)
			if leaf.Subject.CommonName != "win-machine-1" {
				t.Errorf("issued CN = %q, want win-machine-1", leaf.Subject.CommonName)
			}
			// The leaf must chain to (be signed by) the issuing CA.
			if err := leaf.CheckSignatureFrom(env.rootCert); err != nil {
				t.Errorf("issued leaf does not chain to CA: %v", err)
			}
			// It was recorded in inventory (so revocation/renewal work).
			if rec, err := env.db.GetIssuedCertificate(env.caID, leaf.SerialNumber.String()); err != nil || rec == nil {
				t.Errorf("issued certificate not recorded in inventory (err=%v)", err)
			}
		})
	}
}

// TestRST_TemplateMapping verifies the requested template selects the mapped
// issuance profile, whether it is named in the CSR (V1 name / V2 OID) or the RST
// AdditionalContext. The "server" profile yields serverAuth; "client" yields
// clientAuth, so the resolved profile is observable in the issued EKUs.
func TestRST_TemplateMapping(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", nil)
	secret := env.mintToken(t, models.DefaultTenantID, models.TokenScopeTenant, "issuer")

	// The "server" template maps to the server profile; find its synthesized OID.
	serverOID := ""
	for _, tmpl := range env.srv.templates {
		if tmpl.profile == "server" {
			serverOID = tmpl.oid
		}
	}
	if serverOID == "" {
		t.Fatal("server template not built")
	}

	cases := []struct {
		name    string
		exts    []pkix.Extension
		context string
		wantEKU x509.ExtKeyUsage
	}{
		{
			name:    "csr_template_name",
			exts:    []pkix.Extension{templateNameExtension(t, "SecsyWebServer")},
			wantEKU: x509.ExtKeyUsageServerAuth,
		},
		{
			name:    "csr_template_oid",
			exts:    []pkix.Extension{templateOIDExtension(t, serverOID)},
			wantEKU: x509.ExtKeyUsageServerAuth,
		},
		{
			name:    "rst_context_name",
			context: "SecsyWebServer",
			wantEKU: x509.ExtKeyUsageServerAuth,
		},
		{
			name:    "default_profile",
			wantEKU: x509.ExtKeyUsageClientAuth, // default profile is "client"
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, csrDER := makeCSRWithExtensions(t, "mapped-"+tc.name, tc.exts)
			body := rstEnvelope("urn:uuid:"+tc.name, base64.StdEncoding.EncodeToString(csrDER), tc.context)
			status, respBody := postSOAP(t, env.ts.URL+"/mswstep/enroll", body, tokenAuth(secret))
			if status != 200 {
				t.Fatalf("status = %d, want 200\n%s", status, respBody)
			}
			leaf := parseRSTR(t, respBody).issuedCert(t)
			if !hasEKU(leaf, tc.wantEKU) {
				t.Errorf("issued cert EKUs = %v, want to include %v", leaf.ExtKeyUsage, tc.wantEKU)
			}
		})
	}
}

func hasEKU(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, e := range cert.ExtKeyUsage {
		if e == want {
			return true
		}
	}
	return false
}

// TestRST_Unauthenticated verifies the enrollment endpoint fails closed without a
// credential.
func TestRST_Unauthenticated(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", nil)
	_, csrDER := makeCSR(t, "noauth")
	body := rstEnvelope("urn:uuid:na", base64.StdEncoding.EncodeToString(csrDER), "")

	status, _ := postSOAP(t, env.ts.URL+"/mswstep/enroll", body, "")
	if status != 401 {
		t.Errorf("no-credential status = %d, want 401", status)
	}
	status, _ = postSOAP(t, env.ts.URL+"/mswstep/enroll", body, tokenAuth("secsy_pat_nope"))
	if status != 401 {
		t.Errorf("bad-token status = %d, want 401", status)
	}
}

// TestRST_InsufficientRole verifies an authenticated caller lacking the cert:issue
// capability is refused (authenticated but not authorized) — a fail-closed path
// distinct from the unauthenticated 401.
func TestRST_InsufficientRole(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", nil)
	// An auditor token authenticates but holds no cert:issue capability.
	secret := env.mintToken(t, models.DefaultTenantID, models.TokenScopeTenant, "auditor")
	_, csrDER := makeCSR(t, "auditor-cannot-enroll")
	body := rstEnvelope("urn:uuid:role", base64.StdEncoding.EncodeToString(csrDER), "")

	status, respBody := postSOAP(t, env.ts.URL+"/mswstep/enroll", body, tokenAuth(secret))
	if status != 403 {
		t.Fatalf("status = %d, want 403\n%s", status, respBody)
	}
}

// TestRST_BadCSR verifies a malformed PKCS#10 yields a SOAP Sender fault with a
// 400 status.
func TestRST_BadCSR(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", nil)
	secret := env.mintToken(t, models.DefaultTenantID, models.TokenScopeTenant, "issuer")

	body := rstEnvelope("urn:uuid:bad", base64.StdEncoding.EncodeToString([]byte("not a real pkcs10")), "")
	status, respBody := postSOAP(t, env.ts.URL+"/mswstep/enroll", body, tokenAuth(secret))
	if status != 400 {
		t.Fatalf("status = %d, want 400\n%s", status, respBody)
	}
	rstr := parseRSTR(t, respBody)
	if !strings.Contains(rstr.Body.Fault.Code, "Sender") {
		t.Errorf("fault code = %q, want a Sender fault", rstr.Body.Fault.Code)
	}
}

// TestRST_DeviceCertMTLS verifies the machine-renewal path: a client certificate
// this CA previously issued authorizes enrollment over mutual TLS when
// allow_client_cert_issued_by_ca is set — no API token required.
func TestRST_DeviceCertMTLS(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", func(c *Config) {
		c.AllowClientCertIssuedByCA = true
	})

	// A currently-valid client certificate issued by the CA is the machine identity.
	clientCert, clientKey := env.issueClientCert(t, "domain-machine$")

	// Serve the same handler over TLS requesting (not requiring) a client cert.
	tlsSrv := httptest.NewUnstartedServer(env.mux)
	tlsSrv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	tlsSrv.StartTLS()
	defer tlsSrv.Close()

	// Trust the httptest server's certificate. httptest.Server.Client() returns a
	// single shared client, so build dedicated clients (with and without the device
	// certificate) to keep the two connections' client-auth state independent.
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	withCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{clientCert.Raw},
			PrivateKey:  clientKey,
			Leaf:        clientCert,
		}},
	}}}
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	_, csrDER := makeCSR(t, "renewed-machine")
	reqBody := rstEnvelope("urn:uuid:mtls", base64.StdEncoding.EncodeToString(csrDER), "")
	resp := doTLS(t, withCert, tlsSrv.URL+"/mswstep/enroll", reqBody)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("mTLS device-cert enroll status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseRSTR(t, body).issuedCert(t)
	if leaf.Subject.CommonName != "renewed-machine" {
		t.Errorf("issued CN = %q, want renewed-machine", leaf.Subject.CommonName)
	}

	// Without the client certificate the same request must fail closed (401): the
	// machine-renewal path is the only credential this env accepts besides a token.
	resp2 := doTLS(t, noCert, tlsSrv.URL+"/mswstep/enroll", reqBody)
	defer resp2.Body.Close()
	if resp2.StatusCode != 401 {
		t.Errorf("no-client-cert status = %d, want 401", resp2.StatusCode)
	}
}

// doTLS posts a SOAP body over the given TLS client.
func doTLS(t *testing.T, client *http.Client, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentTypeSOAP)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
