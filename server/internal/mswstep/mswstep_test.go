//go:build sqlite

// These tests exercise the MS-XCEP (GetPolicies) and MS-WSTEP
// (RequestSecurityToken) endpoints at the protocol layer: the SOAP request/
// response shapes, PKCS#10 -> issued-certificate issuance (against both the
// software provider and, when configured, SoftHSM), profile/template mapping, and
// the authentication / fail-closed authorization paths. Full Kerberos/AD binding
// cannot be exercised hermetically, so client authentication is tested through the
// Kerberos-free mechanisms this server supports (native API tokens and mutual
// TLS).
package mswstep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// --- providers -------------------------------------------------------------

func softwareProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	p, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
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
	t.Cleanup(func() { p.Close() })
	return p
}

func uniqueLabel(t *testing.T, base string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "mswsteptest-" + base + "-" + hex.EncodeToString(b[:])
}

// --- test environment ------------------------------------------------------

// testEnv holds a running MS-WSTEP/MS-XCEP server over a fresh CA.
type testEnv struct {
	srv      *Server
	db       *database.DB
	provider keyprovider.Provider
	ts       *httptest.Server
	mux      *http.ServeMux
	rootCert *x509.Certificate
	caID     string
	tenantID string
}

// newTestEnv builds a CA (owned by tenantID, or the default tenant when empty)
// and an MS-WSTEP/MS-XCEP server over the given provider. mutate may adjust the
// Config before construction. The returned server is exposed over a plain
// httptest server; mTLS-specific tests build their own TLS server.
func newTestEnv(t *testing.T, provider keyprovider.Provider, tenantID string, mutate func(*Config)) *testEnv {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "mswstep.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if tenantID != "" && tenantID != models.DefaultTenantID {
		if err := db.CreateTenant(&models.Tenant{
			ID: tenantID, Slug: tenantID, Name: tenantID, Status: models.TenantStatusActive,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("create tenant: %v", err)
		}
	}

	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		TenantID: tenantID,
		Label:    uniqueLabel(t, "root"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "MS-WSTEP Test Root"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	rootCert, err := pki.ParseCertificatePEM([]byte(root.Certificate))
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	cfg := Config{
		CAID:           root.ID,
		DefaultProfile: "client",
		CESEndpoint:    "https://ces.example.test/mswstep/enroll",
		Templates: []Template{
			{Profile: "client", Name: "SecsyUser"},
			{Profile: "server", Name: "SecsyWebServer"},
		},
		Tokens: authn.NewTokenAuthenticator(db),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv := New(db, provider, cfg)
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return &testEnv{
		srv: srv, db: db, provider: provider, ts: ts, mux: mux,
		rootCert: rootCert, caID: root.ID,
		tenantID: orDefault(tenantID, models.DefaultTenantID),
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// mintToken creates a native API token in the store and returns its bearer
// secret. scope is models.TokenScopeTenant or models.TokenScopePlatform.
func (e *testEnv) mintToken(t *testing.T, tenantID, scope string, roles ...string) string {
	t.Helper()
	secret, hash, prefix := authn.GenerateToken()
	tok := &models.APIToken{
		ID:        "tok-" + uniqueLabel(t, "id"),
		TenantID:  tenantID,
		Name:      "test-token",
		Prefix:    prefix,
		TokenHash: hash,
		Roles:     roles,
		Scope:     scope,
		CreatedAt: time.Now().UTC(),
	}
	if err := e.db.CreateAPIToken(tok); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return secret
}

// issueClientCert issues a client certificate from the test CA (for the mTLS
// machine-renewal path) and returns the certificate and its private key.
func (e *testEnv) issueClientCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, csrDER := makeCSR(t, cn)
	mgr := ca.NewManager(e.db, e.provider)
	res, err := mgr.IssueCertificate(context.Background(), ca.IssueSpec{
		CAID:        e.caID,
		CSRPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		Profile:     "client",
		RequestedBy: "test",
	})
	if err != nil {
		t.Fatalf("issue client cert: %v", err)
	}
	return res.Certificate, key
}

// --- CSR builders ----------------------------------------------------------

func makeCSR(t *testing.T, cn string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	return makeCSRWithExtensions(t, cn, nil)
}

func makeCSRWithExtensions(t *testing.T, cn string, exts []pkix.Extension) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	if len(exts) > 0 {
		tmpl.ExtraExtensions = exts
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

// templateNameExtension builds a Microsoft V1 template-name CSR extension
// (1.3.6.1.4.1.311.20.2) carrying name as a BMPString, as a Windows client does.
func templateNameExtension(t *testing.T, name string) pkix.Extension {
	t.Helper()
	u := utf16.Encode([]rune(name))
	body := make([]byte, len(u)*2)
	for i, r := range u {
		body[2*i] = byte(r >> 8)
		body[2*i+1] = byte(r)
	}
	val, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 30, Bytes: body})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidTemplateV1, Value: val}
}

// templateOIDExtension builds a Microsoft V2 template CSR extension
// (1.3.6.1.4.1.311.21.7) carrying the template OID.
func templateOIDExtension(t *testing.T, oid string) pkix.Extension {
	t.Helper()
	val, err := asn1.Marshal(struct {
		TemplateID   asn1.ObjectIdentifier
		MajorVersion int
		MinorVersion int
	}{TemplateID: parseOIDString(t, oid), MajorVersion: 100, MinorVersion: 0})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidTemplateV2, Value: val}
}

func parseOIDString(t *testing.T, s string) asn1.ObjectIdentifier {
	t.Helper()
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("bad OID %q: %v", s, err)
		}
		oid[i] = n
	}
	return oid
}

// --- SOAP request builders -------------------------------------------------

func getPoliciesEnvelope(msgID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">%s</a:Action>
    <a:MessageID>%s</a:MessageID>
    <a:To s:mustUnderstand="1">https://ces.example.test/mswstep/policy</a:To>
  </s:Header>
  <s:Body>
    <GetPolicies xmlns="%s">
      <client><lastUpdate/><preferredLanguage>en-US</preferredLanguage></client>
      <requestFilter/>
    </GetPolicies>
  </s:Body>
</s:Envelope>`, actionGetPolicies, msgID, nsEnrollPolicy)
}

// rstEnvelope builds an MS-WSTEP RequestSecurityToken (Issue) SOAP request over
// the given base64 PKCS#10. When contextTemplate is non-empty an AdditionalContext
// ContextItem selects the template.
func rstEnvelope(msgID, csrB64, contextTemplate string) string {
	var addl string
	if contextTemplate != "" {
		addl = fmt.Sprintf(`
      <wst:AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <ContextItem Name="%s"><Value>%s</Value></ContextItem>
      </wst:AdditionalContext>`, contextItemTemplate, contextTemplate)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:wsse="%s" xmlns:wst="%s">
  <s:Header>
    <a:Action s:mustUnderstand="1">%s</a:Action>
    <a:MessageID>%s</a:MessageID>
    <a:To s:mustUnderstand="1">https://ces.example.test/mswstep/enroll</a:To>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>%s</wst:TokenType>
      <wst:RequestType>%s</wst:RequestType>
      <wsse:BinarySecurityToken ValueType="%s" EncodingType="%s">%s</wsse:BinarySecurityToken>%s
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`, nsWSSE, nsWSTrust, actionRST, msgID, valueTypePKCS7, requestTypeIssue, valueTypePKCS10, encodingBase64, csrB64, addl)
}

// --- HTTP helper -----------------------------------------------------------

// postSOAP posts a SOAP body to the URL with an optional Authorization header and
// returns the response status and body.
func postSOAP(t *testing.T, url, body, authHeader string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentTypeSOAP)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

func tokenAuth(secret string) string { return authn.TokenAuthScheme + " " + secret }

// --- response parsers ------------------------------------------------------

// parsedRSTR is a lenient view of an MS-WSTEP RSTR response.
type parsedRSTR struct {
	XMLName xml.Name
	Header  struct {
		Action    string `xml:"Action"`
		RelatesTo string `xml:"RelatesTo"`
	} `xml:"Header"`
	Body struct {
		Coll struct {
			Resp struct {
				TokenType   string `xml:"TokenType"`
				Disposition string `xml:"DispositionMessage"`
				Requested   struct {
					Token string `xml:"BinarySecurityToken"`
				} `xml:"RequestedSecurityToken"`
				RequestID string `xml:"RequestID"`
			} `xml:"RequestSecurityTokenResponse"`
		} `xml:"RequestSecurityTokenResponseCollection"`
		Fault struct {
			Code   string `xml:"Code>Value"`
			Reason string `xml:"Reason>Text"`
		} `xml:"Fault"`
	} `xml:"Body"`
}

func parseRSTR(t *testing.T, body []byte) parsedRSTR {
	t.Helper()
	var r parsedRSTR
	if err := xml.Unmarshal(body, &r); err != nil {
		t.Fatalf("parsing RSTR: %v\n%s", err, body)
	}
	return r
}

// issuedCert decodes the PKCS#7 in an RSTR and returns the leaf certificate.
func (r parsedRSTR) issuedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	tok := strings.TrimSpace(r.Body.Coll.Resp.Requested.Token)
	if tok == "" {
		t.Fatalf("RSTR carried no issued token; fault code=%q reason=%q", r.Body.Fault.Code, r.Body.Fault.Reason)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(tok), ""))
	if err != nil {
		t.Fatalf("decoding issued token base64: %v", err)
	}
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		t.Fatalf("parsing issued PKCS#7: %v", err)
	}
	if len(sd.Certificates) == 0 {
		t.Fatal("issued PKCS#7 carried no certificates")
	}
	return sd.Certificates[0]
}

// parsedGPR is a lenient view of an MS-XCEP GetPoliciesResponse.
type parsedGPR struct {
	XMLName xml.Name
	Header  struct {
		Action    string `xml:"Action"`
		RelatesTo string `xml:"RelatesTo"`
	} `xml:"Header"`
	Body struct {
		Resp struct {
			Response struct {
				PolicyID           string `xml:"policyID"`
				PolicyFriendlyName string `xml:"policyFriendlyName"`
				NextUpdateHours    int    `xml:"nextUpdateHours"`
				Policies           []struct {
					PolicyOIDReference int   `xml:"policyOIDReference"`
					CAReferences       []int `xml:"cAs>cAReference"`
					Attributes         struct {
						CommonName   string `xml:"commonName"`
						PolicySchema int    `xml:"policySchema"`
						Validity     struct {
							ValidityPeriodSeconds int64 `xml:"validityPeriodSeconds"`
							RenewalPeriodSeconds  int64 `xml:"renewalPeriodSeconds"`
						} `xml:"certificateValidity"`
						Permission struct {
							Enroll     bool `xml:"enroll"`
							AutoEnroll bool `xml:"autoEnroll"`
						} `xml:"permission"`
						PrivateKey struct {
							MinimalKeyLength int `xml:"minimalKeyLength"`
						} `xml:"privateKeyAttributes"`
					} `xml:"attributes"`
				} `xml:"policies>policy"`
			} `xml:"response"`
			CAs struct {
				CA []struct {
					Certificate string `xml:"certificate"`
					URIs        []struct {
						URI                  string `xml:"uri"`
						ClientAuthentication int    `xml:"clientAuthentication"`
					} `xml:"uris>cAURI"`
				} `xml:"cA"`
			} `xml:"cAs"`
			OIDs struct {
				OID []struct {
					Value       string `xml:"value"`
					Group       int    `xml:"group"`
					DefaultName string `xml:"defaultName"`
				} `xml:"oID"`
			} `xml:"oIDs"`
		} `xml:"GetPoliciesResponse"`
	} `xml:"Body"`
}

func parseGPR(t *testing.T, body []byte) parsedGPR {
	t.Helper()
	var r parsedGPR
	if err := xml.Unmarshal(body, &r); err != nil {
		t.Fatalf("parsing GetPoliciesResponse: %v\n%s", err, body)
	}
	return r
}
