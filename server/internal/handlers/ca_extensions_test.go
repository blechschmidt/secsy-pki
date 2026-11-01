//go:build sqlite

package handlers

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Task 222: creating a certificate authority through the API — which is what the
// console does on every one of its three CA forms — must accept the whole common
// X.509 v3 extension vocabulary, not the handful crypto/x509 exposes on a
// template. These tests drive the REST handlers exactly as the console does and
// assert on the certificate that comes back out.

// caExtAPI builds an API over an in-memory database and a software key provider,
// plus an admin user authorized in the default tenant.
func caExtAPI(t *testing.T) (*API, *models.UserInfo) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "")
	return api, &models.UserInfo{
		Subject:     "ca-ext-admin",
		TenantRoles: map[string][]string{models.DefaultTenantID: {"admin"}},
	}
}

// postJSON drives a handler with a JSON body and returns the status and body.
func postJSON(t *testing.T, h http.HandlerFunc, target, id string, user *models.UserInfo, body any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling request: %v", err)
	}
	rec := httptest.NewRecorder()
	h(rec, reqAs(http.MethodPost, target, user, id, string(raw)))
	return rec.Code, rec.Body.String()
}

// createCA posts a CA-creation request and parses the certificate it returns.
func createCA(t *testing.T, api *API, user *models.UserInfo, body any) (*models.CA, *x509.Certificate) {
	t.Helper()
	code, respBody := postJSON(t, api.InitRootCA, "/api/ca/init-root", "", user, body)
	if code != http.StatusCreated {
		t.Fatalf("POST /api/ca/init-root = %d: %s", code, respBody)
	}
	var rec models.CA
	if err := json.Unmarshal([]byte(respBody), &rec); err != nil {
		t.Fatalf("decoding CA: %v", err)
	}
	block, _ := pem.Decode([]byte(rec.Certificate))
	if block == nil {
		t.Fatalf("CA record carries no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the issued CA certificate: %v", err)
	}
	return &rec, cert
}

func extByOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

// TestInitRootCA_FullExtensionSet is the headline check: one request carrying
// every extension field, and every extension present on the resulting
// certificate. It is the API shape the console's extension dialog produces.
func TestInitRootCA_FullExtensionSet(t *testing.T) {
	api, user := caExtAPI(t)

	_, cert := createCA(t, api, user, map[string]any{
		"label":         "ext-root",
		"key_type":      "ecdsa-p256",
		"validity_days": 3650,
		"subject": map[string]any{
			"cn": "Northwind Extension Root", "o": "Northwind Logistics GmbH",
			"ou": "PKI", "c": "DE", "st": "Hamburg", "l": "Hamburg",
			"serial_number": "HRB 12345",
			"street":        "Hafenstrasse 1",
			"postal_code":   "20457",
			"dc":            []string{"example", "test"},
			"email":         "pki@example.test",
			"extra_names": []map[string]string{
				{"type": "organizationIdentifier", "value": "VATDE-123456789"},
				{"type": "businessCategory", "value": "Private Organization"},
				{"type": "2.5.4.12", "value": "Root Authority"},
			},
		},
		"extensions": map[string]any{
			"key_usages":             []string{"keyCertSign", "cRLSign"},
			"ext_key_usages":         []string{"serverAuth", "clientAuth", "msSmartcardLogon", "1.3.6.1.4.1.99999.3"},
			"ext_key_usage_critical": true,
			"subject_alt_name": map[string]any{
				"dns": []string{"ca.example.test"}, "ip": []string{"192.0.2.10"},
				"email": []string{"pki@example.test"}, "uri": []string{"https://ca.example.test/"},
				"upn": []string{"svc@CORP.EXAMPLE"}, "dir_names": []string{"O=Northwind,C=DE"},
				"registered_ids": []string{"1.3.6.1.4.1.99999.9"},
				"other_names":    []map[string]string{{"oid": "1.3.6.1.4.1.99999.10", "encoding": "ia5", "value": "marker"}},
			},
			"issuer_alt_name":              map[string]any{"uri": []string{"https://root.example.test/"}},
			"crl_distribution_points":      []string{"http://crl.example.test/root.crl"},
			"freshest_crl":                 []string{"http://crl.example.test/delta.crl"},
			"ocsp_servers":                 []string{"http://ocsp.example.test/"},
			"ca_issuers":                   []string{"http://pki.example.test/parent.cer"},
			"ca_repositories":              []string{"http://pki.example.test/certs/"},
			"timestamp_servers":            []string{"http://tsa.example.test/"},
			"inhibit_any_policy":           1,
			"private_key_usage_period":     map[string]any{"duration": "180d"},
			"subject_directory_attributes": []map[string]any{{"oid": "1.3.6.1.5.5.7.9.4", "encoding": "printable", "values": []string{"DE"}}},
			"must_staple":                  true,
			"ocsp_no_check":                true,
			"netscape_comment":             "Northwind root",
			"netscape_cert_type":           []string{"sslCA", "smimeCA"},
			"subject_key_id":               "de:ad:be:ef:00:11:22:33",
			"custom": []map[string]any{
				{"oid": "1.3.6.1.4.1.99999.100", "critical": true, "encoding": "utf8", "value": "enterprise marker"},
			},
		},
		"name_constraints": map[string]any{"permitted": map[string]any{"dns": []string{"example.test"}}},
		"policies":         map[string]any{"oids": []string{"1.3.6.1.4.1.99999.1.1"}, "cps": "https://cps.example.test/"},
	})

	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage = %b, want certSign|crlSign", cert.KeyUsage)
	}
	if string(cert.SubjectKeyId) != "\xde\xad\xbe\xef\x00\x11\x22\x33" {
		t.Errorf("subject key id = %x", cert.SubjectKeyId)
	}

	// Every subject attribute, including the ones that travel through ExtraNames.
	subj := cert.Subject
	if subj.CommonName != "Northwind Extension Root" || subj.SerialNumber != "HRB 12345" {
		t.Errorf("subject CN/serialNumber = %q/%q", subj.CommonName, subj.SerialNumber)
	}
	if len(subj.StreetAddress) != 1 || subj.StreetAddress[0] != "Hafenstrasse 1" {
		t.Errorf("subject street = %v", subj.StreetAddress)
	}
	if len(subj.PostalCode) != 1 || subj.PostalCode[0] != "20457" {
		t.Errorf("subject postalCode = %v", subj.PostalCode)
	}
	wantAttrs := map[string]string{
		"0.9.2342.19200300.100.1.25": "example", // the first domainComponent
		"1.2.840.113549.1.9.1":       "pki@example.test",
		"2.5.4.97":                   "VATDE-123456789",
		"2.5.4.15":                   "Private Organization",
		"2.5.4.12":                   "Root Authority",
	}
	seen := map[string]string{}
	for _, atv := range subj.Names {
		if s, ok := atv.Value.(string); ok {
			if _, dup := seen[atv.Type.String()]; !dup {
				seen[atv.Type.String()] = s
			}
		}
	}
	for oid, want := range wantAttrs {
		if seen[oid] != want {
			t.Errorf("subject attribute %s = %q, want %q", oid, seen[oid], want)
		}
	}

	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "ca.example.test" {
		t.Errorf("SAN dNSNames = %v", cert.DNSNames)
	}
	if upns := pki.UPNsFromCertificate(cert); len(upns) != 1 || upns[0] != "svc@CORP.EXAMPLE" {
		t.Errorf("SAN UPNs = %v", upns)
	}
	if len(cert.OCSPServer) != 1 || len(cert.IssuingCertificateURL) != 1 || len(cert.CRLDistributionPoints) != 1 {
		t.Errorf("AIA/CRLDP = %v / %v / %v", cert.OCSPServer, cert.IssuingCertificateURL, cert.CRLDistributionPoints)
	}

	// Every hand-rolled extension, named by OID so a silent omission is caught.
	for name, oid := range map[string]asn1.ObjectIdentifier{
		"extKeyUsage":                {2, 5, 29, 37},
		"issuerAltName":              pki.OIDIssuerAltName,
		"freshestCRL":                pki.OIDFreshestCRL,
		"subjectInfoAccess":          pki.OIDSubjectInfoAccess,
		"inhibitAnyPolicy":           pki.OIDInhibitAnyPolicy,
		"privateKeyUsagePeriod":      pki.OIDPrivateKeyUsagePeriod,
		"subjectDirectoryAttributes": pki.OIDSubjectDirectoryAttributes,
		"tlsFeature":                 pki.OIDTLSFeature,
		"ocspNoCheck":                pki.OIDOCSPNoCheck,
		"netscapeComment":            pki.OIDNetscapeComment,
		"netscapeCertType":           pki.OIDNetscapeCertType,
		"custom":                     {1, 3, 6, 1, 4, 1, 99999, 100},
		"nameConstraints":            {2, 5, 29, 30},
		"certificatePolicies":        {2, 5, 29, 32},
	} {
		if _, ok := extByOID(cert, oid); !ok {
			t.Errorf("certificate carries no %s extension (%s)", name, oid)
		}
	}

	// extKeyUsage must be critical, and the unknown OIDs must have survived.
	eku, _ := extByOID(cert, asn1.ObjectIdentifier{2, 5, 29, 37})
	if !eku.Critical {
		t.Error("extKeyUsage is not critical")
	}
	if len(cert.UnknownExtKeyUsage) != 2 {
		t.Errorf("unknown EKUs = %v, want the smartcard-logon and enterprise OIDs", cert.UnknownExtKeyUsage)
	}
	// The name constraints really constrain (the CA layer's own extension, not
	// caext's, but the two must coexist on one certificate).
	if len(cert.PermittedDNSDomains) != 1 || cert.PermittedDNSDomains[0] != "example.test" {
		t.Errorf("permitted DNS domains = %v", cert.PermittedDNSDomains)
	}
}

// TestInitRootCA_DefaultsUnchanged pins the behaviour of a request that
// configures nothing: exactly the certificate secsy-pki issued before the
// extension set existed. An existing automation must not see new extensions
// appear because this feature shipped.
func TestInitRootCA_DefaultsUnchanged(t *testing.T) {
	api, user := caExtAPI(t)
	_, cert := createCA(t, api, user, map[string]any{
		"label": "plain-root", "key_type": "ecdsa-p256", "validity_days": 365,
		"subject": map[string]any{"cn": "Plain Root"},
	})
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	if cert.KeyUsage != want {
		t.Errorf("key usage = %b, want %b", cert.KeyUsage, want)
	}
	for _, e := range cert.Extensions {
		switch e.Id.String() {
		case "2.5.29.15", "2.5.29.19", "2.5.29.14", "2.5.29.35":
		default:
			t.Errorf("an unconfigured root carries an unexpected extension %s", e.Id)
		}
	}
}

// TestIssueIntermediateCA_EKUConstraint is the pattern the feature exists for:
// a delegated issuing CA that can only ever produce server certificates, set up
// through the same API the console calls.
func TestIssueIntermediateCA_EKUConstraint(t *testing.T) {
	api, user := caExtAPI(t)
	root, _ := createCA(t, api, user, map[string]any{
		"label": "eku-root", "key_type": "ecdsa-p256", "validity_days": 3650,
		"subject": map[string]any{"cn": "EKU Root"},
		"extensions": map[string]any{
			"ca_repositories": []string{"http://pki.example.test/certs/"},
		},
	})

	code, body := postJSON(t, api.IssueIntermediateCA, "/api/ca/"+root.ID+"/issue-intermediate", root.ID, user, map[string]any{
		"label": "tls-issuer", "key_type": "ecdsa-p256", "validity_days": 1825,
		"subject":      map[string]any{"cn": "TLS Issuing CA"},
		"max_path_len": 0,
		"extensions": map[string]any{
			"ext_key_usages":           []string{"serverAuth"},
			"crl_distribution_points":  []string{"http://crl.example.test/root.crl"},
			"ocsp_servers":             []string{"http://ocsp.example.test/"},
			"ca_issuers":               []string{"http://pki.example.test/eku-root.cer"},
			"private_key_usage_period": map[string]any{"fraction": 0.5},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("POST issue-intermediate = %d: %s", code, body)
	}
	var rec models.CA
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decoding CA: %v", err)
	}
	block, _ := pem.Decode([]byte(rec.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing intermediate: %v", err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("intermediate EKUs = %v, want [serverAuth]", cert.ExtKeyUsage)
	}
	if !cert.MaxPathLenZero {
		t.Error("intermediate should carry pathLen 0")
	}
	// The usage period must be half the certificate's own validity, within a
	// minute of rounding.
	pkupExt, ok := extByOID(cert, pki.OIDPrivateKeyUsagePeriod)
	if !ok {
		t.Fatal("intermediate carries no privateKeyUsagePeriod")
	}
	pkup, err := pki.ParsePrivateKeyUsagePeriod(pkupExt.Value)
	if err != nil {
		t.Fatalf("decoding privateKeyUsagePeriod: %v", err)
	}
	want := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
	if d := pkup.NotAfter.Sub(want); d > 61e9 || d < -61e9 {
		t.Errorf("usage period notAfter = %s, want ~%s", pkup.NotAfter, want)
	}
	// The intermediate keeps the usual CA key usages, so it can still sign CRLs.
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("intermediate lost crlSign")
	}
}

// TestCAExtensionsRejectedBeforeKeyGeneration proves the gate is fail-closed and
// cheap: a bad extension set returns 400 and leaves no CA and no key behind, so
// an operator can iterate on a configuration without littering the HSM.
func TestCAExtensionsRejectedBeforeKeyGeneration(t *testing.T) {
	api, user := caExtAPI(t)

	cases := map[string]any{
		"key usage without certSign": map[string]any{"key_usages": []string{"digitalSignature"}},
		"unknown key usage":          map[string]any{"key_usages": []string{"certSign", "signAllTheThings"}},
		"unresolvable EKU":           map[string]any{"ext_key_usages": []string{"notAUsage"}},
		"bad custom OID":             map[string]any{"custom": []map[string]any{{"oid": "nope", "value": "x"}}},
		"truncated DER":              map[string]any{"custom": []map[string]any{{"oid": "1.2.3", "encoding": "der-hex", "value": "0c05"}}},
		"duplicate extension":        map[string]any{"must_staple": true, "custom": []map[string]any{{"oid": "1.3.6.1.5.5.7.1.24", "encoding": "der-hex", "value": "0500"}}},
		"bad SAN IP":                 map[string]any{"subject_alt_name": map[string]any{"ip": []string{"299.0.0.1"}}},
		"two usage-period forms":     map[string]any{"private_key_usage_period": map[string]any{"duration": "1y", "fraction": 0.5}},
		"negative inhibitAnyPolicy":  map[string]any{"inhibit_any_policy": -1},
		"bad netscape cert type":     map[string]any{"netscape_cert_type": []string{"webserver"}},
		"bad subject key id":         map[string]any{"subject_key_id": "not hex"},
	}
	for name, exts := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := postJSON(t, api.InitRootCA, "/api/ca/init-root", "", user, map[string]any{
				"label": "reject-" + strings.ReplaceAll(name, " ", "-"), "key_type": "ecdsa-p256",
				"subject": map[string]any{"cn": "Rejected"}, "extensions": exts,
			})
			if code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", code, body)
			}
			if cas, err := api.db.ListCAs(); err != nil {
				t.Fatalf("ListCAs: %v", err)
			} else if len(cas) != 0 {
				t.Fatalf("a rejected request left %d CA(s) behind", len(cas))
			}
		})
	}

	// A subject attribute that cannot be resolved is refused too, rather than
	// quietly dropped — a CA whose DN is not the one asked for is worse.
	code, body := postJSON(t, api.InitRootCA, "/api/ca/init-root", "", user, map[string]any{
		"label": "bad-subject", "key_type": "ecdsa-p256",
		"subject": map[string]any{"cn": "x", "extra_names": []map[string]string{{"type": "notAnAttribute", "value": "v"}}},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("unknown DN attribute: status = %d, want 400: %s", code, body)
	}
}

// TestExternalCACSR_CarriesRequestedExtensions checks the third CA form: the
// requested extension set must travel in the CSR's extensionRequest attribute,
// so an external parent signing it verbatim reproduces the CA that was asked
// for.
func TestExternalCACSR_CarriesRequestedExtensions(t *testing.T) {
	api, user := caExtAPI(t)
	code, body := postJSON(t, api.CreateExternalCACSR, "/api/ca/csr", "", user, map[string]any{
		"label": "corp-sub", "key_type": "ecdsa-p256",
		"subject":      map[string]any{"cn": "Corp Subordinate CA", "o": "Northwind"},
		"max_path_len": 0,
		"extensions": map[string]any{
			"ext_key_usages":  []string{"serverAuth", "clientAuth"},
			"ca_repositories": []string{"http://pki.example.test/certs/"},
			"custom":          []map[string]any{{"oid": "1.3.6.1.4.1.99999.100", "encoding": "utf8", "value": "marker"}},
		},
		"name_constraints": map[string]any{"permitted": map[string]any{"dns": []string{"corp.example.test"}}},
	})
	if code != http.StatusCreated {
		t.Fatalf("POST /api/ca/csr = %d: %s", code, body)
	}
	var resp models.CAExternalCSRResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decoding CSR response: %v", err)
	}
	csr, err := pki.ParseCSRPEM([]byte(resp.CSRPEM))
	if err != nil {
		t.Fatalf("parsing the emitted CSR: %v", err)
	}
	present := map[string]bool{}
	for _, e := range csr.Extensions {
		present[e.Id.String()] = true
	}
	for name, oid := range map[string]string{
		"basicConstraints":  "2.5.29.19",
		"keyUsage":          "2.5.29.15",
		"extKeyUsage":       "2.5.29.37",
		"subjectInfoAccess": "1.3.6.1.5.5.7.1.11",
		"custom":            "1.3.6.1.4.1.99999.100",
		"nameConstraints":   "2.5.29.30",
	} {
		if !present[oid] {
			t.Errorf("CSR does not request %s (%s)", name, oid)
		}
	}
	// The usage period is deliberately absent: only the issuer knows the
	// validity window it would be relative to.
	if present[pki.OIDPrivateKeyUsagePeriod.String()] {
		t.Error("CSR should not request a privateKeyUsagePeriod")
	}
}
