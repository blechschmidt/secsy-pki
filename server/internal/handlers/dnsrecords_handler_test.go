//go:build sqlite

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/dnsrecords"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Known-answer fixtures mirror those in internal/dnsrecords (produced with
// OpenSSL and ssh-keygen); duplicated here so the handler test asserts the wire
// output independently of the library's internals.
const (
	dnsTestCAPEM = `-----BEGIN CERTIFICATE-----
MIIBsDCCAVWgAwIBAgICEjQwCgYIKoZIzj0EAwIwNjEgMB4GA1UEAwwXU2Vjc3kg
REFORSBUZXN0IFJvb3QgQ0ExEjAQBgNVBAoMCVNlY3N5IFBLSTAeFw0yNjA3MDQw
NDI5NDVaFw0zNjA3MDEwNDI5NDVaMDYxIDAeBgNVBAMMF1NlY3N5IERBTkUgVGVz
dCBSb290IENBMRIwEAYDVQQKDAlTZWNzeSBQS0kwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASVDj/GiQ931QgyPGsFd00SJ57HyP9CsoW2PCOr9bxgplUGCZKaIg8D
FUTejxKxPNXsA1tEgb9/5z17pQt1W+Mbo1MwUTAdBgNVHQ4EFgQULFHOhRK2MtoY
5vZOMVp1ecE9ItswHwYDVR0jBBgwFoAULFHOhRK2MtoY5vZOMVp1ecE9ItswDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAvIf6KVJ+QeG5YGnN0Og9
It22mN4SPwNsTvio8ZW0YrYCIQComfTcKbUDYBcEc/0AztOsckOZmwJRp13aah5i
hx1BLQ==
-----END CERTIFICATE-----`

	dnsTestLeafPEM = `-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIDAKvNMAoGCCqGSM49BAMCMDYxIDAeBgNVBAMMF1NlY3N5
IERBTkUgVGVzdCBSb290IENBMRIwEAYDVQQKDAlTZWNzeSBQS0kwHhcNMjYwNzA0
MDQyOTQ1WhcNMjcwNzA0MDQyOTQ1WjAgMR4wHAYDVQQDDBVob3N0LmRhbmUuZXhh
bXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASS6vxqwXrJJrvyc9vr
+VrnbeE6SRi6p4KhQNxzJd8PHxKs89/uWCD844rIQi3zHJEA9fwSzfrKBqGQy48v
GrIoo3IwcDAMBgNVHRMBAf8EAjAAMCAGA1UdEQQZMBeCFWhvc3QuZGFuZS5leGFt
cGxlLmNvbTAdBgNVHQ4EFgQU8udYVkEGeRYCF+/rzMCFBOTt2NEwHwYDVR0jBBgw
FoAULFHOhRK2MtoY5vZOMVp1ecE9ItswCgYIKoZIzj0EAwIDSAAwRQIhAOqu1t+D
Hef08FixiYiV/7YxBWlYggpE2WJZGXfvu7NLAiBYzjnUdUgCkMpDmlJZLixTcjiV
XdBI/9bKqqGhNVDgxg==
-----END CERTIFICATE-----`

	dnsLeafSPKISHA256 = "a59269b3426dc2c6e4385c649c3161bb098a57a1e9104667f1e9770d12802951"
	dnsCASPKISHA256   = "a8b6387c7fef7f750ad8cd7fa32e2a825364ad2b79df11bb59f2d6dec6111b48"

	dnsEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHXr5x01wKSPHQKhi6H0yI5O4SckW/xCzeptwmbK+1I/"
	dnsEd25519FP2 = "ac8972c526e5fc032b20f5c76bc968dff53d7383e26dfbae4dcfd47e0eac467e"
)

func decodeBundle(t *testing.T, body []byte) dnsrecords.Bundle {
	t.Helper()
	var b dnsrecords.Bundle
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("decoding bundle: %v (body=%s)", err, body)
	}
	return b
}

func findTLSA(recs []dnsrecords.TLSARecord, usage, selector, matching int) (dnsrecords.TLSARecord, bool) {
	for _, r := range recs {
		if r.Usage == usage && r.Selector == selector && r.MatchingType == matching {
			return r, true
		}
	}
	return dnsrecords.TLSARecord{}, false
}

// TestDNSRecordsTLSA drives GET /api/ca/{id}/dns-records/tlsa against a seeded
// X.509 CA and one leaf it issued, asserting the DANE-EE/PKIX-CA/DANE-TA records
// and their SHA-256 association data against OpenSSL-derived vectors.
func TestDNSRecordsTLSA(t *testing.T) {
	api, db := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}

	if err := db.CreateCA(&models.CA{
		ID: "dane-ca", TenantID: models.DefaultTenantID, Label: "dane-ca",
		PKCS11URI: "pkcs11:object=dane-ca", KeyType: "ecdsa-p256", PublicKey: "k",
		Certificate: dnsTestCAPEM,
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID: "leaf-1", CAID: "dane-ca", Serial: "43981",
		CommonName: "host.dane.example.com", Profile: "server",
		Certificate: dnsTestLeafPEM,
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		Status: models.CertStatusValid,
	}); err != nil {
		t.Fatalf("RecordIssuedCertificate: %v", err)
	}

	// With a leaf serial: DANE-EE (leaf) + PKIX-CA and DANE-TA (issuer) = 12 records.
	rec := httptest.NewRecorder()
	api.DNSRecordsTLSA(rec, reqAs(http.MethodGet,
		"/api/ca/dane-ca/dns-records/tlsa?host=host.dane.example.com&port=443&serial=43981",
		root, "dane-ca", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("TLSA with serial: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	b := decodeBundle(t, rec.Body.Bytes())
	if len(b.TLSA) != 12 {
		t.Fatalf("got %d TLSA records, want 12", len(b.TLSA))
	}
	if len(b.SSHFP) != 0 {
		t.Errorf("TLSA response carried %d SSHFP records, want 0", len(b.SSHFP))
	}

	// Recommended leaf record 3 1 1 — SPKI/SHA-256 — matches the OpenSSL digest.
	if r, ok := findTLSA(b.TLSA, 3, 1, 1); !ok {
		t.Error("missing DANE-EE 3 1 1 record")
	} else {
		if r.Data != dnsLeafSPKISHA256 {
			t.Errorf("3 1 1 data = %s, want %s", r.Data, dnsLeafSPKISHA256)
		}
		wantZone := "_443._tcp.host.dane.example.com. IN TLSA 3 1 1 " + dnsLeafSPKISHA256
		if r.Zone != wantZone {
			t.Errorf("3 1 1 zone = %q, want %q", r.Zone, wantZone)
		}
	}
	// Issuer records under both usages carry the CA's SPKI digest.
	for _, usage := range []int{0, 2} {
		if r, ok := findTLSA(b.TLSA, usage, 1, 1); !ok {
			t.Errorf("missing issuer %d 1 1 record", usage)
		} else if r.Data != dnsCASPKISHA256 {
			t.Errorf("%d 1 1 data = %s, want %s", usage, r.Data, dnsCASPKISHA256)
		}
	}
	// The zone block must be the newline-joined set of every record's line.
	if strings.Count(b.Zone, "\n") != 11 {
		t.Errorf("zone block has %d newlines, want 11 (12 records)", strings.Count(b.Zone, "\n"))
	}

	// Without a serial: issuer records only (8), no DANE-EE.
	rec = httptest.NewRecorder()
	api.DNSRecordsTLSA(rec, reqAs(http.MethodGet,
		"/api/ca/dane-ca/dns-records/tlsa?host=host.dane.example.com", root, "dane-ca", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("TLSA no serial: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	b = decodeBundle(t, rec.Body.Bytes())
	if len(b.TLSA) != 8 {
		t.Fatalf("got %d issuer-only records, want 8", len(b.TLSA))
	}
	for _, r := range b.TLSA {
		if r.Usage == 3 {
			t.Errorf("issuer-only response contained a DANE-EE record: %+v", r)
		}
	}

	// Error paths.
	rec = httptest.NewRecorder()
	api.DNSRecordsTLSA(rec, reqAs(http.MethodGet, "/api/ca/dane-ca/dns-records/tlsa", root, "dane-ca", ""))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing host: status = %d, want 400", rec.Code)
	}
	rec = httptest.NewRecorder()
	api.DNSRecordsTLSA(rec, reqAs(http.MethodGet,
		"/api/ca/dane-ca/dns-records/tlsa?host=h.example.com&serial=999999", root, "dane-ca", ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown serial: status = %d, want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	api.DNSRecordsTLSA(rec, reqAs(http.MethodGet,
		"/api/ca/nope/dns-records/tlsa?host=h.example.com", root, "nope", ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown CA: status = %d, want 404", rec.Code)
	}
}

// TestDNSRecordsSSHFP drives POST /api/ssh/cas/{id}/dns-records/sshfp for both a
// supplied host key (known-answer vector) and a host certificate this SSH CA
// signed (serial lookup + principal-derived host default).
func TestDNSRecordsSSHFP(t *testing.T) {
	api, _ := tenantAPI(t)
	root := &models.UserInfo{Subject: "root", IsRoot: true}

	// Create an SSH CA.
	rec := httptest.NewRecorder()
	api.CreateSSHCA(rec, reqAs(http.MethodPost, "/api/ssh/cas", root, "", `{"label":"host-ssh-ca"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateSSHCA: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var ca models.CA
	if err := json.Unmarshal(rec.Body.Bytes(), &ca); err != nil {
		t.Fatalf("decoding CA: %v", err)
	}

	// Supplied-key path with the known ed25519 vector.
	body, _ := json.Marshal(map[string]string{"host": "raw.example.com", "public_key": dnsEd25519Pub})
	rec = httptest.NewRecorder()
	api.DNSRecordsSSHFP(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+ca.ID+"/dns-records/sshfp", root, ca.ID, string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("SSHFP by key: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	b := decodeBundle(t, rec.Body.Bytes())
	if len(b.SSHFP) != 2 {
		t.Fatalf("got %d SSHFP records, want 2", len(b.SSHFP))
	}
	if b.SSHFP[1].FPType != 2 || b.SSHFP[1].Data != dnsEd25519FP2 {
		t.Errorf("SHA-256 record = %+v, want fptype 2 data %s", b.SSHFP[1], dnsEd25519FP2)
	}
	wantZone := "raw.example.com. IN SSHFP 4 2 " + dnsEd25519FP2
	if b.SSHFP[1].Zone != wantZone {
		t.Errorf("SHA-256 zone = %q, want %q", b.SSHFP[1].Zone, wantZone)
	}

	// Sign a host certificate whose principal is a hostname, then look it up.
	subjectKey := sshTestSubjectKey(t)
	signBody, _ := json.Marshal(map[string]interface{}{
		"public_key": subjectKey,
		"cert_type":  "host",
		"principals": []string{"web01.ssh.example.com"},
		"key_id":     "web01",
	})
	rec = httptest.NewRecorder()
	api.SignSSHCert(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+ca.ID+"/sign", root, ca.ID, string(signBody)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("SignSSHCert(host): status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// Discover the serial from the inventory.
	rec = httptest.NewRecorder()
	api.ListSSHCertificates(rec, reqAs(http.MethodGet, "/api/ssh/cas/"+ca.ID+"/certificates", root, ca.ID, ""))
	var certs []models.SSHCertificate
	if err := json.Unmarshal(rec.Body.Bytes(), &certs); err != nil || len(certs) == 0 {
		t.Fatalf("listing SSH certs: err=%v n=%d", err, len(certs))
	}
	serial := certs[0].Serial

	// Serial path with no host: the owner defaults to the cert's first principal.
	body, _ = json.Marshal(map[string]string{"serial": serial})
	rec = httptest.NewRecorder()
	api.DNSRecordsSSHFP(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+ca.ID+"/dns-records/sshfp", root, ca.ID, string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("SSHFP by serial: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	b = decodeBundle(t, rec.Body.Bytes())
	if len(b.SSHFP) != 2 {
		t.Fatalf("got %d SSHFP records, want 2", len(b.SSHFP))
	}
	// The subject key was ed25519 (algorithm 4), and the owner is the principal.
	for _, r := range b.SSHFP {
		if r.Algorithm != 4 {
			t.Errorf("algorithm = %d, want 4 (ed25519)", r.Algorithm)
		}
		if r.Name != "web01.ssh.example.com." {
			t.Errorf("owner = %q, want web01.ssh.example.com.", r.Name)
		}
	}
	// The digest must match computing SSHFP over the same subject key directly.
	key, err := dnsrecords.ParseSSHPublicKey([]byte(subjectKey))
	if err != nil {
		t.Fatalf("parsing subject key: %v", err)
	}
	want, err := dnsrecords.SSHFPRecords("web01.ssh.example.com", key)
	if err != nil {
		t.Fatalf("SSHFPRecords: %v", err)
	}
	if b.SSHFP[1].Data != want[1].Data {
		t.Errorf("serial-path SHA-256 = %s, want %s", b.SSHFP[1].Data, want[1].Data)
	}

	// Error paths: neither / both selectors.
	for _, bad := range []string{`{}`, `{"serial":"1","public_key":"ssh-ed25519 AAAA"}`} {
		rec = httptest.NewRecorder()
		api.DNSRecordsSSHFP(rec, reqAs(http.MethodPost, "/api/ssh/cas/"+ca.ID+"/dns-records/sshfp", root, ca.ID, bad))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", bad, rec.Code)
		}
	}
}
