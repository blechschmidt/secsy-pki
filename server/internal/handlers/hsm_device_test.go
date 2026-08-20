//go:build sqlite

package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Device-authenticity verification over REST (Task 189, exposed for console
// parity in Task 190).
//
// The endpoint under test is the half that needs no device, which is exactly the
// half a relying party uses: it is handed a bundle and has to reach the same
// verdict the operator did, without trusting the operator. So the tests here
// check the two things that decide whether that is possible — that the certified
// serial is extracted from the certificate rather than echoed from the bundle's
// own claim, and that a bundle establishing less than it appears to (no
// challenge, unanchored chain) is reported as failing rather than passing.

// syntheticDeviceAttestation builds a device attestation from a throwaway PKI:
// a root, a device certificate carrying Yubico's serial and firmware extensions,
// and no challenge answer. It stands in for real hardware, which the test
// environment does not have.
func syntheticDeviceAttestation(t *testing.T, serial string) (*hsmattest.DeviceAttestation, *x509.CertPool) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test YubiHSM Root CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	serialInt, ok := new(big.Int).SetString(serial, 10)
	if !ok {
		t.Fatalf("serial %q is not a number", serial)
	}
	firmware, err := asn1.Marshal([]byte{2, 4, 0})
	if err != nil {
		t.Fatal(err)
	}
	serialExt, err := asn1.Marshal(serialInt)
	if err != nil {
		t.Fatal(err)
	}
	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "YubiHSM Attestation (" + serial + ")"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 1}, Value: firmware},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 2}, Value: serialExt},
		},
	}
	devDER, err := x509.CreateCertificate(rand.Reader, devTmpl, root, &devKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &hsmattest.DeviceAttestation{
		Kind:                 hsmattest.DeviceAttestationKind,
		DeviceCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: devDER})),
		ReportedSerial:       serial,
		ProducedAt:           time.Now().UTC(),
	}, pool
}

// postDeviceVerify drives the verify endpoint as user and returns the recorder.
func postDeviceVerify(t *testing.T, api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.VerifyDeviceAttestation(rec, reqAs(http.MethodPost, "/api/hsm/device-attestation:verify", user, "", body))
	return rec
}

func decodeDeviceVerdict(t *testing.T, rec *httptest.ResponseRecorder) *hsmattest.DeviceResult {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Verification *hsmattest.DeviceResult `json:"verification"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding verdict: %v", err)
	}
	if out.Verification == nil {
		t.Fatalf("response carries no verification: %s", rec.Body.String())
	}
	return out.Verification
}

func TestVerifyDeviceAttestationREST(t *testing.T) {
	api, _ := tenantAPI(t)
	att, pool := syntheticDeviceAttestation(t, "31650425")

	// Anchor the synthetic root so the chain check can pass; without this every
	// case below would fail for the same uninteresting reason.
	pol := hsmattest.DefaultPolicy()
	pol.Roots = pool
	api.SetKeyAttestationPolicy(pol)

	body := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// A bundle with no challenge answer establishes that a genuine device with
	// this serial exists, not that it produced the bundle. The default policy
	// requires proof of possession, so this must NOT verify — and the serial must
	// still be reported, because that is the finding an operator acts on.
	res := decodeDeviceVerdict(t, postDeviceVerify(t, api, rootUser(), body(map[string]any{"attestation": att})))
	if res.Verified {
		t.Error("a bundle answering no challenge must not verify under the default policy")
	}
	if res.Serial != "31650425" {
		t.Errorf("certified serial = %q, want 31650425 (read from the certificate, not the bundle's claim)", res.Serial)
	}
	if !res.ChainAnchored {
		t.Errorf("the synthetic root was anchored, so chain_anchored should hold: %+v", res.Problems)
	}
	if res.ProofOfPossession {
		t.Error("proof_of_possession must be false when no challenge was answered")
	}

	// Opting into the weaker claim explicitly is what allow_no_challenge means,
	// and it must then verify.
	res = decodeDeviceVerdict(t, postDeviceVerify(t, api, rootUser(),
		body(map[string]any{"attestation": att, "allow_no_challenge": true})))
	if !res.Verified {
		t.Errorf("allow_no_challenge should accept this bundle; problems=%v", res.Problems)
	}

	// An expected serial that disagrees is the whole point of the parameter: it
	// turns "some genuine device" into "the device I was promised".
	res = decodeDeviceVerdict(t, postDeviceVerify(t, api, rootUser(),
		body(map[string]any{"attestation": att, "allow_no_challenge": true, "expected_serial": "99999999"})))
	if res.Verified {
		t.Error("a bundle for a different serial must not verify against expected_serial")
	}

	// An unanchored chain is a certificate anybody could mint, so it fails even
	// when everything else lines up.
	api.SetKeyAttestationPolicy(hsmattest.DefaultPolicy())
	res = decodeDeviceVerdict(t, postDeviceVerify(t, api, rootUser(),
		body(map[string]any{"attestation": att, "allow_no_challenge": true})))
	if res.Verified {
		t.Error("a device certificate that chains to no trusted anchor must not verify")
	}

	// Shape errors are 400s rather than silent false verdicts: a caller that
	// posted the wrong thing needs to know it posted the wrong thing.
	if rec := postDeviceVerify(t, api, rootUser(), `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("empty attestation = %d, want 400", rec.Code)
	}
	if rec := postDeviceVerify(t, api, rootUser(), `not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body = %d, want 400", rec.Code)
	}

	// Verification is audit:read, not hsm:manage — an auditor holding only the
	// bundle must be able to check it. A principal with neither is refused.
	if rec := postDeviceVerify(t, api, &models.UserInfo{Subject: "nobody"}, body(map[string]any{"attestation": att})); rec.Code != http.StatusForbidden {
		t.Errorf("roleless caller = %d, want 403", rec.Code)
	}
}

// The device policy is derived from the key-attestation policy rather than
// configured twice, so a deployment that pins custom attestation roots pins them
// for both. This guards that derivation, which is the only thing keeping the two
// from drifting apart.
func TestDeviceAttestationPolicyFollowsTheKeyPolicy(t *testing.T) {
	api, _ := tenantAPI(t)
	_, pool := syntheticDeviceAttestation(t, "12345678")

	key := hsmattest.DefaultPolicy()
	key.Roots = pool
	key.RequireAnchoredChain = false
	api.SetKeyAttestationPolicy(key)

	dev := api.deviceAttestationPolicy()
	if dev.Roots != pool {
		t.Error("the device policy does not inherit the configured attestation roots")
	}
	if dev.RequireAnchoredChain {
		t.Error("the device policy does not inherit the anchoring requirement")
	}
	// Proof of possession is device-specific and has no key-policy counterpart,
	// so it must keep its own default rather than picking up a key setting.
	if !dev.RequireProofOfPossession {
		t.Error("the device policy must still require proof of possession by default")
	}
}

// HSMAuditStatus has to answer before the device is commissioned: "not
// provisioned" is the most important thing it can say, and a 404 would leave a
// client unable to tell that apart from a server with no HSM at all.
func TestHSMAuditStatusReportsUnprovisioned(t *testing.T) {
	api, _ := tenantAPI(t)

	rec := httptest.NewRecorder()
	api.HSMAuditStatus(rec, reqAs(http.MethodGet, "/api/hsm/audit-status", rootUser(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("audit status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var st struct {
		Provisioned bool `json:"provisioned"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decoding status: %v", err)
	}
	if st.Provisioned {
		t.Error("an uncommissioned device must report provisioned=false")
	}

	rec = httptest.NewRecorder()
	api.HSMAuditStatus(rec, reqAs(http.MethodGet, "/api/hsm/audit-status", &models.UserInfo{Subject: "nobody"}, "", ""))
	if rec.Code != http.StatusForbidden {
		t.Errorf("roleless caller = %d, want 403", rec.Code)
	}
}
