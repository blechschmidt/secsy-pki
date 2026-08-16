//go:build sqlite

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/delegatedcred"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// dcEscrowAPI builds an API with a KEK and a 2-of-3 escrow policy on a software
// provider, plus an issuable root CA, so the PKCS#12 escrow -> delegated-
// credential recovery path can be exercised end to end. It returns the API, the
// CA id, and the recovery-agent IDs.
func dcEscrowAPI(t *testing.T) (*API, string, []string) {
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
	ctx := context.Background()
	if _, err := secret.ProvisionKEK(ctx, prov, "dc-escrow-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	var specs []secret.AgentSpec
	var agentIDs []string
	for i := 0; i < 3; i++ {
		label := fmt.Sprintf("dc-agent-key-%d", i)
		if _, err := prov.GenerateKey(ctx, keyprovider.KeySpec{
			Label:   label,
			KeyType: keyprovider.KeyTypeRSA2048,
			Usage:   keyprovider.KeyUsageDecrypt,
		}); err != nil {
			t.Fatalf("generate agent key %d: %v", i, err)
		}
		id := fmt.Sprintf("dc-agent-%d", i)
		specs = append(specs, secret.AgentSpec{ID: id, KeyLabel: label})
		agentIDs = append(agentIDs, id)
	}

	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "dc-escrow-kek")
	api.SetEscrow(2, specs)

	root, err := ca.NewManager(db, prov).InitRoot(ctx, ca.RootSpec{
		Label:    "dc-handler-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "DC Handler Root", Organization: "Secsy"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return api, root.ID, agentIDs
}

// exportEscrowedLeaf issues a delegation-eligible leaf via the PKCS#12 export with
// escrow enabled, returning the escrow envelope, the serial, and the leaf chain.
func exportEscrowedLeaf(t *testing.T, api *API, caID string) (envelope json.RawMessage, serial, chainPEM string) {
	t.Helper()
	body := `{"profile":"server-delegation","common_name":"dc.example.com",` +
		`"dns_names":["dc.example.com"],"key_type":"ecdsa","encoder":"modern",` +
		`"password":"correct-horse-battery-staple","escrow":true}`
	rec := httptest.NewRecorder()
	api.ExportCertificatePKCS12(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/pkcs12", rootUser(), caID, body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("pkcs12 export status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp models.ExportPKCS12Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding pkcs12 response: %v", err)
	}
	if resp.Escrow == nil || len(resp.Escrow.Envelope) == 0 {
		t.Fatalf("expected an escrow envelope, got %+v", resp.Escrow)
	}
	return resp.Escrow.Envelope, resp.Serial, resp.Chain
}

func mintDCRequest(t *testing.T, api *API, caID string, body []byte, user *models.UserInfo) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.MintDelegatedCredential(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/delegated-credential", user, caID, string(body)))
	return rec
}

// TestMintDelegatedCredentialHandler is the end-to-end happy path: escrow a leaf
// key via PKCS#12 export, then recover it and mint a delegated credential that
// verifies against the leaf.
func TestMintDelegatedCredentialHandler(t *testing.T) {
	api, caID, agentIDs := dcEscrowAPI(t)
	envelope, serial, chainPEM := exportEscrowedLeaf(t, api, caID)

	reqBody, _ := json.Marshal(models.MintDelegatedCredentialRequest{
		Serial:          serial,
		EscrowEnvelope:  envelope,
		RecoveryAgents:  agentIDs[:2], // exactly the threshold
		ValidForSeconds: 3600,
		DCKeyType:       "ecdsa-p256",
	})
	rec := mintDCRequest(t, api, caID, reqBody, rootUser())
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp models.MintDelegatedCredentialResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding mint response: %v", err)
	}
	if resp.Endpoint != "server" || resp.Algorithm != "ecdsa_secp256r1_sha256" {
		t.Errorf("unexpected metadata: %+v", resp)
	}
	if resp.DCPrivateKeyPEM == "" {
		t.Error("expected a generated delegated private key in the response")
	}

	// The returned wire credential must verify against the leaf.
	wire, err := base64.StdEncoding.DecodeString(resp.DelegatedCredential)
	if err != nil {
		t.Fatalf("delegated_credential not base64: %v", err)
	}
	dc, err := delegatedcred.Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	leaf, err := pki.ParseCertificatePEM([]byte(chainPEM))
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	if err := dc.Verify(leaf, delegatedcred.ServerEndpoint); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !dc.ValidAt(leaf, time.Now()) {
		t.Error("credential not valid now")
	}
}

// TestMintDelegatedCredentialSubQuorum proves the escrow dual-control holds: fewer
// than the threshold of recovery agents cannot recover the key, so no credential
// is minted.
func TestMintDelegatedCredentialSubQuorum(t *testing.T) {
	api, caID, agentIDs := dcEscrowAPI(t)
	envelope, serial, _ := exportEscrowedLeaf(t, api, caID)

	reqBody, _ := json.Marshal(models.MintDelegatedCredentialRequest{
		Serial:         serial,
		EscrowEnvelope: envelope,
		RecoveryAgents: agentIDs[:1], // below the 2-of-3 threshold
	})
	rec := mintDCRequest(t, api, caID, reqBody, rootUser())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sub-quorum status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMintDelegatedCredentialGuards covers the input/authorization guards that do
// not need a successful escrow recovery.
func TestMintDelegatedCredentialGuards(t *testing.T) {
	api, caID, agentIDs := dcEscrowAPI(t)

	// RBAC: a tenant auditor (no issue capability) is denied.
	auditor := tenantUser("carol", models.DefaultTenantID, "auditor")
	rec := mintDCRequest(t, api, caID, []byte(`{"serial":"1"}`), auditor)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}

	// Unknown serial -> 404.
	rec = mintDCRequest(t, api, caID, []byte(`{"serial":"99999999"}`), rootUser())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown-serial status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}

	// A cert that is NOT delegation-eligible (plain server profile) -> 400 before
	// any escrow work.
	res, err := ca.NewManager(api.db, api.keyProvider).IssueCertificate(context.Background(), ca.IssueSpec{
		CAID:    caID,
		CSRPEM:  testCSR(t, "plain.example.com"),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	reqBody, _ := json.Marshal(models.MintDelegatedCredentialRequest{
		Serial:         res.Serial.String(),
		EscrowEnvelope: json.RawMessage(`{}`),
		RecoveryAgents: agentIDs,
	})
	rec = mintDCRequest(t, api, caID, reqBody, rootUser())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ineligible-cert status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}

	// An eligible cert but an omitted escrow envelope -> 400 (escrow_envelope is
	// required). Built as a raw body so the field is genuinely absent.
	_, serial, _ := exportEscrowedLeaf(t, api, caID)
	raw := fmt.Sprintf(`{"serial":%q,"recovery_agents":["%s"]}`, serial, agentIDs[0])
	rec = mintDCRequest(t, api, caID, []byte(raw), rootUser())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing-envelope status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}
