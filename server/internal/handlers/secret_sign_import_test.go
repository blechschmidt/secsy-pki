//go:build sqlite

package handlers

// Tests for POST /api/secret/signing-keys/import (Task 198), the REST form of
// `secsy-secret signing-key import`.
//
// Two properties carry the weight here. The first is that an ADOPTED key is
// indistinguishable from a generated one: the response has the same field set as
// POST /api/secret/signing-keys, and the registry row it wrote signs with the
// very key the operator supplied — checked by verifying the signature against the
// original public half outside this package's code. The second is the property
// that follows from a request body carrying a private key: nothing about that
// material is ever echoed, audited or reachable before the authorization gate.
// TestImportSigningKeyNeverEchoesKeyMaterial and
// TestImportSigningKeyAuthorizesBeforeTouchingKeyMaterial are those assertions.

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// importSigningKeyBody builds a request body adopting keyPEM under name.
func importSigningKeyBody(t *testing.T, name, algorithm, keyPEM string) string {
	t.Helper()
	body := `{"name":` + mustJSON(t, name)
	if algorithm != "" {
		body += `,"algorithm":` + mustJSON(t, algorithm)
	}
	return body + `,"key_pem":` + mustJSON(t, keyPEM) + `}`
}

// jsonFieldNames returns the sorted top-level field names of a JSON object, so a
// test can compare two responses' SHAPES rather than their values.
func jsonFieldNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("decode JSON object: %v (body=%s)", err, raw)
	}
	names := make([]string, 0, len(obj))
	for k := range obj {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// TestImportSigningKeyRoundTrip: an existing P-256 key is adopted, the response
// carries exactly the shape creation returns, and the registered key really is
// the supplied one — proved by verifying a signature it produced against the
// original public half.
func TestImportSigningKeyRoundTrip(t *testing.T) {
	api := newCryptoAPI(t)
	keyPEM, key := ecKeyPEM(t)

	rec := postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import",
		importSigningKeyBody(t, "adopted-signer", "", keyPEM))
	if rec.Code != http.StatusCreated {
		t.Fatalf("import = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var got signingKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	// The algorithm is derived from the key material, exactly as the CLI derives
	// it when -algorithm is omitted for an EC key.
	if got.Algorithm != "ecdsa-p256" {
		t.Errorf("algorithm = %q, want ecdsa-p256 (derived from the key)", got.Algorithm)
	}
	if got.Name != "adopted-signer" || got.ID == "" || got.Provider == "" || got.CreatedAt == "" {
		t.Errorf("incomplete key metadata: %+v", got)
	}

	// The exported public half is the supplied key's.
	wantSPKI, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(got.PublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("public_key_pem is not a PUBLIC KEY block: %q", got.PublicKeyPEM)
	}
	if string(block.Bytes) != string(wantSPKI) {
		t.Error("the exported public key is not the imported key's public half")
	}

	// Indistinguishable from a generated key: same response field set.
	createRec := postAs(api.CreateSigningKey, rootUser(), "/api/secret/signing-keys",
		`{"name":"generated-signer","algorithm":"ecdsa-p256"}`)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201; body=%s", createRec.Code, createRec.Body.String())
	}
	imported, created := jsonFieldNames(t, rec.Body.Bytes()), jsonFieldNames(t, createRec.Body.Bytes())
	if strings.Join(imported, ",") != strings.Join(created, ",") {
		t.Errorf("import response shape %v differs from create's %v", imported, created)
	}

	// …and it signs as itself: the provider's signature over a message verifies
	// under the ORIGINAL public key, which is the only check that shows the
	// adopted material, and not some freshly generated key, is what got stored.
	ctx := rootSignCtx()
	tenant := defaultTenant(t, api)
	msg := []byte("signed by the key we adopted")
	sig, err := api.SignOp(ctx, "", tenant, "adopted-signer", msg, nil, "")
	if err != nil {
		t.Fatalf("SignOp on the imported key: %v", err)
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig.Signature) {
		t.Error("the signature does not verify under the imported key's original public half")
	}

	// It is a first-class registry row: listing shows it beside the generated one.
	list, err := api.ListSigningKeysOp(ctx, "", tenant)
	if err != nil {
		t.Fatalf("ListSigningKeysOp: %v", err)
	}
	names := map[string]bool{}
	for _, k := range list {
		names[k.Name] = true
	}
	if !names["adopted-signer"] || !names["generated-signer"] {
		t.Errorf("listing does not carry both keys: %v", names)
	}
}

// TestImportSigningKeyDerivesAndValidatesAlgorithm covers the one way import
// differs from creation: the algorithm is optional, because the key material
// usually determines it — except for RSA, where PSS and PKCS#1 v1.5 are both
// possible and guessing would produce signatures nothing accepts.
func TestImportSigningKeyDerivesAndValidatesAlgorithm(t *testing.T) {
	api := newCryptoAPI(t)
	rsaPEM, _ := rsaKeyPEM(t, 2048)

	rec := postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import",
		importSigningKeyBody(t, "rsa-no-alg", "", rsaPEM))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("RSA without an algorithm = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "algorithm") {
		t.Errorf("the 400 does not say an algorithm is needed: %s", rec.Body.String())
	}

	rec = postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import",
		importSigningKeyBody(t, "rsa-signer", "rsa-pss-2048", rsaPEM))
	if rec.Code != http.StatusCreated {
		t.Fatalf("RSA with an algorithm = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// An algorithm that does not exist is a bad request, as on creation.
	ecPEM, _ := ecKeyPEM(t)
	rec = postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import",
		importSigningKeyBody(t, "bogus-alg", "rsa-1024", ecPEM))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported algorithm = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestImportSigningKeyDuplicateName: the name is the registry's key, so a second
// import under the same name is a 409 — the classification CreateSigningKey gives
// the same collision.
func TestImportSigningKeyDuplicateName(t *testing.T) {
	api := newCryptoAPI(t)
	keyPEM, _ := ecKeyPEM(t)
	body := importSigningKeyBody(t, "taken", "", keyPEM)

	if rec := postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import", body); rec.Code != http.StatusCreated {
		t.Fatalf("first import = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	rec := postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate import = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestImportSigningKeyRejectsUnusableMaterial: material that is not a private key
// at all is a bad request with a message that does not quote the input.
func TestImportSigningKeyRejectsUnusableMaterial(t *testing.T) {
	api := newCryptoAPI(t)
	const notAKey = "this-is-not-a-key-it-is-a-sentence"

	rec := postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import",
		importSigningKeyBody(t, "junk", "", notAKey))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage material = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), notAKey) {
		t.Errorf("the error quotes the supplied material: %s", rec.Body.String())
	}

	// No material at all is the same 400, and it names the two fields.
	rec = postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import", `{"name":"empty"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "key_pem") {
		t.Fatalf("missing material = %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestImportSigningKeyAuthorizesBeforeTouchingKeyMaterial: a principal without
// secret:signing-key is refused 403 even though its body would ALSO have failed
// validation. The ordering is the point — the material of an unauthorized caller
// is never base64-decoded, decrypted or parsed by this process, and the caller
// learns nothing about its request beyond "no".
func TestImportSigningKeyAuthorizesBeforeTouchingKeyMaterial(t *testing.T) {
	api := newCryptoAPI(t)
	auditor := tenantUser("reader", models.DefaultTenantID, "auditor")

	rec := postAs(api.ImportSigningKeyHandler, auditor, "/api/secret/signing-keys/import",
		importSigningKeyBody(t, "sneaky", "not-an-algorithm", "not-a-key"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthorized import = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "secret:signing-key") {
		t.Errorf("the 403 does not name the required capability: %s", rec.Body.String())
	}
	// The denial is in the event log, and no key was registered.
	if log := eventDetails(t, api.db); !strings.Contains(log, audit.ActionSecretSigningKeyImport) {
		t.Errorf("the denied import produced no audit event; log:\n%s", log)
	}
	rows, err := api.db.ListSigningKeys(models.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("a refused import registered %d key(s)", len(rows))
	}
}

// TestImportSigningKeyBodyIsSizeLimited: the body is capped BEFORE it is decoded,
// so an authenticated caller cannot stream arbitrary volume into a JSON decoder
// on an endpoint that exists to receive key material.
func TestImportSigningKeyBodyIsSizeLimited(t *testing.T) {
	api := newCryptoAPI(t)
	oversized := `{"name":"huge","key_pem":"` + strings.Repeat("A", maxKeyImportBody+1024) + `"}`

	rec := postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import", oversized)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestImportSigningKeyNeverEchoesKeyMaterial is the systematic secrecy assertion:
// a private key and a passphrase go in, and neither the response body nor any
// audit event — on success OR on failure — contains any part of either.
func TestImportSigningKeyNeverEchoesKeyMaterial(t *testing.T) {
	api := newCryptoAPI(t)
	keyPEM, _ := ecKeyPEM(t)
	const passphrase = "correct-horse-battery-staple"

	// The body of the key without its PEM armour: the bytes that must not appear.
	secrets := []string{strings.TrimSpace(strings.Split(keyPEM, "\n")[1]), passphrase}
	body := `{"name":"secrecy","passphrase":"` + passphrase + `","key_pem":` + mustJSON(t, keyPEM) + `}`

	for _, want := range []int{http.StatusCreated, http.StatusConflict} { // second call is the duplicate
		rec := postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import", body)
		if rec.Code != want {
			t.Fatalf("import = %d, want %d; body=%s", rec.Code, want, rec.Body.String())
		}
		for _, s := range secrets {
			if strings.Contains(rec.Body.String(), s) {
				t.Fatalf("response echoes secret material (status %d): %s", rec.Code, rec.Body.String())
			}
		}
		if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
			t.Fatalf("response echoes PEM key armour (status %d): %s", rec.Code, rec.Body.String())
		}
	}

	log := eventDetails(t, api.db)
	if !strings.Contains(log, audit.ActionSecretSigningKeyImport) {
		t.Fatalf("expected %s events; log:\n%s", audit.ActionSecretSigningKeyImport, log)
	}
	for _, s := range secrets {
		if strings.Contains(log, s) {
			t.Errorf("the audit log carries secret material; log:\n%s", log)
		}
	}
	if strings.Contains(log, "PRIVATE KEY") {
		t.Errorf("the audit log carries PEM key armour; log:\n%s", log)
	}
	// What it DOES record is the shape of the import.
	for _, want := range []string{"source_format=", "imported=true", "algorithm=ecdsa-p256"} {
		if !strings.Contains(log, want) {
			t.Errorf("the audit detail is missing %q; log:\n%s", want, log)
		}
	}
}

// importFailingProvider is a key provider whose ImportKey fails with a supplied
// error, everything else delegating to the wrapped one. It stands in for a backend
// that is refusing or unreachable — the case no software keystore can produce and
// the one whose misclassification the tests below pin.
type importFailingProvider struct {
	keyprovider.Provider
	err error
}

func (p importFailingProvider) ImportKey(context.Context, keyprovider.ImportSpec) (*keyprovider.KeyInfo, error) {
	return nil, p.err
}

// TestImportSigningKeyServerFailureIs500 is the classification invariant: only the
// failures the caller's material decided are 400; every other failure is 500.
//
// It was a 400 for all of them, including secret.ImportSigningKey's server-side
// paths — and one of those, the registry INSERT, runs AFTER the key is already in
// the provider. An operator told "bad request" retries the same body, and each
// retry mints a fresh id, hence a fresh label, hence another stranded
// non-extractable key. The audit detail is asserted too: it used to be the fixed
// string "signing-key import failed" while the real reason went only to the caller,
// so the event log could not tell an operator why a key had been stranded.
func TestImportSigningKeyServerFailureIs500(t *testing.T) {
	keyPEM, _ := ecKeyPEM(t)

	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
	}{
		// A backend that is down or refusing is ours, not the caller's.
		{"token unreachable", errors.New("pkcs11: token unreachable"), http.StatusInternalServerError},
		{"object creation refused", errors.New("C_CreateObject: CKR_DEVICE_ERROR"), http.StatusInternalServerError},
		// A host-side rejection is the caller's, and stays a 400.
		{"policy rejection", fmt.Errorf("%w: it fails the key-quality gate", keyprovider.ErrImportRejected),
			http.StatusBadRequest},
		{"backend cannot import", fmt.Errorf("%w (backend \"kms\")", keyprovider.ErrImportUnsupported),
			http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newCryptoAPI(t)
			api.keyProvider = importFailingProvider{Provider: api.keyProvider, err: tc.err}

			rec := postAs(api.ImportSigningKeyHandler, rootUser(), "/api/secret/signing-keys/import",
				importSigningKeyBody(t, "classify", "", keyPEM))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			// Whatever the class, the failure is recorded with the SAME text the
			// caller was given — if it is safe to return it is safe to log — and never
			// with the old fixed placeholder.
			log := eventDetails(t, api.db)
			if strings.Contains(log, "signing-key import failed") {
				t.Errorf("the audit detail is still the fixed placeholder:\n%s", log)
			}
			if !strings.Contains(log, tc.err.Error()) {
				t.Errorf("the audit detail does not carry the reason %q:\n%s", tc.err.Error(), log)
			}
			// …and never the key material, whatever the class.
			if strings.Contains(log, "PRIVATE KEY") {
				t.Errorf("the audit detail carries PEM key armour:\n%s", log)
			}
			// Nothing was registered under the name, so a retry is not a duplicate.
			rows, err := api.db.ListSigningKeys(models.DefaultTenantID)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Errorf("a failed import registered %d key(s)", len(rows))
			}
		})
	}
}
