//go:build sqlite

package handlers

// Functional tests for the named HSM-backed signing service (Task 153): create a
// signing key, sign, verify (good and tampered), export the public key, and list
// — end-to-end against a software provider and a real in-memory database.
// Authorization/tenant isolation is covered by the authz matrix; these tests
// prove the crypto and persistence actually round-trip through the shared *Op
// methods that back both REST and gRPC.

import (
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// rootSignCtx returns a context carrying the built-in root principal (allow-all)
// plus a tenant holder, matching what the middleware installs per request.
func rootSignCtx() context.Context {
	ctx := context.WithValue(context.Background(), middleware.UserInfoKey, rootUser())
	return middleware.WithTenantHolder(ctx)
}

func defaultTenant(t *testing.T, api *API) *models.Tenant {
	t.Helper()
	tenant, err := api.db.GetTenant(models.DefaultTenantID)
	if err != nil || tenant == nil {
		t.Fatalf("default tenant unavailable: %v", err)
	}
	return tenant
}

func TestSigningKeyLifecycle(t *testing.T) {
	api := newCryptoAPI(t)
	ctx := rootSignCtx()
	tenant := defaultTenant(t, api)
	msg := []byte("sign me over REST and gRPC alike")

	// Create.
	info, err := api.CreateSigningKeyOp(ctx, "", tenant, "app-signer", "ecdsa-p256")
	if err != nil {
		t.Fatalf("CreateSigningKeyOp: %v", err)
	}
	if info.Algorithm != "ecdsa-p256" || info.PublicKeyPEM == "" || len(info.PublicKeyDER) == 0 {
		t.Fatalf("unexpected key info: %+v", info)
	}

	// Duplicate name -> conflict.
	if _, err := api.CreateSigningKeyOp(ctx, "", tenant, "app-signer", "ecdsa-p256"); err == nil {
		t.Fatal("expected duplicate-name error")
	} else if SecretErrorKind(err) != "conflict" {
		t.Errorf("duplicate: kind = %q, want conflict", SecretErrorKind(err))
	}

	// Unknown algorithm -> bad_request.
	if _, err := api.CreateSigningKeyOp(ctx, "", tenant, "other", "rsa-1024"); SecretErrorKind(err) != "bad_request" {
		t.Errorf("bad algorithm: kind = %q, want bad_request", SecretErrorKind(err))
	}

	// Sign.
	sig, err := api.SignOp(ctx, "", tenant, "app-signer", msg, nil, "")
	if err != nil {
		t.Fatalf("SignOp: %v", err)
	}
	if len(sig.Signature) == 0 || sig.Algorithm != "ecdsa-p256" || sig.Hash != "sha256" {
		t.Fatalf("unexpected sign result: %+v", sig)
	}

	// Verify (good).
	v, err := api.VerifySignatureOp(ctx, "", tenant, "app-signer", msg, nil, sig.Signature, "")
	if err != nil {
		t.Fatalf("VerifySignatureOp: %v", err)
	}
	if !v.Valid {
		t.Fatal("valid signature reported invalid")
	}

	// Verify (tampered) -> valid=false, not an error.
	bad := append([]byte{}, msg...)
	bad[0] ^= 0xff
	v, err = api.VerifySignatureOp(ctx, "", tenant, "app-signer", bad, nil, sig.Signature, "")
	if err != nil {
		t.Fatalf("VerifySignatureOp(tampered): %v", err)
	}
	if v.Valid {
		t.Fatal("tampered signature reported valid")
	}

	// Get public key.
	got, err := api.GetSigningKeyPublicOp(ctx, "", tenant, "app-signer")
	if err != nil {
		t.Fatalf("GetSigningKeyPublicOp: %v", err)
	}
	if got.PublicKeyPEM != info.PublicKeyPEM {
		t.Error("exported public key differs from the created key")
	}

	// List.
	list, err := api.ListSigningKeysOp(ctx, "", tenant)
	if err != nil {
		t.Fatalf("ListSigningKeysOp: %v", err)
	}
	if len(list) != 1 || list[0].Name != "app-signer" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

// TestEd25519SigningOp covers the Ed25519 algorithm through the shared *Op layer:
// it signs the message directly (no selectable hash, reported hash "none"), and a
// caller-specified hash or pre-hashed digest is a fail-closed bad request.
func TestEd25519SigningOp(t *testing.T) {
	api := newCryptoAPI(t)
	ctx := rootSignCtx()
	tenant := defaultTenant(t, api)
	msg := []byte("ed25519 over the crypto service")

	info, err := api.CreateSigningKeyOp(ctx, "", tenant, "ed-signer", "ed25519")
	if err != nil {
		t.Fatalf("CreateSigningKeyOp(ed25519): %v", err)
	}
	if info.Algorithm != "ed25519" || info.PublicKeyPEM == "" {
		t.Fatalf("unexpected ed25519 key info: %+v", info)
	}

	sig, err := api.SignOp(ctx, "", tenant, "ed-signer", msg, nil, "")
	if err != nil {
		t.Fatalf("SignOp(ed25519): %v", err)
	}
	if sig.Hash != "none" {
		t.Errorf("ed25519 sign hash = %q, want none", sig.Hash)
	}
	v, err := api.VerifySignatureOp(ctx, "", tenant, "ed-signer", msg, nil, sig.Signature, "")
	if err != nil || !v.Valid {
		t.Fatalf("VerifySignatureOp(ed25519) = (%+v, %v)", v, err)
	}

	// A caller-specified hash is a fail-closed bad request for Ed25519.
	if _, err := api.SignOp(ctx, "", tenant, "ed-signer", msg, nil, "sha256"); SecretErrorKind(err) != "bad_request" {
		t.Errorf("ed25519 with hash: kind = %q, want bad_request", SecretErrorKind(err))
	}
	// A pre-hashed digest is likewise rejected.
	if _, err := api.SignOp(ctx, "", tenant, "ed-signer", nil, []byte("digest"), ""); SecretErrorKind(err) != "bad_request" {
		t.Errorf("ed25519 with digest: kind = %q, want bad_request", SecretErrorKind(err))
	}
}

// TestVerifyWithSuppliedKeyOp covers verifying a signature against a caller-
// supplied public key (no stored key), including the tampered and mismatch cases.
func TestVerifyWithSuppliedKeyOp(t *testing.T) {
	api := newCryptoAPI(t)
	ctx := rootSignCtx()
	tenant := defaultTenant(t, api)
	msg := []byte("verify against a supplied public key over the crypto service")

	// Create a key and sign, then export its public half.
	info, err := api.CreateSigningKeyOp(ctx, "", tenant, "sk", "ecdsa-p256")
	if err != nil {
		t.Fatalf("CreateSigningKeyOp: %v", err)
	}
	sig, err := api.SignOp(ctx, "", tenant, "sk", msg, nil, "")
	if err != nil {
		t.Fatalf("SignOp: %v", err)
	}
	pubPEM := []byte(info.PublicKeyPEM)

	// Verify against the supplied PEM public key: valid.
	res, err := api.VerifyWithSuppliedKeyOp(ctx, "", tenant, "ecdsa-p256", pubPEM, nil, msg, nil, sig.Signature, "")
	if err != nil {
		t.Fatalf("VerifyWithSuppliedKeyOp: %v", err)
	}
	if !res.Valid {
		t.Fatal("valid signature reported invalid against supplied key")
	}

	// The DER form works too.
	pubDER := info.PublicKeyDER
	if resDER, err := api.VerifyWithSuppliedKeyOp(ctx, "", tenant, "ecdsa-p256", nil, pubDER, msg, nil, sig.Signature, ""); err != nil || !resDER.Valid {
		t.Fatalf("supplied DER key verify = (%+v, %v)", resDER, err)
	}

	// Tampered message -> valid=false (not an error).
	bad := append([]byte{}, msg...)
	bad[0] ^= 0xff
	res, err = api.VerifyWithSuppliedKeyOp(ctx, "", tenant, "ecdsa-p256", pubPEM, nil, bad, nil, sig.Signature, "")
	if err != nil || res.Valid {
		t.Fatalf("tampered supplied-key verify = (%+v, %v)", res, err)
	}

	// Unknown algorithm -> bad_request.
	if _, err := api.VerifyWithSuppliedKeyOp(ctx, "", tenant, "nope", pubPEM, nil, msg, nil, sig.Signature, ""); SecretErrorKind(err) != "bad_request" {
		t.Errorf("bad algorithm: kind = %q, want bad_request", SecretErrorKind(err))
	}
	// Missing key material -> bad_request.
	if _, err := api.VerifyWithSuppliedKeyOp(ctx, "", tenant, "ecdsa-p256", nil, nil, msg, nil, sig.Signature, ""); SecretErrorKind(err) != "bad_request" {
		t.Errorf("no key: kind = %q, want bad_request", SecretErrorKind(err))
	}
	// Garbage public key -> bad_request.
	if _, err := api.VerifyWithSuppliedKeyOp(ctx, "", tenant, "ecdsa-p256", []byte("not a key"), nil, msg, nil, sig.Signature, ""); SecretErrorKind(err) != "bad_request" {
		t.Errorf("garbage key: kind = %q, want bad_request", SecretErrorKind(err))
	}
}

func TestSignUnknownKeyAndBadInput(t *testing.T) {
	api := newCryptoAPI(t)
	ctx := rootSignCtx()
	tenant := defaultTenant(t, api)

	// Unknown key -> bad_request (not a 500, not an existence oracle via 404).
	if _, err := api.SignOp(ctx, "", tenant, "nope", []byte("x"), nil, ""); SecretErrorKind(err) != "bad_request" {
		t.Errorf("unknown key: kind = %q, want bad_request", SecretErrorKind(err))
	}

	if _, err := api.CreateSigningKeyOp(ctx, "", tenant, "rsa", "rsa-pss-2048"); err != nil {
		t.Fatalf("create rsa key: %v", err)
	}
	// Neither message nor digest -> bad_request.
	if _, err := api.SignOp(ctx, "", tenant, "rsa", nil, nil, ""); SecretErrorKind(err) != "bad_request" {
		t.Errorf("no data: kind = %q, want bad_request", SecretErrorKind(err))
	}
	// Unsupported hash -> bad_request.
	if _, err := api.SignOp(ctx, "", tenant, "rsa", []byte("x"), nil, "md5"); SecretErrorKind(err) != "bad_request" {
		t.Errorf("bad hash: kind = %q, want bad_request", SecretErrorKind(err))
	}
}
