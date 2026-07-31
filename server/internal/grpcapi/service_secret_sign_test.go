//go:build sqlite

package grpcapi

// Functional gRPC round-trip for the Task 153 signing service, on top of the
// authz-matrix coverage: it proves the proto <-> core mapping actually carries a
// signature end to end (create -> sign -> verify, plus a tampered negative) for
// an admin of tenant "a".

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
)

func TestGRPCSignRoundTrip(t *testing.T) {
	svc := newGRPCSecretService(t)
	ctx := withUser(grpcAdminA)
	msg := []byte("gRPC signing round-trip")

	created, err := svc.CreateSigningKey(ctx, &pkiv1.CreateSigningKeyRequest{
		Tenant: "a", Name: "svc-signer", Algorithm: "ecdsa-p256",
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	if created.GetPublicKeyPem() == "" || len(created.GetPublicKeyDer()) == 0 {
		t.Fatal("create response missing public key")
	}

	signed, err := svc.Sign(ctx, &pkiv1.SignRequest{Tenant: "a", Key: "svc-signer", Message: msg})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signed.GetSignature()) == 0 || signed.GetAlgorithm() != "ecdsa-p256" {
		t.Fatalf("unexpected sign response: %+v", signed)
	}

	verified, err := svc.Verify(ctx, &pkiv1.VerifyRequest{
		Tenant: "a", Key: "svc-signer", Message: msg, Signature: signed.GetSignature(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verified.GetValid() {
		t.Fatal("valid signature reported invalid over gRPC")
	}

	// Tampered message -> valid=false (not an error).
	bad := append([]byte{}, msg...)
	bad[0] ^= 0xff
	tampered, err := svc.Verify(ctx, &pkiv1.VerifyRequest{
		Tenant: "a", Key: "svc-signer", Message: bad, Signature: signed.GetSignature(),
	})
	if err != nil {
		t.Fatalf("Verify(tampered): %v", err)
	}
	if tampered.GetValid() {
		t.Fatal("tampered signature reported valid over gRPC")
	}

	// Duplicate name -> AlreadyExists.
	_, err = svc.CreateSigningKey(ctx, &pkiv1.CreateSigningKeyRequest{Tenant: "a", Name: "svc-signer", Algorithm: "ecdsa-p256"})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("duplicate create: code = %s, want AlreadyExists", status.Code(err))
	}

	// VerifyWithPublicKey: verify the same signature against the exported public
	// key (SPKI PEM) with no stored key.
	wpk, err := svc.VerifyWithPublicKey(ctx, &pkiv1.VerifyWithPublicKeyRequest{
		Tenant:       "a",
		Algorithm:    "ecdsa-p256",
		PublicKeyPem: created.GetPublicKeyPem(),
		Message:      msg,
		Signature:    signed.GetSignature(),
	})
	if err != nil {
		t.Fatalf("VerifyWithPublicKey: %v", err)
	}
	if !wpk.GetValid() {
		t.Fatal("valid signature reported invalid via VerifyWithPublicKey")
	}
	// Tampered message -> valid=false.
	wpkBad, err := svc.VerifyWithPublicKey(ctx, &pkiv1.VerifyWithPublicKeyRequest{
		Tenant: "a", Algorithm: "ecdsa-p256", PublicKeyPem: created.GetPublicKeyPem(),
		Message: bad, Signature: signed.GetSignature(),
	})
	if err != nil || wpkBad.GetValid() {
		t.Fatalf("VerifyWithPublicKey(tampered) = (%+v, %v)", wpkBad, err)
	}
}
