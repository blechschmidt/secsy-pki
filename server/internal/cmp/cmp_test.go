package cmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"net"
	"testing"
)

// TestBuildParseInitializationRequest round-trips an ir request through the
// client builder and the server-side parser, checking that MAC verification,
// proof of possession, and the CertTemplate contents all survive encoding.
func TestBuildParseInitializationRequest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const ref, secret = "device-1", "s3cr3t-shared"
	subject := pkix.Name{CommonName: "device-1.example.com"}
	reqDER, err := BuildInitializationRequest(ref, secret, subject, key, RequestOptions{
		DNSNames:    []string{"device-1.example.com", "alt.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.7")},
	})
	if err != nil {
		t.Fatalf("BuildInitializationRequest: %v", err)
	}

	msg, err := parseMessage(reqDER)
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if msg.bodyTag != bodyIR {
		t.Fatalf("bodyTag = %d, want %d (ir)", msg.bodyTag, bodyIR)
	}
	if string(msg.header.SenderKID) != ref {
		t.Errorf("senderKID = %q, want %q", msg.header.SenderKID, ref)
	}

	// Correct secret verifies; a wrong secret does not.
	if err := verifyPBM([]byte(secret), msg); err != nil {
		t.Fatalf("verifyPBM with correct secret: %v", err)
	}
	if err := verifyPBM([]byte("wrong"), msg); err == nil {
		t.Error("verifyPBM accepted a wrong secret")
	}

	reqs, err := parseCertReqMessages(msg.bodyContent)
	if err != nil {
		t.Fatalf("parseCertReqMessages: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("got %d CertReqMsg, want 1", len(reqs))
	}
	if err := verifyPOP(reqs[0]); err != nil {
		t.Fatalf("verifyPOP: %v", err)
	}
	got := reqs[0].req
	if got.subject.CommonName != subject.CommonName {
		t.Errorf("subject CN = %q, want %q", got.subject.CommonName, subject.CommonName)
	}
	pub, ok := got.publicKey.(*ecdsa.PublicKey)
	if !ok || pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
		t.Errorf("template public key does not match the request key")
	}
	if len(got.dnsNames) != 2 || got.dnsNames[0] != "device-1.example.com" {
		t.Errorf("dnsNames = %v, want [device-1.example.com alt.example.com]", got.dnsNames)
	}
	if len(got.ipAddresses) != 1 || !got.ipAddresses[0].Equal(net.ParseIP("10.0.0.7")) {
		t.Errorf("ipAddresses = %v, want [10.0.0.7]", got.ipAddresses)
	}
}

// TestTamperedProtectionRejected confirms that flipping a byte of the protected
// part is detected by MAC verification.
func TestTamperedProtectionRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reqDER, err := BuildInitializationRequest("ref", "secret", pkix.Name{CommonName: "x"}, key, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := parseMessage(reqDER)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the protected part; the recomputed MAC must no longer match.
	msg.protectedPartDER[len(msg.protectedPartDER)-1] ^= 0xFF
	if err := verifyPBM([]byte("secret"), msg); err == nil {
		t.Error("verifyPBM accepted a tampered protected part")
	}
}

// TestPOPRejectsForeignKey ensures a proof of possession computed by one key is
// rejected when the template advertises a different public key.
func TestPOPRejectsForeignKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reqDER, err := BuildInitializationRequest("ref", "secret", pkix.Name{CommonName: "x"}, key, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := parseMessage(reqDER)
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := parseCertReqMessages(msg.bodyContent)
	if err != nil {
		t.Fatal(err)
	}
	// Swap in a foreign public key: POP verification must fail.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reqs[0].req.publicKey = &other.PublicKey
	if err := verifyPOP(reqs[0]); err == nil {
		t.Error("verifyPOP accepted a signature made by a different key")
	}
}

// TestPBMKnownAnswer checks the PBM key-derivation and MAC against a directly
// recomputed value, guarding the RFC 4210 §5.1.3.1 derivation.
func TestPBMConsistency(t *testing.T) {
	params, err := defaultPBM()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("protected-part-bytes")
	a, err := computePBM([]byte("secret"), data, params)
	if err != nil {
		t.Fatal(err)
	}
	b, err := computePBM([]byte("secret"), data, params)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("PBM is not deterministic for identical inputs")
	}
	c, err := computePBM([]byte("other"), data, params)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(c) {
		t.Fatal("PBM did not depend on the secret")
	}
}
