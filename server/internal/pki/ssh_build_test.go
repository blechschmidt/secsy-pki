package pki

// The build/sign split (Task 224) exists so a caller can see the certificate
// before it is signed — the signing-restriction gate evaluates the resolved
// template, defaults and all. These tests pin the two halves directly: that the
// defaults are applied at build time, and that each half reports its own
// failures rather than the other's.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func buildTestSubjectKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(sshPub)
}

func TestBuildSSHCertificateAppliesTheDefaults(t *testing.T) {
	after := time.Now()
	before := after.Add(time.Hour)
	cert, err := BuildSSHCertificate(buildTestSubjectKey(t), ssh.UserCert, "ops@example.com",
		[]string{"deploy"}, after, before, nil, nil)
	if err != nil {
		t.Fatalf("BuildSSHCertificate: %v", err)
	}
	// A user certificate with no extensions named gets the defaults — which is
	// exactly what a restriction rule has to be able to see.
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Errorf("the user-certificate defaults were not applied: %v", cert.Extensions)
	}
	if cert.Serial == 0 || cert.KeyId != "ops@example.com" || len(cert.ValidPrincipals) != 1 {
		t.Errorf("unexpected certificate: serial=%d key id=%q principals=%v",
			cert.Serial, cert.KeyId, cert.ValidPrincipals)
	}
	if cert.Signature != nil {
		t.Error("a built certificate is not yet signed")
	}

	// A host certificate carries no extensions by default.
	host, err := BuildSSHCertificate(buildTestSubjectKey(t), ssh.HostCert, "host-1",
		[]string{"host1.example.com"}, after, before, nil, nil)
	if err != nil {
		t.Fatalf("BuildSSHCertificate(host): %v", err)
	}
	if len(host.Extensions) != 0 {
		t.Errorf("host extensions = %v, want none", host.Extensions)
	}

	// An unparseable public key fails at build time, before any key is opened.
	if _, err := BuildSSHCertificate([]byte("not a key"), ssh.UserCert, "k", nil, after, before, nil, nil); err == nil {
		t.Error("a malformed public key must not build")
	}
}

func TestSignBuiltSSHCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := BuildSSHCertificate(buildTestSubjectKey(t), ssh.UserCert, "ops",
		[]string{"deploy"}, time.Now(), time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := SignBuiltSSHCertificate(caKey, cert)
	if err != nil {
		t.Fatalf("SignBuiltSSHCertificate: %v", err)
	}
	if !strings.Contains(string(authorized), "-cert-v01@openssh.com") {
		t.Errorf("not an OpenSSH certificate: %q", authorized)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(authorized)
	if err != nil {
		t.Fatalf("parsing the signed certificate: %v", err)
	}
	signed, ok := parsed.(*ssh.Certificate)
	if !ok || signed.Signature == nil {
		t.Fatal("the result is not a signed certificate")
	}
	if signed.Serial != cert.Serial {
		t.Errorf("serial changed between build and sign: %d != %d", signed.Serial, cert.Serial)
	}

	// A signer whose public key OpenSSH cannot express fails here rather than
	// producing something unverifiable.
	if _, err := SignBuiltSSHCertificate(unsupportedSigner{}, cert); err == nil {
		t.Error("an unusable CA key must not produce a certificate")
	}
}

// unsupportedSigner is a crypto.Signer whose public key is not an SSH key type,
// so ssh.NewSignerFromSigner refuses it.
type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey { return struct{}{} }

func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not reached")
}
