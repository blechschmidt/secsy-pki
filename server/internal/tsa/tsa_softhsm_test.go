package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestSoftHSMRoundTrip provisions the TSA key on a PKCS#11 token (SoftHSM),
// issues a time-stamp token whose CMS signature is produced entirely on the
// device, and verifies it — including openssl `ts -verify` interop. It is
// skipped unless the SoftHSM environment variables are exported (run:
// eval "$(scripts/setup-softhsm.sh --export-env)").
func TestSoftHSMRoundTrip(t *testing.T) {
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	provider, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
		ModulePath: module,
		Pin:        pin,
		TokenLabel: token,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	ctx := context.Background()
	suffix := time.Now().Format("150405") + "-" + randHex(t)
	caLabel := "test-tsa-ca-" + suffix
	tsaLabel := "test-tsa-key-" + suffix

	// Self-signed RSA CA on the HSM.
	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: caLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: caLabel})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM TSA Root"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	// TSA RSA key on the HSM + TSA certificate.
	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: tsaLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, _ := asn1.Marshal([]asn1.ObjectIdentifier{OIDExtKeyUsageTimeStamping})
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM TSA"},
		PublicKey: tsaInfo.PublicKey,
		Serial:    big.NewInt(2),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(12 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuVal},
		},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	tsaCert, _ := x509.ParseCertificate(tsaDER)

	authority, err := New(nil, provider, Config{
		KeyLabel:    tsaLabel,
		Certificate: tsaCert,
		Chain:       []*x509.Certificate{tsaCert, caCert},
		Accuracy:    Accuracy{Seconds: 1},
	})
	if err != nil {
		t.Fatalf("New authority: %v", err)
	}

	// Issue a token, signing on the HSM.
	data := []byte("softhsm interop payload")
	digest := sha256.Sum256(data)
	reqDER, _ := MakeRequest(crypto.SHA256, digest[:], &RequestOptions{Nonce: big.NewInt(0x1234), CertReq: true})
	result, err := authority.Stamp(ctx, reqDER)
	if err != nil || !result.Granted {
		t.Fatalf("Stamp: err=%v granted=%v", err, result.Granted)
	}

	// The HSM-produced signature must verify.
	tokenDER := parseGrantedResp(t, result.Response)
	sd, err := cms.ParseSignedData(tokenDER)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if err := sd.Verify(); err != nil {
		t.Fatalf("HSM-signed token failed verification: %v", err)
	}

	// openssl ts -verify interop against the HSM-signed token.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("token verified; openssl not installed for interop check")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "data.bin"), data)
	writeFile(t, filepath.Join(dir, "resp.tsr"), result.Response)
	writeFile(t, filepath.Join(dir, "ca.pem"), pemCert(caCert))
	writeFile(t, filepath.Join(dir, "tsa.pem"), pemCert(tsaCert))
	cmd := exec.Command(openssl, "ts", "-verify",
		"-data", filepath.Join(dir, "data.bin"),
		"-in", filepath.Join(dir, "resp.tsr"),
		"-CAfile", filepath.Join(dir, "ca.pem"),
		"-untrusted", filepath.Join(dir, "tsa.pem"))
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("Verification: OK")) {
		t.Fatalf("openssl ts -verify of HSM-signed token failed: %v\n%s", err, out)
	}
}

func randHex(t *testing.T) string {
	t.Helper()
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	const hex = "0123456789abcdef"
	return string([]byte{hex[b[0]&0xf], hex[b[1]&0xf], hex[b[2]&0xf]})
}
