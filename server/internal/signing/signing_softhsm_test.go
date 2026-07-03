package signing

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// TestSigningSoftHSM is the Task 60 acceptance test: the code-signing keys, the
// CA key, and the TSA key all live on a PKCS#11 token (SoftHSM). It signs an
// artifact with both an ECDSA and an RSA signer, embeds an RFC 3161
// countersignature from the HSM-backed TSA, and verifies the result three
// ways: this package's Verify, `openssl cms -verify` (detached, and via the
// digest-input signing path), and `openssl ts -verify` on the extracted
// timestamp token. Skipped unless the SoftHSM environment is exported (run:
// eval "$(scripts/setup-softhsm.sh --export-env)").
func TestSigningSoftHSM(t *testing.T) {
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
	suffix := time.Now().Format("150405") + "-" + hsmRandHex(t)
	caLabel := "test-sign-ca-" + suffix
	tsaLabel := "test-sign-tsa-" + suffix

	// Self-signed RSA CA on the HSM.
	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: caLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: caLabel})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	t.Cleanup(func() { caSigner.Close() })
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM Signing Root " + suffix},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// HSM-backed RSA TSA (the CMS token path is RSA-only), with the sole
	// critical id-kp-timeStamping EKU.
	tsaInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: tsaLabel, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("generate TSA key: %v", err)
	}
	ekuVal, err := asn1.Marshal([]asn1.ObjectIdentifier{tsa.OIDExtKeyUsageTimeStamping})
	if err != nil {
		t.Fatal(err)
	}
	tsaDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "SoftHSM Signing TSA " + suffix},
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
		t.Fatalf("CreateLeafCertificate (TSA): %v", err)
	}
	tsaCert, err := x509.ParseCertificate(tsaDER)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := tsa.New(nil, provider, tsa.Config{
		KeyLabel:    tsaLabel,
		Certificate: tsaCert,
		Chain:       []*x509.Certificate{tsaCert, caCert},
		Accuracy:    tsa.Accuracy{Seconds: 1},
	})
	if err != nil {
		t.Fatalf("tsa.New: %v", err)
	}

	// Two HSM-held code-signing identities: ECDSA P-256 and RSA-2048.
	mkSigner := func(name, keyType string, serial int64) SignerConfig {
		t.Helper()
		label := "test-sign-" + name + "-" + suffix
		info, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyType})
		if err != nil {
			t.Fatalf("generate %s key: %v", name, err)
		}
		der, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
			Subject:     pkix.Name{CommonName: "SoftHSM Code Signer " + name + " " + suffix},
			PublicKey:   info.PublicKey,
			Serial:      big.NewInt(serial),
			NotBefore:   time.Now().Add(-time.Hour),
			NotAfter:    time.Now().Add(12 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		})
		if err != nil {
			t.Fatalf("CreateLeafCertificate (%s): %v", name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return SignerConfig{
			Name:               name,
			KeyLabel:           label,
			Certificate:        cert,
			Chain:              []*x509.Certificate{cert, caCert},
			TimestampByDefault: true,
		}
	}
	signers := []SignerConfig{
		mkSigner("ecdsa", keyprovider.KeyTypeECDSAP256, 3),
		mkSigner("rsa", keyprovider.KeyTypeRSA2048, 4),
	}

	svc, err := NewService(provider, authority, signers)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	openssl, opensslErr := exec.LookPath("openssl")
	artifact := []byte("secsy-pki release artifact " + suffix + "\n")

	for _, sc := range signers {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			res, err := svc.Sign(ctx, SignRequest{Signer: sc.Name, Content: artifact})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !res.Timestamped {
				t.Fatal("signature is not timestamped")
			}

			// In-package verification: chain to the HSM CA, timestamp adopted.
			v, err := Verify(VerifyRequest{
				Signature:        res.Signature,
				Content:          artifact,
				Roots:            []*x509.Certificate{caCert},
				RequireTimestamp: true,
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !v.VerifiedAt.Equal(v.TimestampGenTime) {
				t.Error("verification did not adopt the timestamp genTime")
			}

			if opensslErr != nil {
				t.Skip("signature verified; openssl not installed for interop check")
			}
			dir := t.TempDir()
			write := func(name string, data []byte) string {
				t.Helper()
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, data, 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			}
			artifactPath := write("artifact.bin", artifact)
			sigPath := write("sig.p7s", res.Signature)
			caPath := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))

			// openssl cms -verify of the detached signature. -purpose any because
			// openssl's default S/MIME purpose check would reject a codeSigning-EKU
			// certificate; chain building and signature checks remain in force.
			cmd := exec.Command(openssl, "cms", "-verify", "-binary",
				"-inform", "DER", "-in", sigPath,
				"-content", artifactPath,
				"-CAfile", caPath,
				"-purpose", "any",
				"-out", os.DevNull)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("openssl cms -verify failed: %v\n%s", err, out)
			}

			// Tampering must fail openssl verification too.
			tamperedPath := write("tampered.bin", append([]byte("x"), artifact...))
			cmd = exec.Command(openssl, "cms", "-verify", "-binary",
				"-inform", "DER", "-in", sigPath,
				"-content", tamperedPath,
				"-CAfile", caPath,
				"-purpose", "any",
				"-out", os.DevNull)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("openssl cms -verify accepted tampered content:\n%s", out)
			}

			// openssl ts -verify of the embedded RFC 3161 token: extract the token
			// and the signature value it covers, and check the imprint explicitly.
			parsed, err := cms.ParseSignedData(res.Signature)
			if err != nil {
				t.Fatal(err)
			}
			rawTok, ok := parsed.UnauthenticatedAttribute(OIDTimeStampToken)
			if !ok {
				t.Fatal("timestamp attribute missing")
			}
			tokenPath := write("token.der", rawTok.FullBytes)
			tsaPath := write("tsa.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tsaCert.Raw}))
			h := crypto.SHA256.New()
			h.Write(parsed.Signature())
			imprint := hex.EncodeToString(h.Sum(nil))

			cmd = exec.Command(openssl, "ts", "-verify",
				"-digest", imprint,
				"-token_in", "-in", tokenPath,
				"-CAfile", caPath,
				"-untrusted", tsaPath)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("openssl ts -verify of the countersignature failed: %v\n%s", err, out)
			}

			// Digest-input signing: the service never sees the artifact, yet
			// openssl verifies the signature against the real file.
			dh := sc.Digest
			if dh == 0 {
				dh = crypto.SHA256
			}
			ah := dh.New()
			ah.Write(artifact)
			res2, err := svc.Sign(ctx, SignRequest{Signer: sc.Name, Digest: ah.Sum(nil)})
			if err != nil {
				t.Fatalf("Sign by digest: %v", err)
			}
			sig2Path := write("sig2.p7s", res2.Signature)
			cmd = exec.Command(openssl, "cms", "-verify", "-binary",
				"-inform", "DER", "-in", sig2Path,
				"-content", artifactPath,
				"-CAfile", caPath,
				"-purpose", "any",
				"-out", os.DevNull)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("openssl cms -verify of digest-input signature failed: %v\n%s", err, out)
			}
		})
	}
}

func hsmRandHex(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}
