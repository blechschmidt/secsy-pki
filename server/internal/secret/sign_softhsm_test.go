package secret

// SoftHSM acceptance test for Task 153: named HSM-backed asymmetric signatures
// with the private key generated NON-EXTRACTABLE on a real PKCS#11 token. It
// walks the full HSM signing path for every algorithm —
//
//	CreateSigningKey  (generate the key pair on the token, export only the public half)
//	→ Sign            (the private-key operation runs on the token: CKM_ECDSA,
//	                   CKM_RSA_PKCS, or CKM_RSA_PKCS_PSS)
//	→ Verify          (against the exported public key, no HSM)
//	→ openssl dgst -verify  (an independent, external verifier confirms the
//	                   signature is standards-conformant, not just self-consistent)
//
// Mirrors the other *_softhsm_test.go files: skipped unless setup-softhsm.sh's
// environment is present. RSA-4096 key generation is slow on SoftHSM, so those
// algorithms are skipped under -short.

import (
	"context"
	"crypto"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func TestHSMSignVerifyAndOpenSSLCrossVerify(t *testing.T) {
	ctx := context.Background()
	prov := pkcs11Provider(t) // skips unless SoftHSM is configured
	opensslPath, hasOpenSSL := lookOpenSSL()

	store := newFakeSigningKeyStore()
	msg := []byte("Task 153: HSM-backed application-level signatures over arbitrary data.")

	type algCase struct {
		alg     SigningAlgorithm
		pss     bool
		ed      bool
		slowRSA bool
	}
	cases := []algCase{
		{alg: AlgECDSAP256},
		{alg: AlgECDSAP384},
		{alg: AlgECDSAP521},
		{alg: AlgEd25519, ed: true},
		{alg: AlgRSAPSS2048, pss: true},
		{alg: AlgRSAPKCS1v152048},
		{alg: AlgRSAPSS3072, pss: true, slowRSA: true},
		{alg: AlgRSAPKCS1v153072, slowRSA: true},
		{alg: AlgRSAPSS4096, pss: true, slowRSA: true},
		{alg: AlgRSAPKCS1v154096, slowRSA: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			if tc.slowRSA && testing.Short() {
				t.Skip("skipping slow RSA-3072/4096 HSM key generation under -short")
			}
			row, err := CreateSigningKey(ctx, prov, store, CreateSigningKeySpec{
				TenantID: "default", Name: "hsm-" + string(tc.alg), Algorithm: tc.alg, CreatedBy: "test",
			})
			if err != nil {
				t.Fatalf("CreateSigningKey on HSM: %v", err)
			}
			// The private key must live on the token, not in software.
			if row.Provider != "pkcs11" {
				t.Fatalf("expected pkcs11 provider, got %q", row.Provider)
			}

			// Sign on the token, verify against the exported public key.
			res, err := Sign(ctx, prov, row, msg, "", false)
			if err != nil {
				t.Fatalf("Sign on HSM: %v", err)
			}
			ok, err := Verify(row, msg, res.Signature, "", false)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Fatal("HSM signature failed to verify against the exported public key")
			}
			// A tampered message must not verify.
			bad := append([]byte{}, msg...)
			bad[0] ^= 0xff
			if ok, _ := Verify(row, bad, res.Signature, "", false); ok {
				t.Fatal("tampered message verified")
			}

			// Independent cross-verification with the openssl CLI.
			if !hasOpenSSL {
				t.Log("openssl not found; skipping external cross-verification")
				return
			}
			opensslCrossVerify(t, opensslPath, row, msg, res.Signature, tc.pss, tc.ed)
		})
	}
}

// opensslCrossVerify writes the exported public key, the message, and the raw
// signature to disk and asks openssl to check them, so an external implementation
// independently confirms the HSM signature is standards-conformant. ECDSA and RSA
// use `openssl dgst -verify`; Ed25519 (a one-shot algorithm over the raw message)
// uses `openssl pkeyutl -verify -rawin`.
func opensslCrossVerify(t *testing.T, opensslPath string, row *models.SigningKey, msg, sig []byte, pss, ed bool) {
	t.Helper()
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "pub.pem")
	msgPath := filepath.Join(dir, "msg.bin")
	sigPath := filepath.Join(dir, "sig.bin")

	pemBytes, err := PublicKeyPEM(row)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	writeFile(t, pubPath, pemBytes)
	writeFile(t, msgPath, msg)
	writeFile(t, sigPath, sig)

	var args []string
	if ed {
		// Ed25519 verifies the raw message directly (no -dgst hash step).
		args = []string{"pkeyutl", "-verify", "-pubin", "-inkey", pubPath, "-rawin", "-in", msgPath, "-sigfile", sigPath}
	} else {
		hash := SigningAlgorithm(row.Algorithm).DefaultHash()
		args = []string{"dgst", "-" + HashName(hash), "-verify", pubPath, "-signature", sigPath}
		if pss {
			args = append(args,
				"-sigopt", "rsa_padding_mode:pss",
				"-sigopt", opensslSaltOpt(hash),
			)
		}
		args = append(args, msgPath)
	}

	cmd := exec.Command(opensslPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl verify failed (%v): %s\nargs: %v", err, out, args)
	}
	// `dgst -verify` prints "Verified OK"; `pkeyutl -verify` prints "Signature Verified Successfully".
	got := string(out)
	if !strings.Contains(got, "Verified OK") && !strings.Contains(got, "Signature Verified Successfully") {
		t.Fatalf("openssl did not report success: %q\nargs: %v", out, args)
	}
}

// opensslSaltOpt returns the rsa_pss_saltlen sigopt matching this package's
// SaltLength == hash length choice.
func opensslSaltOpt(hash crypto.Hash) string {
	switch hash {
	case crypto.SHA256:
		return "rsa_pss_saltlen:32"
	case crypto.SHA384:
		return "rsa_pss_saltlen:48"
	case crypto.SHA512:
		return "rsa_pss_saltlen:64"
	default:
		return "rsa_pss_saltlen:-1"
	}
}

func lookOpenSSL() (string, bool) {
	p, err := exec.LookPath("openssl")
	if err != nil {
		return "", false
	}
	return p, true
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
