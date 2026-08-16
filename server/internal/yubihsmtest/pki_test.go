//go:build sqlite

package yubihsmtest

// Tier 6: the product, on the device.
//
// The tiers below prove that the device works and that the provider can drive
// it. None of them proves that secsy-pki works on a YubiHSM, because every
// higher-level test in this repository runs against SoftHSM — a software token
// whose keys are files. This tier closes that gap: it stands up a real CA on
// the hardware and exercises the paths a deployment actually depends on.
//
// The `sqlite` build tag is here because the CA, SSH CA and TSA all persist
// through the store; the rest of the suite needs no tag.
//
// It is deliberately one test rather than several. A CA on this device costs a
// key generation per authority — seconds for ECDSA, most of a minute for RSA —
// and every subtest that built its own would pay again, so the CA is built once
// and each phase is a subtest over it. That also mirrors the real thing: these
// operations happen in sequence against one authority, not in isolation.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/sshca"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// TestPKIOnHardware runs the CA lifecycle end to end against the device.
func TestPKIOnHardware(t *testing.T) {
	requireDevice(t)
	// A root, an intermediate, a leaf, a CRL, an OCSP response and an SSH CA is
	// a lot of audited operations; make room before starting rather than
	// failing halfway with a full log.
	keepLogSpace(t, 40)

	// Every key this test creates carries the suite label prefix, so the
	// TestMain sweep reclaims them even if the run is killed. Registered before
	// the provider so it runs after the module has released the device.
	t.Cleanup(func() { sweepPrefix(t) })

	p := provider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "hw.db"))
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mgr := ca.NewManager(db, p)

	// ECDSA P-256 throughout: RSA works (tier 5 proves it) but costs about a
	// minute per CA key on this device, which would make this test unusable as
	// something an operator runs after plugging a device in.
	const keyType = keyprovider.KeyTypeECDSAP256

	var root, inter *models.CA

	t.Run("root", func(t *testing.T) {
		started := time.Now()
		root, err = mgr.InitRoot(ctx, ca.RootSpec{
			Label:    label("ca-root"),
			KeyType:  keyType,
			Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy YubiHSM Hardware Root", Organization: "Secsy"}),
			Validity: 10 * 365 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("creating the root CA on the device: %v", err)
		}
		cert := parseCAPEM(t, root)
		if !cert.IsCA {
			t.Error("the root certificate is not marked as a CA")
		}
		// A root is self-signed: checking that here proves the device signed
		// with the key whose public half went into the certificate.
		if err := cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("the root certificate is not correctly self-signed: %v", err)
		}
		t.Logf("root CA %s created in %s", root.ID, time.Since(started).Round(time.Millisecond))
	})
	if root == nil {
		t.Fatal("no root CA; the rest of the tier cannot run")
	}

	t.Run("intermediate", func(t *testing.T) {
		zero := 0
		inter, err = mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
			ParentID:   root.ID,
			Label:      label("ca-inter"),
			KeyType:    keyType,
			Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy YubiHSM Hardware Intermediate"}),
			Validity:   5 * 365 * 24 * time.Hour,
			MaxPathLen: &zero,
		})
		if err != nil {
			t.Fatalf("issuing the intermediate on the device: %v", err)
		}
		// The device signed the intermediate with the root key: verifying the
		// signature against the root certificate is the check that the two keys
		// are the pair the chain claims.
		if err := parseCAPEM(t, inter).CheckSignatureFrom(parseCAPEM(t, root)); err != nil {
			t.Fatalf("the intermediate is not signed by the root: %v", err)
		}
	})
	if inter == nil {
		t.Fatal("no intermediate CA; the rest of the tier cannot run")
	}

	var leafSerial *big.Int

	t.Run("issue leaf", func(t *testing.T) {
		csr := makeCSR(t, "hardware.example.test")
		res, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
			CAID:    inter.ID,
			CSRPEM:  csr,
			Profile: "server",
		})
		if err != nil {
			t.Fatalf("issuing a leaf from the device-backed intermediate: %v", err)
		}
		leaf := res.Certificate
		leafSerial = leaf.SerialNumber

		// Build the chain the way a TLS client would and verify it. This is the
		// end-to-end statement: three certificates, two of them signed by keys
		// that never left the HSM, forming a path the standard library accepts.
		roots, inters := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(parseCAPEM(t, root))
		inters.AddCert(parseCAPEM(t, inter))
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inters,
			DNSName:       "hardware.example.test",
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatalf("the issued chain does not verify: %v", err)
		}
		t.Logf("leaf %s verified against the device-backed chain", leaf.SerialNumber)
	})
	if leafSerial == nil {
		t.Fatal("no leaf certificate; revocation and CRL cannot run")
	}

	t.Run("revoke and CRL", func(t *testing.T) {
		applied, err := mgr.RevokeCertificate(ctx, inter.ID, leafSerial.String(), "keyCompromise")
		if err != nil {
			t.Fatalf("revoking the leaf: %v", err)
		}
		if !applied {
			t.Fatal("revocation reported no change for a certificate that was not yet revoked")
		}

		crlDER, err := mgr.GenerateCRL(ctx, inter.ID)
		if err != nil {
			t.Fatalf("generating the CRL on the device: %v", err)
		}
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("parsing the CRL: %v", err)
		}
		// The CRL is signed by the intermediate's HSM key; checking the
		// signature is what proves the device produced it.
		if err := crl.CheckSignatureFrom(parseCAPEM(t, inter)); err != nil {
			t.Fatalf("the CRL is not signed by the issuing CA: %v", err)
		}
		var listed bool
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(leafSerial) == 0 {
				listed = true
			}
		}
		if !listed {
			t.Fatalf("the revoked serial %s is not on the CRL", leafSerial)
		}
		t.Logf("CRL #%s lists %d revoked certificate(s), signature verified",
			crl.Number, len(crl.RevokedCertificateEntries))
	})

	t.Run("ssh ca", func(t *testing.T) {
		authority := sshca.NewAuthority(db, p)
		sshCA, err := authority.InitCA(ctx, sshca.CASpec{
			Label:   label("ssh-ca"),
			KeyType: keyType,
		})
		if err != nil {
			t.Fatalf("creating the SSH CA on the device: %v", err)
		}

		// A throwaway user key for the CA to certify.
		userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating a user key: %v", err)
		}
		userPub, err := ssh.NewPublicKey(&userKey.PublicKey)
		if err != nil {
			t.Fatalf("converting the user key: %v", err)
		}

		res, err := authority.Sign(ctx, sshca.SignRequest{
			CAID:       sshCA.ID,
			CertType:   "user",
			PublicKey:  string(ssh.MarshalAuthorizedKey(userPub)),
			KeyID:      "hardware-test",
			Principals: []string{"operator"},
			Validity:   time.Hour,
		})
		if err != nil {
			t.Fatalf("signing an SSH certificate on the device: %v", err)
		}

		// Re-parse the authorized-keys line rather than using res.Certificate:
		// the wire form is what a host actually reads, so a marshalling fault
		// would be invisible to a check against the in-memory struct.
		parsed, _, _, _, err := ssh.ParseAuthorizedKey(res.AuthorizedKey)
		if err != nil {
			t.Fatalf("parsing the SSH certificate: %v", err)
		}
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			t.Fatalf("the SSH CA returned a %T, not a certificate", parsed)
		}

		// ssh.CertChecker is an independent verifier: it re-derives the
		// signature over the certificate body using the CA's public key, so it
		// catches a device signature that is well-formed but wrong.
		checker := &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				return string(auth.Marshal()) == string(cert.SignatureKey.Marshal())
			},
		}
		if err := checker.CheckCert("operator", cert); err != nil {
			t.Fatalf("the SSH certificate does not verify against its CA: %v", err)
		}
		if err := checker.CheckCert("someone-else", cert); err == nil {
			t.Error("the SSH certificate validated for a principal it was not issued to")
		}
		t.Logf("SSH certificate %q signed by the device and verified", cert.KeyId)
	})
}

// sweepPrefix removes every object this run left labelled with the suite
// prefix. The CA layer names its keys, and nothing in the product deletes them,
// so without this a hardware run would accumulate CA keys on the device.
func sweepPrefix(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := yubihsm.Open(ctx, driverConfig())
	if err != nil {
		t.Logf("could not clean up this run's keys: %v", err)
		return
	}
	defer func() { _ = c.Close() }()
	for _, o := range labelledObjects(ctx, c, func(l string) bool {
		return strings.HasPrefix(l, labelPrefix) && strings.HasSuffix(l, runID)
	}) {
		if err := c.DeleteObject(ctx, o.ID, o.Type); err != nil {
			t.Logf("leaving %q (0x%04x) on the device: %v", o.Label, o.ID, err)
		}
	}
}

// parseCAPEM parses a stored CA's certificate.
func parseCAPEM(t *testing.T, c *models.CA) *x509.Certificate {
	t.Helper()
	return parsePEM(t, c.Certificate)
}

func parsePEM(t *testing.T, p string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		t.Fatal("no PEM block in the certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}

// makeCSR builds a PKCS#10 request with a host-generated key. The subscriber
// key is generated on the host on purpose: only the CA key belongs in the HSM.
func makeCSR(t *testing.T, dnsName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the subscriber key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsName},
		DNSNames: []string{dnsName},
	}, key)
	if err != nil {
		t.Fatalf("creating the CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
