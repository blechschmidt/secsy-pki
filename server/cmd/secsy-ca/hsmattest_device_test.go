package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
)

// The offline half of `secsy-ca hsm-attest device`: a bundle handed to an
// auditor has to be recognised for what it is and verified as such. Getting the
// routing wrong would read a device attestation as a key attestation and report
// a pile of missing fields instead of the device's serial number.

func TestDeviceAttestationIsRecognisedByKind(t *testing.T) {
	bundle, _ := deviceBundleJSON(t, "31650425")

	if _, ok := deviceAttestationFrom(bundle); !ok {
		t.Error("a device attestation bundle was not recognised")
	}
	for name, data := range map[string][]byte{
		"a key attestation":   []byte(`{"certificate_pem":"-----BEGIN CERTIFICATE-----\n"}`),
		"a bare PEM":          []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
		"an unrelated object": []byte(`{"kind":"something-else"}`),
		"not JSON at all":     []byte("hello"),
	} {
		if _, ok := deviceAttestationFrom(data); ok {
			t.Errorf("%s was misread as a device attestation", name)
		}
	}
}

// The serial is the answer the command exists to print, so it has to reach
// stdout — and the exit status has to reflect the verdict, because that is what
// makes this usable as a compliance gate.
func TestVerifyDeviceAttestationPrintsTheVerifiedSerial(t *testing.T) {
	data, roots := deviceBundleJSON(t, "31650425")
	att, ok := deviceAttestationFrom(data)
	if !ok {
		t.Fatal("the bundle was not recognised")
	}

	out := captureDeviceStdout(t, func() {
		// The synthetic device answers no challenge and chains to a synthetic
		// root, so both are opted into explicitly; everything else is default.
		if err := verifyDeviceAttestation(att, deviceVerifyFlags{
			roots:            roots,
			requireAnchor:    true,
			allowNoChallenge: true,
		}); err != nil {
			t.Fatalf("a well-formed bundle did not verify: %v", err)
		}
	})
	if !strings.Contains(out, "Device serial:    31650425") {
		t.Errorf("the verified serial was not printed:\n%s", out)
	}
	if !strings.Contains(out, "Yubico-certified: yes") {
		t.Errorf("the anchoring verdict was not printed:\n%s", out)
	}

	// Wrong device: non-zero exit, and the report says which serial it really is.
	out = captureDeviceStdout(t, func() {
		err := verifyDeviceAttestation(att, deviceVerifyFlags{
			roots:            roots,
			requireAnchor:    true,
			allowNoChallenge: true,
			expectSerial:     "00000001",
		})
		if err == nil {
			t.Fatal("the wrong device produced a zero exit status")
		}
		if !strings.Contains(err.Error(), "not the expected 00000001") {
			t.Errorf("error = %v, want the expectation named", err)
		}
	})
	if !strings.Contains(out, "31650425") {
		t.Errorf("the report did not name the device that was actually found:\n%s", out)
	}
}

// A bundle answering no challenge authenticates a certificate rather than a
// device, so accepting it is an explicit choice on the verifying side too.
func TestVerifyDeviceAttestationRequiresAChallengeByDefault(t *testing.T) {
	data, roots := deviceBundleJSON(t, "31650425")
	att, _ := deviceAttestationFrom(data)

	captureDeviceStdout(t, func() {
		err := verifyDeviceAttestation(att, deviceVerifyFlags{roots: roots, requireAnchor: true})
		if err == nil {
			t.Fatal("a bundle with no answered challenge verified by default")
		}
		if !strings.Contains(err.Error(), "no answered challenge") {
			t.Errorf("error = %v, want the missing challenge named", err)
		}
	})
}

// --- helpers ---

// deviceBundleJSON writes a synthetic device attestation bundle and the PEM
// trust anchor it chains to, in the form the CLI reads them.
func deviceBundleJSON(t *testing.T, serial string) (bundle []byte, rootsFile string) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test YubiHSM Root CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialInt, ok := new(big.Int).SetString(serial, 10)
	if !ok {
		t.Fatalf("serial %q is not a number", serial)
	}
	firmware, err := asn1.Marshal([]byte{2, 4, 0})
	if err != nil {
		t.Fatal(err)
	}
	serialExt, err := asn1.Marshal(serialInt)
	if err != nil {
		t.Fatal(err)
	}
	devTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "YubiHSM Attestation (" + serial + ")"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 1}, Value: firmware},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 2}, Value: serialExt},
		},
	}
	devDER, err := x509.CreateCertificate(rand.Reader, devTmpl, root, &devKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	att := &hsmattest.DeviceAttestation{
		Kind:                 hsmattest.DeviceAttestationKind,
		DeviceCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: devDER})),
		ReportedSerial:       serial,
		ProducedAt:           time.Now().UTC(),
	}
	bundle, err = json.MarshalIndent(att, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	rootsFile = filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(rootsFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundle, rootsFile
}

// captureDeviceStdout collects what fn prints, so a test can assert on the
// operator-facing report rather than only on the returned error.
func captureDeviceStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	defer func() {
		os.Stdout = orig
		_ = w.Close()
	}()
	fn()
	os.Stdout = orig
	_ = w.Close()
	return <-done
}
