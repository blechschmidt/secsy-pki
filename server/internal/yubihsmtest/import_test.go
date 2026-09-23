package yubihsmtest

// Tier 5b: importing existing key material onto the device (Task 196).
//
// Every other key in this suite is born inside the HSM. Import is the opposite
// direction and the migration case the product exists to serve: an organization
// already has an RSA CA whose root is in trust stores it does not control, and
// the only useful move is to get that key off a filesystem and onto hardware.
// RSA specifically, because that is what the CAs old enough to be un-rekeyable
// are: a 2048-bit RSA key from before EC was a safe default.
//
// SoftHSM covers the import code path already, and passes — which is exactly
// why this tier is needed. SoftHSM accepts any RSA modulus and any public
// exponent; a YubiHSM 2 accepts three modulus sizes and one exponent, and says
// so with a single undifferentiated CKR_ATTRIBUTE_VALUE_INVALID. So "import
// works" is a claim only hardware can settle, in both directions: the sizes
// that must work, and the rejections that must arrive as sentences rather than
// as a status code from the far side of a USB cable.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// importableRSASizes are the RSA moduli a YubiHSM 2 holds. The device supports
// exactly rsa2048, rsa3072 and rsa4096; there is no fourth size, and no
// mechanism for a modulus in between.
var importableRSASizes = []int{2048, 3072, 4096}

// TestImportRSAKeyOntoDevice is the headline claim of this tier: an RSA private
// key that exists on the host ends up on the YubiHSM, and the key on the device
// is the key that was sent.
//
// "Is the key that was sent" is the whole test. Creating an object and getting a
// handle back proves nothing — a module that truncated a CRT coefficient or
// re-encoded a prime would still return success, and the damage would surface as
// a certificate nobody can verify, months later and far from here. So each size
// is checked three ways: the public half read back from the device equals the
// host key's, a signature made on the device verifies under the host key's
// public half, and a signature over different input does not.
//
// Unlike generation, import is fast at every size — the device is storing
// primes, not searching for them — so RSA-4096 is in the matrix here where
// TestRSA4096IsSupported has to hold it out of the generation matrix.
func TestImportRSAKeyOntoDevice(t *testing.T) {
	requireDevice(t)

	for _, bits := range importableRSASizes {
		t.Run(fmt.Sprintf("rsa%d", bits), func(t *testing.T) {
			keepLogSpace(t, 6)
			host, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatalf("generating an RSA-%d key on the host: %v", bits, err)
			}

			lbl := label(fmt.Sprintf("imp-rsa%d", bits))
			// Registered before the provider so it runs after the provider's
			// Close: cleanups run in reverse order and the native driver cannot
			// claim the USB interface while the module holds it.
			t.Cleanup(func() { sweepLabel(t, lbl) })
			p := provider(t)
			ctx := testContext(t)

			started := time.Now()
			info, err := keyprovider.ImportKey(ctx, p, keyprovider.ImportSpec{
				Label:      lbl,
				Usage:      keyprovider.KeyUsageSign,
				PrivateKey: host,
			})
			if err != nil {
				t.Fatalf("importing the RSA-%d key onto the device: %v", bits, err)
			}
			t.Logf("RSA-%d import took %s", bits, time.Since(started).Round(time.Millisecond))

			if want := fmt.Sprintf("rsa-%d", bits); info.KeyType != want {
				t.Errorf("the imported key reports type %q, want %q", info.KeyType, want)
			}
			if !samePublicKey(info.PublicKey, &host.PublicKey) {
				t.Fatal("the public key the device reported is not the imported key's public key")
			}

			// The lookup the product performs on every restart has to find it.
			found, err := p.FindKey(ctx, keyprovider.KeyRef{Label: lbl})
			if err != nil {
				t.Fatalf("finding the imported key by label: %v", err)
			}
			if !samePublicKey(found.PublicKey, &host.PublicKey) {
				t.Fatal("looking the imported key up by label returned a different public key")
			}

			// One signature settles whether the device holds the right private
			// half. VerifyKeyUsable is the same check the CLI runs before it
			// tells an operator the import succeeded.
			if err := keyprovider.VerifyKeyUsable(ctx, p, keyprovider.KeyRef{Label: lbl}, &host.PublicKey); err != nil {
				t.Fatalf("the device cannot sign correctly with the imported RSA-%d key: %v", bits, err)
			}

			signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: lbl})
			if err != nil {
				t.Fatalf("opening a signer for the imported key: %v", err)
			}
			defer signer.Close()

			signed := sha256.Sum256([]byte("imported rsa key signing on the device"))
			other := sha256.Sum256([]byte("input it was never shown"))
			sig, err := signer.Sign(rand.Reader, signed[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("signing with the imported RSA-%d key: %v", bits, err)
			}
			if rsa.VerifyPKCS1v15(&host.PublicKey, crypto.SHA256, signed[:], sig) != nil {
				t.Fatal("the device's signature does not verify under the host key it was imported from")
			}
			if rsa.VerifyPKCS1v15(&host.PublicKey, crypto.SHA256, other[:], sig) == nil {
				t.Fatal("the signature verifies against input it was not made over")
			}

			// RSA-PSS is the other signature scheme the issuance path can be
			// configured for, and it is a separate device mechanism: an imported
			// key that only does PKCS#1 v1.5 would fail at the first PSS profile.
			pssSig, err := signer.Sign(rand.Reader, signed[:], &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			})
			if err != nil {
				t.Fatalf("PSS-signing with the imported RSA-%d key: %v", bits, err)
			}
			if err := rsa.VerifyPSS(&host.PublicKey, crypto.SHA256, signed[:], pssSig, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			}); err != nil {
				t.Fatalf("the device's PSS signature does not verify under the host key: %v", err)
			}
		})
	}
}

// TestImportRSAKEKDecryptsOnDevice covers the other usage an import can carry.
//
// The secret layer's key-encryption key is RSA and decrypt-only: it never signs,
// and the least-privilege template it is imported under says so. That template
// is a different set of attributes from the signing one, which the device
// validates separately — so a signing import that works says nothing about a KEK
// import, and the failure would only appear when the first secret could not be
// unwrapped.
func TestImportRSAKEKDecryptsOnDevice(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)

	host, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the host KEK: %v", err)
	}

	lbl := label("imp-kek")
	t.Cleanup(func() { sweepLabel(t, lbl) })
	p := provider(t)
	ctx := testContext(t)

	if _, err := keyprovider.ImportKey(ctx, p, keyprovider.ImportSpec{
		Label:      lbl,
		Usage:      keyprovider.KeyUsageDecrypt,
		PrivateKey: host,
	}); err != nil {
		t.Fatalf("importing an RSA key-encryption key: %v", err)
	}

	dp, ok := p.(keyprovider.DecrypterProvider)
	if !ok {
		t.Fatal("the PKCS#11 provider does not implement DecrypterProvider")
	}
	dec, err := dp.Decrypter(ctx, keyprovider.KeyRef{Label: lbl})
	if err != nil {
		t.Fatalf("opening a decrypter for the imported KEK: %v", err)
	}
	defer dec.Close()

	// Wrap on the host with the public half, unwrap on the device. This is
	// exactly what the envelope layer does to a data-encryption key.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("generating a data key: %v", err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &host.PublicKey, dek, nil)
	if err != nil {
		t.Fatalf("wrapping the data key: %v", err)
	}
	unwrapped, err := dec.Decrypt(rand.Reader, wrapped, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("the device could not unwrap with the imported KEK: %v", err)
	}
	if string(unwrapped) != string(dek) {
		t.Fatal("the device unwrapped different bytes than were wrapped")
	}
}

// TestImportRSAHonoursRequestedObjectID checks that an operator who names a
// handle gets that handle.
//
// A YubiHSM object id is the CKA_ID, and it is also the target_key the device
// audit log records and the object an attestation is taken over. A module that
// allocated its own id instead of honouring the requested one would leave a
// configuration pointing at a key that is not there, and an audit argument
// pointing at the wrong object — both of which only show up later.
func TestImportRSAHonoursRequestedObjectID(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 6)

	host, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the host key: %v", err)
	}

	wantID := scratchID(20)
	hexID := fmt.Sprintf("%04x", wantID)
	lbl := label("imp-id")
	t.Cleanup(func() { sweepLabel(t, lbl) })
	p := provider(t)
	ctx := testContext(t)

	info, err := keyprovider.ImportKey(ctx, p, keyprovider.ImportSpec{
		Label:      lbl,
		ID:         hexID,
		Usage:      keyprovider.KeyUsageSign,
		PrivateKey: host,
	})
	if err != nil {
		t.Fatalf("importing at object id 0x%s: %v", hexID, err)
	}
	if !strings.EqualFold(info.ID, hexID) {
		t.Errorf("the import reports id %q, want %q", info.ID, hexID)
	}

	// Addressing the key by id alone must reach the same key: a deployment can
	// reference a key either way, and the two must not diverge.
	byID, err := p.FindKey(ctx, keyprovider.KeyRef{ID: hexID})
	if err != nil {
		t.Fatalf("finding the imported key by CKA_ID 0x%s: %v", hexID, err)
	}
	if byID.Label != lbl {
		t.Errorf("CKA_ID 0x%s resolves to label %q, want %q", hexID, byID.Label, lbl)
	}
	if !samePublicKey(byID.PublicKey, &host.PublicKey) {
		t.Fatal("the key found by CKA_ID is not the imported key")
	}
}

// TestImportedRSAKeyAttestsAsImported ties this tier to the attestation
// argument, for the key type an operator actually migrates.
//
// The claim the rest of the codebase makes about imported keys is that the
// device reports their provenance honestly and the product does not launder it
// (see docs/hsm/key-attestation.md). TestAttestImportedKeyFails establishes that
// for an EC key placed through the native driver. This is the same assertion for
// the path and key type a real migration uses — an RSA key through PKCS#11 —
// because the origin bit is set by whichever command created the object, and
// C_CreateObject is a different command from PUT ASYMMETRIC KEY.
//
// Both halves matter. Imported must not attest as generated, or the product
// would be overstating what the hardware knows. And it must still attest as
// non-exportable, or the product would be understating what the import bought:
// the key cannot be copied off the device from here on, which is the entire
// point of moving it there.
func TestImportedRSAKeyAttestsAsImported(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 8)

	host, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the host key: %v", err)
	}

	objectID := scratchID(21)
	hexID := fmt.Sprintf("%04x", objectID)
	lbl := label("imp-attest")
	t.Cleanup(func() { sweepLabel(t, lbl) })

	// The provider is closed before attesting: the native driver the attester
	// uses cannot claim the USB interface while the PKCS#11 module holds it.
	func() {
		p := provider(t)
		ctx := testContext(t)
		if _, err := keyprovider.ImportKey(ctx, p, keyprovider.ImportSpec{
			Label: lbl, ID: hexID, Usage: keyprovider.KeyUsageSign, PrivateKey: host,
		}); err != nil {
			t.Fatalf("importing the RSA key at 0x%s: %v", hexID, err)
		}
		_ = p.Close()
	}()

	att, err := hsmattest.NewDeviceAttester(hsmConfig()).AttestObject(testContext(t), objectID)
	if err != nil {
		t.Fatalf("attesting the imported RSA key: %v", err)
	}
	// ExpectedPublicKey is what makes this an assertion about *this* key rather
	// than about some key on the device.
	pol := hsmattest.DefaultPolicy()
	pol.ExpectedPublicKey = &host.PublicKey
	res := hsmattest.Verify(att, pol)

	if res.Verified {
		t.Error("an imported key passed the default policy, which requires device generation")
	}
	if res.GeneratedOnDevice {
		t.Error("a key imported through PKCS#11 was reported as generated on the device")
	}
	if !res.NonExportable {
		t.Error("the imported key was reported as exportable; the import template forbids export")
	}
	if res.KeyMatched == nil || !*res.KeyMatched {
		t.Error("the attestation is not over the public key that was imported")
	}
	if !res.DeviceBound {
		t.Error("the attestation was not bound to the device attestation certificate")
	}
	t.Logf("attested as origin %q, non-exportable=%t, serial %s", res.Origin, res.NonExportable, res.DeviceSerial)
}

// TestImportRejectsKeysTheDeviceCannotHold is the other half of "import works".
//
// A YubiHSM 2 takes three RSA modulus sizes and the single public exponent
// 65537. Everything else comes back as CKR_ATTRIBUTE_VALUE_INVALID — one status
// code covering "wrong size", "wrong exponent" and "unsupported algorithm"
// alike, arriving after a round trip, with no indication of which. An operator
// migrating a legacy CA meets this holding a key file that looks perfectly
// valid, and the code alone tells them nothing.
//
// So the checks run on the host, before the device is touched, and this test
// pins the resulting messages. It asserts on the substance of each message, not
// just that an error occurred: an unhelpful rejection is the failure mode being
// guarded against, so "it errored" is not the property worth testing.
func TestImportRejectsKeysTheDeviceCannotHold(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 4)

	cases := []struct {
		name string
		key  *rsa.PrivateKey
		want []string
	}{
		{
			// Between two supported sizes: the device has no rsa2560 algorithm.
			// It is also the case an earlier version got silently wrong, storing
			// it as "rsa-3072" in the CA record.
			name: "modulus-between-supported-sizes",
			key:  rsaKeyWithExponent(t, 2560, 65537),
			want: []string{"2560 bits", "2048, 3072, or 4096"},
		},
		{
			// Below the floor: refused by size before the exponent is reached.
			name: "modulus-below-minimum",
			key:  rsaKeyWithExponent(t, 1024, 65537),
			want: []string{"1024", "minimum is 2048"},
		},
		{
			// The right size, an exponent the device will not take — and one the
			// Baseline Requirements forbid independently.
			name: "exponent-below-65537",
			key:  rsaKeyWithExponent(t, 2048, 3),
			want: []string{"exponent 3", "65537"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lbl := label("imp-rej")
			t.Cleanup(func() { sweepLabel(t, lbl) })
			p := provider(t)
			ctx := testContext(t)

			_, err := keyprovider.ImportKey(ctx, p, keyprovider.ImportSpec{
				Label: lbl, Usage: keyprovider.KeyUsageSign, PrivateKey: tc.key,
			})
			if err == nil {
				t.Fatalf("the device accepted a %d-bit key with exponent %d", tc.key.N.BitLen(), tc.key.E)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the rejection does not mention %q, so an operator cannot act on it:\n  %v", want, err)
				}
			}
			// The rejection must be a diagnosis, not the module's status code
			// relayed verbatim.
			if strings.Contains(err.Error(), "CKR_ATTRIBUTE_VALUE_INVALID") {
				t.Errorf("the key reached the device and came back as a raw PKCS#11 status: %v", err)
			}
			t.Logf("rejected: %v", err)
		})
	}
}

// TestImportedRSAKeyIssuesCertificates is the end of the migration story.
//
// The reason to move an RSA CA key onto a YubiHSM is to keep issuing from it,
// so the test that matters is not that the key signs a challenge but that it
// signs a certificate which verifies against the CA certificate the
// organization already published. The self-signed certificate here stands in for
// that published root: it is made on the host with the original key, before the
// import, and the leaf is then issued by the device afterwards.
func TestImportedRSAKeyIssuesCertificates(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 8)

	host, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the legacy CA key on the host: %v", err)
	}
	// The CA certificate as it exists before the migration: signed in software,
	// already distributed, not reissuable.
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "t196 legacy RSA root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &host.PublicKey, host)
	if err != nil {
		t.Fatalf("self-signing the legacy CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing the legacy CA certificate: %v", err)
	}

	lbl := label("imp-ca")
	t.Cleanup(func() { sweepLabel(t, lbl) })
	p := provider(t)
	ctx := testContext(t)

	if _, err := keyprovider.ImportKey(ctx, p, keyprovider.ImportSpec{
		Label: lbl, Usage: keyprovider.KeyUsageSign, PrivateKey: host,
	}); err != nil {
		t.Fatalf("importing the legacy CA key: %v", err)
	}

	signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: lbl})
	if err != nil {
		t.Fatalf("opening a signer for the migrated CA key: %v", err)
	}
	defer signer.Close()

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a subscriber key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "issued-after-migration.example"},
		DNSNames:     []string{"issued-after-migration.example"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// x509.CreateCertificate drives the device: every signature below is made
	// inside the HSM by the imported key.
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("issuing a certificate with the migrated CA key: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing the issued certificate: %v", err)
	}

	// The device-signed certificate must verify under the CA certificate that
	// was published before the migration. If it does not, the imported key is
	// not the key the organization's relying parties trust.
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("the certificate issued on the device does not verify under the pre-migration CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("path validation of the device-issued certificate failed: %v", err)
	}
	t.Logf("issued %s under the pre-migration root, signed by the imported key on device", leaf.Subject.CommonName)
}

// rsaKeyWithExponent builds an RSA key of an exact modulus size with a chosen
// public exponent, which crypto/rsa cannot do: GenerateKey fixes e at 65537.
// The rejection cases need keys the standard library will not produce, and a
// hand-built one is the only way to present the device with them.
func rsaKeyWithExponent(t *testing.T, bits, e int) *rsa.PrivateKey {
	t.Helper()
	if e == 65537 {
		// The common path: let the standard library do it properly.
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("generating a %d-bit RSA key: %v", bits, err)
		}
		return k
	}
	one := big.NewInt(1)
	E := big.NewInt(int64(e))
	for attempt := 0; attempt < 400; attempt++ {
		half := bits / 2
		p, err := rand.Prime(rand.Reader, half)
		if err != nil {
			t.Fatalf("generating a prime: %v", err)
		}
		q, err := rand.Prime(rand.Reader, bits-half)
		if err != nil {
			t.Fatalf("generating a prime: %v", err)
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		if new(big.Int).GCD(nil, nil, phi, E).Cmp(one) != 0 {
			continue
		}
		d := new(big.Int).ModInverse(E, phi)
		if d == nil {
			continue
		}
		k := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: e},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		k.Precompute()
		if k.Validate() != nil {
			continue
		}
		return k
	}
	t.Fatalf("could not build a %d-bit RSA key with exponent %d", bits, e)
	return nil
}
