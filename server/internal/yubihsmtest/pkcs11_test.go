package yubihsmtest

// Tier 5: the PKCS#11 layer.
//
// Everything the product signs with goes through keyprovider, and on a YubiHSM
// that means Yubico's PKCS#11 module rather than the native driver the tiers
// below use. The two are separate implementations of access to the same device,
// so passing tier 2 says nothing about this one: the module has its own idea of
// which mechanisms exist, its own session handling, and its own mapping from a
// key label to an object.
//
// SoftHSM covers the same API and hides the three things that actually bite
// here — the module's narrower mechanism set, the single serialised USB channel
// underneath a pool that assumes parallelism, and object labels that are the
// only handle the product has on a key.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// provider builds the production key provider against the device.
//
// Closing it matters: the module holds the USB interface for as long as it has
// a session, so a provider left open would lock the native-driver tiers — and
// the scratch sweep in TestMain — out of the device.
func provider(t *testing.T) keyprovider.Provider {
	t.Helper()
	cfg := pkcs11Config(t)
	p, err := keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderPKCS11,
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath: cfg.ModulePath,
			Pin:        cfg.Pin,
			TokenLabel: cfg.TokenLabel,
		},
	})
	if err != nil {
		t.Fatalf("opening the YubiHSM through %s: %v", cfg.ModulePath, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// pkcs11KeyTypes are the key types the product offers that this device can hold.
//
// Ed25519 is in the list because this module turns out to support it, which is
// worth stating: older Yubico PKCS#11 releases exposed no EdDSA mechanism, so
// "the YubiHSM does Ed25519" was true of the device and false of the only path
// the product can reach it through. If that regresses, this matrix is where it
// shows up.
//
// RSA-4096 is not in the list, for time rather than capability: generating one
// takes minutes on this device, where RSA-3072 already takes about 45 seconds.
// TestRSA4096IsSupported covers it separately so an operator can choose to pay
// for that evidence.
var pkcs11KeyTypes = []string{
	keyprovider.KeyTypeECDSAP256,
	keyprovider.KeyTypeECDSAP384,
	keyprovider.KeyTypeECDSAP521,
	keyprovider.KeyTypeEd25519,
	keyprovider.KeyTypeRSA2048,
	keyprovider.KeyTypeRSA3072,
}

// TestProviderKeyLifecycle runs generate, find, sign and verify through the
// provider for every key type the product can be configured with.
//
// The verification is done here rather than on the device, and against the
// public key the provider reported rather than the one it signed with, because
// the failure this catches is a provider that returns key A's public half while
// signing with key B — which produces valid-looking signatures that verify
// against nothing.
func TestProviderKeyLifecycle(t *testing.T) {
	requireDevice(t)

	for _, keyType := range pkcs11KeyTypes {
		t.Run(keyType, func(t *testing.T) {
			keepLogSpace(t, 6)
			lbl := label("p11-" + shortKeyType(keyType))
			// Registered before the provider so that it runs *after* the
			// provider's Close: cleanups run in reverse order, and the native
			// driver cannot claim the USB interface while the module holds it.
			t.Cleanup(func() { sweepLabel(t, lbl) })
			p := provider(t)
			ctx := testContext(t)

			gen, err := p.GenerateKey(ctx, keyprovider.KeySpec{Label: lbl, KeyType: keyType})
			if err != nil {
				t.Fatalf("generating a %s key: %v", keyType, err)
			}
			if gen.KeyType != keyType {
				t.Errorf("generated key reports type %q, want %q", gen.KeyType, keyType)
			}
			if gen.PublicKey == nil {
				t.Fatal("the generated key carries no public key")
			}

			// Looking the key back up by label is what the product does on every
			// restart; it must find the same key.
			found, err := p.FindKey(ctx, keyprovider.KeyRef{Label: lbl})
			if err != nil {
				t.Fatalf("finding the %s key by label: %v", keyType, err)
			}
			if !samePublicKey(found.PublicKey, gen.PublicKey) {
				t.Fatal("looking the key up by label returned a different public key than generation did")
			}

			signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: lbl})
			if err != nil {
				t.Fatalf("opening a signer for the %s key: %v", keyType, err)
			}
			defer signer.Close()

			if !samePublicKey(signer.Public(), gen.PublicKey) {
				t.Fatal("the signer's public key is not the generated key's public key")
			}

			// Ed25519 signs the message itself; everything else signs a digest.
			// Handing an Ed25519 signer a digest would produce a signature over
			// the wrong bytes, and it would verify — against the digest.
			signed := []byte("tier 5 signs through PKCS#11")
			other := []byte("something else entirely")
			opts := crypto.SignerOpts(crypto.SHA256)
			if keyType == keyprovider.KeyTypeEd25519 {
				opts = crypto.Hash(0)
			} else {
				d := sha256.Sum256(signed)
				o := sha256.Sum256(other)
				signed, other = d[:], o[:]
			}

			sig, err := signer.Sign(rand.Reader, signed, opts)
			if err != nil {
				t.Fatalf("signing with the %s key: %v", keyType, err)
			}
			if !verifies(signer.Public(), signed, sig) {
				t.Fatalf("the %s signature does not verify against the public key the provider reported", keyType)
			}
			if verifies(signer.Public(), other, sig) {
				t.Fatalf("the %s signature verifies against input it was not made over", keyType)
			}
		})
	}
}

func shortKeyType(kt string) string {
	switch kt {
	case keyprovider.KeyTypeECDSAP256:
		return "p256"
	case keyprovider.KeyTypeECDSAP384:
		return "p384"
	case keyprovider.KeyTypeECDSAP521:
		return "p521"
	case keyprovider.KeyTypeEd25519:
		return "ed25519"
	}
	return strings.ReplaceAll(kt, "-", "")
}

func samePublicKey(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}

// verifies checks a signature with the standard library. For Ed25519 the input
// is the signed message; for everything else it is the digest.
func verifies(pub crypto.PublicKey, input, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, input, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, input, sig) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(k, input, sig)
	}
	return false
}

// TestRSA4096IsSupported covers the largest key the product offers.
//
// It is separate from the matrix because it is slow — minutes, on a device where
// RSA-3072 takes about 45 seconds — and that slowness is itself the finding: a
// deployment that generates a 4096-bit CA key on this hardware needs to expect a
// key ceremony that appears to hang, and any timeout on the issuance path has to
// accommodate it.
func TestRSA4096IsSupported(t *testing.T) {
	requireDevice(t)
	if testing.Short() {
		t.Skip("RSA-4096 generation takes minutes on this device; skipped under -short")
	}
	keepLogSpace(t, 6)

	lbl := label("p11-rsa4096")
	t.Cleanup(func() { sweepLabel(t, lbl) })
	p := provider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	started := time.Now()
	gen, err := p.GenerateKey(ctx, keyprovider.KeySpec{Label: lbl, KeyType: keyprovider.KeyTypeRSA4096})
	if err != nil {
		t.Fatalf("generating an RSA-4096 key: %v", err)
	}
	t.Logf("RSA-4096 key generation took %s", time.Since(started).Round(time.Second))

	signer, err := p.Signer(ctx, keyprovider.KeyRef{Label: lbl})
	if err != nil {
		t.Fatalf("opening a signer: %v", err)
	}
	defer signer.Close()

	digest := sha256.Sum256([]byte("rsa-4096 through PKCS#11"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if !verifies(gen.PublicKey, digest[:], sig) {
		t.Fatal("the RSA-4096 signature does not verify")
	}
}

// TestConcurrentSigningThroughTheSessionPool drives the pool from many
// goroutines at once.
//
// The session pool exists so that concurrent requests do not serialise on one
// PKCS#11 session, and the tuning advice assumes they genuinely overlap. On a
// YubiHSM they cannot: one USB endpoint, one command at a time. That makes this
// the test that says whether the pool degrades correctly under a device that
// cannot parallelise — every signature still has to be correct and no caller may
// receive another's — rather than deadlocking or interleaving responses.
func TestConcurrentSigningThroughTheSessionPool(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 40)

	const poolSize, goroutines, each = 4, 6, 5
	pool, err := pki.NewSessionPool(pkcs11Config(t), poolSize)
	if err != nil {
		t.Fatalf("opening a %d-session pool: %v", poolSize, err)
	}
	defer pool.Close()

	ctx := testContext(t)
	lbl := label("p11-pool")
	t.Cleanup(func() { sweepLabel(t, lbl) })

	gen, err := pool.GenerateSignKey(ctx, lbl, keyprovider.KeyTypeECDSAP256)
	if err != nil {
		t.Fatalf("generating the pooled signing key: %v", err)
	}
	resolved, err := pool.Resolve(ctx, pki.LabelLocator(lbl))
	if err != nil {
		t.Fatalf("resolving %q: %v", lbl, err)
	}
	pub, ok := resolved.Public.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("resolved key is a %T, want an ECDSA key", resolved.Public)
	}
	_ = gen

	var wg sync.WaitGroup
	errs := make(chan error, goroutines*each)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				// A digest unique to this goroutine and iteration: a signature
				// delivered to the wrong caller then fails to verify.
				digest := sha256.Sum256([]byte{byte(g), byte(i)})
				sig, err := pool.Sign(ctx, pki.LabelLocator(lbl), digest[:], crypto.SHA256)
				if err != nil {
					errs <- err
					return
				}
				if !ecdsa.VerifyASN1(pub, digest[:], sig) {
					errs <- errors.New("a concurrently produced signature does not verify over its own digest")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent signing: %v", err)
	}
	t.Logf("%d signatures across %d goroutines through a %d-session pool, all correct",
		goroutines*each, goroutines, poolSize)
}

// TestProbeAndRandom covers the two provider capabilities that are not signing:
// the readiness probe behind /readyz, and the hardware RNG the crypto service
// exposes.
func TestProbeAndRandom(t *testing.T) {
	requireDevice(t)
	p := provider(t)
	ctx := testContext(t)

	prober, ok := p.(keyprovider.Prober)
	if !ok {
		t.Fatal("the PKCS#11 provider does not implement Prober, so /readyz cannot check the HSM")
	}
	if err := prober.Ping(ctx); err != nil {
		t.Fatalf("the readiness probe failed against a working device: %v", err)
	}

	rng, ok := p.(keyprovider.RandomProvider)
	if !ok {
		t.Fatal("the PKCS#11 provider does not implement RandomProvider, so the crypto service cannot draw from the HSM")
	}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		b, err := rng.Random(ctx, 32)
		if err != nil {
			t.Fatalf("drawing random bytes: %v", err)
		}
		if len(b) != 32 {
			t.Fatalf("asked for 32 random bytes, got %d", len(b))
		}
		if seen[string(b)] {
			t.Fatalf("the device repeated a 32-byte draw: %x", b)
		}
		seen[string(b)] = true
	}
}

// TestSecretEnvelopeRoundTrip drives the product's envelope encryption — the
// "password encryption" half of this system — against the device.
//
// It goes through secret.ProvisionKEK rather than the PKCS#11 layer directly
// because the bug this test exists to prevent lived in the gap between them.
// The KEK template used to ask for CKA_WRAP/CKA_UNWRAP, which Yubico's module
// maps onto a device *wrap-key* object; a wrap-key is not exposed as
// CKO_PRIVATE_KEY, so provisioning succeeded and the immediately following
// lookup failed with "private key label not found". Every secret in such a
// deployment would have been unencryptable, and SoftHSM — which draws no
// distinction between object types — reported everything as fine.
func TestSecretEnvelopeRoundTrip(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 8)

	lbl := label("kek")
	t.Cleanup(func() { sweepLabel(t, lbl) })
	p := provider(t)
	ctx := testContext(t)

	svc, err := secret.ProvisionKEK(ctx, p, lbl, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("provisioning the KEK on the device: %v", err)
	}

	plaintext := []byte("correct horse battery staple")
	const context1, context2 = "app/prod/db-password", "app/prod/other"

	env, err := svc.Encrypt(plaintext, []byte(context1))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	// The unwrap happens inside the HSM: this is the round trip that proves the
	// device can undo what the host wrapped to its public half.
	got, err := svc.Decrypt(env, []byte(context1))
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted %q, want %q", got, plaintext)
	}

	// The context is authenticated additional data: decrypting under a
	// different one must fail, or a secret bound to one purpose could be read
	// out under another.
	if _, err := svc.Decrypt(env, []byte(context2)); err == nil {
		t.Fatal("the envelope decrypted under a context it was not encrypted for")
	}

	// Two encryptions of the same plaintext must differ: each gets a fresh data
	// key, so identical ciphertexts would mean the data key is being reused.
	env2, err := svc.Encrypt(plaintext, []byte(context1))
	if err != nil {
		t.Fatalf("encrypting a second time: %v", err)
	}
	if bytes.Equal(env.Ciphertext, env2.Ciphertext) {
		t.Error("two envelopes over the same plaintext have identical ciphertext")
	}
	t.Logf("envelope round trip through an on-device RSA-2048 KEK succeeded")
}

// TestFindKeyRejectsUnknownLabel checks that a missing key is an error.
//
// A lookup that returned some other key, or nil with no error, would let a
// misconfigured CA sign with whatever the token happened to hold.
func TestFindKeyRejectsUnknownLabel(t *testing.T) {
	requireDevice(t)
	p := provider(t)
	ctx := testContext(t)

	if _, err := p.FindKey(ctx, keyprovider.KeyRef{Label: label("p11-does-not-exist")}); err == nil {
		t.Fatal("finding a key that does not exist reported success")
	}
	if _, err := p.Signer(ctx, keyprovider.KeyRef{Label: label("p11-does-not-exist")}); err == nil {
		t.Fatal("opening a signer for a key that does not exist reported success")
	}
}

// TestPKCS11KeysAreNonExportable checks the property the whole product rests on
// through the interface that creates the keys.
//
// Tier 3 proves the device asserts non-exportability; this proves the provider
// asks for it. A key generated with the wrong template would be attested
// honestly as exportable, and the failure would surface as a policy violation
// long after the key had been in production.
func TestPKCS11KeysAreNonExportable(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 4)
	p := provider(t)
	ctx := testContext(t)

	lbl := label("p11-sensitive")
	t.Cleanup(func() { sweepLabel(t, lbl) })
	if _, err := p.GenerateKey(ctx, keyprovider.KeySpec{
		Label: lbl, KeyType: keyprovider.KeyTypeECDSAP256,
	}); err != nil {
		t.Fatalf("generating the key: %v", err)
	}

	// Close the module before the native driver looks at the device: on direct
	// USB only one of them can hold the interface.
	if err := p.Close(); err != nil {
		t.Fatalf("closing the provider: %v", err)
	}

	var found bool
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		objs, err := c.ListObjects(ctx, yubihsm.ObjectTypeAsymmetricKey)
		if err != nil {
			t.Fatalf("listing objects: %v", err)
		}
		for _, o := range objs {
			info, err := c.GetObjectInfo(ctx, o.ID, o.Type)
			if err != nil || info.Label != lbl {
				continue
			}
			found = true
			const exportableUnderWrap = 1 << 16
			if info.Capabilities&exportableUnderWrap != 0 {
				t.Errorf("the provider generated %q with exportable-under-wrap; "+
					"its private half can leave the device", lbl)
			}
			if info.Origin == 0 {
				t.Errorf("the device reports no origin for %q", lbl)
			}
			t.Logf("%q is object 0x%04x with capabilities 0x%016x", lbl, info.ID, info.Capabilities)
		}
	})
	if !found {
		t.Fatalf("the key %q the provider generated is not on the device", lbl)
	}
}

// TestPKCS11AndNativeDriverAgreeOnAKey is the cross-check between the two
// access paths.
//
// The audit and attestation subsystems address keys by on-device handle over
// the native protocol; the signing path addresses them by label over PKCS#11.
// Joining the two is what lets an audit bundle say "this CA key signed these
// certificates". The join is only valid if both paths agree about which object
// they mean, and about what its public key is.
func TestPKCS11AndNativeDriverAgreeOnAKey(t *testing.T) {
	requireDevice(t)
	keepLogSpace(t, 5)

	lbl := label("p11-crosscheck")
	t.Cleanup(func() { sweepLabel(t, lbl) })

	var providerPub crypto.PublicKey
	func() {
		p := provider(t)
		ctx := testContext(t)
		gen, err := p.GenerateKey(ctx, keyprovider.KeySpec{
			Label: lbl, KeyType: keyprovider.KeyTypeECDSAP256,
		})
		if err != nil {
			t.Fatalf("generating the key through PKCS#11: %v", err)
		}
		providerPub = gen.PublicKey
		if err := p.Close(); err != nil {
			t.Fatalf("closing the provider: %v", err)
		}
	}()

	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		objs, err := c.ListObjects(ctx, yubihsm.ObjectTypeAsymmetricKey)
		if err != nil {
			t.Fatalf("listing objects: %v", err)
		}
		var handle uint16
		for _, o := range objs {
			if info, err := c.GetObjectInfo(ctx, o.ID, o.Type); err == nil && info.Label == lbl {
				handle = o.ID
			}
		}
		if handle == 0 {
			t.Fatalf("the native driver cannot find the key %q that PKCS#11 created", lbl)
		}

		// The attestation the audit subsystem would use must describe the same
		// public key the signing path reported.
		der, err := c.AttestAsymmetricKey(ctx, handle, 0)
		if err != nil {
			t.Fatalf("attesting 0x%04x: %v", handle, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parsing the attestation: %v", err)
		}
		if !samePublicKey(cert.PublicKey, providerPub) {
			t.Fatal("the attestation describes a different key than the provider reported; " +
				"an audit bundle could not be joined to the signing path")
		}
		t.Logf("PKCS#11 label %q and native handle 0x%04x are the same key", lbl, handle)
	})
}
