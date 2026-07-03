//go:build sqlite

// FIPS 140-3 posture checks (Task 65): module state, store key-material
// conformance, and the secret-layer SHA-256 OAEP negotiation — including the
// simulated SoftHSM SHA-1-only token the policy must refuse.
package doctor_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fipsCfg is the extra config enabling the FIPS policy and the secret layer.
const fipsCfg = `secret:
  kek_label: doctor-kek
security:
  fips: true
`

// restoreFIPSPolicy snapshots the process-global policy around a test —
// doctor.Run loads the fixture config, which mirrors security.fips into it.
func restoreFIPSPolicy(t *testing.T) {
	t.Helper()
	prev := fips.PolicyEnforced()
	t.Cleanup(func() { fips.SetPolicy(prev) })
}

// provisionKEK creates the RSA KEK the fixture config references, directly on
// the fixture's software keystore.
func provisionKEK(t *testing.T, f *fixture) {
	t.Helper()
	p, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: f.keystore},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.GenerateKey(context.Background(), keyprovider.KeySpec{
		Label:   "doctor-kek",
		KeyType: keyprovider.KeyTypeRSA2048,
		Usage:   keyprovider.KeyUsageDecrypt,
	}); err != nil {
		t.Fatalf("provisioning KEK: %v", err)
	}
}

func TestDoctorFIPSHealthy(t *testing.T) {
	restoreFIPSPolicy(t)
	f := newFixture(t, fipsCfg)
	provisionKEK(t, f)

	r := f.run(t, doctor.Options{SkipListener: true})

	// The mode check depends on how the test process itself was started: pass
	// on the Go FIPS module (GODEBUG=fips140=on / GOFIPS140 build), warn off it.
	wantMode := doctor.StatusWarn
	if fips.ModuleEnabled() {
		wantMode = doctor.StatusPass
	}
	mode := assertStatus(t, r, "fips.mode", wantMode)
	if wantMode == doctor.StatusWarn && !strings.Contains(mode.Detail, "build-fips") {
		t.Errorf("fips.mode warning should point at make build-fips: %s", mode.Detail)
	}

	assertStatus(t, r, "fips.store_keys", doctor.StatusPass)

	oaep := assertStatus(t, r, "fips.secret_oaep", doctor.StatusPass)
	if !strings.Contains(oaep.Detail, "RSA-OAEP-SHA256") {
		t.Errorf("fips.secret_oaep should report the negotiated algorithm: %s", oaep.Detail)
	}
}

func TestDoctorFIPSChecksSkippedWhenDisabled(t *testing.T) {
	restoreFIPSPolicy(t)
	f := newFixture(t, "")

	r := f.run(t, doctor.Options{SkipListener: true})
	for _, name := range []string{"fips.mode", "fips.store_keys", "fips.secret_oaep"} {
		assertStatus(t, r, name, doctor.StatusSkip)
	}
}

func TestDoctorFIPSNonApprovedStoreKey(t *testing.T) {
	restoreFIPSPolicy(t)
	f := newFixture(t, fipsCfg)
	provisionKEK(t, f)

	// Key material predating the policy: provision an Ed25519 root with the
	// policy off (as a pre-FIPS deployment would have), then diagnose with it on.
	fips.SetPolicy(false)
	p, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: f.keystore},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := ca.NewManager(f.db, p).InitRoot(context.Background(), ca.RootSpec{
		Label:    "doctor-ed-root",
		KeyType:  "ed25519",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Legacy Ed25519 Root"}),
		Validity: 10 * 365 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("provisioning legacy ed25519 root: %v", err)
	}

	r := f.run(t, doctor.Options{SkipListener: true})
	res := assertStatus(t, r, "fips.store_keys", doctor.StatusFail)
	if !strings.Contains(res.Detail, "doctor-ed-root") || !strings.Contains(res.Detail, "Ed25519") {
		t.Errorf("fips.store_keys should name the offending CA and algorithm: %s", res.Detail)
	}
}

// sha1OnlyDoctorProvider simulates SoftHSM's SHA-1-only RSA-OAEP for the
// doctor's negotiation probe (see the softhsm-oaep-sha1-only behavior).
type sha1OnlyDoctorProvider struct {
	keyprovider.Provider
}

func (p *sha1OnlyDoctorProvider) Decrypter(ctx context.Context, ref keyprovider.KeyRef) (keyprovider.Decrypter, error) {
	dp, ok := p.Provider.(keyprovider.DecrypterProvider)
	if !ok {
		return nil, fmt.Errorf("wrapped provider cannot decrypt")
	}
	inner, err := dp.Decrypter(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &sha1OnlyDoctorDecrypter{inner}, nil
}

type sha1OnlyDoctorDecrypter struct {
	keyprovider.Decrypter
}

func (d *sha1OnlyDoctorDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if o, ok := opts.(*rsa.OAEPOptions); ok && o.Hash != crypto.SHA1 {
		return nil, fmt.Errorf("simulated token: CKR_ARGUMENTS_BAD (only SHA-1 OAEP supported)")
	}
	return d.Decrypter.Decrypt(rand, ciphertext, opts)
}

func TestDoctorFIPSRefusesSHA1OnlyToken(t *testing.T) {
	restoreFIPSPolicy(t)
	f := newFixture(t, fipsCfg)
	provisionKEK(t, f)

	r := f.run(t, doctor.Options{
		SkipListener: true,
		BuildProvider: func(cfg *config.Config, role string) (keyprovider.Provider, error) {
			p, err := buildTestProvider(cfg, role)
			if err != nil {
				return nil, err
			}
			return &sha1OnlyDoctorProvider{p}, nil
		},
	})

	res := assertStatus(t, r, "fips.secret_oaep", doctor.StatusFail)
	if !strings.Contains(res.Detail, "SHA-1") || !strings.Contains(res.Detail, "security.fips") {
		t.Errorf("fips.secret_oaep failure should explain the refused SHA-1 fallback: %s", res.Detail)
	}
	if r.ExitCode() != doctor.ExitFail {
		t.Errorf("exit code = %d, want %d", r.ExitCode(), doctor.ExitFail)
	}
}
