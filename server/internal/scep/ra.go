package scep

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// SCEP's pkiMessage EnvelopedData addresses a recipient that must be able to
// DECRYPT the content-encryption key. The issuing CA's signing key is
// deliberately sign-only (least privilege — see the Task 12 hardening
// invariants), so it cannot be that recipient. Instead the SCEP server operates
// a dedicated, decrypt-capable RSA "RA" (registration authority) encryption key,
// provisioned on the same provider (HSM), with a certificate signed by the CA.
//
// Clients obtain both the CA certificate and this RA encryption certificate from
// GetCACert; they encrypt requests to the RA certificate (identified by its
// keyEncipherment usage) and trust issued certificates through the CA. The RA
// private key never leaves the provider — the unwrap runs on the device.
type raIdentity struct {
	encCert *x509.Certificate
	encRef  keyprovider.KeyRef
}

// ensureRA lazily provisions (once per Server) the SCEP RA encryption identity:
// it finds or generates a decrypt-capable RSA key on the provider and issues an
// RA certificate for it, signed by the issuing CA.
func (s *Server) ensureRA(ctx context.Context) (*raIdentity, error) {
	s.raOnce.Do(func() {
		s.ra, s.raErr = s.provisionRA(ctx)
	})
	return s.ra, s.raErr
}

func (s *Server) provisionRA(ctx context.Context) (*raIdentity, error) {
	caCert, caModel, err := s.caCertModel()
	if err != nil {
		return nil, err
	}

	encLabel := s.cfg.EncryptionKeyLabel
	if encLabel == "" {
		encLabel = caModel.Label + "-scep-enc"
	}
	encRef := keyprovider.KeyRef{Label: encLabel}

	// Find the RA encryption key, generating a decrypt-capable RSA key if absent.
	info, err := s.provider.FindKey(ctx, encRef)
	if err != nil {
		if !errors.Is(err, keyprovider.ErrKeyNotFound) {
			return nil, fmt.Errorf("scep: locating RA encryption key: %w", err)
		}
		info, err = s.provider.GenerateKey(ctx, keyprovider.KeySpec{
			Label:   encLabel,
			KeyType: keyprovider.KeyTypeRSA2048,
			Usage:   keyprovider.KeyUsageDecrypt,
		})
		if err != nil {
			return nil, fmt.Errorf("scep: generating RA encryption key: %w", err)
		}
	}

	// Issue an RA certificate for the encryption key, signed by the CA. It is
	// minted fresh each process start; SCEP clients fetch GetCACert immediately
	// before enrolling, so the recipient identity is always current.
	caSigner, err := s.signer(ctx, caModel)
	if err != nil {
		return nil, err
	}
	defer caSigner.Close()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	notAfter := s.now().Add(2 * 365 * 24 * time.Hour)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	der, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:   pkix.Name{CommonName: "SCEP RA (" + caModel.Label + ")"},
		PublicKey: info.PublicKey,
		Serial:    serial,
		NotBefore: s.now().Add(-5 * time.Minute),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
	})
	if err != nil {
		return nil, fmt.Errorf("scep: issuing RA certificate: %w", err)
	}
	encCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &raIdentity{encCert: encCert, encRef: encRef}, nil
}

// encDecrypter returns a Decrypter bound to the RA encryption key.
func (s *Server) encDecrypter(ctx context.Context, ra *raIdentity) (keyprovider.Decrypter, error) {
	dp, ok := s.provider.(keyprovider.DecrypterProvider)
	if !ok {
		return nil, fmt.Errorf("scep: key provider does not support decryption")
	}
	return dp.Decrypter(ctx, ra.encRef)
}
