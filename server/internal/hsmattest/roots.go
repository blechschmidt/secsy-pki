package hsmattest

import (
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
)

// Yubico's published attestation PKI, embedded so that verification needs no
// network and no configuration in the common case.
//
// These files come from https://developers.yubico.com/PKI/ (yubico-ca-1.pem and
// yubico-intermediate.pem). Embedding rather than fetching is deliberate: a
// verifier that downloads its own trust anchors at verification time trusts
// whoever answers that request, which defeats the purpose. Operators who need
// different anchors — a device generation whose sub-CA Yubico has not
// published, or a device with an owner-installed attestation key — supply them
// explicitly via LoadRoots.
//
//go:embed roots/*.pem
var rootsFS embed.FS

var (
	embeddedOnce  sync.Once
	embeddedRoots *x509.CertPool
	embeddedInter []*x509.Certificate
)

func loadEmbedded() {
	embeddedOnce.Do(func() {
		embeddedRoots = x509.NewCertPool()
		if data, err := rootsFS.ReadFile("roots/yubico-attestation-root.pem"); err == nil {
			embeddedRoots.AppendCertsFromPEM(data)
		}
		if data, err := rootsFS.ReadFile("roots/yubico-attestation-intermediates.pem"); err == nil {
			certs, _ := parseCertsPEM(data)
			embeddedInter = certs
		}
	})
}

// EmbeddedRoots returns a pool containing Yubico's published attestation root.
func EmbeddedRoots() *x509.CertPool {
	loadEmbedded()
	return embeddedRoots
}

// EmbeddedIntermediates returns Yubico's published attestation intermediates.
//
// Note that this bundle does not cover every device generation: a YubiHSM 2 on
// firmware 2.4.0 chains through a per-batch "Yubico YubiHSM <n> Sub-CA" that is
// neither stored on the device nor present here. Such a device is genuine but
// unanchorable from public material alone, which is why Policy does not require
// an anchored chain by default.
func EmbeddedIntermediates() []*x509.Certificate {
	loadEmbedded()
	return embeddedInter
}

// LoadRoots reads trust anchors from PEM files.
//
// Certificates that are self-signed become roots; the rest are returned as
// intermediates, so an operator can point at one bundle containing a whole
// chain without having to split it by hand. Passing no files yields the
// embedded Yubico anchors.
func LoadRoots(files []string) (*x509.CertPool, []*x509.Certificate, error) {
	if len(files) == 0 {
		return EmbeddedRoots(), EmbeddedIntermediates(), nil
	}
	roots := x509.NewCertPool()
	var inter []*x509.Certificate
	var n int
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("reading attestation trust anchor %s: %w", f, err)
		}
		certs, err := parseCertsPEM(data)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing attestation trust anchor %s: %w", f, err)
		}
		if len(certs) == 0 {
			return nil, nil, fmt.Errorf("attestation trust anchor %s contains no certificates", f)
		}
		for _, c := range certs {
			n++
			if isSelfSigned(c) {
				roots.AddCert(c)
			} else {
				inter = append(inter, c)
			}
		}
	}
	if n == 0 {
		return nil, nil, fmt.Errorf("no certificates found in attestation trust anchors")
	}
	return roots, inter, nil
}

// parseCertsPEM decodes every CERTIFICATE block in data.
func parseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	return out, nil
}

// isSelfSigned reports whether c is its own issuer and verifies under its own
// key, i.e. is usable as a trust anchor.
func isSelfSigned(c *x509.Certificate) bool {
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}
