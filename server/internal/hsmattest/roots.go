package hsmattest

import (
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Yubico's published attestation PKI, embedded so that verification needs no
// network and no configuration in the common case.
//
// Two disjoint PKIs are embedded, because Yubico runs two:
//
//   - roots/yubihsm2-attestation-*.pem — the YubiHSM 2 device attestation PKI,
//     rooted in "Yubico YubiHSM Root CA". This is the one a YubiHSM 2's
//     pre-loaded certificate (opaque object 0) actually chains through, so it
//     is the one that matters here. Both files come from
//     https://developers.yubico.com/YubiHSM2/Concepts/ — the root as
//     yubihsm2-attest-ca-crt.pem, the sub-CA under the name the YubiHSM 2 User
//     Guide lists it under (§1.2.13, "Pre-Loaded Certificates" → "Intermediates").
//   - roots/yubico-attestation-*.pem — the newer unified Yubico device
//     attestation PKI rooted in "Yubico Attestation Root 1", from
//     https://developers.yubico.com/PKI/ (yubico-ca-1.pem and
//     yubico-intermediate.pem). It covers the YubiKey family and carries a
//     "YubiHSM Attestation B2 1" branch, so devices issued out of it anchor too.
//
// Embedding rather than fetching is deliberate: a verifier that downloads its
// own trust anchors at verification time trusts whoever answers that request,
// which defeats the purpose. Operators whose device chains through a sub-CA not
// bundled here, or who have replaced the factory attestation key with their
// own, supply anchors explicitly via LoadRoots — see YubicoIntermediateURL for
// how to obtain the former.
//
//go:embed roots/*.pem
var rootsFS embed.FS

var (
	embeddedOnce  sync.Once
	embeddedRoots *x509.CertPool
	embeddedInter []*x509.Certificate
)

// loadEmbedded parses every embedded PEM and sorts it by what it is rather than
// by which file it came from: self-signed certificates become trust anchors and
// the rest intermediates. Adding a newly published Yubico sub-CA is then a
// matter of dropping the file into roots/ — the same rule LoadRoots applies to
// operator-supplied bundles, so embedded and configured anchors cannot diverge
// in how they are interpreted.
func loadEmbedded() {
	embeddedOnce.Do(func() {
		embeddedRoots = x509.NewCertPool()
		entries, err := rootsFS.ReadDir("roots")
		if err != nil {
			return
		}
		for _, e := range entries {
			data, err := rootsFS.ReadFile("roots/" + e.Name())
			if err != nil {
				continue
			}
			certs, err := parseCertsPEM(data)
			if err != nil {
				continue
			}
			for _, c := range certs {
				if isSelfSigned(c) {
					embeddedRoots.AddCert(c)
				} else {
					embeddedInter = append(embeddedInter, c)
				}
			}
		}
	})
}

// EmbeddedRoots returns a pool containing Yubico's published attestation roots:
// "Yubico YubiHSM Root CA" and "Yubico Attestation Root 1".
func EmbeddedRoots() *x509.CertPool {
	loadEmbedded()
	return embeddedRoots
}

// EmbeddedIntermediates returns Yubico's published attestation intermediates.
//
// Yubico publishes the YubiHSM 2 sub-CAs individually rather than as a bundle,
// each named after its own subject key identifier, so a device whose sub-CA
// postdates this binary will not be covered. That is a staleness problem with a
// one-file fix, not an unanchorable device: YubicoIntermediateURL turns the
// device certificate into the exact URL to fetch.
func EmbeddedIntermediates() []*x509.Certificate {
	loadEmbedded()
	return embeddedInter
}

// YubicoIntermediateURL returns the URL Yubico publishes deviceCert's issuing
// sub-CA at, or "" when deviceCert carries no authority key identifier.
//
// Yubico names each published YubiHSM 2 intermediate after its subject key
// identifier in uppercase hex — the YubiHSM 2 User Guide lists the current one
// as "E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem" — and a device certificate
// names its issuer by exactly that value in its authority key identifier. The
// mapping is therefore mechanical, which is what makes an unanchored chain an
// actionable error rather than a dead end.
//
// Fetching the result is safe despite being over the network: the intermediate
// is signed by an embedded root, so a hostile server can supply a bad file but
// not a chain that verifies. That is the same argument AIA fetching rests on,
// and the reason this is a URL to hand an operator rather than something the
// verifier retrieves on its own.
func YubicoIntermediateURL(deviceCert *x509.Certificate) string {
	if deviceCert == nil || len(deviceCert.AuthorityKeyId) == 0 {
		return ""
	}
	return yubicoIntermediateBaseURL + strings.ToUpper(hex.EncodeToString(deviceCert.AuthorityKeyId)) + ".pem"
}

const yubicoIntermediateBaseURL = "https://developers.yubico.com/YubiHSM2/Concepts/"

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
