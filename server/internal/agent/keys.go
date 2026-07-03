package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
)

// keyGenerator mints a fresh private key of the configured type.
type keyGenerator func() (crypto.Signer, error)

// parseKeyType maps a CertSpec.KeyType string to a generator. The names are
// the client-side conventions (certbot/lego style) rather than the server's
// PKCS#11 mechanism names, since these keys live on the host.
func parseKeyType(name string) (keyGenerator, error) {
	switch name {
	case "ecdsa-p256":
		return func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }, nil
	case "ecdsa-p384":
		return func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }, nil
	case "rsa-2048":
		return func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }, nil
	case "rsa-3072":
		return func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) }, nil
	case "rsa-4096":
		return func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 4096) }, nil
	default:
		return nil, fmt.Errorf("unsupported key_type %q (want ecdsa-p256, ecdsa-p384, rsa-2048, rsa-3072, or rsa-4096)", name)
	}
}

// generateKey creates the spec's private key locally. It never leaves the
// host: enrollment sends only a CSR.
func generateKey(spec *CertSpec) (crypto.Signer, error) {
	gen, err := parseKeyType(spec.KeyType)
	if err != nil {
		return nil, err
	}
	key, err := gen()
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", spec.KeyType, err)
	}
	return key, nil
}

// buildCSR creates a PKCS#10 request carrying exactly the spec's subject and
// SANs, signed by key.
func buildCSR(spec *CertSpec, key crypto.Signer) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: spec.CommonName},
		DNSNames: append([]string(nil), spec.DNSNames...),
	}
	for _, raw := range spec.IPAddresses {
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip address %q", raw)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	return der, nil
}

// encodeKeyPEM serializes a private key as PKCS#8 PEM.
func encodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parseKeyPEM loads a PKCS#8 (or legacy EC/RSA) PEM private key.
func parseKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key file holds a %T, which cannot sign", key)
		}
		return signer, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("key file is not a parseable private key")
}

// encodeCertPEM serializes one certificate as PEM.
func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// encodeChainPEM serializes certificates as concatenated PEM.
func encodeChainPEM(certs []*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, encodeCertPEM(c.Raw)...)
	}
	return out
}

// parseCertsPEM parses every CERTIFICATE block in data.
func parseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
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
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}

// publicKeysMatch reports whether the certificate was issued for key.
func publicKeysMatch(cert *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := cert.PublicKey.(equaler)
	if !ok {
		return false
	}
	return pub.Equal(key.Public())
}
