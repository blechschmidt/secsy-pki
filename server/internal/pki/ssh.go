package pki

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
)

func SignSSHCertificate(signer crypto.Signer, pubKeyData []byte, certType uint32, keyID string, principals []string, validAfter, validBefore time.Time, extensions, criticalOptions map[string]string) ([]byte, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          serial.Uint64(),
		CertType:        certType,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}

	if extensions != nil {
		cert.Extensions = extensions
	} else if certType == ssh.UserCert {
		// Default extensions for user certificates
		cert.Extensions = map[string]string{
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		}
	}

	if criticalOptions != nil {
		cert.CriticalOptions = criticalOptions
	}

	caSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("creating SSH signer: %w", err)
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("signing certificate: %w", err)
	}

	return ssh.MarshalAuthorizedKey(cert), nil
}

func ParseCertType(s string) (uint32, error) {
	switch s {
	case "user", "":
		return ssh.UserCert, nil
	case "host":
		return ssh.HostCert, nil
	default:
		return 0, fmt.Errorf("invalid cert type: %s (must be 'user' or 'host')", s)
	}
}

func ParseTime(s string, defaultTime time.Time) (time.Time, error) {
	if s == "" {
		return defaultTime, nil
	}
	if s == "always" {
		return time.Unix(0, 0), nil
	}

	// Try relative format like "+52w"
	if len(s) > 1 && s[0] == '+' {
		dur, err := parseRelativeTime(s[1:])
		if err == nil {
			return time.Now().Add(dur), nil
		}
	}

	// Try RFC3339
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t, nil
	}

	// Try Unix timestamp
	var ts int64
	if n, err := fmt.Sscanf(s, "%d", &ts); err == nil && n == 1 {
		return time.Unix(ts, 0), nil
	}

	return time.Time{}, fmt.Errorf("cannot parse time: %s", s)
}

func parseRelativeTime(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid relative time: %s", s)
	}

	unit := s[len(s)-1]
	val := s[:len(s)-1]
	var n int64
	if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
		return 0, err
	}

	switch unit {
	case 's':
		return time.Duration(n) * time.Second, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'w':
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown time unit: %c", unit)
	}
}
