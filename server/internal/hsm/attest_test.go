package hsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// Device-free tests for the parts of this package that decide things before a
// session exists, or after one has closed.
//
// Almost everything here runs against hardware, behind the `yubihsm` build tag.
// The handful of functions below are the exceptions, and they are the ones where
// a mistake is silent: addressing the wrong device, storing a digest in the
// wrong case, or reaching for hardware at all when the caller passed a
// configuration that should have been refused outright.

// A zero Config means "whatever YubiHSM is plugged into this machine", so the
// mapping from this package's configuration to the driver's has to be exact: if
// the audit path and the signing path resolve differently, the log describes
// hardware other than the one holding the CA key.
func TestNativeConfigCarriesTheDeviceAddress(t *testing.T) {
	withoutPKCS11Conf(t)

	cfg := Config{ConnectorURL: "http://hsm.internal:12345", AuthKeyID: 4, Password: "s3cret"}
	got := cfg.nativeConfig()
	if got.ConnectorURL != cfg.ConnectorURL {
		t.Fatalf("connector = %q, want %q", got.ConnectorURL, cfg.ConnectorURL)
	}
	if got.AuthKeyID != 4 {
		t.Fatalf("auth key id = %d, want 4", got.AuthKeyID)
	}
	if got.Password != "s3cret" {
		t.Fatalf("password did not survive the mapping")
	}

	// The driver resolves an empty connector to direct USB and a zero auth key id
	// to key 1; this package must hand it the same defaults rather than its own.
	zero := Config{}.nativeConfig()
	if zero.ConnectorURL != "yhusb://" {
		t.Fatalf("default connector = %q, want yhusb://", zero.ConnectorURL)
	}
	if zero.AuthKeyID != 0 {
		t.Fatalf("auth key id = %d; the driver's own default must not be pre-empted", zero.AuthKeyID)
	}
}

// The audit path must land on the same device the PKCS#11 signing path does, so
// a deployment that configured only YUBIHSM_PKCS11_CONF keeps working. That
// makes this file parse part of the device address.
func TestConnectorArgReadsThePKCS11ConfigFile(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "yubihsm_pkcs11.conf")
	body := "# a comment\n\nconnector = http://127.0.0.1:12345\ndebug\n"
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YUBIHSM_PKCS11_CONF", conf)

	if got := connectorArg(Config{}); got != "http://127.0.0.1:12345" {
		t.Fatalf("connectorArg = %q, want the connector from the PKCS#11 config", got)
	}
	// An explicit connector still wins: the caller named a device.
	if got := connectorArg(Config{ConnectorURL: "yhusb://serial=31650425"}); got != "yhusb://serial=31650425" {
		t.Fatalf("an explicit connector was overridden by the config file: %q", got)
	}
}

// A config file that cannot be read, or that names no connector, must fall back
// to direct USB rather than returning an empty address — which the driver would
// resolve to direct USB anyway, but only by accident.
func TestConnectorArgFallsBackWhenTheConfigIsUnusable(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("YUBIHSM_PKCS11_CONF", filepath.Join(dir, "does-not-exist.conf"))
	if got := connectorArg(Config{}); got != "yhusb://" {
		t.Fatalf("missing config: connectorArg = %q, want yhusb://", got)
	}

	noConnector := filepath.Join(dir, "no-connector.conf")
	if err := os.WriteFile(noConnector, []byte("debug\ncacert = /etc/ca.pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YUBIHSM_PKCS11_CONF", noConnector)
	if got := connectorArg(Config{}); got != "yhusb://" {
		t.Fatalf("config without a connector: connectorArg = %q, want yhusb://", got)
	}
}

// The digest is stored and transported as lowercase hex throughout the audit
// subsystem; the chain verifier compares those strings, so a case or field-order
// change here breaks verification rather than formatting.
func TestConvertEntriesPreservesEveryFieldAndLowercasesTheDigest(t *testing.T) {
	if got := convertEntries(nil); got != nil {
		t.Fatalf("an empty log converted to %#v, want nil", got)
	}

	var digest [16]byte
	copy(digest[:], []byte{0xAB, 0xCD, 0xEF, 0x01})
	in := []yubihsm.LogEntry{{
		Number: 7, Command: 0x56, Length: 0x0041, SessionKey: 0x0001,
		TargetKey: 0x1939, SecondKey: 0xffff, Result: 0x83, Tick: 123456,
		Digest: digest,
	}}
	out := convertEntries(in)
	if len(out) != 1 {
		t.Fatalf("converted %d entries, want 1", len(out))
	}
	e := out[0]
	if e.Number != 7 || e.Command != 0x56 || e.Length != 0x0041 || e.SessionKey != 0x0001 ||
		e.TargetKey != 0x1939 || e.SecondKey != 0xffff || e.Result != 0x83 || e.Tick != 123456 {
		t.Fatalf("a field was dropped or transposed: %+v", e)
	}
	want := hex.EncodeToString(digest[:])
	if e.Hash != want {
		t.Fatalf("digest = %q, want lowercase hex %q", e.Hash, want)
	}
	if strings.ToLower(e.Hash) != e.Hash {
		t.Fatalf("digest %q is not lowercase", e.Hash)
	}
}

// Attestation material leaves this package as PEM. The block type has to be
// CERTIFICATE or nothing downstream — openssl, the console, internal/hsmattest —
// will parse it.
func TestEncodeCertPEMProducesAParsableCertificateBlock(t *testing.T) {
	der := selfSignedDER(t)

	block, rest := pem.Decode([]byte(encodeCertPEM(der)))
	if block == nil {
		t.Fatal("encodeCertPEM produced something that is not PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM block type = %q, want CERTIFICATE", block.Type)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("trailing bytes after the PEM block: %q", rest)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("the encoded certificate does not round-trip: %v", err)
	}
}

func TestAuditLevelNames(t *testing.T) {
	for _, tc := range []struct {
		level uint8
		want  string
	}{
		{0x00, "off"},
		{0x01, "on"},
		{0x02, "fixed"},
		// A level this build does not know must be visible as a number rather
		// than silently reading as "off", which is the level that would mean
		// commands are going unlogged.
		{0x09, "unknown(0x09)"},
	} {
		if got := auditLevelName(tc.level); got != tc.want {
			t.Fatalf("auditLevelName(0x%02x) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

// The commitment label is the commitment: it is a digest of the audit head,
// sized to fill the device's 40-byte label field exactly. A label outside those
// bounds cannot carry one, so it is refused before a session is opened.
//
// The connector names a closed port rather than a device, so a regression that
// moved this check behind withClient fails here with a connection error instead
// of reaching for whatever HSM is plugged into the machine running the tests.
func TestCommitAuditHeadRefusesALabelThatCannotCarryACommitment(t *testing.T) {
	cfg := Config{ConnectorURL: "http://127.0.0.1:1"}

	for _, tc := range []struct {
		name  string
		label string
	}{
		{"empty", ""},
		{"over the device limit", strings.Repeat("x", 41)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := CommitAuditHead(context.Background(), cfg, CommitmentRequest{
				ObjectID: 0xfb00,
				Label:    tc.label,
			})
			if err == nil {
				t.Fatal("an unusable commitment label was accepted")
			}
			if !strings.Contains(err.Error(), "want 1..40") {
				t.Fatalf("expected a label-length refusal before any device access, got %v", err)
			}
		})
	}
}

// withoutPKCS11Conf blanks the PKCS#11 config env var so a test asserting on the
// default device address is not steered by the developer's environment (or by
// TestMain in the yubihsm-tagged file). connectorArg treats empty as unset.
func withoutPKCS11Conf(t *testing.T) {
	t.Helper()
	t.Setenv("YUBIHSM_PKCS11_CONF", "")
}

// selfSignedDER is a throwaway certificate to encode; the contents do not
// matter, only that the result parses back as X.509.
func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "attestation-test"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
