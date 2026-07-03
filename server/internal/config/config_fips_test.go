package config

import (
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

// restorePolicy snapshots the process-global FIPS policy around a test, since
// Load mirrors security.fips into it.
func restorePolicy(t *testing.T) {
	t.Helper()
	prev := fips.PolicyEnforced()
	t.Cleanup(func() { fips.SetPolicy(prev) })
}

func TestLoadFIPSValid(t *testing.T) {
	clearProviderEnv(t)
	restorePolicy(t)

	cfg := writeAndLoad(t, `
root_user:
  password: secret
security:
  fips: true
tsa:
  enabled: true
  key_label: tsa-key
  certificate_file: /tmp/tsa.pem
  accepted_hashes: [sha256, sha384]
`)
	if !cfg.Security.FIPS {
		t.Fatal("security.fips should be true")
	}
	if !fips.PolicyEnforced() {
		t.Fatal("Load should mirror security.fips into the global policy")
	}

	// Loading a non-FIPS config afterwards clears the policy again.
	writeAndLoad(t, "root_user:\n  password: secret\n")
	if fips.PolicyEnforced() {
		t.Fatal("Load of a non-FIPS config should clear the global policy")
	}
}

func TestLoadFIPSViolations(t *testing.T) {
	clearProviderEnv(t)
	restorePolicy(t)

	_, err := loadContent(t, `
root_user:
  password: secret
security:
  fips: true
server:
  ocsp:
    delegated_key_type: ed25519
tsa:
  enabled: true
  key_label: tsa-key
  certificate_file: /tmp/tsa.pem
  accepted_hashes: [sha256, sha1]
est:
  enabled: true
  ca_label: intermediate
  users:
    dev: {password: pw}
  enable_server_keygen: true
  server_keygen_key_type: rsa-1024
`)
	if err == nil {
		t.Fatal("expected FIPS violations to fail the load")
	}
	msg := err.Error()
	// All violations are reported in one pass, each naming its config key.
	for _, want := range []string{
		"security.fips",
		"tsa.accepted_hashes",
		`"sha1"`,
		"est.server_keygen_key_type",
		"rsa-1024",
		"server.ocsp.delegated_key_type",
		"ed25519",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %q; got:\n%s", want, msg)
		}
	}
	// A rejected load must not leave the policy enforced.
	if fips.PolicyEnforced() {
		t.Error("failed Load must not enable the global policy")
	}
}

func TestLoadFIPSOffIgnoresNonApproved(t *testing.T) {
	clearProviderEnv(t)
	restorePolicy(t)

	cfg := writeAndLoad(t, `
root_user:
  password: secret
tsa:
  enabled: true
  key_label: tsa-key
  certificate_file: /tmp/tsa.pem
  accepted_hashes: [sha1, sha256]
`)
	if cfg.Security.FIPS {
		t.Fatal("security.fips should default to false")
	}
	if fips.PolicyEnforced() {
		t.Fatal("policy must stay off without security.fips")
	}
}
