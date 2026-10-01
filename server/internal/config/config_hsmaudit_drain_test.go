package config

import "testing"

// SigningPKCS11Module answers "does this deployment's signing path compete with
// the audit driver for the YubiHSM's USB interface?", and the answer decides
// whether the server starts. Both false positives and false negatives are
// expensive, so the table walks the configurations that distinguish them.
func TestSigningPKCS11Module(t *testing.T) {
	const module = "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so"
	for _, tc := range []struct {
		name string
		cfg  func(*Config)
		want string
	}{
		{
			name: "the global pkcs11 type with the YubiHSM module",
			cfg: func(c *Config) {
				c.KeyProvider.Type = "pkcs11"
				c.PKCS11.ModulePath = module
			},
			want: module,
		},
		{
			// A per-role override is the realistic mixed deployment: CA keys in
			// a cloud KMS, the TSA on the YubiHSM. The TSA still signs through
			// the module, so the contention is real.
			name: "a single role override is enough",
			cfg: func(c *Config) {
				c.KeyProvider.Type = "kms"
				c.KeyProvider.Roles.TSA = "pkcs11"
				c.PKCS11.ModulePath = module
			},
			want: module,
		},
		{
			name: "an RFC 7512 URI carries the module reference",
			cfg: func(c *Config) {
				c.KeyProvider.Type = "pkcs11"
				c.PKCS11.URI = "pkcs11:token=YubiHSM?module-path=/opt/yubihsm_pkcs11.so"
			},
			want: "pkcs11:token=YubiHSM?module-path=/opt/yubihsm_pkcs11.so",
		},
		{
			name: "an HA token URI counts too",
			cfg: func(c *Config) {
				c.KeyProvider.Type = "pkcs11"
				c.PKCS11.Tokens = []PKCS11TokenConfig{{URI: "pkcs11:serial=31650425?module-name=yubihsm_pkcs11"}}
			},
			want: "pkcs11:serial=31650425?module-name=yubihsm_pkcs11",
		},
		{
			// SoftHSM holds SoftHSM's state, not a USB interface. Reporting
			// contention here would refuse to start a working deployment.
			name: "a different PKCS#11 token is not the YubiHSM",
			cfg: func(c *Config) {
				c.KeyProvider.Type = "pkcs11"
				c.PKCS11.ModulePath = "/usr/lib/softhsm/libsofthsm2.so"
			},
			want: "",
		},
		{
			name: "no PKCS#11 signing role at all",
			cfg: func(c *Config) {
				c.KeyProvider.Type = "software"
				c.PKCS11.ModulePath = module
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			tc.cfg(cfg)
			if got := cfg.SigningPKCS11Module(); got != tc.want {
				t.Fatalf("SigningPKCS11Module() = %q, want %q", got, tc.want)
			}
		})
	}
}
