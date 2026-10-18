package config

// Mapping from the YAML configuration onto keyprovider settings.
//
// This mapping used to exist three times — once in cmd/server, once in
// cmd/secsy-ca, once in cmd/secsy-secret — which is why the PKCS#11 block had
// drifted: a field added to the config reached whichever commands someone
// remembered to edit. It lives here now so the server and both CLIs build
// byte-identical provider settings from the same config, and a new addressing
// attribute reaches all three by existing.

import (
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// KeyProviderSettings maps the pkcs11 block onto the backend settings,
// including the full RFC 7512 token/slot addressing and the per-token HA set.
func (p PKCS11Config) KeyProviderSettings() keyprovider.PKCS11Settings {
	// Resolve the module here rather than leaving it to the provider, because
	// only this level can see a module named by a per-token URI. A resolution
	// failure is left to the provider to report: it re-resolves pkcs11.uri and
	// produces the same message in the one place every backend shares.
	modulePath := p.ModulePath
	if modulePath == "" {
		if path, err := p.EffectiveModulePath(); err == nil {
			modulePath = path
		}
	}
	return keyprovider.PKCS11Settings{
		ModulePath:        modulePath,
		URI:               p.URI,
		Pin:               p.Pin,
		PinSource:         p.PinSource.Settings(),
		TokenLabel:        p.TokenLabel,
		TokenSerial:       p.TokenSerial,
		TokenManufacturer: p.TokenManufacturer,
		TokenModel:        p.TokenModel,
		SlotID:            p.SlotID,
		SlotDescription:   p.SlotDescription,
		SlotManufacturer:  p.SlotManufacturer,
		SessionPoolSize:   p.SessionPoolSize,
		Tokens:            tokenSettings(p.Tokens),
		SelectionPolicy:   p.SelectionPolicy,
		FailureThreshold:  p.FailureThreshold,
		ProbeInterval:     time.Duration(p.ProbeIntervalSeconds) * time.Second,
	}
}

// tokenSettings maps the per-token HA entries.
func tokenSettings(tokens []PKCS11TokenConfig) []keyprovider.TokenSettings {
	if len(tokens) == 0 {
		return nil
	}
	out := make([]keyprovider.TokenSettings, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, keyprovider.TokenSettings{
			Name:              t.Name,
			URI:               t.URI,
			TokenLabel:        t.TokenLabel,
			TokenSerial:       t.TokenSerial,
			TokenManufacturer: t.TokenManufacturer,
			TokenModel:        t.TokenModel,
			SlotID:            t.SlotID,
			SlotDescription:   t.SlotDescription,
			SlotManufacturer:  t.SlotManufacturer,
			Pin:               t.Pin,
			PinSource:         t.PinSource.Settings(),
		})
	}
	return out
}

// Settings maps a pin_source block onto the keyprovider settings type.
func (p PinSourceConfig) Settings() keyprovider.PinSourceSettings {
	return keyprovider.PinSourceSettings{
		Type: p.Type,
		Env:  keyprovider.EnvPinSourceSettings{Var: p.Env.Var},
		File: keyprovider.FilePinSourceSettings{Path: p.File.Path, AllowInsecurePerms: p.File.AllowInsecurePerms},
		Vault: keyprovider.VaultPinSourceSettings{
			VaultSettings: p.Vault.Settings(),
			Path:          p.Vault.Path,
			Field:         p.Vault.Field,
			KVVersion:     p.Vault.KVVersion,
		},
		AWS:   keyprovider.AWSPinSourceSettings{Region: p.AWS.Region, SecretID: p.AWS.SecretID, Field: p.AWS.Field},
		Azure: keyprovider.AzurePinSourceSettings{VaultURL: p.Azure.VaultURL, Name: p.Azure.Name, Version: p.Azure.Version, Field: p.Azure.Field},
		GCP:   p.GCP.Settings(),
	}
}

// Settings maps the HashiCorp Vault connection block onto the keyprovider
// settings type. It backs both the Transit key-provider backend and the KV
// pin_source, which share these parameters.
func (v VaultProviderConfig) Settings() keyprovider.VaultSettings {
	return keyprovider.VaultSettings{
		Address:     v.Address,
		Mount:       v.Mount,
		Namespace:   v.Namespace,
		AuthMethod:  v.AuthMethod,
		Token:       v.Token,
		RoleID:      v.RoleID,
		SecretID:    v.SecretID,
		AppRolePath: v.AppRolePath,
		CACertFile:  v.CACertFile,
		Insecure:    v.Insecure,
		Timeout:     time.Duration(v.TimeoutSeconds) * time.Second,
	}
}

// Settings maps the Google Cloud Secret Manager pin_source block.
func (g GCPPinSourceConfig) Settings() keyprovider.GCPPinSourceSettings {
	return keyprovider.GCPPinSourceSettings{
		Project:         g.Project,
		Secret:          g.Secret,
		Version:         g.Version,
		CredentialsFile: g.CredentialsFile,
		CredentialsJSON: g.CredentialsJSON,
		Field:           g.Field,
		Endpoint:        g.Endpoint,
	}
}

// Settings maps the Google Cloud KMS key-provider block.
func (g GCPProviderConfig) Settings() keyprovider.GCPKMSSettings {
	return keyprovider.GCPKMSSettings{
		Project:         g.Project,
		Location:        g.Location,
		KeyRing:         g.KeyRing,
		CredentialsFile: g.CredentialsFile,
		CredentialsJSON: g.CredentialsJSON,
		ProtectionLevel: g.ProtectionLevel,
		RSAPSS:          g.RSAPSS,
		Endpoint:        g.Endpoint,
	}
}

// KeyProviderConfigForRole assembles the full keyprovider.Config for a signing
// role, resolving the backend type through the per-role override.
func (c *Config) KeyProviderConfigForRole(role string) keyprovider.Config {
	return keyprovider.Config{
		Type:   keyprovider.ProviderType(c.KeyProviderTypeForRole(role)),
		PKCS11: c.PKCS11.KeyProviderSettings(),
		Software: keyprovider.SoftwareSettings{
			KeystoreDir: c.KeyProvider.Software.KeystoreDir,
		},
		KMS: keyprovider.KMSSettings{
			Backend:   c.KeyProvider.KMS.Backend,
			Region:    c.KeyProvider.KMS.Region,
			KeyPrefix: c.KeyProvider.KMS.KeyPrefix,
			VaultURL:  c.KeyProvider.KMS.VaultURL,
			Vault:     c.KeyProvider.KMS.Vault.Settings(),
			GCP:       c.KeyProvider.KMS.GCP.Settings(),
		},
	}
}
