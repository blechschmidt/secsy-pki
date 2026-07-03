package main

import (
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/sshca"
)

// sshProfilesFromConfig maps config.SSHProfileConfig entries to sshca.Profile
// values, parsing the human-friendly validity strings. (Mirrored in
// cmd/secsy-ca, like the X.509 profile conversion.)
func sshProfilesFromConfig(in []config.SSHProfileConfig) ([]sshca.Profile, error) {
	profiles := make([]sshca.Profile, 0, len(in))
	for _, p := range in {
		def, err := sshca.ParseValidity(p.DefaultValidity)
		if err != nil {
			return nil, fmt.Errorf("ssh profile %q: default_validity: %w", p.Name, err)
		}
		max, err := sshca.ParseValidity(p.MaxValidity)
		if err != nil {
			return nil, fmt.Errorf("ssh profile %q: max_validity: %w", p.Name, err)
		}
		profiles = append(profiles, sshca.Profile{
			Name:                   p.Name,
			Description:            p.Description,
			CertType:               p.CertType,
			DefaultValidity:        def,
			MaxValidity:            max,
			AllowedPrincipals:      p.AllowedPrincipals,
			AllowEmptyPrincipals:   p.AllowEmptyPrincipals,
			MaxPrincipals:          p.MaxPrincipals,
			DefaultExtensions:      p.DefaultExtensions,
			AllowedExtensions:      p.AllowedExtensions,
			DefaultCriticalOptions: p.DefaultCriticalOptions,
			AllowedCriticalOptions: p.AllowedCriticalOptions,
		})
	}
	return profiles, nil
}
