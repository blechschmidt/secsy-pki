package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/sshca"
)

// installSSHProfiles converts and installs the operator-defined SSH signing
// profiles from config (ssh.profiles), so signing and the profile listing see
// the same effective set as the server.
func installSSHProfiles(cfg *config.Config) error {
	profiles, err := sshProfilesFromConfig(cfg.SSH.Profiles)
	if err != nil {
		return err
	}
	return sshca.SetCustomProfiles(profiles)
}

// sshProfilesFromConfig maps config.SSHProfileConfig entries to sshca.Profile
// values, parsing the human-friendly validity strings.
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

// cmdSSH dispatches the SSH certificate-authority subcommands (Task 57). The
// CA signing key lives in the configured key provider; every signature is
// performed by the backend (HSM/KMS/software keystore) via crypto.Signer.
func cmdSSH(db *database.DB, provider keyprovider.Provider, args []string) error {
	if len(args) == 0 {
		sshUsage()
		return fmt.Errorf("no ssh subcommand given")
	}
	sub, subArgs := args[0], args[1:]
	authority := sshca.NewAuthority(db, provider)
	switch sub {
	case "ca-init":
		return cmdSSHCAInit(db, authority, subArgs)
	case "sign-user":
		return cmdSSHSign(db, authority, sshca.CertTypeUser, subArgs)
	case "sign-host":
		return cmdSSHSign(db, authority, sshca.CertTypeHost, subArgs)
	case "revoke":
		return cmdSSHRevoke(db, authority, subArgs)
	case "krl":
		return cmdSSHKRL(db, authority, subArgs)
	case "list":
		return cmdSSHList(db, subArgs)
	case "profiles":
		return cmdSSHProfiles()
	case "help", "-h", "--help":
		sshUsage()
		return nil
	default:
		sshUsage()
		return fmt.Errorf("unknown ssh subcommand %q", sub)
	}
}

func sshUsage() {
	fmt.Fprint(os.Stderr, `secsy-ca ssh — HSM-backed OpenSSH certificate authority

Usage:
  secsy-ca [-config config.yaml] ssh <subcommand> [flags]

Subcommands:
  ca-init    Generate an SSH CA signing key in the key provider
  sign-user  Sign an OpenSSH public key into a user certificate
  sign-host  Sign an OpenSSH public key into a host certificate
  revoke     Revoke a certificate by serial, or every certificate by key ID
  krl        Generate the CA's OpenSSH Key Revocation List (KRL)
  list       List certificates signed by a CA
  profiles   List the available SSH signing profiles
`)
}

func cmdSSHCAInit(db *database.DB, authority *sshca.Authority, args []string) error {
	fs := flag.NewFlagSet("ssh ca-init", flag.ContinueOnError)
	label := fs.String("label", "", "CA label; doubles as the provider key label (required)")
	keyType := fs.String("key-type", sshca.DefaultCAKeyType, "CA key type (ed25519, ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096)")
	tenant := fs.String("tenant", "", "owning tenant id (default: the default tenant)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" {
		fs.Usage()
		return fmt.Errorf("-label is required")
	}

	ca, err := authority.InitCA(context.Background(), sshca.CASpec{
		TenantID: *tenant,
		Label:    *label,
		KeyType:  *keyType,
	})
	if err != nil {
		return err
	}
	appendAudit(db, &audit.Event{
		Actor: "cli", Action: audit.ActionSSHCAInit, Tenant: ca.TenantID,
		Target: ca.ID, TargetName: ca.Label, Result: audit.ResultSuccess,
		Detail: "key_type=" + ca.KeyType,
	})

	fmt.Fprintf(os.Stderr, "SSH CA %q created (id %s, key type %s)\n", ca.Label, ca.ID, ca.KeyType)
	fmt.Fprintf(os.Stderr, "Trust this CA for user certificates (sshd_config):\n  TrustedUserCAKeys /etc/ssh/%s.pub\n", ca.Label)
	fmt.Fprintf(os.Stderr, "Trust it for host certificates (known_hosts):\n  @cert-authority * %s\n", ca.PublicKey)
	fmt.Println(ca.PublicKey)
	return nil
}

// kvFlag collects repeatable KEY[=VALUE] flags into a map, preserving OpenSSH
// semantics where a bare key (e.g. an extension like permit-pty) maps to "".
type kvFlag map[string]string

func (f kvFlag) String() string {
	parts := make([]string, 0, len(f))
	for k, v := range f {
		if v == "" {
			parts = append(parts, k)
		} else {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, ",")
}

func (f kvFlag) Set(s string) error {
	k, v, _ := strings.Cut(s, "=")
	k = strings.TrimSpace(k)
	if k == "" {
		return fmt.Errorf("empty name")
	}
	f[k] = v
	return nil
}

func cmdSSHSign(db *database.DB, authority *sshca.Authority, certType string, args []string) error {
	fs := flag.NewFlagSet("ssh sign-"+certType, flag.ContinueOnError)
	caRef := fs.String("ca", "", "signing CA id or label (required)")
	pubPath := fs.String("pub", "", "public key file to certify, '-' for stdin (required)")
	keyID := fs.String("key-id", "", "certificate key ID (default: the first principal)")
	principals := fs.String("principals", "", "comma-separated principals (user names or host names)")
	profile := fs.String("profile", "", "signing profile (default: "+sshca.DefaultProfileName(certType)+")")
	validity := fs.String("validity", "", "requested validity (e.g. 12h, 30d; default: profile default)")
	out := fs.String("out", "", "write the certificate here (default: stdout)")
	extensions := kvFlag{}
	criticalOptions := kvFlag{}
	if certType == sshca.CertTypeUser {
		fs.Var(extensions, "extension", "extension NAME[=VALUE]; repeatable, replaces the profile defaults")
		fs.Var(criticalOptions, "option", "critical option NAME=VALUE (e.g. source-address=10.0.0.0/8); repeatable")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" || *pubPath == "" {
		fs.Usage()
		return fmt.Errorf("-ca and -pub are required")
	}

	var pubData []byte
	var err error
	if *pubPath == "-" {
		pubData, err = io.ReadAll(os.Stdin)
	} else {
		pubData, err = os.ReadFile(*pubPath)
	}
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}

	dur, err := sshca.ParseValidity(*validity)
	if err != nil {
		return err
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	var principalList []string
	if s := strings.TrimSpace(*principals); s != "" {
		principalList = strings.Split(s, ",")
	}

	result, err := authority.Sign(context.Background(), sshca.SignRequest{
		CAID:            caID,
		CertType:        certType,
		PublicKey:       string(pubData),
		KeyID:           *keyID,
		Principals:      principalList,
		Profile:         *profile,
		Validity:        dur,
		Extensions:      extensions,
		CriticalOptions: criticalOptions,
		RequestedBy:     "cli",
	})
	if err != nil {
		return err
	}
	rec := result.Record
	appendAudit(db, &audit.Event{
		Actor: "cli", Action: audit.ActionSSHSign, Tenant: result.CA.TenantID,
		Target: result.CA.ID, TargetName: result.CA.Label, Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("serial=%s type=%s key_id=%s principals=%s profile=%s",
			rec.Serial, rec.CertType, rec.KeyID, strings.Join(rec.Principals, ","), rec.Profile),
	})

	fmt.Fprintf(os.Stderr, "Signed %s certificate serial %s (key ID %q, profile %s, valid until %s)\n",
		rec.CertType, rec.Serial, rec.KeyID, rec.Profile, rec.ValidBefore.UTC().Format(time.RFC3339))
	return writeOutput(*out, result.AuthorizedKey)
}

func cmdSSHRevoke(db *database.DB, authority *sshca.Authority, args []string) error {
	fs := flag.NewFlagSet("ssh revoke", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label (required)")
	serial := fs.String("serial", "", "certificate serial to revoke")
	keyID := fs.String("key-id", "", "revoke every certificate bearing this key ID instead")
	reason := fs.String("reason", "", "optional reason recorded with the revocation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	rev, newly, err := authority.Revoke(context.Background(), sshca.RevokeRequest{
		CAID:      caID,
		Serial:    *serial,
		KeyID:     *keyID,
		Reason:    *reason,
		RevokedBy: "cli",
	})
	if err != nil {
		return err
	}
	target := "serial=" + rev.Serial
	if rev.Serial == "" {
		target = "key_id=" + rev.KeyID
	}
	appendAudit(db, &audit.Event{
		Actor: "cli", Action: audit.ActionSSHRevoke,
		Target: caID, Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("%s newly_revoked=%t reason=%s", target, newly, rev.Reason),
	})
	if newly {
		fmt.Fprintf(os.Stderr, "Revoked %s. Regenerate and redistribute the KRL:\n  secsy-ca ssh krl -ca %s -out ca.krl\n", target, *caRef)
	} else {
		fmt.Fprintf(os.Stderr, "%s was already revoked; reason/time updated.\n", target)
	}
	return nil
}

func cmdSSHKRL(db *database.DB, authority *sshca.Authority, args []string) error {
	fs := flag.NewFlagSet("ssh krl", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label (required)")
	comment := fs.String("comment", "", "comment stamped into the KRL header")
	out := fs.String("out", "", "write the KRL here (default: stdout; binary)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	krl, err := authority.BuildKRL(context.Background(), caID, *comment)
	if err != nil {
		return err
	}
	revs, err := db.ListSSHRevocations(caID)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "KRL version %d (%d revocation(s)); point sshd's RevokedKeys at the file.\n", len(revs), len(revs))
	return writeOutput(*out, krl)
}

func cmdSSHList(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("ssh list", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	certs, err := db.ListSSHCertificates(caID)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SERIAL\tTYPE\tKEY ID\tPRINCIPALS\tPROFILE\tSTATUS\tVALID UNTIL")
	for _, c := range certs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Serial, c.CertType, c.KeyID, strings.Join(c.Principals, ","),
			c.Profile, c.Status, c.ValidBefore.UTC().Format(time.RFC3339))
	}
	return w.Flush()
}

func cmdSSHProfiles() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tDEFAULT VALIDITY\tMAX VALIDITY\tDESCRIPTION")
	for _, p := range sshca.Profiles() {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			p.Name, p.CertType,
			time.Duration(p.DefaultValiditySecs)*time.Second,
			time.Duration(p.MaxValiditySecs)*time.Second,
			p.Description)
	}
	return w.Flush()
}
