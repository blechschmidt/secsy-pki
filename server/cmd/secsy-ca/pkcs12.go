package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pkcs12"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// cmdExportP12 implements `secsy-ca export-p12`: it generates a subject keypair
// server-side, issues a leaf under a profile (the CA key stays in the HSM), and
// writes a password-protected PKCS#12 (.p12/.pfx) bundle containing the subject
// key, the leaf, and the full issuer chain. With -escrow the freshly generated
// subject key is additionally escrowed under the configured M-of-N policy so it
// can be recovered under dual control.
func cmdExportP12(db *database.DB, mgr *ca.Manager, provider keyprovider.Provider, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("export-p12", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	profile := fs.String("profile", "server", "certificate profile (see 'profiles')")
	subj := addSubjectFlags(fs)
	dns := fs.String("dns", "", "comma-separated DNS SANs")
	ipList := fs.String("ip", "", "comma-separated IP-address SANs")
	emailList := fs.String("email", "", "comma-separated e-mail SANs (S/MIME)")
	uriList := fs.String("uri", "", "comma-separated URI SANs")
	keyType := fs.String("key-type", pkcs12.DefaultKeyType, "subject key type: ecdsa|rsa")
	keyBits := fs.Int("key-bits", 0, "key size (RSA bits, or ECDSA curve 256|384|521; 0 = default)")
	validityDays := fs.Int("validity-days", 0, "validity in days (0 = profile default)")
	password := fs.String("password", "", "PKCS#12 export password (or use -password-file / $SECSY_P12_PASSWORD)")
	passwordFile := fs.String("password-file", "", "read the export password from this file (first line)")
	encoder := fs.String("encoder", pkcs12.EncoderModern, "PKCS#12 encoder: modern|legacy|legacyrc2")
	out := fs.String("out", "", "write the .p12 bundle here (required)")
	escrow := fs.Bool("escrow", false, "escrow the subject private key under the configured M-of-N policy")
	escrowOut := fs.String("escrow-out", "", "write the escrow envelope JSON here (required with -escrow)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" || *out == "" {
		fs.Usage()
		return fmt.Errorf("-ca and -out are required")
	}
	if *escrow && *escrowOut == "" {
		return fmt.Errorf("-escrow-out is required with -escrow")
	}

	pass, err := resolveP12Password(*password, *passwordFile)
	if err != nil {
		return err
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	ips, err := parseIPList(splitCSV(*ipList))
	if err != nil {
		return err
	}
	uris, err := parseURIList(splitCSV(*uriList))
	if err != nil {
		return err
	}

	ctx := context.Background()

	// Prepare the escrow policy/ring before generating anything, so a
	// misconfiguration surfaces before a key is issued.
	var escrowPolicy *secret.EscrowPolicy
	var ring *secret.Ring
	if *escrow {
		escrowPolicy, err = escrowPolicyFromConfigCA(ctx, cfg, provider)
		if err != nil {
			return err
		}
		ring, err = secretRingFromConfig(ctx, db, provider, cfg)
		if err != nil {
			return err
		}
	}

	result, err := pkcs12.GenerateAndBundle(ctx, mgr, pkcs12.BundleRequest{
		CAID:           caID,
		Profile:        *profile,
		Subject:        ca.PKIXName(subj.subject()),
		DNSNames:       splitCSV(*dns),
		IPAddresses:    ips,
		EmailAddresses: splitCSV(*emailList),
		URIs:           uris,
		Key:            pkcs12.KeySpec{Type: *keyType, Bits: *keyBits},
		Validity:       daysToDuration(*validityDays),
		Password:       pass,
		Encoder:        *encoder,
		RequestedBy:    cliActor(),
	})
	if err != nil {
		return err
	}
	defer zeroCLI(result.PrivateKeyPKCS8)

	if err := os.WriteFile(*out, result.PKCS12, 0o600); err != nil {
		return fmt.Errorf("writing PKCS#12 bundle: %w", err)
	}

	detail := fmt.Sprintf("profile=%s key=%s encoder=%s", result.Profile, result.KeyType, result.Encoder)

	if *escrow {
		context := pkcs12.EscrowContext(result.Serial.String())
		blob, err := ring.EncryptWithEscrowToJSON(result.PrivateKeyPKCS8, []byte(context), escrowPolicy)
		if err != nil {
			return fmt.Errorf("escrowing subject key: %w", err)
		}
		if err := os.WriteFile(*escrowOut, blob, 0o600); err != nil {
			return fmt.Errorf("writing escrow envelope: %w", err)
		}
		// Break-glass key delivery must be auditable: a failure to record is fatal.
		if err := db.AppendEvent(&audit.Event{
			Actor:  cliActor(),
			Action: audit.ActionSecretEscrow,
			Target: result.Serial.String(),
			Result: audit.ResultSuccess,
			Detail: fmt.Sprintf("pkcs12 subject key; threshold=%d agents=%d", escrowPolicy.Threshold(), len(escrowPolicy.Agents())),
		}); err != nil {
			return fmt.Errorf("recording escrow audit event: %w", err)
		}
		detail += fmt.Sprintf(" escrow=%d-of-%d", escrowPolicy.Threshold(), len(escrowPolicy.Agents()))
		fmt.Fprintf(os.Stderr, "Escrowed subject key to %s (recover with: secsy-secret recover -context %q)\n", *escrowOut, context)
	}

	appendAudit(db, &audit.Event{
		Actor:  cliActor(),
		Action: audit.ActionCertPKCS12,
		Target: result.Serial.String(),
		Result: audit.ResultSuccess,
		Detail: detail,
	})

	fmt.Fprintf(os.Stderr, "Exported PKCS#12: serial=%s profile=%s key=%s encoder=%s -> %s\n",
		result.Serial, result.Profile, result.KeyType, result.Encoder, *out)
	return nil
}

// resolveP12Password sources the export password from (in priority order) a
// password file, the -password flag, or the SECSY_P12_PASSWORD environment
// variable. Sourcing it outside the flag avoids leaking it via the process
// argument list.
func resolveP12Password(flagVal, file string) (string, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("reading password file: %w", err)
		}
		// Take the first line, trimming a trailing newline.
		pw := string(data)
		if i := strings.IndexByte(pw, '\n'); i >= 0 {
			pw = pw[:i]
		}
		pw = strings.TrimRight(pw, "\r")
		if pw == "" {
			return "", fmt.Errorf("password file %q is empty", file)
		}
		return pw, nil
	}
	if flagVal != "" {
		return flagVal, nil
	}
	if env := os.Getenv("SECSY_P12_PASSWORD"); env != "" {
		return env, nil
	}
	return "", fmt.Errorf("an export password is required (set -password, -password-file, or $SECSY_P12_PASSWORD)")
}

// parseIPList parses IP-address SAN strings.
func parseIPList(vals []string) ([]net.IP, error) {
	out := make([]net.IP, 0, len(vals))
	for _, s := range vals {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP-address SAN %q", s)
		}
		out = append(out, ip)
	}
	return out, nil
}

// parseURIList parses absolute-URI SAN strings.
func parseURIList(vals []string) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(vals))
	for _, s := range vals {
		u, err := url.Parse(s)
		if err != nil || !u.IsAbs() {
			return nil, fmt.Errorf("invalid URI SAN %q (must be an absolute URI)", s)
		}
		out = append(out, u)
	}
	return out, nil
}

// escrowPolicyFromConfigCA builds a validated M-of-N escrow policy from the
// secret.escrow configuration, resolving each recovery agent's public key from
// the key provider or an inline/file PEM. It mirrors the server's wiring.
func escrowPolicyFromConfigCA(ctx context.Context, cfg *config.Config, provider keyprovider.Provider) (*secret.EscrowPolicy, error) {
	ec := cfg.Secret.Escrow
	if !ec.Enabled {
		return nil, fmt.Errorf("key escrow is not enabled: set secret.escrow.enabled and configure recovery agents")
	}
	specs := make([]secret.AgentSpec, 0, len(ec.Agents))
	for _, a := range ec.Agents {
		spec := secret.AgentSpec{ID: a.ID, KeyLabel: a.KeyLabel, PublicKeyPEM: a.PublicKey}
		if spec.PublicKeyPEM == "" && a.PublicKeyFile != "" {
			pemBytes, err := os.ReadFile(a.PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("reading public_key_file for agent %q: %w", a.ID, err)
			}
			spec.PublicKeyPEM = string(pemBytes)
		}
		specs = append(specs, spec)
	}
	return secret.NewEscrowPolicy(ctx, provider, ec.Threshold, specs)
}

// secretRingFromConfig loads the deployment KEK's rotation-aware Ring so the
// escrow envelope's data key is sealed under the configured secret KEK.
func secretRingFromConfig(ctx context.Context, db *database.DB, provider keyprovider.Provider, cfg *config.Config) (*secret.Ring, error) {
	family := cfg.Secret.KEKLabel
	if family == "" {
		return nil, fmt.Errorf("escrow requires a secret KEK: set secret.kek_label")
	}
	versions, err := db.ListKEKVersions(family)
	if err != nil {
		return nil, fmt.Errorf("reading KEK rotation state: %w", err)
	}
	// Attach the family's post-quantum ML-KEM material (Task 137) so the escrow
	// envelope is sealed hybrid when secret.pqc_hybrid is enabled, matching the
	// secret layer's data-at-rest protection.
	pqcRec, err := db.GetPQCHybridKey(family)
	if err != nil {
		return nil, fmt.Errorf("reading post-quantum hybrid key material: %w", err)
	}
	return secret.LoadRingWithPQC(ctx, provider, family, versions, pqcRec, cfg.Secret.PQCHybrid)
}

// zeroCLI scrubs a byte slice holding transient key material.
func zeroCLI(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
