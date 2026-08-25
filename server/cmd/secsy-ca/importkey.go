package main

// `secsy-ca import-key` and `secsy-ca ca import` — bringing existing key
// material under this PKI (Task 194).
//
// Both commands are deliberately CLI-only. They take a private key file as
// input, and a private key file is the one thing that must never travel to a
// browser or across the network API: the whole point of the operation is to
// stop that material from being copied around. It is read from a local path, on
// an operator's shell, once — and after that it lives in the key provider.
//
//	secsy-ca import-key   place an existing private key into the key provider
//	secsy-ca ca import    adopt an existing CA: its key *and* its certificate
//
// The second is the migration command. The first is the building block, for a
// TSA/signing/SSH key, or for staging a CA key ahead of `ca import
// -existing-key`.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// keyPassphraseEnv names the environment variable consulted for a key file's
// passphrase, so a scripted migration need not put it in the process table.
const keyPassphraseEnv = "SECSY_KEY_PASSPHRASE"

// importKeyFlags are the input flags shared by `import-key` and `ca import`.
type importKeyFlags struct {
	keyFile  string
	passFile string
}

func addImportKeyFlags(fs *flag.FlagSet) *importKeyFlags {
	f := &importKeyFlags{}
	fs.StringVar(&f.keyFile, "key", "", "file holding the existing private key: PEM (PKCS#8, PKCS#1, SEC1, encrypted PKCS#8, OpenSSH), bare DER, or PKCS#12/.p12")
	fs.StringVar(&f.passFile, "pass-file", "", "file holding the key's passphrase (\"-\" reads stdin); defaults to the "+keyPassphraseEnv+" environment variable")
	return f
}

// readPassphrase resolves the key passphrase from -pass-file or the
// environment. Neither a prompt nor a -pass flag is offered: a passphrase on
// the command line lands in the shell history and the process table.
func (f *importKeyFlags) readPassphrase() ([]byte, error) {
	switch {
	case f.passFile == "-":
		data, err := readAllStdin()
		if err != nil {
			return nil, fmt.Errorf("reading the passphrase from stdin: %w", err)
		}
		return trimPassphrase(data), nil
	case f.passFile != "":
		data, err := os.ReadFile(f.passFile)
		if err != nil {
			return nil, fmt.Errorf("reading -pass-file: %w", err)
		}
		return trimPassphrase(data), nil
	default:
		return []byte(os.Getenv(keyPassphraseEnv)), nil
	}
}

// trimPassphrase strips the single trailing newline a file or heredoc adds,
// which is almost never part of the passphrase.
func trimPassphrase(data []byte) []byte {
	return []byte(strings.TrimRight(string(data), "\r\n"))
}

func readAllStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

// loadPrivateKey reads and decodes the key file named by the flags, turning the
// "it is encrypted" and "the passphrase is wrong" cases into advice rather than
// a parse error.
func (f *importKeyFlags) loadPrivateKey() (*pki.ParsedPrivateKey, error) {
	if f.keyFile == "" {
		return nil, fmt.Errorf("-key is required")
	}
	data, err := os.ReadFile(f.keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading -key: %w", err)
	}
	pass, err := f.readPassphrase()
	if err != nil {
		return nil, err
	}
	parsed, err := pki.ParsePrivateKey(data, pass)
	switch {
	case err == nil:
		return parsed, nil
	case strings.Contains(err.Error(), pki.ErrPassphraseRequired.Error()):
		return nil, fmt.Errorf("%s is encrypted: supply the passphrase with -pass-file <file> or the %s environment variable", f.keyFile, keyPassphraseEnv)
	case strings.Contains(err.Error(), pki.ErrWrongPassphrase.Error()):
		return nil, fmt.Errorf("the passphrase for %s is incorrect", f.keyFile)
	default:
		return nil, err
	}
}

// cmdImportKey implements `secsy-ca import-key`. caProvider is the CA-role
// backend main already built; a -role naming a differently-configured backend
// gets its own, so a TSA or signing key is imported where that role's keys live.
func cmdImportKey(db *database.DB, cfg *config.Config, caProvider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("import-key", flag.ContinueOnError)
	label := fs.String("label", "", "label to store the key under in the provider (required)")
	id := fs.String("id", "", "optional hex CKA_ID for the imported key (PKCS#11 only)")
	usage := fs.String("usage", "sign", "key usage: sign (default) or decrypt (an RSA key-encryption key)")
	role := fs.String("role", "ca", "key-provider role that receives the key: ca, tsa, signing, or secret")
	keyFlags := addImportKeyFlags(fs)
	jsonOut := fs.Bool("json", false, "emit the imported key's metadata as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" {
		fs.Usage()
		return fmt.Errorf("-label is required")
	}
	provider := caProvider
	if *role != "" && *role != "ca" {
		if cfg.KeyProviderTypeForRole(*role) != cfg.KeyProviderTypeForRole("ca") {
			rp, err := buildProvider(cfg, *role)
			if err != nil {
				return fmt.Errorf("initializing the %s key provider: %w", *role, err)
			}
			defer rp.Close()
			provider = rp
		}
	}
	keyUsage := keyprovider.KeyUsageSign
	switch strings.ToLower(*usage) {
	case "", "sign":
	case "decrypt", "kek":
		keyUsage = keyprovider.KeyUsageDecrypt
	default:
		return fmt.Errorf("unknown -usage %q (want sign or decrypt)", *usage)
	}

	parsed, err := keyFlags.loadPrivateKey()
	if err != nil {
		return err
	}
	signer, err := parsed.Signer()
	if err != nil {
		return err
	}

	if !keyprovider.CanImport(provider) {
		return fmt.Errorf("the %s key provider cannot import an existing key; generate the key instead, or use the backend's own bring-your-own-key procedure", provider.Name())
	}

	ctx := context.Background()
	info, err := keyprovider.ImportKey(ctx, provider, keyprovider.ImportSpec{
		Label:      *label,
		ID:         *id,
		Usage:      keyUsage,
		PrivateKey: parsed.Key,
	})
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: cliActor(), Action: audit.ActionKeyImport, TargetName: *label,
			Result: audit.ResultError, Detail: err.Error(),
		})
		return err
	}

	// A signing key is proved usable before the operator is told it worked; a
	// decrypt-only key cannot sign, so it is exempt.
	verified := false
	if keyUsage == keyprovider.KeyUsageSign {
		if err := keyprovider.VerifyKeyUsable(ctx, provider, keyprovider.KeyRef{Label: info.Label, ID: info.ID}, signer.Public()); err != nil {
			appendAudit(db, &audit.Event{
				Actor: cliActor(), Action: audit.ActionKeyImport, TargetName: *label,
				Result: audit.ResultError, Detail: "post-import verification failed: " + err.Error(),
			})
			return fmt.Errorf("the key was written to the provider but does not sign correctly — remove it before using it: %w", err)
		}
		verified = true
	}

	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionKeyImport, TargetName: info.Label,
		Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("provider=%s key_type=%s source_format=%s usage=%s verified=%t",
			provider.Name(), info.KeyType, parsed.Format, keyUsage, verified),
	})

	if *jsonOut {
		return emitJSON(map[string]interface{}{
			"label":          info.Label,
			"id":             info.ID,
			"key_type":       info.KeyType,
			"uri":            info.URI,
			"ssh_public_key": info.SSHPublicKey,
			"source_format":  string(parsed.Format),
			"provider":       provider.Name(),
			"verified":       verified,
		})
	}

	fmt.Printf("Imported existing key into the %s key provider:\n", provider.Name())
	fmt.Printf("  Label:     %s\n", info.Label)
	fmt.Printf("  Key type:  %s\n", info.KeyType)
	fmt.Printf("  Read from: %s (%s)\n", keyFlags.keyFile, parsed.Format)
	fmt.Printf("  Reference: %s\n", info.URI)
	if verified {
		fmt.Printf("  Verified:  the provider signed a challenge with it and the signature verified\n")
	}
	printImportProvenanceNotice(provider)
	return nil
}

// cmdCAImport implements `secsy-ca ca import`: adopt an existing CA.
func cmdCAImport(db *database.DB, mgr *ca.Manager, provider keyprovider.Provider, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("ca import", flag.ContinueOnError)
	label := fs.String("label", "", "label / CA name to record the adopted CA under (required)")
	tenant := fs.String("tenant", "", "owning tenant id or slug (default: the built-in default tenant)")
	certFile := fs.String("cert", "", "PEM file with the CA's existing certificate (extra certificates are treated as chain); optional when -key is a PKCS#12 container")
	chainFile := fs.String("chain", "", "PEM file with the issuing chain, when the parent is not in this PKI")
	parentRef := fs.String("parent", "", "id or label of a CA already in this PKI that issued this certificate (default: discovered automatically)")
	existingKey := fs.String("existing-key", "", "adopt a key already in the provider under this label instead of importing one")
	keyFlags := addImportKeyFlags(fs)
	chainOut := fs.String("chain-out", "", "write the combined served chain PEM here")
	jsonOut := fs.Bool("json", false, "emit the adopted CA record and warnings as JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" {
		fs.Usage()
		return fmt.Errorf("-label is required")
	}
	if (keyFlags.keyFile == "") == (*existingKey == "") {
		fs.Usage()
		return fmt.Errorf("supply exactly one of -key (import the key) or -existing-key (adopt a key already in the provider)")
	}

	spec := ca.ImportCASpec{
		TenantID:         *tenant,
		Label:            *label,
		ExistingKeyLabel: *existingKey,
	}

	// A PKCS#12 container carries the certificate alongside the key, so an
	// operator exporting from a Windows CA or a browser has only one file.
	var sourceFormat pki.KeyFileFormat
	if keyFlags.keyFile != "" {
		parsed, err := keyFlags.loadPrivateKey()
		if err != nil {
			return err
		}
		spec.PrivateKey = parsed.Key
		sourceFormat = parsed.Format
		if *certFile == "" {
			if parsed.Certificate == nil {
				return fmt.Errorf("-cert is required (the key file carries no certificate)")
			}
			spec.CertificatePEM = pki.EncodeCertificatePEM(parsed.Certificate.Raw)
			for _, c := range parsed.CACerts {
				spec.ChainPEM = append(spec.ChainPEM, pki.EncodeCertificatePEM(c.Raw)...)
			}
		}
	}
	if *certFile != "" {
		certPEM, err := os.ReadFile(*certFile)
		if err != nil {
			return fmt.Errorf("reading -cert: %w", err)
		}
		spec.CertificatePEM = certPEM
	}
	if *chainFile != "" {
		chainPEM, err := os.ReadFile(*chainFile)
		if err != nil {
			return fmt.Errorf("reading -chain: %w", err)
		}
		spec.ChainPEM = chainPEM
	}
	if *parentRef != "" {
		parentID, err := resolveCA(db, *parentRef)
		if err != nil {
			return err
		}
		spec.ParentID = parentID
	}

	// Adopting a CA creates one, so it passes through the same four-eyes gate as
	// init-root and issue-intermediate: an authority that appears in the tree
	// without a second signature is exactly what maker-checker exists to prevent.
	if err := guardCLI(db, cfg, approval.GuardRequest{
		Class:        approval.ClassCACreate,
		ResourceKey:  "ca-label:" + *label,
		ResourceName: *label,
		Summary:      "Adopt existing CA " + *label,
		Params:       fmt.Sprintf("label=%s;tenant=%s;cert=%s;key=%s", *label, *tenant, *certFile, keyFlags.keyFile),
		Tenant:       *tenant,
	}); err != nil {
		return err
	}

	result, err := mgr.ImportCA(context.Background(), spec)
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: cliActor(), Action: audit.ActionCAImport, TargetName: *label,
			Result: audit.ResultError, Detail: err.Error(),
		})
		return err
	}

	detail := fmt.Sprintf("subject=%s serial=%s self_signed=%t key_imported=%t key_fingerprint=%s source_format=%s",
		result.CA.Subject, result.CA.Serial, result.SelfSigned, result.KeyImported, result.KeyFingerprint, sourceFormat)
	if len(result.Warnings) > 0 {
		detail += " warnings=" + strings.Join(result.Warnings, "; ")
	}
	appendAudit(db, &audit.Event{
		Actor: cliActor(), Action: audit.ActionCAImport, Target: result.CA.ID, TargetName: result.CA.Label,
		Result: audit.ResultSuccess, Detail: detail,
	})

	if *chainOut != "" {
		if err := os.WriteFile(*chainOut, result.ChainPEM, 0o644); err != nil {
			return fmt.Errorf("writing -chain-out: %w", err)
		}
	}

	if *jsonOut {
		return emitJSON(map[string]interface{}{
			"ca":              result.CA,
			"warnings":        result.Warnings,
			"chain_pem":       string(result.ChainPEM),
			"key_imported":    result.KeyImported,
			"key_fingerprint": result.KeyFingerprint,
			"self_signed":     result.SelfSigned,
		})
	}

	kind := "subordinate CA"
	if result.SelfSigned {
		kind = "root CA"
	}
	fmt.Printf("Adopted existing %s %q:\n", kind, result.CA.Label)
	fmt.Printf("  ID:        %s\n", result.CA.ID)
	fmt.Printf("  Subject:   %s\n", result.CA.Subject)
	fmt.Printf("  Serial:    %s\n", result.CA.Serial)
	if result.CA.NotBefore != nil && result.CA.NotAfter != nil {
		fmt.Printf("  Validity:  %s — %s\n", result.CA.NotBefore.Format(time.RFC3339), result.CA.NotAfter.Format(time.RFC3339))
	}
	fmt.Printf("  Key:       %s (%s)\n", result.CA.PKCS11URI, result.CA.KeyType)
	if result.KeyImported {
		fmt.Printf("  Imported:  key material read from %s (%s) and written into the provider\n", keyFlags.keyFile, sourceFormat)
	} else {
		fmt.Printf("  Adopted:   the key already present in the provider as %q\n", *existingKey)
	}
	fmt.Printf("  Verified:  the provider signed a challenge with the key and it matches the certificate\n")
	if result.CA.ParentID != nil {
		fmt.Printf("  Parent:    %s (in this PKI)\n", *result.CA.ParentID)
	} else if result.CA.ExternalChain != "" {
		fmt.Printf("  Parent:    external; the imported chain is served via /api/ca/%s/chain\n", result.CA.ID)
	}
	for _, w := range result.Warnings {
		fmt.Printf("  WARNING:   %s\n", w)
	}
	if result.KeyImported {
		printImportProvenanceNotice(provider)
		fmt.Printf("\nNext: destroy every remaining copy of %s once this CA has been exercised.\n", keyFlags.keyFile)
	}
	return nil
}

// printImportProvenanceNotice states the one thing an import cannot give the
// operator, so nobody concludes from a successful command that the key is now
// as trustworthy as one born on the device.
func printImportProvenanceNotice(provider keyprovider.Provider) {
	fmt.Fprintf(os.Stderr, "\nNote: an imported key existed outside the provider before it arrived. It is now stored\n"+
		"      with the same protections as a generated key (non-extractable, sensitive), but its\n"+
		"      origin cannot be undone: hardware key attestation will report it as imported rather\n"+
		"      than generated, and any copy made before the import remains a copy. See\n"+
		"      docs/hsm/key-attestation.md and docs/ca/import.md.\n")
	if provider.Name() == string(keyprovider.ProviderSoftware) {
		fmt.Fprintf(os.Stderr, "      The software keystore stores keys as files: this import moved the key, it did not\n"+
			"      protect it. Configure a PKCS#11 backend for production CA keys.\n")
	}
}
