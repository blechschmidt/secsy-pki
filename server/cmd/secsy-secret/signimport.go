package main

// `secsy-secret signing-key import` — adopt an existing application signing key
// (Task 194).
//
// The counterpart to `secsy-ca ca import` on the secret layer: a key whose
// public half is already embedded in shipped clients cannot be rotated cheaply,
// but it can be moved off the application server and into the HSM. Like the CA
// command this is deliberately CLI-only — the input is raw private key material
// and it is read once, from a local path.

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// keyPassphraseEnv names the environment variable consulted for a key file's
// passphrase, matching secsy-ca's import commands.
const keyPassphraseEnv = "SECSY_KEY_PASSPHRASE"

// cmdSigningKeyImport adopts an existing private key as a named signing key.
func cmdSigningKeyImport(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("signing-key import", flag.ContinueOnError)
	name := fs.String("name", "", "tenant-unique name for the signing key (required)")
	keyFile := fs.String("key", "", "file holding the existing private key: PEM (PKCS#8, PKCS#1, SEC1, encrypted PKCS#8, OpenSSH), bare DER, or PKCS#12 (required)")
	passFile := fs.String("pass-file", "", "file holding the key's passphrase (\"-\" reads stdin); defaults to the "+keyPassphraseEnv+" environment variable")
	algorithm := fs.String("algorithm", "", "signing algorithm; required for RSA keys (pss vs pkcs1v15), derived from the key otherwise: "+algorithmList())
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	out := fs.String("out", "", "also write the exported public key (SPKI PEM) here")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *keyFile == "" {
		return fmt.Errorf("-name and -key are required")
	}
	var alg secret.SigningAlgorithm
	if *algorithm != "" {
		normalized, err := secret.NormalizeSigningAlgorithm(*algorithm)
		if err != nil {
			return err
		}
		alg = normalized
	}

	parsed, err := loadImportKeyFile(*keyFile, *passFile)
	if err != nil {
		return err
	}

	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	row, err := secret.ImportSigningKey(context.Background(), provider, db, secret.ImportSigningKeySpec{
		TenantID:   *tenant,
		Name:       *name,
		PrivateKey: parsed.Key,
		Algorithm:  alg,
		CreatedBy:  operatorActor(*operator),
	})
	if err != nil {
		return err
	}
	if err := recordEscrowEvent(db, operatorActor(*operator), audit.ActionSecretSigningKeyImport, *name, audit.ResultSuccess,
		fmt.Sprintf("algorithm=%s key_type=%s id=%s tenant=%s source_format=%s provider=%s",
			row.Algorithm, row.KeyType, row.ID, row.TenantID, parsed.Format, row.Provider)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: signing key imported but recording the audit event failed: %v\n", err)
	}

	pemBytes, err := secret.PublicKeyPEM(row)
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, pemBytes, 0o644); err != nil {
			return fmt.Errorf("writing -out: %w", err)
		}
	}
	if *jsonOut {
		der, _ := secret.PublicKeyDER(row)
		return emitCryptoJSON(map[string]any{
			"id":             row.ID,
			"name":           row.Name,
			"tenant":         row.TenantID,
			"algorithm":      row.Algorithm,
			"key_type":       row.KeyType,
			"provider":       row.Provider,
			"imported":       true,
			"source_format":  string(parsed.Format),
			"public_key_pem": string(pemBytes),
			"public_key_der": base64.StdEncoding.EncodeToString(der),
		})
	}
	fmt.Fprintf(os.Stderr, "Signing key %q imported (id %s, algorithm %s, provider %s, read from %s as %s).\n",
		row.Name, row.ID, row.Algorithm, row.Provider, *keyFile, parsed.Format)
	fmt.Fprintf(os.Stderr, "The provider signed a challenge with the key and the signature verified.\n")
	fmt.Fprintf(os.Stderr, "Note: this key existed outside the provider before it arrived; hardware attestation will\n"+
		"      report it as imported. Destroy the remaining copies of %s.\n", *keyFile)
	if *out != "" {
		fmt.Fprintf(os.Stderr, "Public key written to %s.\n", *out)
	} else {
		_, _ = os.Stdout.Write(pemBytes)
	}
	return nil
}

// loadImportKeyFile reads and decodes an operator-supplied key file, turning the
// encrypted-container cases into advice rather than a parse error.
func loadImportKeyFile(keyFile, passFile string) (*pki.ParsedPrivateKey, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading -key: %w", err)
	}
	var pass []byte
	switch {
	case passFile == "-":
		pass, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading the passphrase from stdin: %w", err)
		}
	case passFile != "":
		pass, err = os.ReadFile(passFile)
		if err != nil {
			return nil, fmt.Errorf("reading -pass-file: %w", err)
		}
	default:
		pass = []byte(os.Getenv(keyPassphraseEnv))
	}
	pass = []byte(strings.TrimRight(string(pass), "\r\n"))

	parsed, err := pki.ParsePrivateKey(data, pass)
	switch {
	case err == nil:
		return parsed, nil
	case strings.Contains(err.Error(), pki.ErrPassphraseRequired.Error()):
		return nil, fmt.Errorf("%s is encrypted: supply the passphrase with -pass-file <file> or the %s environment variable", keyFile, keyPassphraseEnv)
	case strings.Contains(err.Error(), pki.ErrWrongPassphrase.Error()):
		return nil, fmt.Errorf("the passphrase for %s is incorrect", keyFile)
	default:
		return nil, err
	}
}
