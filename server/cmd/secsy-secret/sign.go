package main

// Named HSM-backed asymmetric signing (Task 153): the operator-side counterparts
// to the /api/secret/signing-keys, /sign, and /verify endpoints, run locally
// against the key provider and the shared database rather than the server. They
// mirror the other crypto-service commands (crypto.go): self-contained, a plain
// -json flag (deliberately cliout-free per the crypto-service convention), and
// the private key never leaving the provider/HSM.
//
//	secsy-secret signing-key create -name app-signer -algorithm ecdsa-p256
//	secsy-secret signing-key list
//	secsy-secret signing-key public -name app-signer -out app-signer.pub.pem
//	echo -n hello | secsy-secret sign   -key app-signer -out sig.bin
//	echo -n hello | secsy-secret verify -key app-signer -sig-in sig.bin
//
// The exported public key (signing-key public) verifies with external tools, e.g.
//	openssl dgst -sha256 -verify app-signer.pub.pem -signature sig.bin message.bin

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// cmdSigningKey dispatches the signing-key management sub-verbs (create/list/
// public). Keeping them under one command mirrors how the feature reads: a signing
// key is a first-class named resource.
func cmdSigningKey(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secsy-secret signing-key <create|list|public> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdSigningKeyCreate(cfg, provider, rest)
	case "list", "ls":
		return cmdSigningKeyList(cfg, provider, rest)
	case "public", "public-key", "pub":
		return cmdSigningKeyPublic(cfg, provider, rest)
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stderr, "signing-key sub-commands: create, list, public")
		return nil
	default:
		return fmt.Errorf("unknown signing-key sub-command %q (want create|list|public)", sub)
	}
}

// cmdSigningKeyCreate generates a named signing key on the provider (the private
// key stays non-extractable in the HSM) and persists its metadata.
func cmdSigningKeyCreate(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("signing-key create", flag.ContinueOnError)
	name := fs.String("name", "", "tenant-unique name for the signing key (required)")
	algorithm := fs.String("algorithm", string(secret.AlgECDSAP256), "signing algorithm: "+algorithmList())
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	out := fs.String("out", "", "also write the exported public key (SPKI PEM) here")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	alg, err := secret.NormalizeSigningAlgorithm(*algorithm)
	if err != nil {
		return err
	}

	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	row, err := secret.CreateSigningKey(context.Background(), provider, db, secret.CreateSigningKeySpec{
		TenantID:  *tenant,
		Name:      *name,
		Algorithm: alg,
		CreatedBy: operatorActor(*operator),
	})
	if err != nil {
		return err
	}
	if err := recordEscrowEvent(db, operatorActor(*operator), audit.ActionSecretSigningKeyCreate, *name, audit.ResultSuccess,
		fmt.Sprintf("algorithm=%s key_type=%s id=%s tenant=%s", row.Algorithm, row.KeyType, row.ID, row.TenantID)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: signing key created but recording the audit event failed: %v\n", err)
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
			"public_key_pem": string(pemBytes),
			"public_key_der": base64.StdEncoding.EncodeToString(der),
		})
	}
	fmt.Fprintf(os.Stderr, "Signing key %q created (id %s, algorithm %s, provider %s).\n", row.Name, row.ID, row.Algorithm, row.Provider)
	if *out != "" {
		fmt.Fprintf(os.Stderr, "Public key written to %s.\n", *out)
	} else {
		_, _ = os.Stdout.Write(pemBytes)
	}
	return nil
}

// cmdSigningKeyList prints the tenant's signing keys (metadata only).
func cmdSigningKeyList(cfg *config.Config, _ keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("signing-key list", flag.ContinueOnError)
	tenant := fs.String("tenant", models.DefaultTenantID, "tenant whose keys to list")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON array")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	rows, err := db.ListSigningKeys(*tenant)
	if err != nil {
		return err
	}
	if *jsonOut {
		out := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			out = append(out, map[string]any{
				"id": r.ID, "name": r.Name, "algorithm": r.Algorithm,
				"key_type": r.KeyType, "provider": r.Provider, "created_at": r.CreatedAt,
			})
		}
		return emitCryptoJSON(out)
	}
	if len(rows) == 0 {
		fmt.Println("No signing keys for this tenant.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tALGORITHM\tPROVIDER\tID\tCREATED")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Algorithm, r.Provider, r.ID, r.CreatedAt.Format("2006-01-02"))
	}
	return tw.Flush()
}

// cmdSigningKeyPublic exports a signing key's public half as SPKI PEM (or DER
// with -der), the form external verifiers consume.
func cmdSigningKeyPublic(cfg *config.Config, _ keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("signing-key public", flag.ContinueOnError)
	name := fs.String("name", "", "signing key name (required)")
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant")
	out := fs.String("out", "-", "output file, or '-' for stdout")
	der := fs.Bool("der", false, "emit raw DER instead of PEM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	row, err := loadSigningKey(cfg, *tenant, *name)
	if err != nil {
		return err
	}
	var data []byte
	if *der {
		if data, err = secret.PublicKeyDER(row); err != nil {
			return err
		}
	} else {
		if data, err = secret.PublicKeyPEM(row); err != nil {
			return err
		}
	}
	return writeOutput(*out, data)
}

// cmdSign signs stdin/a file with a named signing key. With -prehashed the input
// is treated as a pre-computed digest of the selected -hash rather than a message.
func cmdSign(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	key := fs.String("key", "", "signing key name (required)")
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant")
	in := fs.String("in", "-", "input message (or pre-hashed digest) file, or '-' for stdin")
	hash := fs.String("hash", "", "message hash: sha256|sha384|sha512 (default: the algorithm's)")
	preHashed := fs.Bool("prehashed", false, "the input is already a digest of -hash, sign it verbatim")
	out := fs.String("out", "-", "output signature file (raw bytes), or '-' for stdout (base64)")
	operator := fs.String("operator", "", "operator identity recorded in the audit event (default: OS user)")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return fmt.Errorf("-key is required")
	}
	data, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("input data is required")
	}

	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	row, err := db.GetSigningKey(*tenant, *key)
	if err != nil {
		return err
	}
	if row == nil {
		return fmt.Errorf("no signing key named %q for tenant %q", *key, *tenant)
	}

	res, err := secret.Sign(context.Background(), provider, row, data, *hash, *preHashed)
	if err != nil {
		return err
	}
	if err := recordEscrowEvent(db, operatorActor(*operator), audit.ActionSecretSign, *key, audit.ResultSuccess,
		fmt.Sprintf("algorithm=%s hash=%s prehashed=%v id=%s", res.Algorithm, secret.HashName(res.Hash), *preHashed, row.ID)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: signed but recording the audit event failed: %v\n", err)
	}

	if *jsonOut {
		return emitCryptoJSON(map[string]any{
			"signature": base64.StdEncoding.EncodeToString(res.Signature),
			"algorithm": string(res.Algorithm),
			"hash":      secret.HashName(res.Hash),
			"key":       *key,
		})
	}
	// To a file: raw signature bytes (ready for `openssl dgst -verify`). To stdout:
	// base64, so a terminal is not flooded with binary.
	fmt.Fprintf(os.Stderr, "Signed with %q (%s, hash %s).\n", *key, res.Algorithm, secret.HashName(res.Hash))
	if *out == "-" || *out == "" {
		fmt.Println(base64.StdEncoding.EncodeToString(res.Signature))
		return nil
	}
	return writeOutput(*out, res.Signature)
}

// cmdVerify verifies a signature over stdin/a file against a signing key's public
// half. The key is either a stored named key (-key, read from the database) or a
// caller-supplied public key file (-public-key + -algorithm, no database) — the
// latter validates a signature from a key this service does not manage. It exits
// non-zero when the signature does not verify, so scripts can branch on $?.
// Verification uses only public material — no HSM needed.
func cmdVerify(cfg *config.Config, _ keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	key := fs.String("key", "", "stored signing key name (or use -public-key)")
	pubKeyFile := fs.String("public-key", "", "verify against this SPKI public-key file (PEM or DER) instead of a stored key; needs -algorithm")
	algorithm := fs.String("algorithm", "", "signing algorithm of -public-key (required with -public-key): "+algorithmList())
	tenant := fs.String("tenant", models.DefaultTenantID, "owning tenant (for -key)")
	in := fs.String("in", "-", "input message (or pre-hashed digest) file, or '-' for stdin")
	sigB64 := fs.String("signature", "", "base64 signature to verify (or use -sig-in)")
	sigIn := fs.String("sig-in", "", "file containing the raw signature bytes to verify")
	hash := fs.String("hash", "", "message hash: sha256|sha384|sha512 (default: the algorithm's)")
	preHashed := fs.Bool("prehashed", false, "the input is already a digest of -hash")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	suppliedKey := *pubKeyFile != ""
	switch {
	case suppliedKey && *key != "":
		return fmt.Errorf("set either -key (stored key) or -public-key (supplied key), not both")
	case suppliedKey && *algorithm == "":
		return fmt.Errorf("-algorithm is required with -public-key")
	case !suppliedKey && *key == "":
		return fmt.Errorf("-key or -public-key is required")
	}
	if (*sigB64 == "") == (*sigIn == "") {
		return fmt.Errorf("set exactly one of -signature or -sig-in")
	}
	var sig []byte
	var err error
	if *sigIn != "" {
		if sig, err = os.ReadFile(*sigIn); err != nil {
			return fmt.Errorf("reading -sig-in: %w", err)
		}
	} else {
		if sig, err = base64.StdEncoding.DecodeString(*sigB64); err != nil {
			return fmt.Errorf("-signature must be base64: %w", err)
		}
	}
	data, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var (
		valid    bool
		algLabel string // the algorithm reported back
		keyLabel string // how the key is named in output
	)
	if suppliedKey {
		pubBytes, rerr := os.ReadFile(*pubKeyFile)
		if rerr != nil {
			return fmt.Errorf("reading -public-key: %w", rerr)
		}
		alg, nerr := secret.NormalizeSigningAlgorithm(*algorithm)
		if nerr != nil {
			return nerr
		}
		pub, perr := secret.ParsePublicKey(pubBytes)
		if perr != nil {
			return perr
		}
		if valid, err = secret.VerifyWithPublicKey(alg, pub, data, sig, *hash, *preHashed); err != nil {
			return err
		}
		algLabel, keyLabel = string(alg), *pubKeyFile
	} else {
		row, lerr := loadSigningKey(cfg, *tenant, *key)
		if lerr != nil {
			return lerr
		}
		if valid, err = secret.Verify(row, data, sig, *hash, *preHashed); err != nil {
			return err
		}
		algLabel, keyLabel = row.Algorithm, *key
	}

	if *jsonOut {
		if err := emitCryptoJSON(map[string]any{"valid": valid, "key": keyLabel, "algorithm": algLabel}); err != nil {
			return err
		}
	} else if valid {
		fmt.Printf("OK: signature verified with %q (%s)\n", keyLabel, algLabel)
	} else {
		fmt.Fprintln(os.Stderr, "FAILED: signature did not verify")
	}
	if !valid {
		return exitCodeError{code: 1}
	}
	return nil
}

// loadSigningKey opens the database and fetches one signing-key row, closing the
// database before returning (verify/public-key export need only the stored row).
func loadSigningKey(cfg *config.Config, tenant, name string) (*models.SigningKey, error) {
	db, err := openAuditDB(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	row, err := db.GetSigningKey(tenant, name)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("no signing key named %q for tenant %q", name, tenant)
	}
	return row, nil
}

// algorithmList renders the supported signing algorithms for flag help.
func algorithmList() string {
	algs := secret.SupportedSigningAlgorithms()
	s := ""
	for i, a := range algs {
		if i > 0 {
			s += "|"
		}
		s += a
	}
	return s
}
