package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/delegatedcred"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// cmdDelegatedCredential mints or verifies an RFC 9345 TLS Delegated Credential.
//
// Minting a delegated credential requires the end-entity certificate's PRIVATE
// key, because the credential is signed by it — not by any CA or HSM key. This CA
// never holds subscriber leaf keys for ordinary CSR-based issuance, so this CLI
// helper takes the leaf certificate and its key from the operator's files
// (`-cert`/`-key`). It is the offline, operator-holds-the-leaf-key path; the
// server-side POST /api/ca/{id}/delegated-credential can instead recover a leaf
// key escrowed from a PKCS#12 export (Task 33). See docs/certificates/delegated-credentials.md.
func cmdDelegatedCredential(args []string) error {
	if len(args) == 0 {
		delegatedCredentialUsage()
		return fmt.Errorf("a subcommand is required: mint | verify")
	}
	switch args[0] {
	case "mint":
		return cmdDelegatedCredentialMint(args[1:])
	case "verify":
		return cmdDelegatedCredentialVerify(args[1:])
	case "help", "-h", "--help":
		delegatedCredentialUsage()
		return nil
	default:
		delegatedCredentialUsage()
		return fmt.Errorf("unknown delegated-credential subcommand %q", args[0])
	}
}

func delegatedCredentialUsage() {
	fmt.Fprint(os.Stderr, `usage: secsy-ca delegated-credential <subcommand> [flags]

Subcommands:
  mint     Construct and sign an RFC 9345 delegated credential with an
           end-entity certificate's private key (which the operator holds).
  verify   Verify a delegated credential against its end-entity certificate.
`)
}

// emitDCJSON writes v as indented JSON on stdout (the stable machine-readable
// contract for scripting), matching the encoding used elsewhere in the CLI.
func emitDCJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// delegatedCredentialResult is the JSON shape emitted by `mint`.
type delegatedCredentialResult struct {
	DelegatedCredentialHex    string `json:"delegated_credential_hex"`
	DelegatedCredentialBase64 string `json:"delegated_credential_base64"`
	ValidTimeSeconds          uint32 `json:"valid_time_seconds"`
	NotBefore                 string `json:"not_before"`
	NotAfter                  string `json:"not_after"`
	Endpoint                  string `json:"endpoint"`
	Algorithm                 string `json:"algorithm"`
	ExpectedCertVerifyAlg     string `json:"expected_cert_verify_algorithm"`
	DCKeyType                 string `json:"dc_key_type,omitempty"`
	DCPublicKeyPEM            string `json:"dc_public_key_pem,omitempty"`
	DCPrivateKeyFile          string `json:"dc_private_key_file,omitempty"`
	WireFile                  string `json:"wire_file,omitempty"`
}

func cmdDelegatedCredentialMint(args []string) error {
	fs := flag.NewFlagSet("delegated-credential mint", flag.ContinueOnError)
	certFile := fs.String("cert", "", "end-entity certificate PEM file (must be DelegationUsage-eligible) (required)")
	keyFile := fs.String("key", "", "end-entity private key PEM file (the operator holds this) (required)")
	validFor := fs.Duration("valid-for", 24*time.Hour, "credential lifetime from now (RFC 9345 caps the wire valid_time at 7 days from the certificate notBefore)")
	dcPubFile := fs.String("dc-pub", "", "delegated public-key SPKI PEM file; if set, no key is generated and the operator keeps the delegated private key")
	dcKeyType := fs.String("dc-key-type", "ecdsa-p256", "type of delegated key to generate when -dc-pub is unset: ecdsa-p256|ecdsa-p384|ecdsa-p521|rsa-2048|rsa-3072|ed25519")
	dcKeyOut := fs.String("dc-key-out", "", "write the generated delegated private key (PKCS#8 PEM) here (required when generating)")
	dcAlg := fs.String("dc-alg", "", "expected_cert_verify_algorithm override (TLS scheme name, e.g. ecdsa_secp256r1_sha256); default derived from the delegated key")
	signAlg := fs.String("sign-alg", "", "signing algorithm override (TLS scheme name); default derived from the leaf key (RSA uses RSASSA-PSS)")
	client := fs.Bool("client", false, "mint a client delegated credential (default is a server credential)")
	out := fs.String("out", "", "write the raw wire delegated credential to this file")
	asJSON := fs.Bool("json", false, "emit the result as machine-readable JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" {
		fs.Usage()
		return fmt.Errorf("-cert and -key are required")
	}

	// Load the end-entity certificate and its private key from the operator's files.
	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("reading -cert: %w", err)
	}
	leafCert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		return fmt.Errorf("parsing -cert: %w", err)
	}
	keyPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("reading -key: %w", err)
	}
	leafKey, err := delegatedcred.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("parsing -key: %w", err)
	}

	// Resolve the delegated public key: use the supplied SPKI, or generate a fresh
	// keypair and persist its private half.
	var (
		dcPub        crypto.PublicKey
		generatedKey crypto.Signer
		keyTypeUsed  string
	)
	switch {
	case *dcPubFile != "":
		dcPub, err = readPublicKeyPEM(*dcPubFile)
		if err != nil {
			return fmt.Errorf("parsing -dc-pub: %w", err)
		}
	default:
		if *dcKeyOut == "" {
			fs.Usage()
			return fmt.Errorf("-dc-key-out is required when generating a delegated key (omit it only with -dc-pub)")
		}
		generatedKey, err = delegatedcred.GenerateKey(*dcKeyType)
		if err != nil {
			return err
		}
		dcPub = generatedKey.Public()
		keyTypeUsed = *dcKeyType
	}

	// Resolve optional scheme overrides.
	var algorithm, expected delegatedcred.SignatureScheme
	if *signAlg != "" {
		if algorithm, err = delegatedcred.SchemeFromName(*signAlg); err != nil {
			return fmt.Errorf("-sign-alg: %w", err)
		}
	}
	if *dcAlg != "" {
		if expected, err = delegatedcred.SchemeFromName(*dcAlg); err != nil {
			return fmt.Errorf("-dc-alg: %w", err)
		}
	}

	endpoint := delegatedcred.ServerEndpoint
	if *client {
		endpoint = delegatedcred.ClientEndpoint
	}

	res, err := delegatedcred.Mint(delegatedcred.MintRequest{
		LeafCert:                    leafCert,
		LeafKey:                     leafKey,
		DCPublicKey:                 dcPub,
		ValidFor:                    *validFor,
		Endpoint:                    endpoint,
		Algorithm:                   algorithm,
		ExpectedCertVerifyAlgorithm: expected,
	})
	if err != nil {
		return err
	}

	// Persist the generated delegated private key and the wire credential.
	if generatedKey != nil {
		pkcs8, err := x509.MarshalPKCS8PrivateKey(generatedKey)
		if err != nil {
			return fmt.Errorf("encoding delegated private key: %w", err)
		}
		keyPEMOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		if err := os.WriteFile(*dcKeyOut, keyPEMOut, 0o600); err != nil {
			return fmt.Errorf("writing -dc-key-out: %w", err)
		}
	}
	if *out != "" {
		if err := os.WriteFile(*out, res.Wire, 0o644); err != nil {
			return fmt.Errorf("writing -out: %w", err)
		}
	}

	spkiPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: res.DelegatedCredential.SubjectPublicKeyInfo()})
	endpointName := "server"
	if *client {
		endpointName = "client"
	}
	dcPrivateKeyFile := ""
	if generatedKey != nil {
		dcPrivateKeyFile = *dcKeyOut
	}
	result := delegatedCredentialResult{
		DelegatedCredentialHex:    hex.EncodeToString(res.Wire),
		DelegatedCredentialBase64: base64.StdEncoding.EncodeToString(res.Wire),
		ValidTimeSeconds:          res.ValidTime,
		NotBefore:                 leafCert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:                  res.NotAfter.UTC().Format(time.RFC3339),
		Endpoint:                  endpointName,
		Algorithm:                 res.Algorithm.String(),
		ExpectedCertVerifyAlg:     res.ExpectedCertVerifyAlgorithm.String(),
		DCKeyType:                 keyTypeUsed,
		DCPublicKeyPEM:            string(spkiPEM),
		DCPrivateKeyFile:          dcPrivateKeyFile,
		WireFile:                  *out,
	}
	if *asJSON {
		return emitDCJSON(result)
	}

	fmt.Printf("Minted %s delegated credential\n", endpointName)
	fmt.Printf("  Signing algorithm:      %s\n", result.Algorithm)
	fmt.Printf("  Delegated key scheme:   %s\n", result.ExpectedCertVerifyAlg)
	fmt.Printf("  valid_time:             %d s\n", result.ValidTimeSeconds)
	fmt.Printf("  Not after:              %s\n", result.NotAfter)
	if keyTypeUsed != "" {
		fmt.Printf("  Delegated private key:  %s (%s)\n", *dcKeyOut, keyTypeUsed)
	}
	if *out != "" {
		fmt.Printf("  Wire credential:        %s\n", *out)
	}
	fmt.Printf("  Delegated credential (base64):\n    %s\n", result.DelegatedCredentialBase64)
	return nil
}

func cmdDelegatedCredentialVerify(args []string) error {
	fs := flag.NewFlagSet("delegated-credential verify", flag.ContinueOnError)
	certFile := fs.String("cert", "", "end-entity certificate PEM file (required)")
	dcFile := fs.String("dc", "", "raw wire delegated credential file (as written by `mint -out`) (required)")
	client := fs.Bool("client", false, "verify as a client delegated credential (default server)")
	asJSON := fs.Bool("json", false, "emit the result as machine-readable JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certFile == "" || *dcFile == "" {
		fs.Usage()
		return fmt.Errorf("-cert and -dc are required")
	}
	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("reading -cert: %w", err)
	}
	leafCert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		return fmt.Errorf("parsing -cert: %w", err)
	}
	wire, err := os.ReadFile(*dcFile)
	if err != nil {
		return fmt.Errorf("reading -dc: %w", err)
	}
	dc, err := delegatedcred.Parse(wire)
	if err != nil {
		return fmt.Errorf("parsing delegated credential: %w", err)
	}
	endpoint := delegatedcred.ServerEndpoint
	endpointName := "server"
	if *client {
		endpoint = delegatedcred.ClientEndpoint
		endpointName = "client"
	}
	if err := dc.Verify(leafCert, endpoint); err != nil {
		return err
	}
	notAfter := leafCert.NotBefore.Add(time.Duration(dc.Cred.ValidTime) * time.Second)
	validNow := dc.ValidAt(leafCert, time.Now())
	if *asJSON {
		return emitDCJSON(map[string]any{
			"valid":                          true,
			"endpoint":                       endpointName,
			"valid_time_seconds":             dc.Cred.ValidTime,
			"not_after":                      notAfter.UTC().Format(time.RFC3339),
			"currently_within_window":        validNow,
			"algorithm":                      dc.Algorithm.String(),
			"expected_cert_verify_algorithm": dc.Cred.ExpectedCertVerifyAlgorithm.String(),
		})
	}
	fmt.Printf("Delegated credential is VALID (%s)\n", endpointName)
	fmt.Printf("  Signing algorithm:      %s\n", dc.Algorithm)
	fmt.Printf("  Delegated key scheme:   %s\n", dc.Cred.ExpectedCertVerifyAlgorithm)
	fmt.Printf("  valid_time:             %d s\n", dc.Cred.ValidTime)
	fmt.Printf("  Not after:              %s\n", notAfter.UTC().Format(time.RFC3339))
	fmt.Printf("  Currently in window:    %t\n", validNow)
	return nil
}

// readPublicKeyPEM parses a PEM-encoded SubjectPublicKeyInfo public key.
func readPublicKeyPEM(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
