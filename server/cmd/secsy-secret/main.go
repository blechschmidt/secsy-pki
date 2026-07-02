// Command secsy-secret is an administrative CLI for HSM-backed envelope
// encryption of passwords and other small secrets. It shares the same config
// file and key provider as the server.
//
// A key-encryption key (KEK) — an RSA key whose private half lives in the HSM
// (via PKCS#11) or the software keystore — wraps a fresh per-message data key.
// The plaintext is sealed with AES-256-GCM under that data key. The resulting
// versioned, self-describing JSON envelope can be stored anywhere; decrypting
// it requires access to the KEK (i.e. the HSM).
//
// Usage:
//
//	secsy-secret [-config config.yaml] <command> [flags]
//
// Commands:
//
//	init-kek   Generate the RSA key-encryption key on the configured provider
//	encrypt    Encrypt stdin/a file into a ciphertext envelope
//	decrypt    Decrypt a ciphertext envelope back to plaintext
//	kek-info   Show metadata about the configured KEK
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Usage = usage
	flag.CommandLine.Parse(args)

	rest := flag.Args()
	if len(rest) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	command, cmdArgs := rest[0], rest[1:]

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	provider, err := buildProvider(cfg)
	if err != nil {
		return fmt.Errorf("initializing key provider: %w", err)
	}
	defer provider.Close()

	switch command {
	case "init-kek":
		return cmdInitKEK(cfg, provider, cmdArgs)
	case "encrypt":
		return cmdEncrypt(cfg, provider, cmdArgs)
	case "decrypt":
		return cmdDecrypt(cfg, provider, cmdArgs)
	case "kek-info":
		return cmdKEKInfo(cfg, provider, cmdArgs)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `secsy-secret — HSM-backed envelope encryption for secrets

Usage:
  secsy-secret [-config config.yaml] <command> [flags]

Commands:
  init-kek   Generate the RSA key-encryption key (KEK) on the configured provider
  encrypt    Encrypt stdin or a file into a ciphertext envelope (JSON)
  decrypt    Decrypt a ciphertext envelope back to plaintext
  kek-info   Show metadata about the configured KEK

Run "secsy-secret <command> -h" for command-specific flags.
`)
}

// resolveKEK returns the KEK label from a -kek flag if set, otherwise the
// secret.kek_label from config.
func resolveKEK(cfg *config.Config, flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if cfg.Secret.KEKLabel != "" {
		return cfg.Secret.KEKLabel, nil
	}
	return "", fmt.Errorf("no KEK label configured: set secret.kek_label in config or pass -kek")
}

func cmdInitKEK(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("init-kek", flag.ContinueOnError)
	label := fs.String("kek", "", "KEK label (default: secret.kek_label from config)")
	keyType := fs.String("key-type", "rsa-4096", "RSA key type for the KEK (rsa-2048 or rsa-4096)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kek, err := resolveKEK(cfg, *label)
	if err != nil {
		return err
	}

	svc, err := secret.ProvisionKEK(context.Background(), provider, kek, *keyType)
	if err != nil {
		return err
	}
	info := svc.KEKInfo()
	fmt.Printf("Key-encryption key created:\n")
	printKEK(info)
	fmt.Fprintf(os.Stderr, "\nAdd this to your config so the server and CLI can find it:\n  secret:\n    kek_label: %q\n", info.Label)
	return nil
}

func cmdKEKInfo(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("kek-info", flag.ContinueOnError)
	label := fs.String("kek", "", "KEK label (default: secret.kek_label from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kek, err := resolveKEK(cfg, *label)
	if err != nil {
		return err
	}
	svc, err := secret.NewService(context.Background(), provider, keyprovider.KeyRef{Label: kek})
	if err != nil {
		return err
	}
	printKEK(svc.KEKInfo())
	return nil
}

func cmdEncrypt(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	label := fs.String("kek", "", "KEK label (default: secret.kek_label from config)")
	in := fs.String("in", "-", "input plaintext file, or '-' for stdin")
	out := fs.String("out", "-", "output envelope file, or '-' for stdout")
	context_ := fs.String("context", "", "optional encryption context bound to the ciphertext (required verbatim to decrypt)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kek, err := resolveKEK(cfg, *label)
	if err != nil {
		return err
	}
	svc, err := secret.NewService(context.Background(), provider, keyprovider.KeyRef{Label: kek})
	if err != nil {
		return err
	}

	plaintext, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading plaintext: %w", err)
	}
	defer zero(plaintext)

	blob, err := svc.EncryptToJSON(plaintext, []byte(*context_))
	if err != nil {
		return err
	}
	return writeOutput(*out, append(blob, '\n'))
}

func cmdDecrypt(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	label := fs.String("kek", "", "KEK label (default: secret.kek_label from config)")
	in := fs.String("in", "-", "input envelope file, or '-' for stdin")
	out := fs.String("out", "-", "output plaintext file, or '-' for stdout")
	context_ := fs.String("context", "", "encryption context that was bound at encryption time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kek, err := resolveKEK(cfg, *label)
	if err != nil {
		return err
	}
	svc, err := secret.NewService(context.Background(), provider, keyprovider.KeyRef{Label: kek})
	if err != nil {
		return err
	}

	blob, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading envelope: %w", err)
	}
	plaintext, err := svc.DecryptJSON(blob, []byte(*context_))
	if err != nil {
		return err
	}
	defer zero(plaintext)
	return writeOutput(*out, plaintext)
}

func printKEK(info secret.KEKInfo) {
	fmt.Printf("  Label:    %s\n", info.Label)
	fmt.Printf("  Provider: %s\n", info.Provider)
	fmt.Printf("  Key bits: %d\n", info.KeyBits)
	fmt.Printf("  Wrap alg: %s\n", info.WrapAlg)
	if info.URI != "" {
		fmt.Printf("  URI:      %s\n", info.URI)
	}
}

// buildProvider constructs the configured key provider, mirroring secsy-ca.
func buildProvider(cfg *config.Config) (keyprovider.Provider, error) {
	if cfg.YubiHSM.ConnectorURL != "" && os.Getenv("YUBIHSM_PKCS11_CONF") == "" {
		confPath := "yubihsm_pkcs11.conf"
		if err := os.WriteFile(confPath, []byte("connector = "+cfg.YubiHSM.ConnectorURL+"\n"), 0600); err == nil {
			os.Setenv("YUBIHSM_PKCS11_CONF", confPath)
		}
	}
	return keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderType(cfg.KeyProvider.Type),
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath:        cfg.PKCS11.ModulePath,
			Pin:               cfg.PKCS11.Pin,
			TokenLabel:        cfg.PKCS11.TokenLabel,
			TokenSerial:       cfg.PKCS11.TokenSerial,
			TokenManufacturer: cfg.PKCS11.TokenManufacturer,
		},
		Software: keyprovider.SoftwareSettings{
			KeystoreDir: cfg.KeyProvider.Software.KeystoreDir,
		},
	})
}

func readInput(path string) ([]byte, error) {
	if path == "-" || path == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, data []byte) error {
	if path == "-" || path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	// Envelopes are non-secret, but plaintext output may be sensitive; write
	// with restrictive permissions.
	return os.WriteFile(path, data, 0o600)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
