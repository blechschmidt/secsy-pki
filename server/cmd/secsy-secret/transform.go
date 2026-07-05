package main

// Format-preserving-encryption / tokenization CLI (Task 144): the operator-side
// counterpart to /api/secret/transform/{encode,decode}, run locally against the
// key provider and the shared database (for the FPE seed) rather than the server.
// A named transform template from config selects the alphabet, length window, and
// determinism/tweak policy; the FF1 key is HKDF-derived from a seed sealed under
// the family KEK, exactly as the server does it. Kept cliout-free (a plain -json
// flag) like the rest of the secsy-secret crypto commands.

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// cmdTransform dispatches the transform sub-subcommands (encode|decode).
func cmdTransform(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secsy-secret transform <encode|decode> -template NAME [-value V | -in FILE] [-tweak B64] [-json]")
	}
	sub, subArgs := args[0], args[1:]
	switch sub {
	case "encode":
		return runTransform(cfg, provider, subArgs, true)
	case "decode":
		return runTransform(cfg, provider, subArgs, false)
	default:
		return fmt.Errorf("unknown transform subcommand %q (want encode or decode)", sub)
	}
}

// runTransform encodes (encode=true) or decodes a single value through a named
// FF1 transform template. The value comes from -value (inline) or -in (a file or
// stdin, with a single trailing newline stripped so a piped value works cleanly).
func runTransform(cfg *config.Config, provider keyprovider.Provider, args []string, encode bool) error {
	op := "decode"
	if encode {
		op = "encode"
	}
	fs := flag.NewFlagSet("transform "+op, flag.ContinueOnError)
	template := fs.String("template", "", "transform template name from secret.transforms (required)")
	label := fs.String("kek", "", "explicit KEK label override (default: secret.kek_label from config)")
	value := fs.String("value", "", "the value to "+op+" (plaintext for encode, token for decode)")
	in := fs.String("in", "", "read the value from this file, or '-' for stdin (alternative to -value)")
	tweakB64 := fs.String("tweak", "", "base64 per-request tweak (required for a request-tweak template, forbidden for a deterministic one)")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *template == "" {
		return fmt.Errorf("-template is required")
	}

	val, err := transformInput(*value, *in)
	if err != nil {
		return err
	}
	if val == "" {
		return fmt.Errorf("a value is required (pass -value or -in)")
	}
	var tweak []byte
	if *tweakB64 != "" {
		if tweak, err = base64.StdEncoding.DecodeString(*tweakB64); err != nil {
			return fmt.Errorf("-tweak must be base64: %w", err)
		}
	}

	tmpl, err := cfg.Secret.TransformByName(*template)
	if err != nil {
		return err
	}
	family, err := resolveKEK(cfg, *label)
	if err != nil {
		return err
	}

	ring, db, err := openRing(cfg, provider, family)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	seedRow, err := secret.EnsureFPESeed(ctx, db, ring, family,
		func(n int) ([]byte, error) { b, _, e := cliRandomBytes(provider, n); return b, e })
	if err != nil {
		return err
	}
	transformer, err := secret.NewTransformer(ctx, ring, seedRow, tmpl)
	if err != nil {
		return err
	}

	var result string
	if encode {
		result, err = transformer.Encode(val, tweak)
	} else {
		result, err = transformer.Decode(val, tweak)
	}
	if err != nil {
		return err
	}

	if *jsonOut {
		return emitCryptoJSON(map[string]any{
			"template":      *template,
			"result":        result,
			"deterministic": tmpl.Deterministic,
		})
	}
	fmt.Println(result)
	fmt.Fprintf(os.Stderr, "template %q (%s, radix %d)%s\n", *template, op, tmpl.Alphabet.Radix(),
		map[bool]string{true: ", deterministic", false: ""}[tmpl.Deterministic])
	return nil
}

// transformInput resolves the value from the inline -value flag or, when that is
// empty, from -in (a file or stdin), stripping a single trailing newline so a
// piped value round-trips cleanly.
func transformInput(value, in string) (string, error) {
	if value != "" {
		return value, nil
	}
	if in == "" {
		return "", nil
	}
	raw, err := readInput(in)
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimSuffix(string(raw), "\n"), nil
}
