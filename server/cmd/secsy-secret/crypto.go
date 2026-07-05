package main

// Stateless crypto-service CLI (Task 138): the operator-side counterparts to the
// /api/secret/datakey, /hmac, /hmac/verify, and /random endpoints, run locally
// against the key provider (and, for HMAC, the shared database) rather than the
// server. They mirror the encrypt/decrypt commands: rotation-aware sealing, the
// same -kek override, and a -json machine-readable output mode.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// emitCryptoJSON writes v as stably-indented JSON to stdout. These commands keep
// their own tiny emitter so the crypto-service CLI is self-contained.
func emitCryptoJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// cliRandomBytes draws n random bytes, preferring the provider/HSM RNG and
// falling back to the OS CSPRNG. It returns the bytes and the source label so the
// command can report where the entropy came from, mirroring the server.
func cliRandomBytes(provider keyprovider.Provider, n int) ([]byte, string, error) {
	if rp, ok := provider.(keyprovider.RandomProvider); ok {
		if b, err := rp.Random(context.Background(), n); err == nil && len(b) == n {
			return b, "hsm", nil
		}
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, "", err
	}
	return b, "software", nil
}

// openRing opens the database and builds the family's rotation-aware Ring,
// returning both so the caller (HMAC commands, which also need the MAC-key
// store) can reuse the one open handle. The caller must Close the database.
func openRing(cfg *config.Config, provider keyprovider.Provider, family string) (*secret.Ring, *database.DB, error) {
	db, err := openAuditDB(cfg)
	if err != nil {
		return nil, nil, err
	}
	versions, err := db.ListKEKVersions(family)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("reading KEK rotation state: %w", err)
	}
	ring, err := ringForFamily(cfg, db, provider, family, versions)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return ring, db, nil
}

// cmdDataKey mints a fresh data key and returns it BOTH in the clear and wrapped
// under the family's active KEK. The wrapped envelope is decryptable with
// `secsy-secret decrypt`, so a client can do high-volume envelope encryption
// locally and recover the key later. No plaintext is stored.
func cmdDataKey(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("datakey", flag.ContinueOnError)
	label := fs.String("kek", "", "explicit KEK label override (default: the family's ACTIVE KEK version)")
	bits := fs.Int("bits", 256, "data-key strength in bits: 128, 256, or 512")
	context_ := fs.String("context", "", "optional encryption context bound to the wrapped form (required verbatim to decrypt)")
	wrappedOnly := fs.Bool("wrapped-only", false, "do not emit the plaintext key, only the wrapped envelope")
	out := fs.String("out", "-", "output file for the wrapped envelope (text mode), or '-' for stdout")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object (plaintext + wrapped)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	nbytes, err := dataKeyByteLen(*bits)
	if err != nil {
		return err
	}

	ring, svc, err := serviceOrRing(cfg, provider, *label)
	if err != nil {
		return err
	}
	var ops envelopeOps = svc
	kekLabel, kekVersion := "", 0
	if ring != nil {
		ops = ring
		info := ring.Active().KEKInfo()
		kekLabel, kekVersion = info.Label, info.Version
	} else {
		info := svc.KEKInfo()
		kekLabel, kekVersion = info.Label, info.Version
	}

	key, source, err := cliRandomBytes(provider, nbytes)
	if err != nil {
		return fmt.Errorf("generating data key: %w", err)
	}
	defer zero(key)
	blob, err := ops.EncryptToJSON(key, []byte(*context_))
	if err != nil {
		return fmt.Errorf("wrapping data key: %w", err)
	}

	if *jsonOut {
		payload := map[string]any{
			"wrapped":     json.RawMessage(blob),
			"bits":        *bits,
			"kek_label":   kekLabel,
			"kek_version": kekVersion,
			"source":      source,
		}
		if !*wrappedOnly {
			payload["plaintext"] = base64.StdEncoding.EncodeToString(key)
		}
		return emitCryptoJSON(payload)
	}
	// Text mode: the wrapped envelope goes to -out (default stdout) like encrypt;
	// the plaintext key and metadata go to stderr so a piped stdout is exactly the
	// envelope.
	if !*wrappedOnly {
		fmt.Fprintf(os.Stderr, "data key (%d-bit, base64, source=%s): %s\n", *bits, source, base64.StdEncoding.EncodeToString(key))
	}
	fmt.Fprintf(os.Stderr, "wrapped under KEK %q version %d (decrypt with `secsy-secret decrypt`)\n", kekLabel, kekVersion)
	return writeOutput(*out, append(blob, '\n'))
}

// cmdHMAC computes a keyed HMAC over stdin/a file with the family's active MAC
// key (provisioned on first use), printing the tag and its key version.
func cmdHMAC(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("hmac", flag.ContinueOnError)
	label := fs.String("kek", "", "explicit KEK label override (default: secret.kek_label from config)")
	in := fs.String("in", "-", "input data file to authenticate, or '-' for stdin")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	family, err := resolveKEK(cfg, *label)
	if err != nil {
		return err
	}
	data, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("input data is required")
	}

	ring, db, err := openRing(cfg, provider, family)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	active, err := secret.EnsureActiveMACKey(context.Background(), db, ring, family,
		func(n int) ([]byte, error) { b, _, e := cliRandomBytes(provider, n); return b, e })
	if err != nil {
		return err
	}
	mac, err := secret.TagHMAC(context.Background(), ring, active, data)
	if err != nil {
		return err
	}
	if *jsonOut {
		return emitCryptoJSON(map[string]any{
			"hmac":      base64.StdEncoding.EncodeToString(mac),
			"version":   active.Version,
			"algorithm": secret.HMACAlgSHA256,
		})
	}
	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(mac))
	fmt.Fprintf(os.Stderr, "%s, MAC key version %d\n", secret.HMACAlgSHA256, active.Version)
	return nil
}

// cmdHMACVerify constant-time verifies a keyed HMAC over stdin/a file. It exits
// non-zero when the tag does not verify, so scripts can branch on $?.
func cmdHMACVerify(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("hmac-verify", flag.ContinueOnError)
	label := fs.String("kek", "", "explicit KEK label override (default: secret.kek_label from config)")
	in := fs.String("in", "-", "input data file that was authenticated, or '-' for stdin")
	macB64 := fs.String("hmac", "", "the base64 HMAC tag to verify (required)")
	version := fs.Int("version", 0, "MAC key version the tag was produced under (0 = active)")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *macB64 == "" {
		return fmt.Errorf("-hmac is required")
	}
	mac, err := base64.StdEncoding.DecodeString(*macB64)
	if err != nil {
		return fmt.Errorf("-hmac must be base64: %w", err)
	}
	family, err := resolveKEK(cfg, *label)
	if err != nil {
		return err
	}
	data, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	ring, db, err := openRing(cfg, provider, family)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	// Resolve the version to check against: an explicit one or the active key. A
	// version that was never provisioned yields valid=false rather than an error.
	ver := *version
	if ver <= 0 {
		active, aerr := db.GetActiveMACKey(family)
		if aerr != nil {
			return aerr
		}
		if active == nil {
			return emitVerifyResult(*jsonOut, false, 0)
		}
		ver = active.Version
	}
	row, err := db.GetMACKeyVersion(family, ver)
	if err != nil {
		return err
	}
	if row == nil {
		return emitVerifyResult(*jsonOut, false, ver)
	}
	valid, err := secret.CheckHMAC(context.Background(), ring, row, data, mac)
	if err != nil {
		return err
	}
	return emitVerifyResult(*jsonOut, valid, ver)
}

// emitVerifyResult reports an HMAC verification outcome and signals invalidity
// through a non-zero exit code (text mode) so it is scriptable.
func emitVerifyResult(jsonOut, valid bool, version int) error {
	if jsonOut {
		if err := emitCryptoJSON(map[string]any{"valid": valid, "version": version}); err != nil {
			return err
		}
	} else if valid {
		fmt.Printf("OK: HMAC verified (MAC key version %d)\n", version)
	} else {
		fmt.Fprintln(os.Stderr, "FAILED: HMAC did not verify")
	}
	if !valid {
		return exitCodeError{code: 1}
	}
	return nil
}

// cmdRandom draws CSPRNG bytes from the provider/HSM RNG (or the OS CSPRNG),
// reporting the source. It needs neither a KEK nor the database.
func cmdRandom(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("random", flag.ContinueOnError)
	n := fs.Int("bytes", 32, "number of random bytes to generate (1..1024)")
	format := fs.String("format", "base64", "output encoding: base64 or hex")
	out := fs.String("out", "-", "output file, or '-' for stdout")
	jsonOut := fs.Bool("json", false, "emit a machine-readable JSON object")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *n <= 0 || *n > 1024 {
		return fmt.Errorf("-bytes must be between 1 and 1024")
	}
	if *format != "base64" && *format != "hex" {
		return fmt.Errorf("-format must be base64 or hex")
	}
	b, source, err := cliRandomBytes(provider, *n)
	if err != nil {
		return fmt.Errorf("generating random bytes: %w", err)
	}
	defer zero(b)
	encoded := base64.StdEncoding.EncodeToString(b)
	if *format == "hex" {
		encoded = hex.EncodeToString(b)
	}
	if *jsonOut {
		return emitCryptoJSON(map[string]any{"random": encoded, "format": *format, "bytes": *n, "source": source})
	}
	fmt.Fprintf(os.Stderr, "%d random bytes (source=%s)\n", *n, source)
	return writeOutput(*out, []byte(encoded+"\n"))
}

// dataKeyByteLen maps a requested key strength in bits to a byte length,
// accepting only the AES key sizes.
func dataKeyByteLen(bits int) (int, error) {
	switch bits {
	case 128:
		return 16, nil
	case 256:
		return 32, nil
	case 512:
		return 64, nil
	default:
		return 0, fmt.Errorf("-bits must be 128, 256, or 512")
	}
}
