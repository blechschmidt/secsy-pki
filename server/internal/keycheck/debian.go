package keycheck

import (
	"bufio"
	"crypto"
	"crypto/sha1" //nolint:gosec // SHA-1 is a fingerprint basis for legacy weak-key blocklists, not a security primitive here.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Blocklist is a loaded set of known-weak public-key fingerprints — primarily the
// Debian OpenSSL predictable-key set (CVE-2008-0166), but usable for any
// operator-curated weak-key list. No blocklist is vendored with the binary; an
// operator points the gate at a file or directory of fingerprints (keychecks
// config), which is loaded once at startup.
//
// Supported token formats, one per line (blank lines and '#' comments ignored):
//
//   - a hex SHA-256 or SHA-1 digest (64 or 40 hex chars, optional "0x" prefix) of
//     the DER-encoded SubjectPublicKeyInfo; and
//   - a "SHA256:<base64>" fingerprint in the same textual form Fingerprint emits
//     (so an operator can feed back fingerprints exported from the `blocked-keys`
//     store or discovery tooling).
//
// A key matches when any of its candidate fingerprints (SHA-256/SHA-1 hex over the
// SPKI, or the "SHA256:<base64>" form) is present. Matching the SPKI keeps the
// basis stable across key types and independent of certificate encoding.
type Blocklist struct {
	// hex holds lowercase hex SHA-1/SHA-256 SPKI digests.
	hex map[string]struct{}
	// prefixed holds "SHA256:<base64>" fingerprints verbatim (base64 is
	// case-sensitive, so these are not lowercased).
	prefixed map[string]struct{}
	// sources records the files that contributed, for diagnostics.
	sources []string
}

// Len reports the number of distinct fingerprints loaded.
func (b *Blocklist) Len() int {
	if b == nil {
		return 0
	}
	return len(b.hex) + len(b.prefixed)
}

// Empty reports whether the blocklist has no entries (or is nil).
func (b *Blocklist) Empty() bool { return b.Len() == 0 }

// Sources returns the files that contributed entries.
func (b *Blocklist) Sources() []string {
	if b == nil {
		return nil
	}
	return append([]string(nil), b.sources...)
}

// LoadBlocklist reads weak-key fingerprints from the given paths. Each path may
// be a single file or a directory (walked recursively; unreadable entries are
// skipped). It returns (nil, nil) when no paths are given, so the gate treats "no
// blocklist configured" and "empty blocklist" identically. A path that does not
// exist is a hard error, so a typo'd blocklist path fails closed at startup rather
// than silently disabling the check.
func LoadBlocklist(paths ...string) (*Blocklist, error) {
	var real []string
	for _, p := range paths {
		if strings.TrimSpace(p) != "" {
			real = append(real, p)
		}
	}
	if len(real) == 0 {
		return nil, nil
	}
	bl := &Blocklist{hex: map[string]struct{}{}, prefixed: map[string]struct{}{}}
	for _, p := range real {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("weak-key blocklist path %q: %w", p, err)
		}
		if info.IsDir() {
			if err := bl.loadDir(p); err != nil {
				return nil, err
			}
			continue
		}
		if err := bl.loadFile(p); err != nil {
			return nil, err
		}
	}
	return bl, nil
}

func (b *Blocklist) loadDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking weak-key blocklist dir %q: %w", dir, err)
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		return b.loadFile(path)
	})
}

func (b *Blocklist) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening weak-key blocklist %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := b.read(f); err != nil {
		return fmt.Errorf("reading weak-key blocklist %q: %w", path, err)
	}
	b.sources = append(b.sources, path)
	return nil
}

// read parses tokens from a reader, ignoring blank lines and '#' comments.
func (b *Blocklist) read(r io.Reader) error {
	sc := bufio.NewScanner(r)
	// Allow long lines (some blocklists pack many tokens); 1 MiB is ample.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// A line may carry several whitespace-separated tokens.
		for _, tok := range strings.Fields(line) {
			b.addToken(tok)
		}
	}
	return sc.Err()
}

// addToken canonicalizes and stores one fingerprint token, silently skipping one
// it cannot classify (so a stray header line does not abort a load).
func (b *Blocklist) addToken(tok string) {
	if strings.HasPrefix(strings.ToUpper(tok), "SHA256:") {
		b64 := tok[len("SHA256:"):]
		if b64 != "" {
			b.prefixed["SHA256:"+b64] = struct{}{}
		}
		return
	}
	h := strings.ToLower(strings.TrimPrefix(tok, "0x"))
	if (len(h) == 40 || len(h) == 64) && isHex(h) {
		b.hex[h] = struct{}{}
	}
}

// Contains reports whether a public key's fingerprint is in the blocklist. It is
// safe to call on a nil Blocklist (always false).
func (b *Blocklist) Contains(pub crypto.PublicKey) bool {
	if b.Empty() {
		return false
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false
	}
	if len(b.hex) > 0 {
		s256 := sha256.Sum256(spki)
		if _, ok := b.hex[hex.EncodeToString(s256[:])]; ok {
			return true
		}
		s1 := sha1.Sum(spki) //nolint:gosec // fingerprint basis, not a security primitive.
		if _, ok := b.hex[hex.EncodeToString(s1[:])]; ok {
			return true
		}
	}
	if len(b.prefixed) > 0 {
		s256 := sha256.Sum256(spki)
		fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(s256[:])
		if _, ok := b.prefixed[fp]; ok {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
