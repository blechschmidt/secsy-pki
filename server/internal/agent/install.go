package agent

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// installFile is one target of an atomic install.
type installFile struct {
	path string
	data []byte
	mode fs.FileMode
}

// previousFile snapshots a target before it is replaced, for rollback.
type previousFile struct {
	path    string
	data    []byte
	mode    fs.FileMode
	existed bool
}

// installResult reports what an install changed.
type installResult struct {
	leaf     *x509.Certificate
	rolledIn []string
}

// install atomically places the freshly issued material for spec:
//
//  1. the returned chain is verified against the trust bundle and the new key,
//  2. every target is written to a temp file in its directory with final
//     mode/ownership and fsynced,
//  3. previous contents are snapshotted,
//  4. temp files are renamed over the targets (rename(2) is atomic, so readers
//     see either the old file or the new one, never a partial write),
//  5. the reload hook runs; if it fails, the previous contents are restored
//     the same atomic way and the error is returned.
func (a *Agent) install(spec *CertSpec, key crypto.Signer, chain []*x509.Certificate, bundle *trustBundle, now time.Time) (*installResult, error) {
	leaf := chain[0]
	if !publicKeysMatch(leaf, key) {
		return nil, fmt.Errorf("issued certificate does not match the generated key")
	}
	if err := coversSpec(leaf, spec); err != nil {
		return nil, err
	}
	verified, err := bundle.verifyChain(leaf, chain[1:], now)
	if err != nil {
		return nil, err
	}
	// Prefer the verified chain for issuers: it is complete down to the trust
	// anchor even when the enrollment response carried only the leaf.
	issuers := verified[1:]

	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		return nil, err
	}
	files := []installFile{
		{path: spec.KeyFile, data: keyPEM, mode: fs.FileMode(spec.KeyMode)},
		{path: spec.CertFile, data: encodeCertPEM(leaf.Raw), mode: fs.FileMode(spec.CertMode)},
	}
	if spec.ChainFile != "" {
		files = append(files, installFile{path: spec.ChainFile, data: encodeChainPEM(issuers), mode: fs.FileMode(spec.CertMode)})
	}
	if spec.FullchainFile != "" {
		full := append([]byte{}, encodeCertPEM(leaf.Raw)...)
		full = append(full, encodeChainPEM(issuers)...)
		files = append(files, installFile{path: spec.FullchainFile, data: full, mode: fs.FileMode(spec.CertMode)})
	}

	uid, gid := -1, -1
	if spec.Owner != "" {
		uid, gid, err = parseOwner(spec.Owner)
		if err != nil {
			return nil, err
		}
	}

	// Stage every target first so a failure before the swap leaves the live
	// files untouched.
	staged := make([]string, 0, len(files))
	cleanupStaged := func() {
		for _, tmp := range staged {
			os.Remove(tmp) //nolint:errcheck
		}
	}
	for _, f := range files {
		tmp, err := stageFile(f, uid, gid)
		if err != nil {
			cleanupStaged()
			return nil, err
		}
		staged = append(staged, tmp)
	}

	previous := make([]previousFile, 0, len(files))
	for _, f := range files {
		prev, err := snapshotFile(f.path)
		if err != nil {
			cleanupStaged()
			return nil, err
		}
		previous = append(previous, prev)
	}

	rolledIn := make([]string, 0, len(files))
	for i, f := range files {
		if err := os.Rename(staged[i], f.path); err != nil {
			// Restore what already flipped, drop the rest of the staging.
			for _, tmp := range staged[i:] {
				os.Remove(tmp) //nolint:errcheck
			}
			restoreErr := restorePrevious(previous[:i], uid, gid)
			return nil, errors.Join(fmt.Errorf("renaming %s into place: %w", f.path, err), restoreErr)
		}
		syncDir(f.path)
		rolledIn = append(rolledIn, f.path)
	}

	if err := a.runHook(spec, leaf); err != nil {
		restoreErr := restorePrevious(previous, uid, gid)
		if restoreErr != nil {
			return nil, errors.Join(
				fmt.Errorf("reload hook failed: %w", err),
				fmt.Errorf("rollback also failed — on-disk state may be inconsistent: %w", restoreErr),
			)
		}
		return nil, fmt.Errorf("reload hook failed, previous files restored: %w", err)
	}
	return &installResult{leaf: leaf, rolledIn: rolledIn}, nil
}

// coversSpec verifies the issued leaf carries every requested SAN.
func coversSpec(leaf *x509.Certificate, spec *CertSpec) error {
	if err := verifyHostnames(leaf, spec.DNSNames); err != nil {
		return err
	}
	for _, raw := range spec.IPAddresses {
		if err := leaf.VerifyHostname(raw); err != nil {
			return fmt.Errorf("issued certificate does not cover IP %s", raw)
		}
	}
	return nil
}

func verifyHostnames(leaf *x509.Certificate, names []string) error {
	for _, name := range names {
		if err := leaf.VerifyHostname(name); err != nil {
			return fmt.Errorf("issued certificate does not cover %s: %w", name, err)
		}
	}
	return nil
}

// stageFile writes f's content to a temp file next to the target with final
// permissions and ownership, fsyncs it, and returns the temp path.
func stageFile(f installFile, uid, gid int) (string, error) {
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generating temp suffix: %w", err)
	}
	tmp := filepath.Join(dir, "."+filepath.Base(f.path)+".secsy-tmp."+hex.EncodeToString(suffix[:]))
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
	if err != nil {
		return "", fmt.Errorf("creating temp file for %s: %w", f.path, err)
	}
	defer func() {
		if fh != nil {
			fh.Close()     //nolint:errcheck
			os.Remove(tmp) //nolint:errcheck // best-effort cleanup on error
		}
	}()
	if _, err := fh.Write(f.data); err != nil {
		return "", fmt.Errorf("writing %s: %w", tmp, err)
	}
	// The mode passed to OpenFile is masked by the umask; enforce it exactly.
	if err := fh.Chmod(f.mode); err != nil {
		return "", fmt.Errorf("setting mode on %s: %w", tmp, err)
	}
	if uid >= 0 || gid >= 0 {
		if err := fh.Chown(uid, gid); err != nil {
			return "", fmt.Errorf("setting ownership on %s: %w", tmp, err)
		}
	}
	if err := fh.Sync(); err != nil {
		return "", fmt.Errorf("syncing %s: %w", tmp, err)
	}
	if err := fh.Close(); err != nil {
		return "", fmt.Errorf("closing %s: %w", tmp, err)
	}
	fh = nil // disarm cleanup
	return tmp, nil
}

// snapshotFile captures a target's current content and mode for rollback.
func snapshotFile(path string) (previousFile, error) {
	prev := previousFile{path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return prev, nil
	}
	if err != nil {
		return prev, fmt.Errorf("inspecting %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return prev, fmt.Errorf("snapshotting %s: %w", path, err)
	}
	prev.existed = true
	prev.data = data
	prev.mode = info.Mode().Perm()
	return prev, nil
}

// restorePrevious puts the snapshotted contents back (atomically) after a
// failed hook; targets that did not exist before are removed.
func restorePrevious(previous []previousFile, uid, gid int) error {
	var errs []error
	for _, prev := range previous {
		if !prev.existed {
			if err := os.Remove(prev.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("removing %s: %w", prev.path, err))
			}
			continue
		}
		tmp, err := stageFile(installFile{path: prev.path, data: prev.data, mode: prev.mode}, uid, gid)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.Rename(tmp, prev.path); err != nil {
			os.Remove(tmp) //nolint:errcheck
			errs = append(errs, fmt.Errorf("restoring %s: %w", prev.path, err))
			continue
		}
		syncDir(prev.path)
	}
	return errors.Join(errs...)
}

// syncDir best-effort fsyncs the directory containing path so the rename is
// durable.
func syncDir(path string) {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return
	}
	dir.Sync()  //nolint:errcheck
	dir.Close() //nolint:errcheck
}

// writeFileAtomic writes data to path via a temp file + rename.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp, err := stageFile(installFile{path: path, data: data, mode: mode}, -1, -1)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return fmt.Errorf("renaming %s into place: %w", path, err)
	}
	syncDir(path)
	return nil
}

// readFileIfExists returns (nil, nil) when the file does not exist.
func readFileIfExists(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// parseOwner resolves "user:group" (names or numeric IDs) to uid/gid. A
// missing group defaults to the user's primary group.
func parseOwner(owner string) (uid, gid int, err error) {
	userPart, groupPart, _ := strings.Cut(owner, ":")
	if userPart == "" {
		return -1, -1, fmt.Errorf("owner %q: user part is empty", owner)
	}
	u, lookupErr := user.Lookup(userPart)
	if lookupErr != nil {
		if id, convErr := strconv.Atoi(userPart); convErr == nil {
			uid = id
		} else {
			return -1, -1, fmt.Errorf("owner %q: unknown user %q", owner, userPart)
		}
	} else {
		uid, _ = strconv.Atoi(u.Uid)
	}
	switch {
	case groupPart == "" && u != nil:
		gid, _ = strconv.Atoi(u.Gid)
	case groupPart == "":
		gid = -1
	default:
		g, lookupErr := user.LookupGroup(groupPart)
		if lookupErr != nil {
			if id, convErr := strconv.Atoi(groupPart); convErr == nil {
				gid = id
			} else {
				return -1, -1, fmt.Errorf("owner %q: unknown group %q", owner, groupPart)
			}
		} else {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	return uid, gid, nil
}
