package publish

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DirStore publishes snapshots to a local directory with whole-snapshot
// atomicity. Each snapshot is written to its own versioned directory under
// snapshots/ and the well-known `current` symlink is flipped over it with a
// single rename, so a consumer (CDN origin, rsync job, static file server
// rooted at <root>/current) always sees either the previous complete snapshot
// or the new complete snapshot — never a mixture or a partial write.
//
//	<root>/snapshots/<stamp>/...   one directory per snapshot
//	<root>/current -> snapshots/<stamp>
//
// Before the swap every written file is read back and its SHA-256 compared to
// the manifest (catching torn writes and disk corruption); the swap only
// happens after the whole snapshot verifies. Old snapshots beyond the
// retention count are pruned after a successful swap.
type DirStore struct {
	root string
	keep int
}

// DefaultKeepSnapshots is how many published snapshots the directory backend
// retains (the current one included) when not configured. Keeping more than
// one lets in-flight consumers finish reading a just-replaced snapshot.
const DefaultKeepSnapshots = 3

const (
	dirSnapshots = "snapshots"
	dirCurrent   = "current"
)

// NewDirStore returns a directory backend rooted at root, retaining keep
// snapshots (non-positive uses DefaultKeepSnapshots). The root is created if
// missing.
func NewDirStore(root string, keep int) (*DirStore, error) {
	if root == "" {
		return nil, fmt.Errorf("publish directory path is required")
	}
	if keep <= 0 {
		keep = DefaultKeepSnapshots
	}
	if err := os.MkdirAll(filepath.Join(root, dirSnapshots), 0o755); err != nil {
		return nil, fmt.Errorf("creating publish directory: %w", err)
	}
	return &DirStore{root: root, keep: keep}, nil
}

// Name identifies the backend.
func (s *DirStore) Name() string { return "dir" }

// Root returns the publish root directory.
func (s *DirStore) Root() string { return s.root }

// Publish writes one snapshot directory, verifies it by readback, atomically
// flips the current symlink, and prunes old snapshots.
func (s *DirStore) Publish(ctx context.Context, manifest []byte, artifacts []Artifact) error {
	stamp, err := snapshotStamp()
	if err != nil {
		return err
	}
	snapRel := filepath.Join(dirSnapshots, stamp)
	snapDir := filepath.Join(s.root, snapRel)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return fmt.Errorf("creating snapshot directory: %w", err)
	}
	// A failed publish leaves no half-written snapshot behind (current still
	// points at the previous one regardless).
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(snapDir)
		}
	}()

	for i := range artifacts {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := writeFileInDir(snapDir, artifacts[i].Path, artifacts[i].Data); err != nil {
			return err
		}
	}

	// Integrity check: read every artifact back from disk and compare digests
	// before anything becomes visible.
	for i := range artifacts {
		a := &artifacts[i]
		got, err := os.ReadFile(filepath.Join(snapDir, filepath.FromSlash(a.Path)))
		if err != nil {
			return fmt.Errorf("integrity readback of %s: %w", a.Path, err)
		}
		want := sha256.Sum256(a.Data)
		have := sha256.Sum256(got)
		if have != want {
			return fmt.Errorf("integrity check failed for %s: readback sha256 %s != written %s",
				a.Path, hex.EncodeToString(have[:]), hex.EncodeToString(want[:]))
		}
	}

	// Manifest last, fsynced: its presence marks the snapshot complete.
	if err := writeFileSync(filepath.Join(snapDir, ManifestPath), manifest); err != nil {
		return err
	}

	// Atomic swap: point a temporary symlink at the new snapshot and rename it
	// over `current`. rename(2) replaces the destination atomically, so readers
	// resolve either the old snapshot or the new one at every instant.
	tmpLink := filepath.Join(s.root, dirCurrent+".tmp-"+stamp)
	if err := os.Symlink(snapRel, tmpLink); err != nil {
		return fmt.Errorf("creating snapshot symlink: %w", err)
	}
	if err := os.Rename(tmpLink, filepath.Join(s.root, dirCurrent)); err != nil {
		os.Remove(tmpLink)
		return fmt.Errorf("swapping current snapshot: %w", err)
	}
	if err := syncDir(s.root); err != nil {
		return fmt.Errorf("syncing publish root: %w", err)
	}

	cleanup = false
	s.prune(snapRel)
	return nil
}

// Fetch reads one object of the currently published snapshot.
func (s *DirStore) Fetch(_ context.Context, path string) ([]byte, error) {
	if err := checkRelPath(path); err != nil {
		return nil, fmt.Errorf("invalid path %q: %w", path, err)
	}
	return os.ReadFile(filepath.Join(s.root, dirCurrent, filepath.FromSlash(path)))
}

// prune removes snapshot directories beyond the retention count, never the one
// just published (currentRel) nor whatever `current` resolves to.
func (s *DirStore) prune(currentRel string) {
	entries, err := os.ReadDir(filepath.Join(s.root, dirSnapshots))
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) <= s.keep {
		return
	}
	// Stamps are zero-padded UTC timestamps, so lexicographic order is
	// chronological; newest last.
	sort.Strings(names)
	live, _ := os.Readlink(filepath.Join(s.root, dirCurrent))
	for _, name := range names[:len(names)-s.keep] {
		rel := filepath.Join(dirSnapshots, name)
		if rel == currentRel || rel == live {
			continue
		}
		os.RemoveAll(filepath.Join(s.root, rel))
	}
}

// snapshotStamp builds a sortable, unique snapshot directory name.
func snapshotStamp() (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generating snapshot id: %w", err)
	}
	return time.Now().UTC().Format("20060102-150405.000000000") + "-" + hex.EncodeToString(suffix[:]), nil
}

// writeFileInDir writes an artifact under dir, creating parents. relPath has
// already been validated against traversal by the publisher.
func writeFileInDir(dir, relPath string, data []byte) error {
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	if !strings.HasPrefix(full, dir+string(os.PathSeparator)) {
		return fmt.Errorf("artifact path %q escapes snapshot directory", relPath)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	return nil
}

// writeFileSync writes a file and fsyncs it.
func writeFileSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("syncing %s: %w", path, err)
	}
	return f.Close()
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
