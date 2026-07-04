package publish

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SnapshotRef identifies one retained snapshot of a backend that accumulates
// history (as the directory backend does under snapshots/). It is the unit a
// retention policy — keep-N and max-age — operates on.
type SnapshotRef struct {
	// ID is the backend-specific snapshot identifier (the snapshot directory
	// name for the directory backend). It is what DeleteSnapshot takes.
	ID string
	// CreatedAt is when the snapshot was written, used for max-age retention.
	CreatedAt time.Time
	// Current is true for the snapshot the `current` pointer resolves to; it is
	// never a candidate for deletion.
	Current bool
}

// SnapshotPruner is an optional Store capability: enumerating and deleting past
// snapshots so a caller can enforce its own retention policy (keep-N / max-age)
// beyond a backend's built-in count-based pruning. A backend that only ever
// exposes a single "current" object (the S3 backend overwrites fixed keys) does
// not implement it; retention there is delegated to object-store versioning and
// lifecycle policies. *DirStore implements it.
type SnapshotPruner interface {
	// ListSnapshots returns every retained snapshot, newest first.
	ListSnapshots(ctx context.Context) ([]SnapshotRef, error)
	// DeleteSnapshot removes one past snapshot by ID. It must refuse to delete
	// the snapshot the `current` pointer resolves to.
	DeleteSnapshot(ctx context.Context, id string) error
}

// snapshotStampLayout is the time layout snapshotStamp encodes before the
// random suffix; ListSnapshots parses it back to recover CreatedAt.
const snapshotStampLayout = "20060102-150405.000000000"

// ListSnapshots enumerates the retained snapshot directories under snapshots/,
// newest first, recovering each snapshot's creation time from its stamped name
// (falling back to the directory mtime) and flagging the one `current` points
// at.
func (s *DirStore) ListSnapshots(_ context.Context) ([]SnapshotRef, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, dirSnapshots))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing snapshots: %w", err)
	}
	live, _ := os.Readlink(filepath.Join(s.root, dirCurrent)) // e.g. "snapshots/<stamp>"
	liveName := filepath.Base(live)

	var refs []SnapshotRef
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		ref := SnapshotRef{ID: name, Current: name == liveName}
		if t, perr := time.Parse(snapshotStampLayout, snapshotTimePart(name)); perr == nil {
			ref.CreatedAt = t.UTC()
		} else if info, ierr := e.Info(); ierr == nil {
			ref.CreatedAt = info.ModTime().UTC()
		}
		refs = append(refs, ref)
	}
	// Stamps sort lexicographically in chronological order; newest first.
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID > refs[j].ID })
	return refs, nil
}

// snapshotTimePart returns the timestamp portion of a snapshot stamp
// ("<layout>-<hexsuffix>" → "<layout>"). It strips the trailing random suffix
// added by snapshotStamp.
func snapshotTimePart(name string) string {
	if i := strings.LastIndex(name, "-"); i > 0 {
		return name[:i]
	}
	return name
}

// DeleteSnapshot removes one snapshot directory, refusing to delete the one the
// `current` symlink resolves to (that would break live consumers and lose the
// most recent backup). An unknown ID is a no-op.
func (s *DirStore) DeleteSnapshot(_ context.Context, id string) error {
	if id == "" || strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		return fmt.Errorf("invalid snapshot id %q", id)
	}
	live, _ := os.Readlink(filepath.Join(s.root, dirCurrent))
	if filepath.Base(live) == id {
		return fmt.Errorf("refusing to delete the current snapshot %q", id)
	}
	if err := os.RemoveAll(filepath.Join(s.root, dirSnapshots, id)); err != nil {
		return fmt.Errorf("deleting snapshot %q: %w", id, err)
	}
	return nil
}
