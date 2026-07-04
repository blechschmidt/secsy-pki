package publish

import (
	"context"
	"testing"
)

// publishOne writes a one-artifact snapshot, creating a fresh timestamped
// snapshot directory and flipping `current`.
func publishOne(t *testing.T, s *DirStore, name string) {
	t.Helper()
	arts := []Artifact{{Path: "backup.bin", Data: []byte(name), Kind: "backup"}}
	if err := s.Publish(context.Background(), []byte(`{"v":1}`), arts); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

// TestDirStoreListSnapshots checks enumeration, ordering (newest first),
// creation-time recovery from the stamp, and the current flag.
func TestDirStoreListSnapshots(t *testing.T) {
	s, err := NewDirStore(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		publishOne(t, s, "snap")
	}

	snaps, err := s.ListSnapshots(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(snaps) != 3 {
		t.Fatalf("got %d snapshots, want 3", len(snaps))
	}
	// Newest first, with parsed creation times.
	for i := 1; i < len(snaps); i++ {
		if snaps[i-1].ID < snaps[i].ID {
			t.Fatalf("snapshots not newest-first: %q before %q", snaps[i-1].ID, snaps[i].ID)
		}
		if snaps[i].CreatedAt.IsZero() {
			t.Fatalf("snapshot %q has no creation time", snaps[i].ID)
		}
	}
	// Exactly one current, and it is the newest.
	if !snaps[0].Current {
		t.Fatal("newest snapshot should be current")
	}
	for _, s := range snaps[1:] {
		if s.Current {
			t.Fatalf("only the newest should be current, but %q is too", s.ID)
		}
	}
}

// TestDirStoreDeleteSnapshot verifies a past snapshot can be deleted but the
// current one is protected.
func TestDirStoreDeleteSnapshot(t *testing.T) {
	s, err := NewDirStore(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publishOne(t, s, "old")
	publishOne(t, s, "new")

	snaps, _ := s.ListSnapshots(context.Background())
	if len(snaps) != 2 {
		t.Fatalf("want 2 snapshots, got %d", len(snaps))
	}
	current, past := snaps[0], snaps[1]

	if err := s.DeleteSnapshot(context.Background(), current.ID); err == nil {
		t.Fatal("deleting the current snapshot must be refused")
	}
	if err := s.DeleteSnapshot(context.Background(), past.ID); err != nil {
		t.Fatalf("deleting a past snapshot: %v", err)
	}

	remaining, _ := s.ListSnapshots(context.Background())
	if len(remaining) != 1 || !remaining[0].Current {
		t.Fatalf("after deletion want only the current snapshot, got %+v", remaining)
	}

	// current still fetches from the surviving snapshot.
	if _, err := s.Fetch(context.Background(), "backup.bin"); err != nil {
		t.Fatalf("current snapshot unreadable after prune: %v", err)
	}

	// DirStore implements the SnapshotPruner capability.
	var _ SnapshotPruner = s
}
