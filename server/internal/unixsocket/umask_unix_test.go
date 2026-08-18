//go:build !windows

package unixsocket

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWithRestrictiveUmask proves the mechanism that closes the bind/chmod race:
// anything created inside the callback lands with no permission bits at all, and
// the process umask is restored afterwards so unrelated files are unaffected.
func TestWithRestrictiveUmask(t *testing.T) {
	// Start from a permissive umask — the one that would otherwise leave a
	// freshly bound socket world-connectable.
	prev := syscall.Umask(0)
	defer syscall.Umask(prev)

	dir := t.TempDir()
	inside := filepath.Join(dir, "inside")
	err := withRestrictiveUmask(func() error {
		f, ferr := os.OpenFile(inside, os.O_CREATE|os.O_WRONLY, 0o666)
		if ferr != nil {
			return ferr
		}
		return f.Close()
	})
	if err != nil {
		t.Fatalf("withRestrictiveUmask: %v", err)
	}
	info, err := os.Stat(inside)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0 {
		t.Errorf("file created under the restrictive umask has mode %#o, want 0000", got)
	}

	outside := filepath.Join(dir, "outside")
	f, err := os.OpenFile(outside, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	info, err = os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o666 {
		t.Errorf("the umask must be restored; file created after has mode %#o, want 0666", got)
	}
}

// TestWithRestrictiveUmaskPropagatesError confirms a bind failure inside the
// callback reaches the caller rather than being swallowed by the deferred
// restore.
func TestWithRestrictiveUmaskPropagatesError(t *testing.T) {
	want := os.ErrPermission
	if err := withRestrictiveUmask(func() error { return want }); err != want {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
