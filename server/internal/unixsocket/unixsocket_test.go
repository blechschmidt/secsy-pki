package unixsocket_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/unixsocket"
)

// socketPath returns a short path inside the test's temp dir. Socket paths are
// bounded by sun_path, and t.TempDir() under a long TMPDIR plus a long test name
// can overrun it, so the name is kept to a few bytes.
func socketPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func TestFileModeParsing(t *testing.T) {
	cases := []struct {
		mode string
		want os.FileMode
	}{
		{"", unixsocket.DefaultMode},
		{"0660", 0o660},
		{"660", 0o660},
		{"0o600", 0o600},
		{" 0640 ", 0o640},
		{"0777", 0o777},
	}
	for _, tc := range cases {
		got, err := unixsocket.Config{Path: "/tmp/x.sock", Mode: tc.mode}.FileMode()
		if err != nil {
			t.Fatalf("FileMode(%q): %v", tc.mode, err)
		}
		if got != tc.want {
			t.Errorf("FileMode(%q) = %#o, want %#o", tc.mode, got, tc.want)
		}
	}
	for _, bad := range []string{"rw-rw----", "0888", "1777", "-1"} {
		if _, err := (unixsocket.Config{Path: "/tmp/x.sock", Mode: bad}).FileMode(); err == nil {
			t.Errorf("FileMode(%q) accepted an invalid mode", bad)
		}
	}
}

func TestDefaultModeIsOwnerOnly(t *testing.T) {
	// The default must fail closed: an operator who sets only a path gets a
	// socket no other local account can connect to.
	if unixsocket.DefaultMode != 0o600 {
		t.Fatalf("DefaultMode = %#o, want 0600", unixsocket.DefaultMode)
	}
	if (unixsocket.Config{Path: "/tmp/x.sock"}).WorldAccessible() {
		t.Error("the default mode must not be world-accessible")
	}
	if !(unixsocket.Config{Path: "/tmp/x.sock", Mode: "0666"}).WorldAccessible() {
		t.Error("0666 must be reported as world-accessible")
	}
	if (unixsocket.Config{Path: "/tmp/x.sock", Mode: "0660"}).WorldAccessible() {
		t.Error("0660 grants owner+group only and must not be flagged")
	}
}

func TestValidate(t *testing.T) {
	if err := unixsocket.Validate(unixsocket.Config{}); err != nil {
		t.Fatalf("an unset socket config is not an error: %v", err)
	}
	if err := unixsocket.Validate(unixsocket.Config{Path: "run/secsy.sock"}); err == nil {
		t.Error("a relative path must be rejected")
	}
	long := "/" + strings.Repeat("a", unixsocket.MaxPathLen)
	if err := unixsocket.Validate(unixsocket.Config{Path: long}); err == nil {
		t.Errorf("a path of %d bytes must be rejected (sun_path holds %d)", len(long), unixsocket.MaxPathLen)
	}
	if err := unixsocket.Validate(unixsocket.Config{Path: "/tmp/x.sock", Mode: "nope"}); err == nil {
		t.Error("an unparsable mode must be rejected")
	}
	if err := unixsocket.Validate(unixsocket.Config{Path: "/tmp/x.sock", Group: "definitely-no-such-group"}); err == nil {
		t.Error("an unresolvable group must be rejected")
	}
	if err := unixsocket.Validate(unixsocket.Config{Path: "/tmp/x.sock", Mode: "0660"}); err != nil {
		t.Errorf("a well-formed config must validate: %v", err)
	}
}

func TestGIDResolution(t *testing.T) {
	gid, err := unixsocket.Config{Path: "/tmp/x.sock"}.GID()
	if err != nil || gid != -1 {
		t.Fatalf("GID() with no group = (%d, %v), want (-1, nil)", gid, err)
	}
	// A numeric GID is honored verbatim: container images routinely lack an
	// /etc/group entry for the GID the socket is shared with.
	gid, err = unixsocket.Config{Path: "/tmp/x.sock", Group: "4242"}.GID()
	if err != nil || gid != 4242 {
		t.Fatalf("GID(\"4242\") = (%d, %v), want (4242, nil)", gid, err)
	}
	if _, err := (unixsocket.Config{Path: "/tmp/x.sock", Group: "definitely-no-such-group"}).GID(); err == nil {
		t.Error("an unknown group name must be an error")
	}

	// A group *name* resolves through the system group database. The running
	// process's own group is the only name guaranteed to exist everywhere.
	grp, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("no group database entry for gid %d: %v", os.Getgid(), err)
	}
	gid, err = unixsocket.Config{Path: "/tmp/x.sock", Group: grp.Name}.GID()
	if err != nil {
		t.Fatalf("GID(%q): %v", grp.Name, err)
	}
	if gid != os.Getgid() {
		t.Errorf("GID(%q) = %d, want %d", grp.Name, gid, os.Getgid())
	}
}

// TestListenAppliesModeWithoutRace pins the central permission guarantee: the
// socket is never observable with a mode wider than the configured one. It is
// checked immediately after Listen returns, and with a permissive process umask
// that would otherwise leave the socket world-connectable.
func TestListenAppliesMode(t *testing.T) {
	for _, mode := range []string{"", "0600", "0660", "0666"} {
		t.Run("mode="+mode, func(t *testing.T) {
			path := socketPath(t, "s.sock")
			lis, err := unixsocket.Listen(unixsocket.Config{Path: path, Mode: mode})
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer func() { _ = lis.Close() }()

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat socket: %v", err)
			}
			if info.Mode()&os.ModeSocket == 0 {
				t.Fatalf("%s is not a socket (mode %v)", path, info.Mode())
			}
			want, err := unixsocket.Config{Path: path, Mode: mode}.FileMode()
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != want {
				t.Errorf("socket mode = %#o, want %#o", got, want)
			}
			if lis.Addr().String() != path {
				t.Errorf("Addr() = %q, want %q", lis.Addr().String(), path)
			}
		})
	}
}

func TestListenRejectsBadConfig(t *testing.T) {
	if _, err := unixsocket.Listen(unixsocket.Config{}); err == nil {
		t.Error("Listen with no path must fail")
	}
	if _, err := unixsocket.Listen(unixsocket.Config{Path: "relative.sock"}); err == nil {
		t.Error("Listen with a relative path must fail")
	}
	missing := filepath.Join(socketPath(t, "nodir"), "s.sock")
	if _, err := unixsocket.Listen(unixsocket.Config{Path: missing}); err == nil {
		t.Error("Listen must fail when the parent directory does not exist")
	}
}

// TestListenReclaimsStaleSocket covers the restart-after-SIGKILL case: the
// socket inode outlives the process, and bind would fail with EADDRINUSE unless
// the leftover is removed.
func TestListenReclaimsStaleSocket(t *testing.T) {
	path := socketPath(t, "s.sock")
	first, err := unixsocket.Listen(unixsocket.Config{Path: path})
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	// Drop the listener without closing it, exactly as a killed process would,
	// by unlinking nothing and closing only the underlying descriptor's owner.
	stale := stealSocketFile(t, first, path)

	second, err := unixsocket.Listen(unixsocket.Config{Path: stale})
	if err != nil {
		t.Fatalf("Listen over a stale socket must succeed: %v", err)
	}
	_ = second.Close()
}

// stealSocketFile closes the listener but leaves an equivalent stale socket
// inode at path, standing in for a process killed before it could clean up.
func stealSocketFile(t *testing.T, lis net.Listener, path string) string {
	t.Helper()
	_ = lis.Close() // net unlinks the socket it created
	// Recreate the leftover: bind a second listener, then leak the file by
	// closing the descriptor without unlinking.
	raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("recreating stale socket: %v", err)
	}
	raw.SetUnlinkOnClose(false)
	_ = raw.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket file should still exist: %v", err)
	}
	return path
}

func TestListenRefusesLiveSocket(t *testing.T) {
	path := socketPath(t, "s.sock")
	lis, err := unixsocket.Listen(unixsocket.Config{Path: path})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = lis.Close() }()
	go func() {
		for {
			conn, aerr := lis.Accept()
			if aerr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	if _, err := unixsocket.Listen(unixsocket.Config{Path: path}); err == nil {
		t.Fatal("Listen must refuse a socket another listener is serving")
	} else if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("error should name the conflict, got: %v", err)
	}
}

// TestListenRefusesNonSocketPath is the destructive-typo guard: a path that
// names a real file must never be unlinked to make room for the socket.
func TestListenRefusesNonSocketPath(t *testing.T) {
	path := socketPath(t, "s.sock")
	if err := os.WriteFile(path, []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := unixsocket.Listen(unixsocket.Config{Path: path})
	if err == nil {
		t.Fatal("Listen must refuse a path occupied by a regular file")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("error should explain the refusal, got: %v", err)
	}
	body, rerr := os.ReadFile(path)
	if rerr != nil || string(body) != "important" {
		t.Errorf("the existing file must be left intact, got (%q, %v)", body, rerr)
	}
}

func TestListenRejectsUnresolvableGroup(t *testing.T) {
	path := socketPath(t, "s.sock")
	if _, err := unixsocket.Listen(unixsocket.Config{Path: path, Group: "definitely-no-such-group"}); err == nil {
		t.Fatal("Listen must fail on an unresolvable group")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed Listen must not leave a socket behind (stat: %v)", err)
	}
}

// TestHTTPOverSocket serves a real HTTP handler on the socket and calls it the
// way a co-located client does, proving the listener is usable by net/http and
// that the peer's user ID reaches the handler as the remote address.
func TestHTTPOverSocket(t *testing.T) {
	path := socketPath(t, "s.sock")
	lis, err := unixsocket.Listen(unixsocket.Config{Path: path})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	var remote string
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remote = r.RemoteAddr
			fmt.Fprint(w, "pong")
		}),
	}
	go func() { _ = srv.Serve(lis) }()
	defer func() { _ = srv.Close() }()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	resp, err := client.Get("http://localhost/ping")
	if err != nil {
		t.Fatalf("GET over the socket: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" {
		t.Fatalf("body = %q, want %q", body, "pong")
	}

	// The stock unnamed-client address is "@", which would collapse every local
	// caller into one rate-limit bucket and one audit-log identity.
	if remote == "@" || remote == "" {
		t.Fatalf("remote address should identify the peer, got %q", remote)
	}
	want := "unix/" + strconv.Itoa(os.Getuid())
	if remote != want {
		t.Errorf("RemoteAddr = %q, want %q", remote, want)
	}
	// Consumers key rate-limit buckets on the host part of a host:port address
	// and fall back to the raw string; a colon here would be read as a port.
	if strings.Contains(remote, ":") {
		t.Errorf("RemoteAddr %q must not contain a colon", remote)
	}
}

// TestAcceptExposesPeerCredentials checks the full credential set, which the
// address only summarizes.
func TestAcceptExposesPeerCredentials(t *testing.T) {
	path := socketPath(t, "s.sock")
	lis, err := unixsocket.Listen(unixsocket.Config{Path: path})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = lis.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, aerr := lis.Accept()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	conn, ok := <-accepted
	if !ok {
		t.Fatal("Accept failed")
	}
	defer func() { _ = conn.Close() }()

	addr, ok := conn.RemoteAddr().(*unixsocket.Addr)
	if !ok {
		t.Fatalf("RemoteAddr is %T, want *unixsocket.Addr", conn.RemoteAddr())
	}
	if addr.Network() != "unix" {
		t.Errorf("Network() = %q, want \"unix\"", addr.Network())
	}
	if addr.Path != path {
		t.Errorf("Path = %q, want %q", addr.Path, path)
	}
	if !addr.HasCred {
		t.Fatal("peer credentials should be available on this platform")
	}
	if int(addr.UID) != os.Getuid() {
		t.Errorf("UID = %d, want %d", addr.UID, os.Getuid())
	}
	if int(addr.PID) != os.Getpid() {
		t.Errorf("PID = %d, want %d", addr.PID, os.Getpid())
	}
	if _, ok := conn.(interface{ SetDeadline(time.Time) error }); !ok {
		t.Error("the wrapped connection must still satisfy net.Conn's deadline methods")
	}
}

func TestAddrWithoutCredentials(t *testing.T) {
	addr := &unixsocket.Addr{Path: "/run/secsy/api.sock"}
	if got := addr.String(); got != "unix/unknown" {
		t.Errorf("String() = %q, want \"unix/unknown\"", got)
	}
}

func TestDescribe(t *testing.T) {
	got := unixsocket.Describe(unixsocket.Config{Path: "/run/secsy/api.sock", Mode: "0660", Group: "secsy"})
	for _, want := range []string{"/run/secsy/api.sock", "0660", "secsy"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() = %q, want it to mention %q", got, want)
		}
	}
	if got := unixsocket.Describe(unixsocket.Config{Path: "/run/secsy/api.sock"}); !strings.Contains(got, "0600") {
		t.Errorf("Describe() should report the default mode, got %q", got)
	}
}

// TestCloseUnlinks documents the clean-shutdown half of the stale-socket story:
// a listener that is closed removes its socket, so the reclaim path is only
// needed after an unclean exit.
func TestCloseUnlinks(t *testing.T) {
	path := socketPath(t, "s.sock")
	lis, err := unixsocket.Listen(unixsocket.Config{Path: path})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := lis.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Close should unlink the socket, stat: %v", err)
	}
}
