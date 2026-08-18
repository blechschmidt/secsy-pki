// Package unixsocket binds a listener to a Unix-domain socket so the REST/HTTP
// and gRPC surfaces can be exposed to co-located processes only, with the
// filesystem — not the network — as the access-control boundary.
//
// It exists because an enterprise PKI is frequently deployed as a local signing
// oracle: a reverse proxy, a sidecar, or a host agent on the same machine is the
// only legitimate client, and binding a TCP port at all widens the attack
// surface for no benefit. A Unix socket removes the network from the picture
// entirely: it cannot be reached from another host, it needs no listener
// certificate to stay confidential, and access is granted with ownership and
// permission bits that the operating system already enforces.
//
// Three details matter enough to centralize here rather than repeat at each
// call site:
//
//   - Permissions are applied without a race. net.Listen creates the socket with
//     0777 &^ umask, which on a typical umask of 022 is world-connectable for the
//     window between bind and chmod. Listen therefore binds under a 0777 umask
//     (socket created mode 0000, connectable by nobody) and chmods to the
//     configured mode afterwards, so the socket is never more permissive than
//     the operator asked for.
//
//   - A stale socket file is reclaimed, but only when it is provably stale. A
//     process killed with SIGKILL leaves the socket inode behind and the next
//     bind fails with EADDRINUSE. Listen removes such a leftover only after a
//     connect attempt proves nothing is listening, and it refuses outright to
//     unlink a path that is not a socket — a typo pointing at a real file must
//     never delete it.
//
//   - Accepted connections report the peer's user ID instead of the empty
//     address the kernel supplies for an unnamed client. Everything downstream
//     that keys on the request's remote address — the per-IP rate-limit
//     buckets, the audit log, the JSON access log — would otherwise lump every
//     local caller into one anonymous "@" bucket. See Addr.
package unixsocket

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultMode is applied to a bound socket when the operator does not choose a
// mode: owner-only. It fails closed — a socket that fronts CA issuance, secret
// decryption, and the operator API should not become reachable by every local
// account merely because the mode was left unset. Grant wider access explicitly
// with Config.Mode (and Config.Group for a co-located proxy under another user).
const DefaultMode os.FileMode = 0o600

// MaxPathLen bounds the socket path. The kernel copies it into sockaddr_un's
// fixed sun_path buffer — 108 bytes on Linux, 104 on the BSDs — and a path that
// does not fit is rejected with a bare "invalid argument" from bind(2). The
// limit here is the smallest of those, minus the NUL terminator, so the error an
// operator sees names the real problem rather than the syscall's.
const MaxPathLen = 103

// Config describes a Unix-domain-socket listener.
type Config struct {
	// Path is the filesystem path to bind. Setting it is what enables socket
	// mode; it must be absolute, and its parent directory must already exist
	// (the parent's own permissions are part of the access-control story, so
	// this package will not create it and guess at them).
	Path string
	// Mode is the octal permission string applied to the bound socket, e.g.
	// "0660". Empty means DefaultMode.
	Mode string
	// Group optionally sets the socket's group, by name or numeric GID, so a
	// co-located reverse proxy or sidecar running under a different account can
	// connect with mode 0660. Changing a file's group requires the process to
	// own the socket and belong to the target group (or be root).
	Group string
}

// Enabled reports whether socket mode is configured, i.e. whether a path was
// set. It is the single predicate callers use to choose between a Unix socket
// and a TCP port.
func (c Config) Enabled() bool { return strings.TrimSpace(c.Path) != "" }

// SocketPath returns the trimmed socket path.
func (c Config) SocketPath() string { return strings.TrimSpace(c.Path) }

// FileMode parses Mode as octal, defaulting to DefaultMode when unset.
func (c Config) FileMode() (os.FileMode, error) {
	m := strings.TrimSpace(c.Mode)
	if m == "" {
		return DefaultMode, nil
	}
	// Accept "0660", "660", and "0o660" alike: operators copy modes from chmod
	// invocations, Go literals, and YAML in roughly equal measure.
	m = strings.TrimPrefix(strings.TrimPrefix(m, "0o"), "0O")
	v, err := strconv.ParseUint(m, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("mode %q is not an octal permission value (e.g. \"0660\")", c.Mode)
	}
	if v > 0o777 {
		return 0, fmt.Errorf("mode %q is out of range (expected at most 0777)", c.Mode)
	}
	return os.FileMode(v), nil
}

// GID resolves Group to a numeric group ID, accepting either a group name or a
// numeric GID. It returns -1 when no group is configured, meaning "leave the
// socket's group as the process's own".
func (c Config) GID() (int, error) {
	g := strings.TrimSpace(c.Group)
	if g == "" {
		return -1, nil
	}
	if gid, err := strconv.Atoi(g); err == nil {
		if gid < 0 {
			return -1, fmt.Errorf("group %q is not a valid GID", c.Group)
		}
		// A numeric GID is used as given: a container image frequently carries no
		// /etc/group entry for the GID the socket must be shared with.
		return gid, nil
	}
	grp, err := user.LookupGroup(g)
	if err != nil {
		return -1, fmt.Errorf("resolving group %q: %w", c.Group, err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return -1, fmt.Errorf("group %q has non-numeric GID %q", c.Group, grp.Gid)
	}
	return gid, nil
}

// Validate checks a socket configuration without binding anything, so a bad
// path or mode is reported at config-load time and by `secsy-ca doctor` rather
// than at the moment the server tries to serve. It deliberately does not test
// for the socket's existence: doctor runs both before and while the server is
// up, and a bound socket is not a finding.
func Validate(c Config) error {
	if !c.Enabled() {
		return nil
	}
	path := c.SocketPath()
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path %q must be absolute", c.Path)
	}
	if len(path) > MaxPathLen {
		return fmt.Errorf("path %q is %d bytes; the kernel accepts at most %d for a Unix socket", c.Path, len(path), MaxPathLen)
	}
	if _, err := c.FileMode(); err != nil {
		return err
	}
	if _, err := c.GID(); err != nil {
		return err
	}
	return nil
}

// WorldAccessible reports whether the configured mode grants any access to
// users outside the socket's owner and group. It is posture advice rather than
// a correctness rule — every route behind the socket still authenticates — so
// callers surface it as a warning (see `secsy-ca doctor`), not an error.
func (c Config) WorldAccessible() bool {
	mode, err := c.FileMode()
	if err != nil {
		return false
	}
	return mode&0o007 != 0
}

// Listen binds the configured Unix-domain socket and returns a listener whose
// accepted connections report the peer's credentials (see Addr).
//
// The socket is created unreachable and then chmodded to the requested mode, so
// there is no window in which it is more permissive than configured. A stale
// socket left by a killed process is reclaimed; a live one, or a path occupied
// by anything that is not a socket, is an error.
func Listen(c Config) (net.Listener, error) {
	if !c.Enabled() {
		return nil, errors.New("unixsocket: path is required")
	}
	if err := Validate(c); err != nil {
		return nil, fmt.Errorf("unixsocket: %w", err)
	}
	path := c.SocketPath()
	mode, err := c.FileMode()
	if err != nil {
		return nil, fmt.Errorf("unixsocket: %w", err)
	}
	gid, err := c.GID()
	if err != nil {
		return nil, fmt.Errorf("unixsocket: %w", err)
	}

	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("unixsocket: socket directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("unixsocket: socket directory %s is not a directory", dir)
	}

	if err := reclaimStale(path); err != nil {
		return nil, err
	}

	// Bind with every permission bit masked off, so the socket exists but is
	// connectable by nobody until the chmod below opens it to exactly the
	// configured audience.
	var lis net.Listener
	err = withRestrictiveUmask(func() error {
		l, lerr := net.Listen("unix", path)
		if lerr != nil {
			return lerr
		}
		lis = l
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("unixsocket: listen on %s: %w", path, err)
	}

	// From here on a failure must not leave a half-configured socket behind:
	// closing the listener unlinks the path it created.
	if err := os.Chmod(path, mode); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("unixsocket: setting mode %#o on %s: %w", mode, path, err)
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			_ = lis.Close()
			return nil, fmt.Errorf("unixsocket: setting group %s on %s: %w", c.Group, path, err)
		}
	}

	unixLis, ok := lis.(*net.UnixListener)
	if !ok { // unreachable for network "unix"; keeps the type assertion honest.
		return lis, nil
	}
	return &credListener{UnixListener: unixLis, path: path}, nil
}

// Describe renders the effective socket settings for a startup log line.
func Describe(c Config) string {
	mode, err := c.FileMode()
	if err != nil {
		return c.SocketPath()
	}
	s := fmt.Sprintf("%s (mode %#o", c.SocketPath(), uint32(mode))
	if g := strings.TrimSpace(c.Group); g != "" {
		s += ", group " + g
	}
	return s + ")"
}

// reclaimStale removes a leftover socket inode so a restart after an unclean
// shutdown succeeds — but only after establishing that it really is a leftover.
// A path that is not a socket is never unlinked (a mistyped path must not
// destroy a file), and a socket something is still listening on is reported as
// in use rather than stolen out from under the running process.
func reclaimStale(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("unixsocket: inspecting %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("unixsocket: %s already exists and is not a socket (refusing to remove it)", path)
	}
	if conn, derr := net.DialTimeout("unix", path, 500*time.Millisecond); derr == nil {
		_ = conn.Close()
		return fmt.Errorf("unixsocket: %s is already in use by a live listener (another instance running?)", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("unixsocket: removing stale socket %s: %w", path, err)
	}
	return nil
}

// Addr is the remote address reported for a connection accepted on a Unix
// socket. The kernel names an unnamed client's address the empty string, which
// net renders as "@": with the stock address every local caller shares one
// rate-limit bucket and one indistinguishable line in the audit log. Addr
// substitutes the peer's user ID, which is the closest local analogue of a
// source IP — it is supplied by the kernel, cannot be forged by the client, and
// is stable across that user's processes.
type Addr struct {
	// Path is the socket the connection arrived on.
	Path string
	// UID, GID and PID are the peer's credentials as reported by the kernel.
	// They are meaningful only when HasCred is true.
	UID, GID uint32
	PID      int32
	// HasCred reports whether peer credentials could be read. They are a
	// per-platform facility; when unavailable the address degrades to
	// "unix/unknown" rather than failing the connection.
	HasCred bool
}

// Network implements net.Addr.
func (a *Addr) Network() string { return "unix" }

// String implements net.Addr. The rendering deliberately contains no colon:
// consumers split a host:port remote address with net.SplitHostPort and fall
// back to the raw string, so a colon here would be parsed as a port and collapse
// every peer onto the host part.
func (a *Addr) String() string {
	if !a.HasCred {
		return "unix/unknown"
	}
	return "unix/" + strconv.FormatUint(uint64(a.UID), 10)
}

// credListener decorates accepted connections with peer credentials.
type credListener struct {
	*net.UnixListener
	path string
}

// Accept implements net.Listener.
func (l *credListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	return &credConn{UnixConn: conn, remote: peerAddr(conn, l.path)}, nil
}

// credConn is a *net.UnixConn that reports the peer's credentials as its remote
// address. Every other method — including SyscallConn and the deadline setters
// that net/http and gRPC rely on — is promoted from the embedded connection.
type credConn struct {
	*net.UnixConn
	remote net.Addr
}

// RemoteAddr implements net.Conn.
func (c *credConn) RemoteAddr() net.Addr { return c.remote }

// peerAddr reads the connected peer's credentials, degrading to an
// unknown-credential address when the platform cannot supply them.
func peerAddr(conn *net.UnixConn, path string) net.Addr {
	addr := &Addr{Path: path}
	rc, err := conn.SyscallConn()
	if err != nil {
		return addr
	}
	_ = rc.Control(func(fd uintptr) {
		cred, cerr := peerCredential(fd)
		if cerr != nil {
			return
		}
		addr.UID, addr.GID, addr.PID, addr.HasCred = cred.uid, cred.gid, cred.pid, true
	})
	return addr
}

// credential is the platform-independent shape of a peer's credentials.
type credential struct {
	uid, gid uint32
	pid      int32
}
