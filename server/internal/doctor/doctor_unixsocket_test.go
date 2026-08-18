//go:build sqlite

// Unix-domain-socket listener diagnostics (Task 185). In socket mode the
// filesystem replaces both the TCP port and the listener certificate, so the
// preflight findings are filesystem findings: a directory that does not exist,
// a path already occupied, permissions wider than intended, and whether anything
// is actually listening.
package doctor_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
)

// writeSocketConfig writes a config whose HTTP listener is a Unix socket. When
// withTLS is false the listener has no certificate at all, which is legitimate
// only because the socket never touches a network.
func writeSocketConfig(t *testing.T, f *fixture, socket string, mode string, withTLS bool) {
	t.Helper()
	tlsBlock := ""
	if withTLS {
		tlsBlock = fmt.Sprintf("  tls_cert: %s\n  tls_key: %s\n", f.tlsCert, f.tlsKey)
	}
	modeLine := ""
	if mode != "" {
		modeLine = fmt.Sprintf("    mode: %q\n", mode)
	}
	cfg := fmt.Sprintf(`server:
  host: 127.0.0.1
  port: %d
%s  unix_socket:
    path: %s
%sroot_user:
  password: doctor-test
database:
  driver: sqlite
  dsn: %s
key_provider:
  type: software
  software:
    keystore_dir: %s
`, f.port, tlsBlock, socket, modeLine, f.dbPath, f.keystore)
	if err := os.WriteFile(f.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDoctorUnixSocketSkipped keeps the default deployment's report unchanged:
// with no socket configured the check reports "not applicable", not a finding.
func TestDoctorUnixSocketSkipped(t *testing.T) {
	f := newFixture(t, "")
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "listener.unix_socket", doctor.StatusSkip)
	if !strings.Contains(res.Detail, "no Unix-socket listener") {
		t.Errorf("detail = %q", res.Detail)
	}
}

// TestDoctorUnixSocketBeforeFirstStart is the common preflight case: the config
// is sound but the server has not bound the socket yet.
func TestDoctorUnixSocketBeforeFirstStart(t *testing.T) {
	f := newFixture(t, "")
	socket := filepath.Join(f.dir, "api.sock")
	writeSocketConfig(t, f, socket, "0660", true)

	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "listener.unix_socket", doctor.StatusPass)
	if !strings.Contains(res.Detail, "not bound yet") {
		t.Errorf("detail should say the socket is not bound yet, got %q", res.Detail)
	}
	if !strings.Contains(res.Detail, "0660") {
		t.Errorf("detail should report the configured mode, got %q", res.Detail)
	}
}

// TestDoctorUnixSocketReplacesTLSRequirement is the security-policy assertion:
// "no TLS configured" is a hard failure on a TCP listener and a non-issue on a
// socket, because the socket is not reachable from the network.
func TestDoctorUnixSocketReplacesTLSRequirement(t *testing.T) {
	f := newFixture(t, "")
	socket := filepath.Join(f.dir, "api.sock")
	writeSocketConfig(t, f, socket, "", false)

	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "listener.tls", doctor.StatusPass)
	if !strings.Contains(res.Detail, "unix socket") {
		t.Errorf("detail should explain why TLS is not required, got %q", res.Detail)
	}
	assertStatus(t, r, "listener.unix_socket", doctor.StatusPass)
}

// TestDoctorUnixSocketWorldAccessible warns when the mode lets every local
// account connect — legal, authenticated, and almost never intended.
func TestDoctorUnixSocketWorldAccessible(t *testing.T) {
	f := newFixture(t, "")
	socket := filepath.Join(f.dir, "api.sock")
	writeSocketConfig(t, f, socket, "0666", true)

	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "listener.unix_socket", doctor.StatusWarn)
	if !strings.Contains(res.Detail, "every local account") {
		t.Errorf("detail = %q", res.Detail)
	}
}

// TestDoctorUnixSocketOccupiedPath fails the check for a path the server would
// refuse to bind, before the operator discovers it at restart time.
func TestDoctorUnixSocketOccupiedPath(t *testing.T) {
	f := newFixture(t, "")
	socket := filepath.Join(f.dir, "api.sock")
	if err := os.WriteFile(socket, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSocketConfig(t, f, socket, "0660", true)

	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "listener.unix_socket", doctor.StatusFail)
	if !strings.Contains(res.Detail, "non-socket file") {
		t.Errorf("detail = %q", res.Detail)
	}
}

// TestDoctorUnixSocketMissingDirectory fails when the socket's parent directory
// does not exist: the server will not create it, so it would not start.
func TestDoctorUnixSocketMissingDirectory(t *testing.T) {
	f := newFixture(t, "")
	socket := filepath.Join(f.dir, "no-such-dir", "api.sock")
	writeSocketConfig(t, f, socket, "0660", true)

	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "listener.unix_socket", doctor.StatusFail)
	if !strings.Contains(res.Detail, "refuse to start") {
		t.Errorf("detail should warn that startup fails, got %q", res.Detail)
	}
}

// TestDoctorUnixSocketLive reports a bound socket as serving, and notices when
// the running server's socket does not carry the configured permissions.
func TestDoctorUnixSocketLive(t *testing.T) {
	f := newFixture(t, "")
	socket := filepath.Join(f.dir, "api.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("binding test socket: %v", err)
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
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}

	writeSocketConfig(t, f, socket, "0600", true)
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "listener.unix_socket", doctor.StatusPass)
	if !strings.Contains(res.Detail, "accepting connections") {
		t.Errorf("detail should report the live socket, got %q", res.Detail)
	}

	// Same live socket, but the config now asks for a different mode: the
	// running process is serving with stale permissions.
	writeSocketConfig(t, f, socket, "0660", true)
	r = f.run(t, doctor.Options{})
	res = assertStatus(t, r, "listener.unix_socket", doctor.StatusWarn)
	if !strings.Contains(res.Detail, "restart pending") {
		t.Errorf("detail should flag the mode drift, got %q", res.Detail)
	}
}

// TestDoctorUnixSocketStale distinguishes a leftover socket file from a live
// one: the next start reclaims it, so it is informational rather than a finding.
func TestDoctorUnixSocketStale(t *testing.T) {
	f := newFixture(t, "")
	socket := filepath.Join(f.dir, "api.sock")
	lis, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatalf("binding test socket: %v", err)
	}
	lis.SetUnlinkOnClose(false)
	_ = lis.Close()
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}

	writeSocketConfig(t, f, socket, "0600", true)
	r := f.run(t, doctor.Options{})
	res := assertStatus(t, r, "listener.unix_socket", doctor.StatusPass)
	if !strings.Contains(res.Detail, "stale") {
		t.Errorf("detail should identify the socket as stale, got %q", res.Detail)
	}
}
