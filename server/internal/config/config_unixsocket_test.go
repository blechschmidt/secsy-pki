package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeUnixSocketConfig renders a minimal loadable config with the given
// listener block appended.
func writeUnixSocketConfig(t *testing.T, listeners string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "root_user:\n  username: admin\n  password: secret\n" + listeners
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestUnixSocketConfigLoads checks that the listener keys parse, survive the
// strict unknown-key lint, and reach the listener package in the shape it wants.
func TestUnixSocketConfigLoads(t *testing.T) {
	path := writeUnixSocketConfig(t, `
server:
  unix_socket:
    path: /run/secsy/api.sock
    mode: "0660"
    group: "4242"
grpc:
  enabled: true
  unix_socket:
    path: /run/secsy/grpc.sock
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Server.UnixSocket.Enabled() || !cfg.GRPC.UnixSocket.Enabled() {
		t.Fatal("both listeners should report socket mode enabled")
	}
	lis := cfg.Server.UnixSocket.Listener()
	if lis.Path != "/run/secsy/api.sock" || lis.Mode != "0660" || lis.Group != "4242" {
		t.Errorf("listener config = %+v", lis)
	}
	mode, err := lis.FileMode()
	if err != nil || mode != 0o660 {
		t.Errorf("FileMode() = (%#o, %v), want (0660, nil)", mode, err)
	}
	// An unset mode must not inherit anything permissive.
	grpcMode, err := cfg.GRPC.UnixSocket.Listener().FileMode()
	if err != nil || grpcMode != 0o600 {
		t.Errorf("default FileMode() = (%#o, %v), want (0600, nil)", grpcMode, err)
	}

	// The strict lint backs `secsy-ca doctor`'s config.unknown_keys finding, so
	// the new keys must be known to it.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := UnknownKeys(raw)
	if err != nil {
		t.Fatalf("UnknownKeys: %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("unknown keys reported for a valid config: %v", unknown)
	}
}

// TestUnixSocketConfigUnsetByDefault confirms socket mode is opt-in: an absent
// block leaves both listeners on their TCP ports.
func TestUnixSocketConfigUnsetByDefault(t *testing.T) {
	cfg, err := Load(writeUnixSocketConfig(t, "server:\n  port: 8443\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.UnixSocket.Enabled() || cfg.GRPC.UnixSocket.Enabled() {
		t.Error("socket mode must be off unless a path is configured")
	}
}

// TestUnixSocketConfigRejectsBadSettings pins the load-time validation: a socket
// that could never be bound is a config error, not a startup crash after the
// HSM has been opened.
func TestUnixSocketConfigRejectsBadSettings(t *testing.T) {
	cases := []struct {
		name      string
		listeners string
		wantMatch string
	}{
		{
			name:      "relative http path",
			listeners: "server:\n  unix_socket:\n    path: run/api.sock\n",
			wantMatch: "server.unix_socket",
		},
		{
			name:      "unparsable mode",
			listeners: "server:\n  unix_socket:\n    path: /run/api.sock\n    mode: \"rw-rw----\"\n",
			wantMatch: "octal",
		},
		{
			name:      "unknown group",
			listeners: "server:\n  unix_socket:\n    path: /run/api.sock\n    group: definitely-no-such-group\n",
			wantMatch: "group",
		},
		{
			name:      "relative grpc path",
			listeners: "grpc:\n  unix_socket:\n    path: grpc.sock\n",
			wantMatch: "grpc.unix_socket",
		},
		{
			name:      "path too long for sun_path",
			listeners: "server:\n  unix_socket:\n    path: /" + strings.Repeat("a", 200) + ".sock\n",
			wantMatch: "Unix socket",
		},
		{
			name: "both listeners on one socket",
			listeners: "server:\n  unix_socket:\n    path: /run/shared.sock\n" +
				"grpc:\n  unix_socket:\n    path: /run/shared.sock\n",
			wantMatch: "must differ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeUnixSocketConfig(t, tc.listeners))
			if err == nil {
				t.Fatal("Load should have rejected this listener configuration")
			}
			if !strings.Contains(err.Error(), tc.wantMatch) {
				t.Errorf("error %q should mention %q", err, tc.wantMatch)
			}
		})
	}
}

// TestUnixSocketEnvOverride covers the container case: the runtime knows the
// socket path long after the config file was baked.
func TestUnixSocketEnvOverride(t *testing.T) {
	t.Setenv("SECSY_SERVER_UNIX_SOCKET", "/run/env/api.sock")
	t.Setenv("SECSY_GRPC_UNIX_SOCKET", "/run/env/grpc.sock")
	cfg, err := Load(writeUnixSocketConfig(t, "server:\n  port: 8443\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Server.UnixSocket.Path; got != "/run/env/api.sock" {
		t.Errorf("server socket = %q, want the environment override", got)
	}
	if got := cfg.GRPC.UnixSocket.Path; got != "/run/env/grpc.sock" {
		t.Errorf("grpc socket = %q, want the environment override", got)
	}
}
