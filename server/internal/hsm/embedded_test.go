package hsm

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

func boolp(b bool) *bool { return &b }

// The planner decides whether a process claims a CA's HSM, so both directions
// matter: a relay started where one is already running takes a port and fails,
// and a relay not started where one is needed leaves a force-audited device
// filling its log until it stops signing.
func TestPlanEmbeddedConnector(t *testing.T) {
	const module = "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so"
	for _, tc := range []struct {
		name   string
		opts   EmbeddedConnectorOptions
		start  bool
		listen string
		url    string
		errish string
	}{
		{
			// The deployment this whole mechanism exists for, and the reason
			// the default is on: unset configuration, a YubiHSM on USB, and the
			// module signing through it. Without the relay this is the one
			// configuration that can never drain its device log.
			name:   "direct USB with a signing module multiplexes by default",
			opts:   EmbeddedConnectorOptions{PKCS11Module: module},
			start:  true,
			listen: yubihsm.DefaultEmbeddedListen,
			url:    "http://" + yubihsm.DefaultEmbeddedListen,
		},
		{
			// Nothing competes for the device: the native driver has it to
			// itself, which already works. A relay here would only bind a port
			// and add a way to fail.
			name: "direct USB with no signing module needs no relay",
			opts: EmbeddedConnectorOptions{},
		},
		{
			name:   "an explicit yes starts one even with nothing to relay for",
			opts:   EmbeddedConnectorOptions{Enabled: boolp(true)},
			start:  true,
			listen: yubihsm.DefaultEmbeddedListen,
			url:    "http://" + yubihsm.DefaultEmbeddedListen,
		},
		{
			// An operator who turned it off is running Yubico's daemon, and
			// must not be second-guessed into binding its port.
			name: "an explicit no is final",
			opts: EmbeddedConnectorOptions{Enabled: boolp(false), PKCS11Module: module},
		},
		{
			name:   "an explicit listen address is honoured",
			opts:   EmbeddedConnectorOptions{PKCS11Module: module, Listen: "127.0.0.1:23456"},
			start:  true,
			listen: "127.0.0.1:23456",
			url:    "http://127.0.0.1:23456",
		},
		{
			// The single-container configuration: one URL that the server, the
			// CLI and any vendor tool in the container all use, served from the
			// process that holds the device.
			name:   "an explicit yes serves the loopback URL the config names",
			opts:   EmbeddedConnectorOptions{Enabled: boolp(true), ConnectorURL: "http://127.0.0.1:12345"},
			start:  true,
			listen: "127.0.0.1:12345",
			url:    "http://127.0.0.1:12345",
		},
		{
			name:   "localhost counts as this host",
			opts:   EmbeddedConnectorOptions{Enabled: boolp(true), ConnectorURL: "http://localhost:12345"},
			start:  true,
			listen: "localhost:12345",
			url:    "http://localhost:12345",
		},
		{
			// Before the relay existed, a loopback http URL meant exactly one
			// thing: a yubihsm-connector daemon on this host. That reading has
			// to survive, or upgrading would have every such deployment try to
			// bind a port its daemon already holds.
			name: "a loopback URL alone is still read as somebody else's daemon",
			opts: EmbeddedConnectorOptions{ConnectorURL: "http://127.0.0.1:12345", PKCS11Module: module},
		},
		{
			name: "a remote connector is already shareable",
			opts: EmbeddedConnectorOptions{ConnectorURL: "http://hsm.internal:12345", PKCS11Module: module},
		},
		{
			// Asking for a relay that cannot exist has to be loud: silently
			// not starting it is how a force-audited device ends up wedged.
			name:   "asking to serve another host is a configuration error",
			opts:   EmbeddedConnectorOptions{Enabled: boolp(true), ConnectorURL: "http://hsm.internal:12345"},
			errish: "can only serve a local address",
		},
		{
			name:   "the device to hold must be a USB device",
			opts:   EmbeddedConnectorOptions{Enabled: boolp(true), Device: "http://127.0.0.1:12345"},
			errish: "must be a yhusb:// URL",
		},
		{
			name:   "a pinned serial is carried through",
			opts:   EmbeddedConnectorOptions{PKCS11Module: module, Device: "yhusb://serial=31650425"},
			start:  true,
			listen: yubihsm.DefaultEmbeddedListen,
			url:    "http://" + yubihsm.DefaultEmbeddedListen,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// connectorArg consults YUBIHSM_PKCS11_CONF when no URL is
			// configured, and a developer's machine may well have one.
			t.Setenv("YUBIHSM_PKCS11_CONF", "")
			plan := PlanEmbeddedConnector(tc.opts)
			if tc.errish != "" {
				if plan.Err == nil {
					t.Fatalf("expected a configuration error mentioning %q, got start=%v (%s)",
						tc.errish, plan.Start, plan.Reason)
				}
				if !strings.Contains(plan.Err.Error(), tc.errish) {
					t.Fatalf("error does not mention %q: %v", tc.errish, plan.Err)
				}
				return
			}
			if plan.Err != nil {
				t.Fatalf("unexpected configuration error: %v", plan.Err)
			}
			if plan.Start != tc.start {
				t.Fatalf("Start = %v, want %v (%s)", plan.Start, tc.start, plan.Reason)
			}
			if plan.Reason == "" {
				t.Error("the verdict carries no explanation, so neither the startup log nor the doctor can say why")
			}
			if !tc.start {
				return
			}
			if plan.Listen != tc.listen {
				t.Errorf("Listen = %q, want %q", plan.Listen, tc.listen)
			}
			if plan.URL != tc.url {
				t.Errorf("URL = %q, want %q", plan.URL, tc.url)
			}
			if !yubihsm.IsDirectUSB(plan.DeviceURL) {
				t.Errorf("DeviceURL = %q, want a USB device", plan.DeviceURL)
			}
			want := strings.TrimSpace(tc.opts.Device)
			if want == "" {
				want = "yhusb://"
			}
			if plan.DeviceURL != want {
				t.Errorf("DeviceURL = %q, want %q", plan.DeviceURL, want)
			}
		})
	}
}

// A deployment that configured only YUBIHSM_PKCS11_CONF has its transport
// decided by that file, and the relay decision has to read it the same way the
// signing path does — or the two end up addressing different hardware.
func TestPlanEmbeddedConnectorFollowsTheModuleConfig(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "yubihsm_pkcs11.conf")
	if err := os.WriteFile(conf, []byte("connector = http://hsm.internal:12345\n"), 0o600); err != nil {
		t.Fatalf("writing the module config: %v", err)
	}
	t.Setenv("YUBIHSM_PKCS11_CONF", conf)

	plan := PlanEmbeddedConnector(EmbeddedConnectorOptions{PKCS11Module: "/usr/lib/pkcs11/yubihsm_pkcs11.so"})
	if plan.Start {
		t.Fatalf("a deployment whose module config names a remote connector would start a relay: %s", plan.Reason)
	}
	if !strings.Contains(plan.Reason, "hsm.internal") {
		t.Errorf("the verdict does not name the transport it read: %s", plan.Reason)
	}
}

// PointPKCS11At has to override an existing YUBIHSM_PKCS11_CONF, not defer to
// it: an image or host that ships one saying `connector = yhusb://` would
// otherwise send the module at the USB interface this process is holding, which
// is the contention the relay exists to remove.
func TestPointPKCS11AtOverridesAnExistingConfig(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "stale.conf")
	if err := os.WriteFile(stale, []byte("connector = yhusb://\n"), 0o600); err != nil {
		t.Fatalf("writing the stale config: %v", err)
	}
	t.Setenv("YUBIHSM_PKCS11_CONF", stale)

	// Run in a writable working directory, which is where the file lands.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	if err := PointPKCS11At("http://127.0.0.1:12345", nil); err != nil {
		t.Fatalf("pointing the module at the relay: %v", err)
	}
	conf := os.Getenv("YUBIHSM_PKCS11_CONF")
	if conf == stale {
		t.Fatal("the stale config is still in force, so the module would claim the device directly")
	}
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("reading %s: %v", conf, err)
	}
	if !strings.Contains(string(data), "http://127.0.0.1:12345") {
		t.Fatalf("%s does not name the relay: %q", conf, data)
	}
	// And the resolution the audit path uses must now agree with the module's.
	if got := EffectiveConnectorURL(Config{}); got != "http://127.0.0.1:12345" {
		t.Fatalf("the audit path resolves %q, but the module was pointed at the relay", got)
	}
}

// A process that cannot claim the device because another one already serves it
// must route *both* ways to the device at that relay: the PKCS#11 module, which
// reads a config file, and the native driver, which resolves a connector URL.
//
// Only the module was pointed at it. A container whose config named yhusb:// —
// the natural spelling when one container holds the device — therefore gave an
// exec'd `secsy-ca` half a device: it could sign through the module, while
// `hsm-audit status` and every attestation command resolved yhusb://, reached
// for the USB claim the server was holding, and reported "Device: unreachable".
func TestStartEmbeddedConnectorJoinsAnAlreadyServedAddress(t *testing.T) {
	// Occupy the address with something that answers the connector protocol, as
	// the server process's relay would: the joining process asks which device is
	// on the other side, so that a URL naming a different serial is not quietly
	// answered by this one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A GET DEVICE INFO reply: command|0x80, 2-byte length, then firmware
		// 2.4.0, serial 31650425 (0x01e2f279), a 62-slot log with none used, and
		// two algorithm identifiers.
		body := []byte{2, 4, 0, 0x01, 0xe2, 0xf2, 0x79, 62, 0, 0x01, 0x02}
		reply := append([]byte{0x86, byte(len(body) >> 8), byte(len(body))}, body...)
		_, _ = w.Write(reply)
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	addr := ln.Addr().String()

	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	t.Cleanup(func() { yubihsm.JoinRelay("", "") })

	plan := PlanEmbeddedConnector(EmbeddedConnectorOptions{
		Enabled:      boolp(true),
		Listen:       addr,
		ConnectorURL: "yhusb://",
		PKCS11Module: "/usr/lib/pkcs11/yubihsm_pkcs11.so",
	})
	if plan.Err != nil || !plan.Start {
		t.Fatalf("the plan should start a relay: start=%v err=%v", plan.Start, plan.Err)
	}

	e, err := StartEmbeddedConnector(context.Background(), plan, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("joining an already-served address: %v", err)
	}
	if e != nil {
		_ = e.Close()
		t.Fatal("a relay was started over an address something else already serves")
	}

	// The module, as before.
	conf := os.Getenv("YUBIHSM_PKCS11_CONF")
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("reading %s: %v", conf, err)
	}
	if !strings.Contains(string(data), plan.URL) {
		t.Fatalf("%s does not name the joined relay: %q", conf, data)
	}

	// And the native driver, which is the half that was missing.
	joined, ok := yubihsm.JoinedRelay()
	if !ok {
		t.Fatal("the native driver was not routed to the joined relay, so yhusb:// still goes to USB")
	}
	if joined != plan.URL {
		t.Fatalf("the native driver was routed to %q, want the joined relay %q", joined, plan.URL)
	}

	// The relay was asked which device it holds, so a configuration pinning that
	// serial is answered by it...
	info, err := yubihsm.TransportDeviceInfo(context.Background(),
		yubihsm.Config{ConnectorURL: "yhusb://serial=31650425"})
	if err != nil {
		t.Fatalf("the joined relay did not answer for the serial it holds: %v", err)
	}
	if info.Serial != "31650425" {
		t.Fatalf("the joined relay reports serial %q, want 31650425", info.Serial)
	}

	// ...and one naming a different device is not. Answering for the wrong
	// hardware is the single failure this subsystem must never have: an audit
	// log collected from one device while describing another verifies perfectly
	// and means nothing. Without an attached YubiHSM the attempt falls through to
	// USB and fails there, which is the correct outcome and the one asserted.
	if _, err := yubihsm.TransportDeviceInfo(context.Background(),
		yubihsm.Config{ConnectorURL: "yhusb://serial=99999999"}); err == nil {
		t.Fatal("the joined relay answered for a serial it does not hold")
	}
}
