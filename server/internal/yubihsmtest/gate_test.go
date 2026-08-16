package yubihsmtest

// The gate, the device handles, and the scratch-object discipline shared by
// every tier. See doc.go for what the suite covers and how to enable it.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// Environment variables. Only SECSY_YUBIHSM_TESTS is required; the rest have
// defaults that match a factory-configured device on direct USB.
const (
	envEnable      = "SECSY_YUBIHSM_TESTS"
	envDestructive = "SECSY_YUBIHSM_DESTRUCTIVE"
	envReset       = "SECSY_YUBIHSM_RESET"
	envConnector   = "SECSY_YUBIHSM_CONNECTOR"
	envPassword    = "SECSY_YUBIHSM_PASSWORD"
	envAuthKeyID   = "SECSY_YUBIHSM_AUTH_KEY_ID"
	envModule      = "SECSY_YUBIHSM_PKCS11_MODULE"
)

// Scratch handles. The suite owns 0x7f00–0x7f1f exclusively and touches nothing
// else; the older per-package hardware tests own 0x7e5x, so the two can run in
// the same session without fighting over an object id.
const (
	scratchBase = 0x7f00
	scratchTop  = 0x7f1f
)

func scratchID(n int) uint16 {
	if id := scratchBase + n; id <= scratchTop {
		return uint16(id)
	}
	panic(fmt.Sprintf("yubihsmtest: scratch id %d is outside the reserved 0x%04x-0x%04x range", n, scratchBase, scratchTop))
}

// runID separates this run's PKCS#11 labels from any left by an earlier one.
// Two objects sharing a CKA_LABEL make key lookup ambiguous, and the failure it
// produces is an intermittent bad signature rather than an error, so uniqueness
// is a correctness requirement and not just hygiene.
var runID = func() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}()

// label builds a unique object label. YubiHSM caps labels at 40 bytes, and the
// device silently truncates rather than rejecting, which would reintroduce the
// collision the run id exists to prevent — so truncate the caller's part here,
// where it is visible.
func label(name string) string {
	const max = 40
	full := "t172-" + name + "-" + runID
	if len(full) <= max {
		return full
	}
	keep := max - len("t172--") - len(runID)
	return "t172-" + name[:keep] + "-" + runID
}

// enabled reports whether the operator asked for hardware tests.
func enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envEnable))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// requireDevice is the gate every test in this package starts with.
//
// It skips when the suite is disabled and fails when it is enabled but no
// device answers. Skipping in the second case would be more forgiving and quite
// wrong: the operator asked for hardware tests, so a device that is unplugged
// or held by another process has to be reported. An earlier draft of this file
// skipped instead, and the result was a run that reported PASS for the whole
// suite while touching no hardware at all — which is the one outcome a hardware
// suite must never produce.
func requireDevice(t *testing.T) {
	t.Helper()
	if !enabled() {
		t.Skipf("YubiHSM hardware tests are off; set %s=1 to enable (see docs/hsm/hardware-test-suite.md)", envEnable)
	}
	probeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, probeErr = yubihsm.TransportDeviceInfo(ctx, driverConfig())
	})
	if probeErr != nil {
		t.Fatalf("%s=1 but no YubiHSM answered on %s: %v\n"+
			"Unplugged, or held by another process (yubihsm-connector, the PKCS#11 module, "+
			"or another test run)? Unset %s to skip these tests instead.",
			envEnable, connectorURL(), probeErr, envEnable)
	}
}

var (
	probeOnce sync.Once
	probeErr  error
)

// requireDestructive additionally gates the irreversible operations. Forced
// audit, once set to "fixed", survives every power cycle and can only be undone
// by a factory reset that destroys every key on the device, so it is not
// something a test should do to an operator who merely said "run the hardware
// tests".
func requireDestructive(t *testing.T) {
	t.Helper()
	requireDevice(t)
	if os.Getenv(envDestructive) != "1" {
		t.Skipf("this test changes the device irreversibly; set %s=1 to allow it", envDestructive)
	}
}

// requireReset gates the tests that factory-reset the device.
//
// A separate gate from requireDestructive, and not implied by it, for two
// reasons. A reset erases every key and every log entry — strictly more than
// "irreversible configuration" — and it also runs *mid-suite*, so it would undo
// the forced audit TestProvisionForcedAudit had just established and leave later
// tiers looking at a device in a different state than the one they were told
// about. Opting in separately keeps a destructive run predictable.
func requireReset(t *testing.T) {
	t.Helper()
	requireDestructive(t)
	if os.Getenv(envReset) != "1" {
		t.Skipf("this test factory-resets the device, erasing every key and the whole audit log; "+
			"set %s=1 to allow it", envReset)
	}
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// connectorURL prefers the suite's own variable but honours YUBIHSM_CONNECTOR,
// which the pre-existing per-package hardware tests and the yubihsm-shell
// tooling both read, so one exported value drives everything.
func connectorURL() string { return env(envConnector, env("YUBIHSM_CONNECTOR", "yhusb://")) }
func password() string     { return env(envPassword, env("YUBIHSM_PASSWORD", "password")) }

func authKeyID() int {
	v := env(envAuthKeyID, "1")
	id, err := strconv.Atoi(v)
	if err != nil || id <= 0 || id > 0xffff {
		panic(fmt.Sprintf("yubihsmtest: %s=%q is not a valid object id", envAuthKeyID, v))
	}
	return id
}

func driverConfig() yubihsm.Config {
	return yubihsm.Config{ConnectorURL: connectorURL(), AuthKeyID: uint16(authKeyID()), Password: password()}
}

func hsmConfig() hsm.Config {
	return hsm.Config{ConnectorURL: connectorURL(), AuthKeyID: authKeyID(), Password: password()}
}

// pkcs11ModulePath locates the YubiHSM PKCS#11 module. The path differs across
// distributions, so probe the known ones rather than hard-coding a single
// guess: the older internal/pki hardware test hard-codes /usr/lib/pkcs11 and is
// consequently unrunnable on Debian multiarch, which puts it under
// /usr/lib/<triplet>/pkcs11.
func pkcs11ModulePath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv(envModule); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s=%s: %v", envModule, p, err)
		}
		return p
	}
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so",
		"/usr/lib/aarch64-linux-gnu/pkcs11/yubihsm_pkcs11.so",
		"/usr/lib/pkcs11/yubihsm_pkcs11.so",
		"/usr/local/lib/pkcs11/yubihsm_pkcs11.so",
		"/usr/local/lib/yubihsm_pkcs11.so",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skipf("YubiHSM PKCS#11 module not found in %v; set %s", candidates, envModule)
	return ""
}

// pkcs11Config builds the module configuration. The module reads its connector
// from a file named by YUBIHSM_PKCS11_CONF, which TestMain writes, and its PIN
// is the four-hex-digit authentication key id followed by that key's password.
func pkcs11Config(t *testing.T) pki.PKCS11Config {
	t.Helper()
	return pki.PKCS11Config{
		ModulePath: pkcs11ModulePath(t),
		Pin:        fmt.Sprintf("%04x%s", authKeyID(), password()),
		TokenLabel: "YubiHSM",
	}
}

// --- device handles -------------------------------------------------------

// deadline bounds every hardware interaction. USB stalls are the common failure
// mode on a device that another process is holding, and an unbounded test hangs
// the whole run rather than reporting which tier is stuck.
const deadline = 60 * time.Second

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	t.Cleanup(cancel)
	return ctx
}

// client opens an authenticated SCP03 session, closed when the test ends.
//
// Closing matters more here than in a software-token test: on direct USB the
// driver claims the kernel interface exclusively, so a session left open would
// lock every later tier — and the PKCS#11 module, which claims the same
// interface — out of the device.
func client(t *testing.T) (*yubihsm.Client, context.Context) {
	t.Helper()
	ctx := testContext(t)
	c, err := yubihsm.Open(ctx, driverConfig())
	if err != nil {
		t.Fatalf("opening a session on %s: %v", connectorURL(), err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, ctx
}

// withClient runs fn against a session that is closed as soon as fn returns,
// for tests that also need the device through PKCS#11 or a second session.
func withClient(t *testing.T, fn func(ctx context.Context, c *yubihsm.Client)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	c, err := yubihsm.Open(ctx, driverConfig())
	if err != nil {
		t.Fatalf("opening a session on %s: %v", connectorURL(), err)
	}
	defer func() { _ = c.Close() }()
	fn(ctx, c)
}

// --- scratch objects ------------------------------------------------------

// capabilities resolves capability names to the device's bit mask. Names rather
// than literals because a mistyped bit silently grants the wrong permission,
// and hsmattest holds the authoritative table.
func capabilities(t *testing.T, names ...string) uint64 {
	t.Helper()
	mask, err := hsmattest.ParseCapabilityNames(names)
	if err != nil {
		t.Fatalf("resolving capabilities %v: %v", names, err)
	}
	return uint64(mask)
}

// generateScratch creates a key at a reserved handle and deletes it afterwards.
// It deletes first as well: a test killed mid-run leaves the object behind, and
// the next run's create would fail with "object exists" rather than the failure
// the operator is actually chasing.
//
// The cleanup reuses the caller's session rather than opening its own. On
// direct USB the device admits exactly one session, and cleanups run in reverse
// registration order — so a cleanup that opened a second session would do it
// while the caller's session was still open, and block until the context
// expired. That is a self-inflicted deadlock, and it presents as a 60-second
// hang in teardown rather than as an obvious error, so it is worth the
// awkwardness of threading the session through.
func generateScratch(t *testing.T, c *yubihsm.Client, ctx context.Context, id uint16, name string, algorithm byte, caps ...string) uint16 {
	t.Helper()
	deleteScratch(ctx, c, id)
	got, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
		ID:           id,
		Label:        label(name),
		Domains:      1,
		Capabilities: capabilities(t, caps...),
		Algorithm:    algorithm,
	})
	if err != nil {
		t.Fatalf("generating %s key 0x%04x: %v", yubihsm.AlgorithmName(algorithm), id, err)
	}
	t.Cleanup(func() { deleteScratch(ctx, c, got) })
	return got
}

// deleteScratch removes a scratch object, tolerating its absence. It refuses to
// touch anything outside the reserved range so that a bad id in a test can
// never delete a production key.
func deleteScratch(ctx context.Context, c *yubihsm.Client, id uint16) {
	if id < scratchBase || id > scratchTop {
		panic(fmt.Sprintf("yubihsmtest: refusing to delete 0x%04x outside the reserved scratch range", id))
	}
	_ = c.DeleteObject(ctx, id, yubihsm.ObjectTypeAsymmetricKey)
}

// TestMain sweeps the scratch range before anything runs.
//
// The sweep has to happen here rather than in each test: a DELETE OBJECT that
// lands inside an audit window a test has already anchored looks exactly like
// an unaccounted device operation, which the audit tier is built to reject. Do
// it once, before any window is opened, and that false positive cannot occur.
func TestMain(m *testing.M) {
	if !enabled() {
		fmt.Fprintf(os.Stderr, "yubihsmtest: %s is not set; all hardware tests will skip\n", envEnable)
		os.Exit(m.Run())
	}

	// The PKCS#11 module reads its connector from this file. Write one for the
	// whole run so the module and the native driver agree on the device, and so
	// the run does not depend on a system-wide /etc/yubihsm_pkcs11.conf.
	confDir, err := os.MkdirTemp("", "yubihsmtest-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "yubihsmtest: creating the module config dir: %v\n", err)
		os.Exit(1)
	}
	confPath := confDir + "/yubihsm_pkcs11.conf"
	if err := os.WriteFile(confPath, []byte("connector = "+connectorURL()+"\n"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "yubihsmtest: writing %s: %v\n", confPath, err)
		os.Exit(1)
	}
	os.Setenv("YUBIHSM_PKCS11_CONF", confPath)

	sweepScratch()
	code := m.Run()
	sweepScratch()
	os.RemoveAll(confDir)
	os.Exit(code)
}

// --- audit log pressure ---------------------------------------------------

// keepLogSpace makes room for at least want more audited operations.
//
// A device with forced audit stops accepting audited commands once its 62-slot
// log is full — it does not overwrite. A suite that signs, generates and
// deletes keys across six tiers produces far more than 62 audited operations,
// so without this the run would fail partway through with a device error that
// looks like a driver bug and is really a full log.
//
// Draining acknowledges entries, which removes them from the device for good.
// That is the same thing the deployment's audit collector does, and it is why
// this suite must not be pointed at a device a deployment is collecting from.
func keepLogSpace(t *testing.T, want int) {
	t.Helper()
	withClient(t, func(ctx context.Context, c *yubihsm.Client) {
		info, err := c.DeviceInfo(ctx)
		if err != nil {
			t.Fatalf("reading audit log occupancy: %v", err)
		}
		if int(info.LogTotal)-int(info.LogUsed) >= want {
			return
		}
		log, err := c.GetLogEntries(ctx)
		if err != nil {
			t.Fatalf("reading the audit log before draining it: %v", err)
		}
		if len(log.Entries) == 0 {
			t.Fatalf("the audit log reports %d/%d used but holds no entries to drain",
				info.LogUsed, info.LogTotal)
		}
		last := log.Entries[len(log.Entries)-1].Number
		if err := c.SetLogIndex(ctx, last); err != nil {
			t.Fatalf("draining the audit log up to entry %d: %v", last, err)
		}
		t.Logf("drained %d audit log entries (up to #%d) to make room for %d more operations",
			len(log.Entries), last, want)
	})
}

// labelPrefix marks every object this suite creates, at any handle. The
// PKCS#11 module allocates its own object ids rather than accepting one, so
// keys created through it land outside the reserved scratch range and can only
// be found — and cleaned up — by label.
const labelPrefix = "t172-"

// sweepLabel deletes the object carrying exactly this label, whatever handle it
// ended up at. Used by the PKCS#11 tier, whose keys the scratch-range sweep
// cannot see.
func sweepLabel(t *testing.T, lbl string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := yubihsm.Open(ctx, driverConfig())
	if err != nil {
		t.Logf("could not clean up %q: %v", lbl, err)
		return
	}
	defer func() { _ = c.Close() }()
	for _, o := range labelledObjects(ctx, c, func(l string) bool { return l == lbl }) {
		if err := c.DeleteObject(ctx, o.ID, o.Type); err != nil {
			t.Logf("leaving %q (0x%04x) on the device: %v", lbl, o.ID, err)
		}
	}
}

// sweepableTypes are the object types this suite can create. It is not just
// asymmetric keys: the PKCS#11 module turns an RSA key whose template asks for
// CKA_WRAP into a device *wrap-key* object, a different type at a different
// handle — so a sweep that looked only at asymmetric keys would silently leak
// one 904-byte object per run until the device ran out of storage and started
// answering CKR_DEVICE_MEMORY.
var sweepableTypes = []byte{
	yubihsm.ObjectTypeAsymmetricKey,
	yubihsm.ObjectTypeWrapKey,
	yubihsm.ObjectTypeHMACKey,
	yubihsm.ObjectTypeOpaque,
}

// labelledObjects returns every object of a sweepable type whose label matches.
func labelledObjects(ctx context.Context, c *yubihsm.Client, match func(string) bool) []yubihsm.ObjectInfo {
	var out []yubihsm.ObjectInfo
	for _, ot := range sweepableTypes {
		objs, err := c.ListObjects(ctx, ot)
		if err != nil {
			continue
		}
		for _, o := range objs {
			info, err := c.GetObjectInfo(ctx, o.ID, o.Type)
			if err != nil {
				continue
			}
			if match(info.Label) {
				out = append(out, *info)
			}
		}
	}
	return out
}

// sweepScratch deletes every object this suite could have left behind: any
// asymmetric key in the reserved handle range, and any key whose label carries
// the suite's prefix wherever it sits. Failures are reported, not fatal: an
// unreachable device must skip the suite, not break it.
func sweepScratch() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := yubihsm.Open(ctx, driverConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "yubihsmtest: scratch sweep skipped (%v)\n", err)
		return
	}
	defer func() { _ = c.Close() }()
	mine := func(lbl string) bool { return strings.HasPrefix(lbl, labelPrefix) }
	for _, o := range labelledObjects(ctx, c, mine) {
		if err := c.DeleteObject(ctx, o.ID, o.Type); err != nil {
			fmt.Fprintf(os.Stderr, "yubihsmtest: leaving object 0x%04x (%q) behind: %v\n", o.ID, o.Label, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "yubihsmtest: swept leftover object 0x%04x (%q)\n", o.ID, o.Label)
	}
	// Anything sitting in the reserved handle range is ours too, whatever it
	// is labelled: a run killed between generate and label assignment leaves
	// one behind.
	objs, err := c.ListObjects(ctx, yubihsm.ObjectTypeAsymmetricKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "yubihsmtest: scratch sweep could not list objects: %v\n", err)
		return
	}
	for _, o := range objs {
		if o.ID < scratchBase || o.ID > scratchTop {
			continue
		}
		if err := c.DeleteObject(ctx, o.ID, o.Type); err != nil {
			fmt.Fprintf(os.Stderr, "yubihsmtest: leaving scratch object 0x%04x behind: %v\n", o.ID, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "yubihsmtest: swept leftover scratch object 0x%04x\n", o.ID)
	}
}
