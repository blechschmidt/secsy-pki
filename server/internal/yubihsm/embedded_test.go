package yubihsm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// deviceInfoReply is a GET DEVICE INFO payload for a device reporting the given
// serial, shaped the way the hardware does: firmware triple, serial, log
// capacity, then the algorithm list.
func deviceInfoReply(serial uint32) []byte {
	b := make([]byte, 9)
	b[0], b[1], b[2] = 2, 4, 0
	binary.BigEndian.PutUint32(b[3:7], serial)
	b[7], b[8] = 62, 0
	return append(b, 0x01, 0x02)
}

// startTestEmbedded runs the relay over a fake device on a loopback port the
// kernel picks, so tests never collide with each other or with a real
// yubihsm-connector on 12345.
func startTestEmbedded(t *testing.T, d *fakeDevice, onOp func()) *Embedded {
	t.Helper()
	d.plain[cmdGetDeviceInfo] = func([]byte) ([]byte, error) { return deviceInfoReply(31650425), nil }

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	e, err := startEmbeddedOver(context.Background(), d, ln, log.New(io.Discard, "", 0), onOp)
	if err != nil {
		t.Fatalf("starting the embedded connector: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// overHTTP opens a client that reaches the relay the way an out-of-process
// client does. It cannot go through OpenTransport: that deliberately
// short-circuits the relay's own URL to the shared in-process handle, which is
// the opposite of what these tests need to exercise.
func overHTTP(t *testing.T, e *Embedded) *Client {
	t.Helper()
	tr, err := openConnector(e.URL())
	if err != nil {
		t.Fatalf("opening an HTTP transport to %s: %v", e.URL(), err)
	}
	c, err := OpenOver(context.Background(), tr, Config{AuthKeyID: 1, Password: "password"})
	if err != nil {
		t.Fatalf("opening a session through the relay's HTTP endpoint: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestEmbeddedStatusDocumentSatisfiesTheModule(t *testing.T) {
	e := startTestEmbedded(t, newFakeDevice("password"), nil)

	resp, err := http.Get(e.URL() + connectorStatusPath) //nolint:noctx // test-local, bounded by the test timeout
	if err != nil {
		t.Fatalf("GET %s: %v", connectorStatusPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the status document: %v", err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			fields[k] = v
		}
	}
	// status=OK is the field libyubihsm gates on: without it the module reports
	// "connector not found" and never opens a session, so a relay that got
	// everything else right would still not carry a signature.
	if fields["status"] != "OK" {
		t.Fatalf("status document does not report status=OK: %q", body)
	}
	if fields["serial"] != "31650425" {
		t.Errorf("status serial = %q, want the device's own 31650425", fields["serial"])
	}
	_, port, _ := net.SplitHostPort(e.Addr())
	if fields["port"] != port {
		t.Errorf("status port = %q, want %q", fields["port"], port)
	}
	// Dotted-numeric, because libyubihsm parses this field as a release number.
	if strings.Count(fields["version"], ".") != 2 {
		t.Errorf("status version = %q, want a dotted release number", fields["version"])
	}
	if !strings.Contains(fields["implementation"], "secsy-pki") {
		t.Errorf("status document does not identify the relay: %q", body)
	}
}

func TestEmbeddedStatusReportsNoDeviceOnceClosed(t *testing.T) {
	d := newFakeDevice("password")
	d.plain[cmdGetDeviceInfo] = func([]byte) ([]byte, error) { return deviceInfoReply(31650425), nil }
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	e, err := startEmbeddedOver(context.Background(), d, ln, log.New(io.Discard, "", 0), nil)
	if err != nil {
		t.Fatalf("starting the embedded connector: %v", err)
	}
	// The status document is how a client tells "there is a relay but it has no
	// device" from "there is no relay" — which is the distinction a health
	// check needs, and the one libyubihsm gates a session on.
	rec := httptestGet(t, e, connectorStatusPath)
	if !strings.Contains(rec, "status=OK") {
		t.Fatalf("a running relay reported %q", rec)
	}
	// Once the device is released the answer has to change, including for a
	// request already in flight when Close began: reporting status=OK with no
	// device is the one thing that would make a client open a session it cannot
	// use.
	if err := e.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if got := statusOf(e); !strings.Contains(got, "status=NO_DEVICE") {
		t.Fatalf("a closed relay reported %q, want status=NO_DEVICE", got)
	}
}

// statusOf renders the status document directly, without a live listener.
func statusOf(e *Embedded) string {
	w := &recorder{header: http.Header{}}
	e.handleStatus(w, &http.Request{Method: http.MethodGet})
	return w.body.String()
}

func httptestGet(t *testing.T, e *Embedded, path string) string {
	t.Helper()
	resp, err := http.Get(e.URL() + path) //nolint:noctx // test-local
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

type recorder struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(code int)        { r.code = code }

func TestEmbeddedCarriesASecureChannelOverHTTP(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	e := startTestEmbedded(t, d, nil)

	// The full client, over the relay's HTTP endpoint: SCP03 mutual
	// authentication and MAC chaining end to end, exactly as the PKCS#11
	// module's own secure channel would.
	ctx := context.Background()
	c := overHTTP(t, e)
	got, err := c.Echo(ctx, []byte("through the relay"))
	if err != nil {
		t.Fatalf("echo through the embedded connector: %v", err)
	}
	if string(got) != "through the relay" {
		t.Fatalf("echo returned %q", got)
	}
}

func TestEmbeddedSharesOneClaimWithTheNativeDriver(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	e := startTestEmbedded(t, d, nil)
	ctx := context.Background()

	// This is the behaviour the whole design rests on: in-process code that
	// asks for the device by its yhusb:// URL — every audit, attestation and
	// provisioning path does — must be handed the relay's claim rather than
	// attempt a second one.
	for _, url := range []string{"", "yhusb://", "yhusb://serial=31650425", "yhusb://0031650425", e.URL(), e.URL() + "/"} {
		tr, err := OpenTransport(ctx, url)
		if err != nil {
			t.Fatalf("OpenTransport(%q) while the relay holds the device: %v", url, err)
		}
		if _, ok := tr.(*sharedTransport); !ok {
			t.Fatalf("OpenTransport(%q) returned %T, want the relay's shared handle", url, tr)
		}
		// Closing a borrowed view must not take the device away from anyone
		// else: a Client owns and closes its transport.
		if err := tr.Close(); err != nil {
			t.Fatalf("closing a borrowed view: %v", err)
		}
		if _, err := transact(ctx, e.Transport(), cmdGetDeviceInfo, nil); err != nil {
			t.Fatalf("the device became unusable after a borrower closed its view (%q): %v", url, err)
		}
	}
}

// The relay has to recognise its own address however the configuration spells
// it. A deployment naming http://localhost:12345 while the relay is bound to
// 127.0.0.1:12345 is the same endpoint, and treating it as a different one does
// not merely cost a loopback round trip: it would route the drain's own traffic
// back through the relay's HTTP front end, where the operation hook would
// signal the need for another drain on every cycle.
func TestEmbeddedRecognisesEverySpellingOfItsOwnAddress(t *testing.T) {
	d := newFakeDevice("password")
	d.plain[cmdGetDeviceInfo] = func([]byte) ([]byte, error) { return deviceInfoReply(31650425), nil }
	// A fixed port, because the point is comparing host spellings at one port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("splitting %q: %v", ln.Addr().String(), err)
	}
	e, err := startEmbeddedOver(context.Background(), d, ln, log.New(io.Discard, "", 0), nil)
	if err != nil {
		t.Fatalf("starting the embedded connector: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	for _, spelling := range []string{
		"http://127.0.0.1:" + port,
		"http://localhost:" + port,
		"http://LOCALHOST:" + port + "/",
		"http://[::1]:" + port,
		"http://0.0.0.0:" + port,
	} {
		tr, ok := sharedTransportFor(spelling)
		if !ok {
			t.Errorf("%s was not recognised as the relay's own address", spelling)
			continue
		}
		if _, isShared := tr.(*sharedTransport); !isShared {
			t.Errorf("%s resolved to %T rather than the shared handle", spelling, tr)
		}
	}
	// A different port on the same host is somebody else's connector, and must
	// not be answered by this device.
	other := "http://127.0.0.1:1"
	if _, ok := sharedTransportFor(other); ok {
		t.Errorf("%s was answered by a relay bound to port %s", other, port)
	}
}

func TestEmbeddedRefusesADifferentSerial(t *testing.T) {
	e := startTestEmbedded(t, newFakeDevice("password"), nil)
	// A request for other hardware must not be answered by the device we hold.
	// Collecting an audit log or an attestation from one device while naming
	// another produces evidence that verifies and describes nothing.
	if _, ok := sharedTransportFor("yhusb://serial=99999999"); ok {
		t.Fatal("the relay answered for a serial it does not hold")
	}
	if _, ok := sharedTransportFor("http://192.0.2.1:12345"); ok {
		t.Fatal("the relay answered for a connector URL that is not its own")
	}
	_ = e
}

func TestEmbeddedRefusesASecondRelayInTheSameProcess(t *testing.T) {
	startTestEmbedded(t, newFakeDevice("password"), nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if _, err := startEmbeddedOver(context.Background(), newFakeDevice("password"), ln,
		log.New(io.Discard, "", 0), nil); err == nil {
		t.Fatal("a second relay started in a process that already holds the device")
	}
}

func TestEmbeddedNotifiesForOperationsButNotForProbes(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	var ops atomic.Int64
	e := startTestEmbedded(t, d, func() { ops.Add(1) })
	ctx := context.Background()

	// A device-info probe is unaudited and a PKCS#11 module makes one on every
	// token query, so it must not drive the drain.
	tr, err := openConnector(e.URL())
	if err != nil {
		t.Fatalf("opening an HTTP transport: %v", err)
	}
	if _, err := transact(ctx, tr, cmdGetDeviceInfo, nil); err != nil {
		t.Fatalf("device info through the relay: %v", err)
	}
	if n := ops.Load(); n != 0 {
		t.Fatalf("a device-info probe signalled %d operation(s)", n)
	}

	// A session message might be anything — the relay cannot see inside SCP03 —
	// so it signals, which is what makes collection follow the operations of a
	// client this process has no other view of.
	c := overHTTP(t, e)
	before := ops.Load()
	if _, err := c.Echo(ctx, []byte("x")); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if n := ops.Load(); n <= before {
		t.Fatal("a relayed session command signalled no operation")
	}
	// Tearing the session down signals too, and must: CLOSE SESSION travels
	// *inside* the secure channel, so the relay sees the same opaque session
	// message it sees for a signature. Erring toward a drain that finds nothing
	// is the only safe reading of an encrypted command, and it is why the
	// collector coalesces signals rather than counting them.
	before = ops.Load()
	if err := c.Close(); err != nil {
		t.Fatalf("closing the session: %v", err)
	}
	if n := ops.Load(); n <= before {
		t.Fatal("a session teardown inside the secure channel was treated as unaudited")
	}
}

func TestEmbeddedDoesNotNotifyForItsOwnInProcessTraffic(t *testing.T) {
	d := newFakeDevice("password")
	var ops atomic.Int64
	e := startTestEmbedded(t, d, func() { ops.Add(1) })

	// The drain reads the device through the shared handle, not through HTTP.
	// If it were counted as an operation, every cycle would signal the need for
	// another one and the collector would spin against the device forever.
	for i := 0; i < 5; i++ {
		if _, err := transact(context.Background(), e.Transport(), cmdGetDeviceInfo, nil); err != nil {
			t.Fatalf("in-process device info: %v", err)
		}
	}
	if n := ops.Load(); n != 0 {
		t.Fatalf("in-process traffic signalled %d operation(s)", n)
	}
}

func TestEmbeddedSerialisesConcurrentClients(t *testing.T) {
	d := newFakeDevice("password")
	// A handler that notices overlap: the relay must never have two
	// request/response pairs in flight, or one client's reply could be returned
	// to another. That is the entire guarantee that lets several clients share
	// one device, and it is the guarantee Yubico's own connector provides.
	var inFlight atomic.Int32
	var overlapped atomic.Bool
	d.plain[cmdGetDeviceInfo] = func([]byte) ([]byte, error) {
		if inFlight.Add(1) > 1 {
			overlapped.Store(true)
		}
		time.Sleep(time.Millisecond)
		inFlight.Add(-1)
		return deviceInfoReply(31650425), nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	e, err := startEmbeddedOver(context.Background(), d, ln, log.New(io.Discard, "", 0), nil)
	if err != nil {
		t.Fatalf("starting the embedded connector: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tr, err := openConnector(e.URL())
			if err != nil {
				errs <- fmt.Errorf("client %d: %w", i, err)
				return
			}
			defer func() { _ = tr.Close() }()
			body, err := transact(ctx, tr, cmdGetDeviceInfo, nil)
			if err != nil {
				errs <- fmt.Errorf("client %d: %w", i, err)
				return
			}
			info, err := parseDeviceInfo(body)
			if err != nil {
				errs <- fmt.Errorf("client %d: %w", i, err)
				return
			}
			if info.Serial != "31650425" {
				errs <- fmt.Errorf("client %d got serial %q", i, info.Serial)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if overlapped.Load() {
		t.Fatal("two relayed commands reached the device at once")
	}
}

func TestEmbeddedRejectsOversizedAndEmptyMessages(t *testing.T) {
	e := startTestEmbedded(t, newFakeDevice("password"), nil)

	for _, tc := range []struct {
		name string
		body []byte
		want int
	}{
		{"empty", nil, http.StatusBadRequest},
		{"oversized", bytes.Repeat([]byte{0}, maxMessageSize+1), http.StatusRequestEntityTooLarge},
	} {
		resp, err := http.Post(e.URL()+connectorAPIPath, "application/octet-stream", bytes.NewReader(tc.body)) //nolint:noctx // test-local
		if err != nil {
			t.Fatalf("%s: POST: %v", tc.name, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
}

func TestEmbeddedReportsAddressInUseDistinctly(t *testing.T) {
	// A `secsy-ca` invocation in a container where the server already runs its
	// relay has to be able to tell "somebody else is already multiplexing this
	// device" from a real failure, because the right answer to the first is to
	// use that relay rather than to give up.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_, err = StartEmbedded(context.Background(), EmbeddedConfig{
		Listen: ln.Addr().String(),
		Logger: log.New(io.Discard, "", 0),
	})
	if !errors.Is(err, ErrEmbeddedAddrInUse) {
		t.Fatalf("binding a taken address returned %v, want ErrEmbeddedAddrInUse", err)
	}
	// And it must fail *before* claiming the device, so the caller is free to
	// go use whatever is already there.
	if sharedDevice.Load() != nil {
		t.Fatal("a relay that could not bind still registered as the device holder")
	}
}

func TestEmbeddedRefusesANonUSBDeviceURL(t *testing.T) {
	_, err := StartEmbedded(context.Background(), EmbeddedConfig{
		DeviceURL: "http://192.0.2.1:12345",
		Listen:    "127.0.0.1:0",
		Logger:    log.New(io.Discard, "", 0),
	})
	if err == nil {
		t.Fatal("the relay accepted a connector URL as the device to hold")
	}
	if !strings.Contains(err.Error(), "yhusb://") {
		t.Fatalf("the refusal does not name the expected form: %v", err)
	}
}

// --- joining a relay another process runs ---------------------------------

// A single-container deployment has one relay and several processes that need
// the device: the server holds it, and every `secsy-ca` an operator execs into
// that container finds the address already bound and uses it instead. That
// worked for Yubico's PKCS#11 module, which is handed the address — and not for
// the native driver, which kept resolving the configured yubihsm.connector_url.
// With the natural single-container spelling, yhusb://, every command that needs
// the driver rather than the module (the whole of hsm-audit and hsm-attest)
// reached for a USB claim another process was holding and reported the device
// "unreachable". Signing worked; auditing did not.
func TestJoinedRelayServesDirectUSBURLs(t *testing.T) {
	d := newFakeDevice("password")
	d.handlers[cmdEcho] = func(data []byte) ([]byte, error) { return data, nil }
	e := startTestEmbedded(t, d, nil)

	// Simulate the relay belonging to another process: it keeps serving, but
	// this process has no in-process handle to it.
	clearSharedDevice(e)
	JoinRelay(e.URL(), "31650425")
	t.Cleanup(func() { JoinRelay("", "") })

	tr, err := OpenTransport(context.Background(), "yhusb://")
	if err != nil {
		t.Fatalf("a direct-USB URL was not routed to the joined relay: %v", err)
	}
	defer func() { _ = tr.Close() }()
	if tr.Describe() != e.URL() {
		t.Fatalf("the transport reports %q, want the joined relay %q", tr.Describe(), e.URL())
	}

	c, err := OpenOver(context.Background(), tr, Config{AuthKeyID: 1, Password: "password"})
	if err != nil {
		t.Fatalf("opening a session through the joined relay: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Echo(context.Background(), []byte("hello")); err != nil {
		t.Fatalf("echo through the joined relay: %v", err)
	}
}

// The relay's claim is not this process's to lend out to the wrong device: a URL
// naming a different serial must not be answered by it. Addressing the wrong
// hardware is the one failure this subsystem cannot have — an audit log
// collected from one device while describing another verifies perfectly and
// means nothing.
func TestJoinedRelayDoesNotAnswerForAnotherSerial(t *testing.T) {
	JoinRelay("http://127.0.0.1:12345", "31650425")
	t.Cleanup(func() { JoinRelay("", "") })

	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"", true},
		{"yhusb://", true},
		{"yhusb://serial=31650425", true},
		{"yhusb://0031650425", true}, // zero-padded, as the USB descriptor spells it
		{"yhusb://serial=99999999", false},
		{"http://10.0.0.1:12345", false}, // an endpoint the operator named explicitly
	} {
		got, ok := joinedRelayFor(tc.url)
		if ok != tc.want {
			t.Errorf("joinedRelayFor(%q) routed=%v, want %v", tc.url, ok, tc.want)
		}
		if ok && got != "http://127.0.0.1:12345" {
			t.Errorf("joinedRelayFor(%q) = %q, want the joined relay", tc.url, got)
		}
	}
}

// With no relay joined — every deployment that holds the device itself — nothing
// is rerouted.
func TestNoJoinedRelayLeavesRoutingAlone(t *testing.T) {
	JoinRelay("", "")
	if url, ok := JoinedRelay(); ok {
		t.Fatalf("a relay is registered as joined (%q) with none set", url)
	}
	if _, ok := joinedRelayFor("yhusb://"); ok {
		t.Fatal("a direct-USB URL was rerouted with no relay joined")
	}
}

// An in-process relay still wins: it is the same claim, reached without the HTTP
// hop, and routing through the hop would put the drain's own traffic through the
// relay's operation hook.
func TestAnOwnedRelayTakesPrecedenceOverAJoinedOne(t *testing.T) {
	d := newFakeDevice("password")
	e := startTestEmbedded(t, d, nil)
	JoinRelay("http://127.0.0.1:1", "31650425") // somewhere that cannot answer
	t.Cleanup(func() { JoinRelay("", "") })

	tr, err := OpenTransport(context.Background(), "yhusb://")
	if err != nil {
		t.Fatalf("OpenTransport: %v", err)
	}
	defer func() { _ = tr.Close() }()
	if _, ok := tr.(*sharedTransport); !ok {
		t.Fatalf("got a %T, want this process's own shared device handle", tr)
	}
	_ = e
}
