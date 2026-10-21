package yubihsm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// errTransportRead marks a failure to read the device's reply, as opposed to a
// failure to send one or a failure the device itself reported. Reset is the one
// operation for which it is an expected outcome: the device drops the USB
// connection as it reboots.
var errTransportRead = errors.New("no reply from the device")

// ErrDeviceBusy marks a direct-USB open that failed because another process
// holds the device's interface.
//
// It is a sentinel rather than just a message because the condition has one
// specific, non-obvious cause and one specific fix, and callers need to act on
// it rather than merely print it. Only one process may claim the YubiHSM's USB
// interface, and Yubico's PKCS#11 module claims it for as long as it has a
// session open — which, behind a session pool, is the whole life of the
// process. So a deployment that signs through PKCS#11 and drains the device
// audit log through this driver on the same `yhusb://` device never drains
// anything: every cycle fails here. The audit subsystem's job is to notice that
// and say so at startup, instead of letting a force-audited device fill its
// 62-entry log and stop serving signatures.
//
// A connector multiplexes the device, which is why the fix is to have one in
// the path: the embedded one this process can run itself (embedded.go), or
// Yubico's daemon when something outside this process needs the device too.
var ErrDeviceBusy = errors.New("the YubiHSM USB interface is held by another process")

// IsDirectUSB reports whether url selects the direct-USB transport, where the
// device cannot be shared between processes. An empty URL does, because that is
// what OpenTransport resolves it to.
//
// It lives next to OpenTransport so the two cannot disagree about what a URL
// means: a caller checking for "yhusb://" by hand would miss both the empty
// string and the serial-qualified form.
func IsDirectUSB(url string) bool {
	url = strings.TrimSpace(url)
	return url == "" || url == "yhusb://" || strings.HasPrefix(url, "yhusb://")
}

// Transport carries whole protocol messages to and from a YubiHSM 2.
//
// Two are provided: a direct USB transport that talks to the device the same
// way yubihsm-connector does, and an HTTP transport that talks *to* a
// yubihsm-connector. Both are request/response and are not safe for concurrent
// use; Client serialises access.
type Transport interface {
	// Transact writes one message and returns the device's reply.
	Transact(ctx context.Context, msg []byte) ([]byte, error)
	// Close releases the underlying device or connection.
	Close() error
	// Describe names the endpoint for error messages.
	Describe() string
}

// OpenTransport connects to the device named by a yubihsm-shell style connector
// URL:
//
//	yhusb://                 the single attached YubiHSM over USB
//	yhusb://serial=0123456   a specific device, by USB serial number
//	http://host:12345        a yubihsm-connector
//	https://host:12345       likewise, over TLS
//
// An empty url means yhusb://: direct USB is the deployment this codebase
// targets, and it avoids running a connector daemon that would have to be
// trusted with the plaintext protocol stream.
func OpenTransport(ctx context.Context, url string) (Transport, error) {
	url = strings.TrimSpace(url)
	// An embedded connector in this process already holds the device, and the
	// claim it holds is the only one there is. Anything here addressing that
	// device gets the shared handle — not a second claim that could only fail,
	// and not a loopback round trip through our own HTTP server.
	if t, ok := sharedTransportFor(url); ok {
		return t, nil
	}
	// Failing that, a connector in *another* process may hold it, which this one
	// has joined rather than competed with. Then the device is reachable, but
	// only over that connector: the USB claim is somebody else's.
	if relay, ok := joinedRelayFor(url); ok {
		return openConnector(relay)
	}
	switch {
	case url == "" || url == "yhusb://":
		return openUSB(ctx, "")
	case strings.HasPrefix(url, "yhusb://"):
		return openUSB(ctx, usbSerialFromURL(strings.TrimPrefix(url, "yhusb://")))
	case strings.HasPrefix(url, "http://"), strings.HasPrefix(url, "https://"):
		return openConnector(url)
	default:
		return nil, fmt.Errorf("unsupported YubiHSM connector URL %q: want yhusb://, http:// or https://", url)
	}
}

// usbSerialFromURL extracts the serial from a yhusb:// authority. yubihsm-shell
// accepts "yhusb://serial=0123456789"; a bare authority is also treated as a
// serial so "yhusb://0123456789" works.
func usbSerialFromURL(rest string) string {
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return ""
	}
	if v, ok := strings.CutPrefix(rest, "serial="); ok {
		return v
	}
	return rest
}

// The process's device holder.
//
// An embedded connector (see embedded.go) claims the YubiHSM's USB interface for
// its whole life, which is what lets the PKCS#11 module and this driver share
// one device. The consequence is that no other code in the process may open
// that device directly: openUSB would block on the process-wide USB slot and
// then fail on the kernel's exclusive claim. So the relay registers itself here
// and OpenTransport routes to it.
//
// The registry is package-level rather than threaded through callers for the
// same reason the command observer is: the native driver is reached from a
// dozen places — the audit drain, provisioning, key and device attestation,
// commitments, the doctor, the CLI — each of which opens its own short-lived
// client from a configuration value. A parameter would have to be added to
// every one of them, and silently forgotten by the next one written.
var sharedDevice atomic.Pointer[Embedded]

// setSharedDevice registers e as this process's device holder.
//
// Two relays in one process would be two claims on one interface, so the second
// is refused rather than left to fail later with an EBUSY whose cause is much
// harder to see from where it surfaces.
func setSharedDevice(e *Embedded) error {
	if !sharedDevice.CompareAndSwap(nil, e) {
		return fmt.Errorf("an embedded YubiHSM connector is already running in this process on %s",
			sharedDevice.Load().URL())
	}
	return nil
}

// clearSharedDevice deregisters e, if it is still the registered holder.
func clearSharedDevice(e *Embedded) { sharedDevice.CompareAndSwap(e, nil) }

// sharedTransportFor returns the multiplexed device handle when url addresses
// the device an embedded connector in this process holds.
//
// Both spellings of that device match, because both occur in practice. A
// yhusb:// URL is what the audit and attestation paths carry when no connector
// is configured; the relay's own http:// URL is what they carry once the
// PKCS#11 configuration has been pointed at it, since the native driver resolves
// its endpoint from the same place the module does (hsm.EffectiveConnectorURL).
// Routing the second case here as well is what keeps a drain from making an
// HTTP request to its own process — harmless in itself, but it would put the
// drain's own traffic through the relay's operation hook and have each cycle
// signal the need for another.
//
// A yhusb:// URL that names a *different* serial does not match. Addressing the
// wrong hardware is the one failure this subsystem must never have: an audit
// log or attestation collected from one device while describing another would
// verify perfectly and mean nothing.
func sharedTransportFor(url string) (Transport, bool) {
	e := sharedDevice.Load()
	if e == nil {
		return nil, false
	}
	url = strings.TrimSpace(url)
	if IsDirectUSB(url) {
		serial := usbSerialFromURL(strings.TrimPrefix(url, "yhusb://"))
		if serial != "" && e.Serial() != "" && !sameSerial(serial, e.Serial()) {
			return nil, false
		}
		return e.Transport(), true
	}
	if sameConnectorEndpoint(url, e.URL()) {
		return e.Transport(), true
	}
	return nil, false
}

// The relay this process joined.
//
// A single-container deployment runs one relay and several processes that need
// the device: the server holds it, and every `secsy-ca` the operator execs into
// that container finds the address already bound. hsm.StartEmbeddedConnector
// handles that by using the existing relay instead of failing — but it used to
// point only Yubico's PKCS#11 module at it. The native driver went on resolving
// the configured yubihsm.connector_url, which for the natural single-container
// spelling is yhusb://, so every command that needs the driver rather than the
// module — the whole of hsm-audit and hsm-attest — reached for the USB claim the
// other process was holding and reported the device "unreachable". Half a device:
// signing worked, auditing did not.
//
// Registering the joined address here closes that. It is deliberately not the
// same thing as setSharedDevice: there is no in-process handle to share, the
// relay is somebody else's, and every message takes the HTTP hop that owner's
// clients take.
var joinedDevice atomic.Pointer[joinedRelay]

// joinedRelay is a connector another process serves for the local USB device.
type joinedRelay struct {
	url string
	// serial is the device the relay reports holding, or "" when it could not be
	// read. It exists so a yhusb://serial=N URL naming a *different* device is
	// not quietly answered by this relay — addressing the wrong hardware is the
	// one failure the audit subsystem must never have.
	serial string
}

// JoinRelay records that url is a yubihsm-connector serving the USB device this
// process would otherwise have claimed, so direct-USB URLs resolve to it.
// serial is the device it holds, or "" when that could not be determined.
//
// Passing an empty url deregisters, which is what a process does if it later
// takes the claim itself.
func JoinRelay(url, serial string) {
	url = strings.TrimSpace(url)
	if url == "" {
		joinedDevice.Store(nil)
		return
	}
	joinedDevice.Store(&joinedRelay{url: url, serial: strings.TrimSpace(serial)})
}

// JoinedRelay reports the relay this process joined, if any.
func JoinedRelay() (string, bool) {
	if j := joinedDevice.Load(); j != nil {
		return j.url, true
	}
	return "", false
}

// joinedRelayFor returns the joined relay's URL when url addresses the device it
// holds by direct USB.
//
// Only direct-USB URLs are rerouted. An explicit http:// or https:// URL names
// an endpoint the operator chose and is used as given — including the joined
// relay's own address, which reaches the same place by the same hop.
func joinedRelayFor(url string) (string, bool) {
	j := joinedDevice.Load()
	if j == nil {
		return "", false
	}
	url = strings.TrimSpace(url)
	if !IsDirectUSB(url) {
		return "", false
	}
	serial := usbSerialFromURL(strings.TrimPrefix(url, "yhusb://"))
	if serial != "" && j.serial != "" && !sameSerial(serial, j.serial) {
		return "", false
	}
	return j.url, true
}

// sameSerial compares two device serial numbers.
//
// They are compared numerically because the two places a serial comes from
// disagree on formatting: the USB string descriptor is zero-padded
// ("0031650425") while the device reports its own serial as a plain integer
// (31650425), and an operator configuring one will have seen either.
func sameSerial(a, b string) bool {
	return a == b || strings.TrimLeft(a, "0") == strings.TrimLeft(b, "0")
}
