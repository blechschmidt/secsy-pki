package yubihsm

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
// A yubihsm-connector multiplexes the device, which is why the fix is to run
// one and point both at an http:// URL.
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
