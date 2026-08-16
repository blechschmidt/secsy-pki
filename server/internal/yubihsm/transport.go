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
