//go:build linux

package yubihsm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Direct USB transport for the YubiHSM 2, implemented on Linux usbfs.
//
// The device speaks its protocol over a pair of vendor-specific bulk endpoints;
// there is nothing between the framing in protocol.go and the wire. Driving it
// from Go means submitting bulk transfers ourselves, which usbfs exposes as a
// synchronous ioctl on /dev/bus/usb/<bus>/<device>. That is the whole of the
// dependency: no libusb, no cgo, and no yubihsm-connector daemon in the path of
// a session whose plaintext it would otherwise see.

// YubiHSM 2 USB identity and endpoints. These are fixed for the product: a
// single vendor-specific interface with one bulk pair.
const (
	usbVendorID    = 0x1050 // Yubico
	usbProductID   = 0x0030 // YubiHSM 2
	usbInterface   = 0
	usbEndpointOut = 0x01
	usbEndpointIn  = 0x81
	usbPacketSize  = 64
)

// usbfs ioctl request numbers, from <linux/usbdevice_fs.h>.
//
// The fixed-size ones are spelled out so they are reviewable against the header.
// The bulk-transfer number encodes the size of a struct whose layout is
// word-size dependent, so it is assembled below rather than written as a
// constant that would be silently wrong on a 32-bit build.
const (
	usbdevfsClaimInterface   = 0x8004550F // _IOR('U', 15, unsigned int)
	usbdevfsReleaseInterface = 0x80045510 // _IOR('U', 16, unsigned int)
	usbdevfsClearHalt        = 0x80045515 // _IOR('U', 21, unsigned int)
)

// bulkTransfer mirrors struct usbdevfs_bulktransfer.
//
// No explicit padding: Go aligns the pointer field the same way the C compiler
// does, giving 24 bytes on a 64-bit target and 16 on a 32-bit one, matching the
// kernel struct in both cases.
type bulkTransfer struct {
	endpoint uint32
	length   uint32
	timeout  uint32 // milliseconds; 0 means wait forever
	data     unsafe.Pointer
}

// usbdevfsBulk is _IOWR('U', 2, struct usbdevfs_bulktransfer): direction 3
// (read|write) in the top two bits, the struct size in bits 16..29, the 'U'
// type in bits 8..15, and command number 2 in the low byte.
var usbdevfsBulk = uintptr(3)<<30 | unsafe.Sizeof(bulkTransfer{})<<16 | uintptr('U')<<8 | 2

// defaultUSBTimeout bounds a single bulk transfer. Device operations are
// sub-second except for RSA key generation, which the audit subsystem never
// issues; the bound exists so a wedged device surfaces as an error rather than
// hanging a background collector forever.
const defaultUSBTimeout = 30 * time.Second

type usbTransport struct {
	mu     sync.Mutex
	f      *os.File
	path   string
	serial string
	// released guards the process-wide slot so it is returned exactly once.
	released bool
}

// usbSlot serialises direct USB access within this process.
//
// The interface claim is exclusive per file descriptor, so two goroutines each
// opening their own transport would collide with each other rather than share —
// a REST handler and the background audit collector both reaching for the device
// would leave one of them retrying and then failing, for no reason other than
// that they are in the same program. Queuing is the honest behaviour: the device
// can only serve one at a time regardless.
var usbSlot = make(chan struct{}, 1)

func acquireUSBSlot(ctx context.Context) error {
	select {
	case usbSlot <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for the YubiHSM to become free: %w", ctx.Err())
	}
}

func releaseUSBSlot() { <-usbSlot }

func openUSB(ctx context.Context, serial string) (Transport, error) {
	devices, err := findYubiHSMs()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no YubiHSM 2 found on USB (looking for %04x:%04x)", usbVendorID, usbProductID)
	}

	var match *usbDevice
	switch {
	case serial != "":
		for i := range devices {
			// Serials are compared numerically: the USB string descriptor is
			// zero-padded ("0031650425") while the device reports its serial as a
			// plain integer (31650425), and an operator will have seen either.
			if sameSerial(devices[i].serial, serial) {
				match = &devices[i]
				break
			}
		}
		if match == nil {
			have := make([]string, 0, len(devices))
			for _, d := range devices {
				have = append(have, d.serial)
			}
			return nil, fmt.Errorf("no YubiHSM with serial %q on USB (found: %s)", serial, strings.Join(have, ", "))
		}
	case len(devices) > 1:
		// Refusing beats picking one: the audit and attestation claims are all
		// about a *specific* device, and silently addressing the wrong one would
		// produce evidence that verifies while describing the wrong hardware.
		have := make([]string, 0, len(devices))
		for _, d := range devices {
			have = append(have, d.serial)
		}
		return nil, fmt.Errorf("%d YubiHSMs attached (serials: %s); select one with yhusb://serial=<serial>",
			len(devices), strings.Join(have, ", "))
	default:
		match = &devices[0]
	}

	if err := acquireUSBSlot(ctx); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(match.path, os.O_RDWR, 0)
	if err != nil {
		releaseUSBSlot()
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("opening %s: %w (the process needs read/write access to the USB device; "+
				"add a udev rule or run as a user in the owning group)", match.path, err)
		}
		return nil, fmt.Errorf("opening %s: %w", match.path, err)
	}

	t := &usbTransport{f: f, path: match.path, serial: match.serial}
	if err := t.claim(ctx); err != nil {
		_ = f.Close()
		releaseUSBSlot()
		return nil, err
	}

	// Drain anything a previously aborted process left in the IN endpoint. A
	// stale reply would otherwise be read as the answer to our first command,
	// desynchronising every subsequent request/response pair.
	t.drain()
	return t, nil
}

// claim takes exclusive ownership of the device's interface.
//
// Only one process may hold it, and the PKCS#11 module holds it for as long as
// it has a session open, so a server that signs through PKCS#11 and audits
// through this driver on the same USB device will collide. Much of that
// contention is momentary, so a short retry turns a transient overlap into a
// slightly slower call instead of a failed audit collection. Sustained
// contention still surfaces, with the fix named: run a yubihsm-connector, which
// exists to multiplex the device.
func (t *usbTransport) claim(ctx context.Context) error {
	const (
		attempts = 10
		backoff  = 200 * time.Millisecond
	)
	iface := uint32(usbInterface)
	var err error
	for i := 0; i < attempts; i++ {
		if err = ioctlPtr(t.f, usbdevfsClaimInterface, unsafe.Pointer(&iface)); err == nil {
			return nil
		}
		if !errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("claiming the YubiHSM USB interface on %s: %w", t.path, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("claiming the YubiHSM USB interface on %s: %w "+
		"(another process — yubihsm-connector, yubihsm-shell or the PKCS#11 module — is holding the device; "+
		"run yubihsm-connector and use an http:// connector URL so both can share it)", t.path, err)
}

func (t *usbTransport) Describe() string {
	return fmt.Sprintf("yhusb://serial=%s (%s)", t.serial, t.path)
}

func (t *usbTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil
	}
	iface := uint32(usbInterface)
	_ = ioctlPtr(t.f, usbdevfsReleaseInterface, unsafe.Pointer(&iface))
	err := t.f.Close()
	t.f = nil
	if !t.released {
		t.released = true
		releaseUSBSlot()
	}
	return err
}

func (t *usbTransport) Transact(ctx context.Context, msg []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil, fmt.Errorf("YubiHSM USB transport is closed")
	}

	timeout := defaultUSBTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d < timeout {
			timeout = d
		}
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := t.write(msg, timeout); err != nil {
		// A failed exchange leaves the endpoints in an unknown state; clearing
		// the halt condition keeps a single transient failure from poisoning
		// every later command on this handle.
		t.clearHalt()
		return nil, err
	}
	resp, err := t.read(timeout)
	if err != nil {
		t.clearHalt()
		return nil, err
	}
	return resp, nil
}

func (t *usbTransport) write(msg []byte, timeout time.Duration) error {
	n, err := t.bulk(usbEndpointOut, msg, timeout)
	if err != nil {
		return fmt.Errorf("writing %d bytes to the YubiHSM: %w", len(msg), err)
	}
	if n != len(msg) {
		return fmt.Errorf("short write to the YubiHSM: %d of %d bytes", n, len(msg))
	}
	// USB signals end-of-transfer with a short packet. A message whose length is
	// an exact multiple of the endpoint's packet size has none, so it must be
	// followed by an explicit zero-length packet or the device waits for more.
	if len(msg)%usbPacketSize == 0 {
		if _, err := t.bulk(usbEndpointOut, nil, timeout); err != nil {
			return fmt.Errorf("writing the zero-length terminator to the YubiHSM: %w", err)
		}
	}
	return nil
}

func (t *usbTransport) read(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, maxMessageSize)
	var got int
	for {
		n, err := t.bulk(usbEndpointIn, buf[got:], timeout)
		if err != nil {
			return nil, fmt.Errorf("reading from the YubiHSM: %w: %w", errTransportRead, err)
		}
		got += n
		if got >= 3 {
			want := 3 + int(uint16(buf[1])<<8|uint16(buf[2]))
			if want > maxMessageSize {
				return nil, fmt.Errorf("device announced a %d-byte response, above the %d-byte protocol limit", want, maxMessageSize)
			}
			if got >= want {
				return buf[:want], nil
			}
		}
		if n == 0 {
			// A zero-length packet before the announced length is reached means
			// the device ended the transfer early: the message is truncated.
			return nil, fmt.Errorf("truncated response from the YubiHSM: %d bytes", got)
		}
		if got >= len(buf) {
			return nil, fmt.Errorf("response exceeded the %d-byte protocol limit", maxMessageSize)
		}
	}
}

// drain reads and discards data left in the IN endpoint by a process that died
// mid-transaction.
//
// The timeout is short because anything to discard is already buffered: the
// device only speaks when spoken to, so a read that has to wait is a read with
// nothing to collect, and this runs on every session open.
func (t *usbTransport) drain() {
	buf := make([]byte, maxMessageSize)
	for i := 0; i < 4; i++ {
		n, err := t.bulk(usbEndpointIn, buf, 20*time.Millisecond)
		if err != nil || n == 0 {
			return
		}
	}
}

func (t *usbTransport) clearHalt() {
	for _, ep := range []uint32{usbEndpointOut, usbEndpointIn} {
		e := ep
		_ = ioctlPtr(t.f, usbdevfsClearHalt, unsafe.Pointer(&e))
	}
}

// bulk performs one synchronous usbfs bulk transfer.
func (t *usbTransport) bulk(endpoint uint32, buf []byte, timeout time.Duration) (int, error) {
	ms := timeout.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	bt := bulkTransfer{
		endpoint: endpoint,
		length:   uint32(len(buf)),
		timeout:  uint32(ms),
	}
	// usbfs requires a valid pointer even for a zero-length transfer.
	scratch := [1]byte{}
	if len(buf) > 0 {
		bt.data = unsafe.Pointer(&buf[0])
	} else {
		bt.data = unsafe.Pointer(&scratch[0])
	}

	for {
		n, err := ioctlRet(t.f, usbdevfsBulk, unsafe.Pointer(&bt))
		if errors.Is(err, unix.EINTR) {
			continue // a signal (Go's preemption uses them) is not a transfer failure
		}
		if errors.Is(err, unix.ETIMEDOUT) {
			return 0, fmt.Errorf("bulk transfer on endpoint 0x%02x timed out after %s", endpoint, timeout)
		}
		if err != nil {
			return 0, err
		}
		// bt.data is a real unsafe.Pointer, so the GC already sees the buffer
		// through it; keeping bt alive across the syscall is what makes that
		// reachability cover the kernel's use of the pointer.
		runtime.KeepAlive(&bt)
		runtime.KeepAlive(buf)
		return n, nil
	}
}

func ioctlPtr(f *os.File, req uintptr, arg unsafe.Pointer) error {
	_, err := ioctlRet(f, req, arg)
	return err
}

func ioctlRet(f *os.File, req uintptr, arg unsafe.Pointer) (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), req, uintptr(arg))
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// usbDevice is one YubiHSM found on the bus.
type usbDevice struct {
	path   string // /dev/bus/usb/<bus>/<device>
	serial string
}

// findYubiHSMs enumerates attached YubiHSM 2 devices through sysfs, which
// reports the vendor/product ids, bus/device numbers and USB serial without
// needing to issue any control transfers.
func findYubiHSMs() ([]usbDevice, error) {
	entries, err := os.ReadDir("/sys/bus/usb/devices")
	if err != nil {
		return nil, fmt.Errorf("enumerating USB devices: %w "+
			"(sysfs is required to locate the YubiHSM; use a yubihsm-connector URL instead if it is unavailable)", err)
	}
	var found []usbDevice
	for _, e := range entries {
		dir := filepath.Join("/sys/bus/usb/devices", e.Name())
		if readSysfsHex(dir, "idVendor") != usbVendorID || readSysfsHex(dir, "idProduct") != usbProductID {
			continue
		}
		bus, errBus := strconv.Atoi(readSysfsString(dir, "busnum"))
		dev, errDev := strconv.Atoi(readSysfsString(dir, "devnum"))
		if errBus != nil || errDev != nil {
			continue
		}
		found = append(found, usbDevice{
			path:   fmt.Sprintf("/dev/bus/usb/%03d/%03d", bus, dev),
			serial: readSysfsString(dir, "serial"),
		})
	}
	return found, nil
}

func readSysfsString(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readSysfsHex(dir, name string) int {
	v, err := strconv.ParseUint(readSysfsString(dir, name), 16, 32)
	if err != nil {
		return -1
	}
	return int(v)
}

// sameSerial compares serials ignoring the leading zeros the USB string
// descriptor carries but the device's own report does not.
func sameSerial(a, b string) bool {
	return a == b || strings.TrimLeft(a, "0") == strings.TrimLeft(b, "0")
}
