package yubihsm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// An embedded yubihsm-connector: the device multiplexer, inside the process
// that uses the device.
//
// The problem it removes is structural, not a tuning choice. A YubiHSM 2 speaks
// over one USB interface and the kernel grants that interface to one claim. A
// deployment that signs through Yubico's PKCS#11 module and collects the device
// audit log through this driver therefore has two things reaching for one
// claim, and the module wins: it holds the interface for as long as it has a
// session, which behind a session pool is the life of the process. Every
// collection cycle then fails with EBUSY while signing carries on — the one
// failure shape that looks healthy and ends, on a force-audited device, in an
// HSM that refuses to sign because its 62-entry log filled with entries nobody
// drained. hsmaudit.DrainContention refuses to start such a deployment.
//
// The fix has always been a connector — Yubico ships one, whose entire job is
// to hold the interface and relay messages over HTTP — but running it meant a
// second process, which in a container deployment meant a second container
// alongside the CA, with a device node passed to it and a health check in front
// of it. That is a lot of orchestration for a relay, and it put the one copy of
// the one uncollected copy of an audit log behind a sidecar's lifecycle.
//
// So this is that relay, in-process. It opens the USB device once and is then
// the only thing in the deployment that holds it. The PKCS#11 module reaches it
// over loopback HTTP, speaking Yubico's connector protocol because that is what
// the module already knows how to speak. Everything in this process that needs
// the native driver — the audit drain, key and device attestation, audit-head
// commitments, provisioning — gets the same device handle directly, without a
// round trip through its own HTTP server: OpenTransport routes them here (see
// sharedTransportFor in transport.go).
//
// Two properties make this worth doing rather than merely convenient:
//
//   - One container, one process. No sidecar, no device node shared between
//     containers, no health check gating the CA on a relay's readiness.
//   - The relay sees the operations. Every command the module sends arrives
//     here as an HTTP request, so the drain can be triggered by the operation
//     that produced the log entry rather than by a timer — including operations
//     performed by something other than this program's key provider (an
//     operator's pkcs11-tool, a vendor CLI pointed at the same URL).
//
// What it is not: a security boundary. SCP03 terminates in the HSM and in each
// client, so this relay cannot read a signing request or forge an audit-log
// reply — exactly as for Yubico's connector. It binds loopback by default
// because a relay with no authentication in front of a CA's HSM has no business
// on a network, and because the clients that need it are in the same container.

const (
	// DefaultEmbeddedListen is where the relay binds when nothing says
	// otherwise: Yubico's connector port, on loopback. The port matters because
	// an operator's muscle memory and every yubihsm-shell example use it; the
	// loopback address matters because this relay has no authentication.
	DefaultEmbeddedListen = "127.0.0.1:12345"

	connectorStatusPath = "/connector/status"

	// embeddedConnectorVersion is the version the relay reports in its status
	// document. libyubihsm parses this field as a dotted release number, so it
	// has to look like one; the implementation line next to it is what actually
	// identifies the relay to a human reading the endpoint.
	embeddedConnectorVersion = "3.0.4"

	// embeddedRelayTimeout bounds one relayed command. It is generous because
	// the slowest thing a client can ask for — RSA-4096 key generation — takes
	// tens of seconds on a YubiHSM 2 and must not fail here, and finite because
	// a wedged device should surface as an error rather than an HTTP request
	// that never returns.
	embeddedRelayTimeout = 5 * time.Minute
)

// ErrEmbeddedAddrInUse marks a relay that could not bind because something else
// already has the address.
//
// Callers act on it rather than merely print it: in a single-container
// deployment the thing already bound is almost always this program's own server
// process, having started its relay first, and the right response for a `secsy-ca`
// invocation is to use that one instead of failing.
var ErrEmbeddedAddrInUse = errors.New("the embedded YubiHSM connector address is already in use")

// EmbeddedConfig configures the in-process connector.
type EmbeddedConfig struct {
	// DeviceURL is the device to hold, as a yhusb:// URL. Empty means the single
	// attached device; yhusb://serial=N pins one when several are attached.
	//
	// It must be a direct-USB URL: multiplexing a connector behind another
	// connector would add a hop and solve nothing, and silently accepting it
	// would hide the configuration mistake that produced it.
	DeviceURL string
	// Listen is the address the connector protocol is served on. Empty selects
	// DefaultEmbeddedListen.
	Listen string
	// Logger receives the relay's own diagnostics. nil selects log.Default().
	Logger *log.Logger
	// OnOperation is called after each relayed command that may have left a
	// device audit-log entry. It is how collection follows the operations of
	// clients this process cannot otherwise see. It must not block; see
	// SetOnOperation.
	OnOperation func()
}

// Embedded is a running in-process yubihsm-connector.
type Embedded struct {
	// mu serialises device access across every client, so one request/response
	// pair cannot interleave with another's. The USB transport serialises too,
	// but the guarantee belongs here: it must hold for whatever Transport this
	// relay was given, and it is the whole reason several clients can share one
	// device at all.
	//
	// It is deliberately not context-aware. A client waiting here is waiting
	// for a device that is genuinely busy — an RSA-4096 generation holds it for
	// most of a minute — and queuing is the honest answer, as it is for the
	// process-wide USB slot in usb_linux.go. Letting a waiter give up would not
	// free the device any sooner; it would only turn a slow signature into a
	// failed one.
	mu  sync.Mutex
	dev Transport

	url    string
	addr   string
	serial string

	srv  *http.Server
	ln   net.Listener
	done chan struct{}

	logger *log.Logger
	onOp   atomic.Pointer[func()]
	closed atomic.Bool
}

// StartEmbedded opens the device and serves the connector protocol on
// cfg.Listen until Close.
//
// It registers itself as the process's device holder, so from here on every
// in-process OpenTransport call that addresses this device — by yhusb:// URL or
// by this relay's own http:// URL — is handed the shared handle instead of
// opening a second claim that could only fail. Exactly one relay may run per
// process, because exactly one claim exists to share.
func StartEmbedded(ctx context.Context, cfg EmbeddedConfig) (*Embedded, error) {
	deviceURL := strings.TrimSpace(cfg.DeviceURL)
	if deviceURL == "" {
		deviceURL = "yhusb://"
	}
	if !IsDirectUSB(deviceURL) {
		return nil, fmt.Errorf("the embedded YubiHSM connector holds a USB device, so its device URL must be "+
			"yhusb:// (got %q); a deployment already reaching the device over a connector does not need it", deviceURL)
	}
	listen := strings.TrimSpace(cfg.Listen)
	if listen == "" {
		listen = DefaultEmbeddedListen
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	// The listener first. Binding is the step most likely to fail for a reason
	// the caller can act on — another relay, or a yubihsm-connector daemon, is
	// already serving this address — and failing before the USB device is
	// claimed means that caller is free to go use whatever is already there.
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		if isAddrInUse(err) {
			return nil, fmt.Errorf("%w: %s", ErrEmbeddedAddrInUse, listen)
		}
		return nil, fmt.Errorf("listening for the embedded YubiHSM connector on %s: %w", listen, err)
	}

	// openUSB rather than OpenTransport: this is the one place that must not be
	// routed to a shared handle, since it is what creates one.
	dev, err := openUSB(ctx, usbSerialFromURL(strings.TrimPrefix(deviceURL, "yhusb://")))
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	return startEmbeddedOver(ctx, dev, ln, logger, cfg.OnOperation)
}

// startEmbeddedOver serves the connector protocol for an already-open device.
//
// It is the seam the tests use: everything above it is about finding and
// claiming a USB device, which only real hardware can satisfy, while everything
// below it — the status document, the relay, the operation hook, the sharing
// rule — is protocol behaviour that has to be exercised on machines with no
// HSM. It takes ownership of both dev and ln.
func startEmbeddedOver(ctx context.Context, dev Transport, ln net.Listener, logger *log.Logger, onOp func()) (*Embedded, error) {
	e := &Embedded{
		dev:    dev,
		addr:   ln.Addr().String(),
		url:    "http://" + ln.Addr().String(),
		ln:     ln,
		done:   make(chan struct{}),
		logger: logger,
	}
	e.SetOnOperation(onOp)

	// The serial is read before anything else can use the device, so the status
	// document and the device-matching rule in sharedTransportFor both describe
	// the hardware actually held. A device that will not answer GET DEVICE INFO
	// is not fatal — the relay's job is to carry bytes, and a client's own error
	// is a better diagnosis than one invented here.
	if info, err := readDeviceInfo(func(data []byte) ([]byte, error) {
		return transact(ctx, dev, cmdGetDeviceInfo, data)
	}); err == nil {
		e.serial = info.Serial
	} else {
		logger.Printf("WARNING: the embedded YubiHSM connector could not read device info from %s: %v",
			dev.Describe(), err)
	}

	if err := setSharedDevice(e); err != nil {
		_ = dev.Close()
		_ = ln.Close()
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc(connectorStatusPath, e.handleStatus)
	mux.HandleFunc(connectorAPIPath, e.handleAPI)
	e.srv = &http.Server{
		Handler: mux,
		// No read or write timeout: a relayed command is bounded by
		// embeddedRelayTimeout, and a write deadline shorter than the slowest
		// legitimate device operation would cut off an RSA key generation that
		// was about to succeed. The header timeout still bounds a client that
		// connects and says nothing.
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          logger,
	}

	go func() {
		defer close(e.done)
		if err := e.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("WARNING: the embedded YubiHSM connector stopped serving %s: %v", e.url, err)
		}
	}()

	logger.Printf("Embedded YubiHSM connector serving %s (device %s%s): this process holds the USB "+
		"interface and relays for the PKCS#11 module, so no yubihsm-connector daemon is needed",
		e.url, dev.Describe(), serialSuffix(e.serial))
	return e, nil
}

// URL is the connector URL clients should use, e.g. http://127.0.0.1:12345.
func (e *Embedded) URL() string { return e.url }

// Addr is the host:port the relay is bound to.
func (e *Embedded) Addr() string { return e.addr }

// Serial is the device's serial number, or "" if it could not be read.
func (e *Embedded) Serial() string { return e.serial }

// SetOnOperation installs the hook called after each relayed command that may
// have left an audit-log entry, replacing any previous one. Passing nil removes
// it.
//
// It exists as a setter because the collector the hook feeds is built after the
// relay — the relay has to be up before any key provider is constructed, and
// the collector needs the database. fn runs on the request path, so it must not
// block, must not fail, and must not itself issue device commands; the intended
// implementation is hsmaudit.Collector.Notify, which drops a token into a
// buffered channel.
func (e *Embedded) SetOnOperation(fn func()) {
	if fn == nil {
		e.onOp.Store(nil)
		return
	}
	e.onOp.Store(&fn)
}

// Transport returns an in-process view of the device: a Transport that shares
// the relay's single claim.
//
// Its Close is a no-op, because the handle outlives every borrower — the relay
// owns it. That is also why this is handed out rather than the real transport:
// a Client takes ownership of its transport and closes it, and one client
// closing the device out from under the others is precisely the failure this
// type exists to prevent.
func (e *Embedded) Transport() Transport { return &sharedTransport{e: e} }

// Close stops serving, releases the device, and deregisters the relay.
func (e *Embedded) Close() error {
	if e.closed.Swap(true) {
		return nil
	}
	clearSharedDevice(e)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Shutdown waits for in-flight relays, which is what keeps a command from
	// being cut in half between the device and its client.
	err := e.srv.Shutdown(shutdownCtx)
	<-e.done

	e.mu.Lock()
	defer e.mu.Unlock()
	if cerr := e.dev.Close(); err == nil {
		err = cerr
	}
	return err
}

// handleStatus serves the document libyubihsm reads to decide whether a
// connector has a device.
//
// The field names and the key=value framing are Yubico's, because the client is
// Yubico's: the module checks for status=OK and will not open a session without
// it. The implementation line is an addition — unknown keys are ignored by the
// parser — so that an operator who curls this endpoint, or reads a container's
// health check, can tell this relay from the daemon it replaces.
func (e *Embedded) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := "OK"
	if e.closed.Load() {
		status = "NO_DEVICE"
	}
	serial := e.serial
	if serial == "" {
		serial = "*"
	}
	host, port, err := net.SplitHostPort(e.addr)
	if err != nil {
		host, port = e.addr, ""
	}
	body := fmt.Sprintf("status=%s\nserial=%s\nversion=%s\npid=%d\naddress=%s\nport=%s\nimplementation=%s\n",
		status, serial, embeddedConnectorVersion, os.Getpid(), host, port, "secsy-pki embedded connector")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, body)
}

// handleAPI relays one protocol message to the device and returns its reply
// verbatim.
func (e *Embedded) handleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// One byte over the protocol limit is read on purpose, so an oversized body
	// is rejected as oversized rather than silently truncated into a message
	// whose length header no longer matches its payload.
	msg, err := io.ReadAll(io.LimitReader(r.Body, maxMessageSize+1))
	if err != nil {
		http.Error(w, "reading the request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(msg) == 0 {
		http.Error(w, "empty message", http.StatusBadRequest)
		return
	}
	if len(msg) > maxMessageSize {
		http.Error(w, fmt.Sprintf("message of %d bytes exceeds the %d-byte protocol limit", len(msg), maxMessageSize),
			http.StatusRequestEntityTooLarge)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), embeddedRelayTimeout)
	defer cancel()
	resp, err := e.transact(ctx, msg)
	if err != nil {
		// 500 with the device's own words: libyubihsm reports a non-200 as a
		// connector failure, and an operator reading the CA log needs to see
		// whether the device said no or the relay could not reach it.
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Signal before the reply goes out, so a client that has its answer knows
	// the drain has been told. The device has already acted at this point — the
	// log entry exists — and the hook is a buffered-channel send, so this costs
	// the caller nothing measurable and buys an ordering an operator can rely
	// on: no operation can be seen to succeed while nothing yet knows to
	// collect its log entry.
	if auditableCommand(msg[0]) {
		if fn := e.onOp.Load(); fn != nil {
			(*fn)()
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(resp)
}

// transact carries one message to the device under the relay's lock.
func (e *Embedded) transact(ctx context.Context, msg []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed.Load() {
		return nil, fmt.Errorf("the embedded YubiHSM connector is closed")
	}
	return e.dev.Transact(ctx, msg)
}

// describe names the relayed device for error messages.
func (e *Embedded) describe() string {
	return fmt.Sprintf("%s (embedded connector %s)", e.dev.Describe(), e.url)
}

// auditableCommand reports whether an outer command code could have left a
// device audit-log entry, and so should prompt a drain.
//
// The relay sees only the outer code. Everything a client actually does arrives
// as cmdSessionMessage with the real command encrypted under SCP03, so this
// cannot tell a signature from a key listing — and must not try. It errs toward
// draining: a spurious signal costs one coalesced cycle that finds nothing,
// while a missed one leaves an entry in a 62-entry ring whose last free slot is
// what stands between a force-audited device and a refusal to sign.
//
// Excluded are the two commands a client sends in the clear that are both
// unaudited and issued when nothing is happening: ECHO, and the device-info
// probe a PKCS#11 module makes on every token query. Session establishment is
// *not* excluded — the device keeps an unlogged-authentication counter, so it
// accounts for authentications, and a handful of them per session pool is a
// price worth paying for not having to be sure.
func auditableCommand(cmd byte) bool {
	switch cmd {
	case cmdEcho, cmdGetDeviceInfo:
		return false
	}
	return true
}

func serialSuffix(serial string) string {
	if serial == "" {
		return ""
	}
	return ", serial " + serial
}

// isAddrInUse reports whether err is a bind failure caused by another listener.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

// sharedTransport is the in-process view of the relay's device handle.
type sharedTransport struct{ e *Embedded }

func (s *sharedTransport) Transact(ctx context.Context, msg []byte) ([]byte, error) {
	return s.e.transact(ctx, msg)
}

// Close releases nothing: the relay owns the device, and a borrower returning
// its view must not take the device away from the other borrowers.
func (s *sharedTransport) Close() error { return nil }

func (s *sharedTransport) Describe() string { return s.e.describe() }
