// Package yubihsm is a native, dependency-free driver for the YubiHSM 2.
//
// It speaks the device's own protocol — GlobalPlatform SCP03 over either a
// direct USB bulk transport or a yubihsm-connector — instead of driving the
// yubihsm-shell binary and reading its human-readable output. That matters for
// more than tidiness: the audit, attestation and key-proof subsystems in
// internal/hsmaudit and internal/hsmattest make claims about what a device did
// and cannot do, and those claims are only as trustworthy as the channel that
// carried the evidence.
//
// Concretely, against the shell this replaces:
//
//   - Failure is a typed DeviceError, not a regular expression over English
//     prose. yubihsm-shell exits 0 even when a scripted command is rejected, so
//     the previous code had to recognise failure by matching text; a message
//     reworded upstream would have made a refused "put option" look like a
//     success, which is exactly the state in which unlogged signing becomes
//     possible.
//   - Values arrive as bytes. Audit entries, option maps and attestation
//     certificates are parsed from the wire encoding rather than scraped from
//     formatted output, so nothing depends on field ordering or spacing in a
//     display format the vendor never promised to keep stable.
//   - Nothing is written to the filesystem. Signing through the shell required
//     the data to be signed to exist as a temporary file, and the authentication
//     password to be handed to a child process.
//   - Context deadlines and cancellation reach the device.
//
// The package is deliberately narrow: it implements the commands this codebase
// issues, not the whole YubiHSM command set.
package yubihsm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Config identifies a device and the authentication key to open a session with.
type Config struct {
	// ConnectorURL is a yubihsm-shell style connector URL; empty means yhusb://.
	ConnectorURL string
	// AuthKeyID is the object id of the authentication key; 0 means 1, the
	// factory default.
	AuthKeyID uint16
	// Password derives the session keys. Empty means "password", the factory
	// default, which is useful for a freshly reset device and nothing else.
	Password string
}

func (c Config) authKeyID() uint16 {
	if c.AuthKeyID == 0 {
		return 1
	}
	return c.AuthKeyID
}

func (c Config) password() string {
	if c.Password == "" {
		return "password"
	}
	return c.Password
}

// Client is an authenticated connection to one YubiHSM 2.
//
// It is safe for concurrent use, but the underlying secure channel is strictly
// sequential — SCP03 chains its MAC across messages — so calls serialise.
type Client struct {
	mu        sync.Mutex
	transport Transport
	session   *scp03Session
	closed    bool
	// dead records that the secure channel can no longer be trusted — the device
	// tore the session down, or a reply failed its MAC. Either way the right
	// answer to the next command is an error, not another attempt.
	dead bool
}

// Open connects to the device and establishes an authenticated SCP03 session.
//
// The caller must Close the client: the device supports a small fixed number of
// concurrent sessions, and a leaked one stays occupied until it times out.
func Open(ctx context.Context, cfg Config) (*Client, error) {
	t, err := OpenTransport(ctx, cfg.ConnectorURL)
	if err != nil {
		return nil, err
	}
	return OpenOver(ctx, t, cfg)
}

// OpenOver authenticates over an already-open transport, which it takes
// ownership of: it is closed if authentication fails, and by Client.Close
// otherwise.
func OpenOver(ctx context.Context, t Transport, cfg Config) (*Client, error) {
	encKey, macKey, err := DeriveAuthenticationKeys(cfg.password())
	if err != nil {
		_ = t.Close()
		return nil, err
	}
	s, err := openSession(ctx, t, cfg.authKeyID(), encKey, macKey)
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("%s: %w", t.Describe(), err)
	}
	return &Client{transport: t, session: s}, nil
}

// Close ends the session and releases the device.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// Closing the session frees the device slot immediately. Best effort: the
	// transport is being torn down regardless, and the device reclaims idle
	// sessions on its own.
	if c.session != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = c.send(ctx, cmdCloseSession, nil)
		cancel()
	}
	return c.transport.Close()
}

// Describe names the device endpoint, for error messages and diagnostics.
func (c *Client) Describe() string { return c.transport.Describe() }

// WithSession opens a client, runs fn, and closes the client.
//
// Most callers do one short burst of work per operation, matching how the device
// is used elsewhere in this codebase: sessions are cheap to create and expensive
// to leak.
func WithSession(ctx context.Context, cfg Config, fn func(*Client) error) error {
	c, err := Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return fn(c)
}

// send transmits a command inside the secure channel and returns its payload.
func (c *Client) send(ctx context.Context, cmd byte, data []byte) ([]byte, error) {
	if c.closed && cmd != cmdCloseSession {
		return nil, fmt.Errorf("yubihsm: client is closed")
	}
	if c.dead {
		return nil, fmt.Errorf("yubihsm: the secure channel to %s failed and cannot be reused", c.transport.Describe())
	}
	inner, err := frame(cmd, data)
	if err != nil {
		return nil, err
	}
	outer, counterBlock := c.session.wrap(inner)
	raw, err := c.transport.Transact(ctx, outer)
	if err != nil {
		return nil, err
	}
	// A session-level failure — an expired session, most often — comes back as a
	// bare error frame rather than an encrypted one, so it must be recognised
	// before attempting to unwrap.
	//
	// Only the session-level codes are honoured. An unencrypted, unauthenticated
	// frame is something anything on the transport can produce, so accepting it
	// as the outcome of an arbitrary command would let a compromised connector
	// choose what any call appears to return — turning, say, a key inventory into
	// a shorter one. Anything else falls through to MAC verification, which such
	// a frame cannot pass.
	if len(raw) >= 4 && raw[0] == cmdError && isSessionLevelError(DeviceError(raw[3])) {
		c.dead = true
		return nil, DeviceError(raw[3])
	}
	respInner, err := c.session.unwrap(raw, counterBlock)
	if err != nil {
		// A MAC failure is unambiguous evidence that the channel is no longer
		// carrying this session's traffic. Continuing to issue commands over it
		// would mean deciding, per call, whether to believe the next reply.
		c.dead = true
		return nil, err
	}
	return parseResponse(cmd, respInner)
}

// isSessionLevelError reports whether a device error means the secure channel
// itself is gone, which is the only case the device reports outside it.
func isSessionLevelError(e DeviceError) bool {
	switch e {
	case ErrInvalidSession, ErrSessionFailed, ErrSessionsFull, ErrAuthenticationFailed:
		return true
	default:
		return false
	}
}

// Command sends an arbitrary command inside the secure channel. It exists for
// device operations this package does not model; prefer the typed methods.
func (c *Client) Command(ctx context.Context, cmd byte, data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.send(ctx, cmd, data)
}

// Echo asks the device to return the data unchanged, which proves the secure
// channel is live end to end.
func (c *Client) Echo(ctx context.Context, data []byte) ([]byte, error) {
	return c.Command(ctx, cmdEcho, data)
}

// DeviceInfo is the device's self-description.
type DeviceInfo struct {
	Version    string  `json:"version"`
	Serial     string  `json:"serial"`
	PartNumber string  `json:"part_number,omitempty"`
	LogTotal   uint8   `json:"log_total"`
	LogUsed    uint8   `json:"log_used"`
	Algorithms []uint8 `json:"-"`
}

// LogCapacity renders the log ring-buffer occupancy as "used/total", the form
// the audit collector watches to drain before the device wedges.
func (d *DeviceInfo) LogCapacity() string {
	return fmt.Sprintf("%d/%d", d.LogUsed, d.LogTotal)
}

// DeviceInfo reads the device identity and log occupancy.
//
// GET DEVICE INFO is answered outside a session, so this is also the cheapest
// liveness probe for a device whose authentication key is unknown; see
// TransportDeviceInfo.
func (c *Client) DeviceInfo(ctx context.Context) (*DeviceInfo, error) {
	return readDeviceInfo(func(data []byte) ([]byte, error) {
		return c.Command(ctx, cmdGetDeviceInfo, data)
	})
}

// TransportDeviceInfo reads the device identity without authenticating.
//
// It is the one command the device answers before a session exists, which makes
// it the right probe for "is the expected hardware attached" — including when
// the authentication key has been changed or is not available to this process.
func TransportDeviceInfo(ctx context.Context, cfg Config) (*DeviceInfo, error) {
	t, err := OpenTransport(ctx, cfg.ConnectorURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	return readDeviceInfo(func(data []byte) ([]byte, error) {
		return transact(ctx, t, cmdGetDeviceInfo, data)
	})
}

// deviceInfoPartNumber is the GET DEVICE INFO selector that returns the device's
// part number instead of the default identity block.
const deviceInfoPartNumber byte = 0x01

// readDeviceInfo issues the one or two GET DEVICE INFO calls that make up a full
// device description, over whichever channel send speaks.
func readDeviceInfo(send func(data []byte) ([]byte, error)) (*DeviceInfo, error) {
	body, err := send(nil)
	if err != nil {
		return nil, err
	}
	info, err := parseDeviceInfo(body)
	if err != nil {
		return nil, err
	}
	// The part number comes from a separate selector added in firmware 2.4 and is
	// cosmetic, so a device that rejects the selector still yields device info
	// rather than no answer at all.
	if part, err := send([]byte{deviceInfoPartNumber}); err == nil && isPrintableASCII(part) {
		info.PartNumber = string(part)
	}
	return info, nil
}

// transact sends one unencrypted command over a transport.
func transact(ctx context.Context, t Transport, cmd byte, data []byte) ([]byte, error) {
	msg, err := frame(cmd, data)
	if err != nil {
		return nil, err
	}
	raw, err := t.Transact(ctx, msg)
	if err != nil {
		return nil, err
	}
	return parseResponse(cmd, raw)
}

// deviceInfoFixedLen is the length of the fixed part of a GET DEVICE INFO
// response: version (3), serial (4), log total (1), log used (1).
const deviceInfoFixedLen = 9

func parseDeviceInfo(b []byte) (*DeviceInfo, error) {
	if len(b) < deviceInfoFixedLen {
		return nil, fmt.Errorf("device-info response is %d bytes, want at least %d", len(b), deviceInfoFixedLen)
	}
	// Everything after the fixed part is the list of supported algorithm
	// identifiers, one byte each.
	return &DeviceInfo{
		Version:    fmt.Sprintf("%d.%d.%d", b[0], b[1], b[2]),
		Serial:     fmt.Sprintf("%d", binary.BigEndian.Uint32(b[3:7])),
		LogTotal:   b[7],
		LogUsed:    b[8],
		Algorithms: append([]uint8(nil), b[deviceInfoFixedLen:]...),
	}, nil
}

func isPrintableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// GetOption reads a device option's raw value.
func (c *Client) GetOption(ctx context.Context, option byte) ([]byte, error) {
	body, err := c.Command(ctx, cmdGetOption, []byte{option})
	if err != nil {
		return nil, fmt.Errorf("reading device option 0x%02x: %w", option, err)
	}
	return body, nil
}

// PutOption writes a device option.
//
// The audit options are the security-relevant ones and are write-once in
// practice: setting a level to "fixed" (0x02) cannot be undone short of a
// factory reset, which itself leaves a device-init entry in the log.
func (c *Client) PutOption(ctx context.Context, option byte, value []byte) error {
	req := make([]byte, 0, 3+len(value))
	req = append(req, option)
	req = binary.BigEndian.AppendUint16(req, uint16(len(value)))
	req = append(req, value...)
	if _, err := c.Command(ctx, cmdPutOption, req); err != nil {
		return fmt.Errorf("writing device option 0x%02x=%x: %w", option, value, err)
	}
	return nil
}

// LogEntry is one YubiHSM audit-log record, exactly as the device encodes it.
type LogEntry struct {
	Number     uint16
	Command    uint8
	Length     uint16
	SessionKey uint16
	TargetKey  uint16
	SecondKey  uint16
	Result     uint8
	Tick       uint32
	Digest     [16]byte
}

// LogData is a GET LOG ENTRIES response.
type LogData struct {
	// UnloggedBoots and UnloggedAuthentications are the device's own admission
	// that operations happened which it could not record because the log was
	// full. Any non-zero value voids the completeness claim the audit subsystem
	// is built on, so they are carried alongside the entries rather than dropped.
	UnloggedBoots           uint16
	UnloggedAuthentications uint16
	Entries                 []LogEntry
}

// logEntryLen is the on-wire size of one audit-log record.
const logEntryLen = 32

// GetLogEntries reads the unconsumed device audit log.
//
// Reading does not acknowledge: the entries stay in the device's ring buffer
// until SetLogIndex, so a caller that fails while persisting them can retry.
func (c *Client) GetLogEntries(ctx context.Context) (*LogData, error) {
	body, err := c.Command(ctx, cmdGetLogEntries, nil)
	if err != nil {
		return nil, fmt.Errorf("reading the device audit log: %w", err)
	}
	if len(body) < 5 {
		return nil, fmt.Errorf("log response is %d bytes, want at least 5", len(body))
	}
	out := &LogData{
		UnloggedBoots:           binary.BigEndian.Uint16(body[0:2]),
		UnloggedAuthentications: binary.BigEndian.Uint16(body[2:4]),
	}
	n := int(body[4])
	rest := body[5:]
	if len(rest) < n*logEntryLen {
		return nil, fmt.Errorf("log response announces %d entries but carries %d bytes (want %d)", n, len(rest), n*logEntryLen)
	}
	out.Entries = make([]LogEntry, 0, n)
	for i := 0; i < n; i++ {
		r := rest[i*logEntryLen : (i+1)*logEntryLen]
		e := LogEntry{
			Number:     binary.BigEndian.Uint16(r[0:2]),
			Command:    r[2],
			Length:     binary.BigEndian.Uint16(r[3:5]),
			SessionKey: binary.BigEndian.Uint16(r[5:7]),
			TargetKey:  binary.BigEndian.Uint16(r[7:9]),
			SecondKey:  binary.BigEndian.Uint16(r[9:11]),
			Result:     r[11],
			Tick:       binary.BigEndian.Uint32(r[12:16]),
		}
		copy(e.Digest[:], r[16:32])
		out.Entries = append(out.Entries, e)
	}
	return out, nil
}

// SetLogIndex acknowledges audit-log entries up to and including index, freeing
// those ring-buffer slots on the device.
//
// This is irreversible and destroys the only copy of anything not already
// persisted, which is why it is a separate call from GetLogEntries.
func (c *Client) SetLogIndex(ctx context.Context, index uint16) error {
	if _, err := c.Command(ctx, cmdSetLogIndex, binary.BigEndian.AppendUint16(nil, index)); err != nil {
		return fmt.Errorf("acknowledging device audit log up to entry %d: %w", index, err)
	}
	return nil
}

// ObjectHandle identifies one stored object.
type ObjectHandle struct {
	ID       uint16
	Type     byte
	Sequence uint8
}

// ListObjects enumerates the objects the session's authentication key can see.
// A zero objectType lists every type.
func (c *Client) ListObjects(ctx context.Context, objectType byte) ([]ObjectHandle, error) {
	var filter []byte
	if objectType != 0 {
		filter = []byte{listFilterType, objectType}
	}
	body, err := c.Command(ctx, cmdListObjects, filter)
	if err != nil {
		return nil, fmt.Errorf("listing device objects: %w", err)
	}
	if len(body)%4 != 0 {
		return nil, fmt.Errorf("list-objects response is %d bytes, not a multiple of 4", len(body))
	}
	out := make([]ObjectHandle, 0, len(body)/4)
	for i := 0; i < len(body); i += 4 {
		out = append(out, ObjectHandle{
			ID:       binary.BigEndian.Uint16(body[i : i+2]),
			Type:     body[i+2],
			Sequence: body[i+3],
		})
	}
	return out, nil
}

// ObjectInfo is the device's full description of a stored object.
type ObjectInfo struct {
	Capabilities          uint64
	ID                    uint16
	Length                uint16
	Domains               uint16
	Type                  byte
	Algorithm             byte
	Sequence              uint8
	Origin                uint8
	Label                 string
	DelegatedCapabilities uint64
}

// GET OBJECT INFO response layout: capabilities (8), id (2), length (2),
// domains (2), type (1), algorithm (1), sequence (1), origin (1), label (40),
// delegated capabilities (8).
const (
	objectInfoLabelOffset = 18
	labelLen              = 40
	objectInfoLen         = objectInfoLabelOffset + labelLen + 8
)

// GetObjectInfo reads the device's description of one object.
func (c *Client) GetObjectInfo(ctx context.Context, id uint16, objectType byte) (*ObjectInfo, error) {
	req := binary.BigEndian.AppendUint16(nil, id)
	req = append(req, objectType)
	body, err := c.Command(ctx, cmdGetObjectInfo, req)
	if err != nil {
		return nil, fmt.Errorf("reading info for object 0x%04x (%s): %w", id, ObjectTypeName(objectType), err)
	}
	if len(body) < objectInfoLen {
		return nil, fmt.Errorf("object-info response is %d bytes, want %d", len(body), objectInfoLen)
	}
	// Labels are a fixed-width, NUL-padded field.
	label := body[objectInfoLabelOffset : objectInfoLabelOffset+labelLen]
	if i := bytes.IndexByte(label, 0); i >= 0 {
		label = label[:i]
	}
	return &ObjectInfo{
		Capabilities:          binary.BigEndian.Uint64(body[0:8]),
		ID:                    binary.BigEndian.Uint16(body[8:10]),
		Length:                binary.BigEndian.Uint16(body[10:12]),
		Domains:               binary.BigEndian.Uint16(body[12:14]),
		Type:                  body[14],
		Algorithm:             body[15],
		Sequence:              body[16],
		Origin:                body[17],
		Label:                 string(label),
		DelegatedCapabilities: binary.BigEndian.Uint64(body[objectInfoLabelOffset+labelLen : objectInfoLen]),
	}, nil
}

// GetOpaque reads an opaque object's contents. Object 0 is the factory device
// attestation certificate.
func (c *Client) GetOpaque(ctx context.Context, id uint16) ([]byte, error) {
	body, err := c.Command(ctx, cmdGetOpaque, binary.BigEndian.AppendUint16(nil, id))
	if err != nil {
		return nil, fmt.Errorf("reading opaque object 0x%04x: %w", id, err)
	}
	return body, nil
}

// SignEdDSA signs data with an Ed25519 key on the device. Ed25519 signs the
// message itself, so data is passed whole rather than pre-hashed.
func (c *Client) SignEdDSA(ctx context.Context, keyID uint16, data []byte) ([]byte, error) {
	req := binary.BigEndian.AppendUint16(nil, keyID)
	req = append(req, data...)
	sig, err := c.Command(ctx, cmdSignEdDSA, req)
	if err != nil {
		return nil, fmt.Errorf("signing with EdDSA key 0x%04x: %w", keyID, err)
	}
	return sig, nil
}

// AttestAsymmetricKey asks the device to issue an attestation certificate over
// the public key of one of its asymmetric objects, signed by attestingKeyID.
// Passing 0 selects the factory attestation key, whose certificate chains to
// Yubico's attestation PKI.
//
// The returned bytes are DER. Decoding and verification live in
// internal/hsmattest.
func (c *Client) AttestAsymmetricKey(ctx context.Context, keyID, attestingKeyID uint16) ([]byte, error) {
	req := binary.BigEndian.AppendUint16(nil, keyID)
	req = binary.BigEndian.AppendUint16(req, attestingKeyID)
	der, err := c.Command(ctx, cmdSignAttestationCert, req)
	if err != nil {
		return nil, fmt.Errorf("attesting key 0x%04x: %w", keyID, err)
	}
	return der, nil
}

// GetPseudoRandom draws bytes from the device's random number generator.
func (c *Client) GetPseudoRandom(ctx context.Context, n uint16) ([]byte, error) {
	return c.Command(ctx, cmdGetPseudoRandom, binary.BigEndian.AppendUint16(nil, n))
}

// Reset performs a factory reset: every object and the whole audit log are
// erased and the device reboots.
//
// The device drops the USB connection as it resets, so the reply is often lost;
// a transport error after the command has been accepted is therefore not treated
// as a failure.
func (c *Client) Reset(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.send(ctx, cmdResetDevice, nil)
	if err == nil {
		return nil
	}
	// A successful reset takes the USB connection down with it, so the reply is
	// usually lost and the transport reports a read failure. That specific case
	// is not an error; everything else is.
	//
	// The distinction has to be narrow. Reporting success for, say, a MAC failure
	// or a command that never left the host would tell an operator their device
	// was wiped when it still holds every key and its whole audit history — the
	// state in which they would go on to provision audit logging believing there
	// was nothing before it.
	if errors.Is(err, errTransportRead) {
		return nil
	}
	return fmt.Errorf("resetting the device: %w", err)
}
