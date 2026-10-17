package yubihsm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTP transport for deployments that front the device with yubihsm-connector,
// typically because the HSM is on another host or the process cannot be given
// USB access. The connector is a dumb relay: it POSTs the message bytes to the
// device and returns the reply verbatim, so the SCP03 channel established over
// it is end-to-end between this process and the HSM and a compromised connector
// can drop or reorder messages but cannot read or forge them.

const connectorAPIPath = "/connector/api"

type connectorTransport struct {
	base   string
	client *http.Client
}

func openConnector(url string) (Transport, error) {
	base := strings.TrimSuffix(strings.TrimSpace(url), "/")
	if base == "" {
		return nil, fmt.Errorf("empty connector URL")
	}
	return &connectorTransport{
		base: base,
		// The device itself is the slow part; the bound is generous enough for
		// RSA key generation but still finite so a hung connector surfaces.
		client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (t *connectorTransport) Describe() string { return t.base }

func (t *connectorTransport) Close() error {
	t.client.CloseIdleConnections()
	return nil
}

func (t *connectorTransport) Transact(ctx context.Context, msg []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+connectorAPIPath, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting to yubihsm-connector at %s: %w: %w", t.base, errTransportRead, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessageSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading the yubihsm-connector reply: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The connector reports a device that stopped answering — which a reset
		// legitimately causes — the same way it reports its own failures, so this
		// carries the read sentinel too.
		return nil, fmt.Errorf("yubihsm-connector at %s returned %s: %w: %s",
			t.base, resp.Status, errTransportRead, strings.TrimSpace(string(body)))
	}
	if len(body) > maxMessageSize {
		return nil, fmt.Errorf("yubihsm-connector returned %d bytes, above the %d-byte protocol limit", len(body), maxMessageSize)
	}
	return body, nil
}

// What a connector URL names.
//
// Three callers need to reason about that rather than merely connect to it: the
// relay's sharing rule, which has to recognise its own address so an in-process
// drain is not sent through its own HTTP server; the relay planner, which can
// only serve an address on this host; and the planner again, which needs the
// host:port to bind. All three used to answer it by string comparison, and the
// first one was wrong for `localhost` — a config naming
// http://localhost:12345 would not match a relay bound to 127.0.0.1:12345, so
// the drain would loop back through the operation hook and signal the need for
// another drain on every cycle. The parsing belongs in one place.

// DefaultConnectorPort is the port a connector URL means when it names none.
// It is Yubico's, which is what every yubihsm-shell example and every
// operator's muscle memory uses.
const DefaultConnectorPort = "12345"

// ConnectorHostPort extracts the host:port an http(s) connector URL names,
// defaulting the port.
func ConnectorHostPort(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parsing the connector URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("the connector URL %q names no host", raw)
	}
	if u.Port() == "" {
		return net.JoinHostPort(u.Hostname(), DefaultConnectorPort), nil
	}
	return u.Host, nil
}

// IsLocalConnectorURL reports whether raw names an http(s) connector on this
// host, and so an address this process could serve itself.
//
// An unspecified address (0.0.0.0, [::]) counts: a relay bound there is serving
// this host, among others.
func IsLocalConnectorURL(raw string) bool {
	hostPort, err := ConnectorHostPort(raw)
	if err != nil {
		return false
	}
	return isLocalHost(hostPort)
}

func isLocalHost(hostPort string) bool {
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// sameConnectorEndpoint reports whether two connector URLs address the same
// endpoint.
//
// Equal ports on two local hosts are the same endpoint, because that is what
// they are on the wire: a relay bound to 127.0.0.1:12345, 0.0.0.0:12345 or
// localhost:12345 answers all three spellings. Anything else is compared
// literally, apart from a trailing slash and the case of the scheme and host.
func sameConnectorEndpoint(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	norm := func(s string) string {
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "/"))
	}
	if norm(a) == norm(b) {
		return true
	}
	ha, err := ConnectorHostPort(a)
	if err != nil {
		return false
	}
	hb, err := ConnectorHostPort(b)
	if err != nil {
		return false
	}
	_, pa, err := net.SplitHostPort(ha)
	if err != nil {
		return false
	}
	_, pb, err := net.SplitHostPort(hb)
	if err != nil {
		return false
	}
	return pa == pb && isLocalHost(ha) && isLocalHost(hb)
}
