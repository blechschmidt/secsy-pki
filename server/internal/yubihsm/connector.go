package yubihsm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
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
