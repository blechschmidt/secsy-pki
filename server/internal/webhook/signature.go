// Package webhook implements the durable outbound webhook / eventing system
// (Task 116): a subscription store and a leader-elected delivery engine that
// POSTs certificate lifecycle events to external endpoints with at-least-once
// semantics, exponential-backoff retries, dead-lettering, and an HMAC-SHA256
// signature the receiver verifies to authenticate the sender and blunt replay.
//
// It is deliberately distinct from the two pre-existing paths:
//
//   - the in-process SSE audit feed (Task 104) fans events to operators watching
//     the console live and is lossy by design; and
//   - the monitor's fire-and-forget WebhookSink (Task 15) pushes expiry/canary/CT/
//     backup ALERTS to a single configured URL with no persistence or retries.
//
// This system is durable, per-subscription, retried, and signed — the integration
// substrate external systems build automation on.
package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// GenerateSecret returns a fresh random HMAC signing secret (32 bytes, hex) for
// a new subscription when the operator does not supply one.
func GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SignatureHeader carries the delivery's authentication tag. Its value is
// "t=<unix-seconds>,v1=<hex-hmac>" (a scheme the wider ecosystem, e.g. Stripe,
// popularized) where the HMAC-SHA256 is computed over "<unix-seconds>.<body>"
// under the subscription's shared secret. Binding the timestamp into the signed
// message lets a receiver reject a stale (replayed) delivery: a captured request
// re-sent later still carries its original timestamp, which falls outside the
// receiver's freshness window.
const SignatureHeader = "X-Secsy-Signature"

// Signature-scheme version tag, so the format can evolve without breaking
// existing receivers.
const signatureVersion = "v1"

// Sign returns the SignatureHeader value for a body signed at time ts under
// secret. The receiver recomputes it to authenticate the delivery.
func Sign(secret string, ts time.Time, body []byte) string {
	unix := ts.Unix()
	mac := computeHMAC(secret, unix, body)
	return fmt.Sprintf("t=%d,%s=%s", unix, signatureVersion, mac)
}

// computeHMAC returns the hex HMAC-SHA256 over "<unix>.<body>" under secret.
func computeHMAC(secret string, unix int64, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(strconv.FormatInt(unix, 10)))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify authenticates a received delivery against secret. It parses the
// SignatureHeader value, enforces that the embedded timestamp is within
// tolerance of now (replay/clock-skew guard; pass tolerance <= 0 to skip the
// freshness check), and constant-time-compares the HMAC over the received body.
// It is exported so receivers (and the test suite) can validate deliveries with
// the exact algorithm the sender used.
func Verify(secret, header string, body []byte, tolerance time.Duration, now time.Time) error {
	unix, mac, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}
	if tolerance > 0 {
		skew := now.Sub(time.Unix(unix, 0))
		if skew < 0 {
			skew = -skew
		}
		if skew > tolerance {
			return fmt.Errorf("webhook signature timestamp outside tolerance (%s)", skew)
		}
	}
	want := computeHMAC(secret, unix, body)
	if !hmac.Equal([]byte(want), []byte(mac)) {
		return fmt.Errorf("webhook signature mismatch")
	}
	return nil
}

// parseSignatureHeader splits "t=<unix>,v1=<hex>" into its parts.
func parseSignatureHeader(header string) (unix int64, mac string, err error) {
	var tsSeen, macSeen bool
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			if unix, err = strconv.ParseInt(v, 10, 64); err != nil {
				return 0, "", fmt.Errorf("webhook signature: bad timestamp %q", v)
			}
			tsSeen = true
		case signatureVersion:
			mac = v
			macSeen = true
		}
	}
	if !tsSeen || !macSeen {
		return 0, "", fmt.Errorf("webhook signature: malformed header %q", header)
	}
	return unix, mac, nil
}
