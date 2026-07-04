package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DKIMSigner RSA-DKIM-signs (RFC 6376) the outbound challenge email so the
// receiving mailbox can prove its authenticity, which RFC 8823 §5 requires of
// email-reply-00 challenge messages. It implements the rsa-sha256 algorithm with
// relaxed/relaxed header and body canonicalization — the widely-interoperable
// default. The signing key is a crypto.Signer (an RSA private key), so it may be
// held in software or, in principle, an HSM.
type DKIMSigner struct {
	// Domain is the SDID published in the d= tag; a TXT record at
	// <Selector>._domainkey.<Domain> must carry the matching public key.
	Domain string
	// Selector is the s= tag naming which key under the domain signed the message.
	Selector string
	// Signer is the RSA private key. Its public half must match the DNS record.
	Signer crypto.Signer
	// Now overrides the t= timestamp source (tests). Nil uses time.Now.
	Now func() time.Time
}

// Validate reports a configuration error if the signer is missing required
// fields, so misconfiguration surfaces at startup rather than at first send.
func (d *DKIMSigner) Validate() error {
	if d == nil {
		return nil
	}
	if strings.TrimSpace(d.Domain) == "" {
		return fmt.Errorf("dkim: domain is required")
	}
	if strings.TrimSpace(d.Selector) == "" {
		return fmt.Errorf("dkim: selector is required")
	}
	if d.Signer == nil {
		return fmt.Errorf("dkim: signing key is required")
	}
	return nil
}

// sign returns the DKIM-Signature header value (everything after
// "DKIM-Signature:") covering the given ordered headers and body. The b= tag is
// last so a verifier can reproduce the signed form by emptying it.
func (d *DKIMSigner) sign(hdrs []header, body []byte) (string, error) {
	if d.Signer == nil {
		return "", fmt.Errorf("dkim: no signing key")
	}
	nowFn := d.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	// Body hash over the relaxed-canonicalized body.
	bodyHash := sha256.Sum256(canonBodyRelaxed(body))
	bh := base64.StdEncoding.EncodeToString(bodyHash[:])

	// h= lists the signed header field names in hashing order.
	names := make([]string, len(hdrs))
	for i, h := range hdrs {
		names[i] = strings.ToLower(h.Name)
	}
	hlist := strings.Join(names, ":")

	// Assemble the signature header value with an empty b= (filled after signing).
	value := "v=1; a=rsa-sha256; c=relaxed/relaxed" +
		"; d=" + d.Domain +
		"; s=" + d.Selector +
		"; t=" + strconv.FormatInt(nowFn().Unix(), 10) +
		"; bh=" + bh +
		"; h=" + hlist +
		"; b="

	// Hash input: each signed header canonicalized and CRLF-terminated, then the
	// DKIM-Signature header (with empty b=) canonicalized WITHOUT a trailing CRLF.
	var input strings.Builder
	for _, h := range hdrs {
		input.WriteString(canonHeaderRelaxed(h.Name, h.Value))
		input.WriteString("\r\n")
	}
	input.WriteString(canonHeaderRelaxed("DKIM-Signature", value))

	digest := sha256.Sum256([]byte(input.String()))
	sig, err := d.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dkim: signing: %w", err)
	}
	return value + base64.StdEncoding.EncodeToString(sig), nil
}

// canonHeaderRelaxed applies RFC 6376 §3.4.2 relaxed header canonicalization to a
// single field: the name is lowercased, the value is unfolded, internal WSP runs
// collapse to a single space, and WSP around the colon and at the value's end is
// removed. The colon is retained.
func canonHeaderRelaxed(name, value string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	value = unfold(value)
	value = collapseWSP(value)
	value = strings.Trim(value, " \t")
	return name + ":" + value
}

// canonBodyRelaxed applies RFC 6376 §3.4.4 relaxed body canonicalization:
// trailing WSP on each line is removed, internal WSP runs collapse to a single
// space, and trailing empty lines are removed with the body (when non-empty)
// terminated by a single CRLF.
func canonBodyRelaxed(body []byte) []byte {
	lines := strings.Split(string(body), "\n")
	for i, ln := range lines {
		ln = strings.TrimRight(ln, "\r")
		ln = collapseWSP(ln)
		ln = strings.TrimRight(ln, " \t")
		lines[i] = ln
	}
	// Remove trailing empty lines.
	n := len(lines)
	for n > 0 && lines[n-1] == "" {
		n--
	}
	if n == 0 {
		return []byte{}
	}
	return []byte(strings.Join(lines[:n], "\r\n") + "\r\n")
}

// unfold removes RFC 5322 folding: CR and LF are deleted so a multi-line header
// value becomes a single logical line before WSP collapsing.
func unfold(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// collapseWSP replaces every run of spaces and tabs with a single space.
func collapseWSP(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inWSP := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == ' ' || c == '\t' {
			if !inWSP {
				b.WriteByte(' ')
				inWSP = true
			}
			continue
		}
		b.WriteByte(s[i])
		inWSP = false
	}
	return b.String()
}
