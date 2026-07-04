//go:build sqlite

// End-to-end coverage of the RFC 8823 email-reply-00 challenge (Task 108) using
// the golang.org/x/crypto/acme client, the software key provider, and an
// in-memory fake mail transport — no live SMTP/IMAP and no HSM. It drives a full
// S/MIME order: place an "email" order, respond to the challenge (which mails a
// signed challenge carrying token-part-1), inject the mailbox owner's reply,
// poll the inbox to validate it, and finalize to an emailProtection certificate.
package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// fakeMailTransport is an in-memory MailSender + MailInbox: Send captures the
// dispatched challenge email, deliver() injects a reply, and Fetch/Ack model the
// unseen/seen lifecycle of an IMAP mailbox.
type fakeMailTransport struct {
	mu    sync.Mutex
	sent  []OutboundMail
	inbox []InboundMail
	acked map[string]bool
}

func newFakeMailTransport() *fakeMailTransport {
	return &fakeMailTransport{acked: map[string]bool{}}
}

func (f *fakeMailTransport) Send(_ context.Context, msg OutboundMail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, msg)
	return nil
}

func (f *fakeMailTransport) Fetch(_ context.Context) ([]InboundMail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []InboundMail
	for _, m := range f.inbox {
		if !f.acked[m.ID] {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeMailTransport) Ack(_ context.Context, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		f.acked[id] = true
	}
	return nil
}

func (f *fakeMailTransport) deliver(m InboundMail) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inbox = append(f.inbox, m)
}

func (f *fakeMailTransport) lastSent() OutboundMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[len(f.sent)-1]
}

// withEmailChallenge configures the RFC 8823 email-reply-00 challenge on the test
// server, DKIM-signing challenge emails so the signing path is exercised too.
func withEmailChallenge(f *fakeMailTransport) func(*Config) {
	dkimKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return func(c *Config) {
		c.Email = &EmailChallengeConfig{
			From:    "acme-challenge@pki.example.test",
			Sender:  f,
			Inbox:   f,
			Profile: "smime",
			DKIM:    &DKIMSigner{Domain: "pki.example.test", Selector: "acme", Signer: dkimKey},
		}
	}
}

// emailCSR builds a CSR carrying the mailbox as its sole rfc822Name SAN. It uses
// an RSA key so the dual-use "smime" profile's keyEncipherment usage is valid (an
// EC key could only do key agreement).
func emailCSR(t *testing.T, mailbox string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		EmailAddresses: []string{mailbox},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// buildReply constructs the mailbox owner's challenge-reply email that carries
// the RFC 8823 §4 response block.
func buildReply(mailbox, from, token1, messageID, response string) []byte {
	return []byte("From: " + mailbox + "\r\n" +
		"To: " + from + "\r\n" +
		"Subject: Re: ACME: " + token1 + "\r\n" +
		"In-Reply-To: " + messageID + "\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		acmeResponseBegin + "\r\n" +
		response + "\r\n" +
		acmeResponseEnd + "\r\n")
}

// emailChallengeFor returns the email-reply-00 challenge (and its authz URL) for
// the single-identifier email order.
func emailChallengeFor(t *testing.T, c *xacme.Client, order *xacme.Order) (*xacme.Challenge, string) {
	t.Helper()
	ctx := context.Background()
	for _, au := range order.AuthzURLs {
		authz, err := c.GetAuthorization(ctx, au)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		for _, ch := range authz.Challenges {
			if ch.Type == "email-reply-00" {
				return ch, au
			}
		}
	}
	t.Fatal("server did not offer an email-reply-00 challenge")
	return nil, ""
}

func TestACME_EmailReply00(t *testing.T) {
	fake := newFakeMailTransport()
	env := newTestEnv(t, withEmailChallenge(fake))
	c := env.client(t)
	ctx := context.Background()
	mailbox := "alice@example.com"

	order, err := c.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: mailbox}})
	if err != nil {
		t.Fatalf("AuthorizeOrder(email): %v", err)
	}
	chal, authzURL := emailChallengeFor(t, c, order)
	token2 := chal.Token

	// Respond: the server dispatches the signed challenge email.
	if _, err := c.Accept(ctx, chal); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	sent := fake.lastSent()
	if sent.From != "acme-challenge@pki.example.test" || sent.To != mailbox {
		t.Fatalf("challenge email envelope = From %q To %q", sent.From, sent.To)
	}
	if !strings.Contains(string(sent.Raw), "DKIM-Signature:") {
		t.Error("challenge email is not DKIM-signed")
	}
	if !strings.Contains(sent.Subject, "ACME: ") {
		t.Fatalf("challenge Subject %q lacks the ACME token label", sent.Subject)
	}
	token1, ok := subjectToken1(sent.Subject)
	if !ok {
		t.Fatalf("could not extract token-part-1 from Subject %q", sent.Subject)
	}

	// Compute the reply's response digest over keyAuth(token1‖token2).
	keyAuth, err := c.HTTP01ChallengeResponse(token1 + token2)
	if err != nil {
		t.Fatalf("HTTP01ChallengeResponse: %v", err)
	}
	sum := sha256.Sum256([]byte(keyAuth))
	response := base64.RawURLEncoding.EncodeToString(sum[:])
	fake.deliver(InboundMail{ID: "reply-1", Raw: buildReply(mailbox, sent.From, token1, sent.MessageID, response)})

	// Poll the inbox: the reply validates the challenge.
	if n, err := env.srv.PollEmailChallenges(ctx); err != nil || n != 1 {
		t.Fatalf("PollEmailChallenges = (%d, %v), want (1, nil)", n, err)
	}
	authz, err := c.WaitAuthorization(ctx, authzURL)
	if err != nil {
		t.Fatalf("WaitAuthorization: %v", err)
	}
	if authz.Status != xacme.StatusValid {
		t.Fatalf("authorization status = %q, want valid", authz.Status)
	}

	// Finalize to an S/MIME certificate.
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	der, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, emailCSR(t, mailbox), true)
	if err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != mailbox {
		t.Fatalf("leaf rfc822 SANs = %v, want [%s]", leaf.EmailAddresses, mailbox)
	}
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageEmailProtection) {
		t.Errorf("leaf is missing the emailProtection EKU: %v", leaf.ExtKeyUsage)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: env.roots, Intermediates: env.inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}

	// A cert.acme_email audit event must record the validated challenge.
	events, _, err := env.db.ListEvents(audit.ActionACMEEmail, "", "", 100, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if !anyEventContains(events, "validated") {
		t.Errorf("no cert.acme_email 'validated' audit event found: %+v", events)
	}
}

// TestACME_EmailReply00_WrongResponse verifies that a reply carrying the wrong
// key-authorization digest fails the challenge (and the order) closed.
func TestACME_EmailReply00_WrongResponse(t *testing.T) {
	fake := newFakeMailTransport()
	env := newTestEnv(t, withEmailChallenge(fake))
	c := env.client(t)
	ctx := context.Background()
	mailbox := "bob@example.com"

	order, err := c.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: mailbox}})
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	chal, authzURL := emailChallengeFor(t, c, order)
	if _, err := c.Accept(ctx, chal); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	sent := fake.lastSent()
	token1, _ := subjectToken1(sent.Subject)

	// A digest over a bogus key authorization.
	bad := sha256.Sum256([]byte("not-the-key-auth"))
	response := base64.RawURLEncoding.EncodeToString(bad[:])
	fake.deliver(InboundMail{ID: "reply-1", Raw: buildReply(mailbox, sent.From, token1, sent.MessageID, response)})

	if _, err := env.srv.PollEmailChallenges(ctx); err != nil {
		t.Fatalf("PollEmailChallenges: %v", err)
	}
	// WaitAuthorization returns an error once the authorization goes invalid.
	if _, err := c.WaitAuthorization(ctx, authzURL); err == nil {
		t.Fatal("WaitAuthorization succeeded on a wrong response, want failure")
	}
}

// TestACME_EmailIdentifierDisabled verifies the challenge is not advertised — and
// email identifiers are rejected — when no inbound-mail poller is configured.
func TestACME_EmailIdentifierDisabled(t *testing.T) {
	env := newTestEnv(t) // no email challenge configured
	c := env.client(t)
	ctx := context.Background()
	if _, err := c.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: "x@example.com"}}); err == nil {
		t.Fatal("email order was accepted without an email challenge configured, want rejection")
	}
}

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == want {
			return true
		}
	}
	return false
}

func anyEventContains(events []audit.Event, substr string) bool {
	for _, e := range events {
		if strings.Contains(e.Detail, substr) {
			return true
		}
	}
	return false
}
