package acme

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/smime"
)

// This file implements the RFC 8823 "email-reply-00" ACME challenge, which
// obtains S/MIME (id-kp-emailProtection) certificates for "email"-type
// identifiers through the same account/order/authorization/finalize plumbing as
// the domain-validation challenges. Only the identifier type and the challenge
// validation are new:
//
//   - The client places an order for an "email" identifier. The server offers an
//     email-reply-00 challenge whose "token" field carries token-part-2 and whose
//     "from" field names the sender the challenge email will come from.
//   - When the client responds to (POSTs) the challenge, the server generates
//     token-part-1, dispatches a signed challenge email to the mailbox with
//     token-part-1 in the Subject ("ACME: <token-part-1>"), and moves the
//     challenge to "processing".
//   - The mailbox owner replies. The reply body carries
//     base64url(SHA-256(keyAuthorization)) computed over the full token
//     (token-part-1 ‖ token-part-2). A leader-elected poller reads the inbound
//     (IMAP) mailbox, threads each reply back to its challenge, and validates the
//     digest — flipping the challenge to valid or invalid.
//
// The concrete SMTP sender and IMAP inbox live in internal/mailtransport and are
// injected via the MailSender / MailInbox interfaces, so the whole flow is
// exercised hermetically in tests with an in-memory fake transport.

// MailSender dispatches the outbound challenge email — the SMTP sink. The
// message is a fully-rendered RFC 5322 byte stream (already DKIM-signed when a
// signer is configured); the sender is responsible only for the SMTP envelope
// and transmission.
type MailSender interface {
	Send(ctx context.Context, msg OutboundMail) error
}

// MailInbox polls the inbound mailbox for challenge replies — the IMAP poller.
// Its presence is what enables (and "advertises") the email-reply-00 challenge:
// without an inbox the server cannot observe replies, so it does not offer the
// challenge or accept "email" identifiers.
type MailInbox interface {
	// Fetch returns the currently unprocessed inbound messages as raw RFC 5322
	// bytes. Implementations should return only messages not yet acknowledged
	// (e.g. IMAP UNSEEN).
	Fetch(ctx context.Context) ([]InboundMail, error)
	// Ack marks the listed messages processed so a later Fetch does not return
	// them again (e.g. IMAP STORE +FLAGS \Seen).
	Ack(ctx context.Context, ids []string) error
}

// OutboundMail is a rendered challenge email handed to a MailSender.
type OutboundMail struct {
	From      string // envelope + header From (the challenge "from" address)
	To        string // the mailbox being validated
	MessageID string // header Message-ID (with angle brackets), for reply threading
	Subject   string // header Subject ("ACME: <token-part-1>")
	Raw       []byte // the complete, ready-to-transmit RFC 5322 message
}

// InboundMail is one raw inbound message returned by a MailInbox.
type InboundMail struct {
	// ID is the transport-specific handle (e.g. IMAP UID) passed back to Ack.
	ID string
	// Raw is the complete RFC 5322 message as received.
	Raw []byte
}

// EmailChallengeConfig configures the RFC 8823 email-reply-00 challenge. It is
// carried on Config.Email; the challenge is enabled only when both a MailSender
// and a MailInbox are supplied.
type EmailChallengeConfig struct {
	// From is the sender mailbox challenge emails originate from, echoed in each
	// challenge object's "from" field. Required when the challenge is enabled.
	From string
	// Sender dispatches challenge emails (SMTP). Required to enable the challenge.
	Sender MailSender
	// Inbox polls for replies (IMAP). Required to enable the challenge.
	Inbox MailInbox
	// Profile is the internal ca S/MIME issuance profile applied to email orders
	// (default "smime"). Every "email"-identifier order is issued under an S/MIME
	// profile so applySMIMEPolicy and the S/MIME Baseline-Requirements lint rules
	// gate finalize; a client-selected ACME profile that already maps to an S/MIME
	// profile is honored instead.
	Profile string
	// PollInterval is how often the leader-elected poller reads the inbox
	// (default emailPollDefaultInterval).
	PollInterval time.Duration
	// DKIM, when set, RSA-DKIM-signs (RFC 6376) every challenge email so the
	// receiving mailbox can prove its authenticity, as RFC 8823 §5 requires.
	DKIM *DKIMSigner
	// SubjectPrefix overrides the Subject label (default "ACME:").
	SubjectPrefix string
}

// emailPollDefaultInterval is the default inbound-mailbox poll cadence.
const emailPollDefaultInterval = 30 * time.Second

// acmeResponseBegin / acmeResponseEnd delimit the base64url(SHA-256(keyAuth))
// response inside the reply body (RFC 8823 §4).
const (
	acmeResponseBegin = "-----BEGIN ACME RESPONSE-----"
	acmeResponseEnd   = "-----END ACME RESPONSE-----"
)

// emailChallenger holds the resolved email-reply-00 configuration. It is built
// once in New from Config.Email; the request/poller logic hangs off *Server so
// it can reach the store, clock, and audit helpers.
type emailChallenger struct {
	from          string
	sender        MailSender
	inbox         MailInbox
	profile       string
	pollInterval  time.Duration
	dkim          *DKIMSigner
	subjectPrefix string
}

// newEmailChallenger validates and resolves an EmailChallengeConfig. It returns
// nil (the challenge disabled) when the config is absent or lacks either half of
// the transport, so a partial configuration silently degrades to "not offered"
// rather than advertising a challenge the server cannot complete.
func newEmailChallenger(cfg *EmailChallengeConfig) *emailChallenger {
	if cfg == nil || cfg.Sender == nil || cfg.Inbox == nil || strings.TrimSpace(cfg.From) == "" {
		return nil
	}
	ec := &emailChallenger{
		from:          strings.TrimSpace(cfg.From),
		sender:        cfg.Sender,
		inbox:         cfg.Inbox,
		profile:       strings.TrimSpace(cfg.Profile),
		pollInterval:  cfg.PollInterval,
		dkim:          cfg.DKIM,
		subjectPrefix: strings.TrimSpace(cfg.SubjectPrefix),
	}
	if ec.profile == "" {
		ec.profile = "smime"
	}
	if ec.pollInterval <= 0 {
		ec.pollInterval = emailPollDefaultInterval
	}
	if ec.subjectPrefix == "" {
		ec.subjectPrefix = "ACME:"
	}
	return ec
}

// emailEnabled reports whether the email-reply-00 challenge is offered.
func (s *Server) emailEnabled() bool { return s.email != nil }

// emailIssuanceProfile resolves the S/MIME issuance profile for an email order.
// A client-selected ACME profile that already maps to an S/MIME internal profile
// is honored; otherwise the configured default S/MIME profile is used. It fails
// closed if the resulting profile is not an S/MIME profile, so an email order can
// never be issued under a profile lacking the applySMIMEPolicy gate.
func (s *Server) emailIssuanceProfile(selected string) (string, *Problem) {
	if selected != "" {
		if p, err := ca.LookupProfile(selected); err == nil && p.SMIME != nil {
			return selected, nil
		}
	}
	prof := s.email.profile
	p, err := ca.LookupProfile(prof)
	if err != nil || p.SMIME == nil {
		return "", newProblem(probServerInternal, 500,
			fmt.Sprintf("email issuance profile %q is not a configured S/MIME profile", prof))
	}
	return prof, nil
}

// ---- respond: dispatch the challenge email --------------------------------

// sendEmailChallenge is invoked when a client responds to an email-reply-00
// challenge. It renders and dispatches the (optionally DKIM-signed) challenge
// email carrying token-part-1 in the Subject, records the Message-ID, and leaves
// the challenge in "processing" for the inbound poller to complete. It is
// idempotent: a repeated respond after the email has been sent is a no-op.
func (s *Server) sendEmailChallenge(acctID string, authz *models.ACMEAuthorization, chall *models.ACMEChallenge) {
	if chall.EmailMessageID != "" {
		// Already dispatched; a repeated respond must not re-send.
		return
	}
	mailbox := authz.IdentifierValue
	out, err := s.buildChallengeEmail(chall, mailbox)
	if err != nil {
		s.failEmailChallenge(acctID, authz, chall, "building challenge email: "+err.Error())
		metrics.ACMEEmailChallenge.Inc("send_error")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.email.sender.Send(ctx, out); err != nil {
		s.failEmailChallenge(acctID, authz, chall, "sending challenge email: "+err.Error())
		metrics.ACMEEmailChallenge.Inc("send_error")
		return
	}
	if err := s.db.MarkACMEChallengeEmailSent(chall.ID, out.MessageID); err != nil {
		log.Printf("acme: recording email-reply-00 dispatch for challenge %s: %v", chall.ID, err)
		return
	}
	chall.EmailMessageID = out.MessageID
	chall.Status = models.ACMEChallengeStatusProcessing
	metrics.ACMEEmailChallenge.Inc("sent")
	s.recordEmailEvent(acctID, authz.OrderID, audit.ResultSuccess,
		"email-reply-00 challenge sent to "+mailbox)
}

// failEmailChallenge marks an email challenge (and its authorization/order)
// invalid with the given detail — used when the challenge email cannot be built
// or dispatched.
func (s *Server) failEmailChallenge(acctID string, authz *models.ACMEAuthorization, chall *models.ACMEChallenge, detail string) {
	prob := newProblem(probServerInternal, 500, detail)
	errDoc := problemJSON(prob)
	_ = s.db.UpdateACMEChallenge(chall.ID, models.ACMEChallengeStatusInvalid, nil, errDoc)
	_ = s.db.UpdateACMEAuthorizationStatus(authz.ID, models.ACMEAuthzStatusInvalid)
	s.markOrderInvalid(authz.OrderID, prob)
	s.recordEmailEvent(acctID, authz.OrderID, audit.ResultError, detail)
}

// buildChallengeEmail renders the RFC 8823 §3 challenge email for a mailbox: the
// Subject carries token-part-1 ("ACME: <token-part-1>"), the From is the
// configured challenge sender, and the message is DKIM-signed when a signer is
// configured. The rendered bytes and Message-ID are returned for dispatch and
// reply-threading.
func (s *Server) buildChallengeEmail(chall *models.ACMEChallenge, mailbox string) (OutboundMail, error) {
	from := s.email.from
	messageID := "<" + newUUID() + "@" + hostFromAddress(from) + ">"
	subject := s.email.subjectPrefix + " " + chall.EmailToken1
	body := emailChallengeBody(mailbox)

	// Header order is fixed so the DKIM signature (which hashes headers in the
	// order listed in its h= tag) is reproducible.
	hdrs := []header{
		{"From", from},
		{"To", mailbox},
		{"Subject", subject},
		{"Date", s.now().Format(time.RFC1123Z)},
		{"Message-ID", messageID},
		// RFC 8823 §3 / RFC 3834: the challenge is machine-generated.
		{"Auto-Submitted", "auto-generated; type=acme"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "7bit"},
	}
	if s.email.dkim != nil {
		sig, err := s.email.dkim.sign(hdrs, []byte(body))
		if err != nil {
			return OutboundMail{}, fmt.Errorf("dkim: %w", err)
		}
		// The DKIM-Signature is prepended so verifiers see it first; it is not
		// part of its own h= list.
		hdrs = append([]header{{"DKIM-Signature", sig}}, hdrs...)
	}
	raw := renderMessage(hdrs, body)
	return OutboundMail{From: from, To: mailbox, MessageID: messageID, Subject: subject, Raw: raw}, nil
}

// emailChallengeBody is the human-readable challenge email body. The actionable
// token-part-1 travels in the Subject (RFC 8823 §3); the body only explains the
// message to a human who receives it directly.
func emailChallengeBody(mailbox string) string {
	return "This is an automated ACME (RFC 8823) email-validation challenge for " + mailbox + ".\r\n" +
		"\r\n" +
		"An S/MIME certificate has been requested for this address. If you (or your\r\n" +
		"mail client) initiated the request, reply to this message; your ACME client\r\n" +
		"will complete the challenge automatically. If you did not request a\r\n" +
		"certificate, no action is required and you may ignore this message.\r\n"
}

// ---- poll: validate inbound replies ---------------------------------------

// RunEmailChallengePoller runs the inbound-mailbox poll loop until ctx is
// cancelled. Register it as a leader-elected background job so a single replica
// consumes the shared mailbox. It is a no-op when the challenge is disabled.
func (s *Server) RunEmailChallengePoller(ctx context.Context) {
	if !s.emailEnabled() {
		return
	}
	t := time.NewTicker(s.email.pollInterval)
	defer t.Stop()
	for {
		if _, err := s.PollEmailChallenges(ctx); err != nil {
			log.Printf("acme: email-reply-00 inbox poll: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PollEmailChallenges reads the inbound mailbox once and validates every reply
// that threads back to a pending email-reply-00 challenge. It returns the number
// of challenges it transitioned (valid or invalid). Safe to call directly from
// tests. It is a no-op when the challenge is disabled.
func (s *Server) PollEmailChallenges(ctx context.Context) (int, error) {
	if !s.emailEnabled() {
		return 0, nil
	}
	msgs, err := s.email.inbox.Fetch(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetching inbound mail: %w", err)
	}
	if len(msgs) == 0 {
		return 0, nil
	}

	// Enumerate the challenges awaiting a reply and index them by Message-ID and
	// by token-part-1 so each inbound message can be threaded back cheaply.
	pending, err := s.db.ListACMEChallengesByStatusType(models.ACMEChallengeStatusProcessing, models.ACMEChallengeEmailReply00)
	if err != nil {
		return 0, fmt.Errorf("listing pending email challenges: %w", err)
	}
	byMessageID := make(map[string]*models.ACMEChallenge, len(pending))
	byToken1 := make(map[string]*models.ACMEChallenge, len(pending))
	for i := range pending {
		c := &pending[i]
		if c.EmailMessageID != "" {
			byMessageID[strings.ToLower(stripAngles(c.EmailMessageID))] = c
		}
		if c.EmailToken1 != "" {
			byToken1[c.EmailToken1] = c
		}
	}

	var ackIDs []string
	transitioned := 0
	for _, msg := range msgs {
		parsed, perr := mail.ReadMessage(bytes.NewReader(msg.Raw))
		if perr != nil {
			// Unparseable mail is junk for our purposes; acknowledge it so it is
			// not re-fetched forever.
			ackIDs = append(ackIDs, msg.ID)
			continue
		}
		chall := matchReplyToChallenge(parsed, byMessageID, byToken1)
		if chall == nil {
			// Not a reply to any pending challenge: unrelated mail, or a late/dup
			// reply to a challenge already resolved. A pending challenge always has
			// its Message-ID recorded before any reply can exist, so this is never a
			// not-yet-committed dispatch; acknowledge it either way to bound the
			// mailbox, flagging a stray ACME reply for visibility.
			if _, ok := extractACMEResponse(parsed); ok {
				metrics.ACMEEmailChallenge.Inc("no_match")
			}
			ackIDs = append(ackIDs, msg.ID)
			continue
		}
		metrics.ACMEEmailChallenge.Inc("reply_matched")
		// Acknowledge only once the reply has been acted on. A transient lookup
		// failure returns false and leaves the message for the next poll to retry.
		if s.validateEmailReply(chall, parsed) {
			transitioned++
			ackIDs = append(ackIDs, msg.ID)
		}
	}

	if len(ackIDs) > 0 {
		if err := s.email.inbox.Ack(ctx, ackIDs); err != nil {
			log.Printf("acme: acknowledging %d processed inbound message(s): %v", len(ackIDs), err)
		}
	}
	return transitioned, nil
}

// validateEmailReply checks one reply against its challenge and transitions the
// challenge (and its authorization/order). It returns true if the challenge was
// transitioned to a terminal state.
func (s *Server) validateEmailReply(chall *models.ACMEChallenge, msg *mail.Message) bool {
	authz, err := s.db.GetACMEAuthorization(chall.AuthzID)
	if err != nil || authz == nil {
		log.Printf("acme: email-reply-00: authorization lookup for challenge %s: %v", chall.ID, err)
		return false
	}
	acct, err := s.db.GetACMEAccount(authz.AccountID)
	if err != nil || acct == nil {
		log.Printf("acme: email-reply-00: account lookup for challenge %s: %v", chall.ID, err)
		return false
	}

	// A reply that arrives after the authorization has expired (or otherwise left
	// the pending state) must not resurrect it; acknowledge and discard it.
	s.expireAuthzIfNeeded(authz)
	if authz.Status != models.ACMEAuthzStatusPending {
		return true
	}

	// Anti-abuse: the reply MUST originate from the very mailbox being validated,
	// so a third party who learns token-part-1 cannot answer for someone else.
	if !replyFromMatches(msg, authz.IdentifierValue) {
		s.rejectEmailReply(acct.ID, authz, chall, "reply did not originate from the challenged mailbox")
		return true
	}

	response, ok := extractACMEResponse(msg)
	if !ok {
		s.rejectEmailReply(acct.ID, authz, chall, "reply did not contain an ACME response block")
		return true
	}

	// RFC 8823 §3-4: keyAuthorization is computed over the full token
	// (token-part-1 ‖ token-part-2); the reply carries base64url(SHA-256(keyAuth)).
	fullToken := chall.EmailToken1 + chall.Token
	keyAuth := keyAuthorization(fullToken, acct.Thumbprint)
	if !emailResponseMatches(response, keyAuth) {
		s.rejectEmailReply(acct.ID, authz, chall, "reply response did not match the expected key-authorization digest")
		return true
	}

	now := s.now().UTC()
	_ = s.db.UpdateACMEChallenge(chall.ID, models.ACMEChallengeStatusValid, &now, "")
	_ = s.db.UpdateACMEAuthorizationStatus(authz.ID, models.ACMEAuthzStatusValid)
	metrics.ACMEChallengeValidations.Inc(models.ACMEChallengeEmailReply00, "valid")
	s.recordEmailEvent(acct.ID, authz.OrderID, audit.ResultSuccess,
		"email-reply-00 "+authz.IdentifierValue+" validated")
	if order, _ := s.db.GetACMEOrder(authz.OrderID); order != nil {
		s.refreshOrderStatus(order)
	}
	return true
}

// rejectEmailReply marks an email challenge invalid after a failed reply.
func (s *Server) rejectEmailReply(acctID string, authz *models.ACMEAuthorization, chall *models.ACMEChallenge, detail string) {
	prob := newProblem(probIncorrectResponse, 403, detail)
	_ = s.db.UpdateACMEChallenge(chall.ID, models.ACMEChallengeStatusInvalid, nil, problemJSON(prob))
	_ = s.db.UpdateACMEAuthorizationStatus(authz.ID, models.ACMEAuthzStatusInvalid)
	metrics.ACMEChallengeValidations.Inc(models.ACMEChallengeEmailReply00, "invalid")
	s.markOrderInvalid(authz.OrderID, prob)
	s.recordEmailEvent(acctID, authz.OrderID, audit.ResultError,
		"email-reply-00 "+authz.IdentifierValue+": "+detail)
}

// recordEmailEvent appends a cert.acme_email audit event. The poller has no HTTP
// request, so (unlike recordEvent) no client IP is attached.
func (s *Server) recordEmailEvent(accountID, target, result, detail string) {
	e := &audit.Event{
		ID:         newUUID(),
		Actor:      "acme:" + accountID,
		ActorRoles: "acme",
		Action:     audit.ActionACMEEmail,
		Target:     target,
		Result:     result,
		Detail:     detail,
	}
	if err := s.db.AppendEvent(e); err != nil {
		log.Printf("acme: failed to append %s audit event: %v", audit.ActionACMEEmail, err)
	}
}

// ---- reply parsing --------------------------------------------------------

// matchReplyToChallenge threads an inbound message back to a pending challenge,
// preferring the In-Reply-To / References Message-ID linkage (RFC 5322 §3.6.4)
// and falling back to the "ACME: <token-part-1>" Subject label (RFC 8823 §4).
func matchReplyToChallenge(msg *mail.Message, byMessageID, byToken1 map[string]*models.ACMEChallenge) *models.ACMEChallenge {
	for _, id := range referencedMessageIDs(msg) {
		if c, ok := byMessageID[strings.ToLower(id)]; ok {
			return c
		}
	}
	if token1, ok := subjectToken1(msg.Header.Get("Subject")); ok {
		if c, ok := byToken1[token1]; ok {
			return c
		}
	}
	return nil
}

// referencedMessageIDs returns the Message-IDs a reply threads to, drawn from
// In-Reply-To and References (angle brackets stripped, lowercased by the caller).
func referencedMessageIDs(msg *mail.Message) []string {
	var out []string
	for _, h := range []string{"In-Reply-To", "References"} {
		for _, tok := range strings.Fields(msg.Header.Get(h)) {
			tok = stripAngles(strings.TrimSpace(tok))
			if tok != "" {
				out = append(out, tok)
			}
		}
	}
	return out
}

// subjectToken1 extracts token-part-1 from a challenge-reply Subject. Per RFC
// 8823 §4 the server decodes any RFC 2047 encoding, ignores any prefix before
// the "ACME:" label (typically "Re:"), and takes the following token.
func subjectToken1(subject string) (string, bool) {
	if dec, err := (&mime.WordDecoder{}).DecodeHeader(subject); err == nil {
		subject = dec
	}
	i := strings.Index(subject, "ACME:")
	if i < 0 {
		return "", false
	}
	rest := strings.TrimSpace(subject[i+len("ACME:"):])
	// token-part-1 is a single base64url token; take the first whitespace-
	// delimited field so a trailing comment cannot defeat the match.
	if f := strings.Fields(rest); len(f) > 0 {
		return f[0], true
	}
	return "", false
}

// replyFromMatches reports whether the reply's From header addresses the mailbox
// being validated, comparing under S/MIME mailbox normalization so case and
// punycode spelling differences do not defeat the check.
func replyFromMatches(msg *mail.Message, mailbox string) bool {
	want, err := smime.NormalizeEmail(mailbox)
	if err != nil {
		return false
	}
	from := msg.Header.Get("From")
	if addr, err := mail.ParseAddress(from); err == nil {
		from = addr.Address
	}
	got, err := smime.NormalizeEmail(from)
	if err != nil {
		return false
	}
	return got.Equal(want)
}

// extractACMEResponse returns the base64url response digest carried between the
// BEGIN/END ACME RESPONSE delimiters (RFC 8823 §4), searching the text/plain
// body (including the text/plain alternative of a multipart/alternative message)
// after decoding its Content-Transfer-Encoding.
func extractACMEResponse(msg *mail.Message) (string, bool) {
	ctype := msg.Header.Get("Content-Type")
	body, err := readBody(msg.Body, msg.Header.Get("Content-Transfer-Encoding"))
	if err != nil {
		return "", false
	}
	mediaType, params, _ := mime.ParseMediaType(ctype)
	if strings.HasPrefix(mediaType, "multipart/") {
		if resp, ok := responseFromMultipart(body, params["boundary"]); ok {
			return resp, true
		}
		// Fall through: some senders repeat the block in the multipart preamble.
	}
	return responseFromText(string(body))
}

// responseFromMultipart walks the parts of a multipart body looking for the ACME
// response block in a text/plain part (decoding each part's transfer encoding).
func responseFromMultipart(body []byte, boundary string) (string, bool) {
	if boundary == "" {
		return "", false
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			return "", false
		}
		mediaType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if mediaType != "" && !strings.HasPrefix(mediaType, "text/") {
			continue
		}
		decoded, err := readBody(part, part.Header.Get("Content-Transfer-Encoding"))
		if err != nil {
			continue
		}
		if resp, ok := responseFromText(string(decoded)); ok {
			return resp, true
		}
	}
}

// responseFromText scans a decoded text body for the BEGIN/END ACME RESPONSE
// block and returns the whitespace-stripped base64 payload between the markers.
func responseFromText(text string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inBlock := false
	var b strings.Builder
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == acmeResponseBegin:
			inBlock = true
		case line == acmeResponseEnd:
			if inBlock {
				return b.String(), b.Len() > 0
			}
		case inBlock:
			b.WriteString(line)
		}
	}
	return "", false
}

// emailResponseMatches reports whether the reply's response equals
// base64url(SHA-256(keyAuthorization)). The comparison is done on the raw digest
// bytes so it tolerates the client's choice of base64 alphabet and padding
// (RFC 8823 §4 examples use padded base64url).
func emailResponseMatches(response, keyAuth string) bool {
	want := sha256.Sum256([]byte(keyAuth))
	got, ok := decodeFlexibleBase64(response)
	if !ok {
		return false
	}
	return bytes.Equal(got, want[:])
}

// decodeFlexibleBase64 decodes a base64 string under any of the four common
// alphabet/padding combinations, tolerating embedded whitespace.
func decodeFlexibleBase64(s string) ([]byte, bool) {
	s = strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// readBody reads all of r and decodes it according to a MIME
// Content-Transfer-Encoding (base64 / quoted-printable / identity).
func readBody(r io.Reader, cte string) ([]byte, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		if b, err := decodeAllBase64(raw); err == nil {
			return b, nil
		}
		return raw, nil
	case "quoted-printable":
		if b, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(raw))); err == nil {
			return b, nil
		}
		return raw, nil
	default:
		return raw, nil
	}
}

func decodeAllBase64(b []byte) ([]byte, error) {
	s := strings.Join(strings.Fields(string(b)), "")
	if out, err := base64.StdEncoding.DecodeString(s); err == nil {
		return out, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// ---- message rendering ----------------------------------------------------

// header is one RFC 5322 header field. The challenge email is assembled from an
// ordered slice so the DKIM signature over the h= header list is reproducible.
type header struct{ Name, Value string }

// renderMessage assembles headers and a body into a CRLF-delimited RFC 5322
// message. Header values are emitted verbatim (callers supply short, single-line
// values); the body is expected to already use CRLF line endings.
func renderMessage(hdrs []header, body string) []byte {
	var b bytes.Buffer
	for _, h := range hdrs {
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}

// ---- small helpers --------------------------------------------------------

// stripAngles removes surrounding angle brackets from a Message-ID token.
func stripAngles(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

// hostFromAddress returns the domain of an addr-spec for Message-ID synthesis,
// defaulting to "localhost" when it cannot be determined.
func hostFromAddress(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 && i < len(addr)-1 {
		return addr[i+1:]
	}
	return "localhost"
}

// problemJSON serializes a Problem for storage in a challenge/order error column.
func problemJSON(p *Problem) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(b)
}
