//go:build sqlite

package acme

// Coverage for the two email-reply-00 (RFC 8823) paths with no tests: the
// leader-elected inbox poll loop and the failure path that closes a challenge out
// when its challenge email cannot be built or sent.
//
// The loop is a long-lived background job, so the properties that matter are
// liveness ones: it must return promptly when its context is cancelled (a leaked
// poller on a replica that lost leadership would keep consuming the shared
// mailbox), and a transient inbox error must not silently kill it (a dead poller
// means every email authorization hangs pending until it expires).
//
// The failure path matters because it is what stops a challenge whose email was
// never delivered from sitting in "processing" forever: it must fail the
// challenge, its authorization and its order closed, and leave an audit trail.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ---- controllable mail transport ------------------------------------------

// scriptedMailTransport is a MailSender + MailInbox whose behaviour each test
// scripts: Send may fail, Fetch may fail, and both are counted so a test can
// observe that the poll loop kept running.
type scriptedMailTransport struct {
	mu        sync.Mutex
	sends     int
	fetches   int
	sendErr   error
	fetchErr  error
	fetched   chan struct{} // buffered; one token per Fetch
	lastSent  OutboundMail
	inbox     []InboundMail
	ackedIDs  []string
	ackErrSet bool
}

func newScriptedMailTransport() *scriptedMailTransport {
	return &scriptedMailTransport{fetched: make(chan struct{}, 1024)}
}

func (s *scriptedMailTransport) Send(_ context.Context, msg OutboundMail) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sends++
	if s.sendErr != nil {
		return s.sendErr
	}
	s.lastSent = msg
	return nil
}

func (s *scriptedMailTransport) Fetch(_ context.Context) ([]InboundMail, error) {
	s.mu.Lock()
	s.fetches++
	err := s.fetchErr
	msgs := s.inbox
	s.mu.Unlock()
	select {
	case s.fetched <- struct{}{}:
	default:
	}
	if err != nil {
		return nil, err
	}
	return msgs, nil
}

func (s *scriptedMailTransport) Ack(_ context.Context, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ackedIDs = append(s.ackedIDs, ids...)
	if s.ackErrSet {
		return errors.New("ack failed")
	}
	return nil
}

func (s *scriptedMailTransport) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func (s *scriptedMailTransport) sendCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sends
}

// withScriptedEmail wires the scripted transport in as the email-reply-00
// transport, with an optional DKIM signer and poll interval.
func withScriptedEmail(tr *scriptedMailTransport, poll time.Duration, dkim *DKIMSigner) func(*Config) {
	return func(cfg *Config) {
		cfg.Email = &EmailChallengeConfig{
			From:         "acme-challenge@pki.example.test",
			Sender:       tr,
			Inbox:        tr,
			Profile:      "smime",
			PollInterval: poll,
			DKIM:         dkim,
		}
	}
}

// runPoller starts the poll loop and returns a channel closed when it returns.
func runPoller(srv *Server, ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.RunEmailChallengePoller(ctx)
	}()
	return done
}

// awaitReturn fails the test if the poller has not returned within d.
func awaitReturn(t *testing.T, done <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("RunEmailChallengePoller did not return %s within %s (leaked goroutine)", what, d)
	}
}

// ---- RunEmailChallengePoller ----------------------------------------------

// TestRunEmailChallengePoller_DisabledIsNoOp confirms the loop is inert when the
// challenge is not configured: it must return immediately even under a context
// that is never cancelled, rather than spin on a nil inbox.
func TestRunEmailChallengePoller_DisabledIsNoOp(t *testing.T) {
	env := newTestEnv(t) // no email challenge configured
	awaitReturn(t, runPoller(env.srv, context.Background()), 5*time.Second, "with the challenge disabled")
}

// TestRunEmailChallengePoller_HonorsCancellation is the liveness property: once
// the loop is parked waiting for the next tick, cancelling the context must return
// it promptly. The poll interval is set far beyond the test's patience so a return
// can only come from the cancellation branch.
func TestRunEmailChallengePoller_HonorsCancellation(t *testing.T) {
	tr := newScriptedMailTransport()
	env := newTestEnv(t, withScriptedEmail(tr, time.Hour, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := runPoller(env.srv, ctx)

	// Wait for the immediate first poll, so the loop is definitely parked in its
	// select when the cancellation lands.
	select {
	case <-tr.fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("the poller never performed its initial inbox poll")
	}

	cancel()
	awaitReturn(t, done, 5*time.Second, "after cancellation")

	// It polled once and then stopped; it must not keep polling after returning.
	after := tr.fetchCount()
	time.Sleep(50 * time.Millisecond)
	if got := tr.fetchCount(); got != after {
		t.Errorf("inbox polled %d more times after the poller returned", got-after)
	}
}

// TestRunEmailChallengePoller_AlreadyCancelled confirms a context cancelled before
// the call still returns promptly (the loop polls once, then sees the cancellation
// on its first select).
func TestRunEmailChallengePoller_AlreadyCancelled(t *testing.T) {
	tr := newScriptedMailTransport()
	env := newTestEnv(t, withScriptedEmail(tr, time.Hour, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	awaitReturn(t, runPoller(env.srv, ctx), 5*time.Second, "for an already-cancelled context")
}

// TestRunEmailChallengePoller_InboxErrorDoesNotKillLoop asserts a failing inbox is
// logged and retried rather than ending the loop. A poller that died on the first
// IMAP hiccup would leave every subsequent email authorization stuck in
// "processing" until it expired.
func TestRunEmailChallengePoller_InboxErrorDoesNotKillLoop(t *testing.T) {
	tr := newScriptedMailTransport()
	tr.fetchErr = errors.New("simulated IMAP outage")
	env := newTestEnv(t, withScriptedEmail(tr, 5*time.Millisecond, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := runPoller(env.srv, ctx)

	// Three polls means the loop survived at least two consecutive failures.
	const want = 3
	for i := 0; i < want; i++ {
		select {
		case <-tr.fetched:
		case <-time.After(5 * time.Second):
			t.Fatalf("the poller stopped after %d failing polls; it must keep retrying", i)
		}
	}

	// Recovery: once the inbox works again, the loop is still there to use it.
	tr.mu.Lock()
	tr.fetchErr = nil
	tr.mu.Unlock()
	select {
	case <-tr.fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("the poller did not poll again after the inbox recovered")
	}

	cancel()
	awaitReturn(t, done, 5*time.Second, "after cancellation")
	if tr.fetchCount() < want {
		t.Errorf("inbox polled %d times, want at least %d", tr.fetchCount(), want)
	}
}

// TestPollEmailChallenges_DisabledIsNoOp pins the single-shot form the poller
// wraps: with the challenge disabled it must not touch a nil inbox.
func TestPollEmailChallenges_DisabledIsNoOp(t *testing.T) {
	env := newTestEnv(t)
	n, err := env.srv.PollEmailChallenges(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("PollEmailChallenges (disabled) = (%d, %v), want (0, nil)", n, err)
	}
}

// TestPollEmailChallenges_SurfacesInboxError confirms the error is returned rather
// than swallowed, which is what lets the loop log it.
func TestPollEmailChallenges_SurfacesInboxError(t *testing.T) {
	tr := newScriptedMailTransport()
	tr.fetchErr = errors.New("simulated IMAP outage")
	env := newTestEnv(t, withScriptedEmail(tr, time.Hour, nil))
	if n, err := env.srv.PollEmailChallenges(context.Background()); err == nil || n != 0 {
		t.Fatalf("PollEmailChallenges = (%d, %v), want (0, error)", n, err)
	}
}

// ---- failEmailChallenge ---------------------------------------------------

// newEmailOrder places an order for a single "email" identifier and returns the
// order URL plus the email-reply-00 challenge URL the server offers.
func newEmailOrder(t *testing.T, rc *rawClient, mailbox string) (orderURL, authzURL, challURL string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"identifiers": []map[string]string{{"type": "email", "value": mailbox}},
	})
	if err != nil {
		t.Fatalf("marshal newOrder payload: %v", err)
	}
	resp, body := rc.post(rc.dir.NewOrder, payload, false)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder(email) status = %d, want 201: %s", resp.StatusCode, body)
	}
	var ord rawOrder
	if err := json.Unmarshal(body, &ord); err != nil {
		t.Fatalf("decode order: %v (%s)", err, body)
	}
	if len(ord.Authorizations) != 1 {
		t.Fatalf("order has %d authorizations, want 1: %s", len(ord.Authorizations), body)
	}
	authzURL = ord.Authorizations[0]

	_, ab := rc.post(authzURL, nil, false)
	var az rawAuthz
	if err := json.Unmarshal(ab, &az); err != nil {
		t.Fatalf("decode authz: %v (%s)", err, ab)
	}
	for _, ch := range az.Challenges {
		if ch.Type == models.ACMEChallengeEmailReply00 {
			return resp.Header.Get("Location"), authzURL, ch.URL
		}
	}
	t.Fatalf("server did not offer an email-reply-00 challenge: %s", ab)
	return "", "", ""
}

// assertEmailChallengeFailedClosed checks the whole chain moved to a terminal
// failure: challenge, authorization and order all invalid, with an audit record.
func assertEmailChallengeFailedClosed(t *testing.T, env *testEnv, rc *rawClient,
	orderURL, authzURL, challURL, wantDetail string) {
	t.Helper()

	_, cb := rc.post(challURL, nil, false)
	var ch struct {
		Status string   `json:"status"`
		Error  *Problem `json:"error"`
	}
	if err := json.Unmarshal(cb, &ch); err != nil {
		t.Fatalf("decode challenge: %v (%s)", err, cb)
	}
	if ch.Status != "invalid" {
		t.Errorf("challenge status = %q, want invalid: %s", ch.Status, cb)
	}
	if ch.Error == nil || ch.Error.Type != probServerInternal {
		t.Errorf("challenge error = %+v, want a %s problem", ch.Error, probServerInternal)
	}

	_, ab := rc.post(authzURL, nil, false)
	var az rawAuthz
	_ = json.Unmarshal(ab, &az)
	if az.Status != "invalid" {
		t.Errorf("authorization status = %q, want invalid: %s", az.Status, ab)
	}

	order, err := env.db.GetACMEOrder(idFromURL(orderURL))
	if err != nil || order == nil {
		t.Fatalf("GetACMEOrder(%q): %v", orderURL, err)
	}
	if order.Status != models.ACMEOrderStatusInvalid {
		t.Errorf("order status = %q, want invalid", order.Status)
	}

	events, _, err := env.db.ListEvents(audit.ActionACMEEmail, "", "", 200, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.Result == audit.ResultError && strings.Contains(e.Detail, wantDetail) {
			found = true
		}
	}
	if !found {
		t.Errorf("no errored cert.acme_email audit event mentioning %q: %+v", wantDetail, events)
	}
}

// TestFailEmailChallenge_SendError covers the dispatch failure path: when the SMTP
// sender rejects the challenge email, the challenge must not be parked in
// "processing" (where nothing would ever complete it) — it fails closed along with
// its authorization and order.
func TestFailEmailChallenge_SendError(t *testing.T) {
	tr := newScriptedMailTransport()
	tr.sendErr = errors.New("simulated SMTP rejection")
	env := newTestEnv(t, withScriptedEmail(tr, time.Hour, nil))

	rc := newRawClient(t, env.dirURL)
	rc.register()
	orderURL, authzURL, challURL := newEmailOrder(t, rc, "send-fails@example.com")

	if got := respondChallenge(t, rc, challURL, []byte(`{}`)); got.Status != "invalid" {
		t.Fatalf("challenge status = %q, want invalid: %+v", got.Status, got)
	}
	if tr.sendCount() != 1 {
		t.Errorf("Send called %d times, want 1", tr.sendCount())
	}
	assertEmailChallengeFailedClosed(t, env, rc, orderURL, authzURL, challURL, "sending challenge email")

	// A repeated respond must not resurrect the challenge or re-send.
	resp, body := rc.post(challURL, []byte(`{}`), false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("re-responding to a failed challenge = %d, want 400: %s", resp.StatusCode, body)
	}
	if tr.sendCount() != 1 {
		t.Errorf("Send called %d times after a repeated respond, want 1", tr.sendCount())
	}
}

// TestFailEmailChallenge_BuildError covers the other call site: the challenge email
// cannot even be rendered (here because the configured DKIM key refuses to sign).
// Nothing is dispatched, and the challenge still fails closed rather than hanging.
func TestFailEmailChallenge_BuildError(t *testing.T) {
	tr := newScriptedMailTransport()
	env := newTestEnv(t, withScriptedEmail(tr, time.Hour,
		&DKIMSigner{Domain: "pki.example.test", Selector: "acme", Signer: nilSigner{}}))

	rc := newRawClient(t, env.dirURL)
	rc.register()
	orderURL, authzURL, challURL := newEmailOrder(t, rc, "build-fails@example.com")

	if got := respondChallenge(t, rc, challURL, []byte(`{}`)); got.Status != "invalid" {
		t.Fatalf("challenge status = %q, want invalid: %+v", got.Status, got)
	}
	if tr.sendCount() != 0 {
		t.Errorf("Send called %d times although the message could not be built", tr.sendCount())
	}
	assertEmailChallengeFailedClosed(t, env, rc, orderURL, authzURL, challURL, "building challenge email")
}
