package acme

// These tests cover the RFC 8823 email-reply-00 challenge's pure logic — DKIM
// signing/canonicalization, challenge-reply parsing, and response-digest
// validation — with no HSM, DB, or SMTP/IMAP, so they run in the default build
// alongside the tagged end-to-end flow in email_test.go.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ---- DKIM -----------------------------------------------------------------

func TestDKIMSignAndVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := &DKIMSigner{
		Domain:   "pki.example.com",
		Selector: "acme",
		Signer:   key,
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
	}

	hdrs := []header{
		{"From", "acme-challenge@pki.example.com"},
		{"To", "alice@example.com"},
		{"Subject", "ACME: dGVzdC10b2tlbi1wYXJ0LTE"},
		{"Date", "Mon, 01 Jan 2024 00:00:00 +0000"},
		{"Message-ID", "<abc@pki.example.com>"},
		{"Auto-Submitted", "auto-generated; type=acme"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "7bit"},
	}
	body := []byte("A challenge body.\r\nWith two lines.\r\n")

	sig, err := signer.sign(hdrs, body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tags := parseDKIMTags(sig)
	if tags["v"] != "1" || tags["a"] != "rsa-sha256" || tags["c"] != "relaxed/relaxed" {
		t.Errorf("unexpected static tags: %v", tags)
	}
	if tags["d"] != "pki.example.com" || tags["s"] != "acme" {
		t.Errorf("d/s tags = %q/%q", tags["d"], tags["s"])
	}

	// The body hash must equal base64(SHA-256(relaxed-canonicalized body)).
	wantBodyHash := sha256.Sum256(canonBodyRelaxed(body))
	if got, want := tags["bh"], base64.StdEncoding.EncodeToString(wantBodyHash[:]); got != want {
		t.Errorf("bh tag = %q, want %q", got, want)
	}

	// Reconstruct the signed hash input (headers + DKIM-Signature with an empty
	// b=), then verify the RSA signature with the public key.
	emptied := emptyBTag(sig)
	var input strings.Builder
	for _, h := range hdrs {
		input.WriteString(canonHeaderRelaxed(h.Name, h.Value))
		input.WriteString("\r\n")
	}
	input.WriteString(canonHeaderRelaxed("DKIM-Signature", emptied))
	digest := sha256.Sum256([]byte(input.String()))

	sigBytes, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil {
		t.Fatalf("decode b tag: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		t.Fatalf("DKIM signature does not verify: %v", err)
	}

	// h= must list exactly the signed headers, in order.
	wantH := "from:to:subject:date:message-id:auto-submitted:mime-version:content-type:content-transfer-encoding"
	if tags["h"] != wantH {
		t.Errorf("h tag = %q, want %q", tags["h"], wantH)
	}
}

func TestCanonBodyRelaxed(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"collapses trailing ws and blank lines": {
			in:   "line  one \t\r\nline two\r\n\r\n\r\n",
			want: "line one\r\nline two\r\n",
		},
		"empty body":          {in: "\r\n\r\n", want: ""},
		"single line no crlf": {in: "hello", want: "hello\r\n"},
	}
	for name, c := range cases {
		if got := string(canonBodyRelaxed([]byte(c.in))); got != c.want {
			t.Errorf("%s: canonBodyRelaxed(%q) = %q, want %q", name, c.in, got, c.want)
		}
	}
}

func TestCanonHeaderRelaxed(t *testing.T) {
	// Name lowercased, WSP around the colon and internal runs collapsed.
	if got := canonHeaderRelaxed("Subject", "  ACME:   token  "); got != "subject:ACME: token" {
		t.Errorf("canonHeaderRelaxed = %q", got)
	}
	// Folding is unfolded.
	if got := canonHeaderRelaxed("From", "a@b\r\n c@d"); got != "from:a@b c@d" {
		t.Errorf("canonHeaderRelaxed unfold = %q", got)
	}
}

// ---- subject / reply matching ---------------------------------------------

func TestSubjectToken1(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		found bool
	}{
		{"ACME: abc123", "abc123", true},
		{"Re: ACME: abc123", "abc123", true},
		{"RE: Re: ACME:  abc123 (auto)", "abc123", true},
		{"no acme label here", "", false},
		{"ACME:", "", false},
	}
	for _, c := range cases {
		got, ok := subjectToken1(c.in)
		if ok != c.found || got != c.want {
			t.Errorf("subjectToken1(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.found)
		}
	}
}

func TestReplyFromMatches(t *testing.T) {
	msg := func(from string) *mail.Message {
		m, err := mail.ReadMessage(strings.NewReader("From: " + from + "\r\n\r\nbody\r\n"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return m
	}
	if !replyFromMatches(msg("Alice <alice@example.com>"), "alice@example.com") {
		t.Error("display-name From should match the mailbox")
	}
	if !replyFromMatches(msg("ALICE@example.com"), "alice@example.com") {
		t.Error("case-folded local part should match")
	}
	if replyFromMatches(msg("mallory@example.com"), "alice@example.com") {
		t.Error("different mailbox must not match")
	}
}

func TestMatchReplyToChallenge(t *testing.T) {
	chByID := &models.ACMEChallenge{ID: "c1", EmailMessageID: "<mid-1@pki>", EmailToken1: "tok1"}
	chByTok := &models.ACMEChallenge{ID: "c2", EmailMessageID: "<mid-2@pki>", EmailToken1: "tok2"}
	byMessageID := map[string]*models.ACMEChallenge{"mid-1@pki": chByID, "mid-2@pki": chByTok}
	byToken1 := map[string]*models.ACMEChallenge{"tok1": chByID, "tok2": chByTok}

	// In-Reply-To linkage wins.
	m1 := mustMsg(t, "In-Reply-To: <mid-1@pki>\r\nSubject: Re: unrelated\r\n\r\nx\r\n")
	if got := matchReplyToChallenge(m1, byMessageID, byToken1); got != chByID {
		t.Errorf("In-Reply-To match = %v, want c1", got)
	}
	// Subject token fallback when there is no threading header.
	m2 := mustMsg(t, "Subject: Re: ACME: tok2\r\n\r\nx\r\n")
	if got := matchReplyToChallenge(m2, byMessageID, byToken1); got != chByTok {
		t.Errorf("subject-token match = %v, want c2", got)
	}
	// No linkage at all.
	m3 := mustMsg(t, "Subject: hello\r\n\r\nx\r\n")
	if got := matchReplyToChallenge(m3, byMessageID, byToken1); got != nil {
		t.Errorf("unmatched reply = %v, want nil", got)
	}
}

// ---- response extraction + digest -----------------------------------------

func TestExtractACMEResponse(t *testing.T) {
	const resp = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0="
	block := acmeResponseBegin + "\r\n" + resp + "\r\n" + acmeResponseEnd + "\r\n"

	t.Run("plain text/plain", func(t *testing.T) {
		m := mustMsg(t, "Content-Type: text/plain\r\n\r\nHi\r\n"+block)
		if got, ok := extractACMEResponse(m); !ok || got != resp {
			t.Errorf("plain = (%q,%v)", got, ok)
		}
	})
	t.Run("multi-line base64 joined", func(t *testing.T) {
		split := acmeResponseBegin + "\r\nLoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowy\r\njxAjEuX0=\r\n" + acmeResponseEnd + "\r\n"
		m := mustMsg(t, "\r\n"+split)
		if got, ok := extractACMEResponse(m); !ok || got != resp {
			t.Errorf("multiline = (%q,%v)", got, ok)
		}
	})
	t.Run("multipart/alternative", func(t *testing.T) {
		raw := "Content-Type: multipart/alternative; boundary=BND\r\n\r\n" +
			"--BND\r\nContent-Type: text/html\r\n\r\n<p>hello</p>\r\n" +
			"--BND\r\nContent-Type: text/plain\r\n\r\n" + block +
			"--BND--\r\n"
		m := mustMsg(t, raw)
		if got, ok := extractACMEResponse(m); !ok || got != resp {
			t.Errorf("multipart = (%q,%v)", got, ok)
		}
	})
	t.Run("base64 transfer-encoding", func(t *testing.T) {
		enc := base64.StdEncoding.EncodeToString([]byte(block))
		m := mustMsg(t, "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"+enc+"\r\n")
		if got, ok := extractACMEResponse(m); !ok || got != resp {
			t.Errorf("base64 cte = (%q,%v)", got, ok)
		}
	})
	t.Run("no block", func(t *testing.T) {
		m := mustMsg(t, "\r\njust a normal reply\r\n")
		if _, ok := extractACMEResponse(m); ok {
			t.Error("expected no response block")
		}
	})
}

func TestEmailResponseMatches(t *testing.T) {
	keyAuth := "tok1tok2.thumbprintvalue"
	sum := sha256.Sum256([]byte(keyAuth))
	for _, enc := range []struct {
		name string
		s    string
	}{
		{"raw-url", base64.RawURLEncoding.EncodeToString(sum[:])},
		{"padded-url", base64.URLEncoding.EncodeToString(sum[:])},
		{"padded-std", base64.StdEncoding.EncodeToString(sum[:])},
	} {
		if !emailResponseMatches(enc.s, keyAuth) {
			t.Errorf("%s: expected match for %q", enc.name, enc.s)
		}
	}
	if emailResponseMatches(base64.RawURLEncoding.EncodeToString(sum[:]), "wrong-key-auth") {
		t.Error("mismatched keyAuth must not validate")
	}
	if emailResponseMatches("!!!not base64!!!", keyAuth) {
		t.Error("undecodable response must not validate")
	}
}

// ---- helpers --------------------------------------------------------------

func mustMsg(t *testing.T, raw string) *mail.Message {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	return m
}

// parseDKIMTags splits a DKIM-Signature value into its tag map (values may
// contain '=' padding, so only the first '=' separates key from value).
func parseDKIMTags(sig string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(sig, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '='); i >= 0 {
			out[strings.TrimSpace(part[:i])] = strings.TrimSpace(part[i+1:])
		}
	}
	return out
}

// emptyBTag returns the DKIM-Signature value with the b= tag value removed,
// as a verifier reconstructs it before hashing.
func emptyBTag(sig string) string {
	if i := strings.LastIndex(sig, "; b="); i >= 0 {
		return sig[:i+4]
	}
	return sig
}
