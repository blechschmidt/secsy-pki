package celpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Request-scoped facts.
//
// Three of the five fact sets a rule sees — the JWT, the URL, the body — belong
// to the HTTP request, not to the certificate. They are collected once, at the
// edge, into a holder carried in the request context, and read again deep in the
// issuance path where the gate runs.
//
// The context is the right carrier precisely because these facts are
// request-scoped and optional: ca.Manager's methods already take a
// context.Context from every surface (REST, gRPC, ACME, EST, SCEP, CMP, the
// CLI), so the gate sees whatever the edge captured without a new parameter on
// a dozen signatures — and sees *nothing* on a path that captured nothing,
// which is exactly the right reading for a protocol enrollment that presented
// no token and no JSON body.

type factsKey struct{}

// Facts holds the HTTP-side facts of one request. It is mutable because the
// pieces arrive at different layers: the capture middleware knows the URL and
// the body, the authentication middleware knows the token and the principal, and
// the handler knows which surface it is. Every accessor is mutex-guarded: a
// single request is served by one goroutine, but a handler may fan out (bulk
// issuance issues concurrently) and each of those reads the same holder.
type Facts struct {
	mu        sync.RWMutex
	url       RequestURL
	body      map[string]interface{}
	jwt       map[string]interface{}
	principal Principal
	source    string
	operation string
}

// NewFacts returns an empty fact holder.
func NewFacts() *Facts { return &Facts{} }

// WithFacts attaches f to ctx. It is exported so a test (or a non-HTTP surface
// that nonetheless knows the caller's identity) can supply facts directly.
func WithFacts(ctx context.Context, f *Facts) context.Context {
	if f == nil {
		return ctx
	}
	return context.WithValue(ctx, factsKey{}, f)
}

// FromContext returns the facts captured for this request, or nil when the
// request did not pass through a capturing layer. A nil *Facts is usable: its
// accessors are nil-safe and yield empty facts.
func FromContext(ctx context.Context) *Facts {
	if ctx == nil {
		return nil
	}
	f, _ := ctx.Value(factsKey{}).(*Facts)
	return f
}

// SetURL records the request URL.
func (f *Facts) SetURL(u RequestURL) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.url = u
	f.mu.Unlock()
}

// SetBody records the decoded request body parameters.
func (f *Facts) SetBody(b map[string]interface{}) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.body = b
	f.mu.Unlock()
}

// SetJWT records the verified claim set of the token the caller presented.
//
// It must only ever be called with claims a verifier accepted. An unverified
// claim set reaching a rule would turn every `jwt.*` restriction into a
// decoration: the requester would choose the value the policy tests.
func (f *Facts) SetJWT(claims map[string]interface{}) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.jwt = claims
	f.mu.Unlock()
}

// SetPrincipal records the authenticated caller.
func (f *Facts) SetPrincipal(p Principal) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.principal = p
	f.mu.Unlock()
}

// SetSource records the issuance surface, when the handler knows it more
// precisely than the capture layer could.
func (f *Facts) SetSource(source string) {
	if f == nil || source == "" {
		return
	}
	f.mu.Lock()
	f.source = source
	f.mu.Unlock()
}

// SetOperation records what is being asked of the CA, when a caller knows it
// more precisely than the gate could infer. A renewal re-signs a certificate
// and so passes through the same gate as a first issuance; without this it
// would be indistinguishable from one, and a rule written
// `request.operation == "renew"` would silently never fire — a policy hole that
// reads as a working rule.
func (f *Facts) SetOperation(op string) {
	if f == nil || op == "" {
		return
	}
	f.mu.Lock()
	f.operation = op
	f.mu.Unlock()
}

// Operation returns the recorded operation, or "" when none was recorded.
func (f *Facts) Operation() string {
	if f == nil {
		return ""
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.operation
}

// Source returns the recorded issuance surface, or "" when none was recorded.
func (f *Facts) Source() string {
	if f == nil {
		return ""
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.source
}

// Input combines the captured HTTP facts with the certificate request into the
// complete fact set a rule is evaluated against. A nil holder yields an input
// whose HTTP facts are empty and whose principal is unauthenticated — the
// correct reading for an automated enrollment, and the reason a rule that
// requires a claim denies one rather than passing it.
func (f *Facts) Input(req CertRequest) Input {
	in := Input{Request: req, Now: time.Now().UTC()}
	if f == nil {
		// Normalize even here, so a caller that reads in.Request.Source (the audit
		// detail, the dry-run echo) sees "unknown" rather than an empty string on a
		// path that never passed through an HTTP layer.
		in.Request = in.Request.normalized()
		return in
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	in.URL = f.url
	in.Body = cloneMap(f.body)
	in.JWT = cloneMap(f.jwt)
	in.Principal = f.principal
	if req.Source == "" || req.Source == SourceUnknown {
		if f.source != "" {
			in.Request.Source = f.source
		} else if f.url.Present {
			in.Request.Source = SourceREST
		}
	}
	if f.operation != "" && (in.Request.Operation == "" || in.Request.Operation == OpIssue) {
		in.Request.Operation = f.operation
	}
	if in.Request.RequestedBy == "" {
		in.Request.RequestedBy = f.principal.Subject
	}
	in.Request = in.Request.normalized()
	return in
}

// cloneMap copies the top level of a fact map so an evaluation cannot observe a
// concurrent write by another layer. The values themselves are not deep-copied:
// nothing in this package mutates them, and CEL cannot.
func cloneMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// maxCapturedBodyBytes bounds how much of a request body is decoded for the
// engine (256 KiB). It is far larger than any certificate request — a CSR is a
// couple of kilobytes — and far smaller than the server's 8 MiB body cap, so a
// bulk payload or a backup upload is passed through untouched rather than
// buffered in full. A body past the bound is simply not exposed: it is not
// something a certificate rule has reason to inspect, and silently truncating
// it would give a rule a *wrong* view, which is worse than no view.
const maxCapturedBodyBytes = 256 << 10

// Capture is the middleware that collects the HTTP-side facts for every request
// it wraps: the URL as an object, and the request body's parameters when the
// body is a JSON object or an HTML form. The authentication layer adds the
// verified token and principal to the same holder.
//
// The body is read into memory and the stream is restored, so a handler
// downstream decodes exactly the bytes the client sent. A body larger than
// maxCapturedBodyBytes, or in any other content type (DER, PKCS#10, PKCS#7, the
// enrollment protocols' binary payloads), is streamed through without being
// buffered whole.
func Capture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := NewFacts()
		f.SetURL(URLFrom(r))
		if params, body, ok := captureBody(r); ok {
			f.SetBody(params)
			r.Body = body
		}
		next.ServeHTTP(w, r.WithContext(WithFacts(r.Context(), f)))
	})
}

// captureBody decodes the request body's parameters when it is a shape the
// engine can expose, returning the parameters and a replacement body that
// replays the consumed bytes. The second return is false when nothing was
// consumed, in which case the caller must leave r.Body alone.
func captureBody(r *http.Request) (map[string]interface{}, io.ReadCloser, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil, false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
		return nil, nil, false
	}
	kind := bodyKind(r.Header.Get("Content-Type"))
	if kind == bodyOther {
		return nil, nil, false
	}

	// Read one byte past the bound so an over-long body is recognized as such
	// rather than decoded from a truncated prefix.
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxCapturedBodyBytes+1))
	if err != nil {
		// The body could not be read. Hand the handler a reader over whatever
		// arrived plus the original error-producing stream so the failure surfaces
		// there, where it can be reported to the client, rather than here.
		return nil, replay(buf, r.Body), true
	}
	replacement := replay(buf, r.Body)
	if len(buf) > maxCapturedBodyBytes {
		return nil, replacement, true
	}

	switch kind {
	case bodyJSON:
		return decodeJSONObject(buf), replacement, true
	case bodyForm:
		return decodeForm(buf), replacement, true
	}
	return nil, replacement, true
}

type bodyShape int

const (
	bodyOther bodyShape = iota
	bodyJSON
	bodyForm
)

// bodyKind classifies a Content-Type. An absent Content-Type is treated as JSON:
// this PKI's own clients and the console send JSON, and some set no header.
func bodyKind(ct string) bodyShape {
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return bodyJSON
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return bodyOther
	}
	mt = strings.ToLower(mt)
	switch {
	case mt == "application/json", strings.HasSuffix(mt, "+json"):
		return bodyJSON
	case mt == "application/x-www-form-urlencoded":
		return bodyForm
	}
	return bodyOther
}

// decodeJSONObject decodes a JSON object into the body map. A body that is valid
// JSON but not an object (an array, a bare string) exposes no parameters: `body`
// is a map by declaration, and inventing a key for a non-object would be a
// vocabulary nobody could document.
func decodeJSONObject(buf []byte) map[string]interface{} {
	if len(bytes.TrimSpace(buf)) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil
	}
	return m
}

// decodeForm decodes an HTML form body. A repeated parameter is exposed as the
// list of its values; a single one as a string, which is what an expression
// expects of `body.profile`.
func decodeForm(buf []byte) map[string]interface{} {
	values, err := url.ParseQuery(string(buf))
	if err != nil || len(values) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(values))
	for k, v := range values {
		if len(v) == 1 {
			out[k] = v[0]
			continue
		}
		list := make([]interface{}, 0, len(v))
		for _, s := range v {
			list = append(list, s)
		}
		out[k] = list
	}
	return out
}

// replay returns a body that yields the consumed bytes and then the remainder of
// the original stream, closing the original on Close.
func replay(consumed []byte, rest io.ReadCloser) io.ReadCloser {
	return &replayBody{Reader: io.MultiReader(bytes.NewReader(consumed), rest), closer: rest}
}

type replayBody struct {
	io.Reader
	closer io.Closer
}

func (b *replayBody) Close() error {
	if b.closer == nil {
		return nil
	}
	return b.closer.Close()
}

// WithSource records the issuance surface on the request's fact holder,
// installing a holder when the context has none, and returns the context a
// caller must pass on.
//
// It exists because the surface is known on paths that never saw an HTTP request
// — the CLI, a background job, a workload SVID issued over gRPC — and
// `request.source` has to be trustworthy on exactly those paths: a rule that
// says "an automated enrollment may not ask for this" is only a control if the
// automated enrollment is actually labelled. A holder installed here carries no
// URL, no body and no token, which is the correct reading for such a path.
func WithSource(ctx context.Context, source string) context.Context {
	if source == "" {
		return ctx
	}
	if f := FromContext(ctx); f != nil {
		f.SetSource(source)
		return ctx
	}
	f := NewFacts()
	f.SetSource(source)
	return WithFacts(ctx, f)
}

// WithOperation records what is being asked of the CA — one of the Op*
// constants — installing a fact holder when the context has none, and returns
// the context a caller must pass on. See SetOperation for why a renewal has to
// say so.
func WithOperation(ctx context.Context, op string) context.Context {
	if op == "" {
		return ctx
	}
	if f := FromContext(ctx); f != nil {
		f.SetOperation(op)
		return ctx
	}
	f := NewFacts()
	f.SetOperation(op)
	return WithFacts(ctx, f)
}
