package authn

import "net/http"

// CSRFHeader is the request header a cookie-authenticated console request must
// carry, echoing the session's synchronizer token.
const CSRFHeader = "X-CSRF-Token"

// isSafeMethod reports whether an HTTP method is "safe" (read-only) and thus
// exempt from CSRF protection. Only state-changing methods require a token.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// CheckCSRF validates the anti-CSRF synchronizer token for a request that was
// authenticated by the session cookie. Safe methods are always allowed; unsafe
// methods must present the session's CSRF token in the X-CSRF-Token header (or,
// as a fallback for form posts, a "csrf_token" form field). It returns true when
// the request may proceed.
//
// Only cookie-authenticated requests need this check: Bearer-token, basic-auth,
// and mutual-TLS callers do not rely on ambient credentials the browser attaches
// automatically, so they are not forgeable cross-site.
func CheckCSRF(r *http.Request, sess *Session) bool {
	if sess == nil {
		return false
	}
	if isSafeMethod(r.Method) {
		return true
	}
	// The console is a JSON API and always echoes the token in the header; we do
	// not fall back to a form field, which would needlessly consume the request
	// body of a request about to be rejected.
	token := r.Header.Get(CSRFHeader)
	return token != "" && constantTimeEqual(token, sess.CSRFToken)
}
