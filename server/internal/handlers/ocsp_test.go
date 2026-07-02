package handlers

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestWriteOCSPError verifies the responder maps each failure class to the
// correct pre-serialized RFC 6960 §4.2.1 status response.
func TestWriteOCSPError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want []byte
	}{
		{"malformed", fmt.Errorf("wrap: %w", ca.ErrOCSPMalformed), pki.OCSPMalformedResponse},
		{"unauthorized", fmt.Errorf("wrap: %w", ca.ErrOCSPUnauthorized), pki.OCSPUnauthorizedResponse},
		{"try_later", fmt.Errorf("wrap: %w", ca.ErrOCSPTryLater), pki.OCSPTryLaterResponse},
		{"internal", fmt.Errorf("some unexpected failure"), pki.OCSPInternalErrorResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeOCSPError(w, tc.err)
			if got := w.Body.Bytes(); !bytes.Equal(got, tc.want) {
				t.Errorf("body = %x, want %x", got, tc.want)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/ocsp-response" {
				t.Errorf("Content-Type = %q, want application/ocsp-response", ct)
			}
		})
	}
}
