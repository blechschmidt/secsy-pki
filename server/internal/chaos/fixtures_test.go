//go:build sqlite

package chaos

// Small fixture builders shared across scenarios: audit events, CSRs, and
// numeric slice helpers.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func flatten(rows [][]int64) []string {
	var out []string
	for _, r := range rows {
		for _, v := range r {
			out = append(out, itoa(v))
		}
	}
	return out
}

// newAuditEvent builds a distinct issuance event. AppendEvent assigns the
// sequence, prev-hash and hash under the chain lock, so callers only supply the
// content fields; the (worker,index) pair makes each event's detail unique.
func newAuditEvent(worker, index int) *audit.Event {
	return &audit.Event{
		ID:        fmt.Sprintf("chaos-%d-%d-%d", worker, index, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Actor:     "chaos-suite",
		Action:    audit.ActionCertIssue,
		Target:    fmt.Sprintf("w%d-i%d", worker, index),
		Result:    audit.ResultSuccess,
	}
}

// makeChaosCSR returns a PEM CSR for a fresh ECDSA key with a unique CN, so
// concurrently issued leaves are distinct subjects.
func makeChaosCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cn := "leaf-" + randSuffix(t) + ".chaos.example.com"
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
