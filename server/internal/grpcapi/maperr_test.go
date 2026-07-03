package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestMapIssueErrorTenantGate: the Task 61 tenant-gate errors map to their
// dedicated gRPC codes (mirroring REST's 429/403), including when wrapped, and
// everything else keeps its existing mapping.
func TestMapIssueErrorTenantGate(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"quota exceeded", &models.QuotaExceededError{
			TenantID: "t1", Quota: models.QuotaCertsPerDay, Limit: 5, RetryAfter: time.Hour,
		}, codes.ResourceExhausted},
		{"quota exceeded wrapped", fmt.Errorf("issuing: %w", &models.QuotaExceededError{
			TenantID: "t1", Quota: models.QuotaActiveCerts, Limit: 2,
		}), codes.ResourceExhausted},
		{"tenant suspended", &models.TenantSuspendedError{TenantID: "t1"}, codes.PermissionDenied},
		{"tenant suspended wrapped", fmt.Errorf("issuing: %w", &models.TenantSuspendedError{TenantID: "t1"}), codes.PermissionDenied},
		{"canceled", context.Canceled, codes.Canceled},
		{"deadline", context.DeadlineExceeded, codes.DeadlineExceeded},
		{"generic", errors.New("bad CSR"), codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapIssueError(tc.err)
			st, ok := status.FromError(got)
			if !ok {
				t.Fatalf("mapIssueError returned a non-status error: %v", got)
			}
			if st.Code() != tc.want {
				t.Errorf("code = %v, want %v (message %q)", st.Code(), tc.want, st.Message())
			}
		})
	}
}
