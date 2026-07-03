package main

// CLI-side four-eyes gate for the secret layer (Task 81). Secret-layer KEK
// rotation has no REST endpoint, so this CLI chokepoint is the ONLY gate for it:
// a rotation cannot proceed until the configured number of distinct approvers
// sign off (via `secsy-ca approvals approve`). The gate is inert unless
// approvals.enabled is set.

import (
	"context"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// guardKEKRotate runs the approval gate for a secret-layer KEK rotation. It
// returns nil to proceed or a descriptive error to abort (a pending-approval
// notice or a gate failure). Fail-closed: a store error aborts the rotation.
func guardKEKRotate(cfg *config.Config, db *database.DB, family, keyType, actor string) error {
	if !cfg.Approvals.Enabled {
		return nil
	}
	eng := approval.NewEngine(db, db, approval.Policy{
		Enabled:          cfg.Approvals.Enabled,
		DefaultThreshold: cfg.Approvals.ApprovalDefaultThreshold(),
		Thresholds:       cfg.Approvals.Thresholds,
		TTL:              cfg.Approvals.ApprovalTTL(),
	})
	res, err := eng.Guard(context.Background(), approval.GuardRequest{
		Class:        approval.ClassKEKRotate,
		ResourceKey:  "kek:" + family,
		ResourceName: family,
		Summary:      fmt.Sprintf("Rotate secret KEK family %q to a new %s wrapping key", family, keyType),
		Params:       fmt.Sprintf("family=%s;key_type=%s", family, keyType),
		Actor:        actor,
		Tenant:       models.DefaultTenantID,
	})
	if err != nil {
		return fmt.Errorf("approval gate: %w", err)
	}
	if res.Allowed {
		return nil
	}
	pa := res.Approval
	return fmt.Errorf("KEK rotation requires four-eyes approval — held as request %s\n"+
		"  needs %d distinct approver(s); %d recorded so far\n"+
		"  approvers run:  secsy-ca approvals approve %s\n"+
		"  then re-run this command to execute",
		pa.ID, pa.RequiredApprovals, pa.ApprovalsCount, pa.ID)
}
