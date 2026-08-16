package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// rotationTranscript is the auditable, public record of an intermediate-CA key
// rollover. Like a ceremony transcript it contains only public information — the
// old/new CA identities, the new certificate, and who authorized the rollover —
// never private key material, which is generated inside and never leaves the HSM.
type rotationTranscript struct {
	RotationID        string                 `json:"rotation_id"`
	StartedAt         string                 `json:"started_at"`
	CompletedAt       string                 `json:"completed_at"`
	Quorum            int                    `json:"quorum_m,omitempty"`
	Enrolled          []string               `json:"enrolled_operators,omitempty"`
	Confirmations     []operatorConfirmation `json:"confirmations,omitempty"`
	OldCAID           string                 `json:"old_ca_id"`
	OldCALabel        string                 `json:"old_ca_label"`
	OldCASerial       string                 `json:"old_ca_serial"`
	NewCAID           string                 `json:"new_ca_id"`
	NewCALabel        string                 `json:"new_ca_label"`
	NewCASerial       string                 `json:"new_ca_serial"`
	Subject           string                 `json:"subject"`
	KeyType           string                 `json:"key_type"`
	NewKeyPKCS11URI   string                 `json:"new_key_pkcs11_uri"`
	NewKeyFingerprint string                 `json:"new_public_key_fingerprint_sha256"`
	RetireAfter       string                 `json:"retire_after,omitempty"`
	NewCertificatePEM string                 `json:"new_certificate_pem"`
	CombinedChainPEM  string                 `json:"combined_chain_pem"`
	AuditHeadSeq      int64                  `json:"audit_head_seq"`
	AuditHeadHash     string                 `json:"audit_head_hash"`
	KeyProvider       string                 `json:"key_provider"`
}

// cmdRotateIntermediate performs a ceremony-style, HSM-backed key rollover of an
// intermediate CA. A fresh keypair is generated inside the key provider and
// cross-signed under the parent with the same subject DN; the old key is marked
// superseded and enters a dual-chain overlap window during which both keys
// validate. When operators are enrolled, an M-of-N confirmation quorum gates the
// rollover, mirroring the key ceremony.
func cmdRotateIntermediate(db *database.DB, mgr *ca.Manager, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("rotate-intermediate", flag.ContinueOnError)
	caRef := fs.String("ca", "", "intermediate CA id or label to rotate (required)")
	newLabel := fs.String("new-label", "", "label for the new key (default: derived '-rN' suffix)")
	keyType := fs.String("key-type", "", "new key type (default: reuse the current key's type)")
	validityDays := fs.Int("validity-days", 0, "new intermediate validity in days (0 = reuse original span)")
	operatorsCSV := fs.String("operators", "", "comma-separated enrolled operator names (N) for M-of-N confirmation")
	quorum := fs.Int("quorum", 0, "required confirmations M (0 = majority of N)")
	nonInteractive := fs.Bool("non-interactive", false, "read 'name:phrase' confirmations from stdin instead of prompting")
	confirmFile := fs.String("confirm-file", "", "read 'name:phrase' confirmations from this file instead of prompting")
	transcriptOut := fs.String("transcript-out", "", "write the rotation transcript JSON here (default: stdout)")
	chainOut := fs.String("chain-out", "", "also write the combined overlap chain (PEM) here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	// Four-eyes gate (Task 81): authorize the rotation before the ceremony
	// begins. This is complementary to the M-of-N operator quorum below — the
	// approval records distinct RBAC approvers in the audit chain, the quorum is
	// the execution-time phrase ceremony.
	rotateTenant, _ := db.GetCATenant(caID)
	if err := guardCLI(db, cfg, approval.GuardRequest{
		Class:        approval.ClassCARotate,
		ResourceKey:  "ca:" + caID,
		ResourceName: *caRef,
		Summary:      "Rotate intermediate CA " + caID,
		Params:       fmt.Sprintf("ca=%s;new_label=%s;key_type=%s;validity_days=%d", caID, *newLabel, *keyType, *validityDays),
		Tenant:       rotateTenant,
	}); err != nil {
		return err
	}

	rotationID := uuid.New().String()
	startedAt := time.Now().UTC()
	actor := "rotation:" + rotationID

	fmt.Fprintf(os.Stderr, "=== secsy-pki intermediate key rotation %s ===\n", rotationID)
	fmt.Fprintf(os.Stderr, "CA: %s\n", *caRef)

	appendAudit(db, &audit.Event{
		Actor: actor, Action: audit.ActionCARotate, Target: caID,
		Result: audit.ResultSuccess, Detail: "rotation=" + rotationID + " phase=start",
	})

	// Optional M-of-N operator confirmation, identical to the key ceremony.
	var confirmations []operatorConfirmation
	enrolled := splitOperators(*operatorsCSV)
	m := 0
	if len(enrolled) > 0 {
		m = *quorum
		if m == 0 {
			m = len(enrolled)/2 + 1
		}
		if m < 1 || m > len(enrolled) {
			return fmt.Errorf("-quorum must be between 1 and the number of enrolled operators (%d)", len(enrolled))
		}
		fmt.Fprintf(os.Stderr, "Quorum: %d-of-%d operators\n\n", m, len(enrolled))
		confirmations, err = collectConfirmations(db, actor, *caRef, rotationID, enrolled, m, *nonInteractive, *confirmFile)
		if err != nil {
			appendAudit(db, &audit.Event{
				Actor: actor, Action: audit.ActionCARotate, Target: caID,
				Result: audit.ResultError, Detail: "rotation=" + rotationID + " aborted: " + err.Error(),
			})
			return fmt.Errorf("rotation aborted: %w", err)
		}
		fmt.Fprintf(os.Stderr, "\nQuorum reached (%d/%d). Generating new intermediate key inside the key provider...\n", len(confirmations), m)
	} else {
		fmt.Fprintln(os.Stderr, "No operators enrolled; proceeding without an M-of-N quorum.")
	}

	result, err := mgr.RotateIntermediate(context.Background(), ca.RotateSpec{
		CAID:        caID,
		NewLabel:    *newLabel,
		KeyType:     *keyType,
		Validity:    daysToDuration(*validityDays),
		RequestedBy: actor,
	})
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: actor, Action: audit.ActionCARotate, Target: caID,
			Result: audit.ResultError, Detail: "rotation=" + rotationID + " key generation failed: " + err.Error(),
		})
		return fmt.Errorf("rotation failed: %w", err)
	}

	detail := fmt.Sprintf("rotation=%s old_ca=%s new_ca=%s new_serial=%s", rotationID, result.OldCA.ID, result.NewCA.ID, result.NewCA.Serial)
	if result.RetireAfter != nil {
		detail += " retire_after=" + result.RetireAfter.Format(time.RFC3339)
	}
	appendAudit(db, &audit.Event{
		Actor: actor, Action: audit.ActionCARotate, Target: result.NewCA.ID, TargetName: result.NewCA.Label,
		Result: audit.ResultSuccess, Detail: detail,
	})
	headSeq, headHash := auditHead(db)

	retireAfter := ""
	if result.RetireAfter != nil {
		retireAfter = result.RetireAfter.Format(time.RFC3339)
	}
	transcript := rotationTranscript{
		RotationID:        rotationID,
		StartedAt:         startedAt.Format(time.RFC3339),
		CompletedAt:       time.Now().UTC().Format(time.RFC3339),
		Quorum:            m,
		Enrolled:          enrolled,
		Confirmations:     confirmations,
		OldCAID:           result.OldCA.ID,
		OldCALabel:        result.OldCA.Label,
		OldCASerial:       result.OldCA.Serial,
		NewCAID:           result.NewCA.ID,
		NewCALabel:        result.NewCA.Label,
		NewCASerial:       result.NewCA.Serial,
		Subject:           result.NewCA.Subject,
		KeyType:           result.NewCA.KeyType,
		NewKeyPKCS11URI:   result.NewCA.PKCS11URI,
		NewKeyFingerprint: publicKeyFingerprint(result.NewCA.PublicKey),
		RetireAfter:       retireAfter,
		NewCertificatePEM: result.NewCA.Certificate,
		CombinedChainPEM:  string(result.CombinedChainPEM),
		AuditHeadSeq:      headSeq,
		AuditHeadHash:     headHash,
		KeyProvider:       mgr.ProviderName(),
	}

	fmt.Fprintf(os.Stderr, "\nRotation complete. Dual-chain overlap window is now open.\n")
	fmt.Fprintf(os.Stderr, "  Old CA (superseded): %s (%s) serial=%s\n", result.OldCA.Label, result.OldCA.ID, result.OldCA.Serial)
	fmt.Fprintf(os.Stderr, "  New CA (active):     %s (%s) serial=%s\n", result.NewCA.Label, result.NewCA.ID, result.NewCA.Serial)
	fmt.Fprintf(os.Stderr, "  New key fingerprint: %s\n", transcript.NewKeyFingerprint)
	if retireAfter != "" {
		fmt.Fprintf(os.Stderr, "  Safe to retire old key after: %s (once outstanding leaves expire)\n", retireAfter)
	} else {
		fmt.Fprintf(os.Stderr, "  Old key has no outstanding leaves; it can be retired now.\n")
	}
	fmt.Fprintf(os.Stderr, "  Audit anchor: seq=%d hash=%s\n", headSeq, headHash)

	if *chainOut != "" {
		if err := os.WriteFile(*chainOut, result.CombinedChainPEM, 0o644); err != nil {
			return fmt.Errorf("writing combined chain: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  Combined chain: %s\n", *chainOut)
	}

	out, err := json.MarshalIndent(transcript, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding transcript: %w", err)
	}
	out = append(out, '\n')
	if *transcriptOut == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	if err := os.WriteFile(*transcriptOut, out, 0o644); err != nil {
		return fmt.Errorf("writing transcript: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  Transcript: %s\n", *transcriptOut)
	return nil
}

// cmdRotationStatus reports the rollover state of a CA and its overlap lineage.
func cmdRotationStatus(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("rotation-status", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label (required)")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	status, err := mgr.RotationStatus(caID)
	if err != nil {
		return err
	}

	if asJSON {
		return cliout.Emit(status)
	}

	fmt.Printf("CA:              %s (%s)\n", status.CA.Label, status.CA.ID)
	fmt.Printf("Subject:         %s\n", status.CA.Subject)
	fmt.Printf("Status:          %s\n", status.CA.Status)
	fmt.Printf("Serial:          %s\n", status.CA.Serial)
	if status.CA.NotAfter != nil {
		fmt.Printf("Not after:       %s\n", status.CA.NotAfter.Format(time.RFC3339))
	}
	if status.Predecessor != nil {
		fmt.Printf("Predecessor:     %s (%s) [%s]\n", status.Predecessor.Label, status.Predecessor.ID, status.Predecessor.Status)
	}
	if status.Successor != nil {
		fmt.Printf("Successor:       %s (%s) [%s]\n", status.Successor.Label, status.Successor.ID, status.Successor.Status)
	}
	fmt.Printf("Outstanding leaves (valid, not revoked): %d\n", status.OutstandingLeaves)
	if status.RetireAfter != nil {
		fmt.Printf("Retire after:    %s\n", status.RetireAfter.Format(time.RFC3339))
	}
	fmt.Printf("Safe to retire:  %t\n", status.SafeToRetire)
	return nil
}

// cmdRetireIntermediate decommissions a superseded intermediate key after its
// overlap window drains: it verifies no leaves signed by the old key remain
// valid (unless -force), revokes the old intermediate under its parent on the
// HSM, refreshes the parent CRL, and marks the CA retired. Like a ceremony, it
// can require an M-of-N operator quorum.
func cmdRetireIntermediate(db *database.DB, mgr *ca.Manager, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("retire-intermediate", flag.ContinueOnError)
	caRef := fs.String("ca", "", "superseded CA id or label to retire (required)")
	reason := fs.String("reason", "cessationOfOperation", "RFC 5280 revocation reason for the old intermediate")
	force := fs.Bool("force", false, "retire even if leaves signed by the old key are still valid (breaks those chains)")
	crlOut := fs.String("crl-out", "", "write the refreshed parent CRL (DER) here")
	operatorsCSV := fs.String("operators", "", "comma-separated enrolled operator names (N) for M-of-N confirmation")
	quorum := fs.Int("quorum", 0, "required confirmations M (0 = majority of N)")
	nonInteractive := fs.Bool("non-interactive", false, "read 'name:phrase' confirmations from stdin instead of prompting")
	confirmFile := fs.String("confirm-file", "", "read 'name:phrase' confirmations from this file instead of prompting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	// Four-eyes gate (Task 81): authorize the retirement before the ceremony.
	retireTenant, _ := db.GetCATenant(caID)
	if err := guardCLI(db, cfg, approval.GuardRequest{
		Class:        approval.ClassCARetire,
		ResourceKey:  "ca:" + caID,
		ResourceName: *caRef,
		Summary:      "Retire superseded intermediate CA " + caID,
		Params:       fmt.Sprintf("ca=%s;reason=%s;force=%v", caID, *reason, *force),
		Tenant:       retireTenant,
	}); err != nil {
		return err
	}

	retirementID := uuid.New().String()
	actor := "retirement:" + retirementID

	enrolled := splitOperators(*operatorsCSV)
	if len(enrolled) > 0 {
		m := *quorum
		if m == 0 {
			m = len(enrolled)/2 + 1
		}
		if m < 1 || m > len(enrolled) {
			return fmt.Errorf("-quorum must be between 1 and the number of enrolled operators (%d)", len(enrolled))
		}
		fmt.Fprintf(os.Stderr, "=== secsy-pki intermediate key retirement %s ===\n", retirementID)
		fmt.Fprintf(os.Stderr, "Quorum: %d-of-%d operators\n\n", m, len(enrolled))
		if _, err := collectConfirmations(db, actor, *caRef, retirementID, enrolled, m, *nonInteractive, *confirmFile); err != nil {
			appendAudit(db, &audit.Event{
				Actor: actor, Action: audit.ActionCARetire, Target: caID,
				Result: audit.ResultError, Detail: "retirement=" + retirementID + " aborted: " + err.Error(),
			})
			return fmt.Errorf("retirement aborted: %w", err)
		}
	}

	result, err := mgr.RetireIntermediate(context.Background(), ca.RetireSpec{
		CAID:        caID,
		Force:       *force,
		Reason:      *reason,
		RequestedBy: actor,
	})
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: actor, Action: audit.ActionCARetire, Target: caID,
			Result: audit.ResultError, Detail: "retirement=" + retirementID + " failed: " + err.Error(),
		})
		return err
	}

	appendAudit(db, &audit.Event{
		Actor: actor, Action: audit.ActionCARetire, Target: result.RetiredCA.ID, TargetName: result.RetiredCA.Label,
		Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("retirement=%s parent=%s revoked_serial=%s reason=%s forced=%t outstanding_leaves=%d",
			retirementID, result.ParentID, result.RevokedSerial, *reason, *force, result.OutstandingLeaves),
	})

	fmt.Fprintf(os.Stderr, "Retired intermediate %s (%s).\n", result.RetiredCA.Label, result.RetiredCA.ID)
	fmt.Fprintf(os.Stderr, "  Revoked serial %s under parent %s (reason: %s).\n", result.RevokedSerial, result.ParentID, *reason)
	if result.OutstandingLeaves > 0 {
		fmt.Fprintf(os.Stderr, "  WARNING: forced retirement with %d still-valid leaf certificate(s); those chains will no longer validate.\n", result.OutstandingLeaves)
	}
	fmt.Fprintf(os.Stderr, "  Parent CRL refreshed (%d bytes). Publish it to distribution points.\n", len(result.CRLDER))
	if *crlOut != "" {
		if err := os.WriteFile(*crlOut, result.CRLDER, 0o644); err != nil {
			return fmt.Errorf("writing CRL: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  CRL (DER): %s\n", *crlOut)
	}
	return nil
}

// cmdPublishChain emits the combined overlap chain (bundle) for a CA: the active
// intermediate, any overlapping superseded siblings, and the parent chain up to
// the root. This is what relying parties should be served (AIA/bundle) so leaves
// signed by either key validate during the rollover overlap window.
func cmdPublishChain(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("publish-chain", flag.ContinueOnError)
	caRef := fs.String("ca", "", "CA id or label (required)")
	out := fs.String("out", "", "write the combined chain PEM here (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}
	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	chain, err := mgr.CombinedChainPEM(caID)
	if err != nil {
		return err
	}
	return writeOutput(*out, chain)
}

// cmdListRotations lists CAs by rollover state, so an operator can see which
// superseded keys are awaiting retirement and whether they are safe to retire.
func cmdListRotations(db *database.DB, mgr *ca.Manager, args []string) error {
	fs := flag.NewFlagSet("list-rotations", flag.ContinueOnError)
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}
	cas, err := db.ListCAs()
	if err != nil {
		return err
	}

	// rotationRow is the stable JSON shape of one lineage row.
	type rotationRow struct {
		ID                string     `json:"id"`
		Label             string     `json:"label"`
		Status            string     `json:"status"`
		Serial            string     `json:"serial"`
		NotAfter          *time.Time `json:"not_after,omitempty"`
		OutstandingLeaves int        `json:"outstanding_leaves"`
		SafeToRetire      bool       `json:"safe_to_retire"`
	}
	rows := make([]rotationRow, 0)
	for _, c := range cas {
		// Only X.509 CAs participate in rollover; show those that are part of a
		// rollover lineage (superseded/retired, or an active CA with a predecessor).
		if c.Certificate == "" {
			continue
		}
		if c.Status == "" || c.Status == "active" {
			if c.PredecessorID == nil {
				continue
			}
		}
		status, err := mgr.RotationStatus(c.ID)
		if err != nil {
			return err
		}
		rows = append(rows, rotationRow{
			ID: c.ID, Label: c.Label, Status: c.Status, Serial: c.Serial,
			NotAfter: c.NotAfter, OutstandingLeaves: status.OutstandingLeaves,
			SafeToRetire: status.SafeToRetire,
		})
	}

	if asJSON {
		return cliout.Emit(struct {
			Rotations []rotationRow `json:"rotations"`
		}{Rotations: rows})
	}

	if len(rows) == 0 {
		fmt.Println("No CAs are currently in a key-rotation lineage.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LABEL\tSTATUS\tSERIAL\tNOT AFTER\tOUTSTANDING\tSAFE TO RETIRE")
	for _, r := range rows {
		notAfter := "-"
		if r.NotAfter != nil {
			notAfter = r.NotAfter.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%t\n",
			r.Label, r.Status, r.Serial, notAfter, r.OutstandingLeaves, r.SafeToRetire)
	}
	return tw.Flush()
}
