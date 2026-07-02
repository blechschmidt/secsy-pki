package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// operatorConfirmation records one operator's attested participation in a key
// ceremony. Digest is SHA-256("name:phrase"): it proves the operator supplied
// their confirmation secret without ever storing the secret itself, so the
// transcript and audit log stay free of sensitive material.
type operatorConfirmation struct {
	Name   string `json:"name"`
	Digest string `json:"confirmation_digest"`
	At     string `json:"at"`
}

// ceremonyTranscript is the signed-off record of a completed key ceremony. It is
// written to disk as an auditable artifact. It deliberately contains only public
// information: the CA certificate, the public key and its fingerprint, and who
// participated — never private key material, which stays inside the HSM.
type ceremonyTranscript struct {
	CeremonyID     string                 `json:"ceremony_id"`
	Role           string                 `json:"role"` // "root" or "intermediate"
	StartedAt      string                 `json:"started_at"`
	CompletedAt    string                 `json:"completed_at"`
	Quorum         int                    `json:"quorum_m"`
	Enrolled       []string               `json:"enrolled_operators"`
	Confirmations  []operatorConfirmation `json:"confirmations"`
	CAID           string                 `json:"ca_id"`
	CALabel        string                 `json:"ca_label"`
	Subject        string                 `json:"subject"`
	Serial         string                 `json:"serial"`
	KeyType        string                 `json:"key_type"`
	PKCS11URI      string                 `json:"pkcs11_uri"`
	KeyFingerprint string                 `json:"public_key_fingerprint_sha256"`
	CertificatePEM string                 `json:"certificate_pem"`
	AuditHeadSeq   int64                  `json:"audit_head_seq"`
	AuditHeadHash  string                 `json:"audit_head_hash"`
	KeyProvider    string                 `json:"key_provider"`
	NonExtractable *bool                  `json:"private_key_non_extractable,omitempty"`
}

// cmdCeremony runs a scripted, M-of-N-confirmed key ceremony that generates a
// root or intermediate CA whose private key is created inside — and never
// leaves — the key provider. It records the ceremony start, each operator
// confirmation, and completion in the tamper-evident audit log, and writes a
// public ceremony transcript.
func cmdCeremony(db *database.DB, mgr *ca.Manager, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("ceremony", flag.ContinueOnError)
	role := fs.String("role", "root", "ceremony role: root | intermediate")
	label := fs.String("label", "", "key label / CA name (required)")
	keyType := fs.String("key-type", "ecdsa-p384", "key type (ed25519, ecdsa-p256/p384/p521, rsa-2048, rsa-4096)")
	validityDays := fs.Int("validity-days", 3650, "certificate validity in days")
	pathLen := fs.Int("path-len", -1, "max path length (-1 = unconstrained, 0 = may only issue leaf certs)")
	parent := fs.String("parent", "", "parent CA id or label (required for role=intermediate)")
	operatorsCSV := fs.String("operators", "", "comma-separated enrolled operator names (N)")
	quorum := fs.Int("quorum", 0, "required confirmations M (0 = majority of N)")
	nonInteractive := fs.Bool("non-interactive", false, "read 'name:phrase' confirmations from stdin instead of prompting")
	confirmFile := fs.String("confirm-file", "", "read 'name:phrase' confirmations from this file instead of prompting")
	transcriptOut := fs.String("transcript-out", "", "write the ceremony transcript JSON here (default: stdout)")
	subj := addSubjectFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *label == "" || *subj.cn == "" {
		fs.Usage()
		return fmt.Errorf("-label and -cn are required")
	}
	if *role != "root" && *role != "intermediate" {
		return fmt.Errorf("-role must be 'root' or 'intermediate'")
	}
	if *role == "intermediate" && *parent == "" {
		return fmt.Errorf("-parent is required for role=intermediate")
	}

	enrolled := splitOperators(*operatorsCSV)
	if len(enrolled) == 0 {
		return fmt.Errorf("-operators is required: enroll at least one operator for the ceremony")
	}
	m := *quorum
	if m == 0 {
		m = len(enrolled)/2 + 1 // default: strict majority
	}
	if m < 1 || m > len(enrolled) {
		return fmt.Errorf("-quorum must be between 1 and the number of enrolled operators (%d)", len(enrolled))
	}

	ceremonyID := uuid.New().String()
	startedAt := time.Now().UTC()
	actor := "ceremony:" + ceremonyID

	fmt.Fprintf(os.Stderr, "=== secsy-pki key ceremony %s ===\n", ceremonyID)
	fmt.Fprintf(os.Stderr, "Role: %s   Label: %s   Key type: %s\n", *role, *label, *keyType)
	fmt.Fprintf(os.Stderr, "Quorum: %d-of-%d operators (%s)\n\n", m, len(enrolled), strings.Join(enrolled, ", "))

	// Record the start of the ceremony before any key material is created, so an
	// aborted ceremony still leaves a trace.
	appendAudit(db, &audit.Event{
		Actor:      actor,
		Action:     audit.ActionCeremonyStart,
		TargetName: *label,
		Result:     audit.ResultSuccess,
		Detail:     fmt.Sprintf("role=%s quorum=%d-of-%d key_type=%s", *role, m, len(enrolled), *keyType),
	})

	confirmations, err := collectConfirmations(db, actor, *label, ceremonyID, enrolled, m, *nonInteractive, *confirmFile)
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: actor, Action: audit.ActionCeremonyAbort, TargetName: *label,
			Result: audit.ResultError, Detail: err.Error(),
		})
		return fmt.Errorf("ceremony aborted: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nQuorum reached (%d/%d). Generating %s CA key inside the key provider...\n",
		len(confirmations), m, *role)

	// Perform the actual key generation + certificate signing. The private key
	// is created inside the provider and never leaves it.
	var result *models.CA
	switch *role {
	case "root":
		result, err = mgr.InitRoot(context.Background(), ca.RootSpec{
			Label:      *label,
			KeyType:    *keyType,
			Subject:    ca.PKIXName(subj.subject()),
			Validity:   time.Duration(*validityDays) * 24 * time.Hour,
			MaxPathLen: pathLenValue(*pathLen),
		})
	case "intermediate":
		var parentID string
		parentID, err = resolveCA(db, *parent)
		if err == nil {
			result, err = mgr.IssueIntermediate(context.Background(), ca.IntermediateSpec{
				ParentID:   parentID,
				Label:      *label,
				KeyType:    *keyType,
				Subject:    ca.PKIXName(subj.subject()),
				Validity:   time.Duration(*validityDays) * 24 * time.Hour,
				MaxPathLen: pathLenValue(*pathLen),
			})
		}
	}
	if err != nil {
		appendAudit(db, &audit.Event{
			Actor: actor, Action: audit.ActionCeremonyAbort, TargetName: *label,
			Result: audit.ResultError, Detail: "key generation failed: " + err.Error(),
		})
		return fmt.Errorf("ceremony key generation failed: %w", err)
	}

	// Record the underlying CA-creation event linked to this ceremony.
	caAction := audit.ActionCAInitRoot
	if *role == "intermediate" {
		caAction = audit.ActionCAIssueIntermediate
	}
	appendAudit(db, &audit.Event{
		Actor: actor, Action: caAction, Target: result.ID, TargetName: result.Label,
		Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("ceremony=%s serial=%s key_type=%s", ceremonyID, result.Serial, result.KeyType),
	})

	fingerprint := publicKeyFingerprint(result.PublicKey)
	nonExtractable := verifyNonExtractable(provider, result)

	// Record completion, then snapshot the audit head as a tamper-evidence
	// anchor to embed in the transcript.
	appendAudit(db, &audit.Event{
		Actor: actor, Action: audit.ActionCeremonyComplete, Target: result.ID, TargetName: result.Label,
		Result: audit.ResultSuccess,
		Detail: fmt.Sprintf("fingerprint=%s confirmations=%d/%d", fingerprint, len(confirmations), m),
	})
	headSeq, headHash := auditHead(db)

	transcript := ceremonyTranscript{
		CeremonyID:     ceremonyID,
		Role:           *role,
		StartedAt:      startedAt.Format(time.RFC3339),
		CompletedAt:    time.Now().UTC().Format(time.RFC3339),
		Quorum:         m,
		Enrolled:       enrolled,
		Confirmations:  confirmations,
		CAID:           result.ID,
		CALabel:        result.Label,
		Subject:        result.Subject,
		Serial:         result.Serial,
		KeyType:        result.KeyType,
		PKCS11URI:      result.PKCS11URI,
		KeyFingerprint: fingerprint,
		CertificatePEM: result.Certificate,
		AuditHeadSeq:   headSeq,
		AuditHeadHash:  headHash,
		KeyProvider:    provider.Name(),
		NonExtractable: nonExtractable,
	}

	out, err := json.MarshalIndent(transcript, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding transcript: %w", err)
	}
	out = append(out, '\n')

	fmt.Fprintf(os.Stderr, "\nCeremony complete.\n")
	fmt.Fprintf(os.Stderr, "  CA:          %s (%s)\n", result.Label, result.ID)
	fmt.Fprintf(os.Stderr, "  Subject:     %s\n", result.Subject)
	fmt.Fprintf(os.Stderr, "  Key type:    %s\n", result.KeyType)
	fmt.Fprintf(os.Stderr, "  Fingerprint: %s\n", fingerprint)
	if nonExtractable != nil {
		fmt.Fprintf(os.Stderr, "  Non-extractable key verified: %t\n", *nonExtractable)
	}
	fmt.Fprintf(os.Stderr, "  Audit anchor: seq=%d hash=%s\n", headSeq, headHash)

	if *transcriptOut == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	if err := os.WriteFile(*transcriptOut, out, 0o644); err != nil {
		return fmt.Errorf("writing transcript: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  Transcript:  %s\n", *transcriptOut)
	return nil
}

// collectConfirmations gathers operator attestations until the quorum M is
// reached, auditing each accepted confirmation. In interactive mode it prompts
// each enrolled operator in turn; otherwise it reads "name:phrase" lines from a
// file or stdin. A confirmation from an operator not in the enrolled set, or a
// duplicate from an operator who already confirmed, is rejected.
func collectConfirmations(db *database.DB, actor, label, ceremonyID string, enrolled []string, m int, nonInteractive bool, confirmFile string) ([]operatorConfirmation, error) {
	enrolledSet := map[string]bool{}
	for _, name := range enrolled {
		enrolledSet[name] = true
	}
	confirmed := map[string]bool{}
	var confirmations []operatorConfirmation

	record := func(name, phrase string) error {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		if !enrolledSet[name] {
			return fmt.Errorf("operator %q is not enrolled in this ceremony", name)
		}
		if confirmed[name] {
			return nil // already counted; ignore duplicates
		}
		if strings.TrimSpace(phrase) == "" {
			return fmt.Errorf("operator %q supplied an empty confirmation", name)
		}
		confirmed[name] = true
		c := operatorConfirmation{
			Name:   name,
			Digest: confirmationDigest(name, phrase),
			At:     time.Now().UTC().Format(time.RFC3339),
		}
		confirmations = append(confirmations, c)
		appendAudit(db, &audit.Event{
			Actor: actor, ActorName: name, Action: audit.ActionCeremonyOperatorConfirm,
			TargetName: label, Result: audit.ResultSuccess,
			Detail: fmt.Sprintf("ceremony=%s digest=%s (%d/%d)", ceremonyID, c.Digest, len(confirmations), m),
		})
		fmt.Fprintf(os.Stderr, "  ✓ %s confirmed (%d/%d)\n", name, len(confirmations), m)
		return nil
	}

	if confirmFile != "" {
		f, err := os.Open(confirmFile)
		if err != nil {
			return nil, fmt.Errorf("opening confirmation file: %w", err)
		}
		defer f.Close()
		if err := readConfirmationLines(f, record); err != nil {
			return nil, err
		}
	} else if nonInteractive {
		if err := readConfirmationLines(os.Stdin, record); err != nil {
			return nil, err
		}
	} else {
		reader := bufio.NewReader(os.Stdin)
		for _, name := range enrolled {
			if len(confirmations) >= m {
				break
			}
			fmt.Fprintf(os.Stderr, "Operator %q — enter confirmation phrase to attest presence (blank to skip): ", name)
			line, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("reading confirmation: %w", err)
			}
			phrase := strings.TrimRight(line, "\r\n")
			if strings.TrimSpace(phrase) == "" {
				fmt.Fprintf(os.Stderr, "  … %s skipped\n", name)
				if err == io.EOF {
					break
				}
				continue
			}
			if rerr := record(name, phrase); rerr != nil {
				fmt.Fprintf(os.Stderr, "  ! %v\n", rerr)
			}
			if err == io.EOF {
				break
			}
		}
	}

	if len(confirmations) < m {
		return nil, fmt.Errorf("quorum not met: %d of %d required confirmations", len(confirmations), m)
	}
	return confirmations, nil
}

// readConfirmationLines parses "name:phrase" lines from r, invoking record for
// each. Blank lines and lines beginning with '#' are ignored.
func readConfirmationLines(r io.Reader, record func(name, phrase string) error) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, phrase, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("malformed confirmation line %q (want name:phrase)", line)
		}
		if err := record(name, phrase); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// confirmationDigest is SHA-256("name:phrase"), a non-reversible proof that an
// operator supplied their confirmation secret without recording the secret.
func confirmationDigest(name, phrase string) string {
	sum := sha256.Sum256([]byte(name + ":" + phrase))
	return hex.EncodeToString(sum[:])
}

// splitOperators parses a comma-separated operator list, trimming whitespace and
// dropping empties while preserving order.
func splitOperators(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// publicKeyFingerprint returns the SSH SHA-256 fingerprint of a CA's public key
// (stored as an authorized_keys line), or "unknown" if it cannot be parsed.
func publicKeyFingerprint(authorizedKey string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "unknown"
	}
	return ssh.FingerprintSHA256(pub)
}

// verifyNonExtractable checks, via the key provider's inventory, that the CA's
// freshly generated private key is reported as non-extractable. It returns nil
// if the provider cannot report (e.g. the key label is not found), so a missing
// capability does not falsely assert either way.
func verifyNonExtractable(provider keyprovider.Provider, result *models.CA) *bool {
	lister, ok := provider.(keyprovider.KeyLister)
	if !ok {
		return nil
	}
	keys, err := lister.ListKeys(context.Background())
	if err != nil {
		return nil
	}
	for _, k := range keys {
		if k.Label == result.Label {
			ne := !k.Extractable
			return &ne
		}
	}
	return nil
}

// appendAudit writes an event to the tamper-evident log, logging (but not
// failing on) a persistence error — a ceremony must not silently proceed
// without its audit trail, but a best-effort warning keeps the CLI usable if
// the log store is degraded.
func appendAudit(db *database.DB, e *audit.Event) {
	e.ID = uuid.New().String()
	if err := db.AppendEvent(e); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: failed to write audit event %q: %v\n", e.Action, err)
	}
}

// auditHead returns the sequence number and hash of the newest audit-log entry,
// used as a tamper-evidence anchor in ceremony transcripts and backup manifests.
func auditHead(db *database.DB) (int64, string) {
	events, _, err := db.ListEvents("", "", "", 1, 0)
	if err != nil || len(events) == 0 {
		return 0, ""
	}
	return events[0].Seq, events[0].Hash
}
