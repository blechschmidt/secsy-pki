package ca

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Package rotation support: HSM-backed key rollover for intermediate CAs.
//
// Rotating an intermediate signing key must never break the certificates that
// were issued under the old key. The rollover therefore proceeds in three
// controlled stages:
//
//  1. Rotate — a fresh keypair is generated inside the key provider and a new
//     intermediate certificate is issued under the same parent (root), carrying
//     the SAME subject DN as the old intermediate so it is a drop-in issuer with
//     a new key. The old CA is marked "superseded" but remains fully able to
//     validate the leaves it already signed. New issuance is directed at the new
//     key (see ActiveIssuerID).
//
//  2. Overlap — both intermediate certificates are published together as a
//     combined chain/bundle. A leaf signed by the old key still chains through
//     the old intermediate; a leaf signed by the new key chains through the new
//     one. Relying parties select the right issuer by Authority Key Identifier.
//
//  3. Retire — once no leaves signed by the old key remain valid (they have
//     expired or been renewed onto the new key), the old intermediate is revoked
//     under its parent and the parent CRL/OCSP is refreshed, decommissioning the
//     retired key.

// RotateSpec parameterizes an intermediate-CA key rotation.
type RotateSpec struct {
	// CAID identifies the intermediate CA whose signing key is being rotated. It
	// must be an X.509 intermediate (have a parent and a certificate). If the CA
	// has already been superseded, the rotation targets its active successor.
	CAID string
	// NewLabel is the key label / CA name for the freshly generated key. It must
	// be unique. When empty a label is derived from the old CA's label.
	NewLabel string
	// KeyType selects the new key's algorithm. Empty reuses the old CA's key type.
	KeyType string
	// Validity is the new intermediate certificate's validity. Zero reuses the
	// old certificate's original validity span (clamped to the parent's expiry).
	Validity time.Duration
	// RequestedBy records who initiated the rotation (for audit/labelling).
	RequestedBy string
}

// RotationResult is the outcome of a successful rotation.
type RotationResult struct {
	// OldCA is the now-superseded intermediate (still validating its own leaves).
	OldCA *models.CA
	// NewCA is the freshly generated, now-active intermediate.
	NewCA *models.CA
	// CombinedChainPEM bundles the new and old (overlapping) intermediate
	// certificates plus the parent chain, so relying parties can validate leaves
	// signed by either key during the overlap window.
	CombinedChainPEM []byte
	// RetireAfter is the earliest time the old key can be safely retired: the
	// latest NotAfter among the outstanding leaves it signed at rotation time
	// (nil when no outstanding leaves remain).
	RetireAfter *time.Time
}

// RotateIntermediate performs an HSM-backed key rollover of an intermediate CA.
//
// A new keypair is generated inside the provider and a new intermediate
// certificate — same subject DN, same path-length constraint — is signed under
// the parent CA on the device. The old intermediate is marked superseded and
// linked to its successor with a retire-after deadline; it keeps validating the
// leaves it already issued for the duration of the overlap window. New issuance
// should be directed at the returned NewCA (or resolved via ActiveIssuerID).
func (m *Manager) RotateIntermediate(ctx context.Context, spec RotateSpec) (*RotationResult, error) {
	if spec.CAID == "" {
		return nil, fmt.Errorf("CA id is required")
	}

	// Resolve to the currently active CA in the rollover lineage so rotating an
	// already-superseded id transparently rotates the live key.
	activeID, err := m.ActiveIssuerID(spec.CAID)
	if err != nil {
		return nil, err
	}
	old, err := m.db.GetCA(activeID)
	if err != nil {
		return nil, fmt.Errorf("looking up CA to rotate: %w", err)
	}
	if old == nil {
		return nil, fmt.Errorf("CA %q not found", activeID)
	}
	if old.Certificate == "" {
		return nil, fmt.Errorf("CA %q is not an X.509 CA (no certificate)", old.Label)
	}
	if old.ParentID == nil {
		if old.CSR != "" {
			return nil, fmt.Errorf("CA %q is externally signed; its parent is not held here, so rotate it out-of-band: generate a fresh key and CSR with \"ca csr\", have the external parent sign it, and import the certificate", old.Label)
		}
		return nil, fmt.Errorf("CA %q is a root CA; only intermediate keys can be rotated with this workflow", old.Label)
	}
	if old.Status == models.CAStatusRetired {
		return nil, fmt.Errorf("CA %q is retired and cannot be rotated", old.Label)
	}
	oldCert, err := pki.ParseCertificatePEM([]byte(old.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	parent, parentCert, err := m.loadIssuer(*old.ParentID)
	if err != nil {
		return nil, fmt.Errorf("loading parent CA: %w", err)
	}
	if err := m.checkPathLen(parent, parentCert); err != nil {
		return nil, err
	}

	keyType := spec.KeyType
	if keyType == "" {
		keyType = old.KeyType
	}
	if _, err := keyprovider.NormalizeKeyType(keyType); err != nil {
		return nil, err
	}

	newLabel := spec.NewLabel
	if newLabel == "" {
		newLabel = deriveRotationLabel(old.Label)
	}
	if existing, err := m.db.GetCAByLabel(newLabel); err != nil {
		return nil, fmt.Errorf("checking for existing CA: %w", err)
	} else if existing != nil {
		return nil, fmt.Errorf("a CA with label %q already exists; choose a unique -new-label", newLabel)
	}

	// The new intermediate's validity: reuse the old certificate's original span
	// unless overridden, and always clamp to the parent's expiry.
	now := time.Now()
	validity := spec.Validity
	if validity <= 0 {
		validity = oldCert.NotAfter.Sub(oldCert.NotBefore)
	}
	notAfter := now.Add(validity)
	if notAfter.After(parentCert.NotAfter) {
		notAfter = parentCert.NotAfter
	}

	serial, err := m.db.AllocateSerial(parent.ID)
	if err != nil {
		return nil, fmt.Errorf("allocating serial from parent CA: %w", err)
	}

	keyInfo, err := m.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: newLabel, KeyType: keyType})
	if err != nil {
		return nil, fmt.Errorf("generating rotated intermediate key: %w", err)
	}

	parentSigner, err := m.provider.Signer(ctx, keyRefForCA(parent))
	if err != nil {
		return nil, fmt.Errorf("opening parent CA signer: %w", err)
	}
	defer parentSigner.Close()

	req := pki.CACertRequest{
		// Reuse the exact subject of the old intermediate so the new certificate
		// is a drop-in issuer for the same DN (only the key changes).
		Subject:    oldCert.Subject,
		PublicKey:  keyInfo.PublicKey,
		Serial:     big.NewInt(serial),
		NotBefore:  now.Add(-clockSkew),
		NotAfter:   notAfter,
		MaxPathLen: old.MaxPathLen,
		// Carry the Name Constraints and certificate-policy extensions forward
		// verbatim so the rotated key remains a drop-in issuer for the same scope.
		ExtraExtensions: preservedCAExtensions(oldCert),
	}
	der, err := pki.CreateCACertificate(parentSigner, parentCert, req)
	if err != nil {
		return nil, fmt.Errorf("creating rotated intermediate certificate: %w", err)
	}

	newCA, err := m.persistCA(parent.TenantID, &parent.ID, newLabel, keyInfo, der, req)
	if err != nil {
		return nil, err
	}

	// Compute the retire-after deadline from the outstanding leaves the old key
	// signed, then atomically link the rollover pair (old→superseded→successor,
	// new→predecessor).
	retireAfter, err := m.outstandingLeafDeadline(old.ID, now)
	if err != nil {
		return nil, err
	}
	if err := m.db.MarkCARotated(old.ID, newCA.ID, retireAfter); err != nil {
		return nil, fmt.Errorf("linking rotation: %w", err)
	}

	// Reload both CAs so the returned/linked state (status, successor/predecessor)
	// is consistent with what was persisted.
	old, err = m.db.GetCA(old.ID)
	if err != nil {
		return nil, fmt.Errorf("reloading superseded CA: %w", err)
	}
	newCA, err = m.db.GetCA(newCA.ID)
	if err != nil {
		return nil, fmt.Errorf("reloading rotated-in CA: %w", err)
	}

	chain, err := m.CombinedChainPEM(newCA.ID)
	if err != nil {
		return nil, err
	}

	return &RotationResult{
		OldCA:            old,
		NewCA:            newCA,
		CombinedChainPEM: chain,
		RetireAfter:      retireAfter,
	}, nil
}

// RetireSpec parameterizes retirement of a superseded intermediate key.
type RetireSpec struct {
	// CAID identifies the superseded intermediate to retire (or any id in its
	// rollover lineage; the superseded predecessor of the active key is retired).
	CAID string
	// Force retires even when leaves signed by the old key are still outstanding.
	// This is unsafe: those leaves will fail to validate once the old
	// intermediate is revoked. Intended only for emergency key-compromise
	// response, where breaking the old chain is the goal.
	Force bool
	// Reason is the RFC 5280 revocation reason applied to the old intermediate
	// certificate under its parent. Empty defaults to "cessationOfOperation"
	// (or "keyCompromise" is a sensible choice for compromise-driven retirement).
	Reason string
	// RequestedBy records who initiated the retirement.
	RequestedBy string
}

// RetireResult is the outcome of retiring a superseded intermediate.
type RetireResult struct {
	// RetiredCA is the intermediate whose certificate was revoked under the parent.
	RetiredCA *models.CA
	// ParentID is the CA under which the retired intermediate was revoked.
	ParentID string
	// RevokedSerial is the retired intermediate certificate's serial (the serial
	// it holds in the parent's namespace).
	RevokedSerial string
	// CRLDER is the freshly generated parent CRL (DER) that now lists the retired
	// intermediate, ready for publication.
	CRLDER []byte
	// OutstandingLeaves is the number of not-yet-expired, non-revoked leaves the
	// retired key had signed at retirement time (nonzero only when Force is used).
	OutstandingLeaves int
}

// RetireIntermediate decommissions a superseded intermediate key after the
// overlap window: it verifies no leaves signed by the old key remain valid
// (unless Force is set), revokes the old intermediate certificate under its
// parent (on the HSM, via the parent's CRL), refreshes the parent CRL, and marks
// the old CA retired.
func (m *Manager) RetireIntermediate(ctx context.Context, spec RetireSpec) (*RetireResult, error) {
	if spec.CAID == "" {
		return nil, fmt.Errorf("CA id is required")
	}
	old, err := m.resolveSuperseded(spec.CAID)
	if err != nil {
		return nil, err
	}
	if old.ParentID == nil {
		return nil, fmt.Errorf("CA %q has no parent; cannot revoke it under an issuer", old.Label)
	}

	outstanding, err := m.OutstandingLeaves(old.ID, time.Now())
	if err != nil {
		return nil, err
	}
	if len(outstanding) > 0 && !spec.Force {
		var deadline string
		if old.RetireAfter != nil {
			deadline = "; safe to retire after " + old.RetireAfter.Format(time.RFC3339)
		}
		return nil, fmt.Errorf("cannot retire %q: %d leaf certificate(s) signed by the old key are still valid%s (use force to retire anyway, breaking those chains)",
			old.Label, len(outstanding), deadline)
	}

	reason := spec.Reason
	if reason == "" {
		reason = "cessationOfOperation"
	}
	if _, err := pki.ParseRevocationReason(reason); err != nil {
		return nil, err
	}

	// Revoke the old intermediate's own certificate under its parent, so the
	// parent's CRL/OCSP now reports the retired key as revoked.
	if _, err := m.RevokeCertificate(ctx, *old.ParentID, old.Serial, reason); err != nil {
		return nil, fmt.Errorf("revoking retired intermediate under parent: %w", err)
	}
	if err := m.db.SetCAStatus(old.ID, models.CAStatusRetired); err != nil {
		return nil, fmt.Errorf("marking CA retired: %w", err)
	}

	crlDER, err := m.GenerateCRL(ctx, *old.ParentID)
	if err != nil {
		return nil, fmt.Errorf("refreshing parent CRL after retirement: %w", err)
	}

	retired, err := m.db.GetCA(old.ID)
	if err != nil {
		return nil, fmt.Errorf("reloading retired CA: %w", err)
	}

	return &RetireResult{
		RetiredCA:         retired,
		ParentID:          *old.ParentID,
		RevokedSerial:     old.Serial,
		CRLDER:            crlDER,
		OutstandingLeaves: len(outstanding),
	}, nil
}

// RotationStatus summarizes an intermediate CA's rollover state.
type RotationStatus struct {
	CA *models.CA `json:"ca"`
	// Predecessor and Successor are the linked CAs in the rollover lineage, if any.
	Predecessor *models.CA `json:"predecessor,omitempty"`
	Successor   *models.CA `json:"successor,omitempty"`
	// OutstandingLeaves is the number of not-yet-expired, non-revoked leaves the
	// CA has signed (relevant for a superseded key awaiting retirement).
	OutstandingLeaves int `json:"outstanding_leaves"`
	// RetireAfter is the recorded safe-to-retire deadline for a superseded key.
	RetireAfter *time.Time `json:"retire_after,omitempty"`
	// SafeToRetire reports whether a superseded key can be retired now (no
	// outstanding leaves remain).
	SafeToRetire bool `json:"safe_to_retire"`
}

// RotationStatus reports the rollover state of a CA and its overlap lineage.
func (m *Manager) RotationStatus(caID string) (*RotationStatus, error) {
	if caID == "" {
		return nil, fmt.Errorf("CA id is required")
	}
	ca, err := m.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("looking up CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", caID)
	}
	status := &RotationStatus{CA: ca, RetireAfter: ca.RetireAfter}
	if ca.PredecessorID != nil {
		if pred, err := m.db.GetCA(*ca.PredecessorID); err == nil {
			status.Predecessor = pred
		}
	}
	if ca.SuccessorID != nil {
		if succ, err := m.db.GetCA(*ca.SuccessorID); err == nil {
			status.Successor = succ
		}
	}
	outstanding, err := m.OutstandingLeaves(ca.ID, time.Now())
	if err != nil {
		return nil, err
	}
	status.OutstandingLeaves = len(outstanding)
	status.SafeToRetire = ca.Status == models.CAStatusSuperseded && len(outstanding) == 0
	return status, nil
}

// ActiveIssuerID follows the successor chain from a CA id to the currently
// active signing key in its rollover lineage. Issuance should target the
// returned id so certificates are always minted under the newest key. A CA with
// no successor resolves to itself.
func (m *Manager) ActiveIssuerID(caID string) (string, error) {
	if caID == "" {
		return "", fmt.Errorf("CA id is required")
	}
	seen := map[string]bool{}
	cur := caID
	for {
		if seen[cur] {
			return "", fmt.Errorf("rotation successor chain for CA %q contains a cycle", caID)
		}
		seen[cur] = true
		ca, err := m.db.GetCA(cur)
		if err != nil {
			return "", fmt.Errorf("looking up CA %q: %w", cur, err)
		}
		if ca == nil {
			return "", fmt.Errorf("CA %q not found", cur)
		}
		// A retired successor should never be followed to; stop at the newest
		// non-retired link. In normal operation only the newest is active.
		if ca.SuccessorID == nil || *ca.SuccessorID == "" {
			return ca.ID, nil
		}
		next, err := m.db.GetCA(*ca.SuccessorID)
		if err != nil {
			return "", fmt.Errorf("looking up successor of %q: %w", cur, err)
		}
		if next == nil || next.Status == models.CAStatusRetired {
			return ca.ID, nil
		}
		cur = *ca.SuccessorID
	}
}

// CombinedChainPEM builds the overlap bundle for a CA: the requested CA's
// certificate, every non-retired CA that shares its rollover lineage (the
// overlapping old/new intermediates), and the parent chain up to and including
// the root. Relying parties can validate a leaf signed by any key in the overlap
// window against this single bundle.
func (m *Manager) CombinedChainPEM(caID string) ([]byte, error) {
	ca, err := m.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("looking up CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", caID)
	}

	lineage, err := m.rolloverLineage(ca)
	if err != nil {
		return nil, err
	}

	var out []byte
	added := map[string]bool{}
	appendCert := func(pemStr string) {
		if pemStr == "" || added[pemStr] {
			return
		}
		added[pemStr] = true
		out = append(out, []byte(pemStr)...)
	}

	// Overlapping siblings first (active before superseded), then ancestors.
	for _, sib := range lineage {
		appendCert(sib.Certificate)
	}

	// Walk the parent chain up to the root. Guard against cycles.
	seen := map[string]bool{}
	top := ca
	parentID := ca.ParentID
	for parentID != nil && *parentID != "" && !seen[*parentID] {
		seen[*parentID] = true
		parent, err := m.db.GetCA(*parentID)
		if err != nil {
			return nil, fmt.Errorf("looking up ancestor CA: %w", err)
		}
		if parent == nil {
			break
		}
		appendCert(parent.Certificate)
		top = parent
		parentID = parent.ParentID
	}

	// When the topmost local CA was signed by an external parent (offline
	// corporate root, third-party bridge), append its imported external chain so
	// relying parties get the full path to the external trust anchor.
	if top.ExternalChain != "" {
		appendCert(top.ExternalChain)
	}

	return out, nil
}

// rolloverLineage returns the set of non-retired CAs that share ca's rollover
// lineage (ca itself plus predecessors and successors reachable via the
// rotation links), ordered active-first then by NotAfter descending so the
// freshest issuer appears first in a bundle.
func (m *Manager) rolloverLineage(ca *models.CA) ([]*models.CA, error) {
	visited := map[string]*models.CA{}
	var walk func(id string) error
	walk = func(id string) error {
		if id == "" || visited[id] != nil {
			return nil
		}
		cur, err := m.db.GetCA(id)
		if err != nil {
			return fmt.Errorf("looking up CA %q in lineage: %w", id, err)
		}
		if cur == nil {
			return nil
		}
		visited[id] = cur
		if cur.PredecessorID != nil {
			if err := walk(*cur.PredecessorID); err != nil {
				return err
			}
		}
		if cur.SuccessorID != nil {
			if err := walk(*cur.SuccessorID); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(ca.ID); err != nil {
		return nil, err
	}

	lineage := make([]*models.CA, 0, len(visited))
	for _, c := range visited {
		// A retired intermediate is decommissioned: exclude it from freshly
		// published overlap bundles.
		if c.Status == models.CAStatusRetired {
			continue
		}
		lineage = append(lineage, c)
	}
	sort.SliceStable(lineage, func(i, j int) bool {
		ai := lineage[i].Status == models.CAStatusActive
		aj := lineage[j].Status == models.CAStatusActive
		if ai != aj {
			return ai // active first
		}
		return notAfterOrZero(lineage[i]).After(notAfterOrZero(lineage[j]))
	})
	return lineage, nil
}

// AutoRotateSpec parameterizes a scan-driven bulk rotation of intermediate CAs.
type AutoRotateSpec struct {
	// Before is the remaining-validity threshold: an active intermediate whose
	// own certificate expires within this window is rotated.
	Before time.Duration
	// KeyType overrides the new keys' type (empty reuses each CA's key type).
	KeyType string
	// Validity overrides the new certificates' validity (zero reuses each CA's
	// original span).
	Validity time.Duration
	// RequestedBy records who/what initiated the rotations.
	RequestedBy string
	// Now overrides the wall clock (tests). Zero uses time.Now().
	Now time.Time
}

// AutoRotateDue rotates every active intermediate CA whose own certificate is
// within the configured threshold of expiry and that does not already have an
// active successor. It is the mechanism the expiry monitor uses to trigger
// rotation automatically. Each rotation is independent; a failure on one CA is
// returned but does not prevent the others from rotating.
func (m *Manager) AutoRotateDue(ctx context.Context, spec AutoRotateSpec) ([]RotationResult, error) {
	now := spec.Now
	if now.IsZero() {
		now = time.Now()
	}
	cas, err := m.db.ListCAs()
	if err != nil {
		return nil, fmt.Errorf("listing CAs: %w", err)
	}

	var results []RotationResult
	var firstErr error
	for i := range cas {
		ca := cas[i]
		// Only active intermediates (parented, with a certificate) are candidates.
		if ca.ParentID == nil || ca.Certificate == "" {
			continue
		}
		if ca.Status != models.CAStatusActive {
			continue
		}
		if ca.NotAfter == nil || ca.NotAfter.Sub(now) > spec.Before {
			continue
		}
		res, err := m.RotateIntermediate(ctx, RotateSpec{
			CAID:        ca.ID,
			KeyType:     spec.KeyType,
			Validity:    spec.Validity,
			RequestedBy: spec.RequestedBy,
		})
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rotating CA %q: %w", ca.Label, err)
			}
			continue
		}
		results = append(results, *res)
	}
	return results, firstErr
}

// OutstandingLeaves returns the leaf certificates issued by the given CA that
// are still valid at time now: not expired and not revoked. These are the
// certificates that keep a superseded key alive during the overlap window.
func (m *Manager) OutstandingLeaves(caID string, now time.Time) ([]models.IssuedCertificate, error) {
	certs, err := m.db.ListIssuedCertificates(caID)
	if err != nil {
		return nil, fmt.Errorf("listing issued certificates: %w", err)
	}
	var out []models.IssuedCertificate
	for _, c := range certs {
		if c.Status == models.CertStatusRevoked {
			continue
		}
		if !c.NotAfter.After(now) {
			continue
		}
		// Cross-check the authoritative revocation store as defense-in-depth.
		if revoked, err := m.db.GetRevokedCertificate(caID, c.Serial); err != nil {
			return nil, fmt.Errorf("checking revocation of serial %s: %w", c.Serial, err)
		} else if revoked != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// outstandingLeafDeadline computes the latest NotAfter among the CA's currently
// outstanding leaves — the earliest point at which the key can be safely
// retired. It returns nil when no outstanding leaves remain.
func (m *Manager) outstandingLeafDeadline(caID string, now time.Time) (*time.Time, error) {
	outstanding, err := m.OutstandingLeaves(caID, now)
	if err != nil {
		return nil, err
	}
	var latest time.Time
	for _, c := range outstanding {
		if c.NotAfter.After(latest) {
			latest = c.NotAfter
		}
	}
	if latest.IsZero() {
		return nil, nil
	}
	return &latest, nil
}

// resolveSuperseded resolves a CA id in a rollover lineage to the superseded
// predecessor that is awaiting retirement. If the id is itself superseded it is
// returned directly; otherwise its predecessor is used.
func (m *Manager) resolveSuperseded(caID string) (*models.CA, error) {
	ca, err := m.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("looking up CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", caID)
	}
	switch ca.Status {
	case models.CAStatusSuperseded:
		return ca, nil
	case models.CAStatusRetired:
		return nil, fmt.Errorf("CA %q is already retired", ca.Label)
	}
	// An active CA cannot be retired; its superseded predecessor might be.
	if ca.PredecessorID != nil && *ca.PredecessorID != "" {
		pred, err := m.db.GetCA(*ca.PredecessorID)
		if err != nil {
			return nil, fmt.Errorf("looking up predecessor: %w", err)
		}
		if pred != nil && pred.Status == models.CAStatusSuperseded {
			return pred, nil
		}
	}
	return nil, fmt.Errorf("CA %q is active and has no superseded predecessor to retire", ca.Label)
}

// notAfterOrZero returns a CA's NotAfter, or the zero time when unset.
func notAfterOrZero(ca *models.CA) time.Time {
	if ca.NotAfter != nil {
		return *ca.NotAfter
	}
	return time.Time{}
}

// deriveRotationLabel produces a distinct successor label from a CA's label.
// It appends (or increments) a "-rN" rollover generation suffix so successive
// rotations yield unique, human-recognizable labels.
func deriveRotationLabel(label string) string {
	base := label
	gen := 2
	// If the label already ends in "-rN", bump N.
	if i := lastDashR(label); i >= 0 {
		if n, ok := parseUint(label[i+2:]); ok {
			base = label[:i]
			gen = n + 1
		}
	}
	return fmt.Sprintf("%s-r%d", base, gen)
}

// lastDashR returns the index of a trailing "-r<digits>" marker in s, or -1.
func lastDashR(s string) int {
	for i := len(s) - 1; i >= 1; i-- {
		if s[i] < '0' || s[i] > '9' {
			if s[i] == 'r' && s[i-1] == '-' {
				return i - 1
			}
			return -1
		}
	}
	return -1
}

// parseUint parses a run of decimal digits, returning ok=false on empty/invalid.
func parseUint(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
