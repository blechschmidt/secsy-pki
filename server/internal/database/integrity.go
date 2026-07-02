package database

import (
	"database/sql"
	"fmt"
	"math/big"
)

// IntegrityCheck is the result of a single named store-integrity invariant.
type IntegrityCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// StoreFingerprint captures the continuity-relevant, monotonic state of the
// store as a set of aggregate counters plus the tamper-evident audit head hash.
// Two fingerprints taken before and after a backup / point-in-time restore can
// be compared to prove that no committed state was silently lost or rewound:
//
//   - AuditHeadHash pins the exact tip of the hash chain (any truncation or
//     rewrite changes it).
//   - The Sum* counter fields are monotonic non-decreasing across the life of
//     the store, so a restored snapshot must never report smaller values than a
//     later one (a rewound counter would re-issue duplicate serials / CRL
//     numbers — the classic split-brain-after-restore hazard).
type StoreFingerprint struct {
	AuditEventCount int    `json:"audit_event_count"`
	AuditChainValid bool   `json:"audit_chain_valid"`
	AuditHeadHash   string `json:"audit_head_hash"`
	IssuedCerts     int    `json:"issued_certs"`
	RevokedCerts    int    `json:"revoked_certs"`
	// SumNextSerial is the sum over all CAs of their next-serial counter. It only
	// ever increases as certificates are issued.
	SumNextSerial int64 `json:"sum_next_serial"`
	// SumNextCRLNumber is the sum over all CAs and scopes of their next-CRL-number
	// counters. It only ever increases as CRLs are published.
	SumNextCRLNumber int64 `json:"sum_next_crl_number"`
}

// IntegrityResult is the full outcome of VerifyStoreIntegrity.
type IntegrityResult struct {
	OK          bool             `json:"ok"`
	Checks      []IntegrityCheck `json:"checks"`
	Fingerprint StoreFingerprint `json:"fingerprint"`
}

// VerifyStoreIntegrity walks the persisted store and asserts the invariants a
// disaster-recovery restore must preserve, independent of the HSM:
//
//  1. audit chain — the hash-chained event_log verifies end-to-end from genesis;
//  2. serial monotonicity — every CA's serial counter is strictly ahead of every
//     serial it has already handed to a subordinate CA;
//  3. CRL numbering continuity — every CA/scope CRL counter is strictly ahead of
//     the highest CRL number it has already published (RFC 5280 §5.2.3);
//  4. revocation-store consistency — the inventory's "revoked" set and the
//     authoritative revocation store agree in both directions.
//
// It returns a structured result plus a StoreFingerprint for cross-snapshot
// (PITR) continuity comparison. It performs only reads and advances no counter,
// so it is safe to run against a live store.
func (db *DB) VerifyStoreIntegrity() (*IntegrityResult, error) {
	res := &IntegrityResult{OK: true}
	add := func(name string, ok bool, detail string) {
		res.Checks = append(res.Checks, IntegrityCheck{Name: name, OK: ok, Detail: detail})
		if !ok {
			res.OK = false
		}
	}

	// 1. Audit hash chain.
	chain, err := db.VerifyEventChain()
	if err != nil {
		return nil, fmt.Errorf("verifying audit chain: %w", err)
	}
	res.Fingerprint.AuditEventCount = chain.Count
	res.Fingerprint.AuditChainValid = chain.Valid
	if chain.Valid {
		add("audit_chain", true, fmt.Sprintf("%d event(s) verified, hash chain intact", chain.Count))
	} else {
		add("audit_chain", false, fmt.Sprintf("broken at seq %d: %s", chain.BrokenAtSeq, chain.Reason))
	}
	if head, err := db.auditHeadHash(); err != nil {
		return nil, fmt.Errorf("reading audit head: %w", err)
	} else {
		res.Fingerprint.AuditHeadHash = head
	}

	// 2. Serial-counter monotonicity.
	if detail, sum, ok, err := db.checkSerialMonotonicity(); err != nil {
		return nil, err
	} else {
		res.Fingerprint.SumNextSerial = sum
		add("serial_monotonicity", ok, detail)
	}

	// 3. CRL numbering continuity.
	if detail, sum, ok, err := db.checkCRLContinuity(); err != nil {
		return nil, err
	} else {
		res.Fingerprint.SumNextCRLNumber = sum
		add("crl_continuity", ok, detail)
	}

	// 4. Revocation-store consistency.
	if detail, issued, revoked, ok, err := db.checkRevocationConsistency(); err != nil {
		return nil, err
	} else {
		res.Fingerprint.IssuedCerts = issued
		res.Fingerprint.RevokedCerts = revoked
		add("revocation_consistency", ok, detail)
	}

	return res, nil
}

// auditHeadHash returns the hash of the newest event, or the genesis hash if the
// log is empty. This pins the exact tip of the tamper-evident chain.
func (db *DB) auditHeadHash() (string, error) {
	var hash sql.NullString
	err := db.queryRow(`SELECT hash FROM event_log ORDER BY seq DESC LIMIT 1`).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return hash.String, nil
}

// checkSerialMonotonicity asserts that each CA's serial counter is strictly
// greater than every serial it has already allocated to a subordinate CA.
// Subordinate-CA serials come from ca_serial_counters (see ca.AllocateSerial);
// leaf serials are random 128-bit values and are intentionally excluded — their
// invariant is uniqueness (enforced by the UNIQUE(ca_id, serial) constraint),
// not monotonicity. Serials are parsed as big.Int to avoid SQL integer overflow.
func (db *DB) checkSerialMonotonicity() (detail string, sumNext int64, ok bool, err error) {
	// next_serial per issuing CA.
	next := map[string]*big.Int{}
	rows, err := db.query(`SELECT ca_id, next_serial FROM ca_serial_counters`)
	if err != nil {
		return "", 0, false, err
	}
	for rows.Next() {
		var caID string
		var ns int64
		if err := rows.Scan(&caID, &ns); err != nil {
			rows.Close()
			return "", 0, false, err
		}
		next[caID] = big.NewInt(ns)
		sumNext += ns
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", 0, false, err
	}
	rows.Close()

	// Highest serial handed to a subordinate CA, grouped by the issuing parent.
	crows, err := db.query(`SELECT parent_id, serial FROM cas WHERE parent_id IS NOT NULL AND serial IS NOT NULL AND serial <> ''`)
	if err != nil {
		return "", 0, false, err
	}
	defer crows.Close()
	maxChild := map[string]*big.Int{}
	for crows.Next() {
		var parent, serial string
		if err := crows.Scan(&parent, &serial); err != nil {
			return "", 0, false, err
		}
		v, valid := new(big.Int).SetString(serial, 10)
		if !valid {
			continue // non-decimal serial (should not happen); skip rather than false-alarm
		}
		if cur, seen := maxChild[parent]; !seen || v.Cmp(cur) > 0 {
			maxChild[parent] = v
		}
	}
	if err := crows.Err(); err != nil {
		return "", 0, false, err
	}

	violations := 0
	var firstBad string
	for parent, mc := range maxChild {
		ns, seen := next[parent]
		if !seen {
			// A parent that has issued a subordinate must have a serial counter.
			violations++
			if firstBad == "" {
				firstBad = fmt.Sprintf("CA %s issued serial %s but has no serial counter", parent, mc)
			}
			continue
		}
		if ns.Cmp(mc) <= 0 { // next_serial must be strictly greater than any allocated serial
			violations++
			if firstBad == "" {
				firstBad = fmt.Sprintf("CA %s next_serial=%s <= max issued subordinate serial %s (counter rewound)", parent, ns, mc)
			}
		}
	}
	if violations > 0 {
		return firstBad, sumNext, false, nil
	}
	return fmt.Sprintf("%d serial counter(s) all ahead of allocated serials", len(next)), sumNext, true, nil
}

// checkCRLContinuity asserts that each CA/scope CRL-number counter is strictly
// greater than the highest CRL number already published for that scope, so a
// restored store can never re-emit a CRL with a stale or duplicate number.
// It covers both the unsharded "full" scope (ca_crl_counters) and partitioned
// scopes (ca_scoped_crl_counters).
func (db *DB) checkCRLContinuity() (detail string, sumNext int64, ok bool, err error) {
	// Highest published CRL number per (ca_id, scope).
	type key struct{ ca, scope string }
	maxPub := map[key]int64{}
	prows, err := db.query(`SELECT ca_id, scope, crl_number FROM ca_published_crls`)
	if err != nil {
		return "", 0, false, err
	}
	for prows.Next() {
		var ca, scope string
		var n int64
		if err := prows.Scan(&ca, &scope, &n); err != nil {
			prows.Close()
			return "", 0, false, err
		}
		k := key{ca, scope}
		if n > maxPub[k] {
			maxPub[k] = n
		}
	}
	if err := prows.Err(); err != nil {
		prows.Close()
		return "", 0, false, err
	}
	prows.Close()

	counters := 0
	violations := 0
	var firstBad string

	check := func(ca, scope string, nextNum int64) {
		counters++
		sumNext += nextNum
		mp := maxPub[key{ca, scope}]
		if nextNum <= mp {
			violations++
			if firstBad == "" {
				firstBad = fmt.Sprintf("CA %s scope %q next_number=%d <= highest published %d (counter rewound)", ca, scope, nextNum, mp)
			}
		}
	}

	// Unsharded scope.
	frows, err := db.query(`SELECT ca_id, next_number FROM ca_crl_counters`)
	if err != nil {
		return "", 0, false, err
	}
	for frows.Next() {
		var ca string
		var n int64
		if err := frows.Scan(&ca, &n); err != nil {
			frows.Close()
			return "", 0, false, err
		}
		check(ca, "full", n)
	}
	if err := frows.Err(); err != nil {
		frows.Close()
		return "", 0, false, err
	}
	frows.Close()

	// Partitioned scopes.
	srows, err := db.query(`SELECT ca_id, scope, next_number FROM ca_scoped_crl_counters`)
	if err != nil {
		return "", 0, false, err
	}
	defer srows.Close()
	for srows.Next() {
		var ca, scope string
		var n int64
		if err := srows.Scan(&ca, &scope, &n); err != nil {
			return "", 0, false, err
		}
		check(ca, scope, n)
	}
	if err := srows.Err(); err != nil {
		return "", 0, false, err
	}

	if violations > 0 {
		return firstBad, sumNext, false, nil
	}
	return fmt.Sprintf("%d CRL counter(s) all ahead of published numbers", counters), sumNext, true, nil
}

// checkRevocationConsistency asserts the inventory and the authoritative
// revocation store agree in both directions:
//
//   - every issued certificate marked "revoked" has a row in
//     revoked_certificates (otherwise CRL/OCSP would serve it as good); and
//   - every revoked_certificates row that corresponds to a known issued
//     certificate has that certificate's status set to "revoked" (a revoked
//     serial must never read back as valid).
//
// Revocations for serials with no issued-certificate row are permitted by design
// (externally issued certificates), so they are not flagged.
func (db *DB) checkRevocationConsistency() (detail string, issued, revoked int, ok bool, err error) {
	if err := db.queryRow(`SELECT COUNT(*) FROM issued_certificates`).Scan(&issued); err != nil {
		return "", 0, 0, false, err
	}
	if err := db.queryRow(`SELECT COUNT(*) FROM revoked_certificates`).Scan(&revoked); err != nil {
		return "", 0, 0, false, err
	}

	// Certificates flagged revoked in the inventory but absent from the store.
	var missing int
	if err := db.queryRow(
		`SELECT COUNT(*) FROM issued_certificates ic
		   WHERE ic.status = 'revoked'
		     AND NOT EXISTS (
		         SELECT 1 FROM revoked_certificates rc
		          WHERE rc.ca_id = ic.ca_id AND rc.serial = ic.serial)`,
	).Scan(&missing); err != nil {
		return "", issued, revoked, false, err
	}

	// Certificates present in the revocation store but still marked valid.
	var stillValid int
	if err := db.queryRow(
		`SELECT COUNT(*) FROM revoked_certificates rc
		   JOIN issued_certificates ic ON ic.ca_id = rc.ca_id AND ic.serial = rc.serial
		  WHERE ic.status <> 'revoked' AND ic.status <> 'expired'`,
	).Scan(&stillValid); err != nil {
		return "", issued, revoked, false, err
	}

	if missing == 0 && stillValid == 0 {
		return fmt.Sprintf("%d issued / %d revoked; inventory and revocation store agree", issued, revoked), issued, revoked, true, nil
	}
	return fmt.Sprintf("%d revoked-but-not-in-store, %d in-store-but-not-revoked", missing, stillValid),
		issued, revoked, false, nil
}
