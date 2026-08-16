package hsmaudit

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// The collector drains the device's 62-entry log ring into durable storage.
//
// Its ordering is the whole point. The pre-existing implementation fetched and
// acknowledged in one step and then wrote to the database, logging a warning if
// that write failed. Acknowledgement frees the device's ring slots and is
// irreversible, so any failure after it — a database outage, a crash, a
// constraint violation — destroyed the only copy of records that, by design,
// nothing else in the system can reconstruct. Worse, it did so while returning
// success to the caller, which meant issuance continued over a log that had
// silently stopped being complete.
//
// This collector inverts that: fetch, verify continuity, persist, and only then
// acknowledge. A failure anywhere before the acknowledgement leaves the entries
// on the device, where the next cycle picks them up again. A failure to verify
// stops the drain entirely rather than papering over it, because on a
// force-audited device a stalled drain eventually wedges the HSM — a loud,
// safe failure — whereas a silently discarded segment is exactly the hole an
// abuser needs.

// DrainThreshold is the ring-buffer occupancy at which the collector warns that
// the device is close to refusing operations. The YubiHSM in force-audit mode
// rejects every auditable command once the log is full, so an operator needs
// notice before issuance stops.
const DrainThreshold = MaxLogEntries * 3 / 4

// CollectResult reports what one drain cycle did.
type CollectResult struct {
	// Collected is how many new entries were durably stored this cycle.
	Collected int `json:"collected"`
	// Signatures is how many of them were successful signing operations.
	Signatures int `json:"signatures"`
	// Tail is the position collection now stands at.
	Tail Tail `json:"tail"`
	// LogUsed is the device's ring occupancy report, e.g. "12/62".
	LogUsed string `json:"log_used,omitempty"`
	// Segment is the continuity verdict for the segment just collected.
	Segment *SegmentResult `json:"segment,omitempty"`
}

// Collector drains and verifies the device log on a schedule.
type Collector struct {
	dev      Device
	store    Store
	interval time.Duration
	logger   *log.Logger

	// onFailure is invoked with every verification failure so the server can
	// raise an alert. It is separate from logging because a broken audit chain
	// is an incident, not a log line.
	onFailure func(error)
}

// NewCollector returns a Collector. interval <= 0 selects a default cadence
// chosen to drain the 62-entry ring well before it can fill under normal
// issuance rates.
func NewCollector(dev Device, store Store, interval time.Duration, logger *log.Logger) *Collector {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Collector{dev: dev, store: store, interval: interval, logger: logger}
}

// OnFailure registers a callback invoked whenever a cycle fails verification.
func (c *Collector) OnFailure(fn func(error)) { c.onFailure = fn }

// Run drains the log until ctx is cancelled. It is the entry point registered
// with the leader elector, so exactly one replica drains a given device.
//
// Running it on more than one replica would be incorrect rather than merely
// wasteful: two collectors racing on fetch-and-acknowledge would each see a
// partial segment, and each would report the other's entries as a gap.
func (c *Collector) Run(ctx context.Context) {
	c.logger.Printf("HSM audit collector started (interval %s)", c.interval)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		if res, err := c.Collect(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Printf("ERROR: HSM audit collection failed: %v", err)
			if c.onFailure != nil {
				c.onFailure(err)
			}
		} else if res.Collected > 0 {
			c.logger.Printf("HSM audit: collected %d entr(ies) (%d signature(s)), tail now %d, log %s",
				res.Collected, res.Signatures, res.Tail.Number, res.LogUsed)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Collect performs one drain cycle: fetch, verify, persist, acknowledge.
//
// It returns an error — and leaves the device log unacknowledged — whenever the
// collected segment does not continue the stored chain. That is deliberate
// fail-closed behaviour: continuing to acknowledge entries whose continuity we
// cannot establish would convert a detectable break into an invisible one.
func (c *Collector) Collect(ctx context.Context) (*CollectResult, error) {
	st, err := c.store.LoadAuditState(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading hsm audit state: %w", err)
	}
	if st == nil {
		return nil, fmt.Errorf("HSM audit state not initialised: the device has not been provisioned " +
			"(run `secsy-ca hsm-audit provision`), so there is no pinned chain anchor to verify against")
	}

	info, err := c.dev.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading device info: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(info.Serial), strings.TrimSpace(st.DeviceSerial)) {
		return nil, fmt.Errorf("device serial is %q but the pinned audit state belongs to %q: "+
			"a different HSM is attached, and its log says nothing about the pinned history",
			info.Serial, st.DeviceSerial)
	}

	resp, err := c.dev.FetchLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching device log: %w", err)
	}
	unlogged := Unlogged{Boots: resp.UnloggedBoots, Authentications: resp.UnloggedAuthentications}

	res := &CollectResult{Tail: st.Tail, LogUsed: info.LogUsed}

	// The device re-delivers everything it has not been told to forget. After a
	// cycle that persisted entries but failed to acknowledge them, the next
	// fetch legitimately overlaps what is already stored. Trim the overlap —
	// checking that the overlapping records still match what we hold, since a
	// changed re-delivery means one of the two copies is not genuine — and
	// verify only what is genuinely new.
	fresh, err := trimToTail(resp.Entries, st.Tail)
	if err != nil {
		return nil, err
	}

	seg := VerifySegment(fresh, &st.Tail, unlogged)
	res.Segment = seg
	if err := seg.Err(); err != nil {
		// Do not acknowledge. The entries stay on the device, and the next cycle
		// sees the same problem, until an operator intervenes.
		return res, fmt.Errorf("device log continuity broken, refusing to acknowledge entries: %w", err)
	}

	if len(fresh) > 0 {
		if err := c.store.AppendLogEntries(ctx, fresh); err != nil {
			return res, fmt.Errorf("persisting %d device log entr(ies): %w", len(fresh), err)
		}
		if err := c.store.UpdateTail(ctx, seg.Tail); err != nil {
			return res, fmt.Errorf("advancing collection tail to entry %d: %w", seg.Tail.Number, err)
		}
		res.Collected = len(fresh)
		res.Signatures = countSignatures(fresh)
		res.Tail = seg.Tail
	}

	// Only now, with the segment durable, release the device's ring slots.
	if len(resp.Entries) > 0 {
		last := resp.Entries[len(resp.Entries)-1].Number
		if err := c.dev.ConsumeLog(ctx, last); err != nil {
			// Not fatal: the entries are safely stored, and the next cycle will
			// re-fetch and re-acknowledge them. Report it, because a persistent
			// failure here will fill the ring and wedge the device.
			c.logger.Printf("WARNING: HSM audit: entries stored but acknowledgement failed (device ring will fill if this persists): %v", err)
		}
	}

	metrics.RecordHSMAuditCollection(res.Collected, res.Signatures)

	if used, capacity, ok := parseLogUsed(info.LogUsed); ok && used >= DrainThreshold {
		c.logger.Printf("WARNING: HSM audit: device log %d/%d entries used; the device refuses auditable commands when full",
			used, capacity)
	}
	return res, nil
}

// trimToTail drops entries the store already holds, verifying that the
// overlapping records are unchanged.
//
// An entry that the device re-delivers with different content than the copy we
// persisted cannot be explained innocently: the device log is immutable, so
// either the stored row was edited or the "device" output was fabricated.
func trimToTail(entries []hsm.AuditLogEntry, tail Tail) ([]hsm.AuditLogEntry, error) {
	if tail.Number == 0 || len(entries) == 0 {
		return entries, nil
	}
	for i, e := range entries {
		switch {
		case e.Number == tail.Number:
			if !strings.EqualFold(e.Hash, tail.Digest) {
				return nil, fmt.Errorf(
					"device re-delivered entry %d with digest %s but the stored copy has %s: "+
						"one of the two records is not genuine",
					e.Number, strings.ToLower(e.Hash), strings.ToLower(tail.Digest))
			}
			return entries[i+1:], nil
		case isForward(tail.Number, e.Number) && e.Number != tail.Number:
			// First entry is already past the tail: nothing to trim. Continuity
			// from the tail is VerifySegment's job.
			return entries[i:], nil
		}
	}
	// Everything the device offered is at or behind the tail and none of it
	// matched: the whole segment is stale re-delivery.
	return nil, nil
}

// parseLogUsed parses the device's "used/capacity" report.
func parseLogUsed(s string) (used, capacity int, ok bool) {
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d/%d", &used, &capacity); err != nil {
		return 0, 0, false
	}
	return used, capacity, true
}
