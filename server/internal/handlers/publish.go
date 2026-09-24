package handlers

// REST surface for static-artifact publishing (`secsy-ca publish`, `secsy-ca
// publish -verify`) — Task 198.
//
// Publishing writes the PKI's public revocation and trust artifacts — CRLs, delta
// CRLs, partition shards, issuer chains, CA certificates, and pre-signed OCSP
// responses — as one atomic snapshot to the configured directory or S3-compatible
// store, so a CDN can front the AIA/CDP/OCSP URLs stamped into certificates. The
// server already does this on a schedule, but there was no way to force a
// snapshot after a revocation, and no way to audit the published one, without
// shell access to the CA host.
//
// Both endpoints drive the SAME publish package the background loop and the CLI
// drive, over the SAME configured destination, so the console cannot publish
// somewhere else or report a different snapshot than `secsy-ca publish` does.
//
// Two asymmetries are deliberate, and both are the CLI's:
//
//   - publish needs the CA key provider (a stale CRL is regenerated and signed on
//     the way into the snapshot); verify needs neither the HSM nor the database.
//     Verify is a pure manifest/digest audit, so an operator can prove artifact
//     integrity DURING an HSM outage — which is exactly when they will want to.
//   - verify does not produce anything. It re-reads what is published and checks
//     it against the manifest; it never signs, never touches an artifact, and
//     never replaces a snapshot, which is why it is gated on audit:read rather
//     than on the publish capability.
//
//     It is not, however, literally write-free: opening the destination goes
//     through the same publish.Store constructor the publish path uses, and
//     publish.NewDirStore creates <root>/snapshots if it is absent. So verifying an
//     unpublished directory destination can CREATE the empty directory before
//     answering 404. Nothing inside a snapshot is ever written, and the 404 is
//     unchanged — the claim being narrowed here is "never writes", not the
//     endpoint's read-only authority.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/publish"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// Time budgets. A snapshot regenerates every stale CRL and (unless skipped)
// pre-signs OCSP responses for every known serial, so the work scales with the
// deployment; it is bounded anyway, because it is a request. Verification only
// re-reads and digests what is already published, so it gets a shorter default.
const (
	publishDefaultTimeout = 2 * time.Minute
	publishVerifyTimeout  = 1 * time.Minute
	publishMaxTimeout     = 10 * time.Minute
)

// publishMu serializes snapshot publication across everything in this process.
// Publishing mutates a SHARED destination: two concurrent publishes would race
// their atomic swaps against the same root (and needlessly duplicate the HSM work
// behind them), so the second one is told to retry instead of being interleaved.
//
// It is package-level rather than per-API on purpose, and that is a real
// statement, not an implementation detail: the destination comes from PROCESS
// configuration, so one process has exactly one destination and a per-API lock
// would not guard it — which also means two API values constructed in one process
// share this guard, as they must.
//
// The scope includes the leader-elected background publish loop. In the
// single-binary server that loop is elector.Register("artifact-publish", …) in
// THIS process (cmd/server/presign_publish.go), which is why it takes this same
// guard through TryPublishLock: "one replica publishing prevents racing atomic
// swaps against the same target" is the property that loop is documented to
// provide, and an operator-triggered publish landing mid-swap would break it.
var publishMu sync.Mutex

// TryPublishLock acquires the process-wide publish single-flight, reporting false
// when a publish is already running. The caller must call release exactly once on
// every path when ok is true.
//
// Exported for cmd/server's background publish loop: it publishes to the same
// configured destination as POST /api/publish, so the two must exclude each other
// rather than each assume the other is elsewhere. A loser does not queue — a
// snapshot supersedes rather than merges, so waiting to publish a now-staler view
// of the world buys nothing.
func TryPublishLock() (release func(), ok bool) {
	if !publishMu.TryLock() {
		return nil, false
	}
	return publishMu.Unlock, true
}

// PublishRequest is the body of POST /api/publish. Every field is optional; the
// zero value publishes exactly what the configured schedule would.
type PublishRequest struct {
	// CAs restricts the snapshot to these CA ids or labels (`-ca`). Empty uses the
	// configured publish.cas, and when that is empty too, every unexpired X.509 CA.
	CAs []string `json:"cas,omitempty"`
	// SkipOCSP publishes only CRLs, chains and CA certificates (`-skip-ocsp`).
	SkipOCSP bool `json:"skip_ocsp,omitempty"`
	// OCSPValiditySeconds overrides the pre-signed OCSP response validity
	// (`-ocsp-validity`). 0 uses the configured presign validity. Setting it forces
	// a fresh presign batch, since the shared one carries the configured validity.
	OCSPValiditySeconds int `json:"ocsp_validity_seconds,omitempty"`
	// TimeoutSeconds bounds the run (default 120, capped at 600).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// PublishVerifyRequest is the body of POST /api/publish/verify. Optional.
type PublishVerifyRequest struct {
	// TimeoutSeconds bounds the audit (default 60, capped at 600).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// PublishSkippedCA reports a CA that was left out of the snapshot, and why.
type PublishSkippedCA struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Reason is "not an X.509 CA" (no CA certificate — e.g. an SSH-only signing
	// key) or "CA certificate expired".
	Reason string `json:"reason"`
}

// PublishResponse is the body of POST /api/publish: the snapshot that is now
// current. It carries the per-CA summary and the per-artifact digests the CLI
// prints, so the console can show exactly what a CDN will start serving.
type PublishResponse struct {
	// Backend is "dir" or "s3"; Destination is the resolved target.
	Backend     string `json:"backend"`
	Destination string `json:"destination"`
	// Version and GeneratedAt identify the snapshot; EarliestExpiry is the soonest
	// validity horizon among its artifacts — after it, the snapshot is serving at
	// least one expired artifact and must have been replaced.
	Version        int        `json:"version"`
	GeneratedAt    time.Time  `json:"generated_at"`
	EarliestExpiry *time.Time `json:"earliest_expiry,omitempty"`
	// IncludeOCSP reports whether pre-signed OCSP responses were published, and
	// OCSPFresh whether they were signed for this snapshot (as the CLI does) rather
	// than reused from the background presign batch (as the server loop does).
	IncludeOCSP bool `json:"include_ocsp"`
	OCSPFresh   bool `json:"ocsp_fresh"`
	// CAs summarizes each published CA (id, label, ocsp_responses, crl_shards).
	CAs []publish.ManifestCA `json:"cas"`
	// Skipped names the CAs deliberately left out; empty when a snapshot covers
	// everything (or when the caller named the CAs explicitly).
	Skipped []PublishSkippedCA `json:"skipped,omitempty"`
	// Artifacts is the integrity record of every written object: path, kind,
	// sha256, size, content type, and validity horizon.
	Artifacts []publish.ManifestArtifact `json:"artifacts"`
	// ArtifactCount and CACount are the summary line the CLI prints.
	ArtifactCount int   `json:"artifact_count"`
	CACount       int   `json:"ca_count"`
	DurationMS    int64 `json:"duration_ms"`
}

// PublishVerifyResponse is the body of POST /api/publish/verify: the findings of
// re-reading the published snapshot and checking it against its own manifest.
type PublishVerifyResponse struct {
	Backend     string `json:"backend"`
	Destination string `json:"destination"`
	// OK is true when the manifest was found and every artifact it lists re-read
	// with the recorded digest and size.
	OK bool `json:"ok"`
	// Error is the first integrity finding (the audit is fail-fast, exactly as
	// `secsy-ca publish -verify` is), empty when OK.
	Error string `json:"error,omitempty"`
	// The manifest of the snapshot that was audited; absent when it could not be
	// fetched or decoded.
	Version        int                        `json:"version,omitempty"`
	GeneratedAt    *time.Time                 `json:"generated_at,omitempty"`
	EarliestExpiry *time.Time                 `json:"earliest_expiry,omitempty"`
	CAs            []publish.ManifestCA       `json:"cas,omitempty"`
	Artifacts      []publish.ManifestArtifact `json:"artifacts,omitempty"`
	// VerifiedArtifacts is how many objects were re-read and digest-checked.
	VerifiedArtifacts int   `json:"verified_artifacts"`
	CACount           int   `json:"ca_count"`
	DurationMS        int64 `json:"duration_ms"`
}

// PublishSnapshot handles POST /api/publish — the REST form of `secsy-ca publish`.
//
// Gated on the platform-wide ca:configure capability (admin). A publish replaces
// the revocation and trust artifacts EVERY relying party consumes, across every
// tenant's CAs, and regenerates CRLs on the HSM to do it: a wrong or stale
// snapshot is a deployment-wide revocation-availability event. That is operator
// authority over shared infrastructure, not per-CA issuance authority, so it is
// deliberately not reachable with cert:issue and no tenant-scoped role reaches it
// — a tenant admin must not be able to republish another tenant's CRLs.
func (a *API) PublishSnapshot(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionConfigureCA) {
		a.recordEvent(r, audit.ActionCRLPublish, "", "", audit.ResultDenied,
			"publish=snapshot ca:configure capability required")
		writeError(w, http.StatusForbidden, "ca:configure capability required (admin role)")
		return
	}

	var req PublishRequest
	if err := decodePublishBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.OCSPValiditySeconds < 0 || req.TimeoutSeconds < 0 {
		writeError(w, http.StatusBadRequest, "ocsp_validity_seconds and timeout_seconds must not be negative")
		return
	}

	deps, ok := a.requireOps(w, "static-artifact publishing")
	if !ok {
		return
	}
	store, backend, destination, err := publishStore(deps.Config.Publish)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "%v", err)
		return
	}

	// One publish at a time against a shared destination — including the background
	// loop's, which takes the same guard; the loser retries.
	release, free := TryPublishLock()
	if !free {
		writeError(w, http.StatusConflict,
			"another publish is already running against %s; retry when it completes", destination)
		return
	}
	defer release()

	// Resolve the target CA set here rather than inside the snapshot builder, so an
	// unknown CA is a 400 with its name and the CAs deliberately left out can be
	// reported. The resolved ids are then passed down explicitly, which means the
	// builder's own selection cannot disagree with what is reported here.
	targets, skipped, err := publishTargets(a.db, req.CAs, deps.Config.Publish.CAs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(targets) == 0 {
		writeError(w, http.StatusConflict,
			"no publishable X.509 CA: every CA either has no certificate or has expired")
		return
	}

	// The CA role's provider, reusing the serving one when the role resolves to the
	// same backend: on PKCS#11 a second provider means a second session pool, and a
	// YubiHSM 2 caps the device at 16 sessions against the eight the serving
	// provider already holds — so opening one unconditionally would let one publish
	// sit at the limit and two concurrent ones starve live CA signing. release() is
	// a no-op for the shared provider and closes the one it opened otherwise.
	provider, release, ok := a.providerForRole(w, "ca", "static-artifact publishing")
	if !ok {
		return
	}
	defer release()

	// A snapshot is atomic at the destination but its HSM work is not free to
	// repeat; a client disconnect must not abandon half-regenerated CRLs, so the
	// run is detached from the request's cancellation and bounded on its own.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()),
		publishTimeout(req.TimeoutSeconds, publishDefaultTimeout))
	defer cancel()

	start := time.Now()
	mgr := ca.NewManager(a.db, provider)
	includeOCSP := deps.Config.Publish.IncludeOCSPEnabled() && !req.SkipOCSP
	presigner, fresh := a.publishPresigner(mgr, deps.Config, req, includeOCSP)

	artifacts, caInfos, err := publish.BuildSnapshot(ctx, publish.SnapshotSource{
		Mgr: mgr, DB: a.db, Presigner: presigner,
	}, publish.SnapshotOptions{
		CAIDs:       targets,
		IncludeOCSP: includeOCSP,
		FreshOCSP:   fresh,
	})
	if err != nil {
		a.recordEvent(r, audit.ActionCRLPublish, backend, destination, audit.ResultError,
			fmt.Sprintf("publish=snapshot cas=%d error=%v via=api", len(targets), err))
		writeError(w, http.StatusInternalServerError, "building the snapshot: %v", err)
		return
	}

	manifest, err := publish.NewPublisher(store).Publish(ctx, caInfos, artifacts)
	if err != nil {
		a.recordEvent(r, audit.ActionCRLPublish, backend, destination, audit.ResultError,
			fmt.Sprintf("publish=snapshot artifacts=%d cas=%d error=%v via=api", len(artifacts), len(caInfos), err))
		writeError(w, http.StatusInternalServerError, "publishing the snapshot: %v", err)
		return
	}

	// The per-CRL crl.publish events the CA manager appends when it regenerates a
	// stale CRL are the record of the signing; this one records the snapshot as a
	// whole and, unlike those, which operator asked for it.
	a.recordEvent(r, audit.ActionCRLPublish, backend, destination, audit.ResultSuccess,
		fmt.Sprintf("publish=snapshot backend=%s target=%s artifacts=%d cas=%d skipped=%d ocsp=%t via=api",
			backend, destination, len(manifest.Artifacts), len(caInfos), len(skipped), includeOCSP))

	writeJSON(w, http.StatusOK, PublishResponse{
		Backend:        backend,
		Destination:    destination,
		Version:        manifest.Version,
		GeneratedAt:    manifest.GeneratedAt,
		EarliestExpiry: manifest.EarliestExpiry,
		IncludeOCSP:    includeOCSP,
		OCSPFresh:      includeOCSP && fresh,
		CAs:            caInfos,
		Skipped:        skipped,
		Artifacts:      manifest.Artifacts,
		ArtifactCount:  len(manifest.Artifacts),
		CACount:        len(caInfos),
		DurationMS:     time.Since(start).Milliseconds(),
	})
}

// VerifyPublishedSnapshot handles POST /api/publish/verify — the REST form of
// `secsy-ca publish -verify`.
//
// Gated on the platform-wide audit:read capability, NOT on the publish gate: it
// is a read-only integrity audit of artifacts that are public by construction
// (a CDN serves them to anyone), and its whole value is being available when the
// signing path is not. Requiring the HSM or the administrative capability here
// would defeat the point — an auditor must be able to answer "is what we are
// serving intact?" during an outage.
//
// A failed audit is a finding, not a broken request: the response carries ok=false
// and the finding with HTTP 200, like the diagnostics endpoint. 404 means there is
// no published snapshot at the destination at all.
func (a *API) VerifyPublishedSnapshot(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "platform-wide audit:read capability required (admin or auditor role)")
		return
	}

	var req PublishVerifyRequest
	if err := decodePublishBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.TimeoutSeconds < 0 {
		writeError(w, http.StatusBadRequest, "timeout_seconds must not be negative")
		return
	}

	deps, ok := a.requireOps(w, "publish verification")
	if !ok {
		return
	}
	store, backend, destination, err := publishStore(deps.Config.Publish)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "%v", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(),
		publishTimeout(req.TimeoutSeconds, publishVerifyTimeout))
	defer cancel()

	start := time.Now()
	resp := PublishVerifyResponse{Backend: backend, Destination: destination}

	// Fetch the manifest first so "nothing is published" is distinguishable from
	// "what is published is corrupt". publish.Verify then re-reads and digests
	// every artifact the manifest lists.
	if _, ferr := store.Fetch(ctx, publish.ManifestPath); ferr != nil {
		resp.Error = fmt.Sprintf("no published snapshot at %s (manifest unreadable): %v", destination, ferr)
		resp.DurationMS = time.Since(start).Milliseconds()
		writeJSON(w, http.StatusNotFound, resp)
		return
	}

	manifest, err := publish.Verify(ctx, store)
	resp.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		resp.Error = err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	generated := manifest.GeneratedAt
	resp.OK = true
	resp.Version = manifest.Version
	resp.GeneratedAt = &generated
	resp.EarliestExpiry = manifest.EarliestExpiry
	resp.CAs = manifest.CAs
	resp.Artifacts = manifest.Artifacts
	resp.VerifiedArtifacts = len(manifest.Artifacts)
	resp.CACount = len(manifest.CAs)
	writeJSON(w, http.StatusOK, resp)
}

// publishPresigner picks the source of pre-signed OCSP responses for a snapshot,
// and reports whether a fresh batch will be signed.
//
// The server's shared presigner is preferred when it exists: reusing the batch the
// presign schedule already produced is what the background publish loop does, and
// it keeps an operator-triggered publish from re-signing every known serial on the
// HSM. When there is no shared presigner (pre-signing disabled) or the caller
// overrode the response validity, one is built from configuration and a fresh
// batch is signed — exactly what the CLI does.
func (a *API) publishPresigner(mgr *ca.Manager, cfg *config.Config, req PublishRequest, includeOCSP bool) (*ca.OCSPPresigner, bool) {
	if !includeOCSP {
		return nil, false
	}
	if a.ocspPresigner != nil && req.OCSPValiditySeconds == 0 {
		return a.ocspPresigner, false
	}
	validity := time.Duration(req.OCSPValiditySeconds) * time.Second
	if validity <= 0 {
		validity = cfg.Server.OCSP.Presign.Validity()
	}
	return ca.NewOCSPPresigner(mgr, ca.OCSPPresignerConfig{
		Validity:     validity,
		ExpiredGrace: cfg.Server.OCSP.Presign.ExpiredGrace(),
	}), true
}

// publishTargets resolves the CA set to publish and the CAs left out.
//
// Named CAs (from the request, else publish.cas) are resolved by id or label and
// an unknown or non-X.509 name is an error — the CLI's behavior, and the reason a
// typo does not silently publish a partial snapshot. With nothing named, every
// unexpired X.509 CA is published and the rest are reported as skipped, mirroring
// publish.BuildSnapshot's own selection rules.
func publishTargets(db publishCALister, requested, configured []string) (targets []string, skipped []PublishSkippedCA, err error) {
	all, err := db.ListCAs()
	if err != nil {
		return nil, nil, fmt.Errorf("listing CAs: %w", err)
	}
	names := requested
	if len(names) == 0 {
		names = configured
	}
	if len(names) > 0 {
		byKey := make(map[string]*models.CA, len(all)*2)
		for i := range all {
			byKey[all[i].ID] = &all[i]
			byKey[all[i].Label] = &all[i]
		}
		for _, name := range names {
			c, found := byKey[strings.TrimSpace(name)]
			if !found {
				return nil, nil, fmt.Errorf("CA %q not found", name)
			}
			if c.Certificate == "" {
				return nil, nil, fmt.Errorf("CA %q is not an X.509 CA", name)
			}
			targets = append(targets, c.ID)
		}
		return targets, nil, nil
	}
	now := time.Now()
	for i := range all {
		c := &all[i]
		switch {
		case c.Certificate == "":
			skipped = append(skipped, PublishSkippedCA{ID: c.ID, Label: c.Label, Reason: "not an X.509 CA"})
		case c.NotAfter != nil && c.NotAfter.Before(now):
			skipped = append(skipped, PublishSkippedCA{ID: c.ID, Label: c.Label, Reason: "CA certificate expired"})
		default:
			targets = append(targets, c.ID)
		}
	}
	return targets, skipped, nil
}

// publishCALister is the narrow view of the store publishTargets needs, so it is
// testable without a database.
type publishCALister interface {
	ListCAs() ([]models.CA, error)
}

// publishStore opens the configured publish backend and describes the target.
// Unlike the CLI there is no per-request destination override: the destination is
// process configuration, because accepting one over HTTP would turn an
// administrative endpoint into an arbitrary-filesystem-write primitive.
func publishStore(pub config.PublishConfig) (publish.Store, string, string, error) {
	if pub.Backend() == "s3" {
		store, err := publish.NewS3Store(context.Background(), publish.S3Config{
			Endpoint:        pub.S3.Endpoint,
			Region:          pub.S3.Region,
			Bucket:          pub.S3.Bucket,
			Prefix:          pub.S3.Prefix,
			AccessKeyID:     pub.S3.AccessKeyID,
			SecretAccessKey: pub.S3.SecretAccessKey,
			SessionToken:    pub.S3.SessionToken,
			ForcePathStyle:  pub.S3.ForcePathStyle,
			Concurrency:     pub.S3.Concurrency,
		})
		if err != nil {
			return nil, "", "", fmt.Errorf("opening the S3 publish backend: %w", err)
		}
		return store, "s3", "s3://" + pub.S3.Bucket + "/" + strings.Trim(pub.S3.Prefix, "/"), nil
	}
	if pub.Dir.Path == "" {
		// The CLI falls back to ./publish; a server must not invent a destination
		// relative to its working directory.
		return nil, "", "", fmt.Errorf("static-artifact publishing is unavailable: no destination configured (set publish.dir.path or publish.s3.bucket)")
	}
	store, err := publish.NewDirStore(pub.Dir.Path, pub.Dir.KeepSnapshots)
	if err != nil {
		return nil, "", "", fmt.Errorf("opening the directory publish backend: %w", err)
	}
	return store, "dir", pub.Dir.Path, nil
}

// publishTimeout clamps a requested budget to the endpoint's default and ceiling.
//
// The clamp is applied in SECONDS, before the multiplication: time.Duration counts
// nanoseconds in an int64, so time.Duration(requested) * time.Second wraps once
// requested exceeds ~9.2e9, and it wraps NEGATIVE — which is below the ceiling and
// so passes a clamp applied afterwards. A negative timeout is an already-expired
// deadline, turning a large requested budget into an instant
// "context deadline exceeded" and a 500 on a publish that never started.
func publishTimeout(requested int, def time.Duration) time.Duration {
	if requested <= 0 {
		return def
	}
	if requested >= int(publishMaxTimeout/time.Second) {
		return publishMaxTimeout
	}
	return time.Duration(requested) * time.Second
}

// decodePublishBody decodes an optional JSON body: both endpoints are POSTs whose
// every field has a default, so an empty body means "publish/verify what the
// configuration says", while a malformed one is still rejected.
func decodePublishBody(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
