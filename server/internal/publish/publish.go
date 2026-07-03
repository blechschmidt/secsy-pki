// Package publish writes the PKI's public revocation and trust artifacts —
// CRLs, delta CRLs, partition shards, issuer chains, and pre-signed OCSP
// responses — as static files to a local directory or an S3-compatible object
// store, laid out so a CDN (or any dumb static file server) can front the
// AIA/CDP/OCSP URLs stamped into certificates without the PKI on the hot path.
//
// Every snapshot is accompanied by a manifest recording the SHA-256 of each
// artifact; backends publish artifacts first and the manifest last, and apply
// an integrity check (local readback, or S3 Content-MD5/ETag comparison) so a
// torn or corrupted write is never exposed. The directory backend additionally
// makes whole snapshots atomic: artifacts are written to a fresh versioned
// directory and a `current` symlink is flipped over it in one rename.
//
// Layout, per CA (all paths relative to the publish root / key prefix):
//
//	<caID>/ca.der, ca.pem                 CA certificate (AIA caIssuers)
//	<caID>/chain.pem                      combined rollover-overlap chain
//	<caID>/chain-<crossSignID>.pem        alternate (cross-signed) chains
//	<caID>/crl.der                        complete base CRL
//	<caID>/crl-delta.der                  delta CRL
//	<caID>/crl-partition-<n>.der          shard base CRL (when partitioned)
//	<caID>/crl-partition-<n>-delta.der    shard delta CRL
//	<caID>/ocsp/by-serial/<serial>.der    pre-signed OCSP response
//	<caID>/ocsp/by-request/<b64url>.der   same response, keyed by the canonical
//	                                      RFC 6960 GET request encoding
//	manifest.json                         snapshot manifest (written last)
//
// See docs/ocsp-presign-publish.md for the CDN mapping rules.
package publish

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Artifact kinds, used in the manifest and the artifact-count metrics.
const (
	KindCRL      = "crl"
	KindDeltaCRL = "delta_crl"
	KindChain    = "chain"
	KindCACert   = "ca_cert"
	KindOCSP     = "ocsp"
)

// ManifestPath is the well-known key of the snapshot manifest. It is written
// last, so a reader that starts from the manifest never observes a snapshot
// with artifacts missing.
const ManifestPath = "manifest.json"

// Artifact is one static object of a snapshot.
type Artifact struct {
	// Path is the artifact's forward-slash-separated path relative to the
	// snapshot root.
	Path string
	// Data is the artifact content.
	Data []byte
	// ContentType is stored as the object Content-Type on backends that carry
	// one (S3); informational for the directory backend.
	ContentType string
	// Kind classifies the artifact (Kind* constants).
	Kind string
	// NotAfter, when non-zero, is the artifact's validity horizon (CRL or OCSP
	// NextUpdate) recorded in the manifest for freshness monitoring.
	NotAfter time.Time
}

// Manifest describes one published snapshot.
type Manifest struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	// EarliestExpiry is the soonest validity horizon among all artifacts; after
	// this instant the snapshot is serving at least one expired artifact and
	// must have been replaced.
	EarliestExpiry *time.Time         `json:"earliest_expiry,omitempty"`
	CAs            []ManifestCA       `json:"cas"`
	Artifacts      []ManifestArtifact `json:"artifacts"`
}

// ManifestCA summarizes one CA's contribution to a snapshot.
type ManifestCA struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// OCSPResponses is the number of pre-signed responses published (0 when
	// OCSP publishing is disabled).
	OCSPResponses int `json:"ocsp_responses"`
	// CRLShards is the number of partition shards (0 when unsharded).
	CRLShards int `json:"crl_shards"`
}

// ManifestArtifact is the integrity record for one artifact.
type ManifestArtifact struct {
	Path        string     `json:"path"`
	Kind        string     `json:"kind"`
	SHA256      string     `json:"sha256"`
	Size        int        `json:"size"`
	ContentType string     `json:"content_type,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
}

// Store is a snapshot backend. Implementations must write artifacts before the
// manifest and fail the whole publish if any object cannot be written and
// integrity-verified.
type Store interface {
	// Name identifies the backend ("dir" or "s3") for metrics and logs.
	Name() string
	// Publish writes one complete snapshot: every artifact, then manifest (the
	// serialized Manifest) at ManifestPath.
	Publish(ctx context.Context, manifest []byte, artifacts []Artifact) error
	// Fetch reads one object of the currently published snapshot, for
	// verification. Fetching ManifestPath returns the manifest.
	Fetch(ctx context.Context, path string) ([]byte, error)
}

// Publisher assembles manifests and drives a Store.
type Publisher struct {
	store Store
}

// NewPublisher returns a Publisher over the given backend.
func NewPublisher(store Store) *Publisher { return &Publisher{store: store} }

// StoreName exposes the backend name for logs.
func (p *Publisher) StoreName() string { return p.store.Name() }

// Publish writes the artifact set as one snapshot and returns its manifest.
// It records the publish metrics (duration, result, per-kind artifact counts).
func (p *Publisher) Publish(ctx context.Context, cas []ManifestCA, artifacts []Artifact) (_ *Manifest, err error) {
	start := time.Now()
	defer func() { metrics.RecordPublishRun(p.store.Name(), start, err) }()

	if err := validateArtifacts(artifacts); err != nil {
		return nil, err
	}
	manifest := buildManifest(cas, artifacts)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding manifest: %w", err)
	}
	data = append(data, '\n')
	if err := p.store.Publish(ctx, data, artifacts); err != nil {
		return nil, err
	}

	counts := map[string]int{}
	for i := range artifacts {
		counts[artifacts[i].Kind]++
	}
	for kind, n := range counts {
		metrics.PublishArtifacts.Set(float64(n), kind)
	}
	return manifest, nil
}

// Verify fetches the currently published manifest from a store and re-reads
// every artifact it lists, checking each SHA-256. It returns the manifest on
// success. It needs no HSM or database access, so it is usable to audit a
// published snapshot during an outage.
func Verify(ctx context.Context, store Store) (*Manifest, error) {
	raw, err := store.Fetch(ctx, ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decoding manifest: %w", err)
	}
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		data, err := store.Fetch(ctx, a.Path)
		if err != nil {
			return nil, fmt.Errorf("fetching %s: %w", a.Path, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
			return nil, fmt.Errorf("integrity check failed for %s: sha256 %s, manifest says %s", a.Path, got, a.SHA256)
		}
		if len(data) != a.Size {
			return nil, fmt.Errorf("integrity check failed for %s: size %d, manifest says %d", a.Path, len(data), a.Size)
		}
	}
	return &m, nil
}

func buildManifest(cas []ManifestCA, artifacts []Artifact) *Manifest {
	m := &Manifest{
		Version:     1,
		GeneratedAt: time.Now().UTC(),
		CAs:         cas,
		Artifacts:   make([]ManifestArtifact, 0, len(artifacts)),
	}
	for i := range artifacts {
		a := &artifacts[i]
		sum := sha256.Sum256(a.Data)
		ma := ManifestArtifact{
			Path:        a.Path,
			Kind:        a.Kind,
			SHA256:      hex.EncodeToString(sum[:]),
			Size:        len(a.Data),
			ContentType: a.ContentType,
		}
		if !a.NotAfter.IsZero() {
			t := a.NotAfter.UTC()
			ma.NotAfter = &t
			if m.EarliestExpiry == nil || t.Before(*m.EarliestExpiry) {
				m.EarliestExpiry = &t
			}
		}
		m.Artifacts = append(m.Artifacts, ma)
	}
	sort.Slice(m.Artifacts, func(i, j int) bool { return m.Artifacts[i].Path < m.Artifacts[j].Path })
	return m
}

// validateArtifacts rejects paths that could escape the snapshot root or
// collide with the manifest. Artifact content is validated where it is built
// (BuildSnapshot parses every CRL/certificate before including it).
func validateArtifacts(artifacts []Artifact) error {
	seen := make(map[string]struct{}, len(artifacts))
	for i := range artifacts {
		p := artifacts[i].Path
		if p == "" || p == ManifestPath {
			return fmt.Errorf("invalid artifact path %q", p)
		}
		if err := checkRelPath(p); err != nil {
			return fmt.Errorf("invalid artifact path %q: %w", p, err)
		}
		if _, dup := seen[p]; dup {
			return fmt.Errorf("duplicate artifact path %q", p)
		}
		seen[p] = struct{}{}
		if len(artifacts[i].Data) == 0 {
			return fmt.Errorf("artifact %q is empty", p)
		}
	}
	return nil
}

// checkRelPath enforces clean, relative, forward-slash paths.
func checkRelPath(p string) error {
	if p[0] == '/' {
		return fmt.Errorf("absolute path")
	}
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			seg := p[start:i]
			if seg == "" || seg == "." || seg == ".." {
				return fmt.Errorf("path segment %q not allowed", seg)
			}
			start = i + 1
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Snapshot assembly
// -----------------------------------------------------------------------------

// SnapshotSource supplies the data a snapshot is built from.
type SnapshotSource struct {
	// Mgr provides CRLs, chains, and CA certificates. CRLs are served from the
	// store while fresh, so building a snapshot only reaches the HSM when a CRL
	// is due for regeneration (or OCSP responses are freshly pre-signed).
	Mgr *ca.Manager
	// DB lists the CAs to publish.
	DB *database.DB
	// Presigner supplies pre-signed OCSP responses. Required when
	// SnapshotOptions.IncludeOCSP is set.
	Presigner *ca.OCSPPresigner
}

// SnapshotOptions selects what a snapshot contains.
type SnapshotOptions struct {
	// CAIDs restricts the snapshot to these CA ids; empty publishes every
	// unexpired X.509 CA.
	CAIDs []string
	// IncludeOCSP publishes the pre-signed OCSP responses.
	IncludeOCSP bool
	// FreshOCSP forces a fresh presign batch per CA instead of reusing the
	// presigner's latest batch (used by the one-shot CLI; the server loop reuses
	// what the presign schedule produced).
	FreshOCSP bool
}

// BuildSnapshot assembles the artifact set for a snapshot. Every artifact is
// parsed/validated before inclusion, so a publish never ships bytes that do
// not decode as what their path claims.
func BuildSnapshot(ctx context.Context, src SnapshotSource, opts SnapshotOptions) ([]Artifact, []ManifestCA, error) {
	if src.Mgr == nil || src.DB == nil {
		return nil, nil, fmt.Errorf("snapshot source requires a CA manager and database")
	}
	if opts.IncludeOCSP && src.Presigner == nil {
		return nil, nil, fmt.Errorf("snapshot with OCSP responses requires a presigner")
	}

	targets, err := selectCAs(src.DB, opts.CAIDs)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("no publishable X.509 CAs matched")
	}

	var artifacts []Artifact
	var cas []ManifestCA
	for i := range targets {
		caArts, info, err := buildCAArtifacts(ctx, src, &targets[i], opts)
		if err != nil {
			return nil, nil, fmt.Errorf("CA %s (%s): %w", targets[i].ID, targets[i].Label, err)
		}
		artifacts = append(artifacts, caArts...)
		cas = append(cas, info)
	}
	return artifacts, cas, nil
}

// selectCAs resolves the target CA set: the given ids/labels, or every
// unexpired X.509 CA when none are named.
func selectCAs(db *database.DB, ids []string) ([]models.CA, error) {
	all, err := db.ListCAs()
	if err != nil {
		return nil, fmt.Errorf("listing CAs: %w", err)
	}
	now := time.Now()
	if len(ids) == 0 {
		var out []models.CA
		for i := range all {
			if all[i].Certificate == "" {
				continue
			}
			if all[i].NotAfter != nil && all[i].NotAfter.Before(now) {
				continue
			}
			out = append(out, all[i])
		}
		return out, nil
	}
	byKey := make(map[string]*models.CA, len(all)*2)
	for i := range all {
		byKey[all[i].ID] = &all[i]
		byKey[all[i].Label] = &all[i]
	}
	var out []models.CA
	for _, id := range ids {
		c, ok := byKey[id]
		if !ok {
			return nil, fmt.Errorf("CA %q not found", id)
		}
		if c.Certificate == "" {
			return nil, fmt.Errorf("CA %q is not an X.509 CA", id)
		}
		out = append(out, *c)
	}
	return out, nil
}

func buildCAArtifacts(ctx context.Context, src SnapshotSource, target *models.CA, opts SnapshotOptions) ([]Artifact, ManifestCA, error) {
	info := ManifestCA{ID: target.ID, Label: target.Label}
	base := target.ID
	var artifacts []Artifact

	// CA certificate (the AIA caIssuers payload), DER and PEM.
	caCert, err := pki.ParseCertificatePEM([]byte(target.Certificate))
	if err != nil {
		return nil, info, fmt.Errorf("parsing CA certificate: %w", err)
	}
	artifacts = append(artifacts,
		Artifact{Path: base + "/ca.der", Data: caCert.Raw, ContentType: "application/pkix-cert", Kind: KindCACert, NotAfter: caCert.NotAfter},
		Artifact{Path: base + "/ca.pem", Data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), ContentType: "application/x-pem-file", Kind: KindCACert, NotAfter: caCert.NotAfter},
	)

	// Issuer chains: the rollover-overlap bundle, plus one bundle per active
	// cross-sign so relying parties can fetch whichever trust path they need.
	chains, err := src.Mgr.AlternateChains(target.ID)
	if err != nil {
		return nil, info, fmt.Errorf("building chains: %w", err)
	}
	seenNative := false
	for _, ch := range chains {
		var path string
		if ch.Native {
			path, seenNative = base+"/chain.pem", true
		} else {
			path = base + "/chain-" + ch.CrossSignID + ".pem"
		}
		if err := validatePEMCertificates([]byte(ch.PEM)); err != nil {
			return nil, info, fmt.Errorf("chain %s: %w", path, err)
		}
		artifacts = append(artifacts, Artifact{Path: path, Data: []byte(ch.PEM), ContentType: "application/x-pem-file", Kind: KindChain})
	}
	if !seenNative {
		// A root CA has no parent lineage; publish its own certificate as the
		// chain bundle so the chain URL is always populated.
		artifacts = append(artifacts, Artifact{Path: base + "/chain.pem", Data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), ContentType: "application/x-pem-file", Kind: KindChain})
	}

	// CRLs: the complete base + delta, and per-shard base + delta when
	// partitioning is enabled. GetBaseCRL/GetDeltaCRL serve the stored copy
	// while fresh and HSM-sign a replacement otherwise.
	scopes := []int{ca.FullScope}
	if n := ca.CRLShardCount(); n >= 2 {
		info.CRLShards = n
		for s := 0; s < n; s++ {
			scopes = append(scopes, s)
		}
	}
	for _, shard := range scopes {
		basePath, deltaPath := crlPaths(base, shard)
		crlDER, err := src.Mgr.GetBaseCRL(ctx, target.ID, shard)
		if err != nil {
			return nil, info, fmt.Errorf("base CRL (shard %d): %w", shard, err)
		}
		na, err := validateCRL(crlDER, caCert)
		if err != nil {
			return nil, info, fmt.Errorf("base CRL (shard %d): %w", shard, err)
		}
		artifacts = append(artifacts, Artifact{Path: basePath, Data: crlDER, ContentType: "application/pkix-crl", Kind: KindCRL, NotAfter: na})

		deltaDER, err := src.Mgr.GetDeltaCRL(ctx, target.ID, shard)
		if err != nil {
			return nil, info, fmt.Errorf("delta CRL (shard %d): %w", shard, err)
		}
		na, err = validateCRL(deltaDER, caCert)
		if err != nil {
			return nil, info, fmt.Errorf("delta CRL (shard %d): %w", shard, err)
		}
		artifacts = append(artifacts, Artifact{Path: deltaPath, Data: deltaDER, ContentType: "application/pkix-crl", Kind: KindDeltaCRL, NotAfter: na})
	}

	// Pre-signed OCSP responses, keyed by serial and by the canonical RFC 6960
	// GET request encoding.
	if opts.IncludeOCSP {
		responses := src.Presigner.Latest(target.ID)
		if opts.FreshOCSP || responses == nil {
			responses, err = src.Presigner.PresignCA(ctx, target.ID)
			if err != nil {
				return nil, info, fmt.Errorf("pre-signing OCSP responses: %w", err)
			}
		}
		now := time.Now()
		for i := range responses {
			r := &responses[i]
			if !r.NextUpdate.After(now) {
				continue // never publish an already-expired response
			}
			serial, ok := new(big.Int).SetString(r.Serial, 10)
			if !ok {
				return nil, info, fmt.Errorf("pre-signed serial %q is not a valid integer", r.Serial)
			}
			artifacts = append(artifacts, Artifact{
				Path:        base + "/ocsp/by-serial/" + r.Serial + ".der",
				Data:        r.DER,
				ContentType: "application/ocsp-response",
				Kind:        KindOCSP,
				NotAfter:    r.NextUpdate,
			})
			reqDER, err := pki.BuildOCSPRequestForSerial(caCert, serial)
			if err != nil {
				return nil, info, fmt.Errorf("canonical OCSP request for serial %s: %w", r.Serial, err)
			}
			artifacts = append(artifacts, Artifact{
				Path:        base + "/ocsp/by-request/" + base64.RawURLEncoding.EncodeToString(reqDER) + ".der",
				Data:        r.DER,
				ContentType: "application/ocsp-response",
				Kind:        KindOCSP,
				NotAfter:    r.NextUpdate,
			})
			info.OCSPResponses++
		}
	}

	return artifacts, info, nil
}

func crlPaths(base string, shard int) (basePath, deltaPath string) {
	if shard == ca.FullScope {
		return base + "/crl.der", base + "/crl-delta.der"
	}
	return fmt.Sprintf("%s/crl-partition-%d.der", base, shard),
		fmt.Sprintf("%s/crl-partition-%d-delta.der", base, shard)
}

// validateCRL parses a CRL, verifies it is signed by issuer, and returns its
// NextUpdate. Publishing an unparsable or foreign CRL would poison every CDN
// consumer at once, so this is checked artifact by artifact.
func validateCRL(der []byte, issuer *x509.Certificate) (time.Time, error) {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing CRL: %w", err)
	}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		return time.Time{}, fmt.Errorf("CRL not signed by CA: %w", err)
	}
	if !rl.NextUpdate.After(time.Now()) {
		return time.Time{}, fmt.Errorf("CRL is already expired (NextUpdate %s)", rl.NextUpdate)
	}
	return rl.NextUpdate, nil
}

func validatePEMCertificates(data []byte) error {
	n := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("parsing chain certificate: %w", err)
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("no certificates in chain")
	}
	return nil
}
