package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"strings"
	"time"
)

// decision is the outcome of evaluating one certificate spec.
type decision struct {
	// due means the certificate must be (re)enrolled now.
	due bool
	// reason explains why (for logs, state, and the status command).
	reason string
	// renewAt is the planned renewal moment when not due (zero when due).
	renewAt time.Time
	// source records what drove the timing: "trigger" (missing/drifted/
	// expired), "ari", or "lifetime".
	source string
}

// hashFrac maps a seed deterministically to [0, 1). Deriving jitter from the
// certificate serial keeps every agent's schedule stable across restarts while
// spreading a fleet enrolled in one batch — the client-side counterpart of the
// monitor's renewal-storm prevention.
func hashFrac(seed string) float64 {
	h := fnv.New64a()
	h.Write([]byte(seed)) //nolint:errcheck
	return float64(h.Sum64()>>11) / float64(uint64(1)<<53)
}

// lifetimeRenewTime computes the fraction-of-lifetime renewal moment with
// deterministic jitter: NotBefore + (fraction + jitter·u)·lifetime, capped a
// safety margin before expiry.
func lifetimeRenewTime(cert *x509.Certificate, fraction, jitter float64, seed string) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	if lifetime <= 0 {
		return cert.NotAfter
	}
	point := fraction + jitter*hashFrac(seed)
	renewAt := cert.NotBefore.Add(time.Duration(point * float64(lifetime)))
	margin := lifetime / 20
	if margin > 5*time.Minute {
		margin = 5 * time.Minute
	}
	if latest := cert.NotAfter.Add(-margin); renewAt.After(latest) {
		renewAt = latest
	}
	return renewAt
}

// selectARITime picks the renewal moment inside an ARI suggested window. The
// choice is uniform over the window but deterministic per certificate, so it
// is idempotent across agent restarts (per draft-ietf-acme-ari the client
// selects a uniformly random moment; deriving it from the CertID satisfies
// that without re-rolling every pass).
func selectARITime(start, end time.Time, seed string) time.Time {
	if !end.After(start) {
		return end
	}
	span := end.Sub(start)
	return start.Add(time.Duration(hashFrac(seed) * float64(span)))
}

// evaluate inspects one spec's installed material and decides whether to renew
// now, and if not, when. It never mutates files. offline suppresses network
// lookups (the status command), falling back to cached ARI data or the
// lifetime fraction.
func (a *Agent) evaluate(ctx context.Context, spec *CertSpec, now time.Time, offline bool) decision {
	inst, reason := a.loadInstalled(spec)
	if inst == nil {
		return decision{due: true, reason: reason, source: "trigger"}
	}
	if drift := specDrift(spec, inst); drift != "" {
		return decision{due: true, reason: drift, source: "trigger"}
	}
	if !now.Before(inst.leaf.NotAfter) {
		return decision{due: true, reason: "certificate has expired", source: "trigger"}
	}

	if spec.Enroll == EnrollACME && !a.cfg.Renewal.DisableARI {
		if dec, ok := a.ariDecision(ctx, spec, inst.leaf, now, offline); ok {
			return dec
		}
	}

	renewAt := lifetimeRenewTime(inst.leaf, a.cfg.fraction(spec), a.cfg.jitter(spec), inst.leaf.SerialNumber.String()+"/"+spec.Name)
	if !now.Before(renewAt) {
		return decision{due: true, reason: fmt.Sprintf("past %.0f%% of lifetime", a.cfg.fraction(spec)*100), source: "lifetime"}
	}
	return decision{renewAt: renewAt, source: "lifetime"}
}

// ariDecision consults ACME Renewal Information for the leaf. ok is false when
// ARI is unavailable (unsupported, unknown certificate, transport failure), in
// which case the caller falls back to fraction-of-lifetime timing. offline
// uses only cached data.
func (a *Agent) ariDecision(ctx context.Context, spec *CertSpec, leaf *x509.Certificate, now time.Time, offline bool) (decision, bool) {
	if a.acme == nil {
		return decision{}, false
	}
	certID, err := ariCertID(leaf)
	if err != nil {
		return decision{}, false
	}

	st := a.state.cert(spec.Name)
	info := st.ARI
	// Cached windows stay usable for offline status even past Retry-After, as
	// long as they belong to the installed certificate.
	fresh := info != nil && info.CertID == certID && (offline ||
		(info.RetryAfter > 0 && now.Before(info.FetchedAt.Add(time.Duration(info.RetryAfter)*time.Second))))
	if !fresh {
		if offline {
			return decision{}, false
		}
		fetched, err := a.acme.RenewalInfo(ctx, leaf)
		if err != nil {
			if !errors.Is(err, errARIUnsupported) {
				log.Printf("agent: %s: ARI unavailable, falling back to lifetime fraction: %v", spec.Name, err)
			}
			return decision{}, false
		}
		retryAfter := int64(fetched.RetryAfter / time.Second)
		if retryAfter <= 0 {
			retryAfter = int64(6 * time.Hour / time.Second)
		}
		info = &ariState{
			CertID:      certID,
			WindowStart: fetched.WindowStart,
			WindowEnd:   fetched.WindowEnd,
			Selected:    selectARITime(fetched.WindowStart, fetched.WindowEnd, certID+"/"+spec.Name),
			RetryAfter:  retryAfter,
			FetchedAt:   now,
		}
		st.ARI = info
		a.state.dirty = true
	}

	if !now.Before(info.Selected) {
		return decision{due: true, reason: "inside ARI suggested renewal window", source: "ari"}, true
	}
	return decision{renewAt: info.Selected, source: "ari"}, true
}

// installedCert is the material currently on disk for a spec.
type installedCert struct {
	leaf  *x509.Certificate
	key   crypto.Signer
	chain []*x509.Certificate // extra certs found alongside the leaf
}

// loadInstalled reads the spec's key and certificate files. A nil return
// (with a reason) means enrollment is required.
func (a *Agent) loadInstalled(spec *CertSpec) (*installedCert, string) {
	keyPEM, err := readFileIfExists(spec.KeyFile)
	if err != nil {
		return nil, fmt.Sprintf("key file unreadable: %v", err)
	}
	certPEM, err := readFileIfExists(spec.CertFile)
	if err != nil {
		return nil, fmt.Sprintf("certificate file unreadable: %v", err)
	}
	if keyPEM == nil || certPEM == nil {
		return nil, "not yet installed"
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Sprintf("key file invalid: %v", err)
	}
	certs, err := parseCertsPEM(certPEM)
	if err != nil {
		return nil, fmt.Sprintf("certificate file invalid: %v", err)
	}
	inst := &installedCert{leaf: certs[0], key: key, chain: certs[1:]}
	if !publicKeysMatch(inst.leaf, key) {
		return nil, "private key does not match the certificate"
	}
	if spec.ChainFile != "" {
		if chainPEM, err := readFileIfExists(spec.ChainFile); err == nil && chainPEM != nil {
			if chain, err := parseCertsPEM(chainPEM); err == nil {
				inst.chain = append(inst.chain, chain...)
			}
		}
	}
	return inst, ""
}

// specDrift reports a non-empty reason when the installed certificate no
// longer matches the declared spec (SANs, CN, or key type changed).
func specDrift(spec *CertSpec, inst *installedCert) string {
	haveDNS := make(map[string]bool, len(inst.leaf.DNSNames))
	for _, d := range inst.leaf.DNSNames {
		haveDNS[strings.ToLower(d)] = true
	}
	for _, want := range spec.DNSNames {
		if !haveDNS[strings.ToLower(want)] {
			return fmt.Sprintf("configured DNS name %s missing from certificate", want)
		}
	}
	for _, want := range spec.IPAddresses {
		ip := net.ParseIP(want)
		found := false
		for _, have := range inst.leaf.IPAddresses {
			if have.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("configured IP address %s missing from certificate", want)
		}
	}
	if spec.CommonName != "" && inst.leaf.Subject.CommonName != spec.CommonName {
		return fmt.Sprintf("common name changed (%q -> %q)", inst.leaf.Subject.CommonName, spec.CommonName)
	}
	if actual := keyTypeName(inst.key); actual != "" && actual != spec.KeyType {
		return fmt.Sprintf("key type changed (%s -> %s)", actual, spec.KeyType)
	}
	return ""
}

// keyTypeName maps a parsed private key back to its config name; empty for
// types the agent does not generate.
func keyTypeName(key crypto.Signer) string {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return "ecdsa-p256"
		case elliptic.P384():
			return "ecdsa-p384"
		}
	case *rsa.PrivateKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	}
	return ""
}
