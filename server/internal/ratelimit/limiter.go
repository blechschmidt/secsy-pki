package ratelimit

import (
	"sync"
	"time"
)

// Tier names, used both as configuration keys and as the "tier" metric label.
const (
	TierGlobal     = "global"
	TierPerIP      = "per_ip"
	TierPerAccount = "per_account"
	TierPerTenant  = "per_tenant"
)

// Rate describes a single token-bucket configuration: a sustained rate in
// requests per second and a burst (bucket capacity). A non-positive Rate
// disables the tier entirely.
type Rate struct {
	Rate  float64
	Burst float64
}

// enabled reports whether the tier should be enforced.
func (r Rate) enabled() bool { return r.Rate > 0 && r.Burst > 0 }

// Decision is the outcome of an admission check.
type Decision struct {
	// Allowed is true when the request may proceed.
	Allowed bool
	// Tier names the tier that rejected the request (only when !Allowed).
	Tier string
	// RetryAfter estimates how long the caller should wait before retrying
	// (only meaningful when !Allowed).
	RetryAfter time.Duration
}

// tier binds a Rate to its per-key bucket store.
type tier struct {
	name    string
	buckets *keyedBuckets
}

// TieredLimiter enforces admission across the global, per-IP, and per-account
// tiers. A request is admitted only if it obtains a token from every enabled
// tier for which a key is supplied; admission is all-or-nothing, so tokens
// consumed from earlier tiers are refunded when a later tier rejects.
type TieredLimiter struct {
	now func() time.Time
	// mu guards the tier pointers, perTenantDefault, and the default bounds so
	// UpdateTiers (config hot-reload, Task 166) can atomically re-apply the tier
	// rates on a running limiter concurrently with Allow/Enabled. It is held only
	// briefly; the per-key bucket stores keep their own finer-grained locks, so
	// the admission hot path stays effectively lock-free under the read lock.
	mu      sync.RWMutex
	global  *tier
	perIP   *tier
	perAcct *tier
	// The per-tenant tier keeps its bucket store unconditionally (its default
	// rate may be disabled while individual tenants carry enabled overrides);
	// the effective rate is resolved per request in Allow.
	perTenantDefault Rate
	perTenantBuckets *keyedBuckets
	// maxKeys/idleTTL are the resolved default bounds new per-key stores are
	// built with; retained so UpdateTiers can create a tier that was disabled at
	// startup (nil) with the same bounds as the others.
	maxKeys int
	idleTTL time.Duration
}

// LimiterConfig configures a TieredLimiter.
type LimiterConfig struct {
	Global     Rate
	PerIP      Rate
	PerAccount Rate
	// PerTenant is the deployment-wide default rate for a single tenant's
	// public enrollment endpoints (Task 61). Individual tenants may carry their
	// own override, supplied per request via Keys.TenantLimit. The tier is
	// evaluated only for requests that resolve to a tenant.
	PerTenant Rate
	// MaxKeys bounds the number of distinct per-IP / per-account / per-tenant
	// buckets kept in memory before idle eviction kicks in.
	MaxKeys int
	// IdleTTL is how long a fully-replenished bucket may sit unused before it
	// becomes eligible for eviction.
	IdleTTL time.Duration
	// Now overrides the clock (tests only). Defaults to time.Now.
	Now func() time.Time
}

// NewTieredLimiter builds a limiter from cfg. Tiers with a non-positive rate or
// burst are inert (always admit).
func NewTieredLimiter(cfg LimiterConfig) *TieredLimiter {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	maxKeys := cfg.MaxKeys
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	idle := cfg.IdleTTL
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	mk := func(name string, r Rate) *tier {
		if !r.enabled() {
			return nil
		}
		return &tier{name: name, buckets: newKeyedBuckets(r.Rate, r.Burst, maxKeys, idle, now)}
	}
	return &TieredLimiter{
		now:              now,
		global:           mk(TierGlobal, cfg.Global),
		perIP:            mk(TierPerIP, cfg.PerIP),
		perAcct:          mk(TierPerAccount, cfg.PerAccount),
		perTenantDefault: cfg.PerTenant,
		perTenantBuckets: newKeyedBuckets(cfg.PerTenant.Rate, cfg.PerTenant.Burst, maxKeys, idle, now),
		maxKeys:          maxKeys,
		idleTTL:          idle,
	}
}

// UpdateTiers atomically re-applies the tier rates from cfg to a running
// limiter, for configuration hot-reload (Task 166). Existing per-key buckets are
// retuned in place (see tokenBucket.retune) so in-flight admission state is
// preserved: no request is dropped and no bucket is reset to full. A tier that
// transitions between disabled (nil) and enabled is torn down or created with
// the limiter's default bounds. The deployment-wide per-tenant default is
// swapped; individual tenant buckets self-heal via bucketForRate on their next
// request. Safe to call concurrently with Allow/Enabled.
//
// It cannot resurrect a limiter that was never built (rate_limit.enabled=false
// at startup leaves the middleware with a nil limiter); toggling rate limiting
// on or off as a whole still requires a restart.
func (l *TieredLimiter) UpdateTiers(cfg LimiterConfig) {
	maxKeys := cfg.MaxKeys
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	idle := cfg.IdleTTL
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxKeys, l.idleTTL = maxKeys, idle
	l.global = l.retuneTierLocked(l.global, TierGlobal, cfg.Global)
	l.perIP = l.retuneTierLocked(l.perIP, TierPerIP, cfg.PerIP)
	l.perAcct = l.retuneTierLocked(l.perAcct, TierPerAccount, cfg.PerAccount)
	l.perTenantDefault = cfg.PerTenant
	l.perTenantBuckets.setRate(cfg.PerTenant.Rate, cfg.PerTenant.Burst, maxKeys, idle, now)
}

// retuneTierLocked updates an existing tier's rate in place, creates one when a
// previously disabled (nil) tier becomes enabled, or returns nil to disable a
// tier whose new rate is non-positive. The caller holds l.mu.
func (l *TieredLimiter) retuneTierLocked(t *tier, name string, r Rate) *tier {
	if !r.enabled() {
		return nil // a disabled tier is inert (always admit)
	}
	if t == nil {
		return &tier{name: name, buckets: newKeyedBuckets(r.Rate, r.Burst, l.maxKeys, l.idleTTL, l.now)}
	}
	t.buckets.setRate(r.Rate, r.Burst, l.maxKeys, l.idleTTL, l.now())
	return t
}

// Keys identifies a request to the limiter. An empty IP or Account skips that
// tier for the request (e.g. an unauthenticated ACME newAccount has no account
// yet, so only the global and per-IP tiers apply).
type Keys struct {
	IP      string
	Account string
	// Tenant keys the per-tenant tier; empty skips it (requests that do not
	// resolve to a tenant, e.g. OCSP/CRL fetches by relying parties).
	Tenant string
	// TenantLimit optionally overrides the configured per-tenant default for
	// this tenant (an operator-set quota on the tenant record). nil inherits
	// the LimiterConfig.PerTenant rate. A non-nil disabled rate (zero) exempts
	// the tenant from the tier entirely.
	TenantLimit *Rate
}

// globalKey is the shared key for the single global bucket.
const globalKey = "_global_"

// Allow evaluates the request against every enabled, applicable tier. On
// rejection it names the offending tier and a Retry-After estimate, and refunds
// any tokens already taken from earlier tiers so admission is all-or-nothing.
func (l *TieredLimiter) Allow(keys Keys) Decision {
	// Hold the read lock for the whole admission check so UpdateTiers cannot swap
	// a tier pointer mid-evaluation. The per-key bucket stores keep their own
	// locks, so this permits unbounded concurrent admissions and only blocks
	// against the (rare) reload writer.
	l.mu.RLock()
	defer l.mu.RUnlock()

	now := l.now()

	// Evaluate tiers cheapest-scope-first: global, then per-IP, then
	// per-account. Order only affects which already-consumed tokens must be
	// refunded on rejection; correctness holds for any order.
	type held struct{ b *tokenBucket }
	var consumed []held

	check := func(t *tier, key string) (bool, Decision) {
		if t == nil || key == "" {
			return true, Decision{}
		}
		b := t.buckets.bucketFor(key, now)
		ok, ra := b.take(now)
		if !ok {
			for _, h := range consumed {
				h.b.refund(now)
			}
			return false, Decision{Allowed: false, Tier: t.name, RetryAfter: ra}
		}
		consumed = append(consumed, held{b})
		return true, Decision{}
	}

	if ok, d := check(l.global, globalKey); !ok {
		return d
	}
	if ok, d := check(l.perIP, keys.IP); !ok {
		return d
	}

	// Per-tenant tier: the effective rate is the tenant's own override when
	// supplied, else the deployment default; a disabled effective rate exempts
	// the request from this tier.
	if keys.Tenant != "" {
		eff := l.perTenantDefault
		if keys.TenantLimit != nil {
			eff = *keys.TenantLimit
		}
		if eff.enabled() {
			b := l.perTenantBuckets.bucketForRate(keys.Tenant, eff.Rate, eff.Burst, now)
			ok, ra := b.take(now)
			if !ok {
				for _, h := range consumed {
					h.b.refund(now)
				}
				return Decision{Allowed: false, Tier: TierPerTenant, RetryAfter: ra}
			}
			consumed = append(consumed, held{b})
		}
	}

	if ok, d := check(l.perAcct, keys.Account); !ok {
		return d
	}
	return Decision{Allowed: true}
}

// Enabled reports whether any statically configured tier is active. When false
// the limiter admits every request and callers may skip it — except that a
// request carrying an explicit per-tenant override (Keys.TenantLimit) is still
// enforced by Allow, so middleware should also consult that override when
// deciding whether to consult the limiter.
func (l *TieredLimiter) Enabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.global != nil || l.perIP != nil || l.perAcct != nil || l.perTenantDefault.enabled()
}
