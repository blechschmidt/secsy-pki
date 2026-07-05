// Package rbac defines coarse-grained, organization-wide roles for PKI
// operations and the capabilities each role grants.
//
// It complements — rather than replaces — the existing per-CA permission model
// (SIGN_CERTIFICATE / MANAGE_PERMISSIONS / CONFIGURE_CA on individual CAs).
// Roles are assigned centrally in configuration and answer the question "what
// class of user is this?" across the whole system:
//
//   - admin   — full control, equivalent to the built-in root user.
//   - issuer  — may issue/renew/revoke certificates on any CA (still subject to
//     that CA's restriction sets) and read logs, but may not create or
//     delete CAs, manage access control, or administer the HSM.
//   - signer  — may sign release artifacts with the configured code-signing
//     keys (and read logs), but holds no certificate-issuance or
//     administrative capability. Kept separate from issuer so a CI
//     pipeline credential that signs builds cannot mint certificates,
//     and vice versa (separation of duties for code signing).
//   - auditor — read-only: may read the audit, access, and event logs and list
//     objects, but may not perform or authorize any signing or
//     administrative operation.
//   - approver — may approve or reject four-eyes / maker-checker approval
//     requests for high-risk operations (Task 81), and read the request
//     queue. Deliberately separate from the roles that REQUEST those
//     operations (admin/issuer): a maker cannot also be the checker, and
//     the gate additionally denies self-approval by identity, so genuine
//     dual control needs a distinct approver principal.
//
// A subject may hold several roles; its effective capabilities are the union.
package rbac

import "strings"

// Role is an organization-wide role name.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleIssuer   Role = "issuer"
	RoleSigner   Role = "signer"
	RoleAuditor  Role = "auditor"
	RoleApprover Role = "approver"
)

// AllRoles is the set of recognized roles, used for validation.
var AllRoles = []Role{RoleAdmin, RoleIssuer, RoleSigner, RoleAuditor, RoleApprover}

// ValidRole reports whether r is a recognized role.
func ValidRole(r Role) bool {
	for _, k := range AllRoles {
		if k == r {
			return true
		}
	}
	return false
}

// Action is a capability that a role may or may not grant.
type Action string

const (
	// ActionIssue covers signing, issuing, renewing, and revoking certificates.
	ActionIssue Action = "cert:issue"
	// ActionReadAudit covers reading the audit, access, and event logs.
	ActionReadAudit Action = "audit:read"
	// ActionManageCA covers creating and deleting CAs and initializing roots /
	// intermediates.
	ActionManageCA Action = "ca:manage"
	// ActionConfigureCA covers editing profiles, restriction sets, and defaults.
	ActionConfigureCA Action = "ca:configure"
	// ActionManageRBAC covers managing groups and per-CA permission grants.
	ActionManageRBAC Action = "rbac:manage"
	// ActionManageHSM covers HSM provisioning, attestation, and factory reset.
	ActionManageHSM Action = "hsm:manage"
	// ActionEncrypt / ActionDecrypt cover the secret envelope endpoints.
	ActionEncrypt Action = "secret:encrypt"
	ActionDecrypt Action = "secret:decrypt"
	// ActionDataKey covers minting a fresh data key (returned in the clear plus
	// KEK-wrapped) for client-side envelope encryption (Task 138). It is a
	// creation/encryption-class capability, granted alongside secret:encrypt: a
	// caller that can encrypt can already obtain KEK-protected ciphertext, and a
	// data key is recoverable only through secret:decrypt.
	ActionDataKey Action = "secret:datakey"
	// ActionHMAC covers generating and verifying a keyed HMAC over caller data
	// with the family's HSM/KEK-derived MAC key (Task 138). Generate and verify
	// share one capability: both operate the same MAC key and neither exposes it.
	ActionHMAC Action = "secret:hmac"
	// ActionRandom covers drawing CSPRNG bytes from the crypto service, sourced
	// from the HSM RNG when available (Task 138).
	ActionRandom Action = "secret:random"
	// ActionManageEscrow covers administering the key-escrow configuration
	// (inspecting recovery agents, provisioning agent keys). It is an
	// administrative capability held by admins only.
	ActionManageEscrow Action = "secret:escrow"
	// ActionRecover covers performing an escrow recovery ceremony — the
	// break-glass path that reconstructs a data key from a quorum of recovery
	// agents. It is deliberately admin-only and separate from secret:decrypt: the
	// day-to-day decrypt capability must not by itself authorize break-glass
	// recovery. The cryptographic M-of-N quorum enforces dual control on top of
	// this capability.
	ActionRecover Action = "secret:recover"
	// ActionRotateKEK covers the secret-layer KEK rotation lifecycle: rotating
	// a family to a new HSM wrapping key, re-wrapping stored secrets onto it,
	// retiring superseded versions, and reading the rotation status. It is
	// key management, deliberately admin-only and separate from the day-to-day
	// secret:encrypt/secret:decrypt capabilities: a credential that encrypts
	// application secrets must not be able to rotate or retire the keys that
	// protect every other tenant's ciphertext.
	ActionRotateKEK Action = "secret:rotate"
	// ActionSignArtifact covers producing CMS detached signatures over release
	// artifacts with the configured code-signing keys (/api/sign). It is granted
	// to the dedicated signer role (and admins), NOT to issuers: a credential
	// that signs builds must not also mint certificates.
	ActionSignArtifact Action = "artifact:sign"
	// ActionReadApproval covers viewing the four-eyes approval queue (Task 81):
	// pending requests and their decision history. Granted to approvers (who act
	// on them) and auditors (read-only oversight).
	ActionReadApproval Action = "approval:read"
	// ActionApprove covers approving or rejecting a four-eyes approval request.
	// Granted to the dedicated approver role (and admins). It is deliberately
	// NOT implied by the capability to REQUEST the guarded operation: separating
	// maker from checker is the whole point of the control, and the gate further
	// denies self-approval by identity.
	ActionApprove Action = "approval:approve"
	// ActionManageTokens covers minting, listing, and revoking native scoped API
	// tokens / service accounts (Task 86). It is an administrative capability held
	// by admins only (no non-admin role grants it), because a token can carry any
	// role: allowing a lesser role to mint tokens would let it escalate its own
	// privilege. Tenant admins may manage tokens WITHIN their tenant; platform
	// (cross-tenant) tokens require a platform administrator.
	ActionManageTokens Action = "token:manage"
	// ActionManageWebhooks covers creating, listing, testing, and deleting durable
	// outbound webhook subscriptions (Task 116). Like token:manage it is an
	// administrative capability held by admins only (no non-admin role grants it):
	// a subscription exfiltrates certificate lifecycle events — including subject
	// names and serials — to an operator-chosen external URL, so registering one is
	// a data-egress decision as sensitive as token minting. Tenant admins may
	// manage subscriptions WITHIN their tenant; a platform (all-tenant) subscription
	// requires a platform administrator.
	ActionManageWebhooks Action = "webhook:manage"
	// ActionProfile covers capturing runtime profiles from the opt-in
	// net/http/pprof endpoints (CPU, heap, goroutine, mutex, block) (Task 115).
	// It is an administrative capability held by admins only (no non-admin role
	// grants it): a heap or goroutine profile is a raw dump of process memory and
	// stacks that can contain in-flight secrets, CSRs, and session material, so
	// the ability to pull one is as sensitive as HSM administration. The pprof
	// endpoints are off by default and, when mounted on the API, additionally
	// require an authenticated principal — this capability is the authorization
	// half of that gate. It is deliberately platform-scoped (no tenant grants it):
	// a profile spans the whole process, not one tenant's data.
	ActionProfile Action = "server:profile"
)

// roleActions is the static capability grant per role. admin is handled
// separately as an allow-all superuser so new actions are covered by default.
var roleActions = map[Role]map[Action]bool{
	RoleIssuer: {
		ActionIssue:     true,
		ActionReadAudit: true, // issuers can review their own operations
		ActionEncrypt:   true,
		ActionDecrypt:   true,
		// The stateless crypto-service capabilities travel with the day-to-day
		// encrypt/decrypt grant: the issuer role is the crypto-service consumer.
		ActionDataKey: true,
		ActionHMAC:    true,
		ActionRandom:  true,
	},
	RoleSigner: {
		ActionSignArtifact: true,
		ActionReadAudit:    true, // signers can review their own operations
	},
	RoleAuditor: {
		ActionReadAudit:    true,
		ActionReadApproval: true, // read-only oversight of the approval queue
	},
	RoleApprover: {
		ActionReadApproval: true,
		ActionApprove:      true,
		ActionReadAudit:    true, // approvers review the trail behind a request
	},
}

// RoleGrants returns whether a single role grants an action.
func RoleGrants(role Role, action Action) bool {
	if role == RoleAdmin {
		return true // admin is an allow-all superuser
	}
	return roleActions[role][action]
}

// Can reports whether any of the held roles grants the action.
func Can(roles []Role, action Action) bool {
	for _, r := range roles {
		if RoleGrants(r, action) {
			return true
		}
	}
	return false
}

// HasRole reports whether the set contains a specific role.
func HasRole(roles []Role, want Role) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// IsPrivilegedRole reports whether a role grants any capability beyond read-only
// oversight. It is derived from the capability model rather than a hardcoded
// list, so it stays correct as roles evolve: admin is always privileged; a role
// is privileged if it grants any action other than the read-only audit:read /
// approval:read capabilities. Used to decide when minting a token requires
// four-eyes approval (Task 86) — a token granting a privileged role, or platform
// (cross-tenant) scope, is a meaningful privilege escalation and can be gated.
func IsPrivilegedRole(role Role) bool {
	if role == RoleAdmin {
		return true
	}
	for action := range roleActions[role] {
		switch action {
		case ActionReadAudit, ActionReadApproval:
			// read-only oversight, not privileged on its own
		default:
			return true
		}
	}
	return false
}

// AnyPrivilegedRole reports whether the set contains at least one privileged
// role (see IsPrivilegedRole).
func AnyPrivilegedRole(roles []Role) bool {
	for _, r := range roles {
		if IsPrivilegedRole(r) {
			return true
		}
	}
	return false
}

// Assignments maps subjects and groups to roles. It is built from central
// configuration and is immutable after construction, so lookups are safe for
// concurrent use.
type Assignments struct {
	bySubject map[string][]Role
	byGroup   map[string][]Role
}

// NewAssignments builds an Assignments index from subject->roles and
// group->roles maps (typically decoded from config). Unknown role names are
// ignored so a typo cannot silently grant broad access.
func NewAssignments(bySubject, byGroup map[string][]Role) *Assignments {
	a := &Assignments{
		bySubject: make(map[string][]Role),
		byGroup:   make(map[string][]Role),
	}
	filter := func(in map[string][]Role, out map[string][]Role) {
		for k, roles := range in {
			var valid []Role
			for _, r := range roles {
				if ValidRole(r) {
					valid = append(valid, r)
				}
			}
			if len(valid) > 0 {
				out[k] = valid
			}
		}
	}
	filter(bySubject, a.bySubject)
	filter(byGroup, a.byGroup)
	return a
}

// RolesFor returns the deduplicated set of roles a subject holds, considering
// both its direct subject assignment and its group memberships.
func (a *Assignments) RolesFor(subject string, groupIDs []string) []Role {
	if a == nil {
		return nil
	}
	seen := make(map[Role]bool)
	var out []Role
	add := func(roles []Role) {
		for _, r := range roles {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	add(a.bySubject[subject])
	for _, g := range groupIDs {
		add(a.byGroup[g])
	}
	return out
}

// Empty reports whether no assignments are configured at all.
func (a *Assignments) Empty() bool {
	return a == nil || (len(a.bySubject) == 0 && len(a.byGroup) == 0)
}

// TenantAssignments layers tenant-scoped role assignments over the platform-wide
// (cross-tenant) assignments. A principal's effective capability in a tenant is
// the union of:
//
//   - its PLATFORM roles (from the embedded platform Assignments), which apply in
//     every tenant — reserved for platform operators; and
//   - its roles WITHIN that specific tenant (from the tenant's own Assignments).
//
// A principal that holds a role only in tenant A therefore has no capability in
// tenant B: the mechanism that enforces cross-tenant isolation at the RBAC layer.
type TenantAssignments struct {
	platform *Assignments
	byTenant map[string]*Assignments
}

// NewTenantAssignments builds the index from the platform assignments and a
// per-tenant map of assignments (typically decoded from config).
func NewTenantAssignments(platform *Assignments, byTenant map[string]*Assignments) *TenantAssignments {
	m := make(map[string]*Assignments, len(byTenant))
	for k, v := range byTenant {
		if v != nil {
			m[k] = v
		}
	}
	return &TenantAssignments{platform: platform, byTenant: m}
}

// Platform returns the cross-tenant assignments (may be nil).
func (ta *TenantAssignments) Platform() *Assignments {
	if ta == nil {
		return nil
	}
	return ta.platform
}

// PlatformRolesFor returns the platform-wide roles a subject holds.
func (ta *TenantAssignments) PlatformRolesFor(subject, email string, emailVerified bool, groupIDs []string) []Role {
	if ta == nil {
		return nil
	}
	return rolesFor(ta.platform, subject, email, emailVerified, groupIDs)
}

// TenantRolesFor returns the roles a subject holds within a specific tenant
// (excluding platform roles, which the caller combines separately).
func (ta *TenantAssignments) TenantRolesFor(tenantID, subject, email string, emailVerified bool, groupIDs []string) []Role {
	if ta == nil {
		return nil
	}
	return rolesFor(ta.byTenant[tenantID], subject, email, emailVerified, groupIDs)
}

// Tenants returns the tenant IDs that have any role assignment configured.
func (ta *TenantAssignments) Tenants() []string {
	if ta == nil {
		return nil
	}
	out := make([]string, 0, len(ta.byTenant))
	for t := range ta.byTenant {
		out = append(out, t)
	}
	return out
}

// rolesFor resolves subject + verified-email + group roles against one
// Assignments index. Email-keyed roles are honored only for a verified email.
func rolesFor(a *Assignments, subject, email string, emailVerified bool, groupIDs []string) []Role {
	if a == nil {
		return nil
	}
	roles := a.RolesFor(subject, groupIDs)
	if email != "" && emailVerified {
		roles = append(roles, a.RolesFor(email, nil)...)
	}
	// Dedup preserving order.
	seen := make(map[Role]bool, len(roles))
	out := roles[:0]
	for _, r := range roles {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// JoinRoles renders roles as a stable comma-separated string for logging.
func JoinRoles(roles []Role) string {
	parts := make([]string, len(roles))
	for i, r := range roles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ",")
}
