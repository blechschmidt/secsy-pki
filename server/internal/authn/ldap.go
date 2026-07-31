package authn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	ldap "github.com/go-ldap/ldap/v3"
)

// This file adds LDAP / Active Directory operator authentication (Task 159)
// alongside the OIDC, mutual-TLS, WebAuthn, and API-token mechanisms. It resolves
// *who* a caller is by binding their username+password against a directory and
// translating the caller's directory-group memberships into RBAC roles; it holds
// no authorization logic of its own (that stays in internal/rbac).
//
// Two bind flows are supported, per RFC 4511:
//
//   - search-then-bind (BindDN set): connect and bind as a low-privilege service
//     account, search the user subtree for the entry matching the login name,
//     then bind as that entry's DN with the supplied password to verify it. The
//     service account is used again for the group search. This is the standard AD
//     pattern and the only way to accept a friendly login name (sAMAccountName)
//     rather than a full DN.
//   - simple-bind (BindDN empty): template the login name straight into a bind DN
//     (or userPrincipalName) and bind. No service account is required.
//
// Security invariants enforced here (defence in depth against the classic LDAP
// authentication pitfalls):
//
//   - TLS is mandatory. A bind — which carries the password — is never sent over
//     an unencrypted connection: ldaps:// uses implicit TLS, ldap:// must be
//     upgraded with StartTLS, and a StartTLS failure fails the login closed
//     rather than silently continuing in the clear. The only escape hatch is an
//     explicit InsecureAllowCleartext opt-in for isolated test rigs.
//   - Empty passwords are rejected before any bind. Many directories treat a bind
//     with a DN and an empty password as an *unauthenticated* bind that returns
//     success, which would turn "log in as alice with no password" into a
//     successful authentication. We refuse empty credentials outright.
//   - Filter and DN inputs are escaped (ldap.EscapeFilter / ldap.EscapeDN) before
//     interpolation, so a login name can never inject into the search filter or
//     bind DN.

// Directory-authentication sentinel errors. Callers map ErrLDAPInvalidCredentials
// to a generic 401 (never disclosing whether the user, the password, or the group
// mapping was at fault) and treat the rest as an infrastructure failure.
var (
	// ErrLDAPInvalidCredentials indicates the supplied username/password did not
	// authenticate (unknown user, wrong password, or empty credential).
	ErrLDAPInvalidCredentials = errors.New("authn: invalid directory credentials")
	// ErrLDAPUnavailable indicates the directory could not be reached or the
	// service-account bind/search failed — an operational problem, not a rejected
	// end-user credential.
	ErrLDAPUnavailable = errors.New("authn: directory unavailable")
)

// SecretSource lazily resolves a secret (the LDAP bind-service-account password)
// from a credential store. keyprovider.PinSource satisfies it structurally, so
// the bind password reuses the Task 111 pin_source machinery (env/file/Vault/AWS/
// Azure) with its fail-closed, never-logged semantics. Resolve is called at bind
// time; Describe returns a log-safe description that never includes the secret.
type SecretSource interface {
	Resolve(ctx context.Context) (string, error)
	Describe() string
}

// DirectoryIdentity is the verified identity produced by a successful directory
// bind: a stable Subject (the user's DN), the login Username, optional Email and
// display Name, and the directory Groups the user belongs to (group DNs or names).
// The LDAPPrincipalResolver maps it to a console principal with RBAC roles.
type DirectoryIdentity struct {
	Subject  string
	Username string
	Email    string
	Name     string
	Groups   []string
}

// LDAPPrincipalResolver maps a verified directory identity to a console principal,
// applying the directory-group -> RBAC role mapping (reusing the OIDC ClaimMapper)
// and unioning it with the configured rbac subject/email/group assignments. It is
// supplied by main.go, which owns the rbac layer and the mapper. Returning an
// error denies the login — e.g. the operator resolved to no role and the
// deployment forbids zero-role logins.
type LDAPPrincipalResolver func(id DirectoryIdentity) (*models.UserInfo, error)

// LDAPConfig is the resolved (config-decoupled) configuration for the directory
// authenticator. main.go maps the auth.ldap config block onto it, building the
// BindPassword SecretSource via the pin_source machinery and reading the TLS trust
// material.
type LDAPConfig struct {
	// URLs are the directory endpoints tried in order for failover, each
	// ldaps://host:636 (implicit TLS) or ldap://host:389 (cleartext, requires
	// StartTLS).
	URLs []string
	// StartTLS upgrades an ldap:// connection to TLS before binding. Required for
	// ldap:// URLs unless InsecureAllowCleartext is set.
	StartTLS bool
	// InsecureAllowCleartext permits binding over an unencrypted ldap:// connection.
	// Off by default; it ships credentials in the clear and exists only for tests.
	InsecureAllowCleartext bool

	// BindDN / BindPassword are the service-account credentials for search-then-bind.
	// Empty BindDN selects simple-bind (UserDNTemplate).
	BindDN       string
	BindPassword SecretSource

	// UserBaseDN / UserFilter locate a user entry in search-then-bind. UserFilter
	// must contain a %s placeholder for the escaped username.
	UserBaseDN string
	UserFilter string
	// UserDNTemplate is the bind-DN pattern for simple-bind, with %s for the
	// username (e.g. "uid=%s,ou=people,dc=example,dc=com" or "%s@example.com").
	UserDNTemplate string

	// GroupBaseDN / GroupFilter locate the caller's groups. GroupFilter may contain
	// %s (the user DN) and %u (the username). When empty, groups are read from the
	// GroupAttribute of the user entry instead.
	GroupBaseDN string
	GroupFilter string
	// GroupAttribute names the group identifier: the multi-valued attribute on the
	// user entry (GroupFilter empty; default "memberOf"), or the attribute read
	// from each matched group entry (GroupFilter set; default the entry DN).
	GroupAttribute string

	// UsernameAttribute / EmailAttribute / NameAttribute select user-entry
	// attributes recorded on the principal (defaults: the bound DN, "mail",
	// "displayName" then "cn").
	UsernameAttribute string
	EmailAttribute    string
	NameAttribute     string

	// Timeout bounds each connect+bind+search cycle (default 10s).
	Timeout time.Duration

	// TLS trust material for LDAPS / StartTLS.
	TLSCACertPEM          []byte // trust anchors; empty uses the system pool
	TLSServerName         string // certificate name / SNI override (needed for IP dials)
	TLSInsecureSkipVerify bool   // disables verification (fail-open; tests only)
	TLSMinVersion         uint16 // tls.VersionTLS12 (default) or tls.VersionTLS13
}

// LDAPAuthenticator authenticates a directory username+password and resolves it to
// a console principal. It is immutable after construction and safe for concurrent
// use; each Authenticate opens (and closes) its own short-lived connection, so no
// server-side session or connection state is shared between callers.
type LDAPAuthenticator struct {
	cfg     LDAPConfig
	tls     *tls.Config
	resolve LDAPPrincipalResolver
	timeout time.Duration
}

const defaultLDAPTimeout = 10 * time.Second

// NewLDAPAuthenticator validates the configuration, builds the TLS config, and
// returns the authenticator. It fails closed on a configuration that could ship
// credentials in the clear (an ldap:// URL with neither StartTLS nor an explicit
// cleartext opt-in) or that names no usable bind flow.
func NewLDAPAuthenticator(cfg LDAPConfig, resolve LDAPPrincipalResolver) (*LDAPAuthenticator, error) {
	if len(cfg.URLs) == 0 {
		return nil, errors.New("authn: ldap requires at least one url")
	}
	if resolve == nil {
		return nil, errors.New("authn: ldap requires a principal resolver")
	}
	for _, raw := range cfg.URLs {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("authn: ldap: invalid url %q: %w", raw, err)
		}
		switch u.Scheme {
		case "ldaps":
			// implicit TLS — always encrypted
		case "ldap":
			if !cfg.StartTLS && !cfg.InsecureAllowCleartext {
				return nil, fmt.Errorf("authn: ldap: %q would bind over cleartext; set start_tls or use ldaps:// (or, for tests only, insecure_allow_cleartext)", raw)
			}
		default:
			return nil, fmt.Errorf("authn: ldap: url %q must use scheme ldap:// or ldaps://", raw)
		}
	}
	// Exactly one bind flow must be usable.
	if cfg.BindDN != "" {
		if cfg.UserBaseDN == "" || cfg.UserFilter == "" {
			return nil, errors.New("authn: ldap: search-then-bind (bind_dn set) requires user_base_dn and user_filter")
		}
		if !strings.Contains(cfg.UserFilter, "%s") {
			return nil, errors.New("authn: ldap: user_filter must contain a %s placeholder for the username")
		}
	} else {
		if cfg.UserDNTemplate == "" {
			return nil, errors.New("authn: ldap: simple-bind (no bind_dn) requires user_dn_template")
		}
		if !strings.Contains(cfg.UserDNTemplate, "%s") {
			return nil, errors.New("authn: ldap: user_dn_template must contain a %s placeholder for the username")
		}
	}

	tlsConf := &tls.Config{
		ServerName:         cfg.TLSServerName,
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify, //nolint:gosec // opt-in, off by default; documented tests-only
		MinVersion:         cfg.TLSMinVersion,
	}
	if tlsConf.MinVersion == 0 {
		tlsConf.MinVersion = tls.VersionTLS12
	}
	if len(cfg.TLSCACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.TLSCACertPEM) {
			return nil, errors.New("authn: ldap: tls.ca_file contained no PEM certificates")
		}
		tlsConf.RootCAs = pool
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultLDAPTimeout
	}
	return &LDAPAuthenticator{cfg: cfg, tls: tlsConf, resolve: resolve, timeout: timeout}, nil
}

// Describe returns a short, log-safe description of the directory target and bind
// flow (no credentials), for diagnostics and the doctor check.
func (a *LDAPAuthenticator) Describe() string {
	flow := "simple-bind"
	if a.cfg.BindDN != "" {
		flow = "search-then-bind as " + a.cfg.BindDN
	}
	tlsMode := "ldaps"
	if a.cfg.StartTLS {
		tlsMode = "starttls"
	} else if a.cfg.InsecureAllowCleartext {
		tlsMode = "cleartext(insecure)"
	}
	return fmt.Sprintf("%s [%s, %s]", strings.Join(a.cfg.URLs, ","), flow, tlsMode)
}

// Authenticate binds the supplied directory credentials, resolves the caller's
// groups, and maps them to a console principal. It returns ErrLDAPInvalidCredentials
// for a rejected end-user credential and ErrLDAPUnavailable for an infrastructure
// failure; the resolver's error (e.g. "no role assigned") is returned verbatim so
// the login handler can surface it.
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*models.UserInfo, error) {
	// Reject empty credentials before any bind: an empty password can be silently
	// promoted to an unauthenticated (anonymous) bind that returns success.
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, ErrLDAPInvalidCredentials
	}

	conn, err := a.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLDAPUnavailable, err)
	}
	defer func() { _ = conn.Close() }()

	var (
		userDN string
		entry  *ldap.Entry
	)
	if a.cfg.BindDN != "" {
		userDN, entry, err = a.searchThenBind(ctx, conn, username, password)
	} else {
		userDN, entry, err = a.simpleBind(conn, username, password)
	}
	if err != nil {
		return nil, err
	}

	groups, err := a.resolveGroups(conn, userDN, username, entry)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLDAPUnavailable, err)
	}

	id := DirectoryIdentity{
		Subject:  userDN,
		Username: a.usernameFor(username, entry),
		Email:    entryAttr(entry, a.emailAttr()),
		Name:     a.displayName(entry),
		Groups:   groups,
	}
	return a.resolve(id)
}

// searchThenBind binds the service account, finds the user entry, then binds as the
// user to verify the password, and rebinds the service account for the group search.
func (a *LDAPAuthenticator) searchThenBind(ctx context.Context, conn *ldap.Conn, username, password string) (string, *ldap.Entry, error) {
	svcPassword, err := a.bindPassword(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("%w: resolving bind password: %v", ErrLDAPUnavailable, err)
	}
	if err := conn.Bind(a.cfg.BindDN, svcPassword); err != nil {
		return "", nil, fmt.Errorf("%w: service-account bind failed: %v", ErrLDAPUnavailable, err)
	}
	entry, err := a.findUser(conn, username)
	if err != nil {
		return "", nil, err
	}
	// Verify the end user's password by binding as their DN.
	if err := conn.Bind(entry.DN, password); err != nil {
		if isInvalidCredentials(err) {
			return "", nil, ErrLDAPInvalidCredentials
		}
		return "", nil, fmt.Errorf("%w: user bind failed: %v", ErrLDAPUnavailable, err)
	}
	// Rebind the service account so the (privileged) group search can read.
	if a.cfg.GroupFilter != "" {
		if err := conn.Bind(a.cfg.BindDN, svcPassword); err != nil {
			return "", nil, fmt.Errorf("%w: service-account rebind failed: %v", ErrLDAPUnavailable, err)
		}
	}
	return entry.DN, entry, nil
}

// simpleBind templates the username into a bind DN and binds as it directly.
func (a *LDAPAuthenticator) simpleBind(conn *ldap.Conn, username, password string) (string, *ldap.Entry, error) {
	userDN := strings.ReplaceAll(a.cfg.UserDNTemplate, "%s", ldap.EscapeDN(username))
	if err := conn.Bind(userDN, password); err != nil {
		if isInvalidCredentials(err) {
			return "", nil, ErrLDAPInvalidCredentials
		}
		return "", nil, fmt.Errorf("%w: bind failed: %v", ErrLDAPUnavailable, err)
	}
	// Best-effort: fetch the entry (as the now-authenticated user) to read email,
	// display name, and memberOf. A directory that forbids the self-read simply
	// yields a principal without those attributes.
	var entry *ldap.Entry
	if a.cfg.UserBaseDN != "" && a.cfg.UserFilter != "" {
		if e, err := a.findUser(conn, username); err == nil {
			entry = e
			userDN = e.DN
		}
	}
	return userDN, entry, nil
}

// findUser searches the user subtree for the single entry matching username.
func (a *LDAPAuthenticator) findUser(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	filter := strings.ReplaceAll(a.cfg.UserFilter, "%s", ldap.EscapeFilter(username))
	req := ldap.NewSearchRequest(
		a.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(a.timeout/time.Second), false, // size limit 2 to detect ambiguity
		filter, a.userAttributes(), nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("%w: user search failed: %v", ErrLDAPUnavailable, err)
	}
	switch len(res.Entries) {
	case 0:
		// Unknown user: fail closed with the same generic error as a wrong password.
		return nil, ErrLDAPInvalidCredentials
	case 1:
		return res.Entries[0], nil
	default:
		return nil, fmt.Errorf("%w: user filter matched %d entries (ambiguous)", ErrLDAPUnavailable, len(res.Entries))
	}
}

// resolveGroups returns the caller's directory groups, either by searching the
// group subtree (GroupFilter set) or by reading the group attribute of the user
// entry (memberOf).
func (a *LDAPAuthenticator) resolveGroups(conn *ldap.Conn, userDN, username string, entry *ldap.Entry) ([]string, error) {
	if a.cfg.GroupFilter != "" {
		filter := a.cfg.GroupFilter
		filter = strings.ReplaceAll(filter, "%s", ldap.EscapeFilter(userDN))
		filter = strings.ReplaceAll(filter, "%u", ldap.EscapeFilter(username))
		var attrs []string
		if a.cfg.GroupAttribute != "" {
			attrs = []string{a.cfg.GroupAttribute}
		}
		req := ldap.NewSearchRequest(
			a.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, int(a.timeout/time.Second), false, filter, attrs, nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			return nil, fmt.Errorf("group search failed: %w", err)
		}
		var groups []string
		for _, e := range res.Entries {
			if a.cfg.GroupAttribute == "" {
				groups = append(groups, e.DN)
				continue
			}
			groups = append(groups, e.GetAttributeValues(a.cfg.GroupAttribute)...)
		}
		return groups, nil
	}

	// memberOf on the user entry.
	attr := a.cfg.GroupAttribute
	if attr == "" {
		attr = "memberOf"
	}
	if entry != nil {
		return entry.GetAttributeValues(attr), nil
	}
	// simple-bind without a prior search: read the attribute from the entry's own
	// DN with a base-scoped search (best effort; no groups on failure).
	if userDN == "" {
		return nil, nil
	}
	req := ldap.NewSearchRequest(
		userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, int(a.timeout/time.Second), false, "(objectClass=*)", []string{attr}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		// Best-effort: a directory that forbids the self-read simply yields a
		// principal with no groups; it is not an authentication failure.
		return nil, nil //nolint:nilerr // intentional best-effort group read
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}
	return res.Entries[0].GetAttributeValues(attr), nil
}

// Probe verifies the directory is reachable, TLS is negotiated (fail-closed), and
// — for search-then-bind — the service-account credentials are valid. It performs
// no end-user bind. Used by the `secsy-ca doctor` auth.ldap check.
func (a *LDAPAuthenticator) Probe(ctx context.Context) error {
	conn, err := a.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if a.cfg.BindDN != "" {
		pw, err := a.bindPassword(ctx)
		if err != nil {
			return fmt.Errorf("resolving bind password: %w", err)
		}
		if err := conn.Bind(a.cfg.BindDN, pw); err != nil {
			return fmt.Errorf("service-account bind failed: %w", err)
		}
	}
	return nil
}

// connect dials the first reachable directory URL, enforcing TLS (implicit for
// ldaps://, StartTLS for ldap://), and fails closed on any TLS error.
func (a *LDAPAuthenticator) connect(ctx context.Context) (*ldap.Conn, error) {
	var lastErr error
	for _, raw := range a.cfg.URLs {
		conn, err := a.dialOne(ctx, strings.TrimSpace(raw))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no url configured")
	}
	return nil, lastErr
}

func (a *LDAPAuthenticator) dialOne(ctx context.Context, raw string) (*ldap.Conn, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid url %q: %w", raw, err)
	}
	isLDAPS := u.Scheme == "ldaps"
	if !isLDAPS && !a.cfg.StartTLS && !a.cfg.InsecureAllowCleartext {
		// Defence in depth: the constructor already rejects this, but never dial a
		// cleartext bind even if constructed by another path.
		return nil, fmt.Errorf("refusing cleartext bind to %q", raw)
	}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialerWithDeadline(ctx, a.timeout))}
	if isLDAPS {
		opts = append(opts, ldap.DialWithTLSConfig(a.tls))
	}
	conn, err := ldap.DialURL(raw, opts...)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(a.timeout)
	if !isLDAPS && a.cfg.StartTLS {
		if err := conn.StartTLS(a.tls); err != nil {
			_ = conn.Close()
			// Fail closed: never fall back to an unencrypted bind.
			return nil, fmt.Errorf("StartTLS failed (refusing cleartext bind): %w", err)
		}
	}
	return conn, nil
}

// bindPassword resolves the service-account password from its credential source.
func (a *LDAPAuthenticator) bindPassword(ctx context.Context) (string, error) {
	if a.cfg.BindPassword == nil {
		return "", nil
	}
	return a.cfg.BindPassword.Resolve(ctx)
}

// userAttributes is the set of user-entry attributes to request: the identity
// attributes plus memberOf (when group membership is read from the entry).
func (a *LDAPAuthenticator) userAttributes() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || seen[strings.ToLower(s)] {
			return
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	add(a.emailAttr())
	add(a.nameAttr())
	add("cn")
	if a.cfg.UsernameAttribute != "" {
		add(a.cfg.UsernameAttribute)
	}
	if a.cfg.GroupFilter == "" {
		g := a.cfg.GroupAttribute
		if g == "" {
			g = "memberOf"
		}
		add(g)
	}
	return out
}

func (a *LDAPAuthenticator) emailAttr() string {
	if a.cfg.EmailAttribute != "" {
		return a.cfg.EmailAttribute
	}
	return "mail"
}

func (a *LDAPAuthenticator) nameAttr() string {
	if a.cfg.NameAttribute != "" {
		return a.cfg.NameAttribute
	}
	return "displayName"
}

// displayName returns the entry's display name, preferring the configured name
// attribute (default displayName) and falling back to cn.
func (a *LDAPAuthenticator) displayName(entry *ldap.Entry) string {
	if entry == nil {
		return ""
	}
	if v := entry.GetAttributeValue(a.nameAttr()); v != "" {
		return v
	}
	return entry.GetAttributeValue("cn")
}

// usernameFor returns the login username, preferring the configured username
// attribute when present on the entry.
func (a *LDAPAuthenticator) usernameFor(username string, entry *ldap.Entry) string {
	if entry != nil && a.cfg.UsernameAttribute != "" {
		if v := entry.GetAttributeValue(a.cfg.UsernameAttribute); v != "" {
			return v
		}
	}
	return username
}

func entryAttr(entry *ldap.Entry, name string) string {
	if entry == nil || name == "" {
		return ""
	}
	return entry.GetAttributeValue(name)
}

// isInvalidCredentials reports whether an LDAP error is specifically a rejected
// credential (result code 49), distinguishing "wrong password" from an outage.
func isInvalidCredentials(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials)
}

// dialerWithDeadline builds a net.Dialer whose timeout is the smaller of the
// configured LDAP timeout and any deadline carried on ctx, so a caller's request
// deadline bounds the TCP connect too.
func dialerWithDeadline(ctx context.Context, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if dl, ok := ctx.Deadline(); ok {
		d.Deadline = dl
	}
	return d
}
