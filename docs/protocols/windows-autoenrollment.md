# Windows autoenrollment: MS-XCEP policy + MS-WSTEP enrollment (CEP/CES)

secsy-pki can drive **GPO-based certificate autoenrollment for Active-Directory-joined
Windows machines** by exposing the two Microsoft enrollment web services that
Windows already knows how to talk to:

- **MS-XCEP** ([\[MS-XCEP\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/08ec4475-32c2-457d-8c27-5a176660a210)) —
  the **Certificate Enrollment Policy** service ("CEP"). A `GetPolicies` SOAP
  request returns the **enrollment policy**: the templates available to the
  client (mapped from secsy-pki [issuance profiles](../ca/overview.md)),
  the issuing CA and its certificate, and the URL of the companion enrollment
  service.
- **MS-WSTEP** ([\[MS-WSTEP\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/4766a85d-0d18-4fa1-a51f-e5cb98b752ea)) —
  the **Certificate Enrollment Web Service** ("CES"). A WS-Trust
  `RequestSecurityToken` (RST, `Issue`) SOAP request carries a **PKCS#10** in a
  `BinarySecurityToken`; the server issues the certificate through the shared
  **HSM-backed** [`ca.Manager`](../ca/overview.md) and returns it as a
  certs-only PKCS#7 in a `RequestSecurityTokenResponse` (RSTR).

Like the other enrollment protocols ([SCEP/EST/CMP](scep-est.md), [ACME](acme.md)),
every certificate is signed by an HSM-backed CA — the **CA key never leaves its
provider** — issuance runs through the same profile gates, tenant scoping and
revocation store, and every request is written to the
[tamper-evident audit log](../security/rbac-and-audit.md). The services mount **outside** the
OIDC auth middleware and authenticate with their own transport credentials.

- [1. Kerberos-free authentication](#1-kerberos-free-authentication)
- [2. Configuration](#2-configuration)
- [3. Profile → template mapping](#3-profile--template-mapping)
- [4. Active Directory GPO wiring](#4-active-directory-gpo-wiring)
- [5. The SOAP exchange](#5-the-soap-exchange)
- [6. Tenancy, RBAC, audit & rate limiting](#6-tenancy-rbac-audit--rate-limiting)
- [7. Security notes & limitations](#7-security-notes--limitations)
- [8. Endpoint & reference](#8-endpoint--reference)

## 1. Kerberos-free authentication

In a real AD forest, Windows authenticates to CEP/CES with the machine's
**Kerberos** ticket (or NTLM). secsy-pki is not a domain controller and does not
join the forest, so it supports two **Kerberos-free** client-authentication
mechanisms that thread the existing RBAC/tenant model:

| Mechanism | How the client presents it | Authorization |
|---|---|---|
| **Native API token** ([Task 86](../security/authentication.md)) | `Authorization: Token secsy_pat_…` (or `Bearer secsy_pat_…`) | must hold the **`cert:issue`** capability in the CA's tenant |
| **Operator mutual-TLS** | a client certificate verified against the operator client-CA pool ([`auth.mtls`](../security/authentication.md)) | resolved to a principal; must hold **`cert:issue`** in the CA's tenant |
| **Machine-renewal mutual-TLS** | a client certificate this CA **previously issued** (opt-in) | authorized by prior issuance — no role required |

The `GetPolicies` (CEP) endpoint requires only a **valid credential** (any of the
above); the issuing capability is enforced at **enrollment** (CES) time. All three
paths fail **closed**: a request with no recognized credential gets `401`, and an
authenticated caller lacking `cert:issue` gets `403`.

The advertised **`clientAuthentication`** value in the policy reflects what the
deployment accepts — certificate (`8`) when mTLS is configured, otherwise
username/password (`4`) for the token path.

## 2. Configuration

Windows autoenrollment is **off by default**. Enable it with an `mswstep:` block.
The issuing CA may be any key type (RSA/ECDSA/Ed25519) — unlike SCEP there is no
RSA requirement.

```yaml
mswstep:
  enabled: true
  ca_label: "Corp Issuing CA"          # issuing CA (use ca_label OR ca_id)
  policy_path: /mswstep/policy          # MS-XCEP GetPolicies (CEP) endpoint
  enroll_path: /mswstep/enroll          # MS-WSTEP RST (CES) endpoint
  default_profile: client               # profile when a request names no template

  # Advertised in the policy so the client knows where to enroll (CES URL).
  # This is the URL the AD GPO uses as the enrollment (CES) server; it must be
  # the externally reachable HTTPS URL of enroll_path.
  ces_endpoint: "https://pki.corp.example/mswstep/enroll"

  policy_friendly_name: "Corp Certificate Enrollment Policy"
  next_update_hours: 8                   # policy refresh hint
  template_oid_arc: "1.3.6.1.4.1.311.21.8"   # base arc for synthesized template OIDs

  # Accept a client certificate this CA previously issued as the machine-renewal
  # credential (mutual TLS), the analogue of est.allow_tls_client_reenroll.
  allow_client_cert_issued_by_ca: true

  # Profiles offered as Windows templates. Omit to advertise a single template
  # derived from default_profile.
  templates:
    - profile: server                   # secsy-pki issuance profile (required)
      name: CorpWebServer               # template common name shown to the client
      oid: "1.3.6.1.4.1.311.21.8.1.2.3" # template OID (synthesized if omitted)
      minimal_key_length: 2048
      auto_enroll: true                 # advertise GPO autoenrollment (default true)
    - profile: client
      name: CorpMachine
```

**Client authentication is wired from the existing auth config**: native API
tokens are always accepted, and when [`auth.mtls`](../security/authentication.md) is enabled
the same client-CA pool and bindings authenticate an operator certificate. Enable
`allow_client_cert_issued_by_ca` to additionally accept a certificate this CA
issued (the renewal path).

Because CES issues on the HSM, the endpoints are metered by the
[rate-limit + HSM-concurrency guard](../security/rate-limiting.md) exactly like the other
enrollment protocols.

## 3. Profile → template mapping

Windows selects a **certificate template** by name; secsy-pki maps each configured
template to an **issuance profile**. The `GetPolicies` response advertises, per
template:

- the **template common name** (`attributes.commonName`) and a **template OID**
  (in the `oIDs` collection, group `9` = certificate template) — synthesized under
  `template_oid_arc` when not set explicitly;
- **key specs** — `privateKeyAttributes.minimalKeyLength`, `policySchema`;
- **validity / renewal** — `certificateValidity.validityPeriodSeconds` (from the
  mapped profile's default validity) and a `renewalPeriodSeconds` overlap window;
- **enrollment flags** — `permission.enroll` / `permission.autoEnroll`.

At enrollment time the requested template is resolved back to its profile, in
priority order:

1. an explicit `<ContextItem Name="CertificateTemplate">` in the RST
   `AdditionalContext`;
2. the Microsoft **V2** template extension in the CSR (OID `1.3.6.1.4.1.311.21.7`,
   carrying the template OID);
3. the Microsoft **V1** template-name extension in the CSR (OID
   `1.3.6.1.4.1.311.20.2`, a BMPString name);
4. otherwise the configured **`default_profile`**.

The resolved profile drives the full issuance path — key usages, EKUs, validity,
[lint](../issuance/certlint.md), [CAA](../issuance/caa.md), [name constraints](../issuance/name-constraints.md),
[UPN SANs](../certificates/smartcard-logon.md) — so a Windows machine template and a secsy-pki
profile stay in lockstep.

## 4. Active Directory GPO wiring

On the AD side, autoenrollment is driven by Group Policy. Because secsy-pki uses
Kerberos-free authentication, point the policy at the CEP URL and configure the
matching credential.

1. **Publish the CA chain as trusted.** Distribute the issuing CA (and its root)
   to the domain via *Computer Configuration → Policies → Windows Settings →
   Security Settings → Public Key Policies → Trusted Root Certification
   Authorities* (and *Intermediate* as needed). The CA certificate is also
   advertised in the `GetPolicies` response.

2. **Register the enrollment policy (CEP).** In a GPO under *Computer
   Configuration → Policies → Windows Settings → Security Settings → Public Key
   Policies → Certificate Services Client – Certificate Enrollment Policy*, add a
   new policy server with the **CEP URL** (`https://…/mswstep/policy`) and an
   **authentication type** matching the deployment:
   - *Client certificate* when using mutual TLS (operator or machine-renewal);
   - *Username/password* when using a native API token (supply the token as the
     password).

   The CES (enrollment) URL is advertised **inside** the policy response
   (`ces_endpoint`), so it does not need to be entered separately.

3. **Turn on autoenrollment.** Enable *Certificate Services Client –
   Auto-Enrollment* (*Configure* → *Enroll certificates automatically*, with
   *Renew expired…* and *Update certificates that use certificate templates*
   checked). Windows will call `GetPolicies`, discover the templates whose
   `autoEnroll` flag is set, and enroll against CES.

4. **Match template names.** The template `name` you advertise must match what the
   client requests. For pure GPO autoenrollment the client stamps the template
   into the CSR automatically; the mapping in §3 resolves it back to the profile.

> **Note.** Full Kerberos/AD-integrated authentication and the AD certificate-
> template database are **not** emulated. secsy-pki advertises its own templates
> (mapped from profiles) and authenticates with tokens or client certificates.
> This is ideal for AD-joined machines enrolling from a non-AD PKI, lab/test
> harnesses, and non-domain Windows clients configured with a CEP URL.

## 5. The SOAP exchange

Both services speak **SOAP 1.2** (`application/soap+xml`) with WS-Addressing.

**MS-XCEP `GetPolicies`** — request action
`…/enrollmentpolicy/IPolicy/GetPolicies`, response
`…/IPolicy/GetPoliciesResponse`. The response body is a `GetPoliciesResponse`
(namespace `http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy`)
carrying `response` (policy + templates), `cAs` (issuing CA + CES URIs), and
`oIDs` (template OIDs).

**MS-WSTEP `RequestSecurityToken`** — request action
`…/enrollment/RST/wstep`, response `…/enrollment/RSTRC/wstep`:

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wsse="…wss-wssecurity-secext-1.0.xsd"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:MessageID>urn:uuid:…</a:MessageID>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsse:BinarySecurityToken
          ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
          EncodingType="…#base64binary">BASE64(PKCS#10)</wsse:BinarySecurityToken>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>
```

The RSTR returns the issued certificate (and its CA chain) as a base64 certs-only
PKCS#7 in `RequestSecurityTokenResponse/RequestedSecurityToken/BinarySecurityToken`
(`ValueType …#PKCS7`), echoing the request `MessageID` in `RelatesTo`. Malformed
requests and issuance failures return a **SOAP 1.2 Fault**; authentication
failures return **HTTP 401** before any SOAP processing.

## 6. Tenancy, RBAC, audit & rate limiting

- **Tenancy.** The services bind to one issuing CA and therefore one **tenant**.
  A suspended tenant's enrollment is refused (`403`), and a token whose roles live
  in a **different** tenant cannot enroll here (cross-tenant isolation), enforced
  before any issuance work and again by the fail-closed gate inside `ca.Manager`.
- **RBAC.** Enrollment requires the **`cert:issue`** capability (platform issuer,
  a tenant issuer role, or a per-CA `SIGN_CERTIFICATE` grant); the machine-renewal
  client-cert path is authorized by prior issuance instead.
- **Audit.** Every request writes a chained audit event: `mswstep.getpolicies`
  and `mswstep.enroll`, with the authenticated actor (the token subject or the
  mTLS certificate subject) and the tenant.
- **Metrics.** `secsy_mswstep_getpolicies_total{result}` and
  `secsy_mswstep_requests_total{result}` (`success`/`denied`/`error`), plus the
  shared rate-limit / HSM-guard metrics under the `mswstep_policy` and
  `mswstep_enroll` classes.

## 7. Security notes & limitations

- **CA key stays in the HSM.** Issuance goes through `ca.Manager`; only the public
  certificate ever leaves the server.
- **Serve over HTTPS.** CEP/CES carry credentials (a token, or an mTLS client
  cert) and issue certificates — always terminate TLS in front of these endpoints.
  For the mutual-TLS paths the server must request the client certificate
  (`ClientAuth: RequestClientCert`), which the standard secsy-pki TLS listener
  already does for the enrollment surfaces.
- **Fail-closed everywhere.** No credential → `401`; authenticated but lacking
  `cert:issue` → `403`; suspended/cross-tenant → `403`; malformed PKCS#10 → SOAP
  Sender fault (`400`).
- **Not a domain controller.** Kerberos/NTLM SSPI, the AD template database, and
  key archival (KRA) are out of scope; templates are mapped from secsy-pki
  profiles and clients authenticate Kerberos-free.

## 8. Endpoint & reference

| Method | Path (default) | Auth | Description |
|---|---|---|---|
| `POST` | `/mswstep/policy` | token / mTLS | MS-XCEP `GetPolicies` (CEP) — advertise templates + CA |
| `POST` | `/mswstep/enroll` | token / mTLS (+`cert:issue`) | MS-WSTEP `RequestSecurityToken` (CES) — issue from PKCS#10 |

Related: [SCEP/EST/CMP enrollment](scep-est.md) ·
[Smartcard-logon & PKINIT](../certificates/smartcard-logon.md) ·
[Native API tokens](../security/authentication.md) · [Operator authentication](../security/authentication.md) ·
[Certificate profiles](../ca/overview.md) · [Rate limiting](../security/rate-limiting.md)
