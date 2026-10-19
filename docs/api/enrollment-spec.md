# Enrollment & Grant Specification + Threat Model

**Status:** Reviewed v1.0 — M0 gate complete (reviewed 19 October 2026)
**Version:** 1 · 19 October 2026
**Applies to:** relay protocol version 1
**License:** MIT · Copyright (c) 2026 Tim Laing

This document specifies the highest-risk part of the relay: how a device
becomes authorized to receive pushes for a tenant, and how that authorization
is represented, renewed, and revoked. It was written and reviewed before any
code was written, per the requirements in
`ios-opencode-client/docs/notifications.md` ("specify and review the
enrollment challenge/attestation mechanism… Do not claim a fully secure,
stateless enrollment protocol has already been verified"). Review outcomes are
recorded in §6; the four open questions from the draft are now decisions.

Everything here is protocol version 1. Breaking changes require a new version
segment in grant encoding and endpoint paths.

---

## 1. Roles and trust model

| Party              | Holds                                        | Trusted for                                                      |
| ------------------ | -------------------------------------------- | ---------------------------------------------------------------- |
| **Relay operator** | `.p8` keys, grant-issuer signing key, config | Correct key custody; not trusted with sealed content (by design) |
| **Tenant backend** | Tenant token, tenant Ed25519 keypair, grants | Nothing beyond its own users' devices                            |
| **iOS app**        | Device token, App Attest key, user consent   | Being the sole consent authority; genuine-build proof            |
| **Apple**          | APNs, App Attest roots                       | Platform root of trust (unavoidable)                             |

Authorization for one push requires **three independent proofs**:

1. **Genuine app** — App Attest (the relay will only bind devices running a
   real, operator-configured build).
2. **Destination possession** — an APNs challenge push the device must echo
   (the relay will only bind a token the requester actually holds).
3. **User consent** — the enrollment runs inside the app after an explicit
   consent step (the relay binds only what a human approved).

No single proof suffices: attestation alone doesn't prove token ownership;
possession alone could be a cloned client; neither implies user intent.

### Trust limitation stated honestly

The **operator of an instance holds the `.p8` and grant-issuer key**, but that
alone does **not** let them push to enrolled devices: APNs requires a
destination **device token**, and the relay never stores one — tokens exist
only transiently in `enroll/begin` and `/v1/push` requests, and only their
SHA-256 hashes are persisted (challenge rows, grants). The stock relay
therefore cannot push to a device it has never been asked to reach, and cannot
re-reach one whose token it saw only in passing once that request is over.

The residual risk is a **modified build**: an operator willing to alter the
code could log tokens as they transit and mint grants for them. That is the
real trust boundary — tenants trust that the operator runs the published
software, not a doctored variant. Mitigations: sealed content keeps tenant
message detail blind even to a logging operator; no-storage limits knowledge
to what actively transits; self-hosting removes the third party entirely.
Optional future hardening (not v1): published image digests or reproducible
builds so tenants can verify the relay runs unmodified code. This belongs in
`docs/privacy.md` verbatim.

---

## 2. Enrollment flow

```
 iOS app (genuine, user consented)              Relay                    APNs
 ─────────────────────────────────────────────────┼────────────────────────┼───
 1. app: user taps "Enable remote alerts for <backend>"
 2. app ── POST /v1/enroll/begin ───────────────►│
      { app, tenantId, destinationToken }        │
      (tenantId + tenant pubkey come from the    │  validate app exists & kind
       paired backend; destinationToken is the   │  allowed; token format ok;
       fresh APNs token)                         │  mint serverChallenge (1-use,
                                                 │  10-min TTL)
 3.                                                 ├─ silent APNs push ────► device
      challenge payload: { challengeId, nonce } ◄───┘  (content-available)
 4. app: DCAppAttestService.prepare(serverChallenge)
     app: attestKey(keyId, SHA256(serverChallenge))          → attestation
     app: fetchAssertion(keyId, SHA256(nonce ‖ serverChallenge)) → assertion
 5. app ── POST /v1/enroll/finish ─────────────►│
      { challengeId, attestation, assertion,    │  verify challengeId+nonce
        tenantId, tenantPubkey, kinds }         │  verify attestation chain +
                                                 │  app ID + environment
                                                 │  verify assertion signature
                                                 │  issue grant (Ed25519)
 6. grant returned to app
 7. app ── grant over paired TLS connection ──► tenant backend
                                                 (app↔backend channel; relay
                                                  never contacts the backend)
```

**Foreground requirement:** step 3 is a silent (background) push, which iOS
throttles. Enrollment therefore requires the app to be **active in the
foreground** — which it is, because the user just tapped consent. The contract
must state this; silent push is used as a possession _challenge_, not as a
reliable wake-up mechanism.

### 2.1 `POST /v1/enroll/begin` (unauthenticated, rate-limited per IP)

```json
{
  "app": "opencode-client",
  "tenantId": "opencode.example.com",
  "destinationToken": "<APNs device or ActivityKit token>"
}
```

- `app` must exist and permit the requested operation; `destinationToken`
  format-validated (length/charset), never stored — only used to send the
  challenge and hashed into the grant.
- Response: `{ "challengeId": "<uuid>", "serverChallenge": "<32B b64u>",
"expiresAt": <epoch+600> }`.
- If the challenge push fails at APNs (`410`, invalid token) → `400
invalidDestination`; nothing is stored.
- State: one row (`challengeId`, app, tenantId, token **hash**, nonce,
  serverChallenge, expiry). Deleted on use or expiry. This is the only
  enrollment state; it is separate from the stateless delivery path.

### 2.2 `POST /v1/enroll/finish` (unauthenticated, rate-limited per IP)

```json
{
  "challengeId": "<uuid>",
  "attestation": "<base64 Apple attestation>",
  "assertion": "<base64 Apple assertion>",
  "tenantId": "opencode.example.com",
  "tenantPubkey": "<Ed25519 public key, base64>",
  "kinds": ["alert", "liveActivity"],
  "ttl": 21600
}
```

- `ttl` optional — requested grant lifetime in seconds; clamped to the App's
  `grant_ttl` bounds (§2.5). Omitted → App default.

**Response** (grant + machine-readable consent receipt):

```json
{
  "grant": "v1.<claims>.<sig>",
  "consent": {
    "tenant": "opencode.example.com",
    "app": "opencode-client",
    "appDisplayName": "OpenCode Client",
    "kinds": ["alert", "liveActivity"],
    "boundAt": 1792230900,
    "expiresAt": 1792252500,
    "environment": "production"
  }
}
```

The `consent` object is informational JSON describing exactly what was bound
and for how long — returned so the **app can decide what to do with it**
(display in settings, log locally, discard). The relay stores none of it; it
is derived from the grant that was just issued.

Verification, all mandatory:

1. `challengeId` exists, unexpired, unused; request `tenantId` matches.
2. The pushed `nonce` must be bound into the assertion's signed data
   (`SHA256(nonce ‖ serverChallenge)`) — possession proof, single-use.
3. **App Attest**: verify the attestation's x5c chain to Apple's App Attestation
   Root, the attested **app ID equals the configured bundle ID** for `app`,
   and the **environment matches** `attest_environment` (development vs
   production attestations differ). Extract the credential public key.
4. Verify the assertion signature with that credential key over
   `SHA256(nonce ‖ serverChallenge)`.
5. `kinds` ⊆ the App's configured allowed kinds.

Failure at any step → `400`, challenge burned (single-use even on failure
after nonce consumption). Success → challenge row deleted, grant issued.

_Implementation note (M4): follow Apple's current App Attest verification
document for exact CBOR field handling and root-cert distribution; this spec
fixes the security properties (chain, app ID, environment, single-use
serverChallenge, nonce binding), not Apple's wire encoding. Validate against a
physical device before enabling for any production App._

### 2.3 Grant format

```
grant = "v1." ‖ b64u(claims) ‖ "." ‖ b64u(Ed25519_sig(claims))
claims = canonical JSON (sorted keys, no whitespace):
{ "jti":   "<uuid>",                     // denylist handle; rotates on renewal
  "iss":   "<grant-issuer key id>",      // single issuer key in v1
  "tok":   "sha256:…",                  // SHA-256 of destination token
  "ten":   "opencode.example.com",       // tenant ID
  "tpk":   "<tenant pubkey, base64>",    // binding — see note
  "app":   "opencode-client",
  "kinds": ["alert", "background", "liveActivity"],
  "env":   "production",                 // from app config, not the caller
  "iat":   1792230900,
  "exp":   1792252500,                   // iat + ttl (§2.5)
  "ttl":   21600 }                       // effective grant TTL, seconds
```

- **Topic and APNs environment are never caller-supplied** — resolved from
  `app` via operator config.
- Verification is database-free: signature → issuer key, `exp`, denylist,
  `tok` vs the token presented in the push request, `ten`/`tpk` vs the
  authenticated tenant, `kinds` vs the requested kind.
- `tpk` binds the grant to the tenant's signing key: presenting another
  tenant's keypair fails request authentication regardless of the grant.
- A **stolen grant alone cannot push**: `/v1/push` also requires the tenant
  token and a valid Ed25519 request signature. Grants are bearer-ish only in
  combination with tenant credentials.
- Transport: returned in the `enroll/finish` response; the app delivers it to
  its backend over the existing paired TLS connection. The relay never
  contacts the backend and stores nothing about the grant beyond the `jti`
  denylist entry created on revocation.

### 2.4 `POST /v1/enroll/renew` (tenant-authenticated, signed)

- Requires tenant token + canonical Ed25519 request signature (token-bound,
  as `/v1/push`) and the current grant.
- Verified like `/v1/push` plus: grant unexpired, `jti` not denylisted, tenant
  matches. New grant issued with **new `jti`**, `iat = now`, `exp = now + ttl`,
  where `ttl` is the requested value clamped to App bounds (§2.5; omitted →
  App default); all other claims unchanged. Old grant lapses naturally at its
  `exp` (no backdating, no lifetime extension beyond one TTL per renewal).
- Renewal is authenticated possession of tenant credentials — **no** new App
  Attest or challenge push: the destination binding was proven at enrollment
  and the token hash cannot change without re-enrollment.

### 2.5 Grant lifetime — App-bounded, tenant-configured

Per-App config sets the **bounds**; the tenant chooses its own TTL **within
them** (requested at `enroll/finish` and again at each `renew`; omitted → App
default):

```yaml
grant_ttl: { min: 900, max: 86400, default: 21600 } # seconds; min 15m, max 24h
```

- Operator keeps the abuse ceiling (`max`) and floor (`min`); a tenant that
  wants 10-minute grants for tight revocation semantics or 24-hour grants for
  an unattended home server can have either, and anything between.
- Requested TTL outside bounds → clamped to the nearest bound (documented
  behavior, not an error — avoids brittle clients).
- Renewal may change the TTL (within the same bounds) — the new `exp` is
  `now + requested_ttl`.
- Rationale unchanged: short enough that a leaked grant (including `tpk`) is
  inert quickly, long enough that a backend outage of reasonable length doesn't
  mass-invalidate deliveries. Renewal is cheap; schedule at ≤ ½ TTL.

### 2.6 Revocation

| Path                                      | Trigger                       | Effect                                                                         |
| ----------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------ |
| `POST /v1/revoke` (tenant-authed, signed) | Backend unsubscribes a device | `jti` denylisted until its natural `exp` (bounded storage)                     |
| Operator CLI `relay denylist add`         | Abuse response                | `jti`, `tenant`, or `token-hash` denylisted; tenant-wide kill supported        |
| 30-day non-use deletion                   | Inactivity                    | Tenant + all grants' `jti`s implicitly dead (tenant token no longer validates) |
| Re-enrollment                             | New token / new consent       | Old grant simply lapses; new grant issued for new binding                      |

Denylist entries carry the grant's `exp` as their natural purge time — no
unbounded growth. There is no per-grant _stateful_ check on the delivery path:
verification reads the denylist (small, hot) and nothing else.

---

## 3. Threat model

### 3.1 Assets

`.p8` keys · grant-issuer key · tenant tokens + keypairs · device tokens ·
notification content (plaintext fields + sealed blob) · user attention
(banners are a resource) · Apple account reputation (APNs abuse → throttling
or key revocation).

### 3.2 Adversaries and mitigations

| #   | Attack                                                              | Mitigation                                                                                                                                                                                                                                                           |
| --- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1  | Replay a captured push request                                      | TLS + single-use nonce + token-bound canonical signature (PLAN §3.2)                                                                                                                                                                                                 |
| A2  | Splice a stolen signature onto another tenant's token               | Token digest inside the signed message; verification binds them                                                                                                                                                                                                      |
| A3  | Enroll a victim's device token (unsolicited pushes)                 | Challenge push must be echoed — attacker never receives it; App Attest requires a genuine app; user consent required in-app                                                                                                                                          |
| A4  | Cloned/fake client enrolling devices                                | App Attest chain + exact bundle-ID + environment check; no attestation → no grant                                                                                                                                                                                    |
| A5  | Use a stolen grant to push                                          | Grant alone is insufficient (tenant token + signature also required); short TTL; `jti` denylist; token-hash binding stops token substitution                                                                                                                         |
| A6  | Stolen tenant token without keypair                                 | Cannot sign requests → `401`; `relay tenant reissue` rotates                                                                                                                                                                                                         |
| A7  | Stolen tenant token **and** keypair                                 | Full tenant impersonation until detected — bounded by per-key quotas, per-token caps, denylist, 30-day expiry; incident path is `relay denylist add --tenant`                                                                                                        |
| A8  | SSRF / internal probing via `callback`                              | `PublicHTTPS` guard: HTTPS/443 only, resolve-once, global-address-only, TLS pinned                                                                                                                                                                                   |
| A9  | Quota exhaustion / spam one device                                  | Per-App burst/daily quota, per-token blind-index cap, nginx per-IP `limit_req`, 16 KB body cap                                                                                                                                                                       |
| A10 | Push arbitrary topic / environment / APNs host                      | Never caller-supplied; resolved from `app` in operator config                                                                                                                                                                                                        |
| A11 | Phishing banners under a trusted app's name                         | Structured capped fields only (no raw APNs payload), operator-revocable, documented content policy                                                                                                                                                                   |
| A12 | Device token or content leak from relay storage                     | No device table, no payload persistence, no content in logs; tokens hashed where stored at all                                                                                                                                                                       |
| A13 | Malicious relay operator (modified build logging tokens in transit) | Tokens never stored by the stock relay — nothing to steal at rest; sealed blob keeps detail blind; honest disclosure (§1); self-hosting removes the party; optional future: verifiable image digests                                                                 |
| A14 | Enrollment-endpoint DoS                                             | Per-IP rate limits on `enroll/*`, challenge TTL, single-use rows                                                                                                                                                                                                     |
| A15 | Grant-issuer key compromise                                         | **Single issuer key in v1** (no key-set shipping). Rotation runbook (M8): install new key, restart — all outstanding grants (≤ max 24h TTL) lapse early; tenants re-enroll. `iss` claim present from v1 so a key set can be added later without a grant-format break |

### 3.3 Out of scope (v1)

- Compromise of the device itself or its keychain.
- Apple/platform failures (APNs outage, App Attest outage) — surfaced as
  `retryable` / enrollment failure, never silently.
- Exactly-once delivery (APNs does not provide it; tenants own retry policy).
- Push-to-start Live Activities (deferred).

---

## 4. Known limitations (published in docs, not hidden here)

1. **Operator trust** — §1: holding the keys is not sufficient — device tokens
   are never stored, so an operator can only target devices whose tokens
   actively transit a **modified** relay. Trust reduces to "the operator runs
   the published software"; sealed content, no-storage, and self-hosting are
   the mitigations.
2. **Silent-push challenge** — enrollment needs the app foregrounded; a
   throttled challenge push fails the flow cleanly (retry `begin`).
3. **No instant revocation of a grant without its `jti` known** — revocation
   is by `jti` (known to the holder and, on revoke, to the relay); a grant
   leaked without any handle lives only to its short `exp`.
4. **App reinstall / token rotation** — new token ⇒ `tok` mismatch ⇒
   `invalidDestination` ⇒ re-enrollment. Correct but requires app-side
   detection and a user-visible retry.
5. **Attestation replay across devices** — an assertion is bound to one
   device's credential key and one `serverChallenge`; cross-device replay
   fails signature verification. Server-challenge freshness bounds the window.

---

## 5. Test requirements (M4 gate, distilled from PLAN §13)

- Enrollment rejects: bad attestation chain, wrong app ID, wrong environment,
  reused `challengeId`, wrong/expired nonce, kinds not allowed, unknown tenant.
- Forged/expired/cross-destination/cross-tenant grants rejected; `tok`
  substitution rejected; denylist effective within one request.
- Renewal: unexpired grant only, `jti` rotates, old grant lapses at `exp`.
- Physical-device end-to-end: consent → enroll → alert, Live Activity
  update/end, and sandbox/production separation verified.
- No secrets, tokens, nonces, or attestation blobs in logs.

---

## 6. Review decisions (recorded 19 Oct 2026)

The four M0 open questions are resolved:

1. **Grant TTL — tenant-configurable within App bounds.** Per-App config sets
   `grant_ttl: {min, max, default}` (bounds 15 min–24 h); the tenant requests a
   `ttl` at `enroll/finish` and may change it at each `renew`. Out-of-bounds is
   clamped, not rejected. Operator keeps the abuse ceiling. (§2.2, §2.4, §2.5)
2. **Consent receipt — yes, as JSON, app's discretion.** `enroll/finish`
   returns a machine-readable `consent` object (tenant, app, kinds, boundAt,
   expiresAt, environment). The relay stores none of it; the app decides what
   to do (display, log, discard). (§2.2)
3. **Issuer keys — do not ship key support.** v1 uses a **single** grant-issuer
   key. Rotation is an M8 runbook: install new key, restart, outstanding grants
   (≤ max TTL) lapse early, tenants re-enroll. The `iss` claim is present from
   v1 so a key set can be introduced later without a grant-format break. (A15)
4. **ActivityKit tokens — same enrollment flow.** `kind: liveActivity` with the
   activity push token as `destinationToken`; no separate channel. The
   destination-token hash makes alert and liveActivity bindings naturally
   disjoint, and App Attest / challenge-push / consent apply identically. (§2.1)
