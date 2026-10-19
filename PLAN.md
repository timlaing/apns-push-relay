# apns-push-relay — Implementation Plan

**Status:** agreed, ready to implement
**Date:** 19 October 2026
**License:** MIT · Copyright (c) 2026 Tim Laing

A generic, self-hostable APNs push relay. A tenant's backend (an OpenCode push
plugin, a Family VPN dashboard, anything) sends one signed HTTPS request; the
relay resolves the correct APNs key from a destination-bound grant and forwards
the push. The operator holds the Apple `.p8` keys; tenants never see them.

Two audiences:

- **Hosted instance** (`push.example.org`) — Tim operates it; tenants register,
  bring their apps' device tokens, and push.
- **Self-hosted** — anyone `docker compose up`s the same image with their own
  keys, apps and tenants. Whoever deploys it is the operator.

The code has no knowledge of any specific app. Tim's two apps (OpenCode Client,
Family VPN) are simply the first `apps:` entries in his instance's config.

---

## 1. Locked decisions

| Area         | Decision                                                                                                                                            |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Apps         | Generic **App** entity; operator-onboarded only (admin CLI). Third parties never upload keys.                                                       |
| Auth         | Tenant token + destination-bound grants + Ed25519 request signing                                                                                   |
| Registration | `{id, app, callback?}` scoped per App (key); `callback_required` is **per key**, not per instance; token always relay-generated, scoped to that App |
| Domains      | Instance domain(s) are **config parameters** — no hostname hardcoded anywhere; self-hosters set their own                                           |
| Non-use      | Tenant hard-deleted after **30 days** without an authenticated request                                                                              |
| Push kinds   | alert + background + Live Activity (`update`/`end`; push-to-start deferred)                                                                         |
| Payloads     | Generic structured fields, all length-capped, + **sealed relay-blind blob**                                                                         |
| Stack        | **nginx + FastAPI (uvicorn)**; Python CLI `relay` for config/monitoring                                                                             |
| APNs keys    | **App-specific `.p8`, multi-key, `team_id` per key**                                                                                                |
| Deployment   | **Docker Compose** (nginx + certbot + relay); GHCR images on tags                                                                                   |
| TLS          | **certbot** webroot, automatic renewal + nginx reload                                                                                               |
| Docs         | **GitHub Pages + MkDocs Material** — landing page + multi-page docs                                                                                 |
| Scope        | Family VPN stays on its Worker relay for now; **OpenCode push plugin is built**; iOS app gets a full APNs track                                     |

Reference material: contract model adapted from
`~/Repos/ios-opencode-client/docs/notifications.md` (proposed `POST /v1/push`,
result vocabulary, stateless-grant caveats); reusable code from
`~/Repos/iOS-VPN` (the `family-vpn` clone): `APNsSender` (`family_vpn/app.py`),
`relay_protocol.py`, `relay_service.py` quota/replay store and `PublicHTTPS`
SSRF guard.

---

## 2. Architecture

```
Tenant backend (OpenCode plugin / HA dashboard / anything)
   │  register({id, app, callback?}) ─► tenant token (per App, once)
   │  Ed25519-signed POST /v1/push + tenant token + grant   (per push)
   ▼
Internet ──► nginx (TLS via certbot, limit_req per-IP, 16k body cap)
                │ internal network only — /admin never proxied
                ▼
             uvicorn ── FastAPI
                ├ /v1/push, /v1/enroll/*, /v1/revoke   (tenant-authenticated)
                ├ /health, /metrics                     (minimal / redacted)
                ├ /admin/*                              (internal + admin token)
                └ APNs sender: async httpx HTTP/2,
                   per-kid ES256 JWT cache, key registry
                ▼
             APNs ──► iPhone
```

**State held:** tenant registry, grant `jti` denylist, quotas, ~10-minute
nonces, keys at rest. **No device table, no payload log, no retry queue** —
tenants own retries.

### Domain model

```
App    operator data: topics, .p8 + key_id + team_id (per key), environments,
       allowed kinds, live-activity flag, App Attest config, caps, quota,
       registration.callback_required
Tenant unique ID; one relay-generated token **per App** (register per App);
       last_seen (shared across the tenant's registrations)
Grant  Ed25519-signed: token-hash, tenant pubkey, app_id, kinds, env,
       expiry, jti
```

Topic resolution: `grant.app_id → App.topic → App.key`. The caller never names
a topic, APNs host, or header.

---

## 3. API contract

### 3.1 Register — `POST /v1/register`

Registration is **scoped to one App (key)**: `callback_required` and quota are
per-key settings, so the caller names the App it is registering for. A tenant
using several Apps registers once per App (one token per App) — this keeps
per-key quotas and policy enforcement trivially correct.

```
{ "id": "opencode.example.com",            // required — the tenant's unique ID
  "app": "opencode-client",                // required — App id from the operator
  "callback": "https://…/register-hook" }  // required iff that App's
                                          // registration.callback_required

201 { "tenant", "app", "token", "quota", "registered_at", "expires_at" }
400 callback_required | callback_verification_failed | invalid_callback | unknown_app
409 id_exists                             # per (id, app) pair — first claim wins
429 rate_limited
```

Per-App config `apps[].registration.callback_required: bool = False`:

| `callback_required` | `callback` sent | Result                                              |
| ------------------- | --------------- | --------------------------------------------------- |
| `False`             | no              | registers immediately (NAT-friendly default)        |
| `False`             | yes             | verified inline; failure → 400, **no** registration |
| `True`              | no              | `400 callback_required`                             |
| `True`              | yes             | verified inline; 201 only on success                |

Callback verification (trust-on-first-claim plus optional proof):

- Relay POSTs `{id, kind: "registration", nonce}` to the callback; the endpoint
  must echo the nonce within ~10s.
- **SSRF guard** (family-vpn `PublicHTTPS`, `relay_service.py:20-27`):
  HTTPS-only, port 443, no credentials/query/fragment, DNS-resolve-once,
  reject any non-global IP, pin TLS to the original host.
- Callback host must equal the claimed `id` or a subdomain of it.
- Attempts rate-limited per source IP; proof is one-shot, **nothing stored**.
- Mode flips are grandfathered: `False → True` affects only new registrations.

Identity notes:

- The `id` is a **label, not an authenticator** — the token is. First claim wins
  (409); spoofing a label grants zero authority. Operator CLI can list/revoke.
- Token is **always relay-generated** (`tnt_` + `token_urlsafe(32)`), stored as
  a **SHA-256 digest** (unique-indexed, constant-time compare). Deviates from
  family-vpn's Fernet encryption deliberately: no outbound callbacks need the
  plaintext, so a leaked `relay.db` yields no usable tokens.
- Lost token before expiry → wait out 30 days or `relay tenant reissue <id>`.

### 3.2 Push — `POST /v1/push`

Adapted from `notifications.md` §"Proposed REST interface":

```
{ "grant": "<signed destination-bound authorization>",
  "destinationToken": "<device or ActivityKit token>",
  "kind": "alert" | "background" | "liveActivity",
  "eventId": "<stable event identity>",
  "expiresAt": 1792231200,
  "content": {
    "alert":     { "title", "subtitle", "body", "category", "thread", "sound" },
    "background":{ "payload": <≤512B structured> },
    "liveActivity": { "event": "update"|"end", "timestamp", "state", "staleDate", "dismissalDate" },
    "sealed": "<opaque base64 — relay passes blind>"
  } }
```

- All text fields length-capped per App config; unknown fields rejected
  (Pydantic `extra="forbid"`).
- **Sealed field**: content encrypted app↔backend at pairing time; the relay
  never sees it. Alert text still transits Apple — documented honestly.
- Request signing: Ed25519 over the canonical message below, binding the
  tenant token into the signature. ±5-min skew; 10-min single-use nonce replay
  window (family-vpn `relay_protocol.py` shape, signature not MAC).

  ```
  message = SHA256HEX(tenant_token) \n method \n path \n timestamp \n
            nonce \n SHA256HEX(body)
  signature = Ed25519(tenant_private_key, message)
  ```

  The `Authorization: Bearer tnt_…` header stays as-is; the token is digested
  into the message, never raw (mirrors the `body-sha256` treatment, keeping the
  canonical string safe to log). Digest precedes `body_sha256`; canonical
  ordering is versioned in `docs/api/enrollment-spec.md`. Applies to every
  tenant-authenticated signed route (`/v1/push`, `/v1/enroll/renew`);
  registration is unauthenticated; admin API unchanged (internal + admin token).
  **Divergence from family-vpn**: their signature covers
  method/path/timestamp/nonce/body only — we add the token digest so a leaked
  signature is useless with any other or substituted token, and the token
  verified is the token charged for quota.

- Response: `accepted` (with `apns-id`) / `invalidDestination` / `retryable` /
  `rejected`. `410 Unregistered` → `invalidDestination`; Apple `429` →
  `retryable` + backpressure; `apns-id` passthrough. APNs acceptance is **not**
  proof of display.

### 3.3 Enrollment — app/device side (spec-first, see M0)

```
enroll/begin   → challenge + silent APNs challenge push (token possession)
enroll/finish  → push nonce + App Attest assertion (genuine build) → grant
enroll/renew   → authenticated re-sign while jti live
POST /v1/revoke → denylist
```

Grant binds token **hash**, tenant pubkey, `app_id`, kinds, env, expiry. The
grant's `app_id` must match the App the presented token was issued for.
Delivered app→backend over the existing paired connection. Short-lived grants
plus the denylist close the stateless-revocation gap flagged in
`notifications.md`.

### 3.4 Non-use expiry

- Any successfully authenticated request updates `last_seen`; registration does
  not. `last_seen` is shared across a tenant's per-App registrations.
- `last_seen` older than **30 days** → tenant hard-deleted **with all its
  per-App registrations**, cascading nonces, quota counters, pending grant
  rows. Lazy prune on request path **+** hourly sweep (family-vpn
  `RelayStore.prune()` pattern).
- After deletion: `401 unknown_tenant`; re-register.
- Security property: pushes need a live tenant token, so **deletion ≈ instant
  revocation** — a stolen grant dies with its tenant.

---

## 4. Config & keys

Keys are **app-specific `.p8`** — Team ID/Key ID are **not** in the file, so
they are configured per key:

```yaml
server:
  api_domain:
    api.push.example.org # THIS instance's API domain — set by the
    # operator; no hostname is hardcoded
  docs_domain: push.example.org # GitHub Pages domain (CNAME in mkdocs)
  public_scheme: https

apps:
  - id: opencode-client
    topic: uk.co.laingcorp.opencode-client.OpenCodeRemote
    team_id: 4C8FWEBR8F # required, per key — multi-team supported
    key_file: keys/opencode/AuthKey_XXXXXXXXXX.p8
    key_id: XXXXXXXXXX # derived from AuthKey_<ID>.p8 filename if omitted
    environments: [sandbox, production]
    kinds: [alert, background, liveActivity]
    live_activity: true
    attest_environment: production
    registration:
      callback_required: False # per key — strictness is an App-level policy
    caps: { title: 64, subtitle: 64, body: 200, sealed: 1024, category: 32 }
    quota:
      { burst_per_min: 10, daily: 5000 } # per key — no global default;
      # every App states its own
```

- Boot validation: P-256 parse, filename↔key_id consistency, team_id format,
  per-key JWT pre-sign. Misconfiguration fails at startup, not first push.
- Key rotation: replace file + `key_id` + restart container; per-app, no
  downtime for others.
- Onboarding an app = drop `.p8` in `keys/`, add `apps:` entry, reload. No code
  changes, ever.
- Sandbox + production use the **same** key (environment is the APNs host).
- `server.*` domains are read for the JSON pointer at `/`, TLS probe in
  `relay status`, and docs links; `mkdocs.yml` CNAME and certbot `-d` take the
  same values at deploy time. Self-hosters substitute their own.
- **Prerequisites complete (19 Oct 2026):** app-specific `.p8` for the OpenCode
  Client bundle ID created and held by the operator; App Attest capability
  enabled in team `4C8FWEBR8F`. (Family VPN's key predates this plan.)

Layout:

```
/etc/apns-relay/
├── config.yaml        # as above
├── keys/              # 0600, read-only mount — never in git or env
└── .env               # 0600 — master secret, admin token
```

---

## 5. CLI — `relay`

Thin client over an admin API (internal network + admin token); offline modes
need no server. Same validator powers `doctor` and container pre-flight.

```
relay doctor                   # offline: config + keys + JWT pre-sign
relay app add|list|rotate|suspend
relay tenant list|revoke|reissue|verify
relay denylist add|list
relay status                   # health, quota burn, APNs result counts,
                               # TLS expiry (public probe), per-App policies
relay logs --errors --since 1h # redacted: outcome/latency/error codes only
relay metrics                  # scrape-friendly snapshot
```

---

## 6. Deployment (Docker Compose)

```yaml
services:
  nginx: # nginx:1.27-alpine, ports 80/443, config:ro, site:ro,
    # volumes: certbot-www, certbot-conf:ro
    # entrypoint: self-signed placeholder if no live cert;
    #             mtime-watch fullchain.pem → nginx -s reload
  certbot: # certbot/certbot, webroot issue-if-missing, renew loop every 12h
  relay: # build ., uvicorn, NO published ports,
    # config.yaml:ro + keys:ro + relay-data volume
    # entrypoint pre-flight: relay doctor
volumes: [certbot-www, certbot-conf, relay-data]
```

- **TLS lifecycle:** port 80 serves ACME webroot + 301 redirect; nginx starts
  with a self-signed placeholder for the seconds before first issuance; certbot
  issues/renews (90-day LE certs, renew ≤30 days out); mtime watcher reloads
  nginx — certbot and nginx stay decoupled (no docker socket).
- M1 tests issuance + `certbot renew --dry-run` against LE **staging** first.
- **nginx**: TLS1.2/1.3, `client_max_body_size 16k`, `limit_req_zone` per-IP,
  `server_tokens off`, `location /v1/ → relay:8000`. **`/admin` is not proxied.**
- `location /` on the API host returns a JSON pointer to the docs domain.
- State (`relay.db`, SQLite WAL) on the named volume — the only backup target.
  Keys/config live on the host, outside the container lifecycle.
- CI builds the image on tags, publishes to **GHCR** (family-vpn pattern).
- Domains are **operator-supplied parameters** (example values shown
  throughout): `server.docs_domain` → GitHub Pages (mkdocs CNAME),
  `server.api_domain` → VPS (nginx `server_name` + certbot `-d`). Self-hosters
  substitute their own.

---

## 7. Docs & landing (GitHub Pages + MkDocs Material)

```
mkdocs.yml                 # nav, theme, CNAME: <server.docs_domain>
docs/
├── index.md               # landing: one-line what/why, 4-box diagram,
│                          # trust panel, limits/status, three get-started paths
├── how-it-works.md        # architecture, request flow, three push kinds
├── getting-started.md     # tenant path; both register variants
├── self-hosting.md        # compose up, config.yaml, relay CLI, certbot
├── api/
│   ├── openapi.md         # embedded openapi.yaml (MkDocs plugin / Redoc)
│   └── enrollment-spec.md # M0 output — reviewed v1.0, published
├── privacy.md             # what the relay never sees; 30-day deletion
├── limits-and-abuse.md    # quotas, policy, contact, abuse reporting
└── status.md              # M8: generated snapshot / uptime badge
.github/workflows/docs.yml # push to main → build → deploy Pages
```

MkDocs Material: Python toolchain, MIT, multi-page + search, no second
language in the repo. Docs ship in **M1**, not deferred.

Footer everywhere: MIT, source link, contact, abuse-report address.

---

## 8. iOS app work (ios-opencode-client — parallel track)

Currently **zero APNs code**; independent of the dormant Local Push Connectivity
entitlement. Needed:

- Push Notifications capability; `registerForRemoteNotifications` + token
  lifecycle (rotation, failure, restoration).
- Enrollment consent UI + App Attest; silent challenge-push handling.
- Tap-routing to host/project/session; background handling.
- ActivityKit: update/end, activity-token rotation reporting, stale model.
- Relay settings integrated with existing `NotificationClassifier` preferences.
- Token delivery to the tenant's own backend over the paired connection.

---

## 9. OpenCode push plugin (new scope, separate repo)

- Receives device tokens over the paired connection (like Family VPN's app
  already does).
- Registers with the relay (`{id, app, callback?}`), holds the tenant token.
- Observes native events, normalizes states, filters by subscription, dedupes.
- Durable outbox before transmit; coalesce/expire/retry with backoff; delivery
  failure never blocks an OpenCode task; single delivery-owner lease.
- Obtains/renews grants (enroll flow) and calls `POST /v1/push`.
- No agent tools, no general remote-command channel.

---

## 10. Privacy

- Relay sees, in plaintext: device token (in transit only, never stored),
  category, short capped text. Nothing else.
- Sealed field passes blind; key agreement is app↔backend.
- Tenant tokens stored as digests; state = tenants, quotas, nonces, denylist.
- Logs: outcome / latency / error-code only; token-scoped counters keyed by
  HMAC blind index; short retention; published schedule in `privacy.md`.
- Abandoned deployments leave **zero residue within 30 days**.

## 11. Abuse prevention

Per-tenant burst + daily quota; per-token blind-index rate cap; payload/field
caps; short grant expiry + denylist for instant kill; 30-day expiry; optional
`callback_required` vetting; nginx per-IP `limit_req` + 16k body cap; redacted
metrics with alerting on 429/invalid spikes; published abuse policy + contact;
`relay tenant revoke` as the kill switch.

---

## 12. Build sequence

| #      | Milestone                                                                                                                                                                                                   | Gate                                                                                                                                          |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **M0** | Spec + threat model (enrollment, API, privacy, abuse) → `docs/api/enrollment-spec.md` **(v1.0 reviewed 19 Oct 2026; decisions recorded in §6)**                                                             | **gate closed** — reviewed before code; implementation may proceed                                                                            |
| **M1** | Dockerfile + compose + nginx + certbot (LE staging test); `config.py` (per-key `team_id`) + `relay doctor`; async APNs layer; mkdocs scaffold + Actions deploy (`.p8` + App Attest capability: done 19 Oct) | **in-container sandbox APNs smoke test to a physical device + real cert + `renew --dry-run` pass**                                            |
| **M2** | Core API: register (`{id, app, callback?}`, per-key mode matrix, `PublicHTTPS` guard, 30-day expiry), Ed25519 verify (token-bound canonical message), schema + caps, quotas + replay, result mapping        | contract tests green: token-A-signed/token-B-sent → 401; altered `Authorization` → 401; canonical-string fixture shared with reference client |
| **M3** | Grants: issue / verify / renew / denylist                                                                                                                                                                   | forged/expired/cross-destination tests pass                                                                                                   |
| **M4** | Enrollment: challenge push + App Attest → grant                                                                                                                                                             | enrollment rejects unverified ownership                                                                                                       |
| **M5** | Three push kinds + sealed field                                                                                                                                                                             | sandbox + production delivery verified                                                                                                        |
| **M6** | iOS app track (parallel from M0/M1)                                                                                                                                                                         | physical-device end-to-end                                                                                                                    |
| **M7** | OpenCode push plugin                                                                                                                                                                                        | plugin → relay → device works                                                                                                                 |
| **M8** | Admin API + full `relay` CLI; OpenAPI + reference client; docs complete; metrics/alerting; GHCR publish; abuse runbook                                                                                      | launch checklist                                                                                                                              |

## 13. Open risks / flags

1. **Enrollment is the highest-risk piece** — `notifications.md` requires it be
   specified and reviewed first; App Attest alone ≠ token ownership (hence the
   challenge push). **M0 closed 19 Oct 2026** (`enrollment-spec.md` v1.0):
   implementation risk now sits in M4's App Attest verification, not in design.
2. **Funding/quotas policy** is a documented launch blocker for the _hosted
   instance_ (not for the code or self-hosting).
3. **No end-to-end caller until M7** — M1's smoke test + a test harness carry
   the interim.
4. Live Activity + background pushes add contract surface; iOS throttles
   background pushes — documented as best-effort; push-to-start deferred.
5. App Attest server-side verification needs Apple's attestation root cert +
   dev/production environment handling. Capability enabled in `4C8FWEBR8F`
   (done 19 Oct); the verification implementation lands in M4 and its exact
   requirements are specified in `docs/api/enrollment-spec.md`.
