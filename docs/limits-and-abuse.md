# Limits & abuse

Free to use, hostile to abuse: every lever is either automatic or one CLI
command away.

## Automatic limits

| Layer                       | Limit                                    | Failure                  |
| --------------------------- | ---------------------------------------- | ------------------------ |
| nginx (per IP, at the edge) | `limit_req` burst/minute per route class | `429`                    |
| App quota — tenant burst    | `quota.burst_per_min` per minute         | `429 rate_limited`       |
| App quota — per destination | `quota.token_burst_per_min` per minute   | `429 token_rate_limited` |
| App quota — daily           | `quota.daily` per rolling 24h            | `429 quota_exhausted`    |
| Register/enroll (per IP)    | 10/min per route class                   | `429 rate_limited`       |
| Request replay              | single-use nonce, 10-min window          | `401 replayed_nonce`     |
| Clock skew                  | ±5 minutes                               | `401 stale_timestamp`    |
| Tenant idle                 | 30 days                                  | row deleted              |
| Unauthenticated body size   | 16 KiB (nginx)                           | `413`                    |

All quota numbers are **per App in operator config** — there are no hidden
global defaults. The relay charges quota _before_ contacting APNs, so
spamming the relay never becomes spamming Apple.

## Registration abuse

- `/v1/register` is rate-limited per IP, first-claim-wins (`409 id_exists`),
  and may require an HTTPS **ownership callback** (host must be the tenant
  id or a subdomain; DNS pinned to public addresses — the callback cannot
  probe private networks).
- Callbacks are signed one-shot challenges, not webhooks: a third party can
  make the relay ping a URL it claims to own, at most the per-IP limit, and
  nothing else.

## Enrollment abuse

- The challenge push must be **echoed by the device that owns the token**
  (an attacker never receives it).
- App Attest proves a _genuine build of the app_ — chains to Apple's root,
  exact bundle ID, environment match.
- User consent is collected in-app; the relay binds only what a human
  approved there (it stores no consent record — the receipt goes to the app).
- Challenges are single-use and expire (default 10 minutes).

## Revocation levers (operator runbook)

```sh
# 1. Stop one grant immediately (tenant does this, or you do via denylist):
relay denylist add <jti> --expires 24h

# 2. Stop every destination for one token hash:
relay denylist add sha256:<hex> --expires 24h

# 3. Kill a tenant outright (their next request → 401 unknown_tenant):
relay tenant revoke <tenant-id>

# 4. Disable an App entirely: set `enabled: false` in config.yaml and
#    restart — pushes fail 403 app_disabled; new registrations get 400.
```

## Reporting abuse

If you host a public instance, publish an abuse contact in your instance's
footer. For this project: open a
[GitHub issue](https://github.com/timlaing/apns-push-relay/issues)
(security-sensitive reports: use GitHub Security Advisories on the repo).

!!! info "Operator responsibility"
A relay operator is the controller of the little data that exists
(token digests, blind indexes). The [privacy](privacy.md) page is the
contract to your tenants — keep it true for your deployment.
