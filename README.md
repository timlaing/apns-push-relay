# apns-push-relay

[![Build Status](https://github.com/timlaing/apns-push-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/timlaing/apns-push-relay/actions/workflows/ci.yml)
[![CodeQL](https://github.com/timlaing/apns-push-relay/actions/workflows/codeql.yml/badge.svg)](https://github.com/timlaing/apns-push-relay/actions/workflows/codeql.yml)
[![GitHub stars](https://img.shields.io/github/stars/timlaing/apns-push-relay.svg)](https://github.com/timlaing/apns-push-relay/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/timlaing/apns-push-relay.svg)](https://github.com/timlaing/apns-push-relay/issues)
[![GitHub license](https://img.shields.io/github/license/timlaing/apns-push-relay.svg)](LICENSE)

[![Coverage](https://img.shields.io/badge/coverage-%3E90%25%20line%20%2F%20100%25%20branch-brightgreen)](CONTRIBUTING.md#coverage-policy)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A generic, self-hostable web API that sends **APNs pushes on behalf of your
backends** — using operator-held `.p8` keys, with tenant backends
authenticated by token + Ed25519 request signing, destination-bound grants,
quotas, and a privacy-by-design core that keeps no device table and logs no
content.

- **Privacy**: no device/session storage, no payload retention, destination
  tokens held only as keyed blind indexes, redacted logs (outcome, latency,
  machine error codes — nothing else).
- **Abuse-resistant**: per-tenant and per-token rate limits, daily quotas,
  denylist, revocation, 30-day non-use deletion, SSRF-hardened ownership
  callbacks, App Attest–verified enrollment.
- **Generic**: apps are operator-managed config — no hostnames, bundles, or
  quotas are hardcoded anywhere.

Documentation: see [`docs/`](docs/) (deployed via GitHub Pages) —
getting started, self-hosting, the API reference, and the threat model.

## How it fits together

```
tenant backend ──(token + Ed25519 signature)──► relay ──(.p8 keys)──► APNs ──► device
     register / enroll / rotate / push / renew / revoke   quotas · denylist · logs
```

1. A tenant backend calls `POST /v1/register` once per App to get a token.
2. The iOS app enrolls through `POST /v1/enroll/begin` → challenge push →
   `POST /v1/enroll/finish` (App Attest + assertion), returning a
   destination-bound **grant** plus a machine-readable consent receipt.
3. The backend sends `POST /v1/push` with the grant, signed per request; the
   relay verifies, applies quotas, and forwards to APNs. Outcomes come back
   as `accepted | invalidDestination | retryable | rejected`.
4. Credentials age: the backend rotates its token + signing key with
   `POST /v1/rotate` (signed under the old key), and paired devices
   re-enroll with the new key.

## Quick start (Docker Compose)

```sh
git clone https://github.com/timlaing/apns-push-relay.git
cd apns-push-relay
cp deploy/config.yaml.example deploy/config.yaml   # edit: apps, domains
cp deploy/.env.example deploy/.env                # set API_DOMAIN, RELAY_ADMIN_TOKEN,
                                                  # RELAY_MASTER_SECRET
# drop .p8 keys at deploy/keys/AuthKey_<KEYID>.p8; config sets key_id (never committed)
docker compose -f deploy/docker-compose.yml pull relay         # published relay image
docker compose -f deploy/docker-compose.yml build nginx        # local edge image (openssl baked in)
docker compose -f deploy/docker-compose.yml up -d
```

The stack is nginx + certbot (automatic TLS renewal) + the relay, with
`relay doctor --offline` run as a pre-flight before the API serves
traffic. See
[`deploy/README.md`](deploy/README.md) for the full walkthrough.

## CLI

`relay` ships in the container (also installable locally via `uv sync`):

```sh
relay doctor                  # checks the running server; --offline = local files
relay version                 # package version
relay status                  # version, health, quota, metric snapshot
relay monitor --interval 5    # live dashboard (status, quotas, recent requests)
relay logs --errors --since 1h
relay tenant list|verify|revoke|reissue
relay denylist add <jti|sha256:…> --expires 24h
relay metrics                 # metric table (--json / --prom too)
relay app list|add|remove     # manage apps via the admin API (keeps comments)
```

## Development

```sh
uv sync                       # install deps (fastapi, httpx, cryptography, …)
uv run pytest                 # tests — line coverage > 90%, branch = 100%
uv run ruff check .           # lint
uv run mkdocs serve           # docs at http://127.0.0.1:8000
```

`scripts/check_coverage.py` is the hard gate enforced in CI:
`coverage json` output must clear >90% line coverage **and** 100% branch
coverage.

## Scope

The relay is app-agnostic; first-party consumers (the iOS client, backend
plugins) live in their own repositories. The API contract is documented in
[`docs/api/enrollment-spec.md`](docs/api/enrollment-spec.md).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Tim Laing.
