# Self-hosting

The relay ships as a Docker Compose stack: **nginx** (TLS + rate limits),
**certbot** (automatic renewal), and the **relay** (FastAPI + SQLite).

## 1. Prerequisites

- A host with a public IP, ports 80/443 open, and DNS `A`/`AAAA` records
  for your API and docs domains.
- Apple side: an [App Store Connect API key](https://developer.apple.com/documentation/appstoreconnectapi)
  (`.p8`, Key ID, Team ID) per App you relay for, plus the App Attestation
  root certificates (see below).
- Docker with the Compose plugin.

## 2. Configure

```sh
git clone https://github.com/timlaing/apns-push-relay.git
cd apns-push-relay
cp deploy/config.yaml.example deploy/config.yaml
cp deploy/.env.example .env
```

**`.env`** — two secrets, both ≥32 characters, never committed:

```sh
RELAY_ADMIN_TOKEN=…     # powers `relay` / the admin API
RELAY_MASTER_SECRET=…   # HMAC key for blind destination indexes
```

**`deploy/config.yaml`** — everything structural lives here; nothing is
hardcoded in the code. Relative paths (`keys/…`) resolve against the config
file's directory — `deploy/` on the host, `/etc/apns-relay/` in the
container (compose mounts `./keys` there):

```yaml
server:
  api_domain: api.push.example.org # this instance's API
  docs_domain: push.example.org # GitHub Pages CNAME

enrollment:
  grant_issuer_key: keys/issuer.pem # Ed25519 (see below)
  challenge_ttl: 600
  attest_root_certs: # App Attest roots (see below)
    development: keys/apple-attest-development.pem
    production: keys/apple-attest-production.pem

storage:
  database: /var/lib/apns-relay/relay.db

apps:
  - id: my-app
    display_name: My App
    bundle_id: com.example.myapp
    team_id: ABCDEFGHIJ
    key_file: keys/AuthKey_<KEYID>.p8
    environments: [production]
    kinds: [alert, background, liveActivity]
    live_activity: true
    attest_environment: production
    quota: { burst_per_min: 60, daily: 10000, token_burst_per_min: 30 }
    grant_ttl: { min: 900, max: 86400, default: 21600 }
    caps: { title: 64, body: 200, sealed: 1024, background: 512 }
```

Generate the grant-issuer key once:

```sh
mkdir -p deploy/keys
openssl genpkey -algorithm ed25519 -out deploy/keys/issuer.pem
```

Place your `.p8` files **outside the repo** (the gitignore excludes
`keys/`, `*.p8`, `config.yaml`, `.env` and the database).

## 3. Validate before starting

```sh
docker compose -f deploy/docker-compose.yml run --rm relay relay doctor
```

`relay doctor` is fully offline and checks: config schema, every `.p8`
(P-256 parse + JWT pre-signature), the issuer key (Ed25519), App Attest
roots, `RELAY_MASTER_SECRET`, and database writability. The container
entrypoint runs the same check on **every** start — a broken deploy fails
fast instead of at the first push.

## 4. Up, and TLS

```sh
docker compose -f deploy/docker-compose.yml up -d
```

certbot obtains certificates via the ACME webroot nginx exposes, and
renews on a timer; nginx reloads after renewal. Verify:

```sh
curl -sS https://api.push.example.org/health        # {"status": "ok"}
docker compose exec relay relay status
```

!!! note "Staging first"
Use Let's Encrypt **staging** while iterating on DNS to avoid rate
limits — the compose file documents the switch.

## 5. Day-two operations

```sh
docker compose exec relay relay status              # health + quota + metrics
docker compose exec relay relay logs --errors --since 1h
docker compose exec relay relay tenant list
docker compose exec relay relay tenant revoke hooks.example.com   # kill switch
docker compose exec relay relay denylist add <jti|sha256:…> --expires 24h
docker compose exec relay relay metrics             # Prometheus text
```

- The admin API listens on the internal network only: **nginx returns 404
  for `/admin`** (and `/docs`, `/openapi.json`).
- Back up `relay.db` (named volume) — it is the only state; it contains
  digests and blind indexes, never raw tokens or payloads.
- Upgrades: `git pull && docker compose -f deploy/docker-compose.yml
build && … up -d` (doctor pre-flight gates the swap).

## App Attest roots

Apple publishes development and production App Attestation root
certificates; download them from Apple's certification authority page and
point `enrollment.attest_root_certs` at them. Until they are configured the
relay **fails closed**: `enroll/finish` returns `400
attestation_unavailable` and no grants are issued — pushes of already-valid
grants are unaffected.
