# Self-hosting

The relay ships as a container image
(`ghcr.io/timlaing/apns-push-relay`, one tag per release) and runs as a
Docker Compose stack: **nginx** (TLS + rate limits), **certbot**
(automatic renewal), and the **relay** (FastAPI + SQLite). Building from
source is supported, but not required — the image is the primary path.

## 1. Prerequisites

- A host with a public IP, ports 80/443 open, and DNS `A`/`AAAA` records
  for your API and docs domains.
- Apple side: an [APNs authentication key](https://developer.apple.com/documentation/usernotifications/setting-up-a-remote-notification-server/establishing-a-token-based-connection-to-apns)
  (`.p8`, Key ID, Team ID) per App you relay for — created under
  Certificates, Identifiers & Profiles → Keys with the _Apple Push
  Notifications service (APNs)_ capability enabled (an App Store Connect API
  key is a different thing and APNs rejects it) — plus the App Attestation
  root certificates (see below).
- Docker with the Compose plugin.

## 2. Configure

The compose file, nginx template and config examples live in the repo —
clone it (or copy `deploy/` onto your host):

```sh
git clone https://github.com/timlaing/apns-push-relay.git
cd apns-push-relay
cp deploy/config.yaml.example deploy/config.yaml
cp deploy/.env.example deploy/.env
```

**`.env`** — your domains and two secrets; nothing domain-related is
hardcoded anywhere. The values in `.env.example` are placeholders — replace
them. Secrets must be ≥32 characters; `.env` is gitignored:

```sh
API_DOMAIN=…            # this instance's API hostname (A record → VPS)
DOCS_DOMAIN=…           # docs hostname (bare hostname; docs serve from the
                        # GitHub Pages project URL until a CNAME exists)
LETSENCRYPT_EMAIL=…     # certbot sends expiry notices here
RELAY_ADMIN_TOKEN=…     # powers `relay` / the admin API
RELAY_MASTER_SECRET=…   # HMAC key for blind destination indexes
```

`.env` drives nginx and certbot; the `server:` block in `config.yaml` below
mirrors the same two domains.

**`deploy/config.yaml`** — everything structural lives here; nothing is
hardcoded in the code. Relative paths (`keys/…`) resolve against the config
file's directory — `deploy/` on the host, `/etc/apns-relay/` in the
container (compose mounts `./keys` there):

```yaml
server:
  api_domain: api.push.example.org # this instance's API
  docs_domain: push.example.org # docs host (project URL until a CNAME exists)

enrollment:
  grant_issuer_key: keys/issuer.pem # Ed25519 (see below)
  challenge_ttl: 600
  # App Attest root: downloaded automatically at container startup and
  # verified against a pinned SHA-256 (see below). Override the URL or the
  # paths to manage the file yourself.
  attest_root_url: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
  attest_root_certs:
    development: /var/lib/apns-relay/apple-attest-root.pem
    production: /var/lib/apns-relay/apple-attest-root.pem

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

Pull the published image and start — no build toolchain needed beyond
Docker:

```sh
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d
```

!!! tip "Building from source (alternative)"
To run a modified build — or when no release image exists yet — let
compose build from the checkout instead (`build:` in
`docker-compose.yml`; with no local image, `up` builds automatically):

    ```sh
    docker compose -f deploy/docker-compose.yml up -d --build
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
  for `/admin`**.
- **Interactive API docs**: set `swagger_ui: true` under `server:` in
  `config.yaml` to serve Swagger UI at `/docs`, ReDoc at `/redoc` and the
  schema at `/openapi.json` on the API domain (off by default — the
  published schema lives on the docs site either way).
- **Tenant credentials are tenant-side**: a tenant rotates its own token
  and signing key with `POST /v1/rotate` (signed under the current key).
  Operator kill switches stay `relay tenant revoke` (kill) and
  `relay tenant reissue` (new token, key untouched).
- Back up `relay.db` (named volume) — it is the only state; it contains
  digests and blind indexes, never raw tokens or payloads.
- Upgrades: `git pull && docker compose -f deploy/docker-compose.yml
pull && … up -d` for the image path (or `… up -d --build` on a source
  build); `RELAY_TAG=<version>` in `.env` pins a release. Doctor
  pre-flight gates the swap.

## App Attest roots

Apple publishes a **single** App Attestation Root CA — development and
production attestations chain to it and are separated by AAGUID (spec
§2.2) — at a public link on Apple's certificate-authority page (no Apple
Developer sign-in needed). The container downloads it at startup into
`/var/lib/apns-relay/apple-attest-root.pem` and verifies it against a
pinned SHA-256 fingerprint: a tampered response or an Apple rotation fails
loudly rather than trusting the download. To re-download or update it
later:

```sh
docker compose exec relay relay doctor --fetch-roots    # re-download + full checks
docker compose exec relay relay fetch-roots --if-missing  # the startup step, rerun by hand
```

Set `enrollment.attest_root_url: null` to manage the file(s) entirely
yourself — point `enrollment.attest_root_certs` at your own PEMs; `relay
doctor` validates whichever files are configured (subject, expiry with a
warning under 90 days, fingerprint) either way. Until a root for an App's
`attest_environment` resolves the relay **fails closed**: `enroll/finish`
returns `400 attestation_unavailable` and no grants are issued — pushes of
already-valid grants are unaffected. The startup download is best-effort:
an offline boot still serves.
