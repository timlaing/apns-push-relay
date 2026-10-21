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
LETSENCRYPT_EMAIL=…     # certbot sends expiry notices here
RELAY_ADMIN_TOKEN=…     # powers `relay` / the admin API
RELAY_MASTER_SECRET=…   # HMAC key for blind destination indexes
```

`.env` drives nginx and certbot; the `server:` block in `config.yaml` below
holds the relay's own options (`swagger_ui`).

**`deploy/config.yaml`** — everything structural lives here; nothing is
hardcoded in the code. Relative paths (`keys/…`) resolve against the config
file's directory — `deploy/` on the host, `/etc/apns-relay/` in the
container (compose mounts `./keys` there):

```yaml
server:
  swagger_ui: false # true → Swagger UI at /docs, ReDoc, OpenAPI schema

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
    key_id: XXXXXXXXXX # 10-char id from the AuthKey_<KEYID>.p8 filename
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

Name every `.p8` `AuthKey_<KEYID>.p8` and drop it in `deploy/keys/`; set
that app's `key_id` to the 10-character id — the relay looks the file up
at `keys/AuthKey_<key_id>.p8` next to the config file. Keep it all
**outside the repo** (the gitignore excludes `keys/`, `*.p8`,
`config.yaml`, `.env` and the database).

## 3. Validate before starting

```sh
docker compose -f deploy/docker-compose.yml run --rm relay relay doctor --offline
```

`relay doctor --offline` checks the local files: config schema, every
`.p8` (P-256 parse + JWT pre-signature), the issuer key (Ed25519), App
Attest roots, `RELAY_MASTER_SECRET`, and database writability. The
container entrypoint runs the same check on **every** start — a broken
deploy fails fast instead of at the first push. Once the stack is up,
`relay doctor` (without `--offline`) runs the same checks through the
admin API, against the running server itself.

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

!!! note "Behind another proxy"
    If this stack sits behind an existing TLS-terminating proxy (an
    ingress, another nginx, a tunnel), set `FORCE_HTTPS=0` in `.env` and
    recreate the stack: port 80 then serves requests arriving with
    `X-Forwarded-Proto: https` instead of redirecting them. The certbot
    service is scaled to zero in this mode — no ACME client or renewal
    loop runs, and `LETSENCRYPT_EMAIL` is only required when it runs.
    Plain port-80 requests still redirect, and `/admin` still 404s at the
    edge. Forward the original `Host` header from the upstream proxy.

## 5. Day-two operations

```sh
docker compose exec relay relay status              # version + health + quota + metrics
docker compose exec relay relay version             # package version
docker compose exec relay relay monitor --interval 5   # live dashboard (status, quotas, recent requests)
docker compose exec relay relay logs --errors --since 1h
docker compose exec relay relay tenant list
docker compose exec relay relay tenant revoke hooks.example.com   # kill switch
docker compose exec relay relay denylist add <jti|sha256:…> --expires 24h
docker compose exec relay relay metrics             # metric table (--json / --prom too)
```

- The relay process serves two listeners: the public API on port 8001
  (nginx's upstream, bound to host loopback for pre-nginx CLI/Swagger)
  and **the admin API on its own port 8000** (host loopback only, the
  CLI's default target). The public listener has no `/admin` routes at
  all, and **nginx returns 404 for `/admin`**.
- **Adding or removing apps**: `relay app add` (interactively picks from
  the server's `keys/AuthKey_*.p8`) and `relay app remove` go through
  the admin API — the relay process edits `config.yaml`, preserving
  comments and writing a `.bak`. Run them inside the container
  (`docker compose exec relay relay app add`; the CLI only makes API
  calls, so no elevated user is needed) and then
  `docker compose restart relay` (config is loaded at boot; the
  entrypoint re-runs the offline doctor on every start). From the host,
  export `RELAY_ADMIN_TOKEN` and point
  `RELAY_API_URL` at `http://127.0.0.1:8000` to drive the same
  commands.
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
  build); `docker compose pull` tracks `latest` — GHCR also publishes
  per-version and sha tags if you prefer to pin. Doctor
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
