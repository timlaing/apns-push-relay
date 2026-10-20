# Deployment — Docker Compose

nginx (TLS, 16k body cap, per-IP rate limit) + certbot (Let's Encrypt) +
relay (FastAPI/uvicorn, internal network only). Full walkthrough:
`docs/self-hosting.md`.

## Prerequisites

- A VPS with Docker and the Compose plugin.
- `API_DOMAIN` **A record** → the VPS (port 80 must be reachable for the
  ACME webroot challenge). `DOCS_DOMAIN` = your docs site host (custom domain
  once CNAME'd; the site serves from the GitHub Pages project URL until
  then).
- APNs `.p8` key(s) from the Apple Developer portal — keys stay on the host,
  never in git or the image.

## Steps

```sh
cd deploy
cp .env.example .env               # fill in: tokens, email, domains
cp config.yaml.example config.yaml # edit: apps, domains
mkdir -p keys
# drop the .p8 key(s) in, e.g. keys/AuthKey_XXXXXXXXXX.p8 (key_id = XXXXXXXXXX)
# chmod 600 keys/*.p8
openssl genpkey -algorithm ed25519 -out keys/issuer.pem
docker compose pull # published image (ghcr.io); skip this line to build from source
docker compose up -d
```

On first start nginx serves a self-signed placeholder while certbot issues
the Let's Encrypt certificate for `API_DOMAIN`; once issued, nginx serves
the real certificate. Renewal is fully automatic — certbot re-checks every
12 hours and nginx reloads itself when the certificate file changes (mtime
watcher), so the two containers never touch each other's runtime.

Check status: `docker compose ps`, `docker compose logs -f certbot nginx`.

## Operations

- **State** lives on the `relay-data` volume (`relay.db`, SQLite WAL) — the
  only backup target. Config and keys live on the host, outside the
  container lifecycle.
- **CLI**: run inside the container —
  `docker compose exec relay relay status` (also `relay doctor`,
  `relay monitor`, `relay app list`, `relay tenant list`, …).
- **`/admin` is never proxied** through nginx (internal network only); reach
  the admin API via the CLI above (`docker compose exec`).
- **Onboard an app**: drop its `.p8` in `keys/`, then either add the
  `apps:` entry by hand or run `relay app add` where the config is
  writable (the container mounts it read-only — from a checkout:
  `RELAY_CONFIG=$PWD/config.yaml uv run relay app add` picks a key
  interactively), and `docker compose restart relay`.
