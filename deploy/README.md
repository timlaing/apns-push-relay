# Deployment — Docker Compose

nginx (TLS, 16k body cap, per-IP rate limit) + certbot (Let's Encrypt) +
relay (FastAPI/uvicorn — public API on 8001, admin API on its own port
8000; both bound to host loopback, nginx is the edge). Full walkthrough:
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

## Local bring-up (as if it were on a VPS)

The full stack runs on a workstation exactly as on a server. Resolve the
domains on the machine and start everything:

```sh
echo '127.0.0.1 api.push.example.org push.example.org' | sudo tee -a /etc/hosts
docker compose up -d
```

nginx generates a self-signed placeholder certificate on first boot and
serves HTTPS immediately; without public reachability certbot cannot
solve the ACME challenge and keeps retrying (harmless — see its logs).
Everything else behaves as on a server: port 80 answers ACME and
redirects to HTTPS, 443 serves the API, `/admin` 404s at the edge, and
`swagger_ui: true` serves `/docs`. Accept the browser's certificate
warning, or check with `curl -k https://api.push.example.org/health`.

## Behind another proxy

To serve through an existing TLS-terminating reverse proxy (an ingress,
another nginx, a tunnel), set `FORCE_HTTPS=0` in `.env` and recreate the
nginx container. Port 80 then serves requests that arrive with
`X-Forwarded-Proto: https` instead of redirecting them — the upstream has
already terminated TLS. Plain port-80 requests still redirect, and
`/admin` still 404s at this edge, so the admin API stays unreachable
through the outer proxy. Forward the original `Host` header from the
upstream proxy.

## Operations

- **State** lives on the `relay-data` volume (`relay.db`, SQLite WAL) — the
  only backup target. Config and keys live on the host, outside the
  container lifecycle.
- **CLI**: run inside the container —
  `docker compose exec relay relay status` (also `relay doctor`,
  `relay monitor`, `relay app list`, `relay tenant list`, …).
- **`/admin` is never proxied** through nginx — both ports 404 it at the
  edge, and the public listener (8001) has no admin routes at all. Reach
  the admin API via the CLI above (`docker compose exec`) or
  `http://127.0.0.1:8000` on the host.
- **Onboard an app**: drop its `.p8` in `keys/`, then either add the
  `apps:` entry by hand or run `relay app add` where the config is
  writable (the container mounts it read-only — from a checkout:
  `RELAY_CONFIG=$PWD/config.yaml uv run relay app add` picks a key
  interactively), and `docker compose restart relay`.
