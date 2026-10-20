# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog],
and this project adheres to [Semantic Versioning].

## [Unreleased]

### Added

- **`relay monitor`**: a live rich dashboard — health, apps, quotas, the
  metric snapshot and recent requests. `--errors` tails failures only;
  `--once` renders a single frame for scripts.
- **`relay app add` / `app remove` / `app list`**: manage the `apps:`
  section of `config.yaml` from the CLI. `add` interactively picks from
  the `keys/AuthKey_*.p8` files present (fully scriptable with flags +
  `--yes`); edits preserve comments and write a `config.yaml.bak`
  backup before each change.
- **Behind-proxy mode**: `FORCE_HTTPS=0` (`.env`) makes port 80 serve
  requests arriving with `X-Forwarded-Proto: https` — for stacks behind
  a TLS-terminating reverse proxy — instead of redirecting them. The
  default keeps port 80 redirecting unconditionally, and `/admin` 404s
  at the edge on both ports.
- **The API root answers with the docs pointer**: `GET /` on the public
  listener returns `{"docs": "…"}` (previously static nginx JSON). The
  docs host is the image env `DOCS_DOMAIN` (default: the project's
  GitHub Pages URL), so the `.env` knob is gone.
- **In-container config management**: compose mounts the deploy
  directory read-write (keys stay read-only), so `relay app add` /
  `app remove` run inside the container
  (`docker compose exec -u root relay …`) edit the live config with
  host-side backups. `--config`/`-c` selects the config path for the
  config-editing commands (`app add`, `app remove`).
- **`relay version`** and a `version` row in `relay status` —
  `/admin/status` reports the package version (shown by `monitor` too).
- **Formatted metrics**: `relay metrics` renders the rich table (the
  `metrics` legend section, same as `status`); `--json` on `metrics`
  _and_ `status` prints machine-readable JSON (sorted, indented), and
  `metrics --prom` keeps the raw Prometheus text.
- **`relay doctor` as a table**: the checks render in the usual legend
  section (check / status / detail, coloured statuses) and `--json`
  prints them machine-readable (`failures` count + ordered `checks`).
  The summary line and exit code are unchanged.

### Changed

- **`--config` only where configs are edited**: `app add` / `app remove`
  keep `--config`/`-c`; readers (`app list`, `doctor`, `fetch-roots`)
  resolve `$RELAY_CONFIG` (or the container default) only.
- **CLI help trimmed to purpose**: group descriptions no longer list
  their subcommands, command docstrings no longer advertise output
  options, `doctor` states what it verifies instead of listing its
  steps, and option helps use consistent `(default: …)` parentheticals.
- **`--json` output is no longer mangled by rich markup**: JSON prints
  pass through uninterpreted, so values containing brackets (e.g. the
  `attest-root[production]` check name) survive intact.
- **The image tracks `latest`**: compose's relay service now uses
  `ghcr.io/timlaing/apns-push-relay:latest` — the `RELAY_TAG`
  interpolation is gone (version-pinned tags are invisible to image
  updaters such as Watchtower and What's Up Docker). GHCR still
  publishes per-version and sha tags for pinning.
- **CLI output uses help-style legend panels**: status/apps/metrics,
  recent requests and the app/tenant/denylist tables (plus their empty
  states) render inside `╭─ title ──────╮` rounded panels, matching
  typer's CLI help; failures print in a red `╭─ Error ─╮` panel.
  Section tables use the light grid.
- **CLI rewritten on typer + rich**: sub-command help, table renderings
  (status, tenants, denylist) and coloured doctor check lines; every
  error now prints the failing command's help before exiting.
- **App keys are configured by `key_id`**: the `apps[].key_file` entry
  is gone — set `key_id` (the 10-char id from Apple's
  `AuthKey_<KEYID>.p8` filename) and the file is looked up at
  `keys/AuthKey_<key_id>.p8` next to the config file (flat, no
  subdirectories). Passing `key_file` fails with a migration hint.
- `bundle_id` clarified in the example config and docs: it is the bundle
  identifier only — the APNs topic _is_ the bundle id (no App ID
  prefix).
- **The admin API moved to its own port**: one relay process now serves
  two listeners sharing one state — the public API (+docs) on port 8001
  (nginx's upstream) and the admin API on port 8000. Both are published
  on host loopback only (the CLI's default target is the admin port);
  the public listener has no `/admin` routes at all.

### Fixed

- `server.swagger_ui` was documented but never read by the config
  loader — only code-level overrides could enable it. The loader now
  reads and validates the key (bool), and rejects unknown `server:`
  keys so a documented option can't silently vanish again.

## [0.2.0] - 2026-10-20

### Added

- **Automatic App Attest root**: the container downloads Apple's public
  App Attestation Root CA at startup into the data volume, verified
  against a pinned SHA-256 (fail-loud on mismatch — a rotation is a
  deliberate release, never a silent trust change).
  `relay fetch-roots [--if-missing]` and `relay doctor --fetch-roots`
  re-download/update it, and `relay doctor` now reports each configured
  root's fingerprint and expiry (warns under 90 days, fails when
  expired). `enrollment.attest_root_url` selects the source (`null`
  disables fetching for fully manual root management).

### Changed

- `enrollment.attest_root_certs` documentation updated: Apple publishes
  one App Attest root for both environments (AAGUIDs separate them); the
  example config now ships both environments pointing at the downloaded
  root in the data volume.

## [0.1.0] - 2026-10-20

### Added

- **First public release.** A generic, self-hostable web API that sends APNs
  pushes on behalf of tenant backends using operator-held `.p8` keys.
- **Trust model**: tenant tokens plus per-request Ed25519 signing,
  destination-bound grants, and an App Attest–verified enrolment flow with
  machine-readable consent receipts.
- **Privacy core**: no device or session table (destination tokens held only
  as keyed blind indexes), no payload retention, redacted logs and metrics,
  and hard deletion after 30 days of tenant non-use.
- **Abuse controls**: per-tenant and per-token rate limits, daily quotas,
  denylist, revocation, and SSRF-hardened ownership callbacks.
- **`relay` CLI**: `doctor`, `status`, `logs`, `tenant`, `denylist`,
  `metrics` — shipped in the container, installable locally with `uv sync`.
- **Deployment**: nginx + certbot Docker Compose stack with `relay doctor`
  as a pre-flight, GHCR images published on `v*` tags.
- **Docs**: MkDocs Material site (getting started, self-hosting, API
  reference, threat model) deployed to GitHub Pages, with an exported
  OpenAPI schema and a reference Python client.
- **Quality gates**: test suite with CI enforcing > 90% line **and** 100%
  branch coverage on Python 3.12–3.14, CodeQL scanning and Dependabot.
- **Credential rotation: `POST /v1/rotate`.** A tenant replaces its token
  and Ed25519 signing key in one round trip, authorized by a request signed
  under the current binding (proof of possession). Grants bound to the old
  key stop verifying; paired devices re-enroll with the new key (enrollment
  spec §2.7, v1.2 amendment).
- **Interactive API docs (opt-in):** `server.swagger_ui: true` serves
  Swagger UI (`/docs`), ReDoc (`/redoc`) and the OpenAPI schema
  (`/openapi.json`) on the API host; off by default, and `/admin` is
  never exposed either way.
- **Container image:** self-hosting pulls the published GHCR image
  (`ghcr.io/timlaing/apns-push-relay`, one tag per release); building
  from source remains the compose fallback (`up --build`).

### Fixed

- **Docs rendering:** admonition bodies were not indented on four pages
  (`limits-and-abuse`, `status`, `api/openapi`, `self-hosting` ×2), so
  they rendered as empty title boxes with the text orphaned below; the
  enrollment spec's Status/Version/Applies-to/License header lines merged
  into a single run-on paragraph.

[Unreleased]: https://github.com/timlaing/apns-push-relay/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/timlaing/apns-push-relay/releases/tag/v0.2.0
[0.1.0]: https://github.com/timlaing/apns-push-relay/releases/tag/v0.1.0
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
