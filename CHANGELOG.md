# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog],
and this project adheres to [Semantic Versioning].

## [Unreleased]

### Added

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

## [0.1.0] - 2026-10-19

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

[Unreleased]: https://github.com/timlaing/apns-push-relay/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/timlaing/apns-push-relay/releases/tag/v0.1.0
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
