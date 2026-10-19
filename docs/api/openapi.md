# OpenAPI reference

Machine-readable schema for every endpoint, generated from the running code
by `scripts/export_openapi.py` — regenerate it whenever routes change
(`uv run python scripts/export_openapi.py`).

## Conventions

- **Base URL**: your instance's `server.api_domain` (e.g.
  `https://api.push.example.org`).
- **Content type**: `application/json` everywhere; unknown request fields
  are rejected (`422 invalid_request`, `extra="forbid"`).
- **Signed routes** — `/v1/push`, `/v1/enroll/renew`, `/v1/revoke`,
  `/v1/rotate` — carry `Authorization: Bearer tnt_…`, `X-Relay-Time`,
  `X-Relay-Nonce`, `X-Relay-Signature` (canonical message in
  [Getting started](../getting-started.md#2-sign-every-request)).
- **Push results are always `200`** with
  `result ∈ {accepted, invalidDestination, retryable, rejected}`.
- **Error envelope**: `{"error": "<machine-code>", "detail": "<optional>"}`.
- The admin API (`/admin/*`) is _not_ in this schema — it is internal,
  never proxied by nginx, and authenticated by `RELAY_ADMIN_TOKEN`.
- **Interactive docs**: an instance can serve this schema as Swagger UI at
  `/docs` (plus ReDoc at `/redoc` and raw `/openapi.json`) when the
  operator sets `server.swagger_ui: true` — off by default.

## Endpoints

| Method & path            | Auth   | Purpose                                  |
| ------------------------ | ------ | ---------------------------------------- |
| `POST /v1/register`      | —      | Tenant token issuance (per App, once)    |
| `POST /v1/push`          | signed | Deliver one push against a grant         |
| `POST /v1/enroll/begin`  | —      | Challenge push for a destination token   |
| `POST /v1/enroll/finish` | —      | App Attest + assertion → grant + consent |
| `POST /v1/enroll/renew`  | signed | Fresh grant, new `jti`, same bindings    |
| `POST /v1/revoke`        | signed | Denylist a grant's `jti`                 |
| `POST /v1/rotate`        | signed | Rotate tenant token + signing key        |

!!! note "Regenerating"
The block below is the literal content of `docs/api/openapi.yaml`
(included at build time), so it can never drift from the code that was
exported.

```yaml
--8<-- "docs/api/openapi.yaml"
```
