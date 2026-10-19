# Security Policy

## Reporting a vulnerability

Please **do not** report security vulnerabilities in the public issue tracker.
Instead, report vulnerabilities privately through **GitHub's private
vulnerability reporting**, which goes directly to the maintainers:

> **Report a security vulnerability** → **https://github.com/timlaing/apns-push-relay/security/advisories**

You can also use **GitHub Security Advisories** from the repository's
**Security** tab.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What happens next

- We aim to acknowledge receipt of security reports within a reasonable
  timeframe and to keep you informed as we triage.
- We will coordinate on a fix and release before the issue is publicly
  disclosed wherever possible.
- We ask that reporters allow time for a fix and release before public
  disclosure, and credit the reporter if they wish.

## Scope

This policy covers the code in this repository: the relay service, the `relay`
CLI, the nginx configuration and the Docker Compose stack. It does not cover:

- **Apple APNs** — service or protocol vulnerabilities belong to Apple
- **Tenant backends** — how a tenant stores its token and Ed25519 signing key
  is that tenant's code, in its own repository
- **The client apps** — the iOS app and backend plugins live in their own
  repositories (see the [API contract](docs/api/enrollment-spec.md) for the
  boundary)
- **Your deployment** — whoever deploys the stack is the operator and holds
  the `.p8` keys; misconfiguration of your instance is yours to fix, though
  bugs in the code or docs that make deployments unsafe are in scope

## Security considerations

What the relay is designed to hold — and deliberately not to hold:

- The **operator** holds the Apple `.p8` keys; tenant backends never see them.
  A stolen tenant token + signing key lets an attacker push _through_ your
  relay, within that App's quotas — it lets them read nothing back.
- **No device table.** Destination tokens are stored only as keyed blind
  indexes; enrolments are hard-deleted after 30 days without an authenticated
  request.
- **No payload retention.** Push content is never logged or persisted. Logs
  and metrics carry outcome, latency, route template and machine error codes —
  nothing else (see [`docs/privacy.md`](docs/privacy.md)).
- Requests are **Ed25519-signed per call**, enrolment is **App
  Attest-verified**, and ownership callbacks are SSRF-hardened (see
  [`docs/limits-and-abuse.md`](docs/limits-and-abuse.md)).

### Never paste into a public issue

- `.p8` private keys, tenant tokens, grants or Ed25519 signing keys
- Destination (device) tokens, even truncated ones
- Push payload content — it may contain personal data
- Your `config.yaml` — describe the setting instead of attaching the file

## Supported Versions

| Version  | Supported |
| -------- | --------- |
| Latest   | Yes       |
| < Latest | No        |

## Security tooling

This project uses a number of automated checks to help keep the codebase
secure:

- GitHub **CodeQL** analysis runs in CI
  ([`.github/workflows/codeql.yml`](.github/workflows/codeql.yml)).
- GitHub **Dependabot** monitors dependency updates, known-vulnerability
  advisories and security updates
  ([`.github/dependabot.yml`](.github/dependabot.yml)).
- GitHub **secret scanning** and **push protection** are enabled on this
  repository.
- `prek run --all-files` runs a `detect-private-key` hook to prevent
  committing private keys; [`.gitignore`](.gitignore) excludes `*.p8`,
  `keys/`, `.env` and `config.yaml` regardless.
