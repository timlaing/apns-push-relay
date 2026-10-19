# Security Policy

## Reporting a vulnerability

Please do **not** file public issues for security vulnerabilities. Use
[GitHub Security Advisories](https://github.com/timlaing/apns-push-relay/security/advisories/new)
(private report) instead — you get an encrypted channel and an acknowledged
timeline, and the report stays private until a fix ships.

If the advisory form is unavailable, open a
[question issue](https://github.com/timlaing/apns-push-relay/issues/new/choose)
asking for a contact address and nothing else.

## Scope

The relay holds APNs provider keys (`.p8`), tenant tokens (hashed at rest)
and Ed25519 grant-issuer keys. Anything that can leak those, exfiltrate
tenant/destination material, bypass the signature or App Attest checks, or
use the relay to amplify abuse (quota/rate-limit/SSRF bypasses in the
registration callback especially) is in scope.

## Supported versions

Only the latest release on `main` receives fixes. Self-hosters should rebuild
and restart the compose stack after each release.
