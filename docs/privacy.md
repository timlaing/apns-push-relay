# Privacy

The relay is built so that running it tells an operator as little as
possible about anyone's business — including theirs.

## What is stored (the complete list)

| Table        | Contents                                                            |
| ------------ | ------------------------------------------------------------------- |
| `tenants`    | tenant id, App id, **token digest**, Ed25519 public key, timestamps |
| `usage`      | timestamps bucketed per tenant/day and per **blind index**          |
| `nonces`     | SHA-256 of used nonces (replay window, 10 minutes)                  |
| `challenges` | challenge id, App, tenant id, token digest, nonces, expiry          |
| `denylist`   | grant `jti` or `sha256:…` token hash + expiry                       |

## What the relay never sees (by construction)

- **Destination tokens in the clear, at rest.** A push request's
  `destinationToken` is used to address APNs and to HMAC into a _blind
  index_ (`HMAC(master_secret, token)`) for quota buckets, then discarded.
  Without the operator-held master secret the index cannot be reversed or
  linked back across days even if the database leaks.
- **Payload content.** Content is validated against per-App caps, encoded,
  and forwarded; nothing is logged or retained. `sealed` content is
  decrypted by _you_, never by the relay — it only checks its size.
- **Who your users are.** There is no device table, no session table, no
  user identity. The relay knows "some tenant sent a push to a bucket" —
  nothing more.
- **Grants, once.** Grants are verified statelessly and only remembered if
  you revoke one (`jti` on the denylist).
- **Anything in logs.** Events carry route, status, machine error code and
  latency. Tokens, grants, payloads and tenant ids never appear in output
  from `relay logs` or `relay metrics`.

## Third parties

- **APNs** sees what any APNs sender sees: the token you address, your
  (operator's) app topic, and the payload — that is Apple's platform, not
  the relay's doing.
- **GitHub** hosts the docs/site (Pages) and the source; the repository is
  public and contains no secrets (`.p8`, `config.yaml`, `.env`,
  `relay.db` are gitignored).

## Retention & deletion

- **30-day non-use deletion**: a tenant row that has not been used for 30
  days is deleted entirely — token digest, public key, all of it. The next
  authenticated call returns `401 unknown_tenant`; re-registration starts
  clean.
- **Operator kill switch**: `relay tenant revoke <id>` deletes immediately;
  the next request fails with `unknown_tenant`.
- **Rate-limit state** ages out in minutes; usage rows in 24 hours;
  nonces in 10 minutes; challenges at expiry (≤1 hour).
- **Backups** (if the operator makes them) inherit all of the above — the
  schema is the privacy boundary; there is nothing else in the file.
