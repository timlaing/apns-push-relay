# Getting started

This is the **tenant path**: you run a backend, you want to send pushes to
your own app's users through a relay.

## 1. Register (two variants)

`POST /v1/register` — unauthenticated, rate-limited per IP. One token per
App, forever (or until an operator revokes it).

=== "Plain registration"

    Use this when the operator's App config does not require a callback:

    ```sh
    curl -sS -X POST https://api.push.example.org/v1/register \
      -H 'content-type: application/json' \
      -d '{"id": "hooks.example.com", "app": "my-app"}'
    ```

    ```json
    {
      "tenant": "hooks.example.com",
      "app": "my-app",
      "token": "tnt_…",
      "quota": {"burst_per_min": 60, "daily": 10000, "token_burst_per_min": 30},
      "registered_at": 1792230900,
      "expires_at": 1794822900
    }
    ```

    The `id` must be **your** hostname or a subdomain of it — it is what
    grants are bound to. Store the token like a password: it is shown once.

=== "Callback verification (ownership proof)"

    Some Apps set `registration.callback_required: true`. Then your response
    must include a public HTTPS endpoint the relay will challenge:

    ```json
    {"id": "hooks.example.com", "app": "my-app",
     "callback": "https://hooks.example.com/relay-hook"}
    ```

    The relay POSTs `{"id": …, "kind": "registration", "nonce": …}` and
    requires `{"nonce": "<same value>"}` back — **inline**, before the `201`.

    Requirements (enforced): HTTPS on port 443 only; the callback host must
    equal your `id` or a subdomain of it; DNS resolves to a public address
    only (the callback can never probe private networks).

    Errors: `invalid_callback` (bad URL / host mismatch),
    `callback_verification_failed` (no echo), `id_exists` (already
    registered — first claim wins).

## 2. Sign every request

Signed routes — `/v1/push`, `/v1/enroll/renew`, `/v1/revoke`,
`/v1/rotate` — need an Ed25519 keypair. You send the **public** key at
enrollment (`tenantPubkey`); the private key never leaves your backend.

Canonical message (exact bytes, `\n`-joined):

```
SHA256HEX(token) \n METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA256HEX(body)
```

```python
import base64, hashlib, secrets, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def sign(private: Ed25519PrivateKey, token: str, method: str, path: str,
         body: bytes, timestamp: int | None = None, nonce: str | None = None):
    ts = str(timestamp or int(time.time()))
    nonce = nonce or secrets.token_urlsafe(16)
    message = "\n".join([
        hashlib.sha256(token.encode()).hexdigest(),
        method, path, ts, nonce, hashlib.sha256(body).hexdigest(),
    ]).encode()
    sig = base64.urlsafe_b64encode(private.sign(message)).decode().rstrip("=")
    return {
        "authorization": f"Bearer {token}",
        "x-relay-time": ts,
        "x-relay-nonce": nonce,
        "x-relay-signature": sig,
    }
```

Rules: timestamp ±5 minutes; nonces are 8–128 chars, single-use for 10
minutes; sign the **raw body bytes** you send.

Failures are precise: `missing_token`, `unknown_tenant`, `enrollment_required`,
`invalid_timestamp`, `stale_timestamp`, `invalid_nonce`, `invalid_signature`,
`replayed_nonce` (all `401`).

## 3. Enroll a device (in your app)

Per device, three calls (see the [enrollment spec](api/enrollment-spec.md)
for the full contract):

1. `POST /v1/enroll/begin` `{app, tenantId, destinationToken}` → the relay
   sends the device a silent challenge push → `{challengeId, serverChallenge, expiresAt}`.
2. `POST /v1/enroll/finish` `{challengeId, attestation, assertion,
tenantId, tenantPubkey, kinds, ttl?}` → `{grant, consent}`.
3. Hand the `grant` to your backend over your existing channel (the relay
   never contacts you).

`ttl` is optional and clamped to the App's configured bounds (e.g.
900–86400s; omitted → App default). Renew with
`POST /v1/enroll/renew` before expiry — no re-attestation needed.

## 4. Push

```sh
curl -sS -X POST https://api.push.example.org/v1/push \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $TOKEN" \
  -H "x-relay-time: $TS" -H "x-relay-nonce: $NONCE" -H "x-relay-signature: $SIG" \
  -d '{"grant":"v1.…","destinationToken":"<hex>","kind":"alert",
       "content":{"alert":{"title":"Build finished","body":"all tests green"}}}'
```

```json
{ "result": "accepted", "apnsId": "8F2A…", "detail": null }
```

Results are always `200`:

| `result`             | meaning                                             |
| -------------------- | --------------------------------------------------- |
| `accepted`           | APNs took it (`apnsId` set)                         |
| `invalidDestination` | token is dead/unregistered for this app/environment |
| `retryable`          | network/APNs hiccup — back off and retry            |
| `rejected`           | APNs refused (payload/topic/auth) — see `detail`    |

Pre-flight failures are _not_ 200: `401` auth codes, `403` grant codes
(`grant_expired`, `grant_revoked`, `grant_mismatch`, `destination_mismatch`,
`kind_not_allowed`, …), `429` (`rate_limited`, `token_rate_limited`,
`quota_exhausted`), `422` payload codes (`*_too_long`, `unknown_field`,
`invalid_payload`).

## 5. Revoke

```sh
POST /v1/revoke  {"grant": "v1.…"}   → {"revoked": "<jti>"}
```

The `jti` is denylisted until its expiry; the next push with that grant
fails `403 grant_revoked`. Alternatively your operator can kill a whole
tenant instantly (`relay tenant revoke`).

## 6. Rotate credentials

```sh
POST /v1/rotate  {"pubkey": "<new Ed25519 pubkey, base64url>"}   → {"token": "tnt_…", …}
```

Signed with your **current** token and keypair — the signature is the proof
you hold the binding being rotated. The response replaces both credentials:
the new `token` is shown once, the new pubkey becomes the signing key.
Old grants stop verifying (`403 tenant_mismatch`), so paired devices
re-enroll with the new key; sending your current pubkey rotates only the
token. See [enrollment spec §2.7](api/enrollment-spec.md#27-post-v1rotate-tenant-authenticated-signed-credential-rotation)
for the full semantics.
