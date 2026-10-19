# Reference client (Python)

`relay_client.py` is the reference implementation of the tenant protocol —
the file other language ports should be written against:

- `canonical_message()` / `sign_headers()` — the exact bytes for signed
  routes (shared fixture-tested against the relay's own verifier).
- `RelayClient` — register, push, enroll begin/finish/renew, revoke.
- `grant_claims()` — decode-only helper for tests/inspection (the relay
  verifies signatures; do not treat this as validation).

Only third-party dependency: `cryptography` (Ed25519). HTTP goes through
stdlib `urllib`; inject `transport=` to test in-process or offline.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from relay_client import RelayClient

client = RelayClient(
    "https://api.push.example.org",
    token="tnt_…",                     # from POST /v1/register
    private_key=Ed25519PrivateKey.from_private_bytes(b"…"[:32]),
)
receipt = client.register("hooks.example.com", "my-app")
result = client.push(
    grant, "0f…"[:0] + "a" * 64, "alert",
    {"alert": {"title": "Build finished", "body": "all green"}},
)
```

See `docs/getting-started.md` for the full walkthrough and
`docs/api/openapi.yaml` for the schema.
