#!/bin/sh
# Relay container entrypoint: PLAN §5 pre-flight — fetch the App Attest root
# when it is missing (public Apple URL, verified against a pinned SHA-256;
# best-effort: an offline boot still serves, enroll fails closed until a root
# is present), then validate config, .p8 keys, JWT pre-signature and the
# issuer key via `relay doctor` before serving, so a broken deploy fails at
# start instead of at the first push.
set -eu

relay fetch-roots --if-missing || \
    echo "relay-entrypoint: attest root fetch failed (continuing; retry with 'relay doctor --fetch-roots')" >&2
relay doctor
exec "$@"
