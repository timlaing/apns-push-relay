#!/bin/sh
# Relay container entrypoint: PLAN §5 pre-flight — validate config, .p8 keys,
# JWT pre-signature and the issuer key via `relay doctor` before serving, so a
# broken deploy fails at start instead of at the first push.
set -eu

relay doctor
exec "$@"
