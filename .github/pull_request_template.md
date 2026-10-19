## Change

Describe the problem and the resulting behaviour.

## Validation

List relevant tests (`uv run pytest`, `uv run python scripts/check_coverage.py coverage.json`) and any deployment evidence (`relay doctor`, `relay status`, sanitized logs).

## Checks

- [ ] No credentials, device tokens, private reports or database files included.
- [ ] No .p8 keys, grant-issuer keys, tenant tokens or grant strings included.
- [ ] Tests cover changed behaviour and CI passes.
- [ ] Coverage gate: line > 90%, branch 100% still green.
- [ ] API/deployment documentation and changelog updated where needed.
