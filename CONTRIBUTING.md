# Contributing to apns-push-relay

Thanks for helping — bug reports, documentation fixes and code are all
welcome. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

Please **never** put credentials in a public issue or pull request: `.p8`
keys, tenant tokens, Ed25519 signing keys, grants, destination (device) tokens
or push payloads. See [SECURITY.md](SECURITY.md) for private reporting.

## Development setup

1. Clone the repo and `cd` into it.
2. Install [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer
   (`uv python install 3.12` if you need one).
3. `uv sync` — installs runtime and dev dependencies into `.venv`.
4. `uv run pytest` — get the suite green before changing anything.

`scripts/check_coverage.py` and the tests run entirely offline; validating a
deployment config is what `relay doctor` is for (see
[`deploy/README.md`](deploy/README.md)).

## Running checks

Before submitting a PR, run the full check suite:

```sh
# Lint/format/yaml/markdown hooks (incl. detect-private-key)
prek run --all-files

# Tests — coverage flags live in pyproject.toml
uv run pytest

# The CI coverage gate: line > 90%, branch 100%
uv run coverage json -o coverage.json
uv run python scripts/check_coverage.py coverage.json
```

Install the git hooks once with `prek install` (or `pre-commit install` —
both drive [`.pre-commit-config.yaml`](.pre-commit-config.yaml)).

### Coverage policy

CI enforces [`scripts/check_coverage.py`](scripts/check_coverage.py):
**line coverage > 90%** _and_ **branch coverage = 100%**. A change that adds
branches must add the tests that exercise every path, including the failure
ones.

## Documentation

- `uv run mkdocs serve` — docs at <http://127.0.0.1:8000>; the source lives
  in [`docs/`](docs/) and CI publishes it to GitHub Pages.
- If you change the API surface, regenerate the published schema with
  `uv run python scripts/export_openapi.py` and commit the diff.
- New behaviour worth announcing goes in
  [`CHANGELOG.md`](CHANGELOG.md) (Keep a Changelog format).

## Pull request process

1. Fork the repo and create a branch (`git checkout -b fix/my-thing`).
2. Make your changes, with tests covering the changed behaviour.
3. Run `prek run --all-files`, `uv run pytest` and the coverage gate — all
   must pass; CI runs them on 3.12, 3.13 and 3.14.
4. Open a PR using the template — describe the change, the validation you
   did, and work through the checklist.

## Reporting security issues

Vulnerabilities go through
[GitHub private vulnerability reporting](SECURITY.md) — never the public
issue tracker.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE) covering this project.
