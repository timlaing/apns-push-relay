# APNs push relay image — FastAPI/uvicorn app + `relay` admin CLI.
# Build from the repo root: docker build -f deploy/Dockerfile .

FROM python:3.14-slim

# uv pinned by version (it also generates the committed lockfile) so image
# builds are reproducible; bump deliberately.
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv

# README.md is referenced by pyproject.toml (readme=) and must be in the
# build context. uv.lock is committed: dependencies install from the lock
# (reproducible builds), then the project itself on top.
ENV PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    RELAY_CONFIG=/etc/apns-relay/config.yaml \
    RELAY_DATA_DIR=/var/lib/apns-relay \
    DOCS_DOMAIN=timlaing.github.io/apns-push-relay

WORKDIR /app
COPY pyproject.toml README.md uv.lock ./
COPY src ./src
COPY deploy/relay-entrypoint.sh /usr/local/bin/relay-entrypoint
RUN chmod 0755 /usr/local/bin/relay-entrypoint
RUN uv export --frozen --no-dev --no-emit-project --no-hashes \
        -o /tmp/requirements.txt \
    && uv pip install --system -r /tmp/requirements.txt \
    && uv pip install --system --no-deps .

# Non-root runtime user; the data dir (SQLite db, keys at rest, the
# downloaded App Attest root) lives on a named volume mounted at
# /var/lib/apns-relay.
RUN useradd --system --uid 10001 --user-group --no-create-home \
        --home-dir /var/lib/apns-relay relay \
    && mkdir -p /var/lib/apns-relay /etc/apns-relay \
    && chown relay:relay /var/lib/apns-relay \
    && chmod 0750 /var/lib/apns-relay

USER relay
WORKDIR /var/lib/apns-relay

EXPOSE 8000 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5)"]

# One process serves both listeners (serve.py): the admin API on 8000 and
# the public API on 8001, sharing one state — SQLite has a single writer, so
# extra workers would only contend on the write lock. The entrypoint fetches
# the App Attest root when missing, then runs `relay doctor` first (config +
# keys + JWT pre-sign pre-flight, PLAN §5).
ENTRYPOINT ["/usr/local/bin/relay-entrypoint"]
CMD ["python", "-m", "apns_relay.serve"]
