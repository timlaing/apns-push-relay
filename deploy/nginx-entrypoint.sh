#!/bin/sh
# nginx wrapper: render the config template, ensure a TLS cert exists, then
# run nginx with a watcher that reloads it when certbot (re)issues the cert.
#
# The compose `command` bypasses the image's default entrypoint (which only
# runs envsubst when the command is nginx), so template rendering is invoked
# explicitly here — it substitutes only defined env vars (${API_DOMAIN},
# ${DOCS_DOMAIN}); nginx runtime variables survive untouched.
set -eu

: "${API_DOMAIN:?API_DOMAIN must be set}"

if [ -f /etc/nginx/templates/default.conf.template ]; then
    /docker-entrypoint.d/20-envsubst-on-templates.sh
fi

cert_dir="/etc/letsencrypt/live/${API_DOMAIN}"

# Before the first certbot issuance there is no certificate for nginx to
# load, so self-sign a short-lived placeholder at the exact path the config
# references. certbot replaces it with the real certificate at the same path
# (atomic symlink swap).
if [ ! -f "${cert_dir}/fullchain.pem" ]; then
    echo "nginx-entrypoint: no certificate for ${API_DOMAIN}; generating self-signed placeholder"
    # The nginx alpine image ships no openssl binary; install it just-in-time
    # (only needed on first boot, before the first real certificate exists).
    command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl
    mkdir -p "${cert_dir}"
    openssl req -x509 -nodes -newkey rsa:2048 -days 2 \
        -subj "/CN=${API_DOMAIN}" \
        -keyout "${cert_dir}/privkey.pem" \
        -out "${cert_dir}/fullchain.pem"
fi

# Reload nginx whenever the certificate file changes (certbot's renewal
# swaps the live/ symlink to a new archive file, changing its mtime) — keeps
# nginx and certbot decoupled, no docker socket needed.
(
    last=""
    while :; do
        sleep 60
        now=$(stat -c %Y "${cert_dir}/fullchain.pem" 2>/dev/null || printf 'missing')
        if [ -n "${last}" ] && [ "${now}" != "${last}" ]; then
            echo "nginx-entrypoint: certificate changed; reloading nginx"
            nginx -s reload
        fi
        last="${now}"
    done
) &

exec nginx -g 'daemon off;'
