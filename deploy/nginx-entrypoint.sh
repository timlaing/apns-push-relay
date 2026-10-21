#!/bin/sh
# nginx wrapper: render the config template, ensure a TLS cert exists, then
# run nginx with a watcher that reloads it when certbot (re)issues the cert.
#
# The compose `command` bypasses the image's default entrypoint (which only
# runs envsubst when the command is nginx), so template rendering is invoked
# explicitly here — it substitutes only defined env vars (${API_DOMAIN});
# nginx runtime variables survive untouched.
set -eu

: "${API_DOMAIN:?API_DOMAIN must be set}"

if [ -f /etc/nginx/templates/default.conf.template ]; then
    /docker-entrypoint.d/20-envsubst-on-templates.sh
fi

cert_dir="/etc/letsencrypt/live/${API_DOMAIN}" # certbot-conf volume (read-only here)
run_dir="/etc/nginx/certs" # nginx-owned: placeholder files or symlinks

# nginx serves from ${run_dir} only. The certbot-conf volume is mounted
# read-only into this container, so the placeholder must never go under
# /etc/letsencrypt (writes would fail and abort boot, and a placeholder there
# would also make certbot's `live/<domain>` existence check skip issuance
# forever). Before issuance the files are a self-signed placeholder; once
# certbot issues, they become symlinks to the real certificate.
link_certificate() {
    ln -sf "${cert_dir}/fullchain.pem" "${run_dir}/fullchain.pem"
    ln -sf "${cert_dir}/privkey.pem" "${run_dir}/privkey.pem"
}

mkdir -p "${run_dir}"
if [ -f "${cert_dir}/fullchain.pem" ]; then
    link_certificate
else
    echo "nginx-entrypoint: no certificate for ${API_DOMAIN}; generating self-signed placeholder"
    # openssl ships in this image (deploy/nginx/Dockerfile). Fail loudly
    # rather than reaching for the network mid-boot if it is missing.
    command -v openssl >/dev/null 2>&1 || {
        echo "nginx-entrypoint: openssl missing - rebuild the nginx image (deploy/nginx)" >&2
        exit 1
    }
    openssl req -x509 -nodes -newkey rsa:2048 -days 2 \
        -subj "/CN=${API_DOMAIN}" \
        -addext "subjectAltName=DNS:${API_DOMAIN}" \
        -keyout "${run_dir}/privkey.pem" \
        -out "${run_dir}/fullchain.pem"
fi

# Watch for the certificate appearing (first issuance) or changing (renewal
# swaps the archive the live/ symlink points at, changing its mtime) — keeps
# nginx and certbot decoupled, no docker socket needed.
(
    last=""
    while :; do
        sleep 60
        if [ -f "${cert_dir}/fullchain.pem" ] && [ ! -L "${run_dir}/fullchain.pem" ]; then
            echo "nginx-entrypoint: certificate issued; switching to ${cert_dir}"
            link_certificate
            nginx -s reload
        fi
        now=$(stat -L -c %Y "${run_dir}/fullchain.pem" 2>/dev/null || printf 'missing')
        if [ -n "${last}" ] && [ "${now}" != "${last}" ]; then
            echo "nginx-entrypoint: certificate changed; reloading nginx"
            nginx -s reload
        fi
        last="${now}"
    done
) &

exec nginx -g 'daemon off;'
