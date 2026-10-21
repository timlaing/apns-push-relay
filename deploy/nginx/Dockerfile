# nginx edge image — the stock image plus openssl, which the first-boot
# placeholder-certificate generation needs (nginx-entrypoint.sh; stock
# nginx:alpine ships no openssl binary). Compose builds this from
# deploy/nginx/ (`docker compose up -d --build` on first run); the
# entrypoint fails loudly rather than installing packages from the network
# mid-boot if openssl is ever missing.
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl
