# Secure Vault

Two pieces:

- [`secure-channel/`](secure-channel/README.md) — a C++ vault server/client speaking a custom
  Diffie-Hellman + AES-256-GCM secure channel ("Mini TLS"). This is the trust boundary that
  actually protects secrets in transit and at rest.
- [`vault-api-bridge/`](vault-api-bridge/) — an Express HTTP API (plus a small static dashboard)
  that shells out to the `secure_client` CLI so the vault can be driven over HTTP/JSON instead of
  a raw TCP session.

## Running locally

```bash
cd secure-channel && mkdir -p build && cd build && cmake .. && make
cd ../../vault-api-bridge && npm install
VAULT_PASSWORD=change_me VAULT_CLIENT_PATH=../secure-channel/build/secure_client node server.js
```

Then open `http://localhost:3000/` for the dashboard, or call the API directly:

```bash
curl -X POST http://localhost:3000/api/secrets \
  -H "Authorization: Bearer change_me" -H "Content-Type: application/json" \
  -d '{"key": "example", "value": "hello"}'
```

## Deploying online

```bash
cp .env.example .env   # then edit VAULT_PASSWORD to a strong random value
# edit deploy/Caddyfile: replace your-domain.example.com with your real domain
docker compose up -d --build
```

This builds one container image with both the C++ vault server and the Node bridge (the
`secure_client` binary only ever dials `127.0.0.1:4444`, so they have to share a network
namespace — see [`Dockerfile`](Dockerfile)), and a `caddy` container in front of it that
terminates HTTPS with an automatically-issued Let's Encrypt certificate. Only Caddy's ports
(80/443) are published to the host; the vault/bridge container is reachable solely through the
proxy. Vault data persists in the `vault-data` Docker volume.

If you don't have a domain yet, point `deploy/Caddyfile` at `:8443` instead of a hostname to get
a self-signed cert from Caddy's internal CA for local/LAN testing.

## Progress notes

- **Fixed**: the API bridge accepted secret values containing newlines and forwarded them
  verbatim to the vault CLI's stdin, letting a client smuggle extra protocol commands
  (`set key x\nlogin ...`) into the same session. Values and passwords are now rejected if they
  contain `\r`/`\n`.
- **Fixed**: `index.html` called endpoints (`/api/list`, password-in-query-string) that don't
  exist on the bridge — the dashboard was completely non-functional. It now uses the bridge's
  real `/api/secrets` routes with the password sent as an `Authorization: Bearer` header, and is
  served by the bridge itself so the API calls are same-origin.
- **Added**: Docker/Compose/Caddy scaffolding so the whole thing can be deployed behind TLS
  without hand-rolling process management or a reverse proxy.
- **Not yet addressed** (next steps if you want to keep going):
  - The bridge re-sends the master password on every request instead of issuing short-lived
    session tokens — fine for a single trusted operator, not for multiple users.
  - One `secure_client` subprocess is spawned per HTTP request; under real load a persistent
    connection pool would be far cheaper.
  - There's still a single shared master password / no per-user accounts or audit trail tied to
    a caller identity.
