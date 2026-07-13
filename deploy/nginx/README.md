# ATDR Nginx Deployment Edge

This is an optional controlled shared-host profile. It does not replace the normal local FastAPI and React commands.

1. Build React with `npm ci && npm run build` and install `frontend/dist` at `/opt/atdr/frontend/dist`.
2. Keep Uvicorn bound to `127.0.0.1:8000` with `--no-proxy-headers`.
3. Install `atdr.conf.example` after replacing the hostname and certificate paths.
4. Set `TRUST_PROXY_HEADERS=true` and `TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128` in the private ATDR environment.
5. Validate with `nginx -t` before reload.
6. Keep `/metrics` loopback-only or replace the allow-list with the approved monitoring network.

The proxy overwrites `X-Forwarded-For` with its direct client address. Do not use `$proxy_add_x_forwarded_for` unless every upstream hop is separately authenticated and allow-listed. ATDR currently has no required WebSocket route, but upgrade headers are preserved for compatibility.

TLS certificates and private keys belong outside Git with restricted permissions. This example is not a production-readiness claim.

Before installation, run the v3.96 dry preflight. Operational acceptance requires a matching HTTPS URL/DNS name, absolute certificate/key paths, owner-only key permissions, explicit HTTPS CORS origins, and a narrowly scoped direct-proxy CIDR. Source validation does not replace `nginx -t` and browser/header checks on the approved host.
