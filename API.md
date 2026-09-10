# v0.1 product surface

skytap is a binary, not an importable library. Frozen for operators:

Flags: `-listen`, `-admin` (default 127.0.0.1:8080), `-admin-token` / `SKYTAP_ADMIN_TOKEN`, `-data`, `-install-rules`, `-mode`.

HTTP: `/`, `/domains`, `/flows`, `/state`, `/rules`, `/mcp`, `/ca.pem`, `/meta`, `/ws`.

Auth: REST Bearer only; WS `?token=`; `/meta` public boolean `auth_required`.

Do not import package `main`.
