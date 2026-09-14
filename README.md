# SkyTap

Transparent intercept proxy for Linux. Watch outbound HTTP(S) per domain, decrypt only what you choose, mock or rewrite requests — from a small web UI.

SkyTap is a **binary**, not a Go library. Capture and MITM live in:

- [skydst](https://github.com/SkyFetch0/skydst) — redirect + original destination
- [gomitm](https://github.com/SkyFetch0/gomitm) — CA, TLS terminate, passthrough

Those two do not import each other. SkyTap wires them together with policy, persistence, and the admin UI.

**License:** MIT · **Go:** 1.22+ · **stdlib only**

---

## What it does

| Mode | Behaviour |
|------|-----------|
| **OBSERVED** (default) | Splice only. No decrypt. Safe default. |
| **INTERCEPT** | Terminate TLS, log request/response (bodies capped). |
| **MOCK** | Same as intercept, but you can return a local response. |
| **Rewrite** | Still hits the real server; JSON fields on the request can be patched first. |

Unknown hosts stay **OBSERVED**. Nothing is decrypted until you promote a domain.

Terminated TLS is HTTP/1.1 only (no `h2` ALPN). WebSocket/SSE on an INTERCEPTed host is spliced to origin; `/flows` logs one 101/upgrade row. `-verify-upstream` checks the origin against the **system CA** (hostname + chain). It does **not** pin the SPKI stored in the SSL kit. Pin/impersonate apply to the patched client (`skytap-ssl.conf`), not to SkyTap’s own dial. Flow bodies are capped at 64 KiB (`ReqTruncated` / `ResTruncated`); `ResSize` uses `Content-Length` when present.

---

## Install

```bash
git clone https://github.com/SkyFetch0/skytap.git
cd skytap
go build -o skytap .
```

On Debian, Ubuntu, AlmaLinux, Rocky, Fedora, or Arch (as root):

```bash
sudo ./install.sh
```

This installs `/usr/local/bin/skytap`, data under `/var/lib/skytap`, and a systemd unit.

```bash
./skytap -listen :3128 -admin 127.0.0.1:8080 -data ./data
```

Open [http://127.0.0.1:8080/](http://127.0.0.1:8080/). Languages: English, Türkçe, العربية, Русский.

Remote host without opening the port:

```bash
ssh -L 8080:127.0.0.1:8080 user@host
```

### Flags

| Flag | Default | |
|------|---------|--|
| `-listen` | `:3128` | Transparent proxy |
| `-admin` | `127.0.0.1:8080` | UI + JSON API + MCP |
| `-admin-token` | `$SKYTAP_ADMIN_TOKEN` | Bearer token (required if admin is not loopback) |
| `-data` | `/data` | CA, `state.json`, `rules.json` |
| `-install-rules` | `true` | nftables/iptables in **this** network namespace |
| `-mode` | `output` | `output` or `prerouting` |
| `-ports` | `80,443` | Redirected TCP ports |
| `-exclude-nets` | RFC1918 + loopback | CIDRs that skip redirect |

---

## Security

SkyTap can decrypt TLS and inject responses. Treat the admin port as privileged.

- Admin defaults to **127.0.0.1**. Binding `0.0.0.0` without a token is refused at startup.
- REST and MCP: `Authorization: Bearer <token>` only (not `?token=` on those routes).
- WebSocket `/ws` uses `?token=` (browsers cannot set `Authorization`). Put TLS in front on a public bind.
- `/meta` is public and only reports whether auth is required — never the token.
- The admin server is **plain HTTP**. Use Caddy or nginx if it is not loopback.

---

## Trust store (INTERCEPT / MOCK)

**OBSERVED** needs no CA. Decrypting a client means that **client** must trust SkyTap’s CA (`/ca.pem` in the UI, or `$DATA/ca/ca-cert.pem`). Host trust is not inherited by containers or VMs.

Debian / Ubuntu / Alpine:

```bash
cp ca-cert.pem /usr/local/share/ca-certificates/skytap.crt && update-ca-certificates
```

AlmaLinux / Rocky / RHEL / Fedora:

```bash
cp ca-cert.pem /etc/pki/ca-trust/source/anchors/skytap.crt && update-ca-trust extract
```

Arch / BlackArch / Manjaro:

```bash
cp ca-cert.pem /etc/ca-certificates/trust-source/anchors/skytap.crt && update-ca-trust
```

**Install CA here** in the UI installs into the OS where SkyTap itself is running. If the captured process lives in another container, install the PEM there too.

---

## Docker

Give the proxy `NET_ADMIN` and a `/data` volume. Put the workload in the same netns so `OUTPUT` redirect sees its traffic:

```yaml
services:
  skytap:
    cap_add: [NET_ADMIN]
    volumes: [data:/data]
  app:
    network_mode: "service:skytap"
```

The host firewall is not modified; rules live in the container namespace and are reapplied on restart.

---

## Incus

- **A** — `PreroutingRedirect` on a bridge (`incusbr0`).
- **B** — dedicated network; SkyTap instance is the gateway; rules only inside that instance.

```bash
incus file push /var/lib/skytap/ca/ca-cert.pem c1/usr/local/share/ca-certificates/skytap.crt
incus exec c1 -- update-ca-certificates
```

---

## HTTP API

| | |
|--|--|
| `GET /` | Embedded UI |
| `GET /domains` | Hosts, state, hits |
| `GET /flows?host=` | Recent flows |
| `GET /state?host=&state=` | `OBSERVED` / `INTERCEPTED` / `MOCKED` |
| `GET` / `POST` / `DELETE /rules` | Mock and rewrite rules |
| `GET /ca.pem` | Public CA |
| `POST /ca/trust` | Install CA on this machine (Linux) |
| `GET /ws?token=` | Live flows |
| `POST /mcp` | JSON-RPC tools |

```bash
curl -H "Authorization: Bearer $SKYTAP_ADMIN_TOKEN" \
  "http://127.0.0.1:8080/state?host=api.example.com&state=INTERCEPTED"
```

A seed domain `check.spy.net` is MOCKED with `{"license":"active"}` if you have no saved state.

Loop prevention: `ExcludeUID` is the proxy’s uid so its own upstream dials are not redirected (including uid 0).
