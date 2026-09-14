# SkyTap pin-lab (Docker Compose)

Pinning is **client-side**. SkyTap terminates TLS with its own CA; it does not break SPKI pins. The lab client pins the **origin** leaf SPKI. Bypass skips that check (still trusts SkyTap CA).

## Bring up

From `e:\software\github`:

```bash
docker compose -f docker-compose.lab.yml up --build --abort-on-container-exit
```

Services:

| Service | Ports | Role |
|---------|-------|------|
| `skytap` | compose: 8080 CONNECT, 1080 SOCKS5, 9090 UI (host mapped 18080/11080/19090 if 8080 busy) | MITM |
| `origin` | internal 443 `pinlab.internal` | pinned HTTPS origin |
| `pin-lab` | — | curl + Go pin client tests |

Volumes: `certs` (`ca.crt`, `origin.pem`, `origin-pin.txt`), `sslkeys` (`sslkeys.log`), `skytap-data`.

CA is created on first skytap start (`gomitm.LoadOrCreateCA`) and copied to `/certs/ca.crt`.

## Pin hash

Inside pin-lab (also done by `run-tests.sh`):

```bash
openssl x509 -in /certs/origin.pem -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

That value is `PIN_SPKI_SHA256` (origin SPKI, not SkyTap CA).

## Panel bypass

UI (host): http://127.0.0.1:19090/ → **SSL pin lab** → Enable/Disable.

API: `POST http://skytap:9090/pin-bypass` `{"enabled":true}` (lab: `SKYTAP_ALLOW_OPEN_ADMIN=1`).

## Protocol — last run (2026-09-14)

Origin pin (openssl SPKI SHA-256, this volume): `BZAhLh/dcbGb+KVVESsKJYah9BF9Y7DasCVX3peQlhA=`  
MITM leaf presented (CN=pinlab.internal): `GAQtiFv/xKb0R+vlk7F7+LIH9SvqTpgkm1l5PRsW/eg=`

| Step | Command / path | Result |
|------|----------------|--------|
| 1 unpinned curl CONNECT | `curl --proxy http://skytap:8080 --cacert /certs/ca.crt https://pinlab.internal/` | `curl_exit=0` `http_code=200` body `{"ok":true,...}` |
| 2 pin ON bypass OFF | `PIN_MODE=on` pinclient | `pin_fail_exit=2` `pinning failure: expected BZAh… got GAQti…` |
| 3 panel bypass | `POST /pin-bypass {"enabled":true}` then `PIN_MODE=auto` | `pin_ok_exit=0` `pin check SKIPPED` `status=200` |
| 4 SOCKS5 | `curl --socks5-hostname skytap:1080 --cacert /certs/ca.crt https://pinlab.internal/` | `socks_exit=0` `http_code=200` |
| 5 intercept | `GET /flows?host=pinlab.internal` | `status: 200` `res_body` JSON |
| 5 keylog | volume `sslkeys` `/sslkeys/sslkeys.log` | `keylog_bytes=2528` `CLIENT_HANDSHAKE_TRAFFIC_SECRET` TLS 1.3 |

Compose summary: `curl=0 pin_fail=2 pin_ok=0 socks=0` **PIN LAB PASS**.

## sslkit (patched libcurl 7.88.1 + OpenSSL 3.0.16 + PHP 8.2.28)

```bash
docker compose -f docker-compose.lab.yml up --build --abort-on-container-exit sslkit
```

Env: `SKYTAP_SSL_PIN=off` `SKYTAP_SSL_CA=/certs/ca.crt` `SKYTAP_SSL_PROXY=http://skytap:8080` `SKYTAP_SSL_VERIFY=ca`.

Last run: stock `--pinnedpubkey` **exit 90**; patched curl/PHP **200**; `ldd` → `/opt/skytap/lib/libcurl.so.4` + `libssl.so.3`. ionCube loader is not in the image; same `.so` path would apply.

### Cert impersonation (peer API face)

SkyTap dumps origin chain to `/certs/origin-cache/<sni>.pem` **before** client handshake. Yamalı libssl `SSL_get0_peer_certificate` / `SSL_get_peer_cert_chain` / `SSL_get0_verified_chain` returns that X509. Handshake still uses MITM key (`sslkeys.log`).

Env: `SKYTAP_SSL_IMPERSONATE=on|off` `SKYTAP_SSL_ORIGIN_CERT_DIR=/certs/origin-cache`.

| | IMPERSONATE | peer issuer | PEER_SPKI vs origin `LghICaNq+5vmm9053Oi386zWem4kYxujTgBfacQJA5E=` |
|--|--|--|--|
| A | off | `SkyTap Root CA` | `viRq/WTbNLIST0tKxDQTOVC90o5gt/ZE1IwQQSSKJEY=` **match=no** HTTP 200 |
| B | on | `CN=pinlab.internal` | **same origin SPKI match=yes** HTTP 200 |
| C | on | CURLINFO issuer origin not SkyTap | CERTINFO_ISS=`CN = pinlab.internal` |
| E | on + PIN=on | origin pin CURLOPT | HTTP 200 match=yes |
| G | — | keylog `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | MITM secrets still written |

Go `crypto/tls` does **not** use libssl; `ConnectionState.PeerCertificates` swap would be a separate Go binary. Java JSSE likewise.

## Limits

Android emulator / Frida / OkHttp are not in this compose. Proof is Go `crypto/tls` `VerifyPeerCertificate` SPKI pin vs the same binary with panel-driven skip. No host-network; compose DNS `skytap` / `pinlab.internal`. Host 8080 was already taken so UI/proxy map to 19090/18080/11080.
