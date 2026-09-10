#!/bin/sh
set -eu
# Run inside privileged Debian container with skytap already started.
# Usage: smoke.sh  (expects skytap on :3128/:8080, /data volume)

sleep 1
if [ ! -f /data/ca/ca-cert.pem ]; then
  echo "missing CA" >&2
  exit 1
fi
cp /data/ca/ca-cert.pem /usr/local/share/ca-certificates/skytap.crt
update-ca-certificates >/dev/null 2>&1 || true

echo "=== mock check.spy.net (must not leave the box) ==="
out=$(curl -sS --max-time 10 https://check.spy.net/ || true)
echo "body=$out"
echo "$out" | grep -q '"license":"active"'

echo "=== passthrough example.com ==="
code=$(curl -sS --max-time 20 -o /tmp/ex.html -w '%{http_code}' https://example.com/)
echo "http=$code"
test "$code" = "200"
grep -qi example /tmp/ex.html

echo "SMOKE OK"
