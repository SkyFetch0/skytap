# Isolated Linux smoke: does not touch host iptables.
# Requires Docker Desktop. Privileged so NET_ADMIN + nft work.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path (Join-Path $root "skydst"))) {
  $root = Split-Path -Parent $PSScriptRoot
  if (-not (Test-Path (Join-Path $root "skydst"))) {
    throw "skydst/ not found; run from a checkout that contains skydst, gomitm, and skytap"
  }
}

Write-Host "building image skytap-smoke..."
docker build -f "$root\Dockerfile.skytap" -t skytap-smoke "$root"

$cid = docker run -d --rm --privileged --name skytap-smoke-run `
  -e DEBIAN_FRONTEND=noninteractive `
  skytap-smoke -listen :3128 -admin 127.0.0.1:8080 -admin-token smoke -data /data -install-rules=true -mode output

try {
  Write-Host "waiting for CA..."
  $ok = $false
  for ($i = 0; $i -lt 30; $i++) {
    docker exec $cid test -f /data/ca/ca-cert.pem 2>$null
    if ($LASTEXITCODE -eq 0) { $ok = $true; break }
    Start-Sleep -Seconds 1
  }
  if (-not $ok) { docker logs $cid; throw "CA not created" }

  docker exec $cid sh -c "echo '1.1.1.1 check.spy.net' >> /etc/hosts"
  docker exec $cid sh -c "cp /data/ca/ca-cert.pem /usr/local/share/ca-certificates/skytap.crt && update-ca-certificates"

  Write-Host "=== mock (run as nobody so uid-0 proxy is excluded) ==="
  docker exec -u nobody $cid curl -sS --max-time 15 https://check.spy.net/
  if ($LASTEXITCODE -ne 0) { docker logs $cid; throw "mock curl failed" }

  Write-Host "`n=== passthrough example.com ==="
  docker exec -u nobody $cid curl -sS --max-time 20 -o /tmp/ex.html -w "http=%{http_code}`n" https://example.com/
  if ($LASTEXITCODE -ne 0) { docker logs $cid; throw "example.com curl failed" }
  docker exec $cid grep -qi example /tmp/ex.html
  if ($LASTEXITCODE -ne 0) { throw "example.com body unexpected" }

  Write-Host "SMOKE OK"
  docker logs $cid --tail 40
}
finally {
  docker rm -f skytap-smoke-run 2>$null | Out-Null
}
