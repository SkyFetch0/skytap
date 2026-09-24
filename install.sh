#!/bin/sh
# SkyTap one-shot installer for Linux (Debian 11/12, Ubuntu, Alma, Rocky, Fedora, Arch).
# Usage (from a clone of this repo):
#   sudo ./install.sh
# Env:
#   PREFIX=/usr/local   LISTEN=:3128   ADMIN=127.0.0.1:8080
#   DATA=/var/lib/skytap   TOKEN=   (empty = loopback-only admin)

set -eu

PREFIX="${PREFIX:-/usr/local}"
LISTEN="${LISTEN:-:3128}"
ADMIN="${ADMIN:-127.0.0.1:8080}"
DATA="${DATA:-/var/lib/skytap}"
TOKEN="${TOKEN:-}"
UNIT=/etc/systemd/system/skytap.service

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0" >&2
    exit 1
  fi
}

detect() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo unknown
  fi
}

pkg_go() {
  id=$(detect)
  case "$id" in
    debian|ubuntu)
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go ca-certificates nftables iptables >/dev/null
      ;;
    fedora|rhel|centos|almalinux|rocky)
      if command -v dnf >/dev/null; then
        dnf install -y golang ca-certificates nftables iptables >/dev/null
      else
        yum install -y golang ca-certificates iptables >/dev/null
      fi
      ;;
    arch|manjaro)
      pacman -Sy --noconfirm go ca-certificates nftables iptables >/dev/null
      ;;
    alpine)
      apk add --no-cache go ca-certificates iptables nftables >/dev/null
      ;;
    *)
      echo "unknown distro $id — install Go 1.22+ and nftables/iptables yourself" >&2
      ;;
  esac
}

need_root
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"

if ! command -v go >/dev/null 2>&1; then
  echo "installing Go…"
  pkg_go
fi
command -v go >/dev/null 2>&1 || { echo "go not found"; exit 1; }

echo "building skytap…"
go build -o "$PREFIX/bin/skytap" .

mkdir -p "$DATA/ca"
id skytap >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin skytap || true
chown -R skytap:skytap "$DATA" 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1; then
  cat >"$UNIT" <<EOF
[Unit]
Description=SkyTap intercept proxy
After=network.target

[Service]
Type=simple
User=root
ExecStart=$PREFIX/bin/skytap -listen $LISTEN -admin $ADMIN -data $DATA -install-rules=true -mode output ${TOKEN:+-admin-token $TOKEN}
ExecStop=/bin/sh -c 'nft delete table ip skytap 2>/dev/null || true'
KillMode=mixed
TimeoutStopSec=5
Restart=on-failure
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now skytap.service
  echo "started: systemctl status skytap"
else
  echo "no systemd — run:"
  echo "  $PREFIX/bin/skytap -listen $LISTEN -admin $ADMIN -data $DATA -install-rules=true"
fi

echo "admin UI: http://${ADMIN#*:}/  (bind $ADMIN)"
echo "CA PEM: $DATA/ca/ca-cert.pem — install on intercepted *clients* (see README)."
