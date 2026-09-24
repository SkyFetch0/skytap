#!/usr/bin/env python3
"""Print the pinned curl and OpenSSL versions for the SkyTap sslkit.

Source of truth for which upstream tarballs the injectors target.
Prints two lines (and a third NOTE line when the host curl is untested):

    CURL_VERSION=7.88.1
    OPENSSL_VERSION=3.0.16

Env CURL_VERSION and OPENSSL_VERSION win when set.
"""
import os
import re
import subprocess

PIN_CURL = "7.88.1"
PIN_OPENSSL = "3.0.16"


def os_release():
    data = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                data[key] = val.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def curl_version_text():
    try:
        out = subprocess.run(
            ["curl", "--version"], capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if out.returncode != 0:
        return ""
    return (out.stdout or "").splitlines()[0] if out.stdout else ""


def parse_curl(text):
    m = re.match(r"curl\s+(\d+)\.(\d+)\.(\d+)", text or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def detect():
    env_curl = os.environ.get("CURL_VERSION", "").strip()
    env_ssl = os.environ.get("OPENSSL_VERSION", "").strip()
    if env_curl and env_ssl:
        return env_curl, env_ssl, None

    rel = os_release()
    ident = rel.get("ID", "").lower()
    like = rel.get("ID_LIKE", "").lower()
    codename = rel.get("VERSION_CODENAME", "").lower()
    parsed = parse_curl(curl_version_text())

    debian_family = ident in ("debian", "ubuntu") or "debian" in like.split()
    if debian_family and (codename == "bookworm" or (parsed and parsed[:2] == (7, 88))):
        curl, openssl, note = PIN_CURL, PIN_OPENSSL, None
    elif parsed is None:
        # No curl binary (typical Windows host without os-release): known-good pin.
        curl, openssl, note = PIN_CURL, PIN_OPENSSL, None
    elif parsed[:2] == (7, 88):
        curl, openssl, note = PIN_CURL, PIN_OPENSSL, None
    elif parsed[:2] == (8, 5):
        curl, openssl, note = "8.5.0", PIN_OPENSSL, None
    elif not rel:
        # No os-release (Windows host) and curl is some other build: still the pin.
        curl, openssl, note = PIN_CURL, PIN_OPENSSL, None
    else:
        curl, openssl, note = PIN_CURL, PIN_OPENSSL, "untested-curl-fallback"

    if env_curl:
        curl = env_curl
    if env_ssl:
        openssl = env_ssl
    return curl, openssl, note


def main():
    curl, openssl, note = detect()
    print("CURL_VERSION=%s" % curl)
    print("OPENSSL_VERSION=%s" % openssl)
    if note:
        print("NOTE=%s" % note)


if __name__ == "__main__":
    main()
