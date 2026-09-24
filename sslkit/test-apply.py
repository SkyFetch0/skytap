#!/usr/bin/env python3
"""Download pinned curl/OpenSSL tarballs (cached) and prove the injectors apply.

Run from the skytap repo root:

    python sslkit/test-apply.py

Exits non-zero if a required injected string is missing. No compile.
"""
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, ".cache")

CURL_URLS = ["https://curl.se/download/curl-{v}.tar.gz"]
OPENSSL_URLS = [
    "https://www.openssl.org/source/openssl-{v}.tar.gz",
    "https://github.com/openssl/openssl/releases/download/openssl-{v}/openssl-{v}.tar.gz",
]

CURL_NEEDLES = ["skytap_ssl_policy.h", "skytap_pin_is_off"]
OPENSSL_NEEDLES = ["skytap_ca_path", "skytap_impersonate_leaf"]


def versions():
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "detect.py")],
        capture_output=True, text=True, check=True,
    )
    vals = {}
    for line in out.stdout.splitlines():
        if "=" in line and not line.startswith("NOTE="):
            k, _, v = line.partition("=")
            vals[k] = v.strip()
    return vals["CURL_VERSION"], vals["OPENSSL_VERSION"]


def fetch(name, urls):
    os.makedirs(CACHE, exist_ok=True)
    dest = os.path.join(CACHE, name)
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        print("cache hit %s" % dest)
        return dest
    last = None
    for url in urls:
        print("downloading %s" % url)
        try:
            urllib.request.urlretrieve(url, dest)
            return dest
        except Exception as exc:  # noqa: BLE001
            last = exc
            print("download failed: %s" % exc)
            if os.path.exists(dest):
                os.remove(dest)
    raise SystemExit("could not download %s: %s" % (name, last))


def extract(tarball, work):
    with tarfile.open(tarball, "r:gz") as tf:
        if hasattr(tarfile, "data_filter"):
            tf.extractall(work, filter="data")
        else:
            tf.extractall(work)
    tops = [d for d in os.listdir(work) if os.path.isdir(os.path.join(work, d))]
    if len(tops) != 1:
        raise SystemExit("unexpected tarball layout in %s: %s" % (tarball, tops))
    return os.path.join(work, tops[0])


def run_applier(script, src):
    r = subprocess.run([sys.executable, script, src], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        raise SystemExit("%s failed (exit %d)" % (os.path.basename(script), r.returncode))


def assert_contains(path, needles):
    text = open(path, encoding="utf-8", errors="replace").read()
    missing = [n for n in needles if n not in text]
    found = [n for n in needles if n in text]
    print("%s: found %s" % (os.path.basename(path), ", ".join(found)))
    if missing:
        raise SystemExit("missing in %s: %s" % (path, ", ".join(missing)))


def main():
    curl_ver, ssl_ver = versions()
    print("pins CURL_VERSION=%s OPENSSL_VERSION=%s" % (curl_ver, ssl_ver))

    curl_tb = fetch("curl-%s.tar.gz" % curl_ver,
                    [u.format(v=curl_ver) for u in CURL_URLS])
    ssl_tb = fetch("openssl-%s.tar.gz" % ssl_ver,
                   [u.format(v=ssl_ver) for u in OPENSSL_URLS])

    work = tempfile.mkdtemp(prefix="sslkit-apply-")
    try:
        curl_src = extract(curl_tb, os.path.join(work, "curl"))
        for name in ("skytap_ssl_policy.c", "skytap_ssl_policy.h"):
            shutil.copy(os.path.join(HERE, name), os.path.join(curl_src, "lib", name))
        run_applier(os.path.join(HERE, "apply_curl.py"), curl_src)
        assert_contains(os.path.join(curl_src, "lib", "setopt.c"), CURL_NEEDLES)

        ssl_src = extract(ssl_tb, os.path.join(work, "openssl"))
        for name in ("skytap_ssl_policy.c", "skytap_ssl_policy.h", "skytap_impersonate.c"):
            shutil.copy(os.path.join(HERE, name), os.path.join(ssl_src, "ssl", name))
        run_applier(os.path.join(HERE, "apply_openssl.py"), ssl_src)
        assert_contains(os.path.join(ssl_src, "ssl", "ssl_lib.c"), OPENSSL_NEEDLES)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("PASS")


if __name__ == "__main__":
    main()
