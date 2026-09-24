#!/usr/bin/env python3
"""Inject SkyTap CA/verify policy into OpenSSL 3.0 ssl/ssl_lib.c and build."""
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
p = root / "ssl" / "ssl_lib.c"
t = p.read_text(encoding="utf-8", errors="replace")
if "skytap_ssl_policy.h" not in t:
    needle = '#include "internal/ktls.h"'
    if needle not in t:
        sys.exit("ktls include missing")
    t = t.replace(
        needle,
        needle
        + '\n#include "skytap_ssl_policy.h"\n#include "skytap_ssl_policy.c"\n#include "skytap_impersonate.c"\n',
        1,
    )

old = """int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
    return X509_STORE_set_default_paths_ex(ctx->cert_store, ctx->libctx,
                                           ctx->propq);
}"""
new = """int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
    const char *ca = skytap_ca_path();
    if (ca && ca[0]) {
        if (SSL_CTX_load_verify_file(ctx, ca))
            return 1;
    }
    return X509_STORE_set_default_paths_ex(ctx->cert_store, ctx->libctx,
                                           ctx->propq);
}"""
if old not in t:
    sys.exit("SSL_CTX_set_default_verify_paths body mismatch")
t = t.replace(old, new, 1)

old = """int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CApath)
{
    if (CAfile == NULL && CApath == NULL)
        return 0;"""
new = """int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CApath)
{
    const char *ca = skytap_ca_path();
    if (ca && ca[0]) {
        CAfile = ca;
        CApath = NULL;
    }
    if (CAfile == NULL && CApath == NULL)
        return 0;"""
if old not in t:
    sys.exit("SSL_CTX_load_verify_locations body mismatch")
t = t.replace(old, new, 1)

old = """long SSL_get_verify_result(const SSL *ssl)
{
    return ssl->verify_result;
}"""
new = """long SSL_get_verify_result(const SSL *ssl)
{
    if (skytap_verify_is_none())
        return X509_V_OK;
    return ssl->verify_result;
}"""
if old not in t:
    sys.exit("SSL_get_verify_result body mismatch")
t = t.replace(old, new, 1)

old = """X509 *SSL_get0_peer_certificate(const SSL *s)
{
    if ((s == NULL) || (s->session == NULL))
        return NULL;
    else
        return s->session->peer;
}"""
new = """X509 *SSL_get0_peer_certificate(const SSL *s)
{
    X509 *imp;
    if ((imp = skytap_impersonate_leaf(s)) != NULL)
        return imp;
    if ((s == NULL) || (s->session == NULL))
        return NULL;
    else
        return s->session->peer;
}"""
if old not in t:
    sys.exit("SSL_get0_peer_certificate body mismatch")
t = t.replace(old, new, 1)

old = """STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s)
{
    STACK_OF(X509) *r;

    if ((s == NULL) || (s->session == NULL))
        r = NULL;
    else
        r = s->session->peer_chain;"""
new = """STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s)
{
    STACK_OF(X509) *r;
    STACK_OF(X509) *imp = skytap_chain_for_ssl(s);
    if (imp != NULL)
        return imp;

    if ((s == NULL) || (s->session == NULL))
        r = NULL;
    else
        r = s->session->peer_chain;"""
if old not in t:
    sys.exit("SSL_get_peer_cert_chain body mismatch")
t = t.replace(old, new, 1)

old = """STACK_OF(X509) *SSL_get0_verified_chain(const SSL *s)
{
    return s->verified_chain;
}"""
new = """STACK_OF(X509) *SSL_get0_verified_chain(const SSL *s)
{
    STACK_OF(X509) *imp = skytap_chain_for_ssl(s);
    if (imp != NULL)
        return imp;
    return s->verified_chain;
}"""
if old not in t:
    sys.exit("SSL_get0_verified_chain body mismatch")
t = t.replace(old, new, 1)

old = """long SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    long l;

    switch (cmd) {"""
new = """long SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    long l;
    if (cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME && parg)
        skytap_bind_host(s, (const char *)parg);

    switch (cmd) {"""
if old not in t:
    sys.exit("SSL_ctrl body mismatch")
t = t.replace(old, new, 1)

p.write_text(t, encoding="utf-8")

print("openssl patched")
