/* Included into ssl/ssl_lib.c. Maps SSL* -> origin X509 stack from PEM cache. */
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <pthread.h>

#ifndef SKYTAP_MAX_SSL
#define SKYTAP_MAX_SSL 256
#endif

struct skytap_ssl_face {
    const SSL *ssl;
    char host[256];
    STACK_OF(X509) *chain;
};

static pthread_mutex_t g_face_mu = PTHREAD_MUTEX_INITIALIZER;
static struct skytap_ssl_face g_faces[SKYTAP_MAX_SSL];
static char g_last_host[256];

static void skytap_note_host(const char *name)
{
    if (!name || !name[0])
        return;
    pthread_mutex_lock(&g_face_mu);
    strncpy(g_last_host, name, sizeof(g_last_host) - 1);
    pthread_mutex_unlock(&g_face_mu);
}

static STACK_OF(X509) *skytap_load_origin_chain(const char *host)
{
    char path[768];
    FILE *fp;
    STACK_OF(X509) *sk;
    X509 *x;

    if (!host || !host[0])
        return NULL;
    snprintf(path, sizeof(path), "%s/%s.pem", skytap_origin_cert_dir(), host);
    fp = fopen(path, "r");
    if (!fp)
        return NULL;
    sk = sk_X509_new_null();
    while ((x = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL)
        sk_X509_push(sk, x);
    fclose(fp);
    if (sk_X509_num(sk) == 0) {
        sk_X509_free(sk);
        return NULL;
    }
    return sk;
}

static struct skytap_ssl_face *skytap_face(const SSL *s, int create)
{
    int i, empty = -1;
    struct skytap_ssl_face *f = NULL;
    pthread_mutex_lock(&g_face_mu);
    for (i = 0; i < SKYTAP_MAX_SSL; i++) {
        if (g_faces[i].ssl == s) {
            f = &g_faces[i];
            break;
        }
        if (empty < 0 && g_faces[i].ssl == NULL)
            empty = i;
    }
    if (!f && create && empty >= 0) {
        f = &g_faces[empty];
        memset(f, 0, sizeof(*f));
        f->ssl = s;
        if (g_last_host[0])
            strncpy(f->host, g_last_host, sizeof(f->host) - 1);
    }
    pthread_mutex_unlock(&g_face_mu);
    return f;
}

static void skytap_bind_host(const SSL *s, const char *name)
{
    struct skytap_ssl_face *f;
    if (!s || !name || !name[0])
        return;
    skytap_note_host(name);
    f = skytap_face(s, 1);
    if (!f)
        return;
    pthread_mutex_lock(&g_face_mu);
    strncpy(f->host, name, sizeof(f->host) - 1);
    if (f->chain) {
        sk_X509_pop_free(f->chain, X509_free);
        f->chain = NULL;
    }
    pthread_mutex_unlock(&g_face_mu);
}

static STACK_OF(X509) *skytap_chain_for_ssl(const SSL *s)
{
    struct skytap_ssl_face *f;
    STACK_OF(X509) *sk;
    char host[256];
    const char *sni;

    if (!skytap_impersonate_on() || s == NULL)
        return NULL;
    sni = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    f = skytap_face(s, 1);
    pthread_mutex_lock(&g_face_mu);
    host[0] = 0;
    if (sni && sni[0])
        strncpy(host, sni, sizeof(host) - 1);
    else if (f && f->host[0])
        strncpy(host, f->host, sizeof(host) - 1);
    else if (g_last_host[0])
        strncpy(host, g_last_host, sizeof(host) - 1);
    if (f && f->chain && f->host[0] && strcmp(f->host, host) == 0) {
        sk = f->chain;
        pthread_mutex_unlock(&g_face_mu);
        return sk;
    }
    pthread_mutex_unlock(&g_face_mu);
    if (!host[0])
        return NULL;
    if (!skytap_impersonate_host(host))
        return NULL;
    sk = skytap_load_origin_chain(host);
    if (!sk)
        return NULL;
    pthread_mutex_lock(&g_face_mu);
    if (f) {
        if (f->chain)
            sk_X509_pop_free(f->chain, X509_free);
        f->chain = sk;
        strncpy(f->host, host, sizeof(f->host) - 1);
    }
    pthread_mutex_unlock(&g_face_mu);
    return sk;
}

static X509 *skytap_impersonate_leaf(const SSL *s)
{
    STACK_OF(X509) *sk = skytap_chain_for_ssl(s);
    if (!sk || sk_X509_num(sk) < 1)
        return NULL;
    return sk_X509_value(sk, 0);
}
