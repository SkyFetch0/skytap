#include "skytap_ssl_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifndef SKYTAP_SSL_PIN_DEFAULT
#define SKYTAP_SSL_PIN_DEFAULT "off"
#endif
#ifndef SKYTAP_SSL_CA_DEFAULT
#define SKYTAP_SSL_CA_DEFAULT "/certs/ca.crt"
#endif
#ifndef SKYTAP_SSL_PROXY_DEFAULT
#define SKYTAP_SSL_PROXY_DEFAULT "http://skytap:8080"
#endif
#ifndef SKYTAP_SSL_VERIFY_DEFAULT
#define SKYTAP_SSL_VERIFY_DEFAULT "ca"
#endif
#ifndef SKYTAP_SSL_PIN_OVERRIDE_DEFAULT
#define SKYTAP_SSL_PIN_OVERRIDE_DEFAULT ""
#endif
#ifndef SKYTAP_SSL_KEYLOG_DEFAULT
#define SKYTAP_SSL_KEYLOG_DEFAULT ""
#endif
#ifndef SKYTAP_SSL_IMPERSONATE_DEFAULT
#define SKYTAP_SSL_IMPERSONATE_DEFAULT "on"
#endif
#ifndef SKYTAP_SSL_ORIGIN_CERT_DIR_DEFAULT
#define SKYTAP_SSL_ORIGIN_CERT_DIR_DEFAULT "/certs/origin-cache"
#endif

static char g_pin[32];
static char g_ca[512];
static char g_proxy[256];
static char g_verify[16];
static char g_override[128];
static char g_keylog[512];
static char g_imp[8];
static char g_origdir[512];
static char g_imp_hosts[2048];
static char g_kit_hosts[2048];
static int g_loaded;
static time_t g_loaded_at;

static void trim(char *s)
{
  char *p = s;
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
    p++;
  if (p != s)
    memmove(s, p, strlen(p) + 1);
  size_t n = strlen(s);
  while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n'))
    s[--n] = 0;
}

static void apply_kv(const char *k, const char *v)
{
  if (!k || !v)
    return;
  if (!strcmp(k, "SKYTAP_SSL_PIN"))
    strncpy(g_pin, v, sizeof(g_pin) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_CA"))
    strncpy(g_ca, v, sizeof(g_ca) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_PROXY"))
    strncpy(g_proxy, v, sizeof(g_proxy) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_VERIFY"))
    strncpy(g_verify, v, sizeof(g_verify) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_PIN_OVERRIDE"))
    strncpy(g_override, v, sizeof(g_override) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_KEYLOG"))
    strncpy(g_keylog, v, sizeof(g_keylog) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_IMPERSONATE"))
    strncpy(g_imp, v, sizeof(g_imp) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_ORIGIN_CERT_DIR"))
    strncpy(g_origdir, v, sizeof(g_origdir) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_IMPERSONATE_HOSTS"))
    strncpy(g_imp_hosts, v, sizeof(g_imp_hosts) - 1);
  else if (!strcmp(k, "SKYTAP_SSL_KIT_HOSTS"))
    strncpy(g_kit_hosts, v, sizeof(g_kit_hosts) - 1);
}

static void load_conf(const char *path)
{
  FILE *f = fopen(path, "r");
  if (!f)
    return;
  char line[768];
  while (fgets(line, sizeof(line), f)) {
    if (line[0] == '#' || line[0] == ';')
      continue;
    char *eq = strchr(line, '=');
    if (!eq)
      continue;
    *eq = 0;
    trim(line);
    trim(eq + 1);
    apply_kv(line, eq + 1);
  }
  fclose(f);
}

static void load_once(void)
{
  const char *e;
  time_t now = time(NULL);
  if (g_loaded && now - g_loaded_at < 2)
    return;
  g_loaded = 1;
  g_loaded_at = now;
  g_imp_hosts[0] = 0;
  g_kit_hosts[0] = 0;
  strncpy(g_pin, SKYTAP_SSL_PIN_DEFAULT, sizeof(g_pin) - 1);
  strncpy(g_ca, SKYTAP_SSL_CA_DEFAULT, sizeof(g_ca) - 1);
  strncpy(g_proxy, SKYTAP_SSL_PROXY_DEFAULT, sizeof(g_proxy) - 1);
  strncpy(g_verify, SKYTAP_SSL_VERIFY_DEFAULT, sizeof(g_verify) - 1);
  strncpy(g_override, SKYTAP_SSL_PIN_OVERRIDE_DEFAULT, sizeof(g_override) - 1);
  strncpy(g_keylog, SKYTAP_SSL_KEYLOG_DEFAULT, sizeof(g_keylog) - 1);
  strncpy(g_imp, SKYTAP_SSL_IMPERSONATE_DEFAULT, sizeof(g_imp) - 1);
  strncpy(g_origdir, SKYTAP_SSL_ORIGIN_CERT_DIR_DEFAULT, sizeof(g_origdir) - 1);
  load_conf("/etc/skytap-ssl.conf");
  load_conf("/certs/skytap-ssl.conf");
  if ((e = getenv("SKYTAP_SSL_PIN")))
    strncpy(g_pin, e, sizeof(g_pin) - 1);
  if ((e = getenv("SKYTAP_SSL_CA")))
    strncpy(g_ca, e, sizeof(g_ca) - 1);
  if ((e = getenv("SKYTAP_SSL_PROXY")))
    strncpy(g_proxy, e, sizeof(g_proxy) - 1);
  if ((e = getenv("SKYTAP_SSL_VERIFY")))
    strncpy(g_verify, e, sizeof(g_verify) - 1);
  if ((e = getenv("SKYTAP_SSL_PIN_OVERRIDE")))
    strncpy(g_override, e, sizeof(g_override) - 1);
  if ((e = getenv("SKYTAP_SSL_KEYLOG")))
    strncpy(g_keylog, e, sizeof(g_keylog) - 1);
  if ((e = getenv("SSLKEYLOGFILE")) && !g_keylog[0])
    strncpy(g_keylog, e, sizeof(g_keylog) - 1);
  if ((e = getenv("SKYTAP_SSL_IMPERSONATE")))
    strncpy(g_imp, e, sizeof(g_imp) - 1);
  if ((e = getenv("SKYTAP_SSL_ORIGIN_CERT_DIR")))
    strncpy(g_origdir, e, sizeof(g_origdir) - 1);
  if ((e = getenv("SKYTAP_SSL_IMPERSONATE_HOSTS")))
    strncpy(g_imp_hosts, e, sizeof(g_imp_hosts) - 1);
  if ((e = getenv("SKYTAP_SSL_KIT_HOSTS")))
    strncpy(g_kit_hosts, e, sizeof(g_kit_hosts) - 1);
}

const char *skytap_pin_mode(void) { load_once(); return g_pin; }
const char *skytap_ca_path(void) { load_once(); return g_ca; }
const char *skytap_proxy(void) { load_once(); return g_proxy; }
const char *skytap_verify_mode(void) { load_once(); return g_verify; }
const char *skytap_pin_override(void) { load_once(); return g_override; }
const char *skytap_keylog_path(void) { load_once(); return g_keylog; }
int skytap_pin_is_off(void) { load_once(); return strcmp(g_pin, "on") != 0; }
int skytap_verify_is_none(void) { load_once(); return strcmp(g_verify, "none") == 0; }
static int host_in_list(const char *list, const char *host)
{
  char buf[2048];
  char *tok, *save = NULL;
  if (!host || !host[0])
    return 0;
  if (!list || !list[0])
    return 0;
  strncpy(buf, list, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  for (tok = strtok_r(buf, ", \t\n", &save); tok; tok = strtok_r(NULL, ", \t\n", &save)) {
    if (strcasecmp(tok, host) == 0)
      return 1;
  }
  return 0;
}

int skytap_impersonate_on(void)
{
  load_once();
  return strcmp(g_imp, "off") != 0;
}
const char *skytap_origin_cert_dir(void) { load_once(); return g_origdir; }

int skytap_impersonate_host(const char *host)
{
  load_once();
  if (!skytap_impersonate_on())
    return 0;
  return host_in_list(g_imp_hosts, host);
}

int skytap_kit_host(const char *host)
{
  load_once();
  if (!g_kit_hosts[0])
    return 1;
  return host_in_list(g_kit_hosts, host);
}
