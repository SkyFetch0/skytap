#ifndef SKYTAP_SSL_POLICY_H
#define SKYTAP_SSL_POLICY_H

#ifdef __cplusplus
extern "C" {
#endif

/* pin: off = ignore CURLOPT_PINNEDPUBLICKEY; on = honor (optionally override hash) */
const char *skytap_pin_mode(void);
const char *skytap_ca_path(void);
const char *skytap_proxy(void);
const char *skytap_verify_mode(void); /* ca | none */
const char *skytap_pin_override(void);
const char *skytap_keylog_path(void);

int skytap_pin_is_off(void);
int skytap_verify_is_none(void);
int skytap_impersonate_on(void);
const char *skytap_origin_cert_dir(void);
int skytap_impersonate_host(const char *host);
int skytap_kit_host(const char *host);

#ifdef __cplusplus
}
#endif
#endif
