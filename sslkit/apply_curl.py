#!/usr/bin/env python3
"""Inject SkyTap policy into curl 7.88.1 lib/setopt.c + Makefile.inc."""
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
setopt = (root / "lib" / "setopt.c").read_text(encoding="utf-8", errors="replace")
if "skytap_ssl_policy.h" not in setopt:
    needle = '#include "setopt.h"'
    if needle not in setopt:
        sys.exit("setopt.h include not found")
    setopt = setopt.replace(
        needle, needle + '\n#include "skytap_ssl_policy.h"\n#include "skytap_ssl_policy.c"\n', 1
    )

hook = r'''
  if(result == CURLE_OK && data) {
    if(tag == CURLOPT_PINNEDPUBLICKEY || tag == CURLOPT_PROXY_PINNEDPUBLICKEY) {
      if(skytap_pin_is_off())
        result = Curl_setstropt(&data->set.str[STRING_SSL_PINNEDPUBLICKEY], NULL);
      else if(skytap_pin_override() && skytap_pin_override()[0]) {
        char pinbuf[160];
        msnprintf(pinbuf, sizeof(pinbuf), "sha256//%s", skytap_pin_override());
        result = Curl_setstropt(&data->set.str[STRING_SSL_PINNEDPUBLICKEY], pinbuf);
      }
    }
    if(skytap_proxy() && skytap_proxy()[0]) {
      const char *px = skytap_proxy();
      (void)Curl_setstropt(&data->set.str[STRING_PROXY], px);
      if(!strncmp(px, "socks5h://", 10) || !strncmp(px, "socks5://", 9))
        data->set.proxytype = CURLPROXY_SOCKS5_HOSTNAME;
      else
        data->set.proxytype = CURLPROXY_HTTP;
    }
    if(skytap_ca_path() && skytap_ca_path()[0])
      (void)Curl_setstropt(&data->set.str[STRING_SSL_CAFILE], skytap_ca_path());
    data->set.ssl.primary.verifypeer = skytap_verify_is_none() ? FALSE : TRUE;
    data->set.ssl.primary.verifyhost = skytap_verify_is_none() ? 0 : 2;
    if(skytap_keylog_path() && skytap_keylog_path()[0])
      setenv("SSLKEYLOGFILE", skytap_keylog_path(), 1);
    if(tag == CURLOPT_SSL_VERIFYPEER)
      data->set.ssl.primary.verifypeer = skytap_verify_is_none() ? FALSE : TRUE;
    if(tag == CURLOPT_SSL_VERIFYHOST)
      data->set.ssl.primary.verifyhost = skytap_verify_is_none() ? 0 : 2;
    if(tag == CURLOPT_CAINFO && skytap_ca_path() && skytap_ca_path()[0])
      result = Curl_setstropt(&data->set.str[STRING_SSL_CAFILE], skytap_ca_path());
    if(tag == CURLOPT_PROXY && skytap_proxy() && skytap_proxy()[0])
      result = Curl_setstropt(&data->set.str[STRING_PROXY], skytap_proxy());
  }
'''

old = """  result = Curl_vsetopt(data, tag, arg);

  va_end(arg);
  return result;
}"""
new = f"""  result = Curl_vsetopt(data, tag, arg);
{hook}
  va_end(arg);
  return result;
}}"""
if old not in setopt:
    # try CRLF
    old2 = old.replace("\n", "\r\n")
    if old2 in setopt:
        setopt = setopt.replace(old2, new.replace("\n", "\r\n"), 1)
    else:
        sys.exit("curl_easy_setopt tail not found")
else:
    setopt = setopt.replace(old, new, 1)

(root / "lib" / "setopt.c").write_text(setopt, encoding="utf-8")

print("curl patched")
