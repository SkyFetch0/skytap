# SkyTap sslkit: patched OpenSSL + curl (Debian bookworm majors) + php8.2.
#
# Pins below match sslkit/detect.py, which is the source of truth
# (`python sslkit/detect.py` prints CURL_VERSION / OPENSSL_VERSION).
# Do not float these to "latest"; bookworm is curl 7.88.1 + OpenSSL 3.0.16.
#
# Build with the sslkit directory as context:
#   docker build -f sslkit/Dockerfile sslkit
FROM debian:bookworm-slim AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl wget python3 patch \
    zlib1g-dev libnghttp2-dev libidn2-dev libpsl-dev libbrotli-dev \
    pkg-config perl make autoconf automake libtool \
    xz-utils libxml2-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VERSION=3.0.16
ARG CURL_VERSION=7.88.1
WORKDIR /src
COPY skytap_ssl_policy.c skytap_ssl_policy.h skytap_impersonate.c apply_curl.py apply_openssl.py /src/kit/

# --- OpenSSL ---
RUN wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" -O /tmp/openssl.tgz \
 && tar -xzf /tmp/openssl.tgz -C /src \
 && mv /src/openssl-${OPENSSL_VERSION} /src/openssl
RUN cp /src/kit/skytap_ssl_policy.c /src/kit/skytap_ssl_policy.h /src/kit/skytap_impersonate.c /src/openssl/ssl/ \
 && python3 /src/kit/apply_openssl.py /src/openssl
WORKDIR /src/openssl
RUN ./Configure --prefix=/opt/skytap --libdir=lib linux-x86_64 shared no-tests \
 && make -j"$(nproc)" \
 && make install_sw

# --- curl / libcurl (against patched OpenSSL) ---
WORKDIR /src
RUN wget -q "https://curl.se/download/curl-${CURL_VERSION}.tar.gz" -O /tmp/curl.tgz \
 && tar -xzf /tmp/curl.tgz -C /src \
 && mv /src/curl-${CURL_VERSION} /src/curl
RUN cp /src/kit/skytap_ssl_policy.c /src/kit/skytap_ssl_policy.h /src/curl/lib/ \
 && python3 /src/kit/apply_curl.py /src/curl
WORKDIR /src/curl
ENV PKG_CONFIG_PATH=/opt/skytap/lib/pkgconfig
ENV LD_LIBRARY_PATH=/opt/skytap/lib
RUN ./configure --prefix=/opt/skytap --with-openssl=/opt/skytap --without-libpsl \
    --with-nghttp2 --enable-http --enable-proxy --disable-ldap --disable-manual \
 && make -j"$(nproc)" \
 && make install

# --- PHP 8.2.28 (bookworm) linked to patched OpenSSL + libcurl ---
WORKDIR /src
RUN wget -q "https://www.php.net/distributions/php-8.2.28.tar.xz" -O /tmp/php.txz \
 && tar -xJf /tmp/php.txz -C /src \
 && mv /src/php-8.2.28 /src/php
WORKDIR /src/php
ENV LDFLAGS="-L/opt/skytap/lib -Wl,-rpath,/opt/skytap/lib"
ENV CPPFLAGS="-I/opt/skytap/include"
RUN ./configure --prefix=/opt/skytap --with-openssl=/opt/skytap --with-curl=/opt/skytap \
    --enable-cli --disable-cgi --without-pear --disable-phpdbg --with-openssl-dir=/opt/skytap \
 && make -j"$(nproc)" \
 && make install

# --- runtime ---
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssl curl libcurl4 \
    libnghttp2-14 zlib1g libidn2-0 libbrotli1 libxml2 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/skytap /opt/skytap
ENV LD_LIBRARY_PATH=/opt/skytap/lib
ENV PATH=/opt/skytap/bin:$PATH
ENV SKYTAP_SSL_PIN=off
ENV SKYTAP_SSL_CA=/certs/ca.crt
ENV SKYTAP_SSL_PROXY=http://skytap:8080
ENV SKYTAP_SSL_VERIFY=ca
ENV SKYTAP_SSL_KEYLOG=/sslkeys/php-sslkeys.log
ENV SKYTAP_SSL_IMPERSONATE=on
ENV SKYTAP_SSL_ORIGIN_CERT_DIR=/certs/origin-cache
WORKDIR /opt/skytap
CMD ["php", "-v"]
