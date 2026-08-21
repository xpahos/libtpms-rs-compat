FROM debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef

COPY <<SOURCES_EOF /etc/apt/sources.list.d/debian.sources
Types: deb
URIs: http://snapshot.debian.org/archive/debian/20250811T000000Z
Suites: bookworm bookworm-updates
Components: main
Check-Valid-Until: no
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/20250811T000000Z
Suites: bookworm-security
Components: main
Check-Valid-Until: no
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
SOURCES_EOF

RUN apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update \
    && apt-get install -y --no-install-recommends \
        autoconf=2.71-3 \
        automake=1:1.16.5-1.3 \
        build-essential=12.9 \
        libfaketime=0.9.10-2.1 \
        libssl-dev=3.0.17-1~deb12u2 \
        libtool=2.4.7-7~deb12u1 \
        pkg-config=1.8.1-1 \
        python3=3.11.2-1+b1 \
    && rm -rf /var/lib/apt/lists/*

COPY libtpms/ /build/libtpms/

RUN cd /build/libtpms \
    && NOCONFIGURE=1 ./autogen.sh \
    && mkdir /build/libtpms-build \
    && cd /build/libtpms-build \
    && /build/libtpms/configure \
        --with-tpm2 \
        --with-openssl \
        --disable-shared \
        --disable-use-openssl-functions \
    && make -j"$(nproc)"

COPY scripts/golden_responses/ /build/golden_responses/

RUN cc -O2 -Wall -Wextra -Werror -o /usr/local/bin/golden-runner \
        /build/golden_responses/runner.c \
        -I/build/libtpms/include \
        /build/libtpms-build/src/.libs/libtpms.a \
        $(pkg-config --libs libcrypto)

RUN cc -shared -fPIC -O2 -Wall -Wextra -Werror \
        -o /usr/local/lib/entropy_shim.so \
        /build/golden_responses/entropy_shim.c

RUN set -eu; \
    lib="$(dpkg -L libfaketime | grep '/faketime/libfaketime\.so\.1$')"; \
    ln -s "$lib" /usr/local/lib/libfaketime.so.1

ENV LD_PRELOAD=/usr/local/lib/entropy_shim.so:/usr/local/lib/libfaketime.so.1 \
    FAKETIME="@2026-01-01 00:00:00 x0.0" \
    GOLDEN_ENTROPY_SEED=00000000c0ffee01

WORKDIR /build/golden_responses
ENTRYPOINT ["/usr/local/bin/golden-runner"]
