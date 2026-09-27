FROM golang:1.26.0-bookworm AS go
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim AS dotnet
FROM rust:1.95-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    acl autoconf autoconf-archive automake build-essential ca-certificates cmake \
    dbus expect gawk git iproute2 libcmocka-dev libcurl4-openssl-dev \
    libgcrypt20-dev libglib2.0-dev libgssapi-krb5-2 libicu72 libjson-c-dev libltdl-dev \
    libssl-dev libtool pandoc pkg-config procps python3 python3-cryptography \
    python3-yaml uthash-dev uuid-dev xxd zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go /usr/local/go /usr/local/go
COPY --from=dotnet /usr/share/dotnet /usr/share/dotnet
ENV PATH="/usr/local/go/bin:/usr/share/dotnet:${PATH}" \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    NUGET_PACKAGES=/work/cache/nuget GOMODCACHE=/work/cache/go-mod \
    GOCACHE=/work/cache/go-build CARGO_HOME=/work/cache/cargo \
    CARGO_TARGET_DIR=/work/cache/rust-target
WORKDIR /work
