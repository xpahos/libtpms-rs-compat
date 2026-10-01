# libtpms-rs-compat

This project started because libtpms uses `longjmp`, which complicates using
the library from Go through WebAssembly.

C++ and Rust were considered. Rust was chosen to avoid an external C++
standard library dependency and for Cargo's build system.

The goal is to support this integration, not to rewrite everything in Rust.

## Building

RSA and ECC run on the system OpenSSL 3 `libcrypto` (dynamically linked, no
vendored copy). On Ubuntu 24.04:

```bash
sudo apt-get install build-essential pkg-config libssl-dev
cargo build --release
```

The runtime dependency is `libssl3t64` (`libcrypto.so.3`). See
[docs/openssl-backend](docs/openssl-backend/README.md) for the backend
boundary, the security assessment and the validation record;
`Dockerfile.test-swtpm` defines the Ubuntu 24.04 build and test image.
