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

The runtime dependency on Ubuntu 24.04 is `libssl3t64` (`libcrypto.so.3`).
The backend implementation is in [src/library/tpm2/crypto/ossl](src/library/tpm2/crypto/ossl/).
[Dockerfile.test-swtpm](Dockerfile.test-swtpm) defines the Ubuntu 24.04 build
and test image.

## Testing

Initialize the reference submodules and run the Rust tests, ABI checks and
golden fixture audit from the repository root:

```bash
git submodule update --init --recursive
make check
```

With Docker available, `make test-golden` reproduces the reference responses
and `make test-swtpm-docker` runs the upstream swtpm tests against this library.
See [external-validation](external-validation/README.md) for tests using TPM
tools and client libraries.

## Timing tests

[timing-tests](timing-tests/) provides functional checks, timing searches,
independent dudect verification and candidate replay for the Rust library and
the upstream C libtpms. It was added for additional investigation and regression
checks around CVEs reported in upstream libtpms and the TPM reference code.
Scenarios cover RSA, ECC, symmetric cryptography, MACs, KDFs, key generation,
session authorization, integrity checks and DRBG. Controlled-state DRBG tests
use dedicated test builds.

Baseline scenarios and positive/negative controls have been checked on both
libraries in a Linux VM, including a short `check → search → verify → replay`
cycle. The full scenario catalog has also passed functional checks, with known
limitations reported as skips. This validates the framework's basic operation;
it does not establish constant-time behavior or confirm reproduction of a CVE.

The launcher requires Linux x86_64 and Rust 1.95.0 through rustup. Run
`python3 timing-tests/run.py --help` for options, then explicitly select a
`--scenario`, an `--area`, or the full `--campaign`. Without a selection it
prints guidance and starts no builds or measurements. A full timing campaign
can take many hours. Results are printed to stdout and saved as JSON.

One relevant example is [CVE-2026-6727](https://kb.cert.org/vuls/id/431093),
a timing side channel in RSA OAEP decoding in the TCG TPM 2.0 reference code.
Timing differences can expose information about ciphertexts encrypted to
TPM-managed RSA keys, including credential blobs, import blobs and session
salts. The [upstream libtpms fix](https://github.com/stefanberger/libtpms/commit/fd5b4174622032e131b70389b40ec6add4da3237)
states that libtpms is affected when built with
`--disable-use-openssl-functions` or `-DUSE_OPENSSL_FUNCTIONS_RSA=0`; typical
builds using OpenSSL's RSA functions are not affected.
