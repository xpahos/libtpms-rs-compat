# Licenses and authorship

libtpms-rs-compat is a Rust port of [libtpms v0.10.2](https://github.com/stefanberger/libtpms/tree/03ff2481e133540be3b3ffe3daa1483d2a73d967).
The original code was written by IBM and other contributors, including Ken
Goldman and Stefan Berger. Their copyright notices and license terms are
preserved in this project.

This project's own contributions are licensed under [BSD-3-Clause](../LICENSE).
The original [libtpms license](libtpms-LICENSE.txt) contains IBM's BSD-style
license and the Trusted Computing Group (TCG) terms for TPM 2 code. These terms
continue to apply to the corresponding ported code. Individual source files
may carry different copyright years and notices.

The Rust translation and additions are credited separately:

- Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
- Copyright (c) 2026 Yandex

The ABI/FFI layer uses [BSD-3-Clause](../LICENSE). Its Rust files have
short SPDX headers; the original upstream notices are collected here.

[libtpms-notices.txt](libtpms-notices.txt) contains the original authors,
copyright notices and full license terms. Each notice lists the upstream
files it covers, including files that have not been ported.

When redistributing the project, retain the applicable copyright notices,
license conditions and disclaimers with the source or in the materials
accompanying binaries. The copies in this directory are available without
checking out the original libtpms source tree.
