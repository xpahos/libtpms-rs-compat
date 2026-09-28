// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

pub(super) mod access;
pub(super) mod change_auth;
pub(super) mod define_space;
pub(super) mod lock;
pub(super) mod read;
pub(super) mod undefine_space;
pub(super) mod write;

#[cfg(test)]
pub(super) mod test_support;
