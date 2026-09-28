// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

pub(super) mod allocate;
pub(super) mod event;
pub(super) mod extend;
pub(super) mod read;
pub(super) mod reset;
pub(super) mod update;

#[cfg(test)]
mod test_support;
