// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum Boundary {
    Exponentiation,
    Inverse,
    Product,
    Division,
    Primality,
    NativeKey,
    PointOperation,
    ScalarArithmetic,
    Signature,
    ImportReduction,
    Coordinates,
    #[cfg(test)]
    PointValidation,
    PublicReduction,
}

#[cfg(test)]
thread_local! {
    static ARMED: core::cell::Cell<Option<(Boundary, usize)>> = const { core::cell::Cell::new(None) };
    static FIRED: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
pub(in crate::library::tpm2) fn arm(boundary: Boundary, skipped: usize) {
    ARMED.with(|armed| armed.set(Some((boundary, skipped))));
}

#[cfg(test)]
pub(in crate::library::tpm2) fn disarm() -> bool {
    ARMED.with(|armed| armed.replace(None)).is_none()
}

#[cfg(test)]
pub(in crate::library::tpm2) fn fired() -> u64 {
    FIRED.with(core::cell::Cell::get)
}

#[cfg(test)]
pub(super) fn checkpoint(boundary: Boundary) -> Option<()> {
    let fail = ARMED.with(|armed| match armed.get() {
        Some((armed_boundary, 0)) if armed_boundary == boundary => {
            armed.set(None);
            true
        }
        Some((armed_boundary, skipped)) if armed_boundary == boundary => {
            armed.set(Some((armed_boundary, skipped - 1)));
            false
        }
        _ => false,
    });
    if fail {
        FIRED.with(|count| count.set(count.get() + 1));
        None
    } else {
        Some(())
    }
}

#[cfg(not(test))]
#[inline(always)]
pub(super) fn checkpoint(_boundary: Boundary) -> Option<()> {
    Some(())
}
