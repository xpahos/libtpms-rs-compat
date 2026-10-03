// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use core::cell::{Cell, RefCell};
use core::marker::PhantomData;

const RUNNING_ON_VALGRIND: usize = 0x1001;
const MAKE_MEM_UNDEFINED: usize = 0x4d43_0001;
const MAKE_MEM_DEFINED: usize = 0x4d43_0002;
const GET_VBITS: usize = 0x4d43_0008;
const COUNT_ERRORS: usize = 0x1201;

thread_local! {
    static CONCEALING: Cell<bool> = const { Cell::new(false) };
    static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) };
}

#[cfg(target_arch = "aarch64")]
fn client_request(default: usize, arguments: [usize; 6]) -> usize {
    let result: usize;
    // SAFETY: the four rotations of x12 add up to 128 bits and `orr x10, x10, x10`
    // leaves x10 unchanged, so on hardware the sequence only copies the default into
    // the result. Valgrind recognises the same sequence as a client request that
    // reads the six words behind x4, which stay alive for the whole block.
    unsafe {
        core::arch::asm!(
            "ror x12, x12, #3",
            "ror x12, x12, #13",
            "ror x12, x12, #51",
            "ror x12, x12, #61",
            "orr x10, x10, x10",
            inout("x3") default => result,
            in("x4") arguments.as_ptr(),
            options(nostack),
        );
    }
    result
}

#[cfg(target_arch = "x86_64")]
fn client_request(default: usize, arguments: [usize; 6]) -> usize {
    let result: usize;
    // SAFETY: the four rotations of rdi add up to 128 bits and `xchg rbx, rbx` swaps
    // a register with itself, so on hardware the sequence only copies the default
    // into the result. Valgrind recognises it as a client request that reads the six
    // words behind rax, which stay alive for the whole block.
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            inout("rdx") default => result,
            in("rax") arguments.as_ptr(),
            options(nostack),
        );
    }
    result
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn client_request(default: usize, _arguments: [usize; 6]) -> usize {
    default
}

fn request(request: usize, address: usize, length: usize) -> usize {
    client_request(0, [request, address, length, 0, 0, 0])
}

pub(super) fn running_on_valgrind() -> bool {
    request(RUNNING_ON_VALGRIND, 0, 0) != 0
}

pub(in crate::library::tpm2) fn error_count() -> usize {
    request(COUNT_ERRORS, 0, 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum Shadow {
    Defined,
    Undefined,
    Mixed,
    Unavailable,
}

pub(in crate::library::tpm2) fn shadow(bytes: &[u8]) -> Shadow {
    match vbits(bytes) {
        None => Shadow::Unavailable,
        Some(vbits) if vbits.iter().all(|&bits| bits == 0) => Shadow::Defined,
        Some(vbits) if vbits.iter().all(|&bits| bits == 0xff) => Shadow::Undefined,
        Some(_) => Shadow::Mixed,
    }
}

pub(in crate::library::tpm2) fn undefined_bytes(bytes: &[u8]) -> Option<usize> {
    vbits(bytes).map(|vbits| vbits.iter().filter(|&&bits| bits != 0).count())
}

pub(in crate::library::tpm2) fn undefined_bit_positions(bytes: &[u8]) -> Option<Vec<bool>> {
    let vbits = vbits(bytes)?;
    let mut positions = Vec::with_capacity(vbits.len() * 8);
    for byte in vbits.iter().rev() {
        for bit in 0..8 {
            positions.push(byte >> bit & 1 == 1);
        }
    }
    Some(positions)
}

fn vbits(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut vbits = vec![0u8; bytes.len()];
    let status = client_request(
        0,
        [
            GET_VBITS,
            bytes.as_ptr() as usize,
            vbits.as_mut_ptr() as usize,
            bytes.len(),
            0,
            0,
        ],
    );
    if status != 1 {
        return None;
    }
    request(MAKE_MEM_DEFINED, vbits.as_ptr() as usize, vbits.len());
    Some(vbits)
}

pub(in crate::library::tpm2) fn memcheck_active() -> bool {
    let probe = [0x5au8; 16];
    request(MAKE_MEM_UNDEFINED, probe.as_ptr() as usize, probe.len());
    let concealed = shadow(&probe);
    request(MAKE_MEM_DEFINED, probe.as_ptr() as usize, probe.len());
    let revealed = shadow(&probe);
    concealed == Shadow::Undefined && revealed == Shadow::Defined
}

pub(in crate::library::tpm2) fn require_memcheck() {
    assert!(
        memcheck_active(),
        "this diagnostic needs Valgrind's Memcheck tool: the shadow-state probe failed"
    );
}

fn mode() -> bool {
    CONCEALING.with(Cell::get)
}

fn replace_mode(concealing: bool) -> bool {
    CONCEALING.with(|mode| mode.replace(concealing))
}

#[must_use = "the marking mode is restored when the scope is dropped"]
pub(super) struct MarkingScope {
    previous: bool,
    _thread_bound: PhantomData<*const ()>,
}

impl MarkingScope {
    pub(super) fn concealed() -> Self {
        Self::enter(true)
    }

    pub(super) fn control() -> Self {
        Self::enter(false)
    }

    fn enter(concealing: bool) -> Self {
        Self {
            previous: replace_mode(concealing),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for MarkingScope {
    fn drop(&mut self) {
        replace_mode(self.previous);
    }
}

pub(super) fn concealing() -> bool {
    mode()
}

pub(in crate::library::tpm2) fn secret(bytes: &[u8]) {
    if mode() {
        request(MAKE_MEM_UNDEFINED, bytes.as_ptr() as usize, bytes.len());
    }
}

pub(in crate::library::tpm2) fn secret_words(words: &[u64]) {
    if mode() {
        request(
            MAKE_MEM_UNDEFINED,
            words.as_ptr() as usize,
            core::mem::size_of_val(words),
        );
    }
}

pub(in crate::library::tpm2) fn public(bytes: &[u8]) {
    request(MAKE_MEM_DEFINED, bytes.as_ptr() as usize, bytes.len());
}

pub(in crate::library::tpm2) fn observe(label: &'static str, bytes: &[u8]) {
    record_observation(|| label.to_string(), bytes);
}

pub(in crate::library::tpm2) fn observe_case(label: impl FnOnce() -> String, bytes: &[u8]) {
    record_observation(label, bytes);
}

fn recording() -> bool {
    TRACE.with(|trace| trace.borrow().is_some())
}

fn record_observation(label: impl FnOnce() -> String, bytes: &[u8]) {
    if recording() {
        let state = shadow(bytes);
        let label = label();
        TRACE.with(|trace| {
            if let Some(trace) = trace.borrow_mut().as_mut() {
                trace.observations.push((label, state));
            }
        });
    }
}

pub(in crate::library::tpm2) fn publications_recorded() -> usize {
    TRACE.with(|trace| {
        trace
            .borrow()
            .as_ref()
            .map_or(0, |trace| trace.publications.len())
    })
}

pub(in crate::library::tpm2) fn publish(label: &'static str, bytes: &[u8]) {
    if recording() {
        let publication = Publication {
            label,
            before: shadow(bytes),
            undefined: undefined_bytes(bytes),
        };
        TRACE.with(|trace| {
            if let Some(trace) = trace.borrow_mut().as_mut() {
                trace.publications.push(publication);
            }
        });
    }
    public(bytes);
}

#[derive(Clone, Debug)]
pub(in crate::library::tpm2) struct Publication {
    pub(in crate::library::tpm2) label: &'static str,
    pub(in crate::library::tpm2) before: Shadow,
    pub(in crate::library::tpm2) undefined: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub(in crate::library::tpm2) struct Trace {
    observations: Vec<(String, Shadow)>,
    publications: Vec<Publication>,
}

impl Trace {
    pub(in crate::library::tpm2) fn states(&self, label: &str) -> Vec<Shadow> {
        self.observations
            .iter()
            .filter(|(entry, _)| entry == label)
            .map(|(_, state)| *state)
            .collect()
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn all(&self, label: &str, expected: Shadow) -> usize {
        let observed = self.states(label);
        assert!(!observed.is_empty(), "`{label}` was never observed");
        assert!(
            observed.iter().all(|state| *state == expected),
            "`{label}` expected {expected:?}, observed {observed:?}"
        );
        observed.len()
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn tainted(&self, label: &str) -> usize {
        let observed = self.states(label);
        assert!(!observed.is_empty(), "`{label}` was never observed");
        assert!(
            observed
                .iter()
                .all(|state| matches!(state, Shadow::Undefined | Shadow::Mixed)),
            "`{label}` expected secret bits, observed {observed:?}"
        );
        observed.len()
    }

    pub(in crate::library::tpm2) fn observations(&self) -> &[(String, Shadow)] {
        &self.observations
    }

    pub(in crate::library::tpm2) fn publications(&self) -> &[Publication] {
        &self.publications
    }

    pub(in crate::library::tpm2) fn published(&self, label: &str) -> Vec<&Publication> {
        self.publications
            .iter()
            .filter(|publication| publication.label == label)
            .collect()
    }
}

#[must_use = "the trace stops when the recorder is dropped"]
pub(super) struct Recorder {
    previous: Option<Trace>,
    _thread_bound: PhantomData<*const ()>,
}

impl Recorder {
    pub(super) fn start() -> Self {
        Self {
            previous: TRACE.with(|trace| trace.borrow_mut().replace(Trace::default())),
            _thread_bound: PhantomData,
        }
    }

    pub(super) fn trace(&self) -> Trace {
        TRACE.with(|trace| trace.borrow().clone().unwrap_or_default())
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        let previous = self.previous.take();
        TRACE.with(|trace| *trace.borrow_mut() = previous);
    }
}

pub(in crate::library::tpm2) fn traced<T>(conceal: bool, run: impl FnOnce() -> T) -> (T, Trace) {
    require_memcheck();
    let _scope = if conceal {
        MarkingScope::concealed()
    } else {
        MarkingScope::control()
    };
    let recorder = Recorder::start();
    let value = run();
    let trace = recorder.trace();
    (value, trace)
}

pub(in crate::library::tpm2) fn verification_copy(bytes: &[u8]) -> Vec<u8> {
    let length = [bytes.len()];
    request(
        MAKE_MEM_DEFINED,
        length.as_ptr() as usize,
        core::mem::size_of_val(&length),
    );
    // SAFETY: `length` is a live local; the volatile read takes the length
    // from memory whose shadow state was just set to defined.
    let length = unsafe { core::ptr::read_volatile(length.as_ptr()) };
    let copy: Vec<u8> = bytes[..length].to_vec();
    public(&copy);
    copy
}

pub(super) fn canary(tainted: bool) -> u8 {
    let table: Vec<u8> = (0..=255u8).collect();
    let index = [3u8];
    if tainted {
        request(MAKE_MEM_UNDEFINED, index.as_ptr() as usize, 1);
    }
    // SAFETY: `index` is a live one-byte local; the volatile read only
    // forces the load to happen after the client request.
    let position = unsafe { core::ptr::read_volatile(index.as_ptr()) };
    let selected = if position < 128 {
        [table[usize::from(position)]]
    } else {
        [0]
    };
    public(&selected);
    selected[0]
}

pub(super) fn scoped_canary(byte: u8) -> u8 {
    let table: Vec<u8> = (0..=255u8).collect();
    let marked = [byte];
    secret(&marked);
    // SAFETY: `marked` is a live one-byte local; the volatile read forces the
    // load to happen after the client request issued by `secret`.
    let value = unsafe { core::ptr::read_volatile(marked.as_ptr()) };
    let selected = [table[usize::from(core::hint::black_box(value))]];
    public(&selected);
    selected[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Observations {
        concealed_while_control_active: bool,
        control_while_concealed_active: bool,
        concealed_thread_after_exit: bool,
        control_thread_after_exit: bool,
    }

    fn interleave<S>(
        enter: impl Fn(bool) -> S + Sync,
        current: impl Fn() -> bool + Sync,
    ) -> Observations {
        let barrier = Barrier::new(2);
        std::thread::scope(|threads| {
            let concealed = threads.spawn(|| {
                let scope = enter(true);
                barrier.wait();
                barrier.wait();
                let during = current();
                barrier.wait();
                drop(scope);
                barrier.wait();
                barrier.wait();
                (during, current())
            });
            let control = threads.spawn(|| {
                barrier.wait();
                let scope = enter(false);
                barrier.wait();
                let during = current();
                barrier.wait();
                barrier.wait();
                drop(scope);
                barrier.wait();
                (during, current())
            });
            let (concealed_during, concealed_after) = concealed.join().unwrap();
            let (control_during, control_after) = control.join().unwrap();
            Observations {
                concealed_while_control_active: concealed_during,
                control_while_concealed_active: control_during,
                concealed_thread_after_exit: concealed_after,
                control_thread_after_exit: control_after,
            }
        })
    }

    static LEGACY_GLOBAL: AtomicBool = AtomicBool::new(false);

    struct LegacyCall;

    impl Drop for LegacyCall {
        fn drop(&mut self) {
            LEGACY_GLOBAL.store(false, Ordering::SeqCst);
        }
    }

    fn legacy_enter(concealing: bool) -> LegacyCall {
        LEGACY_GLOBAL.store(concealing, Ordering::SeqCst);
        LegacyCall
    }

    #[test]
    fn the_previous_process_global_mode_lets_concurrent_tests_interfere() {
        let observed = interleave(legacy_enter, || LEGACY_GLOBAL.load(Ordering::SeqCst));
        assert!(
            !observed.concealed_while_control_active,
            "a control test disabled marking inside a concealed test"
        );
        LEGACY_GLOBAL.store(true, Ordering::SeqCst);
        let panicked = std::panic::catch_unwind(|| {
            LEGACY_GLOBAL.store(true, Ordering::SeqCst);
            panic!("measured operation failed");
        });
        assert!(panicked.is_err());
        assert!(
            LEGACY_GLOBAL.load(Ordering::SeqCst),
            "without a guard the mode stays enabled after a panic"
        );
        LEGACY_GLOBAL.store(false, Ordering::SeqCst);
    }

    #[test]
    fn concurrent_scopes_keep_their_own_marking_mode() {
        for _ in 0..64 {
            let observed = interleave(MarkingScope::enter, concealing);
            assert!(observed.concealed_while_control_active);
            assert!(!observed.control_while_concealed_active);
            assert!(!observed.concealed_thread_after_exit);
            assert!(!observed.control_thread_after_exit);
        }
    }

    #[test]
    fn nested_scopes_restore_the_enclosing_mode() {
        assert!(!concealing());
        {
            let _outer = MarkingScope::concealed();
            assert!(concealing());
            {
                let _inner = MarkingScope::control();
                assert!(!concealing());
                {
                    let _innermost = MarkingScope::concealed();
                    assert!(concealing());
                }
                assert!(!concealing());
            }
            assert!(concealing());
        }
        assert!(!concealing());
    }

    #[test]
    fn a_panic_inside_a_scope_restores_the_previous_mode() {
        let failed = std::panic::catch_unwind(|| {
            let _scope = MarkingScope::concealed();
            assert!(concealing());
            panic!("measured operation failed");
        });
        assert!(failed.is_err());
        assert!(!concealing());
        let _outer = MarkingScope::concealed();
        let failed = std::panic::catch_unwind(|| {
            let _inner = MarkingScope::control();
            panic!("measured operation failed");
        });
        assert!(failed.is_err());
        assert!(concealing(), "the enclosing concealed scope is restored");
    }

    #[test]
    fn marking_is_a_no_op_outside_a_concealed_scope() {
        let _control = MarkingScope::control();
        assert_eq!(scoped_canary(3), 3);
        drop(_control);
        let _concealed = MarkingScope::concealed();
        assert_eq!(
            scoped_canary(3),
            3,
            "natively the canary computes the same value"
        );
    }
}
