use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const POWERED: u64 = 1;
const REQUESTED: u64 = 1 << 1;
const GENERATION_STEP: u64 = 1 << 2;
const GENERATION_MASK: u64 = !(POWERED | REQUESTED);

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
#[derive(Clone, Debug)]
pub(in crate::library) struct CancelSignal {
    state: Arc<AtomicU64>,
    generation: u64,
}

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
impl CancelSignal {
    pub(in crate::library) fn detached() -> Self {
        Self {
            state: Arc::new(AtomicU64::new(0)),
            generation: 0,
        }
    }

    // TODO: Poll this from the ECC self-test checkpoints
    // (AlgorithmTests.c CHECK_CANCELED in TestEccSignAndVerify), from
    // CryptEccCommitCompute and from RSA key generation once those paths
    // exist. No command implemented so far reaches an upstream checkpoint.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::library) fn is_signaled(&self) -> bool {
        let word = self.state.load(Ordering::Relaxed);
        word & GENERATION_MASK == self.generation && word & REQUESTED != 0
    }

    #[cfg(test)]
    pub(in crate::library) fn signaled() -> Self {
        let signal = Self::detached();
        signal
            .state
            .store(signal.generation | REQUESTED, Ordering::Relaxed);
        signal
    }

    pub(in crate::library) fn clear(&self) {
        let mut current = self.state.load(Ordering::Relaxed);
        while current & GENERATION_MASK == self.generation && current & REQUESTED != 0 {
            match self.state.compare_exchange_weak(
                current,
                current & !REQUESTED,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

pub(in crate::library) struct CancelGate {
    cancelable: AtomicBool,
    state: Arc<AtomicU64>,
    #[cfg(test)]
    park: std::sync::Mutex<Option<ParkEnds>>,
}

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
impl CancelGate {
    pub(in crate::library) fn new() -> Self {
        Self {
            cancelable: AtomicBool::new(false),
            state: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            park: std::sync::Mutex::new(None),
        }
    }

    pub(in crate::library) fn set_cancelable(&self, cancelable: bool) {
        self.cancelable.store(cancelable, Ordering::Relaxed);
    }

    pub(in crate::library) fn power_on(&self) -> CancelSignal {
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            let generation = (current & GENERATION_MASK).wrapping_add(GENERATION_STEP);
            match self.state.compare_exchange_weak(
                current,
                generation | POWERED,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return CancelSignal {
                        state: Arc::clone(&self.state),
                        generation,
                    };
                }
                Err(actual) => current = actual,
            }
        }
    }

    pub(in crate::library) fn power_off(&self) {
        self.state.fetch_and(!POWERED, Ordering::Relaxed);
    }

    pub(in crate::library) fn request(&self) -> bool {
        if !self.cancelable.load(Ordering::Relaxed) {
            return false;
        }
        let mut current = self.state.load(Ordering::Relaxed);
        let generation = current & GENERATION_MASK;
        #[cfg(test)]
        self.park();
        loop {
            if current & GENERATION_MASK != generation
                || current & POWERED == 0
                || current & REQUESTED != 0
            {
                return true;
            }
            match self.state.compare_exchange_weak(
                current,
                current | REQUESTED,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    #[cfg(test)]
    pub(in crate::library) fn is_signaled(&self) -> bool {
        self.state.load(Ordering::Relaxed) & REQUESTED != 0
    }

    #[cfg(test)]
    pub(in crate::library) fn arm_request_park(&self) -> RequestPark {
        use std::sync::PoisonError;
        use std::sync::mpsc::sync_channel;

        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        *self.park.lock().unwrap_or_else(PoisonError::into_inner) = Some(ParkEnds {
            entered: entered_tx,
            release: release_rx,
        });
        RequestPark {
            entered: entered_rx,
            release: release_tx,
        }
    }

    #[cfg(test)]
    fn park(&self) {
        use std::sync::PoisonError;
        use std::sync::mpsc::RecvTimeoutError;

        let ends = self
            .park
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(ends) = ends else {
            return;
        };
        ends.entered
            .send(())
            .expect("the test thread waits on the request park");
        match ends.release.recv_timeout(PARK_TIMEOUT) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
            Err(RecvTimeoutError::Timeout) => {
                panic!("the test thread never released the request park")
            }
        }
    }
}

impl Default for CancelGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
const PARK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
struct ParkEnds {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
pub(in crate::library) struct RequestPark {
    entered: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::SyncSender<()>,
}

#[cfg(test)]
impl RequestPark {
    pub(in crate::library) fn wait_until_entered(&self) {
        self.entered
            .recv_timeout(PARK_TIMEOUT)
            .expect("a cancellation request reached the park");
    }

    pub(in crate::library) fn release(&self) {
        self.release
            .send(())
            .expect("a cancellation request is parked");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn powered_gate() -> (CancelGate, CancelSignal) {
        let gate = CancelGate::new();
        gate.set_cancelable(true);
        let signal = gate.power_on();
        (gate, signal)
    }

    #[test]
    fn a_detached_signal_toggles_on_its_own_word() {
        let signal = CancelSignal::detached();
        assert!(!signal.is_signaled());
        signal.clear();
        assert!(!signal.is_signaled());
    }

    #[test]
    fn an_unselected_implementation_refuses_without_touching_the_pin() {
        let gate = CancelGate::new();
        let signal = gate.power_on();
        assert!(!gate.request(), "TPM 1.2 and the disabled interface fail");
        assert!(!signal.is_signaled());
    }

    #[test]
    fn a_selected_but_unpowered_implementation_succeeds_without_raising_the_pin() {
        let gate = CancelGate::new();
        gate.set_cancelable(true);
        assert!(gate.request(), "upstream returns TPM_SUCCESS regardless");
        assert!(!gate.is_signaled());
    }

    #[test]
    fn a_powered_selection_raises_the_pin_and_stays_raised() {
        let (gate, signal) = powered_gate();
        for round in 0..4 {
            assert!(gate.request(), "round {round}");
            assert!(signal.is_signaled(), "round {round}");
        }
    }

    #[test]
    fn powering_off_keeps_the_pin_and_powering_on_replaces_it() {
        let (gate, signal) = powered_gate();
        assert!(gate.request());

        gate.power_off();
        assert!(signal.is_signaled(), "power-off leaves the pin alone");
        assert!(gate.request(), "still TPM_SUCCESS with the TPM powered off");
        assert!(signal.is_signaled());

        let next = gate.power_on();
        assert!(!next.is_signaled(), "the new lifecycle starts clear");
        assert!(
            !signal.is_signaled(),
            "the old handle no longer matches the live generation"
        );
    }

    #[test]
    fn a_command_start_clear_only_touches_its_own_lifecycle() {
        let (gate, first) = powered_gate();
        let second = gate.power_on();
        assert!(gate.request());
        assert!(second.is_signaled());

        first.clear();
        assert!(
            second.is_signaled(),
            "a stale handle cannot clear the live request"
        );
        second.clear();
        assert!(!second.is_signaled());
    }

    #[test]
    fn dropping_cancel_support_refuses_later_requests() {
        let (gate, signal) = powered_gate();
        gate.set_cancelable(false);
        assert!(!gate.request());
        assert!(!signal.is_signaled());
    }

    #[test]
    fn a_request_delayed_across_power_off_publishes_nothing() {
        let (gate, signal) = powered_gate();
        std::thread::scope(|scope| {
            let park = gate.arm_request_park();
            let worker = scope.spawn(|| gate.request());
            park.wait_until_entered();
            gate.power_off();
            park.release();
            assert!(worker.join().expect("the request thread finished"));
        });
        assert!(
            !signal.is_signaled(),
            "the lifecycle was powered off before the request published"
        );
    }

    #[test]
    fn a_request_delayed_across_a_restart_never_reaches_the_new_lifecycle() {
        let (gate, first) = powered_gate();
        let second = std::thread::scope(|scope| {
            let park = gate.arm_request_park();
            let worker = scope.spawn(|| gate.request());
            park.wait_until_entered();
            gate.power_off();
            let second = gate.power_on();
            second.clear();
            park.release();
            assert!(worker.join().expect("the request thread finished"));
            second
        });
        assert!(!first.is_signaled());
        assert!(
            !second.is_signaled(),
            "an obsolete request must not cancel the new lifecycle"
        );
        assert!(gate.request(), "a fresh request still works");
        assert!(second.is_signaled());
    }

    #[test]
    fn a_request_delayed_across_many_restarts_never_reaches_the_newest_lifecycle() {
        let (gate, _first) = powered_gate();
        let newest = std::thread::scope(|scope| {
            let park = gate.arm_request_park();
            let worker = scope.spawn(|| gate.request());
            park.wait_until_entered();
            let mut newest = None;
            for _ in 0..8 {
                gate.power_off();
                newest = Some(gate.power_on());
            }
            park.release();
            assert!(worker.join().expect("the request thread finished"));
            newest.expect("at least one restart")
        });
        assert!(!newest.is_signaled());
        assert!(!gate.is_signaled());
    }

    #[test]
    fn a_request_delayed_within_one_lifecycle_still_publishes() {
        let (gate, signal) = powered_gate();
        std::thread::scope(|scope| {
            let park = gate.arm_request_park();
            let worker = scope.spawn(|| gate.request());
            park.wait_until_entered();
            park.release();
            assert!(worker.join().expect("the request thread finished"));
        });
        assert!(signal.is_signaled());
    }

    #[test]
    fn concurrent_requests_and_restarts_never_leave_a_stale_request_behind() {
        const ROUNDS: usize = 512;

        let gate = CancelGate::new();
        gate.set_cancelable(true);
        let _ = gate.power_on();
        std::thread::scope(|scope| {
            let gate = &gate;
            let requester = scope.spawn(move || {
                for _ in 0..ROUNDS {
                    assert!(gate.request());
                }
            });
            for _ in 0..ROUNDS {
                gate.power_off();
                gate.power_on().clear();
            }
            requester.join().expect("the requester finished");
        });
        let live = gate.power_on();
        assert!(!live.is_signaled());
    }
}
