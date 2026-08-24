use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_RC_FAILURE;

use super::live::CLOCK_NOMINAL;
use super::nv::build_nv_image;
use super::runtime::Tpm2Runtime;
use super::volatile::TailV4;

pub(in crate::library) trait HostClock {
    fn realtime_ms(&self) -> u64;
    fn monotonic_ms(&self) -> u64;
}

fn clock_gettime_ms(clock_id: libc::clockid_t) -> u64 {
    let mut timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the pointer denotes a live, writable timespec; both clock
    // ids are supported on both supported platforms (Linux, macOS).
    unsafe { libc::clock_gettime(clock_id, &mut timespec) };
    (timespec.tv_sec as u64).wrapping_mul(1000) + (timespec.tv_nsec as u64) / 1_000_000
}

pub(in crate::library) struct OsClock;

impl HostClock for OsClock {
    fn realtime_ms(&self) -> u64 {
        clock_gettime_ms(libc::CLOCK_REALTIME)
    }

    fn monotonic_ms(&self) -> u64 {
        clock_gettime_ms(libc::CLOCK_MONOTONIC)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RuntimeClock {
    pub(super) host_monotonic_adjust_ms: i64,
    pub(super) suspended_elapsed_ms: u64,
    pub(super) last_system_time_ms: u64,
    pub(super) last_reported_time_ms: u64,
}

impl RuntimeClock {
    pub(super) const POWER_ON_RESET: RuntimeClock = RuntimeClock {
        host_monotonic_adjust_ms: 0,
        suspended_elapsed_ms: 0,
        last_system_time_ms: 0,
        last_reported_time_ms: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TpmTimer {
    pub(super) time_ms: u64,
    pub(super) real_time_previous: u64,
    pub(super) tpm_time: u64,
    pub(super) adjust_rate: u32,
    pub(super) timer_reset: bool,
    pub(super) timer_stopped: bool,
}

impl TpmTimer {
    pub(super) const POWER_ON_RESET: TpmTimer = TpmTimer {
        time_ms: 0,
        real_time_previous: 0,
        tpm_time: 0,
        adjust_rate: CLOCK_NOMINAL,
        timer_reset: true,
        timer_stopped: true,
    };

    pub(super) fn consume_reset(&mut self) -> bool {
        core::mem::replace(&mut self.timer_reset, false)
    }
}

const NV_CLOCK_UPDATE_INTERVAL: u32 = 12;
const CLOCK_UPDATE_MASK: u64 = (1 << NV_CLOCK_UPDATE_INTERVAL) - 1;

const CLOCK_ADJUST_COARSE: u32 = 300;
const CLOCK_ADJUST_MEDIUM: u32 = 30;
const CLOCK_ADJUST_FINE: u32 = 1;
const CLOCK_ADJUST_LIMIT: u32 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClockAdjust {
    CoarseSlower,
    MediumSlower,
    FineSlower,
    NoChange,
    FineFaster,
    MediumFaster,
    CoarseFaster,
}

impl ClockAdjust {
    pub(super) fn from_encoded(byte: u8) -> Option<Self> {
        match byte as i8 {
            -3 => Some(Self::CoarseSlower),
            -2 => Some(Self::MediumSlower),
            -1 => Some(Self::FineSlower),
            0 => Some(Self::NoChange),
            1 => Some(Self::FineFaster),
            2 => Some(Self::MediumFaster),
            3 => Some(Self::CoarseFaster),
            _ => None,
        }
    }
}

pub(super) fn plat_clock_rate_adjust(timer: &mut TpmTimer, adjust: ClockAdjust) {
    let rate = match adjust {
        ClockAdjust::NoChange => return,
        ClockAdjust::CoarseSlower => timer.adjust_rate.wrapping_add(CLOCK_ADJUST_COARSE),
        ClockAdjust::MediumSlower => timer.adjust_rate.wrapping_add(CLOCK_ADJUST_MEDIUM),
        ClockAdjust::FineSlower => timer.adjust_rate.wrapping_add(CLOCK_ADJUST_FINE),
        ClockAdjust::FineFaster => timer.adjust_rate.wrapping_sub(CLOCK_ADJUST_FINE),
        ClockAdjust::MediumFaster => timer.adjust_rate.wrapping_sub(CLOCK_ADJUST_MEDIUM),
        ClockAdjust::CoarseFaster => timer.adjust_rate.wrapping_sub(CLOCK_ADJUST_COARSE),
    };
    timer.adjust_rate = rate.clamp(
        CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT,
        CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT,
    );
}

fn plat_real_time(clock: &RuntimeClock, host: &dyn HostClock) -> u64 {
    host.monotonic_ms()
        .wrapping_add(clock.host_monotonic_adjust_ms as u64)
        .wrapping_add(clock.suspended_elapsed_ms)
}

pub(super) fn plat_timer_read(
    clock: &mut RuntimeClock,
    timer: &mut TpmTimer,
    host: &dyn HostClock,
) -> u64 {
    let mut time_now = plat_real_time(clock, host);
    if clock.last_system_time_ms == 0 {
        clock.last_system_time_ms = time_now;
        clock.last_reported_time_ms = 0;
        timer.real_time_previous = 0;
    }
    if time_now < clock.last_reported_time_ms {
        clock.last_system_time_ms = time_now;
    }
    clock.last_reported_time_ms = clock
        .last_reported_time_ms
        .wrapping_add(time_now)
        .wrapping_sub(clock.last_system_time_ms);
    clock.last_system_time_ms = time_now;
    time_now = clock.last_reported_time_ms;
    if timer.real_time_previous >= time_now {
        return timer.tpm_time;
    }
    let time_diff = time_now - timer.real_time_previous;
    let adjust_rate = u64::from(timer.adjust_rate.max(1));
    let adjusted = time_diff.wrapping_mul(u64::from(CLOCK_NOMINAL)) / adjust_rate;
    timer.tpm_time = timer.tpm_time.wrapping_add(adjusted);
    let readjusted = adjusted.wrapping_mul(adjust_rate) / u64::from(CLOCK_NOMINAL);
    timer.real_time_previous = timer.real_time_previous.wrapping_add(readjusted);
    timer.tpm_time
}

pub(super) fn time_power_on(runtime: &mut Tpm2Runtime, host: &dyn HostClock) {
    runtime.timer.time_ms = plat_timer_read(&mut runtime.clock, &mut runtime.timer, host);
}

pub(super) fn time_clock_update(runtime: &mut Tpm2Runtime, new_time: u64) {
    if (new_time | CLOCK_UPDATE_MASK) > (runtime.live.orderly.clock | CLOCK_UPDATE_MASK) {
        runtime.live.orderly.clock_safe = 1;
        runtime.live.orderly.clock = new_time;
        if let Some(state) = runtime.state.as_mut() {
            state.orderly = runtime.live.orderly.clone();
        }
    } else {
        runtime.live.orderly.clock = new_time;
    }
}

fn time_new_epoch(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    if !runtime.timer.timer_stopped {
        return Ok(());
    }
    let Some(state) = runtime.state.as_mut() else {
        return Ok(());
    };
    let backup = state.persistent.time_epoch;
    state.persistent.time_epoch = backup.wrapping_add(1);
    match build_nv_image(state) {
        Ok(image) => {
            runtime.nv_memory = image;
            runtime.nv_update_pending = true;
            runtime.timer.timer_stopped = false;
            Ok(())
        }
        Err(_) => {
            if let Some(state) = runtime.state.as_mut() {
                state.persistent.time_epoch = backup;
            }
            Err(TPM_RC_FAILURE)
        }
    }
}

pub(super) fn time_update(
    runtime: &mut Tpm2Runtime,
    host: &dyn HostClock,
) -> Result<(), TpmResult> {
    time_new_epoch(runtime)?;
    let now = plat_timer_read(&mut runtime.clock, &mut runtime.timer, host);
    let elapsed = now.wrapping_sub(runtime.timer.time_ms);
    runtime.timer.time_ms = runtime.timer.time_ms.wrapping_add(elapsed);
    let new_clock = runtime.live.orderly.clock.wrapping_add(elapsed);
    time_clock_update(runtime, new_clock);
    super::dictionary_attack::da_self_heal(runtime)
}

pub(super) fn tail_v4_monotonic_adjust(sample: u64, host: &dyn HostClock) -> i64 {
    sample.wrapping_sub(host.monotonic_ms()) as i64
}

pub(super) fn apply_tail_v4(
    clock: &mut RuntimeClock,
    tail: &TailV4,
    host_monotonic_adjust_ms: i64,
) {
    clock.host_monotonic_adjust_ms = host_monotonic_adjust_ms;
    clock.suspended_elapsed_ms = tail.suspended_elapsed_time;
    clock.last_system_time_ms = tail.last_system_time;
    clock.last_reported_time_ms = tail.last_reported_time;
}

pub(super) fn adjust_post_resume(
    clock: &mut RuntimeClock,
    backthen: u64,
    times_are_realtime: bool,
    host: &dyn HostClock,
) {
    let now = host.realtime_ms();
    let timediff = now.wrapping_sub(backthen) as i64;
    if times_are_realtime {
        clock.suspended_elapsed_ms = now;
        clock.host_monotonic_adjust_ms = host.monotonic_ms().wrapping_neg() as i64;
        clock.last_system_time_ms = now;
        clock.last_reported_time_ms = now;
    } else if timediff >= 0 {
        clock.suspended_elapsed_ms = clock.suspended_elapsed_ms.wrapping_add(timediff as u64);
    }
}

#[cfg(test)]
pub(super) struct SteppingClock {
    realtime_ms: core::cell::Cell<u64>,
    monotonic_ms: core::cell::Cell<u64>,
}

#[cfg(test)]
impl SteppingClock {
    pub(super) fn new(realtime_ms: u64, monotonic_ms: u64) -> Self {
        SteppingClock {
            realtime_ms: core::cell::Cell::new(realtime_ms),
            monotonic_ms: core::cell::Cell::new(monotonic_ms),
        }
    }

    pub(super) fn advance(&self, ms: u64) {
        self.realtime_ms.set(self.realtime_ms.get() + ms);
        self.monotonic_ms.set(self.monotonic_ms.get() + ms);
    }

    pub(super) fn rewind_monotonic(&self, ms: u64) {
        self.monotonic_ms
            .set(self.monotonic_ms.get().saturating_sub(ms));
    }

    #[track_caller]
    pub(super) fn set_monotonic(&self, ms: u64) {
        assert!(
            ms >= self.monotonic_ms.get(),
            "the scheduled monotonic clock only moves forward: {} -> {ms}",
            self.monotonic_ms.get()
        );
        self.monotonic_ms.set(ms);
    }

    #[track_caller]
    pub(super) fn set_realtime(&self, ms: u64) {
        assert!(
            ms >= self.realtime_ms.get(),
            "the scheduled realtime clock only moves forward: {} -> {ms}",
            self.realtime_ms.get()
        );
        self.realtime_ms.set(ms);
    }
}

#[cfg(test)]
impl HostClock for SteppingClock {
    fn realtime_ms(&self) -> u64 {
        self.realtime_ms.get()
    }

    fn monotonic_ms(&self) -> u64 {
        self.monotonic_ms.get()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClockCall {
    Realtime,
    Monotonic,
}

#[cfg(test)]
pub(super) struct RecordingClock {
    pub(super) realtime_ms: u64,
    pub(super) monotonic_ms: u64,
    calls: core::cell::RefCell<Vec<ClockCall>>,
}

#[cfg(test)]
impl RecordingClock {
    pub(super) fn new(realtime_ms: u64, monotonic_ms: u64) -> Self {
        RecordingClock {
            realtime_ms,
            monotonic_ms,
            calls: core::cell::RefCell::new(Vec::new()),
        }
    }

    pub(super) fn calls(&self) -> Vec<ClockCall> {
        self.calls.borrow().clone()
    }
}

#[cfg(test)]
impl HostClock for RecordingClock {
    fn realtime_ms(&self) -> u64 {
        self.calls.borrow_mut().push(ClockCall::Realtime);
        self.realtime_ms
    }

    fn monotonic_ms(&self) -> u64 {
        self.calls.borrow_mut().push(ClockCall::Monotonic);
        self.monotonic_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALTIME: u64 = 1_700_000_100_000;
    const MONOTONIC: u64 = 4_000_000;

    const TAIL: TailV4 = TailV4 {
        host_monotonic_sample: 5_000_000,
        suspended_elapsed_time: 60_000,
        last_system_time: 1_600_000_000_500,
        last_reported_time: 1_600_000_000_400,
    };

    fn recording() -> RecordingClock {
        RecordingClock::new(REALTIME, MONOTONIC)
    }

    fn apply_tail(clock: &mut RuntimeClock, tail: &TailV4, host: &dyn HostClock) {
        let adjust = tail_v4_monotonic_adjust(tail.host_monotonic_sample, host);
        apply_tail_v4(clock, tail, adjust);
    }

    #[test]
    fn realtime_versions_rebase_every_value_to_now() {
        let host = recording();
        let mut clock = RuntimeClock::POWER_ON_RESET;
        adjust_post_resume(&mut clock, 1_600_000_000_000, true, &host);
        assert_eq!(
            clock,
            RuntimeClock {
                host_monotonic_adjust_ms: -4_000_000,
                suspended_elapsed_ms: REALTIME,
                last_system_time_ms: REALTIME,
                last_reported_time_ms: REALTIME,
            }
        );
        assert_eq!(host.calls(), [ClockCall::Realtime, ClockCall::Monotonic]);
    }

    #[test]
    fn realtime_negation_wraps_like_the_c_unsigned_negation() {
        let host = RecordingClock::new(10, u64::MAX);
        let mut clock = RuntimeClock::POWER_ON_RESET;
        adjust_post_resume(&mut clock, 0, true, &host);
        assert_eq!(clock.host_monotonic_adjust_ms, 1);
    }

    #[test]
    fn v4_monotonic_adjustment_is_sample_minus_current() {
        let host = recording();
        let mut clock = RuntimeClock::POWER_ON_RESET;
        apply_tail(&mut clock, &TAIL, &host);
        assert_eq!(clock.host_monotonic_adjust_ms, 1_000_000);
        assert_eq!(clock.last_system_time_ms, TAIL.last_system_time);
        assert_eq!(clock.last_reported_time_ms, TAIL.last_reported_time);
        assert_eq!(host.calls(), [ClockCall::Monotonic]);
    }

    #[test]
    fn v4_monotonic_adjustment_wraps_negative_when_current_is_ahead() {
        let host = RecordingClock::new(REALTIME, TAIL.host_monotonic_sample + 250);
        let mut clock = RuntimeClock::POWER_ON_RESET;
        apply_tail(&mut clock, &TAIL, &host);
        assert_eq!(clock.host_monotonic_adjust_ms, -250);
    }

    #[test]
    fn v4_nonnegative_realtime_delta_extends_suspended_time() {
        let host = recording();
        let mut clock = RuntimeClock::POWER_ON_RESET;
        apply_tail(&mut clock, &TAIL, &host);
        adjust_post_resume(&mut clock, REALTIME - 100_000, false, &host);
        assert_eq!(
            clock.suspended_elapsed_ms,
            TAIL.suspended_elapsed_time + 100_000
        );
        assert_eq!(host.calls(), [ClockCall::Monotonic, ClockCall::Realtime]);

        let host = recording();
        let mut clock = RuntimeClock::POWER_ON_RESET;
        apply_tail(&mut clock, &TAIL, &host);
        adjust_post_resume(&mut clock, REALTIME, false, &host);
        assert_eq!(clock.suspended_elapsed_ms, TAIL.suspended_elapsed_time);
    }

    #[test]
    fn v4_negative_realtime_delta_leaves_suspended_time_unchanged() {
        let host = recording();
        let mut clock = RuntimeClock::POWER_ON_RESET;
        apply_tail(&mut clock, &TAIL, &host);
        adjust_post_resume(&mut clock, REALTIME + 5_000, false, &host);
        assert_eq!(clock.suspended_elapsed_ms, TAIL.suspended_elapsed_time);
        assert_eq!(clock.host_monotonic_adjust_ms, 1_000_000);
    }

    #[test]
    fn v4_wrapped_positive_timediff_is_applied_like_c() {
        let host = RecordingClock::new(0, MONOTONIC);
        let mut clock = RuntimeClock::POWER_ON_RESET;
        apply_tail(&mut clock, &TAIL, &host);
        let backthen = u64::MAX;
        adjust_post_resume(&mut clock, backthen, false, &host);
        assert_eq!(clock.suspended_elapsed_ms, TAIL.suspended_elapsed_time + 1);
    }

    #[test]
    fn v4_stream_without_tail_rebases_over_the_reset_baseline() {
        let host = RecordingClock::new(REALTIME, MONOTONIC);
        let mut clock = RuntimeClock::POWER_ON_RESET;
        adjust_post_resume(&mut clock, REALTIME - 42, false, &host);
        assert_eq!(
            clock,
            RuntimeClock {
                host_monotonic_adjust_ms: 0,
                suspended_elapsed_ms: 42,
                last_system_time_ms: 0,
                last_reported_time_ms: 0,
            }
        );
        assert_eq!(host.calls(), [ClockCall::Realtime]);
    }

    #[test]
    fn rebase_is_deterministic_for_identical_inputs() {
        let derive = || {
            let host = recording();
            let mut clock = RuntimeClock::POWER_ON_RESET;
            apply_tail(&mut clock, &TAIL, &host);
            adjust_post_resume(&mut clock, 123, false, &host);
            (clock, host.calls())
        };
        let (first, first_calls) = derive();
        let (second, second_calls) = derive();
        assert_eq!(first, second);
        assert_eq!(first_calls, second_calls);
    }

    #[test]
    fn the_tpm_timer_accumulates_host_monotonic_time() {
        let host = SteppingClock::new(1_000_000, 500_000);
        let mut clock = RuntimeClock::POWER_ON_RESET;
        let mut timer = TpmTimer::POWER_ON_RESET;
        assert_eq!(plat_timer_read(&mut clock, &mut timer, &host), 0);
        host.advance(250);
        assert_eq!(plat_timer_read(&mut clock, &mut timer, &host), 250);
        host.advance(1_000);
        assert_eq!(plat_timer_read(&mut clock, &mut timer, &host), 1_250);
        assert_eq!(timer.real_time_previous, 1_250);
    }

    #[test]
    fn a_backwards_host_clock_never_rewinds_the_tpm_timer() {
        let host = SteppingClock::new(1_000_000, 500_000);
        let mut clock = RuntimeClock::POWER_ON_RESET;
        let mut timer = TpmTimer::POWER_ON_RESET;
        plat_timer_read(&mut clock, &mut timer, &host);
        host.advance(2_000);
        assert_eq!(plat_timer_read(&mut clock, &mut timer, &host), 2_000);
        host.rewind_monotonic(1_500);
        assert_eq!(
            plat_timer_read(&mut clock, &mut timer, &host),
            2_000,
            "the reported time is pinned while the host clock is behind"
        );
        host.advance(300);
        assert_eq!(
            plat_timer_read(&mut clock, &mut timer, &host),
            2_000,
            "the pinned value holds until the reported time catches up"
        );
        host.advance(1_250);
        assert_eq!(plat_timer_read(&mut clock, &mut timer, &host), 2_050);
    }

    #[test]
    fn extreme_timer_states_never_panic() {
        let host = SteppingClock::new(u64::MAX - 10, u64::MAX - 10);
        let mut clock = RuntimeClock {
            host_monotonic_adjust_ms: i64::MAX,
            suspended_elapsed_ms: u64::MAX,
            last_system_time_ms: u64::MAX,
            last_reported_time_ms: u64::MAX,
        };
        let mut timer = TpmTimer {
            time_ms: u64::MAX,
            real_time_previous: u64::MAX,
            tpm_time: u64::MAX,
            adjust_rate: 0,
            timer_reset: false,
            timer_stopped: false,
        };
        let _ = plat_timer_read(&mut clock, &mut timer, &host);
        host.advance(5);
        let _ = plat_timer_read(&mut clock, &mut timer, &host);
    }

    #[test]
    fn consume_reset_reports_the_flag_exactly_once() {
        let mut timer = TpmTimer::POWER_ON_RESET;
        assert!(timer.consume_reset());
        assert!(!timer.consume_reset());
        assert!(!timer.timer_reset);
    }

    const UPPER_LIMIT: u32 = CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT;
    const LOWER_LIMIT: u32 = CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT;

    const SLOWER: [(ClockAdjust, u32); 3] = [
        (ClockAdjust::CoarseSlower, CLOCK_ADJUST_COARSE),
        (ClockAdjust::MediumSlower, CLOCK_ADJUST_MEDIUM),
        (ClockAdjust::FineSlower, CLOCK_ADJUST_FINE),
    ];
    const FASTER: [(ClockAdjust, u32); 3] = [
        (ClockAdjust::CoarseFaster, CLOCK_ADJUST_COARSE),
        (ClockAdjust::MediumFaster, CLOCK_ADJUST_MEDIUM),
        (ClockAdjust::FineFaster, CLOCK_ADJUST_FINE),
    ];

    fn adjusted(start: u32, adjust: ClockAdjust) -> u32 {
        let mut timer = TpmTimer {
            adjust_rate: start,
            ..TpmTimer::POWER_ON_RESET
        };
        plat_clock_rate_adjust(&mut timer, adjust);
        timer.adjust_rate
    }

    #[test]
    fn no_change_never_touches_a_restored_adjustment_rate() {
        for start in [0u32, 1, LOWER_LIMIT, CLOCK_NOMINAL, UPPER_LIMIT, u32::MAX] {
            assert_eq!(
                adjusted(start, ClockAdjust::NoChange),
                start,
                "start {start}"
            );
        }
    }

    #[test]
    fn a_faster_adjustment_from_zero_wraps_before_the_clamp() {
        for (adjust, _) in FASTER {
            assert_eq!(adjusted(0, adjust), UPPER_LIMIT, "{adjust:?}");
        }
    }

    #[test]
    fn a_slower_adjustment_from_the_maximum_wraps_before_the_clamp() {
        for (adjust, _) in SLOWER {
            assert_eq!(adjusted(u32::MAX, adjust), LOWER_LIMIT, "{adjust:?}");
        }
    }

    #[test]
    fn an_in_range_adjustment_moves_by_exactly_one_step() {
        for (adjust, step) in SLOWER {
            assert_eq!(
                adjusted(CLOCK_NOMINAL, adjust),
                CLOCK_NOMINAL + step,
                "{adjust:?}"
            );
        }
        for (adjust, step) in FASTER {
            assert_eq!(
                adjusted(CLOCK_NOMINAL, adjust),
                CLOCK_NOMINAL - step,
                "{adjust:?}"
            );
        }
    }

    #[test]
    fn repeated_adjustments_saturate_at_the_platform_limits() {
        for (adjust, step) in SLOWER {
            let mut timer = TpmTimer::POWER_ON_RESET;
            for _ in 0..(CLOCK_ADJUST_LIMIT / step + 2) {
                plat_clock_rate_adjust(&mut timer, adjust);
                assert!(timer.adjust_rate <= UPPER_LIMIT, "{adjust:?}");
            }
            assert_eq!(timer.adjust_rate, UPPER_LIMIT, "{adjust:?}");
        }
        for (adjust, step) in FASTER {
            let mut timer = TpmTimer::POWER_ON_RESET;
            for _ in 0..(CLOCK_ADJUST_LIMIT / step + 2) {
                plat_clock_rate_adjust(&mut timer, adjust);
                assert!(timer.adjust_rate >= LOWER_LIMIT, "{adjust:?}");
            }
            assert_eq!(timer.adjust_rate, LOWER_LIMIT, "{adjust:?}");
        }
    }

    #[test]
    fn the_encoded_adjustment_values_match_the_vendored_constants() {
        for (encoded, expected) in [
            (0xfdu8, ClockAdjust::CoarseSlower),
            (0xfe, ClockAdjust::MediumSlower),
            (0xff, ClockAdjust::FineSlower),
            (0x00, ClockAdjust::NoChange),
            (0x01, ClockAdjust::FineFaster),
            (0x02, ClockAdjust::MediumFaster),
            (0x03, ClockAdjust::CoarseFaster),
        ] {
            assert_eq!(ClockAdjust::from_encoded(encoded), Some(expected));
        }
        for encoded in [0x04u8, 0x7f, 0x80, 0xfc] {
            assert_eq!(ClockAdjust::from_encoded(encoded), None, "{encoded:#04x}");
        }
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), crate::ffi_types::TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x2c;
        }
        Ok(())
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    fn run_command(runtime: &mut Tpm2Runtime, host: &SteppingClock, bytes: &[u8]) -> Vec<u8> {
        let input = crate::library::CommandInput::new(bytes.len() as u32, bytes.to_vec());
        crate::library::tpm2::process::process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(0),
            &input,
            host,
            |_| Ok(()),
        )
        .expect("processes")
    }

    const STARTUP_CLEAR: [u8; 12] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    const UNKNOWN_COMMAND: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x00];

    fn epoch(runtime: &Tpm2Runtime) -> u32 {
        runtime.state.as_ref().expect("state").persistent.time_epoch
    }

    #[test]
    fn fresh_power_on_starts_with_the_timer_stopped() {
        assert!(TpmTimer::POWER_ON_RESET.timer_stopped);
        assert!(TpmTimer::POWER_ON_RESET.timer_reset);
        assert!(manufactured_runtime().timer.timer_stopped);
    }

    #[test]
    fn startup_rolls_the_time_epoch_exactly_once() {
        let host = SteppingClock::new(1_600_000_000_000, 5_000_000);
        let mut runtime = manufactured_runtime();
        time_power_on(&mut runtime, &host);
        assert_eq!(epoch(&runtime), 0);

        run_command(&mut runtime, &host, &STARTUP_CLEAR);
        assert_eq!(
            epoch(&runtime),
            1,
            "the first startup consumes the stopped timer"
        );
        assert!(!runtime.timer.timer_stopped);

        host.advance(50);
        run_command(&mut runtime, &host, &UNKNOWN_COMMAND);
        host.advance(50);
        run_command(&mut runtime, &host, &UNKNOWN_COMMAND);
        assert_eq!(epoch(&runtime), 1, "later commands roll no further epoch");
        assert!(!runtime.timer.timer_stopped);
    }

    #[test]
    fn volatile_state_saved_after_startup_records_a_running_timer() {
        use crate::library::tpm2::volatile::capture_volatile_state;

        let host = SteppingClock::new(1_600_000_000_000, 5_000_000);
        let mut runtime = manufactured_runtime();
        time_power_on(&mut runtime, &host);
        run_command(&mut runtime, &host, &STARTUP_CLEAR);
        let captured = capture_volatile_state(&runtime, &host).expect("captures");
        assert!(!captured.timer_stopped);
        assert!(!captured.timer_reset);
    }

    #[test]
    fn a_restored_running_timer_rolls_no_epoch() {
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{VolatileDecodeBoundary, attach_volatile_blob};

        let host = SteppingClock::new(1_600_000_000_000, 5_000_000);
        let mut runtime = manufactured_runtime();
        time_power_on(&mut runtime, &host);
        run_command(&mut runtime, &host, &STARTUP_CLEAR);
        let blob = volatile_all_store(&runtime, &host).expect("saves");

        let mut restored = manufactured_runtime();
        host.advance(50);
        attach_volatile_blob(&mut restored, &blob, &host, VolatileDecodeBoundary::Restore)
            .expect("restores");
        assert!(!restored.timer.timer_stopped);
        assert_eq!(epoch(&restored), 0);

        host.advance(50);
        run_command(&mut restored, &host, &UNKNOWN_COMMAND);
        host.advance(50);
        run_command(&mut restored, &host, &UNKNOWN_COMMAND);
        assert_eq!(
            epoch(&restored),
            0,
            "a running restored timer rolls no epoch"
        );
    }

    #[test]
    fn a_restored_stopped_timer_rolls_exactly_one_epoch() {
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{VolatileDecodeBoundary, attach_volatile_blob};

        let host = SteppingClock::new(1_600_000_000_000, 5_000_000);
        let mut runtime = manufactured_runtime();
        time_power_on(&mut runtime, &host);
        run_command(&mut runtime, &host, &STARTUP_CLEAR);
        runtime.timer.timer_stopped = true;
        let blob = volatile_all_store(&runtime, &host).expect("saves");

        let mut restored = manufactured_runtime();
        host.advance(50);
        attach_volatile_blob(&mut restored, &blob, &host, VolatileDecodeBoundary::Restore)
            .expect("restores");
        assert!(
            restored.timer.timer_stopped,
            "the blob carries the stopped flag"
        );

        host.advance(50);
        run_command(&mut restored, &host, &UNKNOWN_COMMAND);
        assert_eq!(
            epoch(&restored),
            1,
            "the first command consumes the stopped timer"
        );
        assert!(!restored.timer.timer_stopped);

        host.advance(50);
        run_command(&mut restored, &host, &UNKNOWN_COMMAND);
        assert_eq!(epoch(&restored), 1, "only one epoch per stop");
    }

    #[test]
    fn an_epoch_persistence_failure_rolls_back_every_field() {
        use crate::library::tpm2::persistent::OwnedSecret;

        let host = SteppingClock::new(1_600_000_000_000, 5_000_000);
        let mut runtime = manufactured_runtime();
        time_power_on(&mut runtime, &host);
        run_command(&mut runtime, &host, &STARTUP_CLEAR);
        runtime.state.as_mut().unwrap().persistent.failed_tries = 2;

        runtime.timer.timer_stopped = true;
        runtime.state.as_mut().unwrap().persistent.owner_auth =
            OwnedSecret::from_vec(vec![0xaa; 4096]);
        let epoch_before = epoch(&runtime);
        let time_before = runtime.timer.time_ms;
        let tpm_time_before = runtime.timer.tpm_time;
        let clock_before = runtime.live.orderly.clock;
        let heal_before = runtime.live.orderly.self_heal_timer;
        let nv_before = runtime.nv_memory.clone();

        host.advance(50);
        let response = run_command(&mut runtime, &host, &UNKNOWN_COMMAND);
        assert_eq!(response[6..], [0x00, 0x00, 0x01, 0x01]);
        assert!(runtime.failure_mode);
        assert_eq!(epoch(&runtime), epoch_before, "the epoch is rolled back");
        assert!(
            runtime.timer.timer_stopped,
            "the stopped flag is not consumed"
        );
        assert_eq!(
            runtime.timer.time_ms, time_before,
            "the TPM time is untouched"
        );
        assert_eq!(runtime.timer.tpm_time, tpm_time_before);
        assert_eq!(runtime.live.orderly.clock, clock_before);
        assert_eq!(runtime.live.orderly.self_heal_timer, heal_before);
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.failed_tries,
            2,
            "DA counters are untouched"
        );
        assert!(
            !runtime.nv_update_pending,
            "no pending NV flag is left behind"
        );
        assert_eq!(
            runtime.nv_memory, nv_before,
            "no partial NV image is published"
        );
    }

    #[test]
    fn a_startup_epoch_persistence_failure_rolls_back_without_consuming_the_flag() {
        use crate::library::tpm2::persistent::OwnedSecret;

        let host = SteppingClock::new(1_600_000_000_000, 5_000_000);
        let mut runtime = manufactured_runtime();
        time_power_on(&mut runtime, &host);
        runtime.state.as_mut().unwrap().persistent.owner_auth =
            OwnedSecret::from_vec(vec![0xaa; 4096]);
        let response = run_command(&mut runtime, &host, &STARTUP_CLEAR);
        assert_eq!(response[6..], [0x00, 0x00, 0x01, 0x01]);
        assert_eq!(epoch(&runtime), 0);
        assert!(runtime.timer.timer_stopped);
        assert!(!runtime.startup_received);
    }

    #[test]
    fn a_backwards_host_clock_rolls_no_epoch_and_recovers_nothing_early() {
        let host = SteppingClock::new(1_600_000_000_000, 5_000_000);
        let mut runtime = manufactured_runtime();
        time_power_on(&mut runtime, &host);
        run_command(&mut runtime, &host, &STARTUP_CLEAR);
        host.advance(6_000);
        run_command(&mut runtime, &host, &UNKNOWN_COMMAND);
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = 1;
            persistent.recovery_time = 1;
        }
        runtime.live.orderly.self_heal_timer = runtime.timer.time_ms;
        let epoch_before = epoch(&runtime);
        let time_before = runtime.timer.time_ms;

        host.rewind_monotonic(3_000);
        run_command(&mut runtime, &host, &UNKNOWN_COMMAND);
        run_command(&mut runtime, &host, &UNKNOWN_COMMAND);
        assert_eq!(
            epoch(&runtime),
            epoch_before,
            "a rewound clock rolls no epoch"
        );
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.failed_tries,
            1,
            "a rewound clock recovers no failed tries"
        );
        assert_eq!(
            runtime.timer.time_ms, time_before,
            "the TPM time is pinned while the host clock is behind"
        );
    }

    #[test]
    fn os_clock_reads_both_host_clocks() {
        let os = OsClock;
        let (first_realtime, first_monotonic) = (os.realtime_ms(), os.monotonic_ms());
        assert!(first_realtime > 0);
        assert!(first_monotonic > 0);
        assert!(os.realtime_ms() >= first_realtime);
        assert!(os.monotonic_ms() >= first_monotonic);
    }
}
