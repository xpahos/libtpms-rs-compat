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
    fn os_clock_reads_both_host_clocks() {
        let os = OsClock;
        let (first_realtime, first_monotonic) = (os.realtime_ms(), os.monotonic_ms());
        assert!(first_realtime > 0);
        assert!(first_monotonic > 0);
        assert!(os.realtime_ms() >= first_realtime);
        assert!(os.monotonic_ms() >= first_monotonic);
    }
}
