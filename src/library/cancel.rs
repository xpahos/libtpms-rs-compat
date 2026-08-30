use std::sync::atomic::{AtomicBool, Ordering};

use crate::library::constants::TPM_RC_CANCELED;
use crate::types::TpmResult;

pub(in crate::library) struct CommandCancellation {
    requested: AtomicBool,
}

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
impl CommandCancellation {
    pub(in crate::library) fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
        }
    }

    pub(in crate::library) fn run<T>(&self, command: impl FnOnce(CancellationToken<'_>) -> T) -> T {
        self.requested.store(false, Ordering::Relaxed);
        command(CancellationToken {
            requested: &self.requested,
        })
    }

    pub(in crate::library) fn cancel(&self) {
        self.requested.store(true, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(in crate::library) fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Relaxed)
    }
}

impl Default for CommandCancellation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub(in crate::library) struct CancellationToken<'a> {
    requested: &'a AtomicBool,
}

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
impl CancellationToken<'_> {
    pub(in crate::library) fn check(self) -> Result<(), TpmResult> {
        if self.requested.load(Ordering::Relaxed) {
            Err(TPM_RC_CANCELED)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(in crate::library) fn disabled() -> CancellationToken<'static> {
        static DISABLED: AtomicBool = AtomicBool::new(false);
        CancellationToken {
            requested: &DISABLED,
        }
    }

    #[cfg(test)]
    pub(in crate::library) fn requested() -> CancellationToken<'static> {
        static REQUESTED: AtomicBool = AtomicBool::new(true);
        CancellationToken {
            requested: &REQUESTED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_clear_state() {
        let cancellation = CommandCancellation::new();
        cancellation.run(|view| assert_eq!(view.check(), Ok(())));
    }

    #[test]
    fn request_visibility() {
        let cancellation = CommandCancellation::new();
        cancellation.run(|view| {
            assert_eq!(view.check(), Ok(()));
            cancellation.cancel();
            assert_eq!(view.check(), Err(TPM_RC_CANCELED));
            assert_eq!(view.check(), Err(TPM_RC_CANCELED), "the request latches");
        });
    }

    #[test]
    fn request_clearance_on_start() {
        let cancellation = CommandCancellation::new();
        cancellation.cancel();
        assert!(cancellation.is_requested(), "latched between commands");
        cancellation.run(|view| assert_eq!(view.check(), Ok(())));
        assert!(!cancellation.is_requested());
    }

    #[test]
    fn repeated_request_idempotence() {
        let cancellation = CommandCancellation::new();
        cancellation.run(|view| {
            for _ in 0..4 {
                cancellation.cancel();
            }
            assert_eq!(view.check(), Err(TPM_RC_CANCELED));
        });
        assert!(
            cancellation.is_requested(),
            "still latched for the next run"
        );
    }

    #[test]
    fn fixed_views() {
        assert_eq!(CancellationToken::disabled().check(), Ok(()));
        assert_eq!(CancellationToken::requested().check(), Err(TPM_RC_CANCELED));
    }
}
