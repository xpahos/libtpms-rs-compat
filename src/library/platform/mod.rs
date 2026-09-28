// Part of the Rust port of libtpms.
//
// Upstream behavior references for this Rust implementation:
// - libtpms/src/tpm2/LibtpmsCallbacks.c
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

#[cfg(test)]
pub(crate) mod test_support;

use crate::types::TpmResult;

pub trait Platform: Send + Sync {
    fn initialize(&self) -> Result<(), TpmResult>;

    fn locality(&self) -> u32;

    fn physical_presence(&self) -> bool;
}

pub struct DefaultPlatform;

impl Platform for DefaultPlatform {
    fn initialize(&self) -> Result<(), TpmResult> {
        Ok(())
    }

    fn locality(&self) -> u32 {
        0
    }

    fn physical_presence(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_platform_inert_defaults() {
        let platform = DefaultPlatform;
        assert_eq!(platform.initialize(), Ok(()));
        assert_eq!(platform.locality(), 0);
        assert!(!platform.physical_presence());
    }
}
