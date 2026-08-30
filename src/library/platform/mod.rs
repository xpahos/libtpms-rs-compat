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
