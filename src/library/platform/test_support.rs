// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use std::sync::Arc;

use crate::types::TpmResult;

use super::Platform;

type InitializeHandler = Arc<dyn Fn() -> Result<(), TpmResult> + Send + Sync>;
type LocalityHandler = Arc<dyn Fn() -> u32 + Send + Sync>;
type PresenceHandler = Arc<dyn Fn() -> bool + Send + Sync>;

#[derive(Clone, Default)]
pub(crate) struct TestPlatform {
    initialize: Option<InitializeHandler>,
    locality: Option<LocalityHandler>,
    physical_presence: Option<PresenceHandler>,
}

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
impl TestPlatform {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn on_initialize(
        mut self,
        handler: impl Fn() -> Result<(), TpmResult> + Send + Sync + 'static,
    ) -> Self {
        self.initialize = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_locality(mut self, handler: impl Fn() -> u32 + Send + Sync + 'static) -> Self {
        self.locality = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_physical_presence(
        mut self,
        handler: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        self.physical_presence = Some(Arc::new(handler));
        self
    }

    pub(crate) fn at_locality(locality: u32) -> Self {
        Self::new().on_locality(move || locality)
    }

    pub(crate) fn arc(self) -> Arc<dyn Platform> {
        Arc::new(self)
    }
}

impl Platform for TestPlatform {
    fn initialize(&self) -> Result<(), TpmResult> {
        match &self.initialize {
            Some(handler) => handler(),
            None => Ok(()),
        }
    }

    fn locality(&self) -> u32 {
        match &self.locality {
            Some(handler) => handler(),
            None => 0,
        }
    }

    fn physical_presence(&self) -> bool {
        match &self.physical_presence {
            Some(handler) => handler(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn unconfigured_no_platform_parity() {
        let platform = TestPlatform::new();
        assert_eq!(platform.initialize(), Ok(()));
        assert_eq!(platform.locality(), 0);
        assert!(!platform.physical_presence());
    }

    #[test]
    fn handler_state_sharing() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&calls);
        let platform = TestPlatform::new()
            .on_initialize(move || {
                recorder.lock().unwrap().push("initialize");
                Err(42)
            })
            .on_locality(|| 3)
            .on_physical_presence(|| true);

        assert_eq!(platform.initialize(), Err(42));
        assert_eq!(platform.locality(), 3);
        assert!(platform.physical_presence());
        assert_eq!(*calls.lock().unwrap(), ["initialize"]);
    }
}
