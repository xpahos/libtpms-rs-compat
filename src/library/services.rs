// Part of the Rust port of libtpms.
//
// Upstream behavior references for this Rust implementation:
// - libtpms/src/tpm_library.c
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use std::sync::Arc;

use super::platform::{DefaultPlatform, Platform};
use super::storage::{NoStorage, Storage};

#[derive(Clone)]
pub struct ExternalServices {
    platform: Arc<dyn Platform>,
    storage: Arc<dyn Storage>,
}

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
impl ExternalServices {
    pub fn new(platform: Arc<dyn Platform>, storage: Arc<dyn Storage>) -> Self {
        Self { platform, storage }
    }

    pub(in crate::library) fn platform_ref(&self) -> &dyn Platform {
        self.platform.as_ref()
    }

    pub(in crate::library) fn storage_ref(&self) -> &dyn Storage {
        self.storage.as_ref()
    }

    #[must_use]
    pub(in crate::library) fn replace_platform(
        &mut self,
        platform: Arc<dyn Platform>,
    ) -> Arc<dyn Platform> {
        core::mem::replace(&mut self.platform, platform)
    }

    #[must_use]
    pub(in crate::library) fn replace_storage(
        &mut self,
        storage: Arc<dyn Storage>,
    ) -> Arc<dyn Storage> {
        core::mem::replace(&mut self.storage, storage)
    }
}

impl Default for ExternalServices {
    fn default() -> Self {
        Self::new(Arc::new(DefaultPlatform), Arc::new(NoStorage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::platform::test_support::TestPlatform;
    use crate::library::storage::test_support::TestStorage;

    #[test]
    fn default_services_inertness() {
        let services = ExternalServices::default();
        assert_eq!(services.platform_ref().locality(), 0);
        assert!(!services.storage_ref().supports_store());
    }

    #[test]
    fn independent_service_replacement() {
        let mut services = ExternalServices::default();
        let previous = services.replace_platform(TestPlatform::at_locality(3).arc());
        assert_eq!(previous.locality(), 0, "the displaced platform is returned");
        assert_eq!(services.platform_ref().locality(), 3);
        assert!(!services.storage_ref().supports_store());

        let previous = services.replace_storage(TestStorage::new().on_can_store(|| true).arc());
        assert!(
            !previous.supports_store(),
            "the displaced storage is returned"
        );
        assert_eq!(
            services.platform_ref().locality(),
            3,
            "the platform survives"
        );
        assert!(services.storage_ref().supports_store());
    }
}
