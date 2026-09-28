// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use std::sync::Arc;

use crate::types::TpmResult;

use super::super::state_blob::StateBlobKind;
use super::{Storage, StorageLoad, StorageProbe};

type InitHandler = Arc<dyn Fn() -> Result<(), TpmResult> + Send + Sync>;
type ProbeHandler = Arc<dyn Fn() -> StorageProbe + Send + Sync>;
type LoadHandler = Arc<dyn Fn(StateBlobKind) -> Result<StorageLoad, TpmResult> + Send + Sync>;
type CanStoreHandler = Arc<dyn Fn() -> bool + Send + Sync>;
type StoreHandler = Arc<dyn Fn(StateBlobKind, &[u8]) -> Result<(), TpmResult> + Send + Sync>;
type DeleteHandler = Arc<dyn Fn(StateBlobKind, bool) -> Result<(), TpmResult> + Send + Sync>;

#[derive(Clone, Default)]
pub(crate) struct TestStorage {
    init: Option<InitHandler>,
    probe: Option<ProbeHandler>,
    load: Option<LoadHandler>,
    supports_store: Option<CanStoreHandler>,
    store: Option<StoreHandler>,
    delete: Option<DeleteHandler>,
}

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
impl TestStorage {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn on_init(
        mut self,
        handler: impl Fn() -> Result<(), TpmResult> + Send + Sync + 'static,
    ) -> Self {
        self.init = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_probe(
        mut self,
        handler: impl Fn() -> StorageProbe + Send + Sync + 'static,
    ) -> Self {
        self.probe = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_load(
        mut self,
        handler: impl Fn(StateBlobKind) -> Result<StorageLoad, TpmResult> + Send + Sync + 'static,
    ) -> Self {
        self.load = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_can_store(
        mut self,
        handler: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        self.supports_store = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_store(
        mut self,
        handler: impl Fn(StateBlobKind, &[u8]) -> Result<(), TpmResult> + Send + Sync + 'static,
    ) -> Self {
        self.store = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_delete(
        mut self,
        handler: impl Fn(StateBlobKind, bool) -> Result<(), TpmResult> + Send + Sync + 'static,
    ) -> Self {
        self.delete = Some(Arc::new(handler));
        self
    }

    pub(crate) fn arc(self) -> Arc<dyn Storage> {
        Arc::new(self)
    }
}

impl Storage for TestStorage {
    fn initialize(&self) -> Result<(), TpmResult> {
        match &self.init {
            Some(handler) => handler(),
            None => Ok(()),
        }
    }

    fn probe_permanent(&self) -> StorageProbe {
        if let Some(handler) = &self.probe {
            return handler();
        }
        let unsupported = StorageProbe::Unsupported;
        let Some(load) = &self.load else {
            return unsupported;
        };
        match load(StateBlobKind::Permanent) {
            Ok(StorageLoad::Unsupported) => unsupported,
            Ok(StorageLoad::Missing) => StorageProbe::Missing,
            Ok(StorageLoad::Empty | StorageLoad::Data(_)) | Err(_) => StorageProbe::Present,
        }
    }

    fn load(&self, kind: StateBlobKind) -> Result<StorageLoad, TpmResult> {
        match &self.load {
            Some(handler) => handler(kind),
            None => Ok(StorageLoad::Unsupported),
        }
    }

    fn supports_store(&self) -> bool {
        match &self.supports_store {
            Some(handler) => handler(),
            None => self.store.is_some(),
        }
    }

    fn store(&self, kind: StateBlobKind, data: &[u8]) -> Result<(), TpmResult> {
        match &self.store {
            Some(handler) => handler(kind, data),
            None => Err(crate::library::TPM_FAIL),
        }
    }

    fn delete(&self, kind: StateBlobKind, must_exist: bool) -> Result<(), TpmResult> {
        match &self.delete {
            Some(handler) => handler(kind, must_exist),
            None => Err(crate::library::TPM_FAIL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::TPM_FAIL;
    use std::sync::Mutex;

    #[test]
    fn unconfigured_storage_unsupported() {
        let storage = TestStorage::new();
        assert_eq!(storage.initialize(), Ok(()));
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(StorageLoad::Unsupported)
        );
        assert!(!storage.supports_store());
        assert_eq!(storage.store(StateBlobKind::Permanent, &[1]), Err(TPM_FAIL));
        assert_eq!(
            storage.delete(StateBlobKind::Permanent, true),
            Err(TPM_FAIL)
        );
        assert_eq!(storage.probe_permanent(), StorageProbe::Unsupported);
    }

    #[test]
    fn probe_load_derivation() {
        for (outcome, probe) in [
            (Ok(StorageLoad::Unsupported), StorageProbe::Unsupported),
            (Ok(StorageLoad::Missing), StorageProbe::Missing),
            (Ok(StorageLoad::Empty), StorageProbe::Present),
            (Ok(StorageLoad::Data(vec![1])), StorageProbe::Present),
            (Err(77), StorageProbe::Present),
        ] {
            let handed = outcome.clone();
            let storage = TestStorage::new().on_load(move |_| handed.clone());
            assert_eq!(storage.probe_permanent(), probe, "{outcome:?}");
        }
    }

    #[test]
    fn handler_state_sharing() {
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let store_log = Arc::clone(&log);
        let delete_log = Arc::clone(&log);
        let storage = TestStorage::new()
            .on_store(move |kind, data| {
                store_log
                    .lock()
                    .unwrap()
                    .push(format!("store:{kind:?}:{data:?}"));
                Ok(())
            })
            .on_delete(move |kind, must_exist| {
                delete_log
                    .lock()
                    .unwrap()
                    .push(format!("delete:{kind:?}:{must_exist}"));
                Ok(())
            });

        assert!(
            storage.supports_store(),
            "a store handler implies supports_store"
        );
        assert_eq!(storage.store(StateBlobKind::Permanent, &[7]), Ok(()));
        assert_eq!(storage.delete(StateBlobKind::Volatile, true), Ok(()));
        assert_eq!(
            *log.lock().unwrap(),
            ["store:Permanent:[7]", "delete:Volatile:true"]
        );
    }

    #[test]
    fn configured_probe_precedence() {
        let storage = TestStorage::new()
            .on_load(|_| Ok(StorageLoad::Missing))
            .on_probe(|| StorageProbe::Present);
        assert_eq!(storage.probe_permanent(), StorageProbe::Present);
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(StorageLoad::Missing)
        );
    }

    #[test]
    fn can_store_independence() {
        let storage = TestStorage::new().on_can_store(|| true);
        assert!(storage.supports_store());
        assert_eq!(
            storage.store(StateBlobKind::Permanent, &[1]),
            Err(TPM_FAIL),
            "supports_store is independent of the store handler"
        );
    }
}
