use std::sync::Arc;

use crate::types::TpmResult;

use super::super::state_blob::StateBlobKind;
use super::{Storage, StorageLoad, StorageOperation, StorageProbe};

type InitHandler = Arc<dyn Fn() -> Result<StorageOperation, TpmResult> + Send + Sync>;
type ProbeHandler = Arc<dyn Fn() -> StorageProbe + Send + Sync>;
type LoadHandler = Arc<dyn Fn(StateBlobKind) -> Result<StorageLoad, TpmResult> + Send + Sync>;
type CanStoreHandler = Arc<dyn Fn() -> bool + Send + Sync>;
type StoreHandler =
    Arc<dyn Fn(StateBlobKind, &[u8]) -> Result<StorageOperation, TpmResult> + Send + Sync>;
type DeleteHandler =
    Arc<dyn Fn(StateBlobKind, bool) -> Result<StorageOperation, TpmResult> + Send + Sync>;

#[derive(Clone, Default)]
pub(crate) struct TestStorage {
    init: Option<InitHandler>,
    probe: Option<ProbeHandler>,
    load: Option<LoadHandler>,
    can_store: Option<CanStoreHandler>,
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
        handler: impl Fn() -> Result<StorageOperation, TpmResult> + Send + Sync + 'static,
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
        self.can_store = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_store(
        mut self,
        handler: impl Fn(StateBlobKind, &[u8]) -> Result<StorageOperation, TpmResult>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.store = Some(Arc::new(handler));
        self
    }

    pub(crate) fn on_delete(
        mut self,
        handler: impl Fn(StateBlobKind, bool) -> Result<StorageOperation, TpmResult>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.delete = Some(Arc::new(handler));
        self
    }

    pub(crate) fn arc(self) -> Arc<dyn Storage> {
        Arc::new(self)
    }
}

impl Storage for TestStorage {
    fn init(&self) -> Result<StorageOperation, TpmResult> {
        match &self.init {
            Some(handler) => handler(),
            None => Ok(StorageOperation::Unsupported),
        }
    }

    fn probe_permanent(&self) -> StorageProbe {
        if let Some(handler) = &self.probe {
            return handler();
        }
        let unsupported = StorageProbe {
            exists: false,
            load_supported: false,
        };
        let Some(load) = &self.load else {
            return unsupported;
        };
        match load(StateBlobKind::Permanent) {
            Ok(StorageLoad::Unsupported) => unsupported,
            Ok(StorageLoad::Missing) => StorageProbe {
                exists: false,
                load_supported: true,
            },
            Ok(StorageLoad::Empty | StorageLoad::Data(_)) | Err(_) => StorageProbe {
                exists: true,
                load_supported: true,
            },
        }
    }

    fn load(&self, kind: StateBlobKind) -> Result<StorageLoad, TpmResult> {
        match &self.load {
            Some(handler) => handler(kind),
            None => Ok(StorageLoad::Unsupported),
        }
    }

    fn can_store(&self) -> bool {
        match &self.can_store {
            Some(handler) => handler(),
            None => self.store.is_some(),
        }
    }

    fn store(&self, kind: StateBlobKind, data: &[u8]) -> Result<StorageOperation, TpmResult> {
        match &self.store {
            Some(handler) => handler(kind, data),
            None => Ok(StorageOperation::Unsupported),
        }
    }

    fn delete(&self, kind: StateBlobKind, must_exist: bool) -> Result<StorageOperation, TpmResult> {
        match &self.delete {
            Some(handler) => handler(kind, must_exist),
            None => Ok(StorageOperation::Unsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn unconfigured_storage_unsupported() {
        let storage = TestStorage::new();
        assert_eq!(storage.init(), Ok(StorageOperation::Unsupported));
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(StorageLoad::Unsupported)
        );
        assert!(!storage.can_store());
        assert_eq!(
            storage.store(StateBlobKind::Permanent, &[1]),
            Ok(StorageOperation::Unsupported)
        );
        assert_eq!(
            storage.delete(StateBlobKind::Permanent, true),
            Ok(StorageOperation::Unsupported)
        );
        assert_eq!(
            storage.probe_permanent(),
            StorageProbe {
                exists: false,
                load_supported: false,
            }
        );
    }

    #[test]
    fn probe_load_derivation() {
        for (outcome, exists, load_supported) in [
            (Ok(StorageLoad::Unsupported), false, false),
            (Ok(StorageLoad::Missing), false, true),
            (Ok(StorageLoad::Empty), true, true),
            (Ok(StorageLoad::Data(vec![1])), true, true),
            (Err(77), true, true),
        ] {
            let handed = outcome.clone();
            let storage = TestStorage::new().on_load(move |_| handed.clone());
            assert_eq!(
                storage.probe_permanent(),
                StorageProbe {
                    exists,
                    load_supported,
                },
                "{outcome:?}"
            );
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
                Ok(StorageOperation::Done)
            })
            .on_delete(move |kind, must_exist| {
                delete_log
                    .lock()
                    .unwrap()
                    .push(format!("delete:{kind:?}:{must_exist}"));
                Ok(StorageOperation::Done)
            });

        assert!(storage.can_store(), "a store handler implies can_store");
        assert_eq!(
            storage.store(StateBlobKind::Permanent, &[7]),
            Ok(StorageOperation::Done)
        );
        assert_eq!(
            storage.delete(StateBlobKind::Volatile, true),
            Ok(StorageOperation::Done)
        );
        assert_eq!(
            *log.lock().unwrap(),
            ["store:Permanent:[7]", "delete:Volatile:true"]
        );
    }

    #[test]
    fn configured_probe_precedence() {
        let storage = TestStorage::new()
            .on_load(|_| Ok(StorageLoad::Missing))
            .on_probe(|| StorageProbe {
                exists: true,
                load_supported: true,
            });
        assert_eq!(
            storage.probe_permanent(),
            StorageProbe {
                exists: true,
                load_supported: true,
            }
        );
        assert_eq!(
            storage.load(StateBlobKind::Permanent),
            Ok(StorageLoad::Missing)
        );
    }

    #[test]
    fn can_store_independence() {
        let storage = TestStorage::new().on_can_store(|| true);
        assert!(storage.can_store());
        assert_eq!(
            storage.store(StateBlobKind::Permanent, &[1]),
            Ok(StorageOperation::Unsupported),
            "can_store is independent of the store handler"
        );
    }
}
