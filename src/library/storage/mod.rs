#[cfg(test)]
pub(crate) mod test_support;

use crate::types::TpmResult;

use super::state_blob::StateBlobKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageLoad {
    Unsupported,
    Missing,
    Empty,
    Data(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageOperation {
    Unsupported,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageProbe {
    pub exists: bool,
    pub load_supported: bool,
}

pub trait Storage: Send + Sync {
    fn init(&self) -> Result<StorageOperation, TpmResult>;

    fn probe_permanent(&self) -> StorageProbe;

    fn load(&self, kind: StateBlobKind) -> Result<StorageLoad, TpmResult>;

    fn can_store(&self) -> bool;

    fn store(&self, kind: StateBlobKind, data: &[u8]) -> Result<StorageOperation, TpmResult>;

    fn delete(&self, kind: StateBlobKind, must_exist: bool) -> Result<StorageOperation, TpmResult>;
}

pub struct NoStorage;

impl Storage for NoStorage {
    fn init(&self) -> Result<StorageOperation, TpmResult> {
        Ok(StorageOperation::Unsupported)
    }

    fn probe_permanent(&self) -> StorageProbe {
        StorageProbe {
            exists: false,
            load_supported: false,
        }
    }

    fn load(&self, _kind: StateBlobKind) -> Result<StorageLoad, TpmResult> {
        Ok(StorageLoad::Unsupported)
    }

    fn can_store(&self) -> bool {
        false
    }

    fn store(&self, _kind: StateBlobKind, _data: &[u8]) -> Result<StorageOperation, TpmResult> {
        Ok(StorageOperation::Unsupported)
    }

    fn delete(
        &self,
        _kind: StateBlobKind,
        _must_exist: bool,
    ) -> Result<StorageOperation, TpmResult> {
        Ok(StorageOperation::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: [StateBlobKind; 3] = [
        StateBlobKind::Permanent,
        StateBlobKind::Volatile,
        StateBlobKind::SaveState,
    ];

    #[test]
    fn no_storage_unsupported_operations() {
        let storage = NoStorage;
        assert_eq!(storage.init(), Ok(StorageOperation::Unsupported));
        assert!(!storage.can_store());
        for kind in ALL_KINDS {
            assert_eq!(storage.load(kind), Ok(StorageLoad::Unsupported));
            assert_eq!(
                storage.store(kind, &[1, 2, 3]),
                Ok(StorageOperation::Unsupported)
            );
            for must_exist in [false, true] {
                assert_eq!(
                    storage.delete(kind, must_exist),
                    Ok(StorageOperation::Unsupported)
                );
            }
        }
    }

    #[test]
    fn no_storage_absent_probe() {
        assert_eq!(
            NoStorage.probe_permanent(),
            StorageProbe {
                exists: false,
                load_supported: false,
            }
        );
    }
}
