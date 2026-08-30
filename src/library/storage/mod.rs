#[cfg(test)]
pub(crate) mod test_support;

use crate::types::TpmResult;

use super::constants::TPM_FAIL;
use super::state_blob::StateBlobKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageLoad {
    Unsupported,
    Missing,
    Empty,
    Data(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageProbe {
    Unsupported,
    Missing,
    Present,
}

pub trait Storage: Send + Sync {
    fn initialize(&self) -> Result<(), TpmResult>;

    fn probe_permanent(&self) -> StorageProbe;

    fn load(&self, kind: StateBlobKind) -> Result<StorageLoad, TpmResult>;

    fn supports_store(&self) -> bool;

    fn store(&self, kind: StateBlobKind, data: &[u8]) -> Result<(), TpmResult>;

    fn delete(&self, kind: StateBlobKind, must_exist: bool) -> Result<(), TpmResult>;
}

pub struct NoStorage;

impl Storage for NoStorage {
    fn initialize(&self) -> Result<(), TpmResult> {
        Ok(())
    }

    fn probe_permanent(&self) -> StorageProbe {
        StorageProbe::Unsupported
    }

    fn load(&self, _kind: StateBlobKind) -> Result<StorageLoad, TpmResult> {
        Ok(StorageLoad::Unsupported)
    }

    fn supports_store(&self) -> bool {
        false
    }

    fn store(&self, _kind: StateBlobKind, _data: &[u8]) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
    }

    fn delete(&self, _kind: StateBlobKind, _must_exist: bool) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
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
        assert_eq!(storage.initialize(), Ok(()));
        assert!(!storage.supports_store());
        for kind in ALL_KINDS {
            assert_eq!(storage.load(kind), Ok(StorageLoad::Unsupported));
            assert_eq!(storage.store(kind, &[1, 2, 3]), Err(TPM_FAIL));
            for must_exist in [false, true] {
                assert_eq!(storage.delete(kind, must_exist), Err(TPM_FAIL));
            }
        }
    }

    #[test]
    fn no_storage_absent_probe() {
        assert_eq!(NoStorage.probe_permanent(), StorageProbe::Unsupported);
    }
}
