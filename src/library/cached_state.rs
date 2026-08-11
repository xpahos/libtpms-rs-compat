use crate::ffi_types::TpmlibStateType;

const TPMLIB_STATE_PERMANENT: TpmlibStateType = 1;
const TPMLIB_STATE_VOLATILE: TpmlibStateType = 2;
const TPMLIB_STATE_SAVE_STATE: TpmlibStateType = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library) enum StateKind {
    Permanent,
    Volatile,
    SaveState,
}

impl StateKind {
    #[allow(dead_code)]
    pub(in crate::library) fn from_c(value: TpmlibStateType) -> Option<Self> {
        match value {
            TPMLIB_STATE_PERMANENT => Some(Self::Permanent),
            TPMLIB_STATE_VOLATILE => Some(Self::Volatile),
            TPMLIB_STATE_SAVE_STATE => Some(Self::SaveState),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library) enum CachedBlob {
    Missing,
    Empty,
    Data(Vec<u8>),
}

impl CachedBlob {
    fn from_data(data: Vec<u8>) -> Self {
        if data.is_empty() {
            Self::Empty
        } else {
            Self::Data(data)
        }
    }

    fn is_present(&self) -> bool {
        !matches!(self, Self::Missing)
    }
}

pub(in crate::library) struct CachedState {
    permanent: CachedBlob,
    volatile: CachedBlob,
    save_state: CachedBlob,
}

impl CachedState {
    pub(in crate::library) const fn new() -> Self {
        Self {
            permanent: CachedBlob::Missing,
            volatile: CachedBlob::Missing,
            save_state: CachedBlob::Missing,
        }
    }

    fn slot(&self, kind: StateKind) -> &CachedBlob {
        match kind {
            StateKind::Permanent => &self.permanent,
            StateKind::Volatile => &self.volatile,
            StateKind::SaveState => &self.save_state,
        }
    }

    fn slot_mut(&mut self, kind: StateKind) -> &mut CachedBlob {
        match kind {
            StateKind::Permanent => &mut self.permanent,
            StateKind::Volatile => &mut self.volatile,
            StateKind::SaveState => &mut self.save_state,
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
    pub(in crate::library) fn get(&self, kind: StateKind) -> &CachedBlob {
        self.slot(kind)
    }

    #[allow(dead_code)]
    pub(in crate::library) fn set_data(&mut self, kind: StateKind, data: Vec<u8>) {
        *self.slot_mut(kind) = CachedBlob::from_data(data);
    }

    #[allow(dead_code)]
    pub(in crate::library) fn set_empty(&mut self, kind: StateKind) {
        *self.slot_mut(kind) = CachedBlob::Empty;
    }

    #[allow(dead_code)]
    pub(in crate::library) fn clear(&mut self, kind: StateKind) {
        *self.slot_mut(kind) = CachedBlob::Missing;
    }

    pub(in crate::library) fn clear_all(&mut self) {
        self.permanent = CachedBlob::Missing;
        self.volatile = CachedBlob::Missing;
        self.save_state = CachedBlob::Missing;
    }

    #[allow(dead_code)]
    pub(in crate::library) fn is_present(&self, kind: StateKind) -> bool {
        self.slot(kind).is_present()
    }

    #[allow(dead_code)]
    pub(in crate::library) fn take(&mut self, kind: StateKind) -> CachedBlob {
        core::mem::replace(self.slot_mut(kind), CachedBlob::Missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_kind_maps_exact_c_values() {
        assert_eq!(StateKind::from_c(1), Some(StateKind::Permanent));
        assert_eq!(StateKind::from_c(2), Some(StateKind::Volatile));
        assert_eq!(StateKind::from_c(4), Some(StateKind::SaveState));
    }

    #[test]
    fn state_kind_rejects_invalid_values() {
        for value in [0, 3, -1, -4, 5, 6, 7, 8, i32::MAX, i32::MIN] {
            assert_eq!(StateKind::from_c(value), None, "value {value}");
        }
    }

    #[test]
    fn new_cache_has_three_missing_entries() {
        let cache = CachedState::new();
        for kind in [
            StateKind::Permanent,
            StateKind::Volatile,
            StateKind::SaveState,
        ] {
            assert_eq!(*cache.get(kind), CachedBlob::Missing);
            assert!(!cache.is_present(kind));
        }
    }

    #[test]
    fn cached_blob_variants_are_distinct() {
        assert_ne!(CachedBlob::Missing, CachedBlob::Empty);
        assert_ne!(CachedBlob::Empty, CachedBlob::Data(vec![0]));
        assert_ne!(CachedBlob::Missing, CachedBlob::Data(vec![0]));
    }

    #[test]
    fn empty_vec_normalizes_to_empty_blob() {
        let mut cache = CachedState::new();
        cache.set_data(StateKind::Volatile, Vec::new());
        assert_eq!(*cache.get(StateKind::Volatile), CachedBlob::Empty);
    }

    #[test]
    fn empty_blob_counts_as_cached_state() {
        let mut cache = CachedState::new();
        cache.set_empty(StateKind::Permanent);
        assert!(cache.is_present(StateKind::Permanent));
    }

    #[test]
    fn data_blob_counts_as_cached_state() {
        let mut cache = CachedState::new();
        cache.set_data(StateKind::Permanent, vec![1]);
        assert!(cache.is_present(StateKind::Permanent));
        assert_eq!(*cache.get(StateKind::Permanent), CachedBlob::Data(vec![1]));
    }

    #[test]
    fn clearing_one_entry_leaves_the_others() {
        let mut cache = CachedState::new();
        cache.set_data(StateKind::Permanent, vec![1]);
        cache.set_empty(StateKind::Volatile);
        cache.clear(StateKind::Permanent);
        assert!(!cache.is_present(StateKind::Permanent));
        assert!(cache.is_present(StateKind::Volatile));
    }

    #[test]
    fn clear_all_resets_every_entry_to_missing() {
        let mut cache = CachedState::new();
        cache.set_data(StateKind::Permanent, vec![1]);
        cache.set_empty(StateKind::Volatile);
        cache.set_data(StateKind::SaveState, vec![2]);
        cache.clear_all();
        for kind in [
            StateKind::Permanent,
            StateKind::Volatile,
            StateKind::SaveState,
        ] {
            assert_eq!(*cache.get(kind), CachedBlob::Missing);
        }
    }

    #[test]
    fn take_transfers_ownership_and_resets_to_missing() {
        let mut cache = CachedState::new();
        cache.set_data(StateKind::SaveState, vec![9, 9]);
        assert_eq!(
            cache.take(StateKind::SaveState),
            CachedBlob::Data(vec![9, 9])
        );
        assert!(!cache.is_present(StateKind::SaveState));
    }
}
