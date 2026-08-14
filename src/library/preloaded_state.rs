use super::state_blob::StateBlobKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library) enum PreloadedBlob {
    Missing,
    Empty,
    Data(Vec<u8>),
}

impl PreloadedBlob {
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

pub(in crate::library) struct PreloadedState {
    permanent: PreloadedBlob,
    volatile: PreloadedBlob,
    save_state: PreloadedBlob,
}

impl PreloadedState {
    pub(in crate::library) const fn new() -> Self {
        Self {
            permanent: PreloadedBlob::Missing,
            volatile: PreloadedBlob::Missing,
            save_state: PreloadedBlob::Missing,
        }
    }

    fn slot(&self, kind: StateBlobKind) -> &PreloadedBlob {
        match kind {
            StateBlobKind::Permanent => &self.permanent,
            StateBlobKind::Volatile => &self.volatile,
            StateBlobKind::SaveState => &self.save_state,
        }
    }

    fn slot_mut(&mut self, kind: StateBlobKind) -> &mut PreloadedBlob {
        match kind {
            StateBlobKind::Permanent => &mut self.permanent,
            StateBlobKind::Volatile => &mut self.volatile,
            StateBlobKind::SaveState => &mut self.save_state,
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
    pub(in crate::library) fn get(&self, kind: StateBlobKind) -> &PreloadedBlob {
        self.slot(kind)
    }

    #[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
    pub(in crate::library) fn set_data(&mut self, kind: StateBlobKind, data: Vec<u8>) {
        *self.slot_mut(kind) = PreloadedBlob::from_data(data);
    }

    #[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
    pub(in crate::library) fn set_empty(&mut self, kind: StateBlobKind) {
        *self.slot_mut(kind) = PreloadedBlob::Empty;
    }

    #[allow(dead_code)]
    pub(in crate::library) fn clear(&mut self, kind: StateBlobKind) {
        *self.slot_mut(kind) = PreloadedBlob::Missing;
    }

    pub(in crate::library) fn clear_all(&mut self) {
        self.permanent = PreloadedBlob::Missing;
        self.volatile = PreloadedBlob::Missing;
        self.save_state = PreloadedBlob::Missing;
    }

    #[allow(dead_code)]
    pub(in crate::library) fn is_present(&self, kind: StateBlobKind) -> bool {
        self.slot(kind).is_present()
    }

    #[allow(dead_code)]
    pub(in crate::library) fn take(&mut self, kind: StateBlobKind) -> PreloadedBlob {
        core::mem::replace(self.slot_mut(kind), PreloadedBlob::Missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_preloaded_state_has_three_missing_entries() {
        let preloaded = PreloadedState::new();
        for kind in [
            StateBlobKind::Permanent,
            StateBlobKind::Volatile,
            StateBlobKind::SaveState,
        ] {
            assert_eq!(*preloaded.get(kind), PreloadedBlob::Missing);
            assert!(!preloaded.is_present(kind));
        }
    }

    #[test]
    fn preloaded_blob_variants_are_distinct() {
        assert_ne!(PreloadedBlob::Missing, PreloadedBlob::Empty);
        assert_ne!(PreloadedBlob::Empty, PreloadedBlob::Data(vec![0]));
        assert_ne!(PreloadedBlob::Missing, PreloadedBlob::Data(vec![0]));
    }

    #[test]
    fn empty_vec_normalizes_to_empty_blob() {
        let mut preloaded = PreloadedState::new();
        preloaded.set_data(StateBlobKind::Volatile, Vec::new());
        assert_eq!(
            *preloaded.get(StateBlobKind::Volatile),
            PreloadedBlob::Empty
        );
    }

    #[test]
    fn empty_blob_counts_as_preloaded_state() {
        let mut preloaded = PreloadedState::new();
        preloaded.set_empty(StateBlobKind::Permanent);
        assert!(preloaded.is_present(StateBlobKind::Permanent));
    }

    #[test]
    fn data_blob_counts_as_preloaded_state() {
        let mut preloaded = PreloadedState::new();
        preloaded.set_data(StateBlobKind::Permanent, vec![1]);
        assert!(preloaded.is_present(StateBlobKind::Permanent));
        assert_eq!(
            *preloaded.get(StateBlobKind::Permanent),
            PreloadedBlob::Data(vec![1])
        );
    }

    #[test]
    fn clearing_one_entry_leaves_the_others() {
        let mut preloaded = PreloadedState::new();
        preloaded.set_data(StateBlobKind::Permanent, vec![1]);
        preloaded.set_empty(StateBlobKind::Volatile);
        preloaded.clear(StateBlobKind::Permanent);
        assert!(!preloaded.is_present(StateBlobKind::Permanent));
        assert!(preloaded.is_present(StateBlobKind::Volatile));
    }

    #[test]
    fn clear_all_resets_every_entry_to_missing() {
        let mut preloaded = PreloadedState::new();
        preloaded.set_data(StateBlobKind::Permanent, vec![1]);
        preloaded.set_empty(StateBlobKind::Volatile);
        preloaded.set_data(StateBlobKind::SaveState, vec![2]);
        preloaded.clear_all();
        for kind in [
            StateBlobKind::Permanent,
            StateBlobKind::Volatile,
            StateBlobKind::SaveState,
        ] {
            assert_eq!(*preloaded.get(kind), PreloadedBlob::Missing);
        }
    }

    #[test]
    fn take_transfers_ownership_and_resets_to_missing() {
        let mut preloaded = PreloadedState::new();
        preloaded.set_data(StateBlobKind::SaveState, vec![9, 9]);
        assert_eq!(
            preloaded.take(StateBlobKind::SaveState),
            PreloadedBlob::Data(vec![9, 9])
        );
        assert!(!preloaded.is_present(StateBlobKind::SaveState));
    }
}
