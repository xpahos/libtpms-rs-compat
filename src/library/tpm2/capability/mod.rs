pub(super) mod algorithms;
pub(super) mod commands;
pub(super) mod properties;

pub(super) const TPM_CAP_ALGS: u32 = 0x0000_0000;
pub(super) const TPM_CAP_COMMANDS: u32 = 0x0000_0002;
pub(super) const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;

pub(super) const MAX_CAP_BUFFER: usize = 1024;
pub(super) const MAX_CAP_DATA: usize = MAX_CAP_BUFFER - 4 - 4;

pub(super) struct CapabilityPage<T> {
    pub(super) entries: Vec<T>,
    pub(super) more_data: bool,
}

impl<T> CapabilityPage<T> {
    pub(super) fn empty() -> Self {
        Self {
            entries: Vec::new(),
            more_data: false,
        }
    }
}

pub(super) fn paginate<T>(
    eligible: impl Iterator<Item = T>,
    requested_count: u32,
    capacity: usize,
) -> CapabilityPage<T> {
    let limit = usize::try_from(requested_count)
        .unwrap_or(usize::MAX)
        .min(capacity);
    let mut entries = Vec::with_capacity(limit);
    let mut more_data = false;
    for entry in eligible {
        if entries.len() < limit {
            entries.push(entry);
        } else {
            more_data = true;
            break;
        }
    }
    CapabilityPage { entries, more_data }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_returns_at_most_the_requested_count() {
        let page = paginate(0u32..10, 3, 100);
        assert_eq!(page.entries, [0, 1, 2]);
        assert!(page.more_data);
    }

    #[test]
    fn pagination_caps_the_count_at_the_capacity() {
        let page = paginate(0u32..10, 1000, 4);
        assert_eq!(page.entries, [0, 1, 2, 3]);
        assert!(page.more_data);
    }

    #[test]
    fn count_zero_reports_more_data_when_an_entry_exists() {
        let page = paginate(0u32..10, 0, 100);
        assert!(page.entries.is_empty());
        assert!(page.more_data);
    }

    #[test]
    fn count_zero_with_no_eligible_entries_reports_no_more_data() {
        let page = paginate(core::iter::empty::<u32>(), 0, 100);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn an_exactly_consumed_iterator_reports_no_more_data() {
        let page = paginate(0u32..4, 4, 100);
        assert_eq!(page.entries, [0, 1, 2, 3]);
        assert!(!page.more_data);
    }

    #[test]
    fn oversized_counts_do_not_over_allocate() {
        let page = paginate(core::iter::empty::<u32>(), u32::MAX, 254);
        assert!(page.entries.capacity() <= 254);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }
}
