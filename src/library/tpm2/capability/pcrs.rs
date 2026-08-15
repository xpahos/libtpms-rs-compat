use super::super::algorithm::{algorithm_enabled, hash_profile_name};
use super::super::persistent::{OwnedPcrAllocation, OwnedPcrSelection};
use super::CapabilityPage;

/// Collects the `TPML_PCR_SELECTION` for `TPM_CAP_PCRS`.
///
/// Upstream's `PCRCapGetAllocation()` ignores `requested_count` except for the
/// single case of zero, which answers an empty list and `moreData` set; any
/// other count copies the whole of `gp.pcrAllocated` and clears `moreData`.
/// The list is therefore never paged and never truncated to the count.
pub(in crate::library::tpm2) fn collect(
    allocation: &OwnedPcrAllocation,
    profile_algorithms: &[u8],
    requested_count: u32,
) -> CapabilityPage<OwnedPcrSelection> {
    if requested_count == 0 {
        // `PCRCapGetAllocation()` returns YES for a zero count whether or not
        // any bank is allocated, so this is not the usual "an entry remains".
        return CapabilityPage {
            entries: Vec::new(),
            more_data: true,
        };
    }
    let mut entries = allocation.selections.clone();
    filter_disabled_banks(&mut entries, profile_algorithms);
    CapabilityPage {
        entries,
        more_data: false,
    }
}

/// Drops the banks the active profile disables, exactly as upstream's
/// `RuntimeAlgorithmsFilterPCRSelection()` does.
///
/// That loop decrements `count` and then only closes the gap when
/// `count - 1 > i`, so removing the entry at `count - 2` leaves the entry after
/// it outside the new count and the re-examined slot removes a second entry.
/// A disabled bank therefore never survives, but an enabled bank that follows
/// one can be dropped with it.  Restored state blobs may carry an allocation of
/// any length, so the quirk is reachable and is reproduced rather than fixed.
fn filter_disabled_banks(selections: &mut Vec<OwnedPcrSelection>, profile_algorithms: &[u8]) {
    let mut count = selections.len();
    let mut index = 0;
    while index < count {
        if bank_enabled(selections[index].hash_alg, profile_algorithms) {
            index += 1;
            continue;
        }
        count -= 1;
        // Upstream's guard is `count - 1 > i` on an unsigned count; a count of
        // zero wraps it to true but then copies `count - i` == 0 entries, so
        // the underflow is inert and the saturating form matches it.
        if count.saturating_sub(1) > index {
            // Upstream copies `count - index` entries from `index + 1` down to
            // `index`; rotating the same span leaves the identical contents
            // below the new count and parks the removed entry above it, where
            // nothing reads it again.
            selections[index..=count].rotate_left(1);
        }
    }
    selections.truncate(count);
}

fn bank_enabled(hash_alg: u16, profile_algorithms: &[u8]) -> bool {
    hash_profile_name(hash_alg).is_some_and(|name| algorithm_enabled(profile_algorithms, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;

    const ALL_BANKS: &[u8] = b"sha1,sha256,sha384,sha512,aes,null";
    const NO_SHA1: &[u8] = b"sha256,sha384,sha512,aes,null";
    const NO_SHA512: &[u8] = b"sha1,sha256,sha384,aes,null";
    const NO_SHA1_SHA512: &[u8] = b"sha256,sha384,aes,null";

    fn allocation(algs: &[u16]) -> OwnedPcrAllocation {
        OwnedPcrAllocation {
            selections: algs
                .iter()
                .enumerate()
                .map(|(index, &hash_alg)| OwnedPcrSelection {
                    hash_alg,
                    select: vec![0x10 + index as u8; 3],
                })
                .collect(),
        }
    }

    /// `oracle18` prints the filtered list as `hash/first bitmap byte` pairs.
    #[track_caller]
    fn filtered(algs: &[u16], profile: &[u8]) -> Vec<(u16, u8)> {
        let mut selections = allocation(algs).selections;
        filter_disabled_banks(&mut selections, profile);
        selections
            .iter()
            .map(|entry| (entry.hash_alg, entry.select[0]))
            .collect()
    }

    #[test]
    fn an_all_banks_profile_filters_nothing() {
        for algs in [
            &[][..],
            &[TPM_ALG_SHA1],
            &[TPM_ALG_SHA256, TPM_ALG_SHA1],
            &[TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512],
        ] {
            let expected: Vec<(u16, u8)> = algs
                .iter()
                .enumerate()
                .map(|(index, &alg)| (alg, 0x10 + index as u8))
                .collect();
            assert_eq!(filtered(algs, ALL_BANKS), expected, "{algs:04x?}");
        }
    }

    /// Every case here is a line of `oracle18.out`.
    #[test]
    fn the_disabled_bank_filter_matches_the_oracle() {
        const S1: u16 = TPM_ALG_SHA1;
        const S256: u16 = TPM_ALG_SHA256;
        const S384: u16 = TPM_ALG_SHA384;
        const S512: u16 = TPM_ALG_SHA512;

        // == no_sha1 ==
        assert_eq!(filtered(&[], NO_SHA1), []);
        assert_eq!(filtered(&[S1], NO_SHA1), []);
        assert_eq!(filtered(&[S256], NO_SHA1), [(S256, 0x10)]);
        assert_eq!(filtered(&[S512], NO_SHA1), [(S512, 0x10)]);
        assert_eq!(filtered(&[S1, S256], NO_SHA1), []);
        assert_eq!(filtered(&[S256, S1], NO_SHA1), [(S256, 0x10)]);
        assert_eq!(filtered(&[S1, S512], NO_SHA1), []);
        assert_eq!(filtered(&[S512, S1], NO_SHA1), [(S512, 0x10)]);
        assert_eq!(
            filtered(&[S256, S384], NO_SHA1),
            [(S256, 0x10), (S384, 0x11)]
        );
        assert_eq!(
            filtered(&[S1, S256, S384], NO_SHA1),
            [(S256, 0x11), (S384, 0x12)]
        );
        assert_eq!(filtered(&[S256, S1, S384], NO_SHA1), [(S256, 0x10)]);
        assert_eq!(
            filtered(&[S256, S384, S1], NO_SHA1),
            [(S256, 0x10), (S384, 0x11)]
        );
        assert_eq!(
            filtered(&[S1, S512, S256], NO_SHA1),
            [(S512, 0x11), (S256, 0x12)]
        );
        assert_eq!(filtered(&[S256, S1, S512], NO_SHA1), [(S256, 0x10)]);
        assert_eq!(
            filtered(&[S1, S256, S512], NO_SHA1),
            [(S256, 0x11), (S512, 0x12)]
        );
        assert_eq!(
            filtered(&[S1, S256, S384, S512], NO_SHA1),
            [(S256, 0x11), (S384, 0x12), (S512, 0x13)]
        );
        assert_eq!(
            filtered(&[S256, S1, S512, S384], NO_SHA1),
            [(S256, 0x10), (S512, 0x12), (S384, 0x13)]
        );
        assert_eq!(
            filtered(&[S256, S384, S1, S512], NO_SHA1),
            [(S256, 0x10), (S384, 0x11)]
        );
        assert_eq!(
            filtered(&[S1, S512, S256, S384], NO_SHA1),
            [(S512, 0x11), (S256, 0x12), (S384, 0x13)]
        );
        assert_eq!(filtered(&[S1, S1, S256], NO_SHA1), []);

        // == no_sha512 ==
        assert_eq!(filtered(&[S512], NO_SHA512), []);
        assert_eq!(filtered(&[S1, S512], NO_SHA512), [(S1, 0x10)]);
        assert_eq!(filtered(&[S512, S1], NO_SHA512), []);
        assert_eq!(filtered(&[S1, S512, S256], NO_SHA512), [(S1, 0x10)]);
        assert_eq!(
            filtered(&[S256, S1, S512], NO_SHA512),
            [(S256, 0x10), (S1, 0x11)]
        );
        assert_eq!(
            filtered(&[S1, S256, S512], NO_SHA512),
            [(S1, 0x10), (S256, 0x11)]
        );
        assert_eq!(
            filtered(&[S1, S256, S384, S512], NO_SHA512),
            [(S1, 0x10), (S256, 0x11), (S384, 0x12)]
        );
        assert_eq!(
            filtered(&[S256, S1, S512, S384], NO_SHA512),
            [(S256, 0x10), (S1, 0x11)]
        );
        assert_eq!(
            filtered(&[S256, S384, S1, S512], NO_SHA512),
            [(S256, 0x10), (S384, 0x11), (S1, 0x12)]
        );
        assert_eq!(
            filtered(&[S1, S512, S256, S384], NO_SHA512),
            [(S1, 0x10), (S256, 0x12), (S384, 0x13)]
        );
        assert_eq!(
            filtered(&[S1, S1, S256], NO_SHA512),
            [(S1, 0x10), (S1, 0x11), (S256, 0x12)]
        );

        // == no_sha1_no_sha512 ==
        assert_eq!(filtered(&[S1], NO_SHA1_SHA512), []);
        assert_eq!(filtered(&[S512], NO_SHA1_SHA512), []);
        assert_eq!(filtered(&[S1, S256], NO_SHA1_SHA512), []);
        assert_eq!(filtered(&[S256, S1], NO_SHA1_SHA512), [(S256, 0x10)]);
        assert_eq!(filtered(&[S512, S1], NO_SHA1_SHA512), []);
        assert_eq!(filtered(&[S1, S512, S256], NO_SHA1_SHA512), []);
        assert_eq!(filtered(&[S256, S1, S512], NO_SHA1_SHA512), [(S256, 0x10)]);
        assert_eq!(filtered(&[S1, S256, S512], NO_SHA1_SHA512), [(S256, 0x11)]);
        assert_eq!(
            filtered(&[S1, S256, S384, S512], NO_SHA1_SHA512),
            [(S256, 0x11), (S384, 0x12)]
        );
        assert_eq!(
            filtered(&[S256, S1, S512, S384], NO_SHA1_SHA512),
            [(S256, 0x10)]
        );
        assert_eq!(
            filtered(&[S256, S384, S1, S512], NO_SHA1_SHA512),
            [(S256, 0x10), (S384, 0x11)]
        );
        assert_eq!(
            filtered(&[S1, S512, S256, S384], NO_SHA1_SHA512),
            [(S256, 0x12), (S384, 0x13)]
        );
        assert_eq!(filtered(&[S1, S1, S256], NO_SHA1_SHA512), []);
    }

    #[test]
    fn a_disabled_bank_never_survives_the_filter() {
        const BANKS: [u16; 4] = [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512];
        for profile in [ALL_BANKS, NO_SHA1, NO_SHA512, NO_SHA1_SHA512] {
            // Every ordered arrangement of one to four banks, with repeats.
            for length in 0..=4usize {
                let combinations = 4usize.pow(length as u32);
                for encoded in 0..combinations {
                    let algs: Vec<u16> = (0..length)
                        .map(|slot| BANKS[(encoded >> (2 * slot)) & 0b11])
                        .collect();
                    for (alg, _) in filtered(&algs, profile) {
                        assert!(
                            bank_enabled(alg, profile),
                            "{alg:#06x} survived {algs:04x?} under {}",
                            String::from_utf8_lossy(profile)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_unknown_bank_algorithm_counts_as_disabled() {
        for alg in [0x0000u16, 0x0010, 0x0012, 0x0027, 0xffff] {
            assert!(!bank_enabled(alg, ALL_BANKS), "alg {alg:#06x}");
        }
    }

    #[test]
    fn a_zero_count_reports_more_data_and_no_entries() {
        for algs in [&[][..], &[TPM_ALG_SHA256]] {
            let page = collect(&allocation(algs), ALL_BANKS, 0);
            assert!(page.entries.is_empty());
            assert!(page.more_data, "upstream answers YES for a zero count");
        }
    }

    #[test]
    fn any_non_zero_count_returns_the_whole_allocation() {
        let allocation = allocation(&[TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384]);
        for count in [1u32, 2, 3, 4, 64, u32::MAX] {
            let page = collect(&allocation, ALL_BANKS, count);
            assert_eq!(page.entries.len(), 3, "count {count}");
            assert!(!page.more_data, "count {count}");
        }
    }

    #[test]
    fn an_empty_allocation_returns_an_empty_list_without_more_data() {
        let page = collect(&allocation(&[]), ALL_BANKS, 64);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn the_bitmaps_are_returned_verbatim() {
        let allocation = OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0xa5, 0x3c, 0x81],
            }],
        };
        let page = collect(&allocation, ALL_BANKS, 64);
        assert_eq!(page.entries[0].select, [0xa5, 0x3c, 0x81]);
    }
}
