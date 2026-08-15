use super::super::hierarchy::IMPLEMENTED_PERMANENT_HANDLES;
use super::super::live::LiveState;
use super::super::object::ATTR_OCCUPIED;
use super::super::persistent::{OwnedPersistentState, OwnedUserNvramEntry};
use super::super::volatile::MAX_LOADED_SESSIONS;
use super::{CapabilityPage, MAX_CAP_DATA, paginate};

const SIZEOF_TPM_HANDLE: usize = 4;
pub(super) const MAX_CAP_HANDLES: usize = MAX_CAP_DATA / SIZEOF_TPM_HANDLE;

const HR_SHIFT: u32 = 24;
const HR_HANDLE_MASK: u32 = 0x00ff_ffff;

const TPM_HT_PCR: u32 = 0x00;
const TPM_HT_NV_INDEX: u32 = 0x01;
const TPM_HT_HMAC_SESSION: u32 = 0x02;
const TPM_HT_POLICY_SESSION: u32 = 0x03;
const TPM_HT_PERMANENT: u32 = 0x40;
const TPM_HT_TRANSIENT: u32 = 0x80;
const TPM_HT_PERSISTENT: u32 = 0x81;

const fn handle_range(handle_type: u32) -> u32 {
    handle_type << HR_SHIFT
}

const PCR_FIRST: u32 = handle_range(TPM_HT_PCR);
const HMAC_SESSION_FIRST: u32 = handle_range(TPM_HT_HMAC_SESSION);
const POLICY_SESSION_FIRST: u32 = handle_range(TPM_HT_POLICY_SESSION);
const TRANSIENT_FIRST: u32 = handle_range(TPM_HT_TRANSIENT);

const SESSION_ATTR_IS_POLICY: u32 = 1 << 0;

#[derive(Clone, Copy, Eq, PartialEq)]
enum NvramEntryKind {
    Index,
    Persistent,
}

pub(in crate::library::tpm2) fn collect(
    live: &LiveState,
    state: &OwnedPersistentState,
    property: u32,
    requested_count: u32,
) -> Option<CapabilityPage<u32>> {
    let page = match property >> HR_SHIFT {
        TPM_HT_PCR => pcr(live, property, requested_count),
        TPM_HT_NV_INDEX => user_nvram(state, property, requested_count, NvramEntryKind::Index),
        TPM_HT_HMAC_SESSION => loaded_sessions(live, property, requested_count),
        TPM_HT_POLICY_SESSION => saved_sessions(live, property, requested_count),
        TPM_HT_PERMANENT => permanent(property, requested_count),
        TPM_HT_TRANSIENT => transient(live, property, requested_count),
        TPM_HT_PERSISTENT => {
            user_nvram(state, property, requested_count, NvramEntryKind::Persistent)
        }
        _ => return None,
    };
    Some(page)
}

fn permanent(property: u32, requested_count: u32) -> CapabilityPage<u32> {
    paginate(
        IMPLEMENTED_PERMANENT_HANDLES
            .into_iter()
            .filter(|handle| *handle >= property),
        requested_count,
        MAX_CAP_HANDLES,
    )
}

fn pcr(live: &LiveState, property: u32, requested_count: u32) -> CapabilityPage<u32> {
    let first = property & HR_HANDLE_MASK;
    let implemented = live.pcrs.len() as u32;
    paginate(
        (first..implemented).map(|index| PCR_FIRST + index),
        requested_count,
        MAX_CAP_HANDLES,
    )
}

fn transient(live: &LiveState, property: u32, requested_count: u32) -> CapabilityPage<u32> {
    let first = (property & HR_HANDLE_MASK) as usize;
    paginate(
        live.objects
            .iter()
            .enumerate()
            .skip(first)
            .filter(|(_, object)| object.attributes & ATTR_OCCUPIED != 0)
            .map(|(slot, _)| TRANSIENT_FIRST + slot as u32),
        requested_count,
        MAX_CAP_HANDLES,
    )
}

fn context_slots_from(live: &LiveState, first: usize) -> impl Iterator<Item = (usize, u16)> + '_ {
    live.state_reset
        .as_ref()
        .map_or(&[][..], |reset| &reset.context_array[..])
        .iter()
        .copied()
        .enumerate()
        .skip(first)
}

fn loaded_sessions(live: &LiveState, property: u32, requested_count: u32) -> CapabilityPage<u32> {
    let first = (property & HR_HANDLE_MASK) as usize;
    paginate(
        context_slots_from(live, first)
            .filter(|(_, context)| *context != 0 && usize::from(*context) <= MAX_LOADED_SESSIONS)
            .map(|(slot, context)| {
                let base = if is_policy_session(live, context) {
                    POLICY_SESSION_FIRST
                } else {
                    HMAC_SESSION_FIRST
                };
                base + slot as u32
            }),
        requested_count,
        MAX_CAP_HANDLES,
    )
}

fn saved_sessions(live: &LiveState, property: u32, requested_count: u32) -> CapabilityPage<u32> {
    let first = (property & HR_HANDLE_MASK) as usize;
    paginate(
        context_slots_from(live, first)
            .filter(|(_, context)| usize::from(*context) > MAX_LOADED_SESSIONS)
            .map(|(slot, _)| HMAC_SESSION_FIRST + slot as u32),
        requested_count,
        MAX_CAP_HANDLES,
    )
}

fn is_policy_session(live: &LiveState, context: u16) -> bool {
    usize::from(context)
        .checked_sub(1)
        .and_then(|ram_slot| live.sessions.get(ram_slot))
        .and_then(|slot| slot.session.as_ref())
        .is_some_and(|session| session.attributes & SESSION_ATTR_IS_POLICY != 0)
}

fn user_nvram(
    state: &OwnedPersistentState,
    property: u32,
    requested_count: u32,
    kind: NvramEntryKind,
) -> CapabilityPage<u32> {
    let mut eligible: Vec<u32> = state
        .user_nvram
        .entries
        .iter()
        .filter_map(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { handle, .. } if kind == NvramEntryKind::Index => {
                Some(*handle)
            }
            OwnedUserNvramEntry::Persistent { handle, .. }
                if kind == NvramEntryKind::Persistent =>
            {
                Some(*handle)
            }
            _ => None,
        })
        .filter(|handle| *handle >= property)
        .collect();
    eligible.sort_unstable();
    paginate(eligible.into_iter(), requested_count, MAX_CAP_HANDLES)
}

#[cfg(test)]
pub(in crate::library::tpm2) mod test_state {
    use super::{ATTR_OCCUPIED, MAX_LOADED_SESSIONS, SESSION_ATTR_IS_POLICY};
    use crate::library::tpm2::persistent::{
        OwnedAnyObject, OwnedAnyObjectBody, OwnedNvIndex, OwnedSecret, OwnedUserNvramEntry,
    };
    use crate::library::tpm2::public::SymDefObject;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::volatile::OwnedSession;

    pub(in crate::library::tpm2) fn nv_index_entry(handle: u32) -> OwnedUserNvramEntry {
        OwnedUserNvramEntry::NvIndex {
            declared_entry_size: 0,
            handle,
            index: OwnedNvIndex {
                nv_index: handle,
                name_alg: 0x000b,
                attributes: 0,
                auth_policy: Vec::new(),
                data_size: 8,
                auth_value: OwnedSecret::from_vec(Vec::new()),
            },
            data: vec![0; 8],
        }
    }

    pub(in crate::library::tpm2) fn persistent_entry(handle: u32) -> OwnedUserNvramEntry {
        OwnedUserNvramEntry::Persistent {
            declared_entry_size: 0,
            handle,
            object: OwnedAnyObject {
                attributes: ATTR_OCCUPIED,
                body: OwnedAnyObjectBody::Unoccupied,
            },
            object_destination_size: 2608,
        }
    }

    pub(in crate::library::tpm2) fn push_nvram(
        runtime: &mut Tpm2Runtime,
        entries: impl IntoIterator<Item = OwnedUserNvramEntry>,
    ) {
        let user_nvram = &mut runtime.state.as_mut().expect("state present").user_nvram;
        user_nvram.entries.extend(entries);
    }

    pub(in crate::library::tpm2) fn occupy_object(runtime: &mut Tpm2Runtime, slot: usize) {
        runtime.live.objects[slot].attributes |= ATTR_OCCUPIED;
    }

    fn session(is_policy: bool) -> OwnedSession {
        OwnedSession {
            attributes: if is_policy { SESSION_ATTR_IS_POLICY } else { 0 },
            pcr_counter: 0,
            start_time: 0,
            timeout: 0,
            epoch: 0,
            command_code: 0,
            auth_hash_alg: 0x000b,
            command_locality: 0,
            symmetric: SymDefObject {
                algorithm: 0x0010,
                key_bits: None,
                mode: None,
            },
            session_key: OwnedSecret::from_vec(Vec::new()),
            nonce_tpm: OwnedSecret::from_vec(Vec::new()),
            bound_entity: Vec::new(),
            audit_digest: Vec::new(),
        }
    }

    pub(in crate::library::tpm2) fn load_session(
        runtime: &mut Tpm2Runtime,
        context_slot: usize,
        ram_slot: usize,
        policy: bool,
    ) {
        let reset = runtime
            .live
            .state_reset
            .as_mut()
            .expect("state reset present");
        reset.context_array[context_slot] = ram_slot as u16 + 1;
        runtime.live.sessions[ram_slot].occupied = true;
        runtime.live.sessions[ram_slot].session = Some(session(policy));
    }

    pub(in crate::library::tpm2) fn save_session(
        runtime: &mut Tpm2Runtime,
        context_slot: usize,
        context_id: u16,
    ) {
        assert!(usize::from(context_id) > MAX_LOADED_SESSIONS);
        let reset = runtime
            .live
            .state_reset
            .as_mut()
            .expect("state reset present");
        reset.context_array[context_slot] = context_id;
    }
}

#[cfg(test)]
mod tests {
    use super::test_state::*;
    use super::*;
    use crate::ffi_types::TpmResult;
    use crate::library::CommandInput;
    use crate::library::tpm2::command::{dispatch, parse_command};
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{Tpm2Runtime, commit_manufactured_state};

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x27;
        }
        Ok(())
    }

    fn started_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let bytes = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0, 0,
        ];
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let parsed = parse_command(&input).expect("the header parses");
        assert_eq!(
            dispatch(&mut runtime, &parsed).code(),
            0,
            "Startup succeeds"
        );
        runtime.nv_update_pending = false;
        runtime
    }

    #[track_caller]
    fn page(runtime: &Tpm2Runtime, property: u32, count: u32) -> CapabilityPage<u32> {
        let state = runtime.state.as_ref().expect("state present");
        collect(&runtime.live, state, property, count).expect("the handle type is supported")
    }

    #[track_caller]
    fn entries(runtime: &Tpm2Runtime, property: u32, count: u32) -> Vec<u32> {
        page(runtime, property, count).entries
    }

    #[test]
    fn the_handle_range_constants_match_upstream() {
        assert_eq!(PCR_FIRST, 0x0000_0000);
        assert_eq!(HMAC_SESSION_FIRST, 0x0200_0000);
        assert_eq!(POLICY_SESSION_FIRST, 0x0300_0000);
        assert_eq!(TRANSIENT_FIRST, 0x8000_0000);
        assert_eq!(handle_range(TPM_HT_NV_INDEX), 0x0100_0000);
        assert_eq!(handle_range(TPM_HT_PERMANENT), 0x4000_0000);
        assert_eq!(handle_range(TPM_HT_PERSISTENT), 0x8100_0000);
        assert_eq!(MAX_CAP_HANDLES, 254);
    }

    #[test]
    fn unimplemented_handle_types_have_no_collector() {
        let runtime = started_runtime();
        let state = runtime.state.as_ref().expect("state present");
        for handle_type in [
            0x04u32, 0x05, 0x0f, 0x10, 0x11, 0x12, 0x3f, 0x41, 0x7f, 0x82, 0x90, 0xff,
        ] {
            assert!(
                collect(&runtime.live, state, handle_range(handle_type), 10).is_none(),
                "handle type {handle_type:#04x}"
            );
        }
    }

    #[test]
    fn every_implemented_handle_type_has_a_collector() {
        let runtime = started_runtime();
        let state = runtime.state.as_ref().expect("state present");
        for handle_type in [
            TPM_HT_PCR,
            TPM_HT_NV_INDEX,
            TPM_HT_HMAC_SESSION,
            TPM_HT_POLICY_SESSION,
            TPM_HT_PERMANENT,
            TPM_HT_TRANSIENT,
            TPM_HT_PERSISTENT,
        ] {
            assert!(
                collect(&runtime.live, state, handle_range(handle_type), 10).is_some(),
                "handle type {handle_type:#04x}"
            );
        }
    }

    #[test]
    fn a_freshly_started_tpm_reports_only_static_handles() {
        let runtime = started_runtime();
        assert!(
            entries(&runtime, 0x0100_0000, 1000).is_empty(),
            "NV indexes"
        );
        assert!(
            entries(&runtime, 0x8100_0000, 1000).is_empty(),
            "persistent objects"
        );
        assert!(
            entries(&runtime, 0x8000_0000, 1000).is_empty(),
            "transient objects"
        );
        assert!(
            entries(&runtime, 0x0200_0000, 1000).is_empty(),
            "loaded sessions"
        );
        assert!(
            entries(&runtime, 0x0300_0000, 1000).is_empty(),
            "saved sessions"
        );
        assert_eq!(entries(&runtime, 0x4000_0000, 1000).len(), 7);
        assert_eq!(entries(&runtime, 0x0000_0000, 1000).len(), 24);
    }

    #[test]
    fn permanent_handles_are_filtered_by_the_start_handle() {
        let runtime = started_runtime();
        assert_eq!(
            entries(&runtime, 0x4000_0000, 1000),
            [
                0x4000_0001,
                0x4000_0007,
                0x4000_0009,
                0x4000_000a,
                0x4000_000b,
                0x4000_000c,
                0x4000_000d
            ]
        );
        assert_eq!(
            entries(&runtime, 0x4000_0002, 3),
            [0x4000_0007, 0x4000_0009, 0x4000_000a],
            "a start inside the 0x40000002..0x40000006 gap"
        );
        assert_eq!(entries(&runtime, 0x4000_000d, 5), [0x4000_000d], "the last");
        assert!(
            entries(&runtime, 0x4000_000e, 5).is_empty(),
            "past the last"
        );
        assert!(
            entries(&runtime, 0x40ff_ffff, 5).is_empty(),
            "past the range"
        );
    }

    #[test]
    fn pcr_handles_span_the_implemented_pcrs() {
        let runtime = started_runtime();
        assert_eq!(entries(&runtime, 0, 1000), (0..24).collect::<Vec<u32>>());
        assert_eq!(entries(&runtime, 0x0000_000a, 3), [10, 11, 12]);
        assert_eq!(entries(&runtime, 0x0000_0017, 5), [23], "the last PCR");
        assert!(
            entries(&runtime, 0x0000_0018, 5).is_empty(),
            "past the last"
        );
        assert!(
            entries(&runtime, 0x00ff_ffff, 5).is_empty(),
            "past the range"
        );
    }

    #[test]
    fn nv_index_handles_are_sorted_filtered_and_paged() {
        let mut runtime = started_runtime();
        push_nvram(
            &mut runtime,
            [
                nv_index_entry(0x0100_0005),
                nv_index_entry(0x0100_0001),
                nv_index_entry(0x0100_0003),
                nv_index_entry(0x0100_000a),
            ],
        );
        assert_eq!(
            entries(&runtime, 0x0100_0000, 10),
            [0x0100_0001, 0x0100_0003, 0x0100_0005, 0x0100_000a],
            "storage order is 5, 1, 3, a"
        );
        assert_eq!(
            entries(&runtime, 0x0100_0002, 10),
            [0x0100_0003, 0x0100_0005, 0x0100_000a]
        );
        assert_eq!(entries(&runtime, 0x0100_0005, 1), [0x0100_0005]);
        assert!(entries(&runtime, 0x0100_000b, 10).is_empty());

        let paged = page(&runtime, 0x0100_0000, 2);
        assert_eq!(paged.entries, [0x0100_0001, 0x0100_0003]);
        assert!(paged.more_data);
        assert!(!page(&runtime, 0x0100_0000, 4).more_data);
    }

    #[test]
    fn persistent_handles_come_from_the_user_nvram() {
        let mut runtime = started_runtime();
        push_nvram(
            &mut runtime,
            [persistent_entry(0x8100_0005), persistent_entry(0x8100_0001)],
        );
        assert_eq!(
            entries(&runtime, 0x8100_0000, 10),
            [0x8100_0001, 0x8100_0005]
        );
        assert_eq!(entries(&runtime, 0x8100_0002, 10), [0x8100_0005]);
        assert!(entries(&runtime, 0x8100_0006, 10).is_empty());
        assert!(
            entries(&runtime, 0x0100_0000, 10).is_empty(),
            "persistent objects never appear in the NV index range"
        );
    }

    #[test]
    fn nv_indexes_and_persistent_objects_do_not_leak_into_each_other() {
        let mut runtime = started_runtime();
        push_nvram(
            &mut runtime,
            [nv_index_entry(0x0100_0001), persistent_entry(0x8100_0001)],
        );
        assert_eq!(entries(&runtime, 0x0100_0000, 10), [0x0100_0001]);
        assert_eq!(entries(&runtime, 0x8100_0000, 10), [0x8100_0001]);
    }

    #[test]
    fn transient_handles_track_occupied_object_slots() {
        let mut runtime = started_runtime();
        occupy_object(&mut runtime, 0);
        occupy_object(&mut runtime, 2);
        assert_eq!(
            entries(&runtime, 0x8000_0000, 10),
            [0x8000_0000, 0x8000_0002]
        );
        assert_eq!(entries(&runtime, 0x8000_0001, 10), [0x8000_0002]);
        assert!(entries(&runtime, 0x8000_0003, 10).is_empty());
        let paged = page(&runtime, 0x8000_0000, 1);
        assert_eq!(paged.entries, [0x8000_0000]);
        assert!(paged.more_data);
    }

    #[test]
    fn the_start_handle_selects_a_context_slot_across_free_slots() {
        let mut runtime = started_runtime();
        load_session(&mut runtime, 1, 0, false);
        assert_eq!(entries(&runtime, 0x0200_0000, 10), [0x0200_0001]);
        assert_eq!(
            entries(&runtime, 0x0200_0001, 10),
            [0x0200_0001],
            "the free slot 0 must not consume the start handle"
        );
        assert!(entries(&runtime, 0x0200_0002, 10).is_empty());
        let paged = page(&runtime, 0x0200_0001, 0);
        assert!(paged.entries.is_empty());
        assert!(paged.more_data);

        save_session(&mut runtime, 5, MAX_LOADED_SESSIONS as u16 + 1);
        assert_eq!(entries(&runtime, 0x0300_0000, 10), [0x0200_0005]);
        assert_eq!(
            entries(&runtime, 0x0300_0005, 10),
            [0x0200_0005],
            "saved sessions filter on the context slot too"
        );
        assert!(entries(&runtime, 0x0300_0006, 10).is_empty());
    }

    #[test]
    fn loaded_sessions_are_typed_by_the_is_policy_attribute() {
        let mut runtime = started_runtime();
        load_session(&mut runtime, 0, 0, false);
        load_session(&mut runtime, 1, 1, true);
        assert_eq!(
            entries(&runtime, 0x0200_0000, 10),
            [0x0200_0000, 0x0300_0001],
            "the policy session keeps its context slot but changes range"
        );
        assert_eq!(
            entries(&runtime, 0x0200_0001, 10),
            [0x0300_0001],
            "the start handle filters on the context slot, not the range"
        );
        assert!(entries(&runtime, 0x0200_0002, 10).is_empty());
        assert!(
            entries(&runtime, 0x0300_0000, 10).is_empty(),
            "the policy range only reports saved sessions"
        );
    }

    #[test]
    fn saved_sessions_are_reported_in_the_hmac_range() {
        let mut runtime = started_runtime();
        load_session(&mut runtime, 1, 1, true);
        save_session(&mut runtime, 0, MAX_LOADED_SESSIONS as u16 + 1);
        assert_eq!(entries(&runtime, 0x0200_0000, 10), [0x0300_0001], "loaded");
        assert_eq!(entries(&runtime, 0x0300_0000, 10), [0x0200_0000], "saved");
        assert!(entries(&runtime, 0x0300_0001, 10).is_empty());
    }

    #[test]
    fn a_missing_state_reset_reports_no_sessions() {
        let mut runtime = started_runtime();
        runtime.live.state_reset = None;
        assert!(entries(&runtime, 0x0200_0000, 10).is_empty());
        assert!(entries(&runtime, 0x0300_0000, 10).is_empty());
    }

    #[test]
    fn a_count_of_zero_reports_more_data_only_when_a_handle_exists() {
        let runtime = started_runtime();
        for property in [0x0000_0000u32, 0x4000_0000] {
            let paged = page(&runtime, property, 0);
            assert!(paged.entries.is_empty(), "property {property:#010x}");
            assert!(paged.more_data, "property {property:#010x}");
        }
        for property in [
            0x0100_0000u32,
            0x8000_0000,
            0x8100_0000,
            0x0200_0000,
            0x0300_0000,
        ] {
            let paged = page(&runtime, property, 0);
            assert!(paged.entries.is_empty(), "property {property:#010x}");
            assert!(!paged.more_data, "property {property:#010x}");
        }
    }

    #[test]
    fn the_response_size_limit_caps_the_handle_list() {
        let mut runtime = started_runtime();
        push_nvram(
            &mut runtime,
            (0..300u32).map(|index| nv_index_entry(0x0100_1000 + index)),
        );
        for count in [255u32, 300, 1000, u32::MAX] {
            let paged = page(&runtime, 0x0100_0000, count);
            assert_eq!(paged.entries.len(), MAX_CAP_HANDLES, "count {count}");
            assert_eq!(paged.entries[0], 0x0100_1000);
            assert_eq!(paged.entries[MAX_CAP_HANDLES - 1], 0x0100_1000 + 253);
            assert!(paged.more_data, "count {count}");
        }
        let paged = page(&runtime, 0x0100_0000, 254);
        assert_eq!(paged.entries.len(), MAX_CAP_HANDLES);
        assert!(paged.more_data);
    }
}
