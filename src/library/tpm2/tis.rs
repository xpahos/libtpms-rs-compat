use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_BAD_LOCALITY, TPM_SUCCESS};

use super::object::{ATTR_EVENT_SEQ, ATTR_OCCUPIED, ATTR_TEMPORARY, HASH_OBJECT_VERSION};
use super::pcr::{
    BankHasher, DRTM_PCR, HCRTM_PCR, PCR_SLOT_BANKS, allocation_selects, pcr_in_tcb_group,
    pcr_resets_to_ones,
};
use super::persistent::{OwnedAnyObject, OwnedAnyObjectBody, OwnedHashObjectBody, OwnedSecret};
use super::public::TPM_ALG_NULL;
use super::runtime::Tpm2Runtime;
use super::volatile::IMPLEMENTATION_PCR;

const TPMA_OBJECT_NO_DA: u32 = 1 << 10;

const BANK_COUNT: usize = PCR_SLOT_BANKS.len();

pub(super) struct DrtmSequence {
    slot: usize,
    contexts: [BankHasher; BANK_COUNT],
}

fn fresh_contexts() -> [BankHasher; BANK_COUNT] {
    BankHasher::all()
}

fn drtm_sequence_object() -> OwnedAnyObject {
    OwnedAnyObject {
        attributes: ATTR_OCCUPIED | ATTR_EVENT_SEQ | ATTR_TEMPORARY,
        body: OwnedAnyObjectBody::Sequence(Box::new(OwnedHashObjectBody {
            section_version: HASH_OBJECT_VERSION,
            object_type: TPM_ALG_NULL,
            name_alg: TPM_ALG_NULL,
            object_attributes: TPMA_OBJECT_NO_DA,
            auth: OwnedSecret::from_vec(Vec::new()),
            states: None,
            hmac_state: None,
        })),
    }
}

fn release_slot(objects: &mut [OwnedAnyObject], slot: usize) {
    if let Some(object) = objects.get_mut(slot) {
        object.attributes = 0;
        object.body = OwnedAnyObjectBody::Unoccupied;
    }
}

fn allocate_slot(objects: &mut [OwnedAnyObject]) -> usize {
    let slot = objects
        .iter()
        .position(|object| object.attributes & ATTR_OCCUPIED == 0)
        .unwrap_or(0);
    release_slot(objects, slot);
    slot
}

pub(super) fn abort_sequence(runtime: &mut Tpm2Runtime) {
    if let Some(sequence) = runtime.drtm_sequence.take() {
        release_slot(&mut runtime.live.objects, sequence.slot);
    }
}

fn target_pcr(runtime: &Tpm2Runtime) -> usize {
    if runtime.startup_received {
        DRTM_PCR
    } else {
        HCRTM_PCR
    }
}

fn allocated_banks(runtime: &Tpm2Runtime, pcr: usize) -> [bool; BANK_COUNT] {
    let mut mask = [false; BANK_COUNT];
    if let Some(allocation) = runtime.effective_pcr_allocated() {
        for (slot, (hash_alg, _)) in PCR_SLOT_BANKS.iter().enumerate() {
            mask[slot] = allocation_selects(allocation, *hash_alg, pcr);
        }
    }
    mask
}

fn pcr_changed(runtime: &mut Tpm2Runtime, pcr: usize) {
    if (pcr == HCRTM_PCR || !pcr_in_tcb_group(pcr))
        && let Some(state_reset) = runtime.live.state_reset.as_mut()
    {
        state_reset.pcr_counter = state_reset.pcr_counter.wrapping_add(1);
    }
}

fn pcr_drtm(
    runtime: &mut Tpm2Runtime,
    pcr: usize,
    slot: usize,
    mut extender: BankHasher,
    digest: &[u8],
    started: bool,
) {
    let (_, digest_size) = PCR_SLOT_BANKS[slot];
    let mut value = vec![0u8; digest_size];
    if !started {
        value[digest_size - 1] = 4;
    }
    extender.update(&value);
    extender.update(digest);
    runtime.live.pcrs[pcr].banks[slot] = Some(extender.finalize());
    pcr_changed(runtime, pcr);
}

fn reset_dynamic_pcrs(runtime: &mut Tpm2Runtime) {
    for pcr in 0..IMPLEMENTATION_PCR {
        if !pcr_resets_to_ones(pcr) {
            continue;
        }
        let mask = allocated_banks(runtime, pcr);
        for (slot, allocated) in mask.into_iter().enumerate() {
            if allocated {
                let (_, digest_size) = PCR_SLOT_BANKS[slot];
                runtime.live.pcrs[pcr].banks[slot] = Some(vec![0u8; digest_size]);
            }
        }
    }
}

pub(in crate::library) fn hash_start(runtime: &mut Tpm2Runtime) -> TpmResult {
    abort_sequence(runtime);
    let slot = allocate_slot(&mut runtime.live.objects);
    runtime.live.objects[slot] = drtm_sequence_object();
    runtime.drtm_sequence = Some(DrtmSequence {
        slot,
        contexts: fresh_contexts(),
    });
    runtime.tpm_established = true;
    TPM_SUCCESS
}

pub(in crate::library) fn hash_data(runtime: &mut Tpm2Runtime, data: &[u8]) -> TpmResult {
    let mask = allocated_banks(runtime, target_pcr(runtime));
    if let Some(sequence) = runtime.drtm_sequence.as_mut() {
        for (slot, context) in sequence.contexts.iter_mut().enumerate() {
            if mask[slot] {
                context.update(data);
            }
        }
    }
    TPM_SUCCESS
}

pub(in crate::library) fn hash_end(runtime: &mut Tpm2Runtime) -> TpmResult {
    let Some(sequence) = runtime.drtm_sequence.take() else {
        return TPM_SUCCESS;
    };
    release_slot(&mut runtime.live.objects, sequence.slot);
    let started = runtime.startup_received;
    let pcr = if started {
        reset_dynamic_pcrs(runtime);
        if let Some(state_reset) = runtime.live.state_reset.as_mut() {
            state_reset.restart_count = state_reset.restart_count.wrapping_add(1);
        }
        DRTM_PCR
    } else {
        runtime.live.drtm_pre_startup = true;
        HCRTM_PCR
    };
    let mask = allocated_banks(runtime, pcr);
    for ((slot, context), extender) in sequence
        .contexts
        .into_iter()
        .enumerate()
        .zip(BankHasher::all())
    {
        if mask[slot] {
            let digest = context.finalize();
            pcr_drtm(runtime, pcr, slot, extender, &digest, started);
        }
    }
    TPM_SUCCESS
}

pub(in crate::library) fn established_reset(
    runtime: &mut Tpm2Runtime,
    host_locality: u32,
) -> TpmResult {
    let platform_locality = host_locality as u8;
    runtime.locality = if (5..32).contains(&platform_locality) {
        0
    } else {
        platform_locality
    };
    if host_locality == 3 || host_locality == 4 {
        runtime.tpm_established = false;
        TPM_SUCCESS
    } else {
        TPM_BAD_LOCALITY
    }
}

#[cfg(test)]
mod tests {
    fn process(
        runtime: &mut crate::library::tpm2::runtime::Tpm2Runtime,
        locality: u8,
        command: &crate::library::CommandInput,
        commit_nv: impl FnOnce(
            &crate::library::tpm2::runtime::Tpm2Runtime,
        ) -> Result<(), crate::ffi_types::TpmResult>,
    ) -> Result<Vec<u8>, crate::ffi_types::TpmResult> {
        crate::library::tpm2::process(
            runtime,
            locality,
            command,
            &crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000),
            commit_nv,
        )
    }
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;

    const SHA1_SLOT: usize = 0;
    const SHA256_SLOT: usize = 1;
    const SHA384_SLOT: usize = 2;
    const SHA512_SLOT: usize = 3;

    const HCRTM_ABC_SHA1: &str = "901e9ce9d04e2102fa74fbbb9bb0abd25e3fdbe8";
    const HCRTM_ABC_SHA256: &str =
        "15703cc929081671c587dad9b09606521a35aa6bf4741df448d22c4b307acc71";
    const HCRTM_ABC_SHA384: &str = "7ba168b158d2f118b5d922a0d941b823a43c0be59e71ca6789eab371b63e\
                                    1680ea412895f93a863de5d51d421d529ba4";
    const HCRTM_ABC_SHA512: &str = "ac7af0a8385bd5e5b4dab8a7a0ee58d325f40c5256db0759b1099aedb455\
                                    0cc7f19ec50117dba6f24f3ae3e6c4c5f103f3eea39c8480ca7f202146fb\
                                    53598089";
    const HCRTM_EMPTY_SHA256: &str =
        "6d5d02e322f054209780964921fb62321645d4577482feb6d9f7391ea46882cb";
    const DRTM_ABC_SHA1: &str = "ccd5bd41458de644ac34a2478b58ff819bef5acf";
    const DRTM_ABC_SHA256: &str =
        "589f9ffed4c477966bfb8d41f37895b08c69047df8f911d6f3b57fbe08faee8d";
    const DRTM_ABC_SHA384: &str = "93732e3733514a841c982cfa75ea76ab55fe011acb9cd980ef4523913c65\
                                   be1b0998e04d77f8c174f81a82151619ca40";
    const DRTM_ABC_SHA512: &str = "6b9e946755055542adba95a1588a7eaed86323b3bed97d602ee06839d734\
                                   048e02c63f37892d3adde0d25b5a9d89162e8804ab9ec0ac4a263545c4fa\
                                   ecfdf53b";

    const STARTUP_PCR_COUNTER: u32 = 20;

    fn hex(value: &str) -> Vec<u8> {
        let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x71;
        }
        Ok(())
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    fn run_command(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        process(runtime, 0, &input, |_| Ok(())).expect("the command processes")
    }

    fn startup_clear(runtime: &mut Tpm2Runtime) {
        let response = run_command(
            runtime,
            &[
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
            ],
        );
        assert_eq!(
            response,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );
    }

    fn started_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime();
        startup_clear(&mut runtime);
        runtime
    }

    fn occupied_slots(runtime: &Tpm2Runtime) -> usize {
        runtime
            .live
            .objects
            .iter()
            .filter(|object| object.attributes & ATTR_OCCUPIED != 0)
            .count()
    }

    fn pcr_bank(runtime: &Tpm2Runtime, pcr: usize, slot: usize) -> Option<&Vec<u8>> {
        runtime.live.pcrs[pcr].banks[slot].as_ref()
    }

    fn state_reset(runtime: &Tpm2Runtime) -> &super::super::persistent::OwnedStateResetData {
        runtime.live.state_reset.as_ref().expect("started runtime")
    }

    #[test]
    fn hash_start_sets_established_and_reserves_a_transient_slot() {
        let mut runtime = manufactured_runtime();
        assert!(!runtime.tpm_established);
        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert!(runtime.tpm_established);
        assert_eq!(occupied_slots(&runtime), 1);
        assert_eq!(
            runtime.live.objects[0].attributes,
            ATTR_OCCUPIED | ATTR_EVENT_SEQ | ATTR_TEMPORARY
        );
        assert!(matches!(
            runtime.live.objects[0].body,
            OwnedAnyObjectBody::Sequence(_)
        ));
    }

    #[test]
    fn hash_start_with_full_slots_flushes_the_first_transient_object() {
        let mut runtime = manufactured_runtime();
        for object in &mut runtime.live.objects {
            object.attributes = ATTR_OCCUPIED;
        }
        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert_eq!(occupied_slots(&runtime), runtime.live.objects.len());
        assert_eq!(
            runtime.live.objects[0].attributes,
            ATTR_OCCUPIED | ATTR_EVENT_SEQ | ATTR_TEMPORARY
        );
        assert_eq!(runtime.live.objects[1].attributes, ATTR_OCCUPIED);
    }

    #[test]
    fn hash_data_before_start_is_a_successful_noop() {
        let mut runtime = manufactured_runtime();
        assert_eq!(hash_data(&mut runtime, b"xy"), TPM_SUCCESS);
        assert!(!runtime.tpm_established);
        assert!(
            runtime
                .live
                .pcrs
                .iter()
                .all(|pcr| pcr.banks.iter().all(|bank| bank.is_none()))
        );
    }

    #[test]
    fn hash_end_before_start_is_a_successful_noop() {
        let mut runtime = manufactured_runtime();
        assert_eq!(hash_end(&mut runtime), TPM_SUCCESS);
        assert!(!runtime.live.drtm_pre_startup);
        assert!(!runtime.tpm_established);
    }

    #[test]
    fn pre_startup_hash_end_completes_the_hcrtm_and_startup_preserves_pcr0() {
        let mut runtime = manufactured_runtime();
        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert_eq!(hash_data(&mut runtime, b"a"), TPM_SUCCESS);
        assert_eq!(hash_data(&mut runtime, b"bc"), TPM_SUCCESS);
        assert_eq!(hash_data(&mut runtime, &[]), TPM_SUCCESS);
        assert_eq!(hash_end(&mut runtime), TPM_SUCCESS);

        assert!(runtime.live.drtm_pre_startup);
        assert_eq!(occupied_slots(&runtime), 0, "the sequence is released");
        assert!(runtime.drtm_sequence.is_none());
        for (slot, oracle) in [
            (SHA1_SLOT, HCRTM_ABC_SHA1),
            (SHA256_SLOT, HCRTM_ABC_SHA256),
            (SHA384_SLOT, HCRTM_ABC_SHA384),
            (SHA512_SLOT, HCRTM_ABC_SHA512),
        ] {
            assert_eq!(pcr_bank(&runtime, HCRTM_PCR, slot), Some(&hex(oracle)));
        }

        startup_clear(&mut runtime);
        for (slot, oracle) in [
            (SHA1_SLOT, HCRTM_ABC_SHA1),
            (SHA256_SLOT, HCRTM_ABC_SHA256),
            (SHA384_SLOT, HCRTM_ABC_SHA384),
            (SHA512_SLOT, HCRTM_ABC_SHA512),
        ] {
            assert_eq!(
                pcr_bank(&runtime, HCRTM_PCR, slot),
                Some(&hex(oracle)),
                "TPM2_Startup preserves the H-CRTM PCR"
            );
        }
        assert_eq!(state_reset(&runtime).pcr_counter, STARTUP_PCR_COUNTER);
        assert!(runtime.tpm_established, "startup leaves the flag alone");
    }

    #[test]
    fn empty_hcrtm_sequence_extends_the_empty_digest() {
        let mut runtime = manufactured_runtime();
        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert_eq!(hash_end(&mut runtime), TPM_SUCCESS);
        assert_eq!(
            pcr_bank(&runtime, HCRTM_PCR, SHA256_SLOT),
            Some(&hex(HCRTM_EMPTY_SHA256))
        );
    }

    #[test]
    fn repeated_hash_start_replaces_the_previous_sequence() {
        let mut runtime = manufactured_runtime();
        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert_eq!(hash_data(&mut runtime, b"zz"), TPM_SUCCESS);
        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert_eq!(occupied_slots(&runtime), 1, "one sequence at a time");
        assert_eq!(hash_data(&mut runtime, b"abc"), TPM_SUCCESS);
        assert_eq!(hash_end(&mut runtime), TPM_SUCCESS);
        assert_eq!(
            pcr_bank(&runtime, HCRTM_PCR, SHA256_SLOT),
            Some(&hex(HCRTM_ABC_SHA256))
        );
    }

    #[test]
    fn hashing_is_incremental_across_data_calls() {
        let mut one_shot = manufactured_runtime();
        assert_eq!(hash_start(&mut one_shot), TPM_SUCCESS);
        assert_eq!(hash_data(&mut one_shot, b"abc"), TPM_SUCCESS);
        assert_eq!(hash_end(&mut one_shot), TPM_SUCCESS);

        let mut split = manufactured_runtime();
        assert_eq!(hash_start(&mut split), TPM_SUCCESS);
        for chunk in [b"a".as_slice(), b"b", b"", b"c"] {
            assert_eq!(hash_data(&mut split, chunk), TPM_SUCCESS);
        }
        assert_eq!(hash_end(&mut split), TPM_SUCCESS);

        for slot in 0..PCR_SLOT_BANKS.len() {
            assert_eq!(
                pcr_bank(&one_shot, HCRTM_PCR, slot),
                pcr_bank(&split, HCRTM_PCR, slot)
            );
        }
    }

    #[test]
    fn post_startup_hash_end_resets_dynamics_extends_drtm_and_counts() {
        let mut runtime = started_runtime();
        let pcr16_marker = vec![0xaa; 32];
        runtime.live.pcrs[16].banks[SHA256_SLOT] = Some(pcr16_marker.clone());
        let pcr18_marker = vec![0xbb; 32];
        runtime.live.pcrs[18].banks[SHA256_SLOT] = Some(pcr18_marker);
        assert_eq!(state_reset(&runtime).restart_count, 0);

        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert!(runtime.tpm_established);
        assert_eq!(occupied_slots(&runtime), 1);
        assert_eq!(hash_data(&mut runtime, b"abc"), TPM_SUCCESS);
        assert_eq!(hash_end(&mut runtime), TPM_SUCCESS);

        for (slot, oracle) in [
            (SHA1_SLOT, DRTM_ABC_SHA1),
            (SHA256_SLOT, DRTM_ABC_SHA256),
            (SHA384_SLOT, DRTM_ABC_SHA384),
            (SHA512_SLOT, DRTM_ABC_SHA512),
        ] {
            assert_eq!(pcr_bank(&runtime, DRTM_PCR, slot), Some(&hex(oracle)));
        }
        assert_eq!(
            pcr_bank(&runtime, 16, SHA256_SLOT),
            Some(&pcr16_marker),
            "PCR 16 is not locality-4 resettable"
        );
        assert_eq!(
            pcr_bank(&runtime, 18, SHA256_SLOT),
            Some(&vec![0u8; 32]),
            "dynamic PCR 18 is reset to zeros"
        );
        for pcr in [19, 20, 21, 22] {
            assert_eq!(pcr_bank(&runtime, pcr, SHA256_SLOT), Some(&vec![0u8; 32]));
        }
        assert_eq!(state_reset(&runtime).restart_count, 1);
        assert_eq!(
            state_reset(&runtime).pcr_counter,
            STARTUP_PCR_COUNTER + PCR_SLOT_BANKS.len() as u32
        );
        assert_eq!(occupied_slots(&runtime), 0, "the sequence is released");
        assert!(runtime.drtm_sequence.is_none());
    }

    #[test]
    fn any_command_aborts_the_inflight_sequence() {
        let mut runtime = started_runtime();
        let pcr17_before = pcr_bank(&runtime, DRTM_PCR, SHA256_SLOT).cloned();
        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert_eq!(hash_data(&mut runtime, b"abc"), TPM_SUCCESS);
        run_command(
            &mut runtime,
            &[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x00],
        );
        assert!(runtime.drtm_sequence.is_none());
        assert_eq!(occupied_slots(&runtime), 0);
        assert_eq!(hash_end(&mut runtime), TPM_SUCCESS, "aborted: a no-op");
        assert_eq!(
            pcr_bank(&runtime, DRTM_PCR, SHA256_SLOT).cloned(),
            pcr17_before
        );
        assert_eq!(state_reset(&runtime).restart_count, 0);
        assert!(runtime.tpm_established, "the abort keeps the flag");
    }

    #[test]
    fn established_reset_localities_follow_the_oracle() {
        let mut runtime = started_runtime();
        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        for locality in [0u32, 1, 2, 5, 31, 255] {
            assert_eq!(
                established_reset(&mut runtime, locality),
                TPM_BAD_LOCALITY,
                "locality {locality}"
            );
            assert!(runtime.tpm_established, "locality {locality} left the flag");
        }
        assert_eq!(established_reset(&mut runtime, 3), TPM_SUCCESS);
        assert!(!runtime.tpm_established);
        assert_eq!(runtime.locality, 3);

        assert_eq!(hash_start(&mut runtime), TPM_SUCCESS);
        assert!(runtime.tpm_established);
        assert_eq!(established_reset(&mut runtime, 4), TPM_SUCCESS);
        assert!(!runtime.tpm_established);
        assert_eq!(runtime.locality, 4);

        assert_eq!(established_reset(&mut runtime, 5), TPM_BAD_LOCALITY);
        assert_eq!(runtime.locality, 0, "extended localities normalize to 0");
    }
}
