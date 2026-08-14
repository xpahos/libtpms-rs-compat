use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_FAIL;

use super::data::PersistentDataPrefix;
use super::orderly::{DrbgState, OrderlyData};
use crate::library::tpm2::DecodedPersistentAll;
use crate::library::tpm2::nv::{
    IndexOrderlyRam, NV_RAM_HEADER_SIZE, NvIndex, OrderlyRamEntry, RAM_INDEX_SPACE,
    USER_NVRAM_CAPACITY, UserNvram, UserNvramEntry,
};
use crate::library::tpm2::object::{
    AnyObject, AnyObjectBody, BnPrime, HASH_STATE_COUNT, HashObjectBody, HashPayload, HashState,
    ObjectBody, PrivateExponent,
};
use crate::library::tpm2::pcr::{
    NUM_POLICY_PCR_GROUP, PcrAllocation, PcrPolicyEntry, PcrSelection,
};
use crate::library::tpm2::profile::ValidatedProfile;
use crate::library::tpm2::public::{PublicId, PublicParms, TpmtPublic, TpmtSensitive};
use crate::library::tpm2::state::{
    COMMIT_ARRAY_SIZE, MAX_ACTIVE_SESSIONS, NUM_AUTHVALUE_PCR_GROUP, PCR_BANKS, PcrBank,
    StateClearData, StateResetData,
};

#[allow(dead_code)]
#[derive(Clone)]
pub(in crate::library::tpm2) struct OwnedSecret(Vec<u8>);

impl OwnedSecret {
    pub(in crate::library::tpm2) fn copy_of(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub(in crate::library::tpm2) fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(in crate::library::tpm2) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for OwnedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OwnedSecret {{ len: {} }}", self.0.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OwnedPcrSelection {
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) select: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OwnedPcrAllocation {
    pub(in crate::library::tpm2) selections: Vec<OwnedPcrSelection>,
}

fn own_pcr_allocation(allocation: &PcrAllocation<'_>) -> OwnedPcrAllocation {
    OwnedPcrAllocation {
        selections: allocation.selections[..allocation.declared_count as usize]
            .iter()
            .map(|selection: &PcrSelection<'_>| OwnedPcrSelection {
                hash_alg: selection.hash_alg,
                select: selection.select.to_vec(),
            })
            .collect(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OwnedPcrPolicyEntry {
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) policy: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OwnedCommandBitmap {
    pub(in crate::library::tpm2) compressed: bool,
    pub(in crate::library::tpm2) bytes: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedPersistentData {
    pub(in crate::library::tpm2) section_version: u16,

    pub(in crate::library::tpm2) disable_clear: bool,

    pub(in crate::library::tpm2) owner_alg: u16,
    pub(in crate::library::tpm2) endorsement_alg: u16,
    pub(in crate::library::tpm2) lockout_alg: u16,

    pub(in crate::library::tpm2) owner_policy: Vec<u8>,
    pub(in crate::library::tpm2) endorsement_policy: Vec<u8>,
    pub(in crate::library::tpm2) lockout_policy: Vec<u8>,

    pub(in crate::library::tpm2) owner_auth: OwnedSecret,
    pub(in crate::library::tpm2) endorsement_auth: OwnedSecret,
    pub(in crate::library::tpm2) lockout_auth: OwnedSecret,

    pub(in crate::library::tpm2) ep_seed: OwnedSecret,
    pub(in crate::library::tpm2) sp_seed: OwnedSecret,
    pub(in crate::library::tpm2) pp_seed: OwnedSecret,

    pub(in crate::library::tpm2) ph_proof: OwnedSecret,
    pub(in crate::library::tpm2) sh_proof: OwnedSecret,
    pub(in crate::library::tpm2) eh_proof: OwnedSecret,

    pub(in crate::library::tpm2) total_reset_count: u64,
    pub(in crate::library::tpm2) reset_count: u32,

    pub(in crate::library::tpm2) pcr_policies: [OwnedPcrPolicyEntry; NUM_POLICY_PCR_GROUP],
    pub(in crate::library::tpm2) pcr_allocated: OwnedPcrAllocation,
    pub(in crate::library::tpm2) pp_list: OwnedCommandBitmap,

    pub(in crate::library::tpm2) failed_tries: u32,
    pub(in crate::library::tpm2) max_tries: u32,
    pub(in crate::library::tpm2) recovery_time: u32,
    pub(in crate::library::tpm2) lockout_recovery: u32,
    pub(in crate::library::tpm2) lockout_auth_enabled: bool,
    pub(in crate::library::tpm2) orderly_state: u16,

    pub(in crate::library::tpm2) audit_commands: OwnedCommandBitmap,
    pub(in crate::library::tpm2) audit_hash_alg: u16,
    pub(in crate::library::tpm2) audit_counter: u64,
    pub(in crate::library::tpm2) algorithm_set: u32,
    pub(in crate::library::tpm2) firmware_v1: u32,
    pub(in crate::library::tpm2) firmware_v2: u32,
    pub(in crate::library::tpm2) time_epoch: u32,

    pub(in crate::library::tpm2) shadow_pcr_allocated: Option<OwnedPcrAllocation>,
    pub(in crate::library::tpm2) ep_seed_compat_level: u8,
    pub(in crate::library::tpm2) sp_seed_compat_level: u8,
    pub(in crate::library::tpm2) pp_seed_compat_level: u8,
}

fn own_persistent_data(
    data: &crate::library::tpm2::DecodedPersistentData<'_>,
) -> OwnedPersistentData {
    let prefix: &PersistentDataPrefix<'_> = &data.prefix;
    let mut pcr_policies = core::array::from_fn(|_| OwnedPcrPolicyEntry {
        hash_alg: 0,
        policy: Vec::new(),
    });
    for (owned, decoded) in pcr_policies.iter_mut().zip(&data.pcr_policies.entries) {
        let decoded: &PcrPolicyEntry<'_> = decoded;
        *owned = OwnedPcrPolicyEntry {
            hash_alg: decoded.hash_alg,
            policy: decoded.policy.to_vec(),
        };
    }

    OwnedPersistentData {
        section_version: prefix.header.version,
        disable_clear: prefix.disable_clear,
        owner_alg: prefix.owner_alg,
        endorsement_alg: prefix.endorsement_alg,
        lockout_alg: prefix.lockout_alg,
        owner_policy: prefix.owner_policy.to_vec(),
        endorsement_policy: prefix.endorsement_policy.to_vec(),
        lockout_policy: prefix.lockout_policy.to_vec(),
        owner_auth: prefix.owner_auth.to_owned_secret(),
        endorsement_auth: prefix.endorsement_auth.to_owned_secret(),
        lockout_auth: prefix.lockout_auth.to_owned_secret(),
        ep_seed: prefix.ep_seed.to_owned_secret(),
        sp_seed: prefix.sp_seed.to_owned_secret(),
        pp_seed: prefix.pp_seed.to_owned_secret(),
        ph_proof: prefix.ph_proof.to_owned_secret(),
        sh_proof: prefix.sh_proof.to_owned_secret(),
        eh_proof: prefix.eh_proof.to_owned_secret(),
        total_reset_count: prefix.total_reset_count,
        reset_count: prefix.reset_count,
        pcr_policies,
        pcr_allocated: own_pcr_allocation(&data.pcr_allocated),
        pp_list: OwnedCommandBitmap {
            compressed: data.pp_list.compressed,
            bytes: data.pp_list.array.to_vec(),
        },
        failed_tries: data.lockout.failed_tries,
        max_tries: data.lockout.max_tries,
        recovery_time: data.lockout.recovery_time,
        lockout_recovery: data.lockout.lockout_recovery,
        lockout_auth_enabled: data.lockout.lockout_auth_enabled,
        orderly_state: data.lockout.orderly_state,
        audit_commands: OwnedCommandBitmap {
            compressed: data.audit.commands_compressed,
            bytes: data.audit.commands.to_vec(),
        },
        audit_hash_alg: data.audit.audit_hash_alg,
        audit_counter: data.audit.audit_counter,
        algorithm_set: data.audit.algorithm_set,
        firmware_v1: data.audit.firmware_v1,
        firmware_v2: data.audit.firmware_v2,
        time_epoch: data.audit.time_epoch,
        shadow_pcr_allocated: data
            .compat
            .shadow_pcr_allocated
            .as_ref()
            .map(own_pcr_allocation),
        ep_seed_compat_level: data.compat.ep_seed_compat_level,
        sp_seed_compat_level: data.compat.sp_seed_compat_level,
        pp_seed_compat_level: data.compat.pp_seed_compat_level,
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedDrbgState {
    pub(in crate::library::tpm2) reseed_counter: u64,
    pub(in crate::library::tpm2) drbg_magic: u32,
    pub(in crate::library::tpm2) seed: OwnedSecret,
    pub(in crate::library::tpm2) last_value: [u32; super::orderly::DRBG_LAST_VALUE_COUNT],
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedOrderlyData {
    pub(in crate::library::tpm2) clock: u64,
    pub(in crate::library::tpm2) clock_safe: u8,
    pub(in crate::library::tpm2) drbg_state: OwnedDrbgState,
    pub(in crate::library::tpm2) self_heal_timer: u64,
    pub(in crate::library::tpm2) lockout_timer: u64,
    pub(in crate::library::tpm2) time: u64,
}

pub(in crate::library::tpm2) fn own_orderly_data(orderly: &OrderlyData<'_>) -> OwnedOrderlyData {
    let drbg: &DrbgState<'_> = &orderly.drbg_state;
    OwnedOrderlyData {
        clock: orderly.clock,
        clock_safe: orderly.clock_safe,
        drbg_state: OwnedDrbgState {
            reseed_counter: drbg.reseed_counter,
            drbg_magic: drbg.drbg_magic,
            seed: OwnedSecret::copy_of(drbg.seed),
            last_value: drbg.last_value,
        },
        self_heal_timer: orderly.self_heal_timer,
        lockout_timer: orderly.lockout_timer,
        time: orderly.time,
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedStateResetData {
    pub(in crate::library::tpm2) null_proof: OwnedSecret,
    pub(in crate::library::tpm2) null_seed: OwnedSecret,
    pub(in crate::library::tpm2) clear_count: u32,
    pub(in crate::library::tpm2) object_context_id: u64,
    pub(in crate::library::tpm2) context_array: Box<[u16; MAX_ACTIVE_SESSIONS]>,
    pub(in crate::library::tpm2) context_slot_mask: u16,
    pub(in crate::library::tpm2) context_counter: u64,
    pub(in crate::library::tpm2) command_audit_digest: Vec<u8>,
    pub(in crate::library::tpm2) restart_count: u32,
    pub(in crate::library::tpm2) pcr_counter: u32,
    pub(in crate::library::tpm2) commit_counter: u64,
    pub(in crate::library::tpm2) commit_nonce: OwnedSecret,
    pub(in crate::library::tpm2) commit_array: [u8; COMMIT_ARRAY_SIZE],
    pub(in crate::library::tpm2) null_seed_compat_level: u8,
}

pub(in crate::library::tpm2) fn own_state_reset(reset: &StateResetData<'_>) -> OwnedStateResetData {
    let mut commit_array = [0u8; COMMIT_ARRAY_SIZE];
    commit_array.copy_from_slice(reset.commit_array);
    OwnedStateResetData {
        null_proof: OwnedSecret::copy_of(reset.null_proof),
        null_seed: OwnedSecret::copy_of(reset.null_seed),
        clear_count: reset.clear_count,
        object_context_id: reset.object_context_id,
        context_array: Box::new(reset.context_array),
        context_slot_mask: reset.context_slot_mask,
        context_counter: reset.context_counter,
        command_audit_digest: reset.command_audit_digest.to_vec(),
        restart_count: reset.restart_count,
        pcr_counter: reset.pcr_counter,
        commit_counter: reset.commit_counter,
        commit_nonce: OwnedSecret::copy_of(reset.commit_nonce),
        commit_array,
        null_seed_compat_level: reset.null_seed_compat_level,
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedPcrBank {
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) pcrs: Vec<u8>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedStateClearData {
    pub(in crate::library::tpm2) sh_enable: bool,
    pub(in crate::library::tpm2) eh_enable: bool,
    pub(in crate::library::tpm2) ph_enable_nv: bool,
    pub(in crate::library::tpm2) platform_alg: u16,
    pub(in crate::library::tpm2) platform_policy: Vec<u8>,
    pub(in crate::library::tpm2) platform_auth: OwnedSecret,
    pub(in crate::library::tpm2) pcr_save: [Option<OwnedPcrBank>; PCR_BANKS.len()],
    pub(in crate::library::tpm2) pcr_auth_values: [OwnedSecret; NUM_AUTHVALUE_PCR_GROUP],
}

pub(in crate::library::tpm2) fn own_state_clear(clear: &StateClearData<'_>) -> OwnedStateClearData {
    OwnedStateClearData {
        sh_enable: clear.sh_enable,
        eh_enable: clear.eh_enable,
        ph_enable_nv: clear.ph_enable_nv,
        platform_alg: clear.platform_alg,
        platform_policy: clear.platform_policy.to_vec(),
        platform_auth: OwnedSecret::copy_of(clear.platform_auth),
        pcr_save: core::array::from_fn(|index| {
            clear.pcr_save.banks[index].map(|bank: PcrBank<'_>| OwnedPcrBank {
                hash_alg: bank.hash_alg,
                pcrs: bank.pcrs.to_vec(),
            })
        }),
        pcr_auth_values: core::array::from_fn(|index| {
            OwnedSecret::copy_of(clear.pcr_auth_values[index])
        }),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct OwnedOrderlyRamEntry {
    pub(in crate::library::tpm2) declared_size: u32,
    pub(in crate::library::tpm2) handle: u32,
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) data: Vec<u8>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedIndexOrderlyRam {
    pub(in crate::library::tpm2) sourceside_size: u32,
    pub(in crate::library::tpm2) entries: Vec<OwnedOrderlyRamEntry>,
    pub(in crate::library::tpm2) terminated: bool,
    pub(in crate::library::tpm2) used_bytes: u64,
}

fn own_index_orderly_ram(ram: &IndexOrderlyRam<'_>) -> Result<OwnedIndexOrderlyRam, TpmResult> {
    let mut used_bytes: u64 = 0;
    for entry in &ram.entries {
        let entry: &OrderlyRamEntry<'_> = entry;
        used_bytes = used_bytes
            .checked_add(NV_RAM_HEADER_SIZE)
            .and_then(|used| used.checked_add(entry.data.len() as u64))
            .filter(|&used| used <= RAM_INDEX_SPACE)
            .ok_or(TPM_FAIL)?;
    }
    Ok(OwnedIndexOrderlyRam {
        sourceside_size: ram.sourceside_size,
        entries: ram
            .entries
            .iter()
            .map(|entry| OwnedOrderlyRamEntry {
                declared_size: entry.declared_size,
                handle: entry.handle,
                attributes: entry.attributes,
                data: entry.data.to_vec(),
            })
            .collect(),
        terminated: ram.terminated,
        used_bytes,
    })
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) enum OwnedHashPayload {
    Sha1 {
        h: [u32; 5],
        nl: u32,
        nh: u32,
        data: OwnedSecret,
        num: u32,
    },
    Sha256 {
        h: [u32; 8],
        nl: u32,
        nh: u32,
        data: OwnedSecret,
        num: u32,
        md_len: u32,
    },
    Sha512 {
        h: [u64; 8],
        nl: u64,
        nh: u64,
        data: OwnedSecret,
        num: u32,
        md_len: u32,
    },
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedHashState {
    pub(in crate::library::tpm2) state_type: u8,
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) payload: Option<OwnedHashPayload>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedBnPrime {
    pub(in crate::library::tpm2) numbytes: u16,
    pub(in crate::library::tpm2) data: OwnedSecret,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedPrivateExponent {
    pub(in crate::library::tpm2) primes: [OwnedBnPrime; 4],
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedTpmtPublic {
    pub(in crate::library::tpm2) object_type: u16,
    pub(in crate::library::tpm2) name_alg: u16,
    pub(in crate::library::tpm2) object_attributes: u32,
    pub(in crate::library::tpm2) auth_policy: Vec<u8>,
    pub(in crate::library::tpm2) parameters: PublicParms,
    pub(in crate::library::tpm2) unique: OwnedPublicId,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) enum OwnedPublicId {
    KeyedHash(Vec<u8>),
    Sym(Vec<u8>),
    Rsa(Vec<u8>),
    Ecc { x: Vec<u8>, y: Vec<u8> },
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedTpmtSensitive {
    pub(in crate::library::tpm2) sensitive_type: u16,
    pub(in crate::library::tpm2) auth_value: OwnedSecret,
    pub(in crate::library::tpm2) seed_value: OwnedSecret,
    pub(in crate::library::tpm2) sensitive: Option<OwnedSecret>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedObjectBody {
    pub(in crate::library::tpm2) section_version: u16,
    pub(in crate::library::tpm2) public: OwnedTpmtPublic,
    pub(in crate::library::tpm2) sensitive: OwnedTpmtSensitive,
    pub(in crate::library::tpm2) private_exponent: Option<OwnedPrivateExponent>,
    pub(in crate::library::tpm2) qualified_name: Vec<u8>,
    pub(in crate::library::tpm2) evict_handle: u32,
    pub(in crate::library::tpm2) name: Vec<u8>,
    pub(in crate::library::tpm2) seed_compat_level: u8,
    pub(in crate::library::tpm2) hierarchy: Option<u32>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedHashObjectBody {
    pub(in crate::library::tpm2) section_version: u16,
    pub(in crate::library::tpm2) object_type: u16,
    pub(in crate::library::tpm2) name_alg: u16,
    pub(in crate::library::tpm2) object_attributes: u32,
    pub(in crate::library::tpm2) auth: OwnedSecret,
    pub(in crate::library::tpm2) states: Option<Box<[OwnedHashState; HASH_STATE_COUNT]>>,
    pub(in crate::library::tpm2) hmac_state: Option<(OwnedHashState, OwnedSecret)>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(in crate::library::tpm2) enum OwnedAnyObjectBody {
    Unoccupied,
    Object(Box<OwnedObjectBody>),
    Sequence(Box<OwnedHashObjectBody>),
}

#[derive(Clone)]
pub(in crate::library::tpm2) struct OwnedAnyObject {
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) body: OwnedAnyObjectBody,
}

impl core::fmt::Debug for OwnedAnyObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match &self.body {
            OwnedAnyObjectBody::Unoccupied => "unoccupied",
            OwnedAnyObjectBody::Object(_) => "object",
            OwnedAnyObjectBody::Sequence(_) => "sequence",
        };
        f.debug_struct("OwnedAnyObject")
            .field("attributes", &format_args!("{:#010x}", self.attributes))
            .field("body", &kind)
            .finish()
    }
}

fn own_hash_state(state: &HashState<'_>) -> OwnedHashState {
    OwnedHashState {
        state_type: state.state_type,
        hash_alg: state.hash_alg,
        payload: state.payload.as_ref().map(|payload| match *payload {
            HashPayload::Sha1 {
                h,
                nl,
                nh,
                data,
                num,
            } => OwnedHashPayload::Sha1 {
                h,
                nl,
                nh,
                data: OwnedSecret::copy_of(data),
                num,
            },
            HashPayload::Sha256 {
                h,
                nl,
                nh,
                data,
                num,
                md_len,
            } => OwnedHashPayload::Sha256 {
                h,
                nl,
                nh,
                data: OwnedSecret::copy_of(data),
                num,
                md_len,
            },
            HashPayload::Sha512 {
                h,
                nl,
                nh,
                data,
                num,
                md_len,
            } => OwnedHashPayload::Sha512 {
                h,
                nl,
                nh,
                data: OwnedSecret::copy_of(data),
                num,
                md_len,
            },
        }),
    }
}

fn own_tpmt_public(public: &TpmtPublic<'_>) -> OwnedTpmtPublic {
    OwnedTpmtPublic {
        object_type: public.object_type,
        name_alg: public.name_alg,
        object_attributes: public.object_attributes,
        auth_policy: public.auth_policy.to_vec(),
        parameters: public.parameters,
        unique: match public.unique {
            PublicId::KeyedHash(bytes) => OwnedPublicId::KeyedHash(bytes.to_vec()),
            PublicId::Sym(bytes) => OwnedPublicId::Sym(bytes.to_vec()),
            PublicId::Rsa(bytes) => OwnedPublicId::Rsa(bytes.to_vec()),
            PublicId::Ecc { x, y } => OwnedPublicId::Ecc {
                x: x.to_vec(),
                y: y.to_vec(),
            },
        },
    }
}

fn own_tpmt_sensitive(sensitive: &TpmtSensitive<'_>) -> OwnedTpmtSensitive {
    OwnedTpmtSensitive {
        sensitive_type: sensitive.sensitive_type,
        auth_value: OwnedSecret::copy_of(sensitive.auth_value),
        seed_value: OwnedSecret::copy_of(sensitive.seed_value),
        sensitive: sensitive.sensitive.map(OwnedSecret::copy_of),
    }
}

fn own_private_exponent(exponent: &PrivateExponent<'_>) -> OwnedPrivateExponent {
    OwnedPrivateExponent {
        primes: core::array::from_fn(|index| {
            let prime: &BnPrime<'_> = &exponent.primes[index];
            OwnedBnPrime {
                numbytes: prime.numbytes,
                data: OwnedSecret::copy_of(prime.data),
            }
        }),
    }
}

fn own_object_body(object: &ObjectBody<'_>) -> OwnedObjectBody {
    OwnedObjectBody {
        section_version: object.section_version,
        public: own_tpmt_public(&object.public),
        sensitive: own_tpmt_sensitive(&object.sensitive),
        private_exponent: object.private_exponent.as_ref().map(own_private_exponent),
        qualified_name: object.qualified_name.to_vec(),
        evict_handle: object.evict_handle,
        name: object.name.to_vec(),
        seed_compat_level: object.seed_compat_level,
        hierarchy: object.hierarchy,
    }
}

fn own_hash_object_body(sequence: &HashObjectBody<'_>) -> OwnedHashObjectBody {
    OwnedHashObjectBody {
        section_version: sequence.section_version,
        object_type: sequence.object_type,
        name_alg: sequence.name_alg,
        object_attributes: sequence.object_attributes,
        auth: OwnedSecret::copy_of(sequence.auth),
        states: sequence
            .states
            .as_ref()
            .map(|states| Box::new(core::array::from_fn(|index| own_hash_state(&states[index])))),
        hmac_state: sequence
            .hmac_state
            .as_ref()
            .map(|(state, key)| (own_hash_state(state), OwnedSecret::copy_of(key))),
    }
}

pub(in crate::library::tpm2) fn own_any_object(object: &AnyObject<'_>) -> OwnedAnyObject {
    OwnedAnyObject {
        attributes: object.attributes,
        body: match &object.body {
            AnyObjectBody::Unoccupied => OwnedAnyObjectBody::Unoccupied,
            AnyObjectBody::Object(body) => {
                OwnedAnyObjectBody::Object(Box::new(own_object_body(body)))
            }
            AnyObjectBody::Sequence(body) => {
                OwnedAnyObjectBody::Sequence(Box::new(own_hash_object_body(body)))
            }
        },
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedNvIndex {
    pub(in crate::library::tpm2) nv_index: u32,
    pub(in crate::library::tpm2) name_alg: u16,
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) auth_policy: Vec<u8>,
    pub(in crate::library::tpm2) data_size: u16,
    pub(in crate::library::tpm2) auth_value: OwnedSecret,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) enum OwnedUserNvramEntry {
    NvIndex {
        declared_entry_size: u32,
        handle: u32,
        index: OwnedNvIndex,
        data: Vec<u8>,
    },
    Persistent {
        declared_entry_size: u32,
        handle: u32,
        object: OwnedAnyObject,
        object_destination_size: u64,
    },
}

impl OwnedUserNvramEntry {
    pub(in crate::library::tpm2) fn destination_size(&self) -> u64 {
        match self {
            Self::NvIndex { data, .. } => {
                4 + crate::library::tpm2::nv::SIZEOF_NV_INDEX + data.len() as u64
            }
            Self::Persistent {
                object_destination_size,
                ..
            } => 4 + 4 + object_destination_size,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedUserNvram {
    pub(in crate::library::tpm2) entries: Vec<OwnedUserNvramEntry>,
    pub(in crate::library::tpm2) max_count: u64,
    pub(in crate::library::tpm2) required_capacity: u64,
}

fn own_user_nvram(user: &UserNvram<'_>) -> Result<OwnedUserNvram, TpmResult> {
    let entries: Vec<OwnedUserNvramEntry> = user
        .entries
        .iter()
        .map(|entry| match entry {
            UserNvramEntry::NvIndex {
                declared_entry_size,
                handle,
                index,
                data,
            } => {
                let index: &NvIndex<'_> = index;
                OwnedUserNvramEntry::NvIndex {
                    declared_entry_size: *declared_entry_size,
                    handle: *handle,
                    index: OwnedNvIndex {
                        nv_index: index.nv_index,
                        name_alg: index.name_alg,
                        attributes: index.attributes,
                        auth_policy: index.auth_policy.to_vec(),
                        data_size: index.data_size,
                        auth_value: OwnedSecret::copy_of(index.auth_value),
                    },
                    data: data.to_vec(),
                }
            }
            UserNvramEntry::Persistent {
                declared_entry_size,
                handle,
                object,
                object_destination_size,
            } => OwnedUserNvramEntry::Persistent {
                declared_entry_size: *declared_entry_size,
                handle: *handle,
                object: own_any_object(object),
                object_destination_size: *object_destination_size,
            },
        })
        .collect();

    let mut required_capacity: u64 = 0;
    for entry in &entries {
        required_capacity = required_capacity
            .checked_add(entry.destination_size())
            .filter(|&needed| needed <= USER_NVRAM_CAPACITY)
            .ok_or(TPM_FAIL)?;
    }
    required_capacity = required_capacity
        .checked_add(4 + 8)
        .filter(|&needed| needed <= USER_NVRAM_CAPACITY)
        .ok_or(TPM_FAIL)?;
    if required_capacity != user.required_capacity {
        return Err(TPM_FAIL);
    }

    Ok(OwnedUserNvram {
        entries,
        max_count: user.max_count,
        required_capacity,
    })
}

#[derive(Debug)]
#[allow(dead_code)]
pub(in crate::library::tpm2) struct OwnedPersistentState {
    pub(in crate::library::tpm2) profile: ValidatedProfile,
    pub(in crate::library::tpm2) persistent: OwnedPersistentData,
    pub(in crate::library::tpm2) orderly: OwnedOrderlyData,
    pub(in crate::library::tpm2) state_reset: Option<OwnedStateResetData>,
    pub(in crate::library::tpm2) state_clear: Option<OwnedStateClearData>,
    pub(in crate::library::tpm2) index_orderly_ram: OwnedIndexOrderlyRam,
    pub(in crate::library::tpm2) user_nvram: OwnedUserNvram,
    pub(in crate::library::tpm2) envelope_version: u16,
    pub(in crate::library::tpm2) read_su_state: bool,
}

pub(in crate::library::tpm2) fn materialize_persistent_state(
    decoded: DecodedPersistentAll<'_>,
) -> Result<OwnedPersistentState, TpmResult> {
    let profile = decoded.profile;

    let (state_reset, state_clear) = match (
        decoded.read_su_state,
        &decoded.state_reset_data,
        &decoded.state_clear_data,
    ) {
        (true, Some(reset), Some(clear)) => {
            (Some(own_state_reset(reset)), Some(own_state_clear(clear)))
        }
        (false, None, None) => (None, None),
        _ => return Err(TPM_FAIL),
    };

    let persistent = own_persistent_data(&decoded.persistent_data);

    let orderly = own_orderly_data(&decoded.orderly_data);

    let index_orderly_ram = own_index_orderly_ram(&decoded.index_orderly_ram)?;
    let user_nvram = own_user_nvram(&decoded.user_nvram)?;

    Ok(OwnedPersistentState {
        profile,
        persistent,
        orderly,
        state_reset,
        state_clear,
        index_orderly_ram,
        user_nvram,
        envelope_version: decoded.envelope_version,
        read_su_state: decoded.read_su_state,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{PersistentAllEnvelope, compat_tail, data, orderly};
    use super::*;
    use crate::library::constants::TPM_RC_SIZE;
    use crate::library::tpm2::nv::{
        IndexOrderlyRamFixture, NvIndexFixture, SIZEOF_NV_INDEX, UserNvramFixture,
    };
    use crate::library::tpm2::pcr::{PcrAllocationFixture, PcrPoliciesFixture};
    use crate::library::tpm2::profile::PersistentObjectFormat;
    use crate::library::tpm2::{
        DecodedPersistentAll, audit, compile_constants, lockout, object,
        parse_persistent_all_payload, pp_list, valid_permanent_state_fixture,
    };

    fn envelope_with_payload(payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
        blob.extend_from_slice(payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        blob
    }

    fn envelope_v4_with_profile(profile: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0x00, 0x04, 0xab, 0x36, 0x47, 0x23, 0x00, 0x04];
        blob.extend_from_slice(&u16::try_from(profile.len() + 1).unwrap().to_be_bytes());
        blob.extend_from_slice(profile);
        blob.push(0);
        blob.extend_from_slice(payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        blob
    }

    fn simple_payload(orderly_state: u16, sections: Vec<u8>) -> Vec<u8> {
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &data::PrefixFixture {
                tail: PcrPoliciesFixture {
                    tail: PcrAllocationFixture {
                        tail: pp_list::PpListFixture {
                            tail: lockout::LockoutFixture {
                                orderly_state,
                                tail: audit::AuditFixture {
                                    tail: compat_tail::CompatTailFixture {
                                        tail: sections,
                                        ..compat_tail::CompatTailFixture::default()
                                    }
                                    .bytes(),
                                    ..audit::AuditFixture::default()
                                }
                                .bytes(),
                                ..lockout::LockoutFixture::default()
                            }
                            .bytes(),
                            ..pp_list::PpListFixture::default()
                        }
                        .bytes(),
                        ..PcrAllocationFixture::default()
                    }
                    .bytes(),
                    ..PcrPoliciesFixture::default()
                }
                .bytes(),
                ..data::PrefixFixture::default()
            }
            .bytes(),
        );
        payload
    }

    fn decode(blob: &[u8]) -> DecodedPersistentAll<'_> {
        let envelope = PersistentAllEnvelope::parse(blob).unwrap();
        parse_persistent_all_payload(&envelope).unwrap()
    }

    fn materialize(blob: &[u8]) -> OwnedPersistentState {
        materialize_persistent_state(decode(blob)).unwrap()
    }

    #[test]
    fn valid_fixture_materializes_the_null_profile_candidate() {
        let blob = valid_permanent_state_fixture();
        let candidate = materialize(&blob);

        assert!(candidate.profile.was_null_profile);
        assert_eq!(candidate.profile.name, b"null");
        assert_eq!(candidate.profile.state_format_level, 1);
        assert_eq!(
            candidate.profile.object_format(),
            PersistentObjectFormat::LegacyRsa3072
        );
        assert!(candidate.profile.attributes.is_none());

        assert_eq!(candidate.envelope_version, 3);
        assert!(!candidate.read_su_state);
        assert!(candidate.state_reset.is_none());
        assert!(candidate.state_clear.is_none());

        assert!(!candidate.persistent.disable_clear);
        assert_eq!(candidate.persistent.section_version, 5);
        assert_eq!(candidate.persistent.total_reset_count, 0);
        assert_eq!(candidate.persistent.orderly_state, 0);
        assert!(!candidate.persistent.pp_list.compressed);
        assert_eq!(candidate.persistent.pp_list.bytes.len(), 17);
        assert_eq!(candidate.persistent.pcr_allocated.selections.len(), 1);
        assert!(candidate.persistent.shadow_pcr_allocated.is_some());
        assert_eq!(candidate.persistent.ep_seed_compat_level, 0);

        assert_eq!(candidate.orderly.clock, 0);
        assert_eq!(candidate.orderly.clock_safe, 1);
        assert_eq!(candidate.orderly.drbg_state.seed.expose(), &[0x5a; 48][..]);

        assert!(candidate.index_orderly_ram.entries.is_empty());
        assert!(candidate.index_orderly_ram.terminated);
        assert_eq!(candidate.index_orderly_ram.used_bytes, 0);
        assert!(candidate.user_nvram.entries.is_empty());
        assert_eq!(candidate.user_nvram.max_count, 0);
        assert_eq!(candidate.user_nvram.required_capacity, 12);
    }

    #[test]
    fn candidate_survives_dropping_the_input_blob() {
        let candidate = {
            let blob = valid_permanent_state_fixture();
            materialize(&blob)
        };
        assert_eq!(candidate.orderly.drbg_state.seed.expose(), &[0x5a; 48][..]);
        assert_eq!(candidate.user_nvram.required_capacity, 12);
    }

    #[test]
    fn candidate_debug_output_never_contains_secret_bytes() {
        let auth = b"auth-secret-mark".to_vec();
        let seed = b"seed-secret-mark".to_vec();
        let proof = b"proof-secret-mrk".to_vec();
        let mut prefix = data::PrefixFixture {
            tail: PcrPoliciesFixture {
                tail: PcrAllocationFixture {
                    tail: pp_list::PpListFixture {
                        tail: crate::library::tpm2::persistent_data_tail(),
                        ..pp_list::PpListFixture::default()
                    }
                    .bytes(),
                    ..PcrAllocationFixture::default()
                }
                .bytes(),
                ..PcrPoliciesFixture::default()
            }
            .bytes(),
            ..data::PrefixFixture::default()
        };
        prefix.tpm2bs[3] = auth.clone();
        prefix.tpm2bs[6] = seed.clone();
        prefix.tpm2bs[9] = proof.clone();
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(&prefix.bytes());
        let blob = envelope_with_payload(&payload);
        let candidate = materialize(&blob);
        let formatted = format!("{candidate:?}");
        for secret in ["auth-secret-mark", "seed-secret-mark", "proof-secret-mrk"] {
            assert!(
                !formatted.contains(secret),
                "candidate Debug must not contain {secret:?}"
            );
        }
        assert!(formatted.contains("OwnedSecret { len: 16 }"), "{formatted}");
    }

    #[test]
    fn serialized_profiles_select_the_documented_object_formats() {
        for (profile, level, format) in [
            (
                &br#"{"Name":"null","StateFormatLevel":1}"#[..],
                1,
                PersistentObjectFormat::LegacyRsa3072,
            ),
            (
                br#"{"Name":"default-v1","StateFormatLevel":5}"#,
                5,
                PersistentObjectFormat::AnyObject { object_version: 3 },
            ),
            (
                br#"{"Name":"default-v1","StateFormatLevel":6}"#,
                6,
                PersistentObjectFormat::AnyObject { object_version: 4 },
            ),
            (
                br#"{"Name":"default-v1","StateFormatLevel":7}"#,
                7,
                PersistentObjectFormat::AnyObject { object_version: 4 },
            ),
        ] {
            let blob = envelope_v4_with_profile(
                profile,
                &simple_payload(0, crate::library::tpm2::remaining_sections()),
            );
            let candidate = materialize(&blob);
            assert_eq!(candidate.profile.state_format_level, level);
            assert_eq!(candidate.profile.object_format(), format);
            assert!(!candidate.profile.was_null_profile);
            assert_eq!(candidate.envelope_version, 4);
        }
    }

    #[test]
    fn su_state_blob_materializes_both_startup_sections() {
        let blob = envelope_with_payload(&simple_payload(
            0x0001,
            crate::library::tpm2::remaining_sections_with_su_state(),
        ));
        let candidate = materialize(&blob);
        assert!(candidate.read_su_state);
        let reset = candidate.state_reset.as_ref().unwrap();
        assert_eq!(reset.null_proof.expose(), &[0x0f; 8][..]);
        assert_eq!(reset.null_seed.expose(), &[0x5e; 8][..]);
        assert_eq!(reset.context_slot_mask, 0xffff);
        assert_eq!(*reset.context_array, [0u16; MAX_ACTIVE_SESSIONS]);
        assert_eq!(reset.commit_array, [0u8; COMMIT_ARRAY_SIZE]);
        assert_eq!(reset.null_seed_compat_level, 0);
        let clear = candidate.state_clear.as_ref().unwrap();
        assert!(clear.sh_enable && clear.eh_enable && clear.ph_enable_nv);
        assert_eq!(clear.platform_alg, 0x0010);
        for (slot, &(alg, size)) in clear.pcr_save.iter().zip(PCR_BANKS.iter()) {
            let bank = slot.as_ref().unwrap();
            assert_eq!(bank.hash_alg, alg);
            assert_eq!(bank.pcrs.len(), size);
        }
        assert_eq!(clear.pcr_auth_values.len(), NUM_AUTHVALUE_PCR_GROUP);
    }

    #[test]
    fn non_su_state_blob_materializes_no_startup_sections() {
        let blob = envelope_with_payload(&simple_payload(
            0x0000,
            crate::library::tpm2::remaining_sections(),
        ));
        let candidate = materialize(&blob);
        assert!(!candidate.read_su_state);
        assert!(candidate.state_reset.is_none());
        assert!(candidate.state_clear.is_none());
    }

    #[test]
    fn pcr_allocation_and_shadow_stay_separate_in_the_candidate() {
        let allocated = PcrAllocationFixture {
            selections: vec![(0x000b, 3, vec![0x01, 0x00, 0x00])],
            ..PcrAllocationFixture::default()
        };
        let compat = compat_tail::CompatTailFixture {
            shadow: PcrAllocationFixture {
                selections: vec![(0x0004, 3, vec![0x00, 0x00, 0x02])],
                ..PcrAllocationFixture::default()
            }
            .bytes(),
            ..compat_tail::CompatTailFixture::default()
        };
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &data::PrefixFixture {
                tail: PcrPoliciesFixture {
                    tail: PcrAllocationFixture {
                        tail: pp_list::PpListFixture {
                            tail: lockout::LockoutFixture {
                                tail: audit::AuditFixture {
                                    tail: compat_tail::CompatTailFixture {
                                        tail: crate::library::tpm2::remaining_sections(),
                                        ..compat
                                    }
                                    .bytes(),
                                    ..audit::AuditFixture::default()
                                }
                                .bytes(),
                                ..lockout::LockoutFixture::default()
                            }
                            .bytes(),
                            ..pp_list::PpListFixture::default()
                        }
                        .bytes(),
                        ..allocated
                    }
                    .bytes(),
                    ..PcrPoliciesFixture::default()
                }
                .bytes(),
                ..data::PrefixFixture::default()
            }
            .bytes(),
        );
        let blob = envelope_with_payload(&payload);
        let candidate = materialize(&blob);
        assert_eq!(
            candidate.persistent.pcr_allocated.selections,
            vec![OwnedPcrSelection {
                hash_alg: 0x000b,
                select: vec![0x01, 0x00, 0x00],
            }]
        );
        assert_eq!(
            candidate.persistent.shadow_pcr_allocated,
            Some(OwnedPcrAllocation {
                selections: vec![OwnedPcrSelection {
                    hash_alg: 0x0004,
                    select: vec![0x00, 0x00, 0x02],
                }]
            })
        );
    }

    #[test]
    fn orderly_values_are_preserved_exactly() {
        let mut sections = orderly::OrderlyFixture {
            clock: 0x1122_3344_5566_7788,
            clock_safe: 0,
            drbg: orderly::DrbgFixture {
                reseed_counter: 9,
                last_value: [5, 6, 7, 8],
                ..orderly::DrbgFixture::default()
            }
            .bytes(),
            self_heal: [11, 22, 33],
            ..orderly::OrderlyFixture::default()
        }
        .bytes();
        sections.extend_from_slice(&IndexOrderlyRamFixture::default().bytes());
        sections.extend_from_slice(&UserNvramFixture::default().bytes());
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);
        let blob = envelope_with_payload(&simple_payload(0, sections));
        let candidate = materialize(&blob);
        assert_eq!(candidate.orderly.clock, 0x1122_3344_5566_7788);
        assert_eq!(candidate.orderly.clock_safe, 0);
        assert_eq!(candidate.orderly.drbg_state.reseed_counter, 9);
        assert_eq!(candidate.orderly.drbg_state.last_value, [5, 6, 7, 8]);
        assert_eq!(candidate.orderly.self_heal_timer, 11);
        assert_eq!(candidate.orderly.lockout_timer, 22);
        assert_eq!(candidate.orderly.time, 33);
    }

    #[test]
    fn mixed_nv_index_and_persistent_entries_materialize() {
        let index_bytes = NvIndexFixture::default().bytes();
        let bulk = vec![0xa5u8; 24];
        let object_bytes = object::fixtures::any_rsa_object(4);
        let mut sections = orderly::OrderlyFixture::default().bytes();
        sections.extend_from_slice(&IndexOrderlyRamFixture::default().bytes());
        sections.extend_from_slice(
            &UserNvramFixture {
                entries: vec![
                    UserNvramFixture::nv_index_entry(0x0100_0001, &index_bytes, &bulk),
                    UserNvramFixture::persistent_entry(0x8100_0001, &object_bytes),
                ],
                max_count: Some(41),
                ..UserNvramFixture::default()
            }
            .bytes(),
        );
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);
        let blob = envelope_v4_with_profile(
            br#"{"Name":"default-v1","StateFormatLevel":7}"#,
            &simple_payload(0, sections),
        );
        let candidate = materialize(&blob);
        assert_eq!(candidate.user_nvram.max_count, 41);
        assert_eq!(candidate.user_nvram.entries.len(), 2);
        let mut expected_capacity = 4 + 8;
        match &candidate.user_nvram.entries[0] {
            OwnedUserNvramEntry::NvIndex {
                handle,
                index,
                data,
                ..
            } => {
                assert_eq!(*handle, 0x0100_0001);
                assert_eq!(index.nv_index, 0x0100_0001);
                assert_eq!(index.name_alg, 0x000b);
                assert_eq!(index.data_size, 8);
                assert_eq!(data, &bulk);
                expected_capacity += 4 + SIZEOF_NV_INDEX + bulk.len() as u64;
            }
            other => panic!("expected an NV index entry, got {other:?}"),
        }
        match &candidate.user_nvram.entries[1] {
            OwnedUserNvramEntry::Persistent {
                handle,
                object,
                object_destination_size,
                ..
            } => {
                assert_eq!(*handle, 0x8100_0001);
                assert!(matches!(object.body, OwnedAnyObjectBody::Object(_)));
                expected_capacity += 4 + 4 + object_destination_size;
            }
            other => panic!("expected a persistent entry, got {other:?}"),
        }
        assert_eq!(candidate.user_nvram.required_capacity, expected_capacity);
    }

    fn boundary_blob(last_datasize: u32) -> Vec<u8> {
        let index_bytes = NvIndexFixture::default().bytes();
        let entries = [65792u32, 65792, last_datasize]
            .iter()
            .enumerate()
            .map(|(i, &datasize)| {
                UserNvramFixture::nv_index_entry(
                    0x0100_0001 + i as u32,
                    &index_bytes,
                    &vec![0u8; datasize as usize],
                )
            })
            .collect();
        let mut sections = orderly::OrderlyFixture::default().bytes();
        sections.extend_from_slice(&IndexOrderlyRamFixture::default().bytes());
        sections.extend_from_slice(
            &UserNvramFixture {
                entries,
                ..UserNvramFixture::default()
            }
            .bytes(),
        );
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);
        envelope_with_payload(&simple_payload(0, sections))
    }

    #[test]
    fn exact_nvram_boundary_is_accepted() {
        let blob = boundary_blob(39148);
        let candidate = materialize(&blob);
        assert_eq!(candidate.user_nvram.required_capacity, USER_NVRAM_CAPACITY);
    }

    #[test]
    fn one_byte_nvram_overflow_is_rejected() {
        let blob = boundary_blob(39149);
        let envelope = PersistentAllEnvelope::parse(&blob).unwrap();
        let error = parse_persistent_all_payload(&envelope)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn mismatched_su_state_metadata_is_rejected() {
        let su_blob = envelope_with_payload(&simple_payload(
            0x0001,
            crate::library::tpm2::remaining_sections_with_su_state(),
        ));
        let plain_blob = envelope_with_payload(&simple_payload(
            0,
            crate::library::tpm2::remaining_sections(),
        ));

        let mut decoded = decode(&su_blob);
        decoded.read_su_state = false;
        assert_eq!(materialize_persistent_state(decoded).unwrap_err(), TPM_FAIL);

        let mut decoded = decode(&su_blob);
        decoded.state_clear_data = None;
        assert_eq!(materialize_persistent_state(decoded).unwrap_err(), TPM_FAIL);

        let mut decoded = decode(&su_blob);
        decoded.state_reset_data = None;
        assert_eq!(materialize_persistent_state(decoded).unwrap_err(), TPM_FAIL);

        let mut decoded = decode(&plain_blob);
        decoded.read_su_state = true;
        assert_eq!(materialize_persistent_state(decoded).unwrap_err(), TPM_FAIL);
    }

    #[test]
    fn inconsistent_nvram_accounting_is_rejected() {
        let blob = valid_permanent_state_fixture();
        let mut decoded = decode(&blob);
        decoded.user_nvram.required_capacity += 1;
        assert_eq!(materialize_persistent_state(decoded).unwrap_err(), TPM_FAIL);
    }

    #[test]
    fn orderly_ram_overflow_is_rejected() {
        static BIG: [u8; 200] = [0u8; 200];
        let blob = valid_permanent_state_fixture();
        let mut decoded = decode(&blob);
        for _ in 0..3 {
            decoded.index_orderly_ram.entries.push(OrderlyRamEntry {
                declared_size: 212,
                handle: 0x0100_0002,
                attributes: 0,
                data: &BIG,
            });
        }
        assert_eq!(materialize_persistent_state(decoded).unwrap_err(), TPM_FAIL);
    }
}
