use super::dispatcher::CommandFrame;
use super::output::CommandOutput;
use crate::library::tpm2::command::{
    administration, attestation, context, crypto, hierarchy, lifecycle, nv, object, pcr, platform,
    policy, session,
};
use crate::library::tpm2::hierarchy::is_hierarchy_auth_handle;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;
use crate::types::TpmResult;
pub(in crate::library::tpm2) const TPM_CC_NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x0000_011f;
pub(in crate::library::tpm2) const TPM_CC_EVICT_CONTROL: u32 = 0x0000_0120;
pub(in crate::library::tpm2) const TPM_CC_HIERARCHY_CONTROL: u32 = 0x0000_0121;
pub(in crate::library::tpm2) const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
pub(in crate::library::tpm2) const TPM_CC_CHANGE_EPS: u32 = 0x0000_0124;
pub(in crate::library::tpm2) const TPM_CC_CHANGE_PPS: u32 = 0x0000_0125;
pub(in crate::library::tpm2) const TPM_CC_CLEAR: u32 = 0x0000_0126;
pub(in crate::library::tpm2) const TPM_CC_CLEAR_CONTROL: u32 = 0x0000_0127;
pub(in crate::library::tpm2) const TPM_CC_CLOCK_SET: u32 = 0x0000_0128;
pub(in crate::library::tpm2) const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;
pub(in crate::library::tpm2) const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012a;
pub(in crate::library::tpm2) const TPM_CC_PCR_ALLOCATE: u32 = 0x0000_012b;
pub(in crate::library::tpm2) const TPM_CC_PCR_SET_AUTH_POLICY: u32 = 0x0000_012c;
pub(in crate::library::tpm2) const TPM_CC_PP_COMMANDS: u32 = 0x0000_012d;
pub(in crate::library::tpm2) const TPM_CC_SET_PRIMARY_POLICY: u32 = 0x0000_012e;
pub(in crate::library::tpm2) const TPM_CC_CLOCK_RATE_ADJUST: u32 = 0x0000_0130;
pub(in crate::library::tpm2) const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub(in crate::library::tpm2) const TPM_CC_NV_GLOBAL_WRITE_LOCK: u32 = 0x0000_0132;
pub(in crate::library::tpm2) const TPM_CC_GET_COMMAND_AUDIT_DIGEST: u32 = 0x0000_0133;
pub(in crate::library::tpm2) const TPM_CC_NV_INCREMENT: u32 = 0x0000_0134;
pub(in crate::library::tpm2) const TPM_CC_NV_SET_BITS: u32 = 0x0000_0135;
pub(in crate::library::tpm2) const TPM_CC_NV_EXTEND: u32 = 0x0000_0136;
pub(in crate::library::tpm2) const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
pub(in crate::library::tpm2) const TPM_CC_NV_WRITE_LOCK: u32 = 0x0000_0138;
pub(in crate::library::tpm2) const TPM_CC_DICTIONARY_ATTACK_LOCK_RESET: u32 = 0x0000_0139;
pub(in crate::library::tpm2) const TPM_CC_DICTIONARY_ATTACK_PARAMETERS: u32 = 0x0000_013a;
pub(in crate::library::tpm2) const TPM_CC_NV_CHANGE_AUTH: u32 = 0x0000_013b;
pub(in crate::library::tpm2) const TPM_CC_PCR_EVENT: u32 = 0x0000_013c;
pub(in crate::library::tpm2) const TPM_CC_PCR_RESET: u32 = 0x0000_013d;
pub(in crate::library::tpm2) const TPM_CC_SEQUENCE_COMPLETE: u32 = 0x0000_013e;
pub(in crate::library::tpm2) const TPM_CC_SET_ALGORITHM_SET: u32 = 0x0000_013f;
pub(in crate::library::tpm2) const TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x0000_0140;
pub(in crate::library::tpm2) const TPM_CC_INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
pub(in crate::library::tpm2) const TPM_CC_SELF_TEST: u32 = 0x0000_0143;
pub(in crate::library::tpm2) const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub(in crate::library::tpm2) const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub(in crate::library::tpm2) const TPM_CC_STIR_RANDOM: u32 = 0x0000_0146;
pub(in crate::library::tpm2) const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
pub(in crate::library::tpm2) const TPM_CC_CERTIFY: u32 = 0x0000_0148;
pub(in crate::library::tpm2) const TPM_CC_POLICY_NV: u32 = 0x0000_0149;
pub(in crate::library::tpm2) const TPM_CC_CERTIFY_CREATION: u32 = 0x0000_014a;
pub(in crate::library::tpm2) const TPM_CC_DUPLICATE: u32 = 0x0000_014b;
pub(in crate::library::tpm2) const TPM_CC_GET_TIME: u32 = 0x0000_014c;
pub(in crate::library::tpm2) const TPM_CC_GET_SESSION_AUDIT_DIGEST: u32 = 0x0000_014d;
pub(in crate::library::tpm2) const TPM_CC_NV_READ: u32 = 0x0000_014e;
pub(in crate::library::tpm2) const TPM_CC_NV_READ_LOCK: u32 = 0x0000_014f;
pub(in crate::library::tpm2) const TPM_CC_OBJECT_CHANGE_AUTH: u32 = 0x0000_0150;
pub(in crate::library::tpm2) const TPM_CC_POLICY_SECRET: u32 = 0x0000_0151;
pub(in crate::library::tpm2) const TPM_CC_REWRAP: u32 = 0x0000_0152;
pub(in crate::library::tpm2) const TPM_CC_CREATE: u32 = 0x0000_0153;
pub(in crate::library::tpm2) const TPM_CC_ECDH_ZGEN: u32 = 0x0000_0154;
pub(in crate::library::tpm2) const TPM_CC_HMAC: u32 = 0x0000_0155;
pub(in crate::library::tpm2) const TPM_CC_IMPORT: u32 = 0x0000_0156;
pub(in crate::library::tpm2) const TPM_CC_LOAD: u32 = 0x0000_0157;
pub(in crate::library::tpm2) const TPM_CC_QUOTE: u32 = 0x0000_0158;
pub(in crate::library::tpm2) const TPM_CC_RSA_DECRYPT: u32 = 0x0000_0159;
pub(in crate::library::tpm2) const TPM_CC_HMAC_START: u32 = 0x0000_015b;
pub(in crate::library::tpm2) const TPM_CC_SEQUENCE_UPDATE: u32 = 0x0000_015c;
pub(in crate::library::tpm2) const TPM_CC_SIGN: u32 = 0x0000_015d;
pub(in crate::library::tpm2) const TPM_CC_UNSEAL: u32 = 0x0000_015e;
pub(in crate::library::tpm2) const TPM_CC_POLICY_SIGNED: u32 = 0x0000_0160;
pub(in crate::library::tpm2) const TPM_CC_CONTEXT_LOAD: u32 = 0x0000_0161;
pub(in crate::library::tpm2) const TPM_CC_CONTEXT_SAVE: u32 = 0x0000_0162;
pub(in crate::library::tpm2) const TPM_CC_ECDH_KEY_GEN: u32 = 0x0000_0163;
pub(in crate::library::tpm2) const TPM_CC_ENCRYPT_DECRYPT: u32 = 0x0000_0164;
pub(in crate::library::tpm2) const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub(in crate::library::tpm2) const TPM_CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
pub(in crate::library::tpm2) const TPM_CC_MAKE_CREDENTIAL: u32 = 0x0000_0168;
pub(in crate::library::tpm2) const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub(in crate::library::tpm2) const TPM_CC_POLICY_AUTHORIZE: u32 = 0x0000_016a;
pub(in crate::library::tpm2) const TPM_CC_POLICY_AUTH_VALUE: u32 = 0x0000_016b;
pub(in crate::library::tpm2) const TPM_CC_POLICY_COMMAND_CODE: u32 = 0x0000_016c;
pub(in crate::library::tpm2) const TPM_CC_POLICY_COUNTER_TIMER: u32 = 0x0000_016d;
pub(in crate::library::tpm2) const TPM_CC_POLICY_CP_HASH: u32 = 0x0000_016e;
pub(in crate::library::tpm2) const TPM_CC_POLICY_LOCALITY: u32 = 0x0000_016f;
pub(in crate::library::tpm2) const TPM_CC_POLICY_NAME_HASH: u32 = 0x0000_0170;
pub(in crate::library::tpm2) const TPM_CC_POLICY_OR: u32 = 0x0000_0171;
pub(in crate::library::tpm2) const TPM_CC_POLICY_TICKET: u32 = 0x0000_0172;
pub(in crate::library::tpm2) const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
pub(in crate::library::tpm2) const TPM_CC_RSA_ENCRYPT: u32 = 0x0000_0174;
pub(in crate::library::tpm2) const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub(in crate::library::tpm2) const TPM_CC_VERIFY_SIGNATURE: u32 = 0x0000_0177;
pub(in crate::library::tpm2) const TPM_CC_ECC_PARAMETERS: u32 = 0x0000_0178;
pub(in crate::library::tpm2) const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;
pub(in crate::library::tpm2) const TPM_CC_GET_RANDOM: u32 = 0x0000_017b;
pub(in crate::library::tpm2) const TPM_CC_GET_TEST_RESULT: u32 = 0x0000_017c;
pub(in crate::library::tpm2) const TPM_CC_HASH: u32 = 0x0000_017d;
pub(in crate::library::tpm2) const TPM_CC_PCR_READ: u32 = 0x0000_017e;
pub(in crate::library::tpm2) const TPM_CC_POLICY_PCR: u32 = 0x0000_017f;
pub(in crate::library::tpm2) const TPM_CC_POLICY_RESTART: u32 = 0x0000_0180;
pub(in crate::library::tpm2) const TPM_CC_READ_CLOCK: u32 = 0x0000_0181;
pub(in crate::library::tpm2) const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub(in crate::library::tpm2) const TPM_CC_PCR_SET_AUTH_VALUE: u32 = 0x0000_0183;
pub(in crate::library::tpm2) const TPM_CC_NV_CERTIFY: u32 = 0x0000_0184;
pub(in crate::library::tpm2) const TPM_CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x0000_0185;
pub(in crate::library::tpm2) const TPM_CC_HASH_SEQUENCE_START: u32 = 0x0000_0186;
pub(in crate::library::tpm2) const TPM_CC_POLICY_PHYSICAL_PRESENCE: u32 = 0x0000_0187;
pub(in crate::library::tpm2) const TPM_CC_POLICY_DUPLICATION_SELECT: u32 = 0x0000_0188;
pub(in crate::library::tpm2) const TPM_CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;
pub(in crate::library::tpm2) const TPM_CC_TEST_PARMS: u32 = 0x0000_018a;
pub(in crate::library::tpm2) const TPM_CC_COMMIT: u32 = 0x0000_018b;
pub(in crate::library::tpm2) const TPM_CC_POLICY_PASSWORD: u32 = 0x0000_018c;
pub(in crate::library::tpm2) const TPM_CC_ZGEN_2_PHASE: u32 = 0x0000_018d;
pub(in crate::library::tpm2) const TPM_CC_EC_EPHEMERAL: u32 = 0x0000_018e;
pub(in crate::library::tpm2) const TPM_CC_POLICY_NV_WRITTEN: u32 = 0x0000_018f;
pub(in crate::library::tpm2) const TPM_CC_POLICY_TEMPLATE: u32 = 0x0000_0190;
pub(in crate::library::tpm2) const TPM_CC_CREATE_LOADED: u32 = 0x0000_0191;
pub(in crate::library::tpm2) const TPM_CC_POLICY_AUTHORIZE_NV: u32 = 0x0000_0192;
pub(in crate::library::tpm2) const TPM_CC_ENCRYPT_DECRYPT2: u32 = 0x0000_0193;
pub(in crate::library::tpm2) const TPM_CC_CERTIFY_X509: u32 = 0x0000_0197;
pub(in crate::library::tpm2) const TPM_CC_ECC_ENCRYPT: u32 = 0x0000_0199;
pub(in crate::library::tpm2) const TPM_CC_ECC_DECRYPT: u32 = 0x0000_019a;
pub(in crate::library::tpm2) const TPM_CC_POLICY_CAPABILITY: u32 = 0x0000_019b;
pub(in crate::library::tpm2) const TPM_CC_POLICY_PARAMETERS: u32 = 0x0000_019c;

pub(in crate::library::tpm2::command) use crate::library::tpm2::hierarchy::TPM_RH_NULL;
use crate::library::tpm2::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM, is_hierarchy_handle,
};
use crate::library::tpm2::nv::is_nv_index_handle;
use crate::library::tpm2::object_create::is_object_handle;
use crate::library::tpm2::session::{
    is_hmac_session_handle, is_policy_session_handle, is_session_handle,
};

const TPMA_CC_COMMAND_INDEX_MASK: u32 = 0x0000_ffff;
const TPMA_CC_NV: u32 = 1 << 22;
const TPMA_CC_EXTENSIVE: u32 = 1 << 23;
const TPMA_CC_FLUSHED: u32 = 1 << 24;
const TPMA_CC_C_HANDLES_SHIFT: u32 = 25;
const TPMA_CC_R_HANDLE: u32 = 1 << 28;

const fn tpma_cc(code: u32, nv: bool, command_handles: u32) -> u32 {
    (code & TPMA_CC_COMMAND_INDEX_MASK)
        | if nv { TPMA_CC_NV } else { 0 }
        | (command_handles << TPMA_CC_C_HANDLES_SHIFT)
}

const fn tpma_cc_with_response_handle(code: u32, nv: bool, command_handles: u32) -> u32 {
    tpma_cc(code, nv, command_handles) | TPMA_CC_R_HANDLE
}

const fn tpma_cc_flushed(code: u32, nv: bool, command_handles: u32) -> u32 {
    tpma_cc(code, nv, command_handles) | TPMA_CC_FLUSHED
}

pub(in crate::library::tpm2::command) type CommandHandler =
    for<'a> fn(&mut Tpm2Runtime, &CommandFrame<'a>) -> Result<CommandOutput, TpmResult>;

#[derive(Clone, Copy)]
pub(in crate::library::tpm2::command) enum CommandLifecycle {
    RequiresNotStarted,
    RequiresStarted,
}

impl CommandLifecycle {
    pub(in crate::library::tpm2::command) fn allows(self, runtime: &Tpm2Runtime) -> bool {
        match self {
            Self::RequiresNotStarted => !runtime.startup_received,
            Self::RequiresStarted => runtime.startup_received,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::library::tpm2::command) enum HandleKind {
    HierarchyAuth,
    Hierarchy,
    BaseHierarchy,
    Clear,
    Endorsement,
    Lockout,
    Platform,
    Provision,
    Object,
    ObjectAllowNull,
    Context,
    Parent,
    Pcr,
    PcrAllowNull,
    NvIndex,
    NvAuth,
    Entity,
    EntityAllowNull,
    PolicySession,
    HmacSession,
}

const TPM_RH_AUTH_00: u32 = 0x4000_0010;
const TPM_RH_AUTH_FF: u32 = 0x4000_010f;

impl HandleKind {
    pub(in crate::library::tpm2::command) fn accepts(self, handle: u32) -> bool {
        match self {
            Self::HierarchyAuth => is_hierarchy_auth_handle(handle),
            Self::Hierarchy => is_hierarchy_handle(handle),
            Self::BaseHierarchy => {
                matches!(handle, TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM)
            }
            Self::Clear => matches!(handle, TPM_RH_LOCKOUT | TPM_RH_PLATFORM),
            Self::Endorsement => handle == TPM_RH_ENDORSEMENT,
            Self::Lockout => handle == TPM_RH_LOCKOUT,
            Self::Platform => handle == TPM_RH_PLATFORM,
            Self::Provision => matches!(handle, TPM_RH_OWNER | TPM_RH_PLATFORM),
            Self::Object => is_object_handle(handle),
            Self::ObjectAllowNull => is_object_handle(handle) || handle == TPM_RH_NULL,
            Self::Context => {
                crate::library::tpm2::object_create::is_transient_object_handle(handle)
                    || is_session_handle(handle)
            }
            Self::Parent => is_hierarchy_handle(handle) || is_object_handle(handle),
            Self::Pcr => (handle as usize) < IMPLEMENTATION_PCR,
            Self::PcrAllowNull => (handle as usize) < IMPLEMENTATION_PCR || handle == TPM_RH_NULL,
            Self::NvIndex => is_nv_index_handle(handle),
            Self::NvAuth => {
                matches!(handle, TPM_RH_OWNER | TPM_RH_PLATFORM) || is_nv_index_handle(handle)
            }
            Self::Entity => {
                matches!(
                    handle,
                    TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM | TPM_RH_LOCKOUT
                ) || is_object_handle(handle)
                    || is_nv_index_handle(handle)
                    || (handle as usize) < IMPLEMENTATION_PCR
                    || (TPM_RH_AUTH_00..=TPM_RH_AUTH_FF).contains(&handle)
            }
            Self::EntityAllowNull => Self::Entity.accepts(handle) || handle == TPM_RH_NULL,
            Self::PolicySession => is_policy_session_handle(handle),
            Self::HmacSession => is_hmac_session_handle(handle),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::library::tpm2::command) enum AuthRole {
    User,
    Admin,
    Dup,
}

pub(in crate::library::tpm2::command) struct HandleSpec {
    pub(in crate::library::tpm2::command) kind: HandleKind,
    pub(in crate::library::tpm2::command) user_auth: bool,
    pub(in crate::library::tpm2::command) role: AuthRole,
}

impl HandleSpec {
    pub(in crate::library::tpm2::command) fn admin_role(&self) -> bool {
        self.role == AuthRole::Admin
    }

    pub(in crate::library::tpm2::command) fn policy_only_role(&self) -> bool {
        matches!(self.role, AuthRole::Admin | AuthRole::Dup)
    }

    pub(in crate::library::tpm2::command) fn dup_role(&self) -> bool {
        self.role == AuthRole::Dup
    }
}

const POLICY_SESSION_HANDLE: HandleSpec = HandleSpec {
    kind: HandleKind::PolicySession,
    user_auth: false,
    role: AuthRole::User,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::library::tpm2::command) enum NvAccess {
    Neither,
    Read,
    Write,
}

pub(in crate::library::tpm2) struct CommandDescriptor {
    pub(in crate::library::tpm2) code: u32,
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) physical_presence: bool,
    pub(in crate::library::tpm2) physical_presence_required: bool,
    pub(in crate::library::tpm2::command) lifecycle: CommandLifecycle,
    pub(in crate::library::tpm2::command) handles: &'static [HandleSpec],
    pub(in crate::library::tpm2::command) decrypt_size: u16,
    pub(in crate::library::tpm2::command) encrypt_size: u16,
    pub(in crate::library::tpm2::command) sessions_allowed: bool,
    pub(in crate::library::tpm2::command) nv_access: NvAccess,
    pub(in crate::library::tpm2::command) handler: CommandHandler,
}

static COMMANDS: &[CommandDescriptor] = &[
    CommandDescriptor {
        code: TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
        attributes: tpma_cc(TPM_CC_NV_UNDEFINE_SPACE_SPECIAL, true, 2),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: true,
                role: AuthRole::Admin,
            },
            HandleSpec {
                kind: HandleKind::Platform,
                user_auth: true,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv::undefine_space::execute_special,
    },
    CommandDescriptor {
        code: TPM_CC_EVICT_CONTROL,
        attributes: tpma_cc(TPM_CC_EVICT_CONTROL, true, 2),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Provision,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::evict_control::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HIERARCHY_CONTROL,
        attributes: tpma_cc(TPM_CC_HIERARCHY_CONTROL, true, 1) | TPMA_CC_EXTENSIVE,
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::BaseHierarchy,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::control::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_UNDEFINE_SPACE,
        attributes: tpma_cc(TPM_CC_NV_UNDEFINE_SPACE, true, 2),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Provision,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv::undefine_space::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CHANGE_EPS,
        attributes: tpma_cc(TPM_CC_CHANGE_EPS, true, 1) | TPMA_CC_EXTENSIVE,
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Platform,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::change_eps::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CHANGE_PPS,
        attributes: tpma_cc(TPM_CC_CHANGE_PPS, true, 1) | TPMA_CC_EXTENSIVE,
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Platform,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::change_pps::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CLEAR,
        attributes: tpma_cc(TPM_CC_CLEAR, true, 1) | TPMA_CC_EXTENSIVE,
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Clear,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::clear::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CLEAR_CONTROL,
        attributes: tpma_cc(TPM_CC_CLEAR_CONTROL, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Clear,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::clear_control::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CLOCK_SET,
        attributes: tpma_cc(TPM_CC_CLOCK_SET, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Provision,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: platform::clock::execute_clock_set,
    },
    CommandDescriptor {
        code: TPM_CC_HIERARCHY_CHANGE_AUTH,
        attributes: tpma_cc(TPM_CC_HIERARCHY_CHANGE_AUTH, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::HierarchyAuth,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::change_auth::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_DEFINE_SPACE,
        attributes: tpma_cc(TPM_CC_NV_DEFINE_SPACE, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Provision,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv::define_space::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_ALLOCATE,
        attributes: tpma_cc(TPM_CC_PCR_ALLOCATE, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Platform,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr::allocate::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_SET_AUTH_POLICY,
        attributes: tpma_cc(TPM_CC_PCR_SET_AUTH_POLICY, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Platform,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::pcr_policy::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PP_COMMANDS,
        attributes: tpma_cc(TPM_CC_PP_COMMANDS, true, 1),
        physical_presence: false,
        physical_presence_required: true,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Platform,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: platform::pp_commands::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SET_PRIMARY_POLICY,
        attributes: tpma_cc(TPM_CC_SET_PRIMARY_POLICY, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::HierarchyAuth,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::primary_policy::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CLOCK_RATE_ADJUST,
        attributes: tpma_cc(TPM_CC_CLOCK_RATE_ADJUST, false, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Provision,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: platform::clock::execute_clock_rate_adjust,
    },
    CommandDescriptor {
        code: TPM_CC_CREATE_PRIMARY,
        attributes: tpma_cc_with_response_handle(TPM_CC_CREATE_PRIMARY, false, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Hierarchy,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::create_primary::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_GLOBAL_WRITE_LOCK,
        attributes: tpma_cc(TPM_CC_NV_GLOBAL_WRITE_LOCK, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Provision,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv::lock::execute_global_write_lock,
    },
    CommandDescriptor {
        code: TPM_CC_GET_COMMAND_AUDIT_DIGEST,
        attributes: tpma_cc(TPM_CC_GET_COMMAND_AUDIT_DIGEST, true, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Endorsement,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: true,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: attestation::get_command_audit_digest::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_INCREMENT,
        attributes: tpma_cc(TPM_CC_NV_INCREMENT, true, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Write,
        handler: nv::write::execute_increment,
    },
    CommandDescriptor {
        code: TPM_CC_NV_SET_BITS,
        attributes: tpma_cc(TPM_CC_NV_SET_BITS, true, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Write,
        handler: nv::write::execute_set_bits,
    },
    CommandDescriptor {
        code: TPM_CC_NV_EXTEND,
        attributes: tpma_cc(TPM_CC_NV_EXTEND, true, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Write,
        handler: nv::write::execute_extend,
    },
    CommandDescriptor {
        code: TPM_CC_NV_WRITE,
        attributes: tpma_cc(TPM_CC_NV_WRITE, true, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Write,
        handler: nv::write::execute_write,
    },
    CommandDescriptor {
        code: TPM_CC_NV_WRITE_LOCK,
        attributes: tpma_cc(TPM_CC_NV_WRITE_LOCK, true, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Write,
        handler: nv::lock::execute_write_lock,
    },
    CommandDescriptor {
        code: TPM_CC_DICTIONARY_ATTACK_LOCK_RESET,
        attributes: tpma_cc(TPM_CC_DICTIONARY_ATTACK_LOCK_RESET, true, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Lockout,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hierarchy::lock_reset::execute,
    },
    CommandDescriptor {
        code: TPM_CC_DICTIONARY_ATTACK_PARAMETERS,
        attributes: tpma_cc(TPM_CC_DICTIONARY_ATTACK_PARAMETERS, true, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Lockout,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: administration::dictionary_attack_parameters::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_CHANGE_AUTH,
        attributes: tpma_cc(TPM_CC_NV_CHANGE_AUTH, true, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::NvIndex,
            user_auth: true,
            role: AuthRole::Admin,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv::change_auth::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_EVENT,
        attributes: tpma_cc(TPM_CC_PCR_EVENT, true, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::PcrAllowNull,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr::event::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_RESET,
        attributes: tpma_cc(TPM_CC_PCR_RESET, true, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Pcr,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr::reset::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SEQUENCE_COMPLETE,
        attributes: tpma_cc_flushed(TPM_CC_SEQUENCE_COMPLETE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::sequence::complete::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SET_ALGORITHM_SET,
        attributes: tpma_cc(TPM_CC_SET_ALGORITHM_SET, true, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Platform,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: platform::algorithm_set::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
        attributes: tpma_cc(TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS, true, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Provision,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: administration::set_command_code_audit_status::execute,
    },
    CommandDescriptor {
        code: TPM_CC_INCREMENTAL_SELF_TEST,
        attributes: tpma_cc(TPM_CC_INCREMENTAL_SELF_TEST, true, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: lifecycle::incremental_self_test::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SELF_TEST,
        attributes: tpma_cc(TPM_CC_SELF_TEST, true, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: lifecycle::self_test::execute,
    },
    CommandDescriptor {
        code: TPM_CC_STARTUP,
        attributes: tpma_cc(TPM_CC_STARTUP, true, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresNotStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: false,
        nv_access: NvAccess::Neither,
        handler: lifecycle::startup::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SHUTDOWN,
        attributes: tpma_cc(TPM_CC_SHUTDOWN, true, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: lifecycle::shutdown::execute,
    },
    CommandDescriptor {
        code: TPM_CC_STIR_RANDOM,
        attributes: tpma_cc(TPM_CC_STIR_RANDOM, true, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::stir_random::execute,
    },
    CommandDescriptor {
        code: TPM_CC_ACTIVATE_CREDENTIAL,
        attributes: tpma_cc(TPM_CC_ACTIVATE_CREDENTIAL, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: true,
                role: AuthRole::Admin,
            },
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: true,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::credential::execute_activate_credential,
    },
    CommandDescriptor {
        code: TPM_CC_CERTIFY,
        attributes: tpma_cc(TPM_CC_CERTIFY, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: true,
                role: AuthRole::Admin,
            },
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: true,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: attestation::certify::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_NV,
        attributes: tpma_cc(TPM_CC_POLICY_NV, false, 3),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
            POLICY_SESSION_HANDLE,
        ],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::operand::execute_nv,
    },
    CommandDescriptor {
        code: TPM_CC_CERTIFY_CREATION,
        attributes: tpma_cc(TPM_CC_CERTIFY_CREATION, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: attestation::certify_creation::execute,
    },
    CommandDescriptor {
        code: TPM_CC_DUPLICATE,
        attributes: tpma_cc(TPM_CC_DUPLICATE, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: true,
                role: AuthRole::Dup,
            },
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::duplication::execute_duplicate,
    },
    CommandDescriptor {
        code: TPM_CC_GET_TIME,
        attributes: tpma_cc(TPM_CC_GET_TIME, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Endorsement,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: true,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: attestation::get_time::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_SESSION_AUDIT_DIGEST,
        attributes: tpma_cc(TPM_CC_GET_SESSION_AUDIT_DIGEST, false, 3),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Endorsement,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::HmacSession,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: attestation::get_session_audit_digest::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_READ,
        attributes: tpma_cc(TPM_CC_NV_READ, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Read,
        handler: nv::read::execute_read,
    },
    CommandDescriptor {
        code: TPM_CC_NV_READ_LOCK,
        attributes: tpma_cc(TPM_CC_NV_READ_LOCK, true, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Read,
        handler: nv::lock::execute_read_lock,
    },
    CommandDescriptor {
        code: TPM_CC_OBJECT_CHANGE_AUTH,
        attributes: tpma_cc(TPM_CC_OBJECT_CHANGE_AUTH, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: true,
                role: AuthRole::Admin,
            },
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::change_auth::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_SECRET,
        attributes: tpma_cc(TPM_CC_POLICY_SECRET, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Entity,
                user_auth: true,
                role: AuthRole::User,
            },
            POLICY_SESSION_HANDLE,
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::ticket::execute_secret,
    },
    CommandDescriptor {
        code: TPM_CC_REWRAP,
        attributes: tpma_cc(TPM_CC_REWRAP, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::duplication::execute_rewrap,
    },
    CommandDescriptor {
        code: TPM_CC_CREATE,
        attributes: tpma_cc(TPM_CC_CREATE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::create::execute,
    },
    CommandDescriptor {
        code: TPM_CC_ECDH_ZGEN,
        attributes: tpma_cc(TPM_CC_ECDH_ZGEN, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::ecc::key_exchange::execute_zgen,
    },
    CommandDescriptor {
        code: TPM_CC_HMAC,
        attributes: tpma_cc(TPM_CC_HMAC, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::hmac::execute,
    },
    CommandDescriptor {
        code: TPM_CC_IMPORT,
        attributes: tpma_cc(TPM_CC_IMPORT, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::duplication::execute_import,
    },
    CommandDescriptor {
        code: TPM_CC_LOAD,
        attributes: tpma_cc_with_response_handle(TPM_CC_LOAD, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::load::execute,
    },
    CommandDescriptor {
        code: TPM_CC_QUOTE,
        attributes: tpma_cc(TPM_CC_QUOTE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::ObjectAllowNull,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: attestation::quote::execute,
    },
    CommandDescriptor {
        code: TPM_CC_RSA_DECRYPT,
        attributes: tpma_cc(TPM_CC_RSA_DECRYPT, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::rsa::execute_decrypt,
    },
    CommandDescriptor {
        code: TPM_CC_HMAC_START,
        attributes: tpma_cc_with_response_handle(TPM_CC_HMAC_START, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::sequence::hmac_start::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SEQUENCE_UPDATE,
        attributes: tpma_cc(TPM_CC_SEQUENCE_UPDATE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::sequence::update::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SIGN,
        attributes: tpma_cc(TPM_CC_SIGN, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::sign::execute,
    },
    CommandDescriptor {
        code: TPM_CC_UNSEAL,
        attributes: tpma_cc(TPM_CC_UNSEAL, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::unseal::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_SIGNED,
        attributes: tpma_cc(TPM_CC_POLICY_SIGNED, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: false,
                role: AuthRole::User,
            },
            POLICY_SESSION_HANDLE,
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::ticket::execute_signed,
    },
    CommandDescriptor {
        code: TPM_CC_CONTEXT_LOAD,
        attributes: tpma_cc_with_response_handle(TPM_CC_CONTEXT_LOAD, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: false,
        nv_access: NvAccess::Neither,
        handler: context::load_save::execute_load,
    },
    CommandDescriptor {
        code: TPM_CC_CONTEXT_SAVE,
        attributes: tpma_cc(TPM_CC_CONTEXT_SAVE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Context,
            user_auth: false,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: false,
        nv_access: NvAccess::Neither,
        handler: context::load_save::execute_save,
    },
    CommandDescriptor {
        code: TPM_CC_ECDH_KEY_GEN,
        attributes: tpma_cc(TPM_CC_ECDH_KEY_GEN, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: false,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::ecc::key_exchange::execute_key_gen,
    },
    CommandDescriptor {
        code: TPM_CC_ENCRYPT_DECRYPT,
        attributes: tpma_cc(TPM_CC_ENCRYPT_DECRYPT, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::encrypt_decrypt::execute,
    },
    CommandDescriptor {
        code: TPM_CC_FLUSH_CONTEXT,
        attributes: tpma_cc(TPM_CC_FLUSH_CONTEXT, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: false,
        nv_access: NvAccess::Neither,
        handler: context::flush::execute,
    },
    CommandDescriptor {
        code: TPM_CC_LOAD_EXTERNAL,
        attributes: tpma_cc_with_response_handle(TPM_CC_LOAD_EXTERNAL, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::load::execute_external,
    },
    CommandDescriptor {
        code: TPM_CC_MAKE_CREDENTIAL,
        attributes: tpma_cc(TPM_CC_MAKE_CREDENTIAL, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: false,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::credential::execute_make_credential,
    },
    CommandDescriptor {
        code: TPM_CC_NV_READ_PUBLIC,
        attributes: tpma_cc(TPM_CC_NV_READ_PUBLIC, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::NvIndex,
            user_auth: false,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv::read::execute_read_public,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_AUTHORIZE,
        attributes: tpma_cc(TPM_CC_POLICY_AUTHORIZE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::authorize::execute_authorize,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_AUTH_VALUE,
        attributes: tpma_cc(TPM_CC_POLICY_AUTH_VALUE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::session_state::execute_auth_value,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_COMMAND_CODE,
        attributes: tpma_cc(TPM_CC_POLICY_COMMAND_CODE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::session_state::execute_command_code,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_COUNTER_TIMER,
        attributes: tpma_cc(TPM_CC_POLICY_COUNTER_TIMER, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::operand::execute_counter_timer,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_CP_HASH,
        attributes: tpma_cc(TPM_CC_POLICY_CP_HASH, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::restrictions::execute_cp_hash,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_LOCALITY,
        attributes: tpma_cc(TPM_CC_POLICY_LOCALITY, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::restrictions::execute_locality,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_NAME_HASH,
        attributes: tpma_cc(TPM_CC_POLICY_NAME_HASH, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::restrictions::execute_name_hash,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_OR,
        attributes: tpma_cc(TPM_CC_POLICY_OR, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::or::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_TICKET,
        attributes: tpma_cc(TPM_CC_POLICY_TICKET, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::ticket::execute_ticket,
    },
    CommandDescriptor {
        code: TPM_CC_READ_PUBLIC,
        attributes: tpma_cc(TPM_CC_READ_PUBLIC, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: false,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::read_public::execute,
    },
    CommandDescriptor {
        code: TPM_CC_RSA_ENCRYPT,
        attributes: tpma_cc(TPM_CC_RSA_ENCRYPT, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: false,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::rsa::execute_encrypt,
    },
    CommandDescriptor {
        code: TPM_CC_START_AUTH_SESSION,
        attributes: tpma_cc_with_response_handle(TPM_CC_START_AUTH_SESSION, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: false,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::EntityAllowNull,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: session::start::execute,
    },
    CommandDescriptor {
        code: TPM_CC_VERIFY_SIGNATURE,
        attributes: tpma_cc(TPM_CC_VERIFY_SIGNATURE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: false,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::verify_signature::execute,
    },
    CommandDescriptor {
        code: TPM_CC_ECC_PARAMETERS,
        attributes: tpma_cc(TPM_CC_ECC_PARAMETERS, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::ecc::parameters::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_CAPABILITY,
        attributes: tpma_cc(TPM_CC_GET_CAPABILITY, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: administration::get_capability::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_RANDOM,
        attributes: tpma_cc(TPM_CC_GET_RANDOM, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::get_random::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_TEST_RESULT,
        attributes: tpma_cc(TPM_CC_GET_TEST_RESULT, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: lifecycle::get_test_result::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HASH,
        attributes: tpma_cc(TPM_CC_HASH, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::hash::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_READ,
        attributes: tpma_cc(TPM_CC_PCR_READ, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr::read::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_PCR,
        attributes: tpma_cc(TPM_CC_POLICY_PCR, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::pcr::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_RESTART,
        attributes: tpma_cc(TPM_CC_POLICY_RESTART, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::session_state::execute_restart,
    },
    CommandDescriptor {
        code: TPM_CC_READ_CLOCK,
        attributes: tpma_cc(TPM_CC_READ_CLOCK, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: platform::clock::execute_read_clock,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_EXTEND,
        attributes: tpma_cc(TPM_CC_PCR_EXTEND, true, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::PcrAllowNull,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr::extend::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_SET_AUTH_VALUE,
        attributes: tpma_cc(TPM_CC_PCR_SET_AUTH_VALUE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Pcr,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: platform::pcr_auth_value::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_CERTIFY,
        attributes: tpma_cc(TPM_CC_NV_CERTIFY, false, 3),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::ObjectAllowNull,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Read,
        handler: attestation::nv_certify::execute,
    },
    CommandDescriptor {
        code: TPM_CC_EVENT_SEQUENCE_COMPLETE,
        attributes: tpma_cc_flushed(TPM_CC_EVENT_SEQUENCE_COMPLETE, true, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::PcrAllowNull,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: true,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::sequence::event_complete::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HASH_SEQUENCE_START,
        attributes: tpma_cc_with_response_handle(TPM_CC_HASH_SEQUENCE_START, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::sequence::hash_start::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_PHYSICAL_PRESENCE,
        attributes: tpma_cc(TPM_CC_POLICY_PHYSICAL_PRESENCE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::restrictions::execute_physical_presence,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_DUPLICATION_SELECT,
        attributes: tpma_cc(TPM_CC_POLICY_DUPLICATION_SELECT, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::restrictions::execute_duplication_select,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_GET_DIGEST,
        attributes: tpma_cc(TPM_CC_POLICY_GET_DIGEST, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::session_state::execute_get_digest,
    },
    CommandDescriptor {
        code: TPM_CC_TEST_PARMS,
        attributes: tpma_cc(TPM_CC_TEST_PARMS, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::test_parms::execute,
    },
    CommandDescriptor {
        code: TPM_CC_COMMIT,
        attributes: tpma_cc(TPM_CC_COMMIT, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::ecc::commitment::execute_commit,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_PASSWORD,
        attributes: tpma_cc(TPM_CC_POLICY_PASSWORD, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::session_state::execute_password,
    },
    CommandDescriptor {
        code: TPM_CC_ZGEN_2_PHASE,
        attributes: tpma_cc(TPM_CC_ZGEN_2_PHASE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::ecc::key_exchange::execute_two_phase,
    },
    CommandDescriptor {
        code: TPM_CC_EC_EPHEMERAL,
        attributes: tpma_cc(TPM_CC_EC_EPHEMERAL, false, 0),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::ecc::commitment::execute_ephemeral,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_NV_WRITTEN,
        attributes: tpma_cc(TPM_CC_POLICY_NV_WRITTEN, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::restrictions::execute_nv_written,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_TEMPLATE,
        attributes: tpma_cc(TPM_CC_POLICY_TEMPLATE, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::restrictions::execute_template,
    },
    CommandDescriptor {
        code: TPM_CC_CREATE_LOADED,
        attributes: tpma_cc_with_response_handle(TPM_CC_CREATE_LOADED, false, 1),
        physical_presence: true,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Parent,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: object::create_loaded::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_AUTHORIZE_NV,
        attributes: tpma_cc(TPM_CC_POLICY_AUTHORIZE_NV, false, 3),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                role: AuthRole::User,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                role: AuthRole::User,
            },
            POLICY_SESSION_HANDLE,
        ],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::authorize::execute_authorize_nv,
    },
    CommandDescriptor {
        code: TPM_CC_ENCRYPT_DECRYPT2,
        attributes: tpma_cc(TPM_CC_ENCRYPT_DECRYPT2, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::encrypt_decrypt::execute_two,
    },
    CommandDescriptor {
        code: TPM_CC_CERTIFY_X509,
        attributes: tpma_cc(TPM_CC_CERTIFY_X509, false, 2),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: true,
                role: AuthRole::Admin,
            },
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: true,
                role: AuthRole::User,
            },
        ],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: attestation::certify_x509::execute,
    },
    CommandDescriptor {
        code: TPM_CC_ECC_ENCRYPT,
        attributes: tpma_cc(TPM_CC_ECC_ENCRYPT, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: false,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::ecc::encryption::execute_encrypt,
    },
    CommandDescriptor {
        code: TPM_CC_ECC_DECRYPT,
        attributes: tpma_cc(TPM_CC_ECC_DECRYPT, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Object,
            user_auth: true,
            role: AuthRole::User,
        }],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: crypto::ecc::encryption::execute_decrypt,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_CAPABILITY,
        attributes: tpma_cc(TPM_CC_POLICY_CAPABILITY, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::operand::execute_capability,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_PARAMETERS,
        attributes: tpma_cc(TPM_CC_POLICY_PARAMETERS, false, 1),
        physical_presence: false,
        physical_presence_required: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy::restrictions::execute_parameters,
    },
];

pub(in crate::library::tpm2) fn find(code: u32) -> Option<&'static CommandDescriptor> {
    COMMANDS
        .binary_search_by(|descriptor| descriptor.code.cmp(&code))
        .ok()
        .map(|index| &COMMANDS[index])
}

pub(in crate::library::tpm2) fn implemented() -> impl Iterator<Item = &'static CommandDescriptor> {
    COMMANDS.iter()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::cancel::CancellationToken;
    use crate::library::constants::{TPM_RC_COMMAND_CODE, TPM_RC_INITIALIZE};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::parse_command;
    use crate::library::tpm2::runtime::empty_state_runtime;

    const TPMA_CC_RESERVED: u32 = 0x003f_0000 | 0xc000_0000;

    #[test]
    fn registry_implemented_command_coverage() {
        assert_eq!(implemented().count(), 114);
    }

    #[test]
    fn registry_strict_sort_order() {
        let codes: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        assert!(
            codes.windows(2).all(|pair| pair[0] < pair[1]),
            "descriptors must be strictly ascending: {codes:#x?}"
        );
    }

    #[test]
    fn registry_command_code_uniqueness() {
        let codes: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        for (index, &code) in codes.iter().enumerate() {
            assert!(
                !codes[index + 1..].contains(&code),
                "duplicate command code {code:#x}"
            );
        }
    }

    #[test]
    fn registered_command_lookup_coverage() {
        for descriptor in implemented() {
            assert_eq!(
                find(descriptor.code).map(|found| found.code),
                Some(descriptor.code),
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn unregistered_command_code_lookup_rejection() {
        assert!(find(0x0000_0000).is_none(), "below all entries");
        assert!(
            find(TPM_CC_NV_UNDEFINE_SPACE_SPECIAL - 1).is_none(),
            "just below the first"
        );
        assert!(find(0xffff_ffff).is_none(), "above all entries");
        assert!(
            find(TPM_CC_POLICY_PARAMETERS + 1).is_none(),
            "just above the last"
        );
        let registered: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        for code in 0x0000_011eu32..=0x0000_019d {
            assert_eq!(
                find(code).is_some(),
                registered.contains(&code),
                "code {code:#010x}"
            );
        }
    }

    #[test]
    fn iteration_unique_implemented_command_coverage() {
        let codes: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        assert_eq!(
            codes,
            [
                TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
                TPM_CC_EVICT_CONTROL,
                TPM_CC_HIERARCHY_CONTROL,
                TPM_CC_NV_UNDEFINE_SPACE,
                TPM_CC_CHANGE_EPS,
                TPM_CC_CHANGE_PPS,
                TPM_CC_CLEAR,
                TPM_CC_CLEAR_CONTROL,
                TPM_CC_CLOCK_SET,
                TPM_CC_HIERARCHY_CHANGE_AUTH,
                TPM_CC_NV_DEFINE_SPACE,
                TPM_CC_PCR_ALLOCATE,
                TPM_CC_PCR_SET_AUTH_POLICY,
                TPM_CC_PP_COMMANDS,
                TPM_CC_SET_PRIMARY_POLICY,
                TPM_CC_CLOCK_RATE_ADJUST,
                TPM_CC_CREATE_PRIMARY,
                TPM_CC_NV_GLOBAL_WRITE_LOCK,
                TPM_CC_GET_COMMAND_AUDIT_DIGEST,
                TPM_CC_NV_INCREMENT,
                TPM_CC_NV_SET_BITS,
                TPM_CC_NV_EXTEND,
                TPM_CC_NV_WRITE,
                TPM_CC_NV_WRITE_LOCK,
                TPM_CC_DICTIONARY_ATTACK_LOCK_RESET,
                TPM_CC_DICTIONARY_ATTACK_PARAMETERS,
                TPM_CC_NV_CHANGE_AUTH,
                TPM_CC_PCR_EVENT,
                TPM_CC_PCR_RESET,
                TPM_CC_SEQUENCE_COMPLETE,
                TPM_CC_SET_ALGORITHM_SET,
                TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
                TPM_CC_INCREMENTAL_SELF_TEST,
                TPM_CC_SELF_TEST,
                TPM_CC_STARTUP,
                TPM_CC_SHUTDOWN,
                TPM_CC_STIR_RANDOM,
                TPM_CC_ACTIVATE_CREDENTIAL,
                TPM_CC_CERTIFY,
                TPM_CC_POLICY_NV,
                TPM_CC_CERTIFY_CREATION,
                TPM_CC_DUPLICATE,
                TPM_CC_GET_TIME,
                TPM_CC_GET_SESSION_AUDIT_DIGEST,
                TPM_CC_NV_READ,
                TPM_CC_NV_READ_LOCK,
                TPM_CC_OBJECT_CHANGE_AUTH,
                TPM_CC_POLICY_SECRET,
                TPM_CC_REWRAP,
                TPM_CC_CREATE,
                TPM_CC_ECDH_ZGEN,
                TPM_CC_HMAC,
                TPM_CC_IMPORT,
                TPM_CC_LOAD,
                TPM_CC_QUOTE,
                TPM_CC_RSA_DECRYPT,
                TPM_CC_HMAC_START,
                TPM_CC_SEQUENCE_UPDATE,
                TPM_CC_SIGN,
                TPM_CC_UNSEAL,
                TPM_CC_POLICY_SIGNED,
                TPM_CC_CONTEXT_LOAD,
                TPM_CC_CONTEXT_SAVE,
                TPM_CC_ECDH_KEY_GEN,
                TPM_CC_ENCRYPT_DECRYPT,
                TPM_CC_FLUSH_CONTEXT,
                TPM_CC_LOAD_EXTERNAL,
                TPM_CC_MAKE_CREDENTIAL,
                TPM_CC_NV_READ_PUBLIC,
                TPM_CC_POLICY_AUTHORIZE,
                TPM_CC_POLICY_AUTH_VALUE,
                TPM_CC_POLICY_COMMAND_CODE,
                TPM_CC_POLICY_COUNTER_TIMER,
                TPM_CC_POLICY_CP_HASH,
                TPM_CC_POLICY_LOCALITY,
                TPM_CC_POLICY_NAME_HASH,
                TPM_CC_POLICY_OR,
                TPM_CC_POLICY_TICKET,
                TPM_CC_READ_PUBLIC,
                TPM_CC_RSA_ENCRYPT,
                TPM_CC_START_AUTH_SESSION,
                TPM_CC_VERIFY_SIGNATURE,
                TPM_CC_ECC_PARAMETERS,
                TPM_CC_GET_CAPABILITY,
                TPM_CC_GET_RANDOM,
                TPM_CC_GET_TEST_RESULT,
                TPM_CC_HASH,
                TPM_CC_PCR_READ,
                TPM_CC_POLICY_PCR,
                TPM_CC_POLICY_RESTART,
                TPM_CC_READ_CLOCK,
                TPM_CC_PCR_EXTEND,
                TPM_CC_PCR_SET_AUTH_VALUE,
                TPM_CC_NV_CERTIFY,
                TPM_CC_EVENT_SEQUENCE_COMPLETE,
                TPM_CC_HASH_SEQUENCE_START,
                TPM_CC_POLICY_PHYSICAL_PRESENCE,
                TPM_CC_POLICY_DUPLICATION_SELECT,
                TPM_CC_POLICY_GET_DIGEST,
                TPM_CC_TEST_PARMS,
                TPM_CC_COMMIT,
                TPM_CC_POLICY_PASSWORD,
                TPM_CC_ZGEN_2_PHASE,
                TPM_CC_EC_EPHEMERAL,
                TPM_CC_POLICY_NV_WRITTEN,
                TPM_CC_POLICY_TEMPLATE,
                TPM_CC_CREATE_LOADED,
                TPM_CC_POLICY_AUTHORIZE_NV,
                TPM_CC_ENCRYPT_DECRYPT2,
                TPM_CC_CERTIFY_X509,
                TPM_CC_ECC_ENCRYPT,
                TPM_CC_ECC_DECRYPT,
                TPM_CC_POLICY_CAPABILITY,
                TPM_CC_POLICY_PARAMETERS
            ]
        );
    }

    #[test]
    fn extensive_commands_vendored_table_match() {
        const EXTENSIVE: [u32; 4] = [
            TPM_CC_HIERARCHY_CONTROL,
            TPM_CC_CHANGE_EPS,
            TPM_CC_CHANGE_PPS,
            TPM_CC_CLEAR,
        ];
        for descriptor in implemented() {
            assert_eq!(
                descriptor.attributes & TPMA_CC_EXTENSIVE != 0,
                EXTENSIVE.contains(&descriptor.code),
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn pcr_event_handle_kind_pcr_null_acceptance() {
        let kind = find(TPM_CC_PCR_EVENT).unwrap().handles[0].kind;
        for pcr in 0..IMPLEMENTATION_PCR as u32 {
            assert!(kind.accepts(pcr), "PCR {pcr}");
        }
        assert!(
            kind.accepts(TPM_RH_NULL),
            "upstream unmarshals with allowNull"
        );
        for handle in [
            IMPLEMENTATION_PCR as u32,
            0x0100_0000,
            0x8000_0000,
            TPM_RH_NULL - 1,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn exact_pcr_handle_kind_null_rejection() {
        let kind = find(TPM_CC_PCR_RESET).unwrap().handles[0].kind;
        for pcr in 0..24u32 {
            assert!(kind.accepts(pcr), "PCR {pcr}");
        }
        assert!(
            !kind.accepts(TPM_RH_NULL),
            "PCR_Reset unmarshals without allowNull"
        );
        for handle in [24u32, 0x0100_0000, 0x8000_0000, TPM_RH_NULL - 1, u32::MAX] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn physical_presence_applicability_vendored_table_parity() {
        const PP_COMMANDS: [u32; 19] = [
            TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
            TPM_CC_EVICT_CONTROL,
            TPM_CC_HIERARCHY_CONTROL,
            TPM_CC_NV_UNDEFINE_SPACE,
            TPM_CC_CHANGE_EPS,
            TPM_CC_CHANGE_PPS,
            TPM_CC_CLEAR,
            TPM_CC_CLEAR_CONTROL,
            TPM_CC_CLOCK_SET,
            TPM_CC_HIERARCHY_CHANGE_AUTH,
            TPM_CC_NV_DEFINE_SPACE,
            TPM_CC_PCR_ALLOCATE,
            TPM_CC_PCR_SET_AUTH_POLICY,
            TPM_CC_SET_PRIMARY_POLICY,
            TPM_CC_CLOCK_RATE_ADJUST,
            TPM_CC_CREATE_PRIMARY,
            TPM_CC_NV_GLOBAL_WRITE_LOCK,
            TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
            TPM_CC_CREATE_LOADED,
        ];
        for descriptor in implemented() {
            assert_eq!(
                descriptor.physical_presence,
                PP_COMMANDS.contains(&descriptor.code),
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn handle_count_attribute_declaration_match() {
        for descriptor in implemented() {
            assert_eq!(
                (descriptor.attributes >> 25) & 0x7,
                descriptor.handles.len() as u32,
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn authorization_area_prohibition_startup_and_flush_context_only() {
        for descriptor in implemented() {
            assert_eq!(
                descriptor.sessions_allowed,
                !matches!(
                    descriptor.code,
                    TPM_CC_STARTUP
                        | TPM_CC_CONTEXT_LOAD
                        | TPM_CC_CONTEXT_SAVE
                        | TPM_CC_FLUSH_CONTEXT
                ),
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn pcr_handle_kind_pcr_null_acceptance() {
        let kind = find(TPM_CC_PCR_EXTEND).unwrap().handles[0].kind;
        for pcr in 0..24u32 {
            assert!(kind.accepts(pcr), "PCR {pcr}");
        }
        assert!(
            kind.accepts(TPM_RH_NULL),
            "upstream unmarshals with allowNull"
        );
        for handle in [24u32, 0x0100_0000, 0x8000_0000, TPM_RH_NULL - 1, u32::MAX] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn attribute_command_index_command_code_mirroring() {
        for descriptor in implemented() {
            assert_eq!(
                descriptor.attributes & 0xffff,
                descriptor.code & 0xffff,
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn reserved_attribute_bits_zero() {
        for descriptor in implemented() {
            assert_eq!(
                descriptor.attributes & TPMA_CC_RESERVED,
                0,
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn startup_only_command_requiring_unstarted_tpm() {
        for descriptor in implemented() {
            assert_eq!(
                matches!(descriptor.lifecycle, CommandLifecycle::RequiresNotStarted),
                descriptor.code == TPM_CC_STARTUP,
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn physical_presence_requirement_pp_commands_only() {
        for descriptor in implemented() {
            assert_eq!(
                descriptor.physical_presence_required,
                descriptor.code == TPM_CC_PP_COMMANDS,
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[rustfmt::skip]
    const HANDLE_ACCEPTANCE: &[(u32, usize, &[u32], &[u32])] = {
        const RS_PW: u32 = 0x4000_0009;
        const PLATFORM_NV: u32 = 0x4000_000d;
        const ACT_0: u32 = 0x4000_0110;
        const PCR_END: u32 = IMPLEMENTATION_PCR as u32;
        &[
            (TPM_CC_EVICT_CONTROL, 0, &[TPM_RH_OWNER, TPM_RH_PLATFORM],
                &[TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, PLATFORM_NV, RS_PW, 0,
                  0x0100_0001, 0x8000_0000, 0x8100_0000, u32::MAX]),
            (TPM_CC_EVICT_CONTROL, 1, &[0x8000_0000, 0x8000_0002, 0x8100_0000, 0x81ff_ffff],
                &[0x7fff_ffff, 0x8000_0003, 0x80ff_ffff, 0x8200_0000, TPM_RH_OWNER, 0x0100_0001,
                  0x0200_0000, 0]),
            (TPM_CC_HIERARCHY_CONTROL, 0, &[TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM],
                &[TPM_RH_NULL, TPM_RH_LOCKOUT, PLATFORM_NV, RS_PW, 0, 23, 0x0100_0000, ACT_0,
                  0x8000_0000, 0x8100_0000, u32::MAX]),
            (TPM_CC_CLEAR_CONTROL, 0, &[TPM_RH_LOCKOUT, TPM_RH_PLATFORM],
                &[TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_NULL, PLATFORM_NV, RS_PW, 0, 23,
                  0x0100_0000, 0x8000_0000, u32::MAX]),
            (TPM_CC_HIERARCHY_CHANGE_AUTH, 0,
                &[TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM, TPM_RH_LOCKOUT],
                &[TPM_RH_NULL, 0, 23, PCR_END, 0x0100_0000, 0x0200_0000, 0x0300_0000,
                  0x4000_0000, 0x4000_0009, 0x4000_000d, 0x8000_0000, 0x8100_0000, u32::MAX]),
            (TPM_CC_NV_DEFINE_SPACE, 0, &[TPM_RH_OWNER, TPM_RH_PLATFORM],
                &[TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, 0x0100_0000, 0x8100_0000]),
            (TPM_CC_PCR_ALLOCATE, 0, &[TPM_RH_PLATFORM],
                &[TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, 0, 23, PCR_END,
                  0x0100_0000, 0x8000_0000, u32::MAX]),
            (TPM_CC_SET_PRIMARY_POLICY, 0,
                &[TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM, TPM_RH_LOCKOUT],
                &[TPM_RH_NULL, PLATFORM_NV, RS_PW, ACT_0, 0x4000_011f, 0, 0x0100_0000,
                  0x8000_0000, u32::MAX]),
            (TPM_CC_CREATE_PRIMARY, 0,
                &[TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, TPM_RH_NULL],
                &[0x4000_000a, 0x4000_0009, 0, 23, 0x8000_0000, u32::MAX]),
            (TPM_CC_NV_WRITE, 0, &[TPM_RH_OWNER, TPM_RH_PLATFORM, 0x0100_0000, 0x01ff_ffff],
                &[0x4000_0000, 0x4000_000b, 0x0200_0000, 0x8100_0000, 0]),
            (TPM_CC_DICTIONARY_ATTACK_PARAMETERS, 0, &[TPM_RH_LOCKOUT],
                &[TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM, TPM_RH_NULL, 0, 23, PCR_END,
                  0x0100_0000, 0x4000_0009, 0x8000_0000, u32::MAX]),
            (TPM_CC_CERTIFY, 0, &[], &[TPM_RH_NULL]),
            (TPM_CC_CERTIFY, 1, &[TPM_RH_NULL], &[]),
            (TPM_CC_GET_TIME, 0, &[TPM_RH_ENDORSEMENT],
                &[TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_NULL, 0x8000_0000]),
            (TPM_CC_GET_SESSION_AUDIT_DIGEST, 2, &[0x0200_0000, 0x0200_003f],
                &[0x0200_0040, 0x0300_0000, RS_PW, TPM_RH_NULL, 0]),
            (TPM_CC_CREATE, 0,
                &[0x8000_0000, 0x8000_0001, 0x8000_0002, 0x8100_0000, 0x81ff_ffff],
                &[0, 23, 0x0100_0000, TPM_RH_OWNER, TPM_RH_NULL, TPM_RH_ENDORSEMENT, 0x4000_0009,
                  0x8000_0003, 0x8200_0000, u32::MAX]),
            (TPM_CC_SIGN, 0, &[0x8000_0000, 0x8100_0000],
                &[TPM_RH_NULL, TPM_RH_OWNER, 0x0100_0001, 0x0200_0000]),
            (TPM_CC_CONTEXT_SAVE, 0, &[0x8000_0000, 0x8000_0002, 0x0200_0000, 0x0300_0000],
                &[0, 0x0100_0000, 0x8000_0003, 0x8100_0000, TPM_RH_OWNER, TPM_RH_NULL, u32::MAX]),
            (TPM_CC_NV_CERTIFY, 0, &[0x8000_0000, 0x8100_0000, TPM_RH_NULL],
                &[TPM_RH_OWNER, TPM_RH_ENDORSEMENT, 0x0100_0001, 0x0200_0000]),
            (TPM_CC_CERTIFY_X509, 0, &[], &[TPM_RH_NULL]),
            (TPM_CC_CERTIFY_X509, 1, &[], &[TPM_RH_NULL]),
        ]
    };

    #[test]
    fn handle_kind_acceptance_reference_table() {
        for &(code, index, accepted, rejected) in HANDLE_ACCEPTANCE {
            let descriptor = find(code).unwrap_or_else(|| panic!("{code:#06x} is registered"));
            let kind = descriptor.handles[index].kind;
            for &handle in accepted {
                assert!(
                    kind.accepts(handle),
                    "{code:#06x}: handle {index} accepts {handle:#010x}"
                );
            }
            for &handle in rejected {
                assert!(
                    !kind.accepts(handle),
                    "{code:#06x}: handle {index} refuses {handle:#010x}"
                );
            }
        }
    }

    mod metadata {
        use super::*;
        use Auth::{Absent, Admin, Dup, User};
        use HandleKind::*;
        use NvAccess::*;

        #[derive(Clone, Copy, Eq, PartialEq)]
        enum Auth {
            Absent,
            User,
            Admin,
            Dup,
        }

        impl Auth {
            fn role(self) -> AuthRole {
                match self {
                    Absent | User => AuthRole::User,
                    Admin => AuthRole::Admin,
                    Dup => AuthRole::Dup,
                }
            }
        }

        struct Expected {
            name: &'static str,
            code: u32,
            nv_access: Option<NvAccess>,
            parameter_sizes: (u16, u16),
            handles: &'static [(HandleKind, Auth)],
        }

        macro_rules! row {
            ($code:ident, $nv_access:expr, $parameter_sizes:expr, $handles:expr $(,)?) => {
                Expected {
                    name: stringify!($code),
                    code: $code,
                    nv_access: $nv_access,
                    parameter_sizes: $parameter_sizes,
                    handles: $handles,
                }
            };
        }

        #[rustfmt::skip]
        const METADATA: &[Expected] = &[
            row!(TPM_CC_NV_UNDEFINE_SPACE_SPECIAL, Some(Neither), (0, 0), &[
                (NvIndex, Admin),
                (Platform, User),
            ]),
            row!(TPM_CC_EVICT_CONTROL, None, (0, 0), &[(Provision, User), (Object, Absent)]),
            row!(TPM_CC_HIERARCHY_CONTROL, Some(Neither), (0, 0), &[(BaseHierarchy, User)]),
            row!(TPM_CC_NV_UNDEFINE_SPACE, Some(Neither), (0, 0), &[
                (Provision, User),
                (NvIndex, Absent),
            ]),
            row!(TPM_CC_CHANGE_EPS, None, (0, 0), &[(Platform, User)]),
            row!(TPM_CC_CHANGE_PPS, Some(Neither), (0, 0), &[(Platform, User)]),
            row!(TPM_CC_CLEAR, Some(Neither), (0, 0), &[(Clear, User)]),
            row!(TPM_CC_CLEAR_CONTROL, Some(Neither), (0, 0), &[(Clear, User)]),
            row!(TPM_CC_CLOCK_SET, Some(Neither), (0, 0), &[(Provision, User)]),
            row!(TPM_CC_HIERARCHY_CHANGE_AUTH, None, (2, 0), &[(HierarchyAuth, User)]),
            row!(TPM_CC_NV_DEFINE_SPACE, Some(Neither), (2, 0), &[(Provision, User)]),
            row!(TPM_CC_PCR_ALLOCATE, None, (0, 0), &[(Platform, User)]),
            row!(TPM_CC_PCR_SET_AUTH_POLICY, Some(Neither), (2, 0), &[(Platform, User)]),
            row!(TPM_CC_PP_COMMANDS, Some(Neither), (0, 0), &[(Platform, User)]),
            row!(TPM_CC_SET_PRIMARY_POLICY, Some(Neither), (2, 0), &[(HierarchyAuth, User)]),
            row!(TPM_CC_CLOCK_RATE_ADJUST, Some(Neither), (0, 0), &[(Provision, User)]),
            row!(TPM_CC_CREATE_PRIMARY, None, (2, 2), &[(Hierarchy, User)]),
            row!(TPM_CC_NV_GLOBAL_WRITE_LOCK, Some(Neither), (0, 0), &[(Provision, User)]),
            row!(TPM_CC_GET_COMMAND_AUDIT_DIGEST, Some(Neither), (2, 2), &[
                (Endorsement, User),
                (ObjectAllowNull, User),
            ]),
            row!(TPM_CC_NV_INCREMENT, Some(Write), (0, 0), &[(NvAuth, User), (NvIndex, Absent)]),
            row!(TPM_CC_NV_SET_BITS, Some(Write), (0, 0), &[(NvAuth, User), (NvIndex, Absent)]),
            row!(TPM_CC_NV_EXTEND, Some(Write), (2, 0), &[(NvAuth, User), (NvIndex, Absent)]),
            row!(TPM_CC_NV_WRITE, Some(Write), (2, 0), &[(NvAuth, User), (NvIndex, Absent)]),
            row!(TPM_CC_NV_WRITE_LOCK, Some(Write), (0, 0), &[
                (NvAuth, User),
                (NvIndex, Absent),
            ]),
            row!(TPM_CC_DICTIONARY_ATTACK_LOCK_RESET, Some(Neither), (0, 0), &[(Lockout, User)]),
            row!(TPM_CC_DICTIONARY_ATTACK_PARAMETERS, None, (0, 0), &[(Lockout, User)]),
            row!(TPM_CC_NV_CHANGE_AUTH, Some(Neither), (2, 0), &[(NvIndex, Admin)]),
            row!(TPM_CC_PCR_EVENT, Some(Neither), (2, 0), &[(PcrAllowNull, User)]),
            row!(TPM_CC_PCR_RESET, None, (0, 0), &[(Pcr, User)]),
            row!(TPM_CC_SEQUENCE_COMPLETE, None, (2, 2), &[(Object, User)]),
            row!(TPM_CC_SET_ALGORITHM_SET, Some(Neither), (0, 0), &[(Platform, User)]),
            row!(TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS, Some(Neither), (0, 0), &[
                (Provision, User),
            ]),
            row!(TPM_CC_INCREMENTAL_SELF_TEST, None, (0, 0), &[]),
            row!(TPM_CC_SELF_TEST, None, (0, 0), &[]),
            row!(TPM_CC_STARTUP, None, (0, 0), &[]),
            row!(TPM_CC_SHUTDOWN, None, (0, 0), &[]),
            row!(TPM_CC_STIR_RANDOM, None, (2, 0), &[]),
            row!(TPM_CC_ACTIVATE_CREDENTIAL, Some(Neither), (2, 2), &[
                (Object, Admin),
                (Object, User),
            ]),
            row!(TPM_CC_CERTIFY, Some(Neither), (2, 2), &[
                (Object, Admin),
                (ObjectAllowNull, User),
            ]),
            row!(TPM_CC_POLICY_NV, Some(Neither), (2, 0), &[
                (NvAuth, User),
                (NvIndex, Absent),
                (PolicySession, Absent),
            ]),
            row!(TPM_CC_CERTIFY_CREATION, Some(Neither), (2, 2), &[
                (ObjectAllowNull, User),
                (Object, Absent),
            ]),
            row!(TPM_CC_DUPLICATE, Some(Neither), (2, 2), &[
                (Object, Dup),
                (ObjectAllowNull, Absent),
            ]),
            row!(TPM_CC_GET_TIME, Some(Neither), (2, 2), &[
                (Endorsement, User),
                (ObjectAllowNull, User),
            ]),
            row!(TPM_CC_GET_SESSION_AUDIT_DIGEST, Some(Neither), (2, 2), &[
                (Endorsement, User),
                (ObjectAllowNull, User),
                (HmacSession, Absent),
            ]),
            row!(TPM_CC_NV_READ, Some(Read), (0, 2), &[(NvAuth, User), (NvIndex, Absent)]),
            row!(TPM_CC_NV_READ_LOCK, Some(Read), (0, 0), &[(NvAuth, User), (NvIndex, Absent)]),
            row!(TPM_CC_OBJECT_CHANGE_AUTH, Some(Neither), (2, 2), &[
                (Object, Admin),
                (Object, Absent),
            ]),
            row!(TPM_CC_POLICY_SECRET, Some(Neither), (2, 2), &[
                (Entity, User),
                (PolicySession, Absent),
            ]),
            row!(TPM_CC_REWRAP, Some(Neither), (2, 2), &[
                (ObjectAllowNull, User),
                (ObjectAllowNull, Absent),
            ]),
            row!(TPM_CC_CREATE, None, (2, 2), &[(Object, User)]),
            row!(TPM_CC_ECDH_ZGEN, Some(Neither), (2, 2), &[(Object, User)]),
            row!(TPM_CC_HMAC, Some(Neither), (2, 2), &[(Object, User)]),
            row!(TPM_CC_IMPORT, Some(Neither), (2, 2), &[(Object, User)]),
            row!(TPM_CC_LOAD, Some(Neither), (2, 2), &[(Object, User)]),
            row!(TPM_CC_QUOTE, Some(Neither), (2, 2), &[(ObjectAllowNull, User)]),
            row!(TPM_CC_RSA_DECRYPT, Some(Neither), (2, 2), &[(Object, User)]),
            row!(TPM_CC_HMAC_START, None, (2, 0), &[(Object, User)]),
            row!(TPM_CC_SEQUENCE_UPDATE, None, (2, 0), &[(Object, User)]),
            row!(TPM_CC_SIGN, Some(Neither), (2, 0), &[(Object, User)]),
            row!(TPM_CC_UNSEAL, Some(Neither), (0, 2), &[(Object, User)]),
            row!(TPM_CC_POLICY_SIGNED, Some(Neither), (2, 2), &[
                (Object, Absent),
                (PolicySession, Absent),
            ]),
            row!(TPM_CC_CONTEXT_LOAD, None, (0, 0), &[]),
            row!(TPM_CC_CONTEXT_SAVE, Some(Neither), (0, 0), &[(Context, Absent)]),
            row!(TPM_CC_ECDH_KEY_GEN, None, (0, 2), &[(Object, Absent)]),
            row!(TPM_CC_ENCRYPT_DECRYPT, Some(Neither), (0, 2), &[(Object, User)]),
            row!(TPM_CC_FLUSH_CONTEXT, None, (0, 0), &[]),
            row!(TPM_CC_LOAD_EXTERNAL, None, (2, 2), &[]),
            row!(TPM_CC_MAKE_CREDENTIAL, Some(Neither), (2, 2), &[(Object, Absent)]),
            row!(TPM_CC_NV_READ_PUBLIC, Some(Neither), (0, 2), &[(NvIndex, Absent)]),
            row!(TPM_CC_POLICY_AUTHORIZE, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_AUTH_VALUE, Some(Neither), (0, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_COMMAND_CODE, Some(Neither), (0, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_COUNTER_TIMER, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_CP_HASH, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_LOCALITY, Some(Neither), (0, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_NAME_HASH, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_OR, Some(Neither), (0, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_TICKET, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_READ_PUBLIC, Some(Neither), (0, 2), &[(Object, Absent)]),
            row!(TPM_CC_RSA_ENCRYPT, Some(Neither), (2, 2), &[(Object, Absent)]),
            row!(TPM_CC_START_AUTH_SESSION, Some(Neither), (2, 2), &[
                (ObjectAllowNull, Absent),
                (EntityAllowNull, Absent),
            ]),
            row!(TPM_CC_VERIFY_SIGNATURE, Some(Neither), (2, 0), &[(Object, Absent)]),
            row!(TPM_CC_ECC_PARAMETERS, Some(Neither), (0, 0), &[]),
            row!(TPM_CC_GET_CAPABILITY, None, (0, 0), &[]),
            row!(TPM_CC_GET_RANDOM, None, (0, 2), &[]),
            row!(TPM_CC_GET_TEST_RESULT, None, (0, 2), &[]),
            row!(TPM_CC_HASH, None, (2, 2), &[]),
            row!(TPM_CC_PCR_READ, None, (0, 0), &[]),
            row!(TPM_CC_POLICY_PCR, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_RESTART, Some(Neither), (0, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_READ_CLOCK, Some(Neither), (0, 0), &[]),
            row!(TPM_CC_PCR_EXTEND, None, (0, 0), &[(PcrAllowNull, User)]),
            row!(TPM_CC_PCR_SET_AUTH_VALUE, Some(Neither), (2, 0), &[(Pcr, User)]),
            row!(TPM_CC_NV_CERTIFY, Some(Read), (2, 2), &[
                (ObjectAllowNull, User),
                (NvAuth, User),
                (NvIndex, Absent),
            ]),
            row!(TPM_CC_EVENT_SEQUENCE_COMPLETE, None, (2, 0), &[
                (PcrAllowNull, User),
                (Object, User),
            ]),
            row!(TPM_CC_HASH_SEQUENCE_START, None, (2, 0), &[]),
            row!(TPM_CC_POLICY_PHYSICAL_PRESENCE, Some(Neither), (0, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_DUPLICATION_SELECT, Some(Neither), (2, 0), &[
                (PolicySession, Absent),
            ]),
            row!(TPM_CC_POLICY_GET_DIGEST, Some(Neither), (0, 2), &[(PolicySession, Absent)]),
            row!(TPM_CC_TEST_PARMS, Some(Neither), (0, 0), &[]),
            row!(TPM_CC_COMMIT, Some(Neither), (2, 2), &[(Object, User)]),
            row!(TPM_CC_POLICY_PASSWORD, Some(Neither), (0, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_ZGEN_2_PHASE, None, (2, 2), &[(Object, User)]),
            row!(TPM_CC_EC_EPHEMERAL, None, (0, 2), &[]),
            row!(TPM_CC_POLICY_NV_WRITTEN, Some(Neither), (0, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_TEMPLATE, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_CREATE_LOADED, None, (2, 2), &[(Parent, User)]),
            row!(TPM_CC_POLICY_AUTHORIZE_NV, Some(Neither), (0, 0), &[
                (NvAuth, User),
                (NvIndex, Absent),
                (PolicySession, Absent),
            ]),
            row!(TPM_CC_ENCRYPT_DECRYPT2, Some(Neither), (2, 2), &[(Object, User)]),
            row!(TPM_CC_CERTIFY_X509, Some(Neither), (2, 2), &[
                (Object, Admin),
                (Object, User),
            ]),
            row!(TPM_CC_ECC_ENCRYPT, Some(Neither), (2, 2), &[(Object, Absent)]),
            row!(TPM_CC_ECC_DECRYPT, None, (2, 2), &[(Object, User)]),
            row!(TPM_CC_POLICY_CAPABILITY, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
            row!(TPM_CC_POLICY_PARAMETERS, Some(Neither), (2, 0), &[(PolicySession, Absent)]),
        ];

        #[test]
        fn descriptor_metadata_reference_table() {
            let mut listed = Vec::new();
            for expected in METADATA {
                let (name, code) = (expected.name, expected.code);
                assert!(!listed.contains(&code), "{name} has more than one row");
                listed.push(code);
                let descriptor = find(code).unwrap_or_else(|| panic!("{name} is registered"));
                if let Some(nv_access) = expected.nv_access {
                    assert!(descriptor.nv_access == nv_access, "{name}: nv_access");
                }
                assert_eq!(
                    (descriptor.decrypt_size, descriptor.encrypt_size),
                    expected.parameter_sizes,
                    "{name}: (decrypt_size, encrypt_size)"
                );
                assert_eq!(
                    descriptor.handles.len(),
                    expected.handles.len(),
                    "{name}: handle count"
                );
                for (index, (spec, &(kind, auth))) in
                    descriptor.handles.iter().zip(expected.handles).enumerate()
                {
                    assert!(
                        core::mem::discriminant(&spec.kind) == core::mem::discriminant(&kind),
                        "{name}: handle {index} kind"
                    );
                    assert_eq!(
                        spec.user_auth,
                        auth != Absent,
                        "{name}: handle {index} user_auth"
                    );
                    assert!(spec.role == auth.role(), "{name}: handle {index} role");
                }
            }
            assert_eq!(
                listed.len(),
                implemented().count(),
                "every registered command has a row"
            );
        }
    }

    #[test]
    fn registered_handler_dispatcher_reachability() {
        for descriptor in implemented() {
            let mut runtime = empty_state_runtime();
            runtime.startup_received = match descriptor.lifecycle {
                CommandLifecycle::RequiresNotStarted => false,
                CommandLifecycle::RequiresStarted => true,
            };
            let mut bytes = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a];
            bytes.extend_from_slice(&descriptor.code.to_be_bytes());
            let input = CommandInput::new(bytes.len() as u32, bytes);
            let parsed = parse_command(&input).expect("the header parses");
            let code = dispatch(&mut runtime, &parsed, CancellationToken::disabled()).code();
            assert_ne!(code, TPM_RC_COMMAND_CODE, "code {:#x}", descriptor.code);
            assert_ne!(code, TPM_RC_INITIALIZE, "code {:#x}", descriptor.code);
        }
    }
}
