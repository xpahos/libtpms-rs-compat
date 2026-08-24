use crate::ffi_types::TpmResult;

use super::super::hierarchy::is_hierarchy_auth_handle;
use super::super::runtime::Tpm2Runtime;
use super::super::volatile::IMPLEMENTATION_PCR;
use super::certify;
use super::certify_creation;
use super::change_eps;
use super::context;
use super::create;
use super::create_loaded;
use super::create_primary;
use super::dictionary_attack_parameters;
use super::dispatcher::CommandFrame;
use super::encrypt_decrypt;
use super::event_sequence_complete;
use super::evict_control;
use super::flush_context;
use super::get_capability;
use super::get_command_audit_digest;
use super::get_random;
use super::get_session_audit_digest;
use super::get_test_result;
use super::get_time;
use super::hash;
use super::hash_sequence_start;
use super::hierarchy_admin;
use super::hierarchy_change_auth;
use super::hmac;
use super::hmac_start;
use super::incremental_self_test;
use super::load;
use super::nv_certify;
use super::nv_change_auth;
use super::nv_define_space;
use super::nv_lock;
use super::nv_read;
use super::nv_undefine_space;
use super::nv_write;
use super::object_change_auth;
use super::object_transfer;
use super::output::CommandOutput;
use super::pcr_allocate;
use super::pcr_event;
use super::pcr_extend;
use super::pcr_read;
use super::pcr_reset;
use super::policy_authorization;
use super::policy_authorize;
use super::policy_commands;
use super::policy_operand;
use super::policy_or;
use super::policy_pcr;
use super::policy_restrictions;
use super::quote;
use super::read_public;
use super::rsa_encryption;
use super::self_test;
use super::sequence_complete;
use super::sequence_update;
use super::set_command_code_audit_status;
use super::shutdown;
use super::sign;
use super::start_auth_session;
use super::startup;
use super::stir_random;
use super::test_parms;
use super::unseal;
use super::verify_signature;

pub(in crate::library::tpm2) const TPM_CC_NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x0000_011f;
pub(in crate::library::tpm2) const TPM_CC_EVICT_CONTROL: u32 = 0x0000_0120;
pub(in crate::library::tpm2) const TPM_CC_HIERARCHY_CONTROL: u32 = 0x0000_0121;
pub(in crate::library::tpm2) const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
pub(in crate::library::tpm2) const TPM_CC_CHANGE_EPS: u32 = 0x0000_0124;
pub(in crate::library::tpm2) const TPM_CC_CHANGE_PPS: u32 = 0x0000_0125;
pub(in crate::library::tpm2) const TPM_CC_CLEAR: u32 = 0x0000_0126;
pub(in crate::library::tpm2) const TPM_CC_CLEAR_CONTROL: u32 = 0x0000_0127;
pub(in crate::library::tpm2) const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;
pub(in crate::library::tpm2) const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012a;
pub(in crate::library::tpm2) const TPM_CC_PCR_ALLOCATE: u32 = 0x0000_012b;
pub(in crate::library::tpm2) const TPM_CC_PCR_SET_AUTH_POLICY: u32 = 0x0000_012c;
pub(in crate::library::tpm2) const TPM_CC_SET_PRIMARY_POLICY: u32 = 0x0000_012e;
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
pub(in crate::library::tpm2) const TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x0000_0140;
pub(in crate::library::tpm2) const TPM_CC_INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
pub(in crate::library::tpm2) const TPM_CC_SELF_TEST: u32 = 0x0000_0143;
pub(in crate::library::tpm2) const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub(in crate::library::tpm2) const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub(in crate::library::tpm2) const TPM_CC_STIR_RANDOM: u32 = 0x0000_0146;
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
pub(in crate::library::tpm2) const TPM_CC_ENCRYPT_DECRYPT: u32 = 0x0000_0164;
pub(in crate::library::tpm2) const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub(in crate::library::tpm2) const TPM_CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
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
pub(in crate::library::tpm2) const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;
pub(in crate::library::tpm2) const TPM_CC_GET_RANDOM: u32 = 0x0000_017b;
pub(in crate::library::tpm2) const TPM_CC_GET_TEST_RESULT: u32 = 0x0000_017c;
pub(in crate::library::tpm2) const TPM_CC_HASH: u32 = 0x0000_017d;
pub(in crate::library::tpm2) const TPM_CC_PCR_READ: u32 = 0x0000_017e;
pub(in crate::library::tpm2) const TPM_CC_POLICY_PCR: u32 = 0x0000_017f;
pub(in crate::library::tpm2) const TPM_CC_POLICY_RESTART: u32 = 0x0000_0180;
pub(in crate::library::tpm2) const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub(in crate::library::tpm2) const TPM_CC_NV_CERTIFY: u32 = 0x0000_0184;
pub(in crate::library::tpm2) const TPM_CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x0000_0185;
pub(in crate::library::tpm2) const TPM_CC_HASH_SEQUENCE_START: u32 = 0x0000_0186;
pub(in crate::library::tpm2) const TPM_CC_POLICY_PHYSICAL_PRESENCE: u32 = 0x0000_0187;
pub(in crate::library::tpm2) const TPM_CC_POLICY_DUPLICATION_SELECT: u32 = 0x0000_0188;
pub(in crate::library::tpm2) const TPM_CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;
pub(in crate::library::tpm2) const TPM_CC_TEST_PARMS: u32 = 0x0000_018a;
pub(in crate::library::tpm2) const TPM_CC_POLICY_PASSWORD: u32 = 0x0000_018c;
pub(in crate::library::tpm2) const TPM_CC_POLICY_NV_WRITTEN: u32 = 0x0000_018f;
pub(in crate::library::tpm2) const TPM_CC_POLICY_TEMPLATE: u32 = 0x0000_0190;
pub(in crate::library::tpm2) const TPM_CC_CREATE_LOADED: u32 = 0x0000_0191;
pub(in crate::library::tpm2) const TPM_CC_POLICY_AUTHORIZE_NV: u32 = 0x0000_0192;
pub(in crate::library::tpm2) const TPM_CC_ENCRYPT_DECRYPT2: u32 = 0x0000_0193;
pub(in crate::library::tpm2) const TPM_CC_POLICY_CAPABILITY: u32 = 0x0000_019b;
pub(in crate::library::tpm2) const TPM_CC_POLICY_PARAMETERS: u32 = 0x0000_019c;

pub(super) use super::super::hierarchy::TPM_RH_NULL;
use super::super::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM, is_hierarchy_handle,
};
use super::super::nv::is_nv_index_handle;
use super::super::object_create::is_object_handle;
use super::super::session::{is_hmac_session_handle, is_policy_session_handle, is_session_handle};

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

pub(super) type CommandHandler =
    for<'a> fn(&mut Tpm2Runtime, &CommandFrame<'a>) -> Result<CommandOutput, TpmResult>;

#[derive(Clone, Copy)]
pub(super) enum CommandLifecycle {
    RequiresNotStarted,
    RequiresStarted,
}

impl CommandLifecycle {
    pub(super) fn allows(self, runtime: &Tpm2Runtime) -> bool {
        match self {
            Self::RequiresNotStarted => !runtime.startup_received,
            Self::RequiresStarted => runtime.startup_received,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum HandleKind {
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
    pub(super) fn accepts(self, handle: u32) -> bool {
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
                super::super::object_create::is_transient_object_handle(handle)
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
pub(super) enum AuthRole {
    User,
    Admin,
    Dup,
}

pub(super) struct HandleSpec {
    pub(super) kind: HandleKind,
    pub(super) user_auth: bool,
    pub(super) role: AuthRole,
}

impl HandleSpec {
    pub(super) fn admin_role(&self) -> bool {
        self.role == AuthRole::Admin
    }

    pub(super) fn policy_only_role(&self) -> bool {
        matches!(self.role, AuthRole::Admin | AuthRole::Dup)
    }

    pub(super) fn dup_role(&self) -> bool {
        self.role == AuthRole::Dup
    }
}

const POLICY_SESSION_HANDLE: HandleSpec = HandleSpec {
    kind: HandleKind::PolicySession,
    user_auth: false,
    role: AuthRole::User,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum NvAccess {
    Neither,
    Read,
    Write,
}

pub(in crate::library::tpm2) struct CommandDescriptor {
    pub(in crate::library::tpm2) code: u32,
    pub(in crate::library::tpm2) attributes: u32,
    // TODO: Consume this when TPM2_PP_Commands and the physical-presence gate
    // are implemented.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::library::tpm2) physical_presence: bool,
    pub(super) lifecycle: CommandLifecycle,
    pub(super) handles: &'static [HandleSpec],
    pub(super) decrypt_size: u16,
    pub(super) encrypt_size: u16,
    pub(super) sessions_allowed: bool,
    pub(super) nv_access: NvAccess,
    pub(super) handler: CommandHandler,
}

static COMMANDS: &[CommandDescriptor] = &[
    CommandDescriptor {
        code: TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
        attributes: tpma_cc(TPM_CC_NV_UNDEFINE_SPACE_SPECIAL, true, 2),
        physical_presence: true,
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
        handler: nv_undefine_space::execute_special,
    },
    CommandDescriptor {
        code: TPM_CC_EVICT_CONTROL,
        attributes: tpma_cc(TPM_CC_EVICT_CONTROL, true, 2),
        physical_presence: true,
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
        handler: evict_control::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HIERARCHY_CONTROL,
        attributes: tpma_cc(TPM_CC_HIERARCHY_CONTROL, true, 1) | TPMA_CC_EXTENSIVE,
        physical_presence: true,
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
        handler: hierarchy_admin::control::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_UNDEFINE_SPACE,
        attributes: tpma_cc(TPM_CC_NV_UNDEFINE_SPACE, true, 2),
        physical_presence: true,
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
        handler: nv_undefine_space::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CHANGE_EPS,
        attributes: tpma_cc(TPM_CC_CHANGE_EPS, true, 1) | TPMA_CC_EXTENSIVE,
        physical_presence: true,
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
        handler: change_eps::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CHANGE_PPS,
        attributes: tpma_cc(TPM_CC_CHANGE_PPS, true, 1) | TPMA_CC_EXTENSIVE,
        physical_presence: true,
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
        handler: hierarchy_admin::change_pps::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CLEAR,
        attributes: tpma_cc(TPM_CC_CLEAR, true, 1) | TPMA_CC_EXTENSIVE,
        physical_presence: true,
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
        handler: hierarchy_admin::clear::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CLEAR_CONTROL,
        attributes: tpma_cc(TPM_CC_CLEAR_CONTROL, true, 1),
        physical_presence: true,
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
        handler: hierarchy_admin::clear_control::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HIERARCHY_CHANGE_AUTH,
        attributes: tpma_cc(TPM_CC_HIERARCHY_CHANGE_AUTH, true, 1),
        physical_presence: true,
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
        handler: hierarchy_change_auth::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_DEFINE_SPACE,
        attributes: tpma_cc(TPM_CC_NV_DEFINE_SPACE, true, 1),
        physical_presence: true,
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
        handler: nv_define_space::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_ALLOCATE,
        attributes: tpma_cc(TPM_CC_PCR_ALLOCATE, true, 1),
        physical_presence: true,
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
        handler: pcr_allocate::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_SET_AUTH_POLICY,
        attributes: tpma_cc(TPM_CC_PCR_SET_AUTH_POLICY, true, 1),
        physical_presence: true,
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
        handler: hierarchy_admin::pcr_policy::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SET_PRIMARY_POLICY,
        attributes: tpma_cc(TPM_CC_SET_PRIMARY_POLICY, true, 1),
        physical_presence: true,
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
        handler: hierarchy_admin::primary_policy::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CREATE_PRIMARY,
        attributes: tpma_cc_with_response_handle(TPM_CC_CREATE_PRIMARY, false, 1),
        physical_presence: true,
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
        handler: create_primary::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_GLOBAL_WRITE_LOCK,
        attributes: tpma_cc(TPM_CC_NV_GLOBAL_WRITE_LOCK, true, 1),
        physical_presence: true,
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
        handler: nv_lock::execute_global_write_lock,
    },
    CommandDescriptor {
        code: TPM_CC_GET_COMMAND_AUDIT_DIGEST,
        attributes: tpma_cc(TPM_CC_GET_COMMAND_AUDIT_DIGEST, true, 2),
        physical_presence: false,
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
        handler: get_command_audit_digest::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_INCREMENT,
        attributes: tpma_cc(TPM_CC_NV_INCREMENT, true, 2),
        physical_presence: false,
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
        handler: nv_write::execute_increment,
    },
    CommandDescriptor {
        code: TPM_CC_NV_SET_BITS,
        attributes: tpma_cc(TPM_CC_NV_SET_BITS, true, 2),
        physical_presence: false,
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
        handler: nv_write::execute_set_bits,
    },
    CommandDescriptor {
        code: TPM_CC_NV_EXTEND,
        attributes: tpma_cc(TPM_CC_NV_EXTEND, true, 2),
        physical_presence: false,
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
        handler: nv_write::execute_extend,
    },
    CommandDescriptor {
        code: TPM_CC_NV_WRITE,
        attributes: tpma_cc(TPM_CC_NV_WRITE, true, 2),
        physical_presence: false,
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
        handler: nv_write::execute_write,
    },
    CommandDescriptor {
        code: TPM_CC_NV_WRITE_LOCK,
        attributes: tpma_cc(TPM_CC_NV_WRITE_LOCK, true, 2),
        physical_presence: false,
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
        handler: nv_lock::execute_write_lock,
    },
    CommandDescriptor {
        code: TPM_CC_DICTIONARY_ATTACK_LOCK_RESET,
        attributes: tpma_cc(TPM_CC_DICTIONARY_ATTACK_LOCK_RESET, true, 1),
        physical_presence: false,
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
        handler: hierarchy_admin::lock_reset::execute,
    },
    CommandDescriptor {
        code: TPM_CC_DICTIONARY_ATTACK_PARAMETERS,
        attributes: tpma_cc(TPM_CC_DICTIONARY_ATTACK_PARAMETERS, true, 1),
        physical_presence: false,
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
        handler: dictionary_attack_parameters::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_CHANGE_AUTH,
        attributes: tpma_cc(TPM_CC_NV_CHANGE_AUTH, true, 1),
        physical_presence: false,
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
        handler: nv_change_auth::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_EVENT,
        attributes: tpma_cc(TPM_CC_PCR_EVENT, false, 1),
        physical_presence: false,
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
        handler: pcr_event::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_RESET,
        attributes: tpma_cc(TPM_CC_PCR_RESET, false, 1),
        physical_presence: false,
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
        handler: pcr_reset::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SEQUENCE_COMPLETE,
        attributes: tpma_cc_flushed(TPM_CC_SEQUENCE_COMPLETE, false, 1),
        physical_presence: false,
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
        handler: sequence_complete::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
        attributes: tpma_cc(TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS, true, 1),
        physical_presence: true,
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
        handler: set_command_code_audit_status::execute,
    },
    CommandDescriptor {
        code: TPM_CC_INCREMENTAL_SELF_TEST,
        attributes: tpma_cc(TPM_CC_INCREMENTAL_SELF_TEST, true, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: incremental_self_test::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SELF_TEST,
        attributes: tpma_cc(TPM_CC_SELF_TEST, true, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: self_test::execute,
    },
    CommandDescriptor {
        code: TPM_CC_STARTUP,
        attributes: tpma_cc(TPM_CC_STARTUP, true, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresNotStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: false,
        nv_access: NvAccess::Neither,
        handler: startup::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SHUTDOWN,
        attributes: tpma_cc(TPM_CC_SHUTDOWN, true, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: shutdown::execute,
    },
    CommandDescriptor {
        code: TPM_CC_STIR_RANDOM,
        attributes: tpma_cc(TPM_CC_STIR_RANDOM, true, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: stir_random::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CERTIFY,
        attributes: tpma_cc(TPM_CC_CERTIFY, false, 2),
        physical_presence: false,
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
        handler: certify::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_NV,
        attributes: tpma_cc(TPM_CC_POLICY_NV, false, 3),
        physical_presence: false,
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
        handler: policy_operand::execute_nv,
    },
    CommandDescriptor {
        code: TPM_CC_CERTIFY_CREATION,
        attributes: tpma_cc(TPM_CC_CERTIFY_CREATION, false, 2),
        physical_presence: false,
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
        handler: certify_creation::execute,
    },
    CommandDescriptor {
        code: TPM_CC_DUPLICATE,
        attributes: tpma_cc(TPM_CC_DUPLICATE, false, 2),
        physical_presence: false,
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
        handler: object_transfer::execute_duplicate,
    },
    CommandDescriptor {
        code: TPM_CC_GET_TIME,
        attributes: tpma_cc(TPM_CC_GET_TIME, false, 2),
        physical_presence: false,
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
        handler: get_time::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_SESSION_AUDIT_DIGEST,
        attributes: tpma_cc(TPM_CC_GET_SESSION_AUDIT_DIGEST, false, 3),
        physical_presence: false,
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
        handler: get_session_audit_digest::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_READ,
        attributes: tpma_cc(TPM_CC_NV_READ, false, 2),
        physical_presence: false,
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
        handler: nv_read::execute_read,
    },
    CommandDescriptor {
        code: TPM_CC_NV_READ_LOCK,
        attributes: tpma_cc(TPM_CC_NV_READ_LOCK, true, 2),
        physical_presence: false,
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
        handler: nv_lock::execute_read_lock,
    },
    CommandDescriptor {
        code: TPM_CC_OBJECT_CHANGE_AUTH,
        attributes: tpma_cc(TPM_CC_OBJECT_CHANGE_AUTH, false, 2),
        physical_presence: false,
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
        handler: object_change_auth::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_SECRET,
        attributes: tpma_cc(TPM_CC_POLICY_SECRET, false, 2),
        physical_presence: false,
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
        handler: policy_authorization::execute_secret,
    },
    CommandDescriptor {
        code: TPM_CC_REWRAP,
        attributes: tpma_cc(TPM_CC_REWRAP, false, 2),
        physical_presence: false,
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
        handler: object_transfer::execute_rewrap,
    },
    CommandDescriptor {
        code: TPM_CC_CREATE,
        attributes: tpma_cc(TPM_CC_CREATE, false, 1),
        physical_presence: false,
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
        handler: create::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HMAC,
        attributes: tpma_cc(TPM_CC_HMAC, false, 1),
        physical_presence: false,
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
        handler: hmac::execute,
    },
    CommandDescriptor {
        code: TPM_CC_IMPORT,
        attributes: tpma_cc(TPM_CC_IMPORT, false, 1),
        physical_presence: false,
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
        handler: object_transfer::execute_import,
    },
    CommandDescriptor {
        code: TPM_CC_LOAD,
        attributes: tpma_cc_with_response_handle(TPM_CC_LOAD, false, 1),
        physical_presence: false,
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
        handler: load::execute,
    },
    CommandDescriptor {
        code: TPM_CC_QUOTE,
        attributes: tpma_cc(TPM_CC_QUOTE, false, 1),
        physical_presence: false,
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
        handler: quote::execute,
    },
    CommandDescriptor {
        code: TPM_CC_RSA_DECRYPT,
        attributes: tpma_cc(TPM_CC_RSA_DECRYPT, false, 1),
        physical_presence: false,
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
        handler: rsa_encryption::execute_decrypt,
    },
    CommandDescriptor {
        code: TPM_CC_HMAC_START,
        attributes: tpma_cc_with_response_handle(TPM_CC_HMAC_START, false, 1),
        physical_presence: false,
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
        handler: hmac_start::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SEQUENCE_UPDATE,
        attributes: tpma_cc(TPM_CC_SEQUENCE_UPDATE, false, 1),
        physical_presence: false,
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
        handler: sequence_update::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SIGN,
        attributes: tpma_cc(TPM_CC_SIGN, false, 1),
        physical_presence: false,
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
        handler: sign::execute,
    },
    CommandDescriptor {
        code: TPM_CC_UNSEAL,
        attributes: tpma_cc(TPM_CC_UNSEAL, false, 1),
        physical_presence: false,
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
        handler: unseal::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_SIGNED,
        attributes: tpma_cc(TPM_CC_POLICY_SIGNED, false, 2),
        physical_presence: false,
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
        handler: policy_authorization::execute_signed,
    },
    CommandDescriptor {
        code: TPM_CC_CONTEXT_LOAD,
        attributes: tpma_cc_with_response_handle(TPM_CC_CONTEXT_LOAD, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: false,
        nv_access: NvAccess::Neither,
        handler: context::execute_load,
    },
    CommandDescriptor {
        code: TPM_CC_CONTEXT_SAVE,
        attributes: tpma_cc(TPM_CC_CONTEXT_SAVE, false, 1),
        physical_presence: false,
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
        handler: context::execute_save,
    },
    CommandDescriptor {
        code: TPM_CC_ENCRYPT_DECRYPT,
        attributes: tpma_cc(TPM_CC_ENCRYPT_DECRYPT, false, 1),
        physical_presence: false,
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
        handler: encrypt_decrypt::execute,
    },
    CommandDescriptor {
        code: TPM_CC_FLUSH_CONTEXT,
        attributes: tpma_cc(TPM_CC_FLUSH_CONTEXT, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: false,
        nv_access: NvAccess::Neither,
        handler: flush_context::execute,
    },
    CommandDescriptor {
        code: TPM_CC_LOAD_EXTERNAL,
        attributes: tpma_cc_with_response_handle(TPM_CC_LOAD_EXTERNAL, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: load::execute_external,
    },
    CommandDescriptor {
        code: TPM_CC_NV_READ_PUBLIC,
        attributes: tpma_cc(TPM_CC_NV_READ_PUBLIC, false, 1),
        physical_presence: false,
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
        handler: nv_read::execute_read_public,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_AUTHORIZE,
        attributes: tpma_cc(TPM_CC_POLICY_AUTHORIZE, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_authorize::execute_authorize,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_AUTH_VALUE,
        attributes: tpma_cc(TPM_CC_POLICY_AUTH_VALUE, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_commands::execute_auth_value,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_COMMAND_CODE,
        attributes: tpma_cc(TPM_CC_POLICY_COMMAND_CODE, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_commands::execute_command_code,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_COUNTER_TIMER,
        attributes: tpma_cc(TPM_CC_POLICY_COUNTER_TIMER, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_operand::execute_counter_timer,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_CP_HASH,
        attributes: tpma_cc(TPM_CC_POLICY_CP_HASH, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_restrictions::execute_cp_hash,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_LOCALITY,
        attributes: tpma_cc(TPM_CC_POLICY_LOCALITY, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_restrictions::execute_locality,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_NAME_HASH,
        attributes: tpma_cc(TPM_CC_POLICY_NAME_HASH, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_restrictions::execute_name_hash,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_OR,
        attributes: tpma_cc(TPM_CC_POLICY_OR, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_or::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_TICKET,
        attributes: tpma_cc(TPM_CC_POLICY_TICKET, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_authorization::execute_ticket,
    },
    CommandDescriptor {
        code: TPM_CC_READ_PUBLIC,
        attributes: tpma_cc(TPM_CC_READ_PUBLIC, false, 1),
        physical_presence: false,
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
        handler: read_public::execute,
    },
    CommandDescriptor {
        code: TPM_CC_RSA_ENCRYPT,
        attributes: tpma_cc(TPM_CC_RSA_ENCRYPT, false, 1),
        physical_presence: false,
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
        handler: rsa_encryption::execute_encrypt,
    },
    CommandDescriptor {
        code: TPM_CC_START_AUTH_SESSION,
        attributes: tpma_cc_with_response_handle(TPM_CC_START_AUTH_SESSION, false, 2),
        physical_presence: false,
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
        handler: start_auth_session::execute,
    },
    CommandDescriptor {
        code: TPM_CC_VERIFY_SIGNATURE,
        attributes: tpma_cc(TPM_CC_VERIFY_SIGNATURE, false, 1),
        physical_presence: false,
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
        handler: verify_signature::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_CAPABILITY,
        attributes: tpma_cc(TPM_CC_GET_CAPABILITY, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: get_capability::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_RANDOM,
        attributes: tpma_cc(TPM_CC_GET_RANDOM, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: get_random::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_TEST_RESULT,
        attributes: tpma_cc(TPM_CC_GET_TEST_RESULT, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: get_test_result::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HASH,
        attributes: tpma_cc(TPM_CC_HASH, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 2,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hash::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_READ,
        attributes: tpma_cc(TPM_CC_PCR_READ, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr_read::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_PCR,
        attributes: tpma_cc(TPM_CC_POLICY_PCR, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_pcr::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_RESTART,
        attributes: tpma_cc(TPM_CC_POLICY_RESTART, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_commands::execute_restart,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_EXTEND,
        attributes: tpma_cc(TPM_CC_PCR_EXTEND, false, 1),
        physical_presence: false,
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
        handler: pcr_extend::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_CERTIFY,
        attributes: tpma_cc(TPM_CC_NV_CERTIFY, false, 3),
        physical_presence: false,
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
        handler: nv_certify::execute,
    },
    CommandDescriptor {
        code: TPM_CC_EVENT_SEQUENCE_COMPLETE,
        attributes: tpma_cc_flushed(TPM_CC_EVENT_SEQUENCE_COMPLETE, true, 2),
        physical_presence: false,
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
        handler: event_sequence_complete::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HASH_SEQUENCE_START,
        attributes: tpma_cc_with_response_handle(TPM_CC_HASH_SEQUENCE_START, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: hash_sequence_start::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_PHYSICAL_PRESENCE,
        attributes: tpma_cc(TPM_CC_POLICY_PHYSICAL_PRESENCE, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_restrictions::execute_physical_presence,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_DUPLICATION_SELECT,
        attributes: tpma_cc(TPM_CC_POLICY_DUPLICATION_SELECT, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_restrictions::execute_duplication_select,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_GET_DIGEST,
        attributes: tpma_cc(TPM_CC_POLICY_GET_DIGEST, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 2,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_commands::execute_get_digest,
    },
    CommandDescriptor {
        code: TPM_CC_TEST_PARMS,
        attributes: tpma_cc(TPM_CC_TEST_PARMS, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: test_parms::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_PASSWORD,
        attributes: tpma_cc(TPM_CC_POLICY_PASSWORD, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_commands::execute_password,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_NV_WRITTEN,
        attributes: tpma_cc(TPM_CC_POLICY_NV_WRITTEN, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 0,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_restrictions::execute_nv_written,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_TEMPLATE,
        attributes: tpma_cc(TPM_CC_POLICY_TEMPLATE, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_restrictions::execute_template,
    },
    CommandDescriptor {
        code: TPM_CC_CREATE_LOADED,
        attributes: tpma_cc_with_response_handle(TPM_CC_CREATE_LOADED, false, 1),
        physical_presence: true,
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
        handler: create_loaded::execute,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_AUTHORIZE_NV,
        attributes: tpma_cc(TPM_CC_POLICY_AUTHORIZE_NV, false, 3),
        physical_presence: false,
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
        handler: policy_authorize::execute_authorize_nv,
    },
    CommandDescriptor {
        code: TPM_CC_ENCRYPT_DECRYPT2,
        attributes: tpma_cc(TPM_CC_ENCRYPT_DECRYPT2, false, 1),
        physical_presence: false,
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
        handler: encrypt_decrypt::execute_two,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_CAPABILITY,
        attributes: tpma_cc(TPM_CC_POLICY_CAPABILITY, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_operand::execute_capability,
    },
    CommandDescriptor {
        code: TPM_CC_POLICY_PARAMETERS,
        attributes: tpma_cc(TPM_CC_POLICY_PARAMETERS, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[POLICY_SESSION_HANDLE],
        decrypt_size: 2,
        encrypt_size: 0,
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: policy_restrictions::execute_parameters,
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
    use super::super::dispatcher::dispatch;
    use super::super::header::parse_command;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::{TPM_RC_COMMAND_CODE, TPM_RC_INITIALIZE};
    use crate::library::tpm2::runtime::empty_state_runtime;

    const TPMA_CC_RESERVED: u32 = 0x003f_0000 | 0xc000_0000;

    #[test]
    fn registry_is_strictly_sorted_by_command_code() {
        let codes: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        assert!(
            codes.windows(2).all(|pair| pair[0] < pair[1]),
            "descriptors must be strictly ascending: {codes:#x?}"
        );
    }

    #[test]
    fn registry_has_no_duplicate_command_codes() {
        let codes: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        for (index, &code) in codes.iter().enumerate() {
            assert!(
                !codes[index + 1..].contains(&code),
                "duplicate command code {code:#x}"
            );
        }
    }

    #[test]
    fn lookup_finds_every_registered_command() {
        assert_eq!(
            find(TPM_CC_EVICT_CONTROL).map(|d| d.code),
            Some(TPM_CC_EVICT_CONTROL)
        );
        assert_eq!(
            find(TPM_CC_CHANGE_EPS).map(|d| d.code),
            Some(TPM_CC_CHANGE_EPS)
        );
        assert_eq!(
            find(TPM_CC_HIERARCHY_CHANGE_AUTH).map(|d| d.code),
            Some(TPM_CC_HIERARCHY_CHANGE_AUTH)
        );
        assert_eq!(
            find(TPM_CC_PCR_ALLOCATE).map(|d| d.code),
            Some(TPM_CC_PCR_ALLOCATE)
        );
        assert_eq!(
            find(TPM_CC_CREATE_PRIMARY).map(|d| d.code),
            Some(TPM_CC_CREATE_PRIMARY)
        );
        assert_eq!(
            find(TPM_CC_PCR_RESET).map(|d| d.code),
            Some(TPM_CC_PCR_RESET)
        );
        assert_eq!(
            find(TPM_CC_INCREMENTAL_SELF_TEST).map(|d| d.code),
            Some(TPM_CC_INCREMENTAL_SELF_TEST)
        );
        assert_eq!(
            find(TPM_CC_SELF_TEST).map(|d| d.code),
            Some(TPM_CC_SELF_TEST)
        );
        assert_eq!(find(TPM_CC_STARTUP).map(|d| d.code), Some(TPM_CC_STARTUP));
        assert_eq!(find(TPM_CC_SHUTDOWN).map(|d| d.code), Some(TPM_CC_SHUTDOWN));
        assert_eq!(
            find(TPM_CC_STIR_RANDOM).map(|d| d.code),
            Some(TPM_CC_STIR_RANDOM)
        );
        assert_eq!(
            find(TPM_CC_READ_PUBLIC).map(|d| d.code),
            Some(TPM_CC_READ_PUBLIC)
        );
        assert_eq!(
            find(TPM_CC_VERIFY_SIGNATURE).map(|d| d.code),
            Some(TPM_CC_VERIFY_SIGNATURE)
        );
        assert_eq!(
            find(TPM_CC_GET_CAPABILITY).map(|d| d.code),
            Some(TPM_CC_GET_CAPABILITY)
        );
        assert_eq!(
            find(TPM_CC_GET_RANDOM).map(|d| d.code),
            Some(TPM_CC_GET_RANDOM)
        );
        assert_eq!(find(TPM_CC_HASH).map(|d| d.code), Some(TPM_CC_HASH));
        assert_eq!(find(TPM_CC_PCR_READ).map(|d| d.code), Some(TPM_CC_PCR_READ));
        assert_eq!(
            find(TPM_CC_PCR_EXTEND).map(|d| d.code),
            Some(TPM_CC_PCR_EXTEND)
        );
    }

    #[test]
    fn lookup_rejects_unregistered_command_codes() {
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
    fn iteration_returns_every_implemented_command_exactly_once() {
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
                TPM_CC_HIERARCHY_CHANGE_AUTH,
                TPM_CC_NV_DEFINE_SPACE,
                TPM_CC_PCR_ALLOCATE,
                TPM_CC_PCR_SET_AUTH_POLICY,
                TPM_CC_SET_PRIMARY_POLICY,
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
                TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
                TPM_CC_INCREMENTAL_SELF_TEST,
                TPM_CC_SELF_TEST,
                TPM_CC_STARTUP,
                TPM_CC_SHUTDOWN,
                TPM_CC_STIR_RANDOM,
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
                TPM_CC_ENCRYPT_DECRYPT,
                TPM_CC_FLUSH_CONTEXT,
                TPM_CC_LOAD_EXTERNAL,
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
                TPM_CC_GET_CAPABILITY,
                TPM_CC_GET_RANDOM,
                TPM_CC_GET_TEST_RESULT,
                TPM_CC_HASH,
                TPM_CC_PCR_READ,
                TPM_CC_POLICY_PCR,
                TPM_CC_POLICY_RESTART,
                TPM_CC_PCR_EXTEND,
                TPM_CC_NV_CERTIFY,
                TPM_CC_EVENT_SEQUENCE_COMPLETE,
                TPM_CC_HASH_SEQUENCE_START,
                TPM_CC_POLICY_PHYSICAL_PRESENCE,
                TPM_CC_POLICY_DUPLICATION_SELECT,
                TPM_CC_POLICY_GET_DIGEST,
                TPM_CC_TEST_PARMS,
                TPM_CC_POLICY_PASSWORD,
                TPM_CC_POLICY_NV_WRITTEN,
                TPM_CC_POLICY_TEMPLATE,
                TPM_CC_CREATE_LOADED,
                TPM_CC_POLICY_AUTHORIZE_NV,
                TPM_CC_ENCRYPT_DECRYPT2,
                TPM_CC_POLICY_CAPABILITY,
                TPM_CC_POLICY_PARAMETERS
            ]
        );
    }

    #[test]
    fn change_eps_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_CHANGE_EPS).unwrap().attributes, 0x02c0_0124);
    }

    #[test]
    fn change_eps_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_CHANGE_EPS)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn change_eps_declares_one_platform_handle_requiring_user_authorization() {
        let descriptor = find(TPM_CC_CHANGE_EPS).unwrap();
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Platform));
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_ne!(descriptor.attributes & (1 << 22), 0, "ChangeEPS updates NV");
    }

    #[test]
    fn the_extensive_commands_match_the_vendored_attribute_table() {
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
    fn dictionary_attack_parameters_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(
            find(TPM_CC_DICTIONARY_ATTACK_PARAMETERS)
                .unwrap()
                .attributes,
            0x0240_013a
        );
    }

    #[test]
    fn dictionary_attack_parameters_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_DICTIONARY_ATTACK_PARAMETERS)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn dictionary_attack_parameters_declares_one_lockout_handle_requiring_user_authorization() {
        let descriptor = find(TPM_CC_DICTIONARY_ATTACK_PARAMETERS).unwrap();
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Lockout));
        assert!(descriptor.sessions_allowed);
        assert!(!descriptor.physical_presence);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_ne!(
            descriptor.attributes & (1 << 22),
            0,
            "DictionaryAttackParameters updates NV"
        );
    }

    #[test]
    fn the_lockout_handle_kind_accepts_only_the_lockout_hierarchy() {
        use crate::library::tpm2::hierarchy::{
            TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM,
        };
        let kind = find(TPM_CC_DICTIONARY_ATTACK_PARAMETERS).unwrap().handles[0].kind;
        assert!(kind.accepts(TPM_RH_LOCKOUT));
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_PLATFORM,
            TPM_RH_NULL,
            0,
            23,
            IMPLEMENTATION_PCR as u32,
            0x0100_0000,
            0x4000_0009,
            0x8000_0000,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn hierarchy_change_auth_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(
            find(TPM_CC_HIERARCHY_CHANGE_AUTH).unwrap().attributes,
            0x0240_0129
        );
    }

    #[test]
    fn hierarchy_change_auth_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_HIERARCHY_CHANGE_AUTH)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn hierarchy_change_auth_declares_one_command_handle_requiring_user_authorization() {
        let descriptor = find(TPM_CC_HIERARCHY_CHANGE_AUTH).unwrap();
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn the_hierarchy_auth_handle_kind_accepts_only_the_four_hierarchies() {
        use crate::library::tpm2::hierarchy::{
            TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM,
        };
        let kind = find(TPM_CC_HIERARCHY_CHANGE_AUTH).unwrap().handles[0].kind;
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_PLATFORM,
            TPM_RH_LOCKOUT,
        ] {
            assert!(kind.accepts(handle), "handle {handle:#x}");
        }
        assert!(!kind.accepts(TPM_RH_NULL), "the null hierarchy has no auth");
        for handle in [
            0u32,
            23,
            IMPLEMENTATION_PCR as u32,
            0x0100_0000,
            0x0200_0000,
            0x0300_0000,
            0x4000_0000,
            0x4000_0009,
            0x4000_000d,
            0x8000_0000,
            0x8100_0000,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn pcr_allocate_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_PCR_ALLOCATE).unwrap().attributes, 0x0240_012b);
    }

    #[test]
    fn pcr_allocate_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_PCR_ALLOCATE)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn pcr_allocate_declares_one_command_handle_requiring_user_authorization() {
        let descriptor = find(TPM_CC_PCR_ALLOCATE).unwrap();
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_ne!(
            descriptor.attributes & (1 << 22),
            0,
            "PCR_Allocate updates NV"
        );
    }

    #[test]
    fn the_platform_handle_kind_accepts_only_the_platform_hierarchy() {
        use crate::library::tpm2::hierarchy::{
            TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM,
        };
        let kind = find(TPM_CC_PCR_ALLOCATE).unwrap().handles[0].kind;
        assert!(kind.accepts(TPM_RH_PLATFORM));
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_LOCKOUT,
            TPM_RH_NULL,
            0,
            23,
            IMPLEMENTATION_PCR as u32,
            0x0100_0000,
            0x8000_0000,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn incremental_self_test_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(
            find(TPM_CC_INCREMENTAL_SELF_TEST).unwrap().attributes,
            0x0040_0142
        );
    }

    #[test]
    fn incremental_self_test_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_INCREMENTAL_SELF_TEST)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn incremental_self_test_declares_no_handles_and_allows_sessions() {
        let descriptor = find(TPM_CC_INCREMENTAL_SELF_TEST).unwrap();
        assert!(descriptor.handles.is_empty());
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn self_test_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_SELF_TEST).unwrap().attributes, 0x0040_0143);
    }

    #[test]
    fn self_test_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_SELF_TEST)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn self_test_declares_no_handles_and_allows_sessions() {
        let descriptor = find(TPM_CC_SELF_TEST).unwrap();
        assert!(descriptor.handles.is_empty());
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn startup_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_STARTUP).unwrap().attributes, 0x0040_0144);
    }

    #[test]
    fn shutdown_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_SHUTDOWN).unwrap().attributes, 0x0040_0145);
    }

    #[test]
    fn stir_random_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_STIR_RANDOM).unwrap().attributes, 0x0040_0146);
    }

    #[test]
    fn stir_random_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_STIR_RANDOM)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn stir_random_declares_no_handles_and_allows_sessions() {
        let descriptor = find(TPM_CC_STIR_RANDOM).unwrap();
        assert!(descriptor.handles.is_empty());
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn get_capability_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_GET_CAPABILITY).unwrap().attributes, 0x0000_017a);
    }

    #[test]
    fn get_capability_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_GET_CAPABILITY)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn get_random_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_GET_RANDOM).unwrap().attributes, 0x0000_017b);
    }

    #[test]
    fn get_random_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_GET_RANDOM)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn get_random_declares_no_handles_and_allows_sessions() {
        let descriptor = find(TPM_CC_GET_RANDOM).unwrap();
        assert!(descriptor.handles.is_empty());
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn hash_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_HASH).unwrap().attributes, 0x0000_017d);
    }

    #[test]
    fn hash_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_HASH)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn hash_declares_no_handles_and_allows_sessions() {
        let descriptor = find(TPM_CC_HASH).unwrap();
        assert!(descriptor.handles.is_empty());
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn hash_carries_no_nv_attribute() {
        assert_eq!(find(TPM_CC_HASH).unwrap().attributes & (1 << 22), 0);
    }

    #[test]
    fn pcr_read_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_PCR_READ).unwrap().attributes, 0x0000_017e);
    }

    #[test]
    fn pcr_read_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_PCR_READ)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn pcr_extend_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_PCR_EXTEND).unwrap().attributes, 0x0200_0182);
    }

    #[test]
    fn pcr_extend_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_PCR_EXTEND)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn pcr_extend_declares_one_command_handle_requiring_user_authorization() {
        let descriptor = find(TPM_CC_PCR_EXTEND).unwrap();
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(descriptor.sessions_allowed);
    }

    #[test]
    fn pcr_event_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_PCR_EVENT).unwrap().attributes, 0x0200_013c);
    }

    #[test]
    fn pcr_event_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_PCR_EVENT)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn pcr_event_declares_one_command_handle_requiring_user_authorization() {
        let descriptor = find(TPM_CC_PCR_EVENT).unwrap();
        assert_eq!(descriptor.code, TPM_CC_PCR_EVENT);
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(
            descriptor.handles[0].kind,
            HandleKind::PcrAllowNull
        ));
        assert!(descriptor.sessions_allowed);
        assert!(!descriptor.physical_presence);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert_eq!(
            descriptor.attributes & (1 << 22),
            0,
            "PCR_Event carries no NV attribute"
        );
        assert_eq!(
            descriptor.attributes & (1 << 28),
            0,
            "PCR_Event has no response handle"
        );
    }

    #[test]
    fn the_pcr_event_handle_kind_accepts_implemented_pcrs_and_the_null_handle() {
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
    fn pcr_event_sorts_between_nv_change_auth_and_pcr_reset() {
        let codes: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        let at = codes
            .iter()
            .position(|&code| code == TPM_CC_PCR_EVENT)
            .expect("PCR_Event is registered");
        assert_eq!(codes[at - 1], TPM_CC_NV_CHANGE_AUTH);
        assert_eq!(codes[at + 1], TPM_CC_PCR_RESET);
    }

    #[test]
    fn pcr_reset_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_PCR_RESET).unwrap().attributes, 0x0200_013d);
    }

    #[test]
    fn pcr_reset_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_PCR_RESET)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn pcr_reset_declares_one_command_handle_requiring_user_authorization() {
        let descriptor = find(TPM_CC_PCR_RESET).unwrap();
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn the_exact_pcr_handle_kind_rejects_the_null_handle() {
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
    fn physical_presence_applicability_matches_the_vendored_attribute_table() {
        const PP_COMMANDS: [u32; 17] = [
            TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
            TPM_CC_EVICT_CONTROL,
            TPM_CC_HIERARCHY_CONTROL,
            TPM_CC_NV_UNDEFINE_SPACE,
            TPM_CC_CHANGE_EPS,
            TPM_CC_CHANGE_PPS,
            TPM_CC_CLEAR,
            TPM_CC_CLEAR_CONTROL,
            TPM_CC_HIERARCHY_CHANGE_AUTH,
            TPM_CC_NV_DEFINE_SPACE,
            TPM_CC_PCR_ALLOCATE,
            TPM_CC_PCR_SET_AUTH_POLICY,
            TPM_CC_SET_PRIMARY_POLICY,
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
    fn the_handle_count_attribute_matches_the_declared_handles() {
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
    fn only_startup_and_flush_context_forbid_an_authorization_area() {
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
    fn flush_context_attributes_match_the_upstream_tpma_cc() {
        assert_eq!(find(TPM_CC_FLUSH_CONTEXT).unwrap().attributes, 0x0000_0165);
    }

    #[test]
    fn flush_context_is_registered_exactly_once() {
        let count = implemented()
            .filter(|descriptor| descriptor.code == TPM_CC_FLUSH_CONTEXT)
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn flush_context_declares_no_handles_and_no_sessions() {
        let descriptor = find(TPM_CC_FLUSH_CONTEXT).unwrap();
        assert!(descriptor.handles.is_empty());
        assert!(!descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(
            descriptor.attributes & (1 << 22),
            0,
            "FlushContext does not update NV"
        );
        assert_eq!(
            descriptor.attributes & (1 << 28),
            0,
            "FlushContext has no response handle"
        );
    }

    #[test]
    fn the_pcr_handle_kind_accepts_implemented_pcrs_and_the_null_handle() {
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
    fn attribute_command_index_mirrors_the_command_code() {
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
    fn reserved_attribute_bits_are_clear() {
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
    fn every_registered_handler_is_reachable_through_the_dispatcher() {
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
            let code = dispatch(&mut runtime, &parsed).code();
            assert_ne!(code, TPM_RC_COMMAND_CODE, "code {:#x}", descriptor.code);
            assert_ne!(code, TPM_RC_INITIALIZE, "code {:#x}", descriptor.code);
        }
    }
}
