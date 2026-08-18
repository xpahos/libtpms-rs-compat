use crate::ffi_types::TpmResult;

use super::super::hierarchy::is_hierarchy_auth_handle;
use super::super::runtime::Tpm2Runtime;
use super::super::volatile::IMPLEMENTATION_PCR;
use super::change_eps;
use super::create_primary;
use super::dictionary_attack_parameters;
use super::dispatcher::CommandFrame;
use super::evict_control;
use super::flush_context;
use super::get_capability;
use super::get_random;
use super::hash;
use super::hierarchy_change_auth;
use super::incremental_self_test;
use super::nv_certify;
use super::nv_change_auth;
use super::nv_define_space;
use super::nv_lock;
use super::nv_read;
use super::nv_undefine_space;
use super::nv_write;
use super::output::CommandOutput;
use super::pcr_allocate;
use super::pcr_extend;
use super::pcr_read;
use super::pcr_reset;
use super::self_test;
use super::shutdown;
use super::startup;
use super::stir_random;

pub(in crate::library::tpm2) const TPM_CC_NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x0000_011f;
pub(in crate::library::tpm2) const TPM_CC_EVICT_CONTROL: u32 = 0x0000_0120;
pub(in crate::library::tpm2) const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
pub(in crate::library::tpm2) const TPM_CC_CHANGE_EPS: u32 = 0x0000_0124;
pub(in crate::library::tpm2) const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;
pub(in crate::library::tpm2) const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012a;
pub(in crate::library::tpm2) const TPM_CC_PCR_ALLOCATE: u32 = 0x0000_012b;
pub(in crate::library::tpm2) const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub(in crate::library::tpm2) const TPM_CC_NV_GLOBAL_WRITE_LOCK: u32 = 0x0000_0132;
pub(in crate::library::tpm2) const TPM_CC_NV_INCREMENT: u32 = 0x0000_0134;
pub(in crate::library::tpm2) const TPM_CC_NV_SET_BITS: u32 = 0x0000_0135;
pub(in crate::library::tpm2) const TPM_CC_NV_EXTEND: u32 = 0x0000_0136;
pub(in crate::library::tpm2) const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
pub(in crate::library::tpm2) const TPM_CC_NV_WRITE_LOCK: u32 = 0x0000_0138;
pub(in crate::library::tpm2) const TPM_CC_DICTIONARY_ATTACK_PARAMETERS: u32 = 0x0000_013a;
pub(in crate::library::tpm2) const TPM_CC_NV_CHANGE_AUTH: u32 = 0x0000_013b;
pub(in crate::library::tpm2) const TPM_CC_PCR_RESET: u32 = 0x0000_013d;
pub(in crate::library::tpm2) const TPM_CC_INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
pub(in crate::library::tpm2) const TPM_CC_SELF_TEST: u32 = 0x0000_0143;
pub(in crate::library::tpm2) const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub(in crate::library::tpm2) const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub(in crate::library::tpm2) const TPM_CC_STIR_RANDOM: u32 = 0x0000_0146;
pub(in crate::library::tpm2) const TPM_CC_NV_READ: u32 = 0x0000_014e;
pub(in crate::library::tpm2) const TPM_CC_NV_READ_LOCK: u32 = 0x0000_014f;
pub(in crate::library::tpm2) const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub(in crate::library::tpm2) const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub(in crate::library::tpm2) const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;
pub(in crate::library::tpm2) const TPM_CC_GET_RANDOM: u32 = 0x0000_017b;
pub(in crate::library::tpm2) const TPM_CC_HASH: u32 = 0x0000_017d;
pub(in crate::library::tpm2) const TPM_CC_PCR_READ: u32 = 0x0000_017e;
pub(in crate::library::tpm2) const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub(in crate::library::tpm2) const TPM_CC_NV_CERTIFY: u32 = 0x0000_0184;

pub(super) use super::super::hierarchy::TPM_RH_NULL;
use super::super::hierarchy::{TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM, is_hierarchy_handle};
use super::super::nv::is_nv_index_handle;
use super::super::object_create::is_object_handle;

const TPMA_CC_COMMAND_INDEX_MASK: u32 = 0x0000_ffff;
const TPMA_CC_NV: u32 = 1 << 22;
const TPMA_CC_EXTENSIVE: u32 = 1 << 23;
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
    Lockout,
    Platform,
    Provision,
    Object,
    ObjectAllowNull,
    Pcr,
    PcrAllowNull,
    NvIndex,
    NvAuth,
}

impl HandleKind {
    pub(super) fn accepts(self, handle: u32) -> bool {
        match self {
            Self::HierarchyAuth => is_hierarchy_auth_handle(handle),
            Self::Hierarchy => is_hierarchy_handle(handle),
            Self::Lockout => handle == TPM_RH_LOCKOUT,
            Self::Platform => handle == TPM_RH_PLATFORM,
            Self::Provision => matches!(handle, TPM_RH_OWNER | TPM_RH_PLATFORM),
            Self::Object => is_object_handle(handle),
            Self::ObjectAllowNull => is_object_handle(handle) || handle == TPM_RH_NULL,
            Self::Pcr => (handle as usize) < IMPLEMENTATION_PCR,
            Self::PcrAllowNull => (handle as usize) < IMPLEMENTATION_PCR || handle == TPM_RH_NULL,
            Self::NvIndex => is_nv_index_handle(handle),
            Self::NvAuth => {
                matches!(handle, TPM_RH_OWNER | TPM_RH_PLATFORM) || is_nv_index_handle(handle)
            }
        }
    }
}

pub(super) struct HandleSpec {
    pub(super) kind: HandleKind,
    pub(super) user_auth: bool,
    pub(super) admin_role: bool,
}

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
                admin_role: true,
            },
            HandleSpec {
                kind: HandleKind::Platform,
                user_auth: true,
                admin_role: false,
            },
        ],
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::Object,
                user_auth: false,
                admin_role: false,
            },
        ],
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: evict_control::execute,
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
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
            admin_role: false,
        }],
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: change_eps::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HIERARCHY_CHANGE_AUTH,
        attributes: tpma_cc(TPM_CC_HIERARCHY_CHANGE_AUTH, true, 1),
        physical_presence: true,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::HierarchyAuth,
            user_auth: true,
            admin_role: false,
        }],
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
            admin_role: false,
        }],
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
            admin_role: false,
        }],
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr_allocate::execute,
    },
    CommandDescriptor {
        code: TPM_CC_CREATE_PRIMARY,
        attributes: tpma_cc_with_response_handle(TPM_CC_CREATE_PRIMARY, false, 1),
        physical_presence: true,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Hierarchy,
            user_auth: true,
            admin_role: false,
        }],
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
            admin_role: false,
        }],
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv_lock::execute_global_write_lock,
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
        sessions_allowed: true,
        nv_access: NvAccess::Write,
        handler: nv_lock::execute_write_lock,
    },
    CommandDescriptor {
        code: TPM_CC_DICTIONARY_ATTACK_PARAMETERS,
        attributes: tpma_cc(TPM_CC_DICTIONARY_ATTACK_PARAMETERS, true, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Lockout,
            user_auth: true,
            admin_role: false,
        }],
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
            admin_role: true,
        }],
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv_change_auth::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_RESET,
        attributes: tpma_cc(TPM_CC_PCR_RESET, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Pcr,
            user_auth: true,
            admin_role: false,
        }],
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr_reset::execute,
    },
    CommandDescriptor {
        code: TPM_CC_INCREMENTAL_SELF_TEST,
        attributes: tpma_cc(TPM_CC_INCREMENTAL_SELF_TEST, true, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
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
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: stir_random::execute,
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
        sessions_allowed: true,
        nv_access: NvAccess::Read,
        handler: nv_lock::execute_read_lock,
    },
    CommandDescriptor {
        code: TPM_CC_FLUSH_CONTEXT,
        attributes: tpma_cc(TPM_CC_FLUSH_CONTEXT, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: false,
        nv_access: NvAccess::Neither,
        handler: flush_context::execute,
    },
    CommandDescriptor {
        code: TPM_CC_NV_READ_PUBLIC,
        attributes: tpma_cc(TPM_CC_NV_READ_PUBLIC, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::NvIndex,
            user_auth: false,
            admin_role: false,
        }],
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: nv_read::execute_read_public,
    },
    CommandDescriptor {
        code: TPM_CC_GET_CAPABILITY,
        attributes: tpma_cc(TPM_CC_GET_CAPABILITY, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
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
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: get_random::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HASH,
        attributes: tpma_cc(TPM_CC_HASH, false, 0),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
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
        sessions_allowed: true,
        nv_access: NvAccess::Neither,
        handler: pcr_read::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_EXTEND,
        attributes: tpma_cc(TPM_CC_PCR_EXTEND, false, 1),
        physical_presence: false,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::PcrAllowNull,
            user_auth: true,
            admin_role: false,
        }],
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
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvAuth,
                user_auth: true,
                admin_role: false,
            },
            HandleSpec {
                kind: HandleKind::NvIndex,
                user_auth: false,
                admin_role: false,
            },
        ],
        sessions_allowed: true,
        nv_access: NvAccess::Read,
        handler: nv_certify::execute,
    },
];

pub(super) fn find(code: u32) -> Option<&'static CommandDescriptor> {
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
        assert!(find(TPM_CC_PCR_EXTEND + 1).is_none(), "just above the last");
        let registered: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        for code in 0x0000_011eu32..=0x0000_0185 {
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
                TPM_CC_NV_UNDEFINE_SPACE,
                TPM_CC_CHANGE_EPS,
                TPM_CC_HIERARCHY_CHANGE_AUTH,
                TPM_CC_NV_DEFINE_SPACE,
                TPM_CC_PCR_ALLOCATE,
                TPM_CC_CREATE_PRIMARY,
                TPM_CC_NV_GLOBAL_WRITE_LOCK,
                TPM_CC_NV_INCREMENT,
                TPM_CC_NV_SET_BITS,
                TPM_CC_NV_EXTEND,
                TPM_CC_NV_WRITE,
                TPM_CC_NV_WRITE_LOCK,
                TPM_CC_DICTIONARY_ATTACK_PARAMETERS,
                TPM_CC_NV_CHANGE_AUTH,
                TPM_CC_PCR_RESET,
                TPM_CC_INCREMENTAL_SELF_TEST,
                TPM_CC_SELF_TEST,
                TPM_CC_STARTUP,
                TPM_CC_SHUTDOWN,
                TPM_CC_STIR_RANDOM,
                TPM_CC_NV_READ,
                TPM_CC_NV_READ_LOCK,
                TPM_CC_FLUSH_CONTEXT,
                TPM_CC_NV_READ_PUBLIC,
                TPM_CC_GET_CAPABILITY,
                TPM_CC_GET_RANDOM,
                TPM_CC_HASH,
                TPM_CC_PCR_READ,
                TPM_CC_PCR_EXTEND,
                TPM_CC_NV_CERTIFY
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
    fn change_eps_is_the_only_extensive_command() {
        for descriptor in implemented() {
            assert_eq!(
                descriptor.attributes & TPMA_CC_EXTENSIVE != 0,
                descriptor.code == TPM_CC_CHANGE_EPS,
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
        assert!(!descriptor.handles[0].admin_role);
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
        const PP_COMMANDS: [u32; 9] = [
            TPM_CC_NV_UNDEFINE_SPACE_SPECIAL,
            TPM_CC_EVICT_CONTROL,
            TPM_CC_NV_UNDEFINE_SPACE,
            TPM_CC_CHANGE_EPS,
            TPM_CC_HIERARCHY_CHANGE_AUTH,
            TPM_CC_NV_DEFINE_SPACE,
            TPM_CC_PCR_ALLOCATE,
            TPM_CC_CREATE_PRIMARY,
            TPM_CC_NV_GLOBAL_WRITE_LOCK,
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
                !matches!(descriptor.code, TPM_CC_STARTUP | TPM_CC_FLUSH_CONTEXT),
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
