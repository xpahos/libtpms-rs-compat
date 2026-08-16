use crate::ffi_types::TpmResult;

use super::super::hierarchy::is_hierarchy_auth_handle;
use super::super::runtime::Tpm2Runtime;
use super::super::volatile::IMPLEMENTATION_PCR;
use super::change_eps;
use super::dispatcher::CommandFrame;
use super::get_capability;
use super::get_random;
use super::hash;
use super::hierarchy_change_auth;
use super::incremental_self_test;
use super::output::CommandOutput;
use super::pcr_allocate;
use super::pcr_extend;
use super::pcr_read;
use super::pcr_reset;
use super::self_test;
use super::shutdown;
use super::startup;
use super::stir_random;

pub(in crate::library::tpm2) const TPM_CC_CHANGE_EPS: u32 = 0x0000_0124;
pub(in crate::library::tpm2) const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;
pub(in crate::library::tpm2) const TPM_CC_PCR_ALLOCATE: u32 = 0x0000_012b;
pub(in crate::library::tpm2) const TPM_CC_PCR_RESET: u32 = 0x0000_013d;
pub(in crate::library::tpm2) const TPM_CC_INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
pub(in crate::library::tpm2) const TPM_CC_SELF_TEST: u32 = 0x0000_0143;
pub(in crate::library::tpm2) const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub(in crate::library::tpm2) const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub(in crate::library::tpm2) const TPM_CC_STIR_RANDOM: u32 = 0x0000_0146;
pub(in crate::library::tpm2) const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;
pub(in crate::library::tpm2) const TPM_CC_GET_RANDOM: u32 = 0x0000_017b;
pub(in crate::library::tpm2) const TPM_CC_HASH: u32 = 0x0000_017d;
pub(in crate::library::tpm2) const TPM_CC_PCR_READ: u32 = 0x0000_017e;
pub(in crate::library::tpm2) const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;

pub(super) use super::super::hierarchy::TPM_RH_NULL;
use super::super::hierarchy::TPM_RH_PLATFORM;

const TPMA_CC_COMMAND_INDEX_MASK: u32 = 0x0000_ffff;
const TPMA_CC_NV: u32 = 1 << 22;
const TPMA_CC_EXTENSIVE: u32 = 1 << 23;
const TPMA_CC_C_HANDLES_SHIFT: u32 = 25;

const fn tpma_cc(code: u32, nv: bool, command_handles: u32) -> u32 {
    (code & TPMA_CC_COMMAND_INDEX_MASK)
        | if nv { TPMA_CC_NV } else { 0 }
        | (command_handles << TPMA_CC_C_HANDLES_SHIFT)
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
    Platform,
    Pcr,
    PcrAllowNull,
}

impl HandleKind {
    pub(super) fn accepts(self, handle: u32) -> bool {
        match self {
            Self::HierarchyAuth => is_hierarchy_auth_handle(handle),
            Self::Platform => handle == TPM_RH_PLATFORM,
            Self::Pcr => (handle as usize) < IMPLEMENTATION_PCR,
            Self::PcrAllowNull => (handle as usize) < IMPLEMENTATION_PCR || handle == TPM_RH_NULL,
        }
    }
}

pub(super) struct HandleSpec {
    pub(super) kind: HandleKind,
    pub(super) user_auth: bool,
}

pub(in crate::library::tpm2) struct CommandDescriptor {
    pub(in crate::library::tpm2) code: u32,
    pub(in crate::library::tpm2) attributes: u32,
    pub(super) lifecycle: CommandLifecycle,
    pub(super) handles: &'static [HandleSpec],
    pub(super) sessions_allowed: bool,
    pub(super) handler: CommandHandler,
}

static COMMANDS: &[CommandDescriptor] = &[
    CommandDescriptor {
        code: TPM_CC_CHANGE_EPS,
        attributes: tpma_cc(TPM_CC_CHANGE_EPS, true, 1) | TPMA_CC_EXTENSIVE,
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Platform,
            user_auth: true,
        }],
        sessions_allowed: true,
        handler: change_eps::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HIERARCHY_CHANGE_AUTH,
        attributes: tpma_cc(TPM_CC_HIERARCHY_CHANGE_AUTH, true, 1),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::HierarchyAuth,
            user_auth: true,
        }],
        sessions_allowed: true,
        handler: hierarchy_change_auth::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_ALLOCATE,
        attributes: tpma_cc(TPM_CC_PCR_ALLOCATE, true, 1),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Platform,
            user_auth: true,
        }],
        sessions_allowed: true,
        handler: pcr_allocate::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_RESET,
        attributes: tpma_cc(TPM_CC_PCR_RESET, false, 1),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::Pcr,
            user_auth: true,
        }],
        sessions_allowed: true,
        handler: pcr_reset::execute,
    },
    CommandDescriptor {
        code: TPM_CC_INCREMENTAL_SELF_TEST,
        attributes: tpma_cc(TPM_CC_INCREMENTAL_SELF_TEST, true, 0),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: true,
        handler: incremental_self_test::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SELF_TEST,
        attributes: tpma_cc(TPM_CC_SELF_TEST, true, 0),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: true,
        handler: self_test::execute,
    },
    CommandDescriptor {
        code: TPM_CC_STARTUP,
        attributes: tpma_cc(TPM_CC_STARTUP, true, 0),
        lifecycle: CommandLifecycle::RequiresNotStarted,
        handles: &[],
        sessions_allowed: false,
        handler: startup::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SHUTDOWN,
        attributes: tpma_cc(TPM_CC_SHUTDOWN, true, 0),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: true,
        handler: shutdown::execute,
    },
    CommandDescriptor {
        code: TPM_CC_STIR_RANDOM,
        attributes: tpma_cc(TPM_CC_STIR_RANDOM, true, 0),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: true,
        handler: stir_random::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_CAPABILITY,
        attributes: tpma_cc(TPM_CC_GET_CAPABILITY, false, 0),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: true,
        handler: get_capability::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_RANDOM,
        attributes: tpma_cc(TPM_CC_GET_RANDOM, false, 0),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: true,
        handler: get_random::execute,
    },
    CommandDescriptor {
        code: TPM_CC_HASH,
        attributes: tpma_cc(TPM_CC_HASH, false, 0),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: true,
        handler: hash::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_READ,
        attributes: tpma_cc(TPM_CC_PCR_READ, false, 0),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[],
        sessions_allowed: true,
        handler: pcr_read::execute,
    },
    CommandDescriptor {
        code: TPM_CC_PCR_EXTEND,
        attributes: tpma_cc(TPM_CC_PCR_EXTEND, false, 1),
        lifecycle: CommandLifecycle::RequiresStarted,
        handles: &[HandleSpec {
            kind: HandleKind::PcrAllowNull,
            user_auth: true,
        }],
        sessions_allowed: true,
        handler: pcr_extend::execute,
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
            find(TPM_CC_CHANGE_EPS - 1).is_none(),
            "just below the first"
        );
        assert!(
            find(TPM_CC_CHANGE_EPS + 1).is_none(),
            "between ChangeEPS and HierarchyChangeAuth"
        );
        assert!(
            find(TPM_CC_HIERARCHY_CHANGE_AUTH - 1).is_none(),
            "just below HierarchyChangeAuth"
        );
        assert!(
            find(TPM_CC_HIERARCHY_CHANGE_AUTH + 1).is_none(),
            "between HierarchyChangeAuth and PCR_Allocate"
        );
        assert!(
            find(TPM_CC_PCR_ALLOCATE - 1).is_none(),
            "just below PCR_Allocate"
        );
        assert!(
            find(TPM_CC_PCR_ALLOCATE + 1).is_none(),
            "between PCR_Allocate and PCR_Reset"
        );
        assert!(find(TPM_CC_PCR_RESET - 1).is_none(), "just below PCR_Reset");
        assert!(
            find(TPM_CC_PCR_RESET + 1).is_none(),
            "between PCR_Reset and IncrementalSelfTest"
        );
        assert!(
            find(TPM_CC_INCREMENTAL_SELF_TEST - 1).is_none(),
            "just below IncrementalSelfTest"
        );
        assert!(
            find(TPM_CC_STIR_RANDOM + 1).is_none(),
            "between StirRandom and GetCapability"
        );
        assert!(
            find(TPM_CC_GET_CAPABILITY - 1).is_none(),
            "just below GetCapability"
        );
        assert!(
            find(TPM_CC_GET_RANDOM + 1).is_none(),
            "between GetRandom and Hash"
        );
        assert!(find(TPM_CC_HASH - 1).is_none(), "just below Hash");
        assert!(
            find(TPM_CC_PCR_READ + 1).is_none(),
            "between PCR_Read and PCR_Extend"
        );
        assert!(find(TPM_CC_PCR_EXTEND - 1).is_none(), "just below the last");
        assert!(find(TPM_CC_PCR_EXTEND + 1).is_none(), "just above the last");
        assert!(find(0xffff_ffff).is_none(), "above all entries");
    }

    #[test]
    fn iteration_returns_every_implemented_command_exactly_once() {
        let codes: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        assert_eq!(
            codes,
            [
                TPM_CC_CHANGE_EPS,
                TPM_CC_HIERARCHY_CHANGE_AUTH,
                TPM_CC_PCR_ALLOCATE,
                TPM_CC_PCR_RESET,
                TPM_CC_INCREMENTAL_SELF_TEST,
                TPM_CC_SELF_TEST,
                TPM_CC_STARTUP,
                TPM_CC_SHUTDOWN,
                TPM_CC_STIR_RANDOM,
                TPM_CC_GET_CAPABILITY,
                TPM_CC_GET_RANDOM,
                TPM_CC_HASH,
                TPM_CC_PCR_READ,
                TPM_CC_PCR_EXTEND
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
    fn the_handle_count_attribute_matches_the_declared_handles() {
        for descriptor in implemented() {
            assert_eq!(
                descriptor.attributes >> 25,
                descriptor.handles.len() as u32,
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn only_startup_forbids_an_authorization_area() {
        for descriptor in implemented() {
            assert_eq!(
                descriptor.sessions_allowed,
                descriptor.code != TPM_CC_STARTUP,
                "code {:#x}",
                descriptor.code
            );
        }
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
