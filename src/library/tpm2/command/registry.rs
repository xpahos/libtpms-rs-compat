use super::super::runtime::Tpm2Runtime;
use super::get_capability;
use super::header::{Command, Response};
use super::shutdown;
use super::startup;

pub(in crate::library::tpm2) const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub(in crate::library::tpm2) const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub(in crate::library::tpm2) const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;

const TPMA_CC_COMMAND_INDEX_MASK: u32 = 0x0000_ffff;
const TPMA_CC_NV: u32 = 1 << 22;

const fn tpma_cc(code: u32, nv: bool) -> u32 {
    (code & TPMA_CC_COMMAND_INDEX_MASK) | if nv { TPMA_CC_NV } else { 0 }
}

pub(super) type CommandHandler = for<'a> fn(&mut Tpm2Runtime, &Command<'a>) -> Response;

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

// TODO: Move session eligibility into CommandDescriptor after session processing is centralized.
pub(in crate::library::tpm2) struct CommandDescriptor {
    pub(in crate::library::tpm2) code: u32,
    pub(in crate::library::tpm2) attributes: u32,
    pub(super) lifecycle: CommandLifecycle,
    pub(super) handler: CommandHandler,
}

static COMMANDS: &[CommandDescriptor] = &[
    CommandDescriptor {
        code: TPM_CC_STARTUP,
        attributes: tpma_cc(TPM_CC_STARTUP, true),
        lifecycle: CommandLifecycle::RequiresNotStarted,
        handler: startup::execute,
    },
    CommandDescriptor {
        code: TPM_CC_SHUTDOWN,
        attributes: tpma_cc(TPM_CC_SHUTDOWN, true),
        lifecycle: CommandLifecycle::RequiresStarted,
        handler: shutdown::execute,
    },
    CommandDescriptor {
        code: TPM_CC_GET_CAPABILITY,
        attributes: tpma_cc(TPM_CC_GET_CAPABILITY, false),
        lifecycle: CommandLifecycle::RequiresStarted,
        handler: get_capability::execute,
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
        assert_eq!(find(TPM_CC_STARTUP).map(|d| d.code), Some(TPM_CC_STARTUP));
        assert_eq!(find(TPM_CC_SHUTDOWN).map(|d| d.code), Some(TPM_CC_SHUTDOWN));
        assert_eq!(
            find(TPM_CC_GET_CAPABILITY).map(|d| d.code),
            Some(TPM_CC_GET_CAPABILITY)
        );
    }

    #[test]
    fn lookup_rejects_unregistered_command_codes() {
        assert!(find(0x0000_0000).is_none(), "below all entries");
        assert!(find(TPM_CC_STARTUP - 1).is_none(), "just below the first");
        assert!(find(TPM_CC_SHUTDOWN + 1).is_none(), "between the entries");
        assert!(
            find(TPM_CC_GET_CAPABILITY - 1).is_none(),
            "just below the last"
        );
        assert!(
            find(TPM_CC_GET_CAPABILITY + 1).is_none(),
            "just above the last"
        );
        assert!(find(0xffff_ffff).is_none(), "above all entries");
    }

    #[test]
    fn iteration_returns_every_implemented_command_exactly_once() {
        let codes: Vec<u32> = implemented().map(|descriptor| descriptor.code).collect();
        assert_eq!(
            codes,
            [TPM_CC_STARTUP, TPM_CC_SHUTDOWN, TPM_CC_GET_CAPABILITY]
        );
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
