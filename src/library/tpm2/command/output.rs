pub(super) struct CommandOutput {
    parameters: Vec<u8>,
}

impl CommandOutput {
    pub(super) fn empty() -> Self {
        Self {
            parameters: Vec::new(),
        }
    }

    pub(super) fn from_parameters(parameters: Vec<u8>) -> Self {
        Self { parameters }
    }

    pub(super) fn into_parameters(self) -> Vec<u8> {
        self.parameters
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_output_carries_no_parameters() {
        assert!(CommandOutput::empty().into_parameters().is_empty());
    }

    #[test]
    fn encoded_parameters_survive_the_wrapper_unchanged() {
        let encoded = vec![0x00, 0x01, 0x02, 0xff, 0x80, 0x00];
        assert_eq!(
            CommandOutput::from_parameters(encoded.clone()).into_parameters(),
            encoded
        );
    }
}
