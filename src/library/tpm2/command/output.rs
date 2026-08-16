pub(super) struct CommandOutput {
    handles: Vec<u32>,
    parameters: Vec<u8>,
}

impl CommandOutput {
    pub(super) fn empty() -> Self {
        Self {
            handles: Vec::new(),
            parameters: Vec::new(),
        }
    }

    pub(super) fn from_parameters(parameters: Vec<u8>) -> Self {
        Self {
            handles: Vec::new(),
            parameters,
        }
    }

    pub(super) fn with_handle(handle: u32, parameters: Vec<u8>) -> Self {
        Self {
            handles: vec![handle],
            parameters,
        }
    }

    pub(super) fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        let mut handles = Vec::with_capacity(self.handles.len() * 4);
        for handle in &self.handles {
            handles.extend_from_slice(&handle.to_be_bytes());
        }
        (handles, self.parameters)
    }

    #[cfg(test)]
    pub(super) fn into_parameters(self) -> Vec<u8> {
        self.parameters
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_output_carries_no_handles_and_no_parameters() {
        let (handles, parameters) = CommandOutput::empty().into_parts();
        assert!(handles.is_empty());
        assert!(parameters.is_empty());
    }

    #[test]
    fn encoded_parameters_survive_the_wrapper_unchanged() {
        let encoded = vec![0x00, 0x01, 0x02, 0xff, 0x80, 0x00];
        assert_eq!(
            CommandOutput::from_parameters(encoded.clone()).into_parameters(),
            encoded
        );
        let (handles, parameters) = CommandOutput::from_parameters(encoded.clone()).into_parts();
        assert!(handles.is_empty(), "no response handle by default");
        assert_eq!(parameters, encoded);
    }

    #[test]
    fn a_response_handle_is_encoded_big_endian_ahead_of_the_parameters() {
        let (handles, parameters) =
            CommandOutput::with_handle(0x8000_0000, vec![0xaa, 0xbb]).into_parts();
        assert_eq!(handles, [0x80, 0x00, 0x00, 0x00]);
        assert_eq!(parameters, [0xaa, 0xbb]);
    }
}
