use super::marshal::BlobReader;
use super::persistent::{PersistentAllError, StateSection};

pub(super) const COMMAND_COUNT: usize = 129;

const COMPRESSED_UNTIL_VERSION: u16 = 4;

pub(super) fn parse_command_bitmap<'a>(
    reader: &mut BlobReader<'a>,
    blob_version: u16,
    section: StateSection,
    capacity: usize,
) -> Result<(bool, &'a [u8]), PersistentAllError> {
    let array_size = reader
        .read_u16()
        .map_err(|_| PersistentAllError::Truncated { section })?;
    let compressed = blob_version <= COMPRESSED_UNTIL_VERSION;

    if !compressed && usize::from(array_size) > capacity {
        return Err(PersistentAllError::CommandArraySizeExceeded {
            section,
            actual: array_size,
            maximum: capacity,
        });
    }

    let array = reader
        .take(usize::from(array_size))
        .map_err(|_| PersistentAllError::Truncated { section })?;
    Ok((compressed, array))
}
