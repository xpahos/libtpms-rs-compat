use std::fs;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::scalar::ScalarPair;
use crate::scenario::Scenario;

pub fn content_sha256(scenario: Scenario, pair: &ScalarPair) -> String {
    let (low, high) = pair.unordered_key();
    let mut hasher = Sha256::new();
    hasher.update(b"tpms-timing-candidate-content/v2\0");
    hasher.update(scenario.name().as_bytes());
    hasher.update([0]);
    hasher.update(low.bytes());
    hasher.update(high.bytes());
    hex::encode(hasher.finalize())
}

pub fn artifact_stem(scenario: Scenario, pair: &ScalarPair) -> String {
    format!(
        "{}-{}",
        scenario.name(),
        &content_sha256(scenario, pair)[..24]
    )
}

pub fn is_plain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 200
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '^'))
        && !label.starts_with('.')
}

pub fn display_label(label: &str) -> String {
    if is_plain_label(label) {
        label.to_string()
    } else {
        format!("{label:?}")
    }
}

pub fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("refusing to overwrite {}: {e}", path.display()),
            )
        })?;
    file.write_all(bytes)
}

pub fn create_new_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("refusing to overwrite {}: {e}", path.display()),
            )
        })
}

pub fn create_new_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "refusing to reuse existing directory {}: {e}",
                path.display()
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::Scalar521;

    #[test]
    fn identity_ignores_orientation_but_not_scenario_or_content() {
        let a = Scalar521::from_u128(5).unwrap();
        let b = Scalar521::from_u128(9).unwrap();
        let c = Scalar521::from_u128(10).unwrap();
        let ab = ScalarPair { a, b };
        let ba = ScalarPair { a: b, b: a };
        let ac = ScalarPair { a, b: c };
        assert_eq!(
            artifact_stem(Scenario::EcdhP521, &ab),
            artifact_stem(Scenario::EcdhP521, &ba)
        );
        assert_ne!(
            artifact_stem(Scenario::EcdhP521, &ab),
            artifact_stem(Scenario::EcdhP521, &ac)
        );
        assert_ne!(
            artifact_stem(Scenario::EcdhP521, &ab),
            artifact_stem(Scenario::ControlPositive, &ab)
        );
        assert!(is_plain_label(&artifact_stem(Scenario::EcdhP521, &ab)));
    }

    #[test]
    fn labels_never_become_paths() {
        assert!(!is_plain_label("../../etc/passwd"));
        assert!(!is_plain_label("a/b"));
        assert!(!is_plain_label(".hidden"));
        assert!(is_plain_label("seed-limb-2^64-minus-1-vs-2^64"));
    }

    #[test]
    fn writes_refuse_to_overwrite() {
        let dir = std::env::temp_dir().join(format!("tpms-artifacts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_new_dir(&dir).unwrap();
        assert!(create_new_dir(&dir).is_err());
        write_new(&dir.join("x"), b"1").unwrap();
        assert!(write_new(&dir.join("x"), b"2").is_err());
        assert_eq!(fs::read(dir.join("x")).unwrap(), b"1");
        fs::remove_dir_all(&dir).unwrap();
    }
}
