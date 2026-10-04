use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const RUN_FORMAT: &str = "tpms-timing-run/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunState {
    InProgress,
    Completed,
    Incomplete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    pub format: String,
    pub run_id: String,
    pub command: String,
    pub state: RunState,
    pub started_utc: String,
    pub finished_utc: Option<String>,
    pub detail: Option<String>,
    pub argv: Vec<String>,
}

pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

pub struct Run {
    pub dir: PathBuf,
    pub info: RunInfo,
}

impl Run {
    pub fn create(out_dir: &Path, command: &str, name: Option<&str>) -> std::io::Result<Self> {
        let started = utc_now();
        let nonce = format!(
            "{:08x}",
            std::process::id()
                ^ (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0))
        );
        let run_id = match name {
            Some(name) => format!("{started}-{command}-{name}-{nonce}"),
            None => format!("{started}-{command}-{nonce}"),
        };
        let dir = out_dir.join(&run_id);
        if dir.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("run directory {} already exists", dir.display()),
            ));
        }
        fs::create_dir_all(&dir)?;
        let run = Self {
            dir,
            info: RunInfo {
                format: RUN_FORMAT.into(),
                run_id,
                command: command.into(),
                state: RunState::InProgress,
                started_utc: started,
                finished_utc: None,
                detail: None,
                argv: std::env::args().collect(),
            },
        };
        run.write_info()?;
        Ok(run)
    }

    fn write_info(&self) -> std::io::Result<()> {
        fs::write(
            self.dir.join("run.json"),
            serde_json::to_vec_pretty(&self.info).unwrap(),
        )
    }

    pub fn write_json<T: Serialize>(&self, name: &str, value: &T) -> std::io::Result<()> {
        fs::write(
            self.dir.join(name),
            serde_json::to_vec_pretty(value).unwrap(),
        )
    }

    pub fn finish(&mut self, state: RunState, detail: Option<String>) -> std::io::Result<()> {
        self.info.state = state;
        self.info.finished_utc = Some(utc_now());
        self.info.detail = detail;
        self.write_info()
    }
}

pub fn read_run_info(dir: &Path) -> Result<RunInfo, String> {
    let path = dir.join("run.json");
    let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let info: RunInfo =
        serde_json::from_slice(&bytes).map_err(|e| format!("malformed {}: {e}", path.display()))?;
    if info.format != RUN_FORMAT {
        return Err(format!(
            "{}: unsupported format {:?}",
            path.display(),
            info.format
        ));
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_compact_utc() {
        let now = utc_now();
        assert_eq!(now.len(), 16);
        assert!(now.ends_with('Z'));
        assert_eq!(&now[8..9], "T");
    }
}
