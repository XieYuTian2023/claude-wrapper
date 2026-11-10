//! Bounded local event log. Only structured, non-secret diagnostics are stored.
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{
    notice::{self, Level},
    proxy::{ExitIpError, UnexpectedExitCountry},
};

const LIMIT: usize = 100;
const MAX_BYTES: u64 = 64 * 1024;
const FILE: &str = ".wrapper-events.json";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Block,
    Error,
    Exit,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Self::Block => "Blocked",
            Self::Error => "Error",
            Self::Exit => "Exit",
        }
    }
}

#[derive(Deserialize, Serialize)]
pub enum Event {
    Diagnostic(crate::diagnostic::Report),
    CountryBlocked { observed: String, expected: String },
    IpBlocked { observed: IpAddr, expected: IpAddr },
    UnstableIp { first: IpAddr, observed: IpAddr },
    CredentialBlocked,
    ApiUnavailable,
    ProbeFailed,
    ClientExit(i32),
    OperationFailed,
    Pinned(IpAddr),
    ResetPin,
}

impl Event {
    pub fn category(&self) -> Category {
        match self {
            Self::Diagnostic(report) if report.blocked() => Category::Block,
            Self::Diagnostic(report) if report.passed() => Category::Exit,
            Self::CountryBlocked { .. }
            | Self::IpBlocked { .. }
            | Self::UnstableIp { .. }
            | Self::CredentialBlocked => Category::Block,
            Self::Pinned(_) | Self::ResetPin => Category::Exit,
            _ => Category::Error,
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Diagnostic(report) => report.journal_summary(),
            Self::CountryBlocked { observed, .. } if observed == "CN" => {
                "Region - Mainland China exit detected (CN)".into()
            }
            Self::CountryBlocked { observed, expected } => {
                format!("Region - expected {expected}, observed {observed}")
            }
            Self::IpBlocked { observed, expected } => {
                format!("IP - expected {expected}, observed {observed}")
            }
            Self::UnstableIp { first, observed } => {
                format!("Auto-pin - first saw {first}, then {observed}")
            }
            Self::CredentialBlocked => {
                "Auth - subscription OAuth conflicts with a custom API".into()
            }
            Self::ApiUnavailable => "Network - Claude API HTTPS check failed".into(),
            Self::ProbeFailed => "Network - exit probe failed".into(),
            Self::ClientExit(code) => format!("Client exited with status {code}"),
            Self::OperationFailed => "Operation failed. See the terminal output.".into(),
            Self::Pinned(ip) => format!("Auto-pin - pinned {ip}"),
            Self::ResetPin => "Auto-pin cleared. Waiting for a new probe.".into(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Record {
    pub unix_time: u64,
    pub profile: Option<String>,
    pub operation: String,
    pub event: Event,
}

pub fn read(dir: &Path) -> Result<Vec<Record>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(FILE))
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("could not read Wrapper log"),
    };
    let metadata = owned_file(&file)?;
    ensure!(
        metadata.len() <= MAX_BYTES,
        "Wrapper log exceeds size limit"
    );
    serde_json::from_reader(file.take(MAX_BYTES)).context("invalid Wrapper log")
}

fn owned_file(file: &File) -> Result<fs::Metadata> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() },
        "Wrapper log requires owned regular files"
    );
    Ok(metadata)
}

fn append(dir: &Path, profile: Option<&str>, operation: &str, event: Event) -> Result<()> {
    fs::create_dir_all(dir)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(".wrapper-events.lock"))?;
    owned_file(&lock)?;
    lock.lock()?;
    let mut records = read(dir)?;
    if records.len() >= LIMIT {
        records.drain(..=records.len() - LIMIT);
    }
    records.push(Record {
        unix_time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        profile: profile
            .filter(|name| crate::profile::valid_name(name))
            .map(str::to_owned),
        operation: operation.into(),
        event,
    });
    let mut temporary = NamedTempFile::new_in(dir)?;
    serde_json::to_writer(&mut temporary, &records)?;
    temporary.write_all(b"\n")?;
    temporary
        .persist(dir.join(FILE))
        .map_err(|error| error.error)?;
    Ok(())
}

pub fn record(dir: &Path, profile: Option<&str>, operation: &str, event: Event) {
    if append(dir, profile, operation, event).is_err() {
        notice::emit(
            Level::Warning,
            format_args!("Could not write to the local log"),
        );
    }
}

pub fn failure(dir: &Path, profile: Option<&str>, operation: &str, error: &anyhow::Error) {
    let event = if let Some(country) = error.downcast_ref::<UnexpectedExitCountry>() {
        Event::CountryBlocked {
            observed: country.observed.clone(),
            expected: country.expected.clone(),
        }
    } else if let Some(ip) = error.downcast_ref::<ExitIpError>() {
        match *ip {
            ExitIpError::Mismatch { observed, expected } => Event::IpBlocked { observed, expected },
            ExitIpError::Unstable { first, observed } => Event::UnstableIp { first, observed },
        }
    } else {
        let chain = format!("{error:#}");
        if chain.contains("explicit Claude subscription OAuth credential") {
            Event::CredentialBlocked
        } else if chain.contains("Claude API HTTPS probe failed") {
            Event::ApiUnavailable
        } else if chain.contains("probe") || chain.contains("VPN preflight failed") {
            Event::ProbeFailed
        } else {
            Event::OperationFailed
        }
    };
    record(dir, profile, operation, event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_policy_blocks_without_persisting_untrusted_error_text() {
        let root = tempfile::tempdir().unwrap();
        let error = anyhow::Error::new(ExitIpError::Mismatch {
            observed: "203.0.113.10".parse().unwrap(),
            expected: "203.0.113.11".parse().unwrap(),
        })
        .context("untrusted context with sensitive-value");
        failure(root.path(), Some("lab"), "run", &error);
        failure(
            root.path(),
            Some("../sensitive-value"),
            "doctor",
            &anyhow::anyhow!("sensitive-value"),
        );
        let records = read(root.path()).unwrap();
        assert!(matches!(records[0].event, Event::IpBlocked { .. }));
        assert!(matches!(records[1].event, Event::OperationFailed));
        assert!(records[1].profile.is_none());
        assert!(
            !fs::read_to_string(root.path().join(FILE))
                .unwrap()
                .contains("sensitive-value")
        );
    }
}
