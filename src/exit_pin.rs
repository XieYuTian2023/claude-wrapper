//! Persist only the IP observed by an opted-in automatic exit check.
use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use tempfile::NamedTempFile;

pub const SAMPLES: usize = 3;
pub const PREFIX: &str = ".exit-pin-";

pub fn read(path: &Path) -> Result<Option<IpAddr>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("could not open automatic exit pin"),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() },
        "automatic exit pin must be an owned regular file"
    );
    let mut content = String::new();
    file.take(65).read_to_string(&mut content)?;
    ensure!(content.len() <= 64, "automatic exit pin is too large");
    Ok(Some(content.trim().parse().context(
        "invalid automatic exit pin; reset it before relearning",
    )?))
}

pub fn establish(path: &Path, observed: IpAddr) -> Result<IpAddr> {
    let directory = path.parent().context("exit pin directory missing")?;
    let mut pending = NamedTempFile::new_in(directory)?;
    writeln!(pending, "{observed}")?;
    pending.as_file().sync_all()?;
    match pending.persist_noclobber(path) {
        Ok(_) => {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix(PREFIX));
            crate::journal::record(
                directory,
                name,
                "preflight",
                crate::journal::Event::Pinned(observed),
            );
            Ok(observed)
        }
        Err(error) if error.error.kind() == ErrorKind::AlreadyExists => {
            read(path)?.context("automatic exit pin was reset during learning; retry the check")
        }
        Err(error) => Err(error.error).context("could not save automatic exit pin"),
    }
}

pub fn reset(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("could not reset automatic exit pin"),
    }
}
