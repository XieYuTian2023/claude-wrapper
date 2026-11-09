use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value};
use tempfile::NamedTempFile;

fn private_directory(path: &Path) -> Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() },
        "Claude configuration directory must be an owned directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Initialize only the wrapper-owned client state. Project paths and HOME are untouched.
pub fn prepare(directory: &Path, configured_id: Option<&str>) -> Result<String> {
    let parent = directory
        .parent()
        .context("client configuration parent missing")?;
    private_directory(parent)?;
    private_directory(directory)?;
    let lock: File = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join(".wrapper-init.lock"))?;
    lock.lock()
        .context("could not lock client configuration initialization")?;

    let path = directory.join(".claude.json");
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() },
            "client configuration must be an owned file without shared hard or symbolic links"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    let mut value: Map<String, Value> = match fs::read_to_string(&path) {
        Ok(text) => {
            serde_json::from_str(&text).context("client configuration is not a JSON object")?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Map::new(),
        Err(error) => return Err(error).context("could not read client configuration"),
    };
    let existing = value.get("userID").and_then(Value::as_str);
    let device_id = match configured_id {
        Some(device_id) => device_id.to_owned(),
        None => match existing {
            Some(device_id)
                if device_id.len() == 64
                    && device_id.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
            {
                device_id.to_ascii_lowercase()
            }
            _ => crate::profile::new_device_id()?,
        },
    };
    if existing != Some(device_id.as_str()) {
        value.insert("userID".into(), Value::String(device_id.clone()));
        let mut temporary = NamedTempFile::new_in(directory)?;
        serde_json::to_writer_pretty(&mut temporary, &value)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&path)
            .map_err(|error| error.error)
            .context("could not atomically initialize client identity")?;
    }
    Ok(device_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_legacy_initialization_keeps_one_id_and_other_settings() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("clients/a");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(".claude.json"),
            br#"{"other":{"keep":true}}"#,
        )
        .unwrap();
        let threads = (0..6)
            .map(|_| {
                let directory = directory.clone();
                std::thread::spawn(move || prepare(&directory, None).unwrap())
            })
            .collect::<Vec<_>>();
        let ids = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 1);
        let data: Value =
            serde_json::from_slice(&fs::read(directory.join(".claude.json")).unwrap()).unwrap();
        assert_eq!(data["other"]["keep"], true);
        assert_eq!(
            data["userID"].as_str(),
            ids.iter().next().map(String::as_str)
        );
    }

    #[test]
    fn client_state_cannot_share_a_hard_link_between_profiles() {
        let root = tempfile::tempdir().unwrap();
        let a = root.path().join("clients/a");
        let b = root.path().join("clients/b");
        prepare(&a, Some(&"a".repeat(64))).unwrap();
        fs::create_dir(&b).unwrap();
        fs::hard_link(a.join(".claude.json"), b.join(".claude.json")).unwrap();
        assert!(prepare(&b, Some(&"b".repeat(64))).is_err());
        let original: Value =
            serde_json::from_slice(&fs::read(a.join(".claude.json")).unwrap()).unwrap();
        assert_eq!(original["userID"], "a".repeat(64));
    }
}
