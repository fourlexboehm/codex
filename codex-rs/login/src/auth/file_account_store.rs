use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;
use tracing::warn;

use super::storage::AuthDotJson;
use super::storage::read_auth_json_file;

pub(super) const LEGACY_ACTIVE_AUTH_FILE_NAME: &str = "auth.json";
const ACTIVE_AUTH_POINTER_FILE_NAME: &str = ".active-auth.json";
const AUTH_FILE_PREFIX: &str = "auth-";
const AUTH_FILE_SUFFIX: &str = ".json";

#[derive(Debug)]
pub(super) struct LoadedFileAuth {
    pub auth_file: PathBuf,
    pub auth_dot_json: AuthDotJson,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActiveAuthPointer {
    active_auth_file: String,
}

pub(super) fn get_legacy_auth_file(codex_home: &Path) -> PathBuf {
    codex_home.join(LEGACY_ACTIVE_AUTH_FILE_NAME)
}

pub(super) fn load_active_file_auth(codex_home: &Path) -> io::Result<Option<LoadedFileAuth>> {
    let Some(auth_file) = active_auth_file_path(codex_home)? else {
        return Ok(None);
    };

    let auth_dot_json = read_auth_json_file(&auth_file)?;
    Ok(Some(LoadedFileAuth {
        auth_file,
        auth_dot_json,
    }))
}

pub(super) fn active_auth_file_path(codex_home: &Path) -> io::Result<Option<PathBuf>> {
    migrate_legacy_auth_file_if_needed(codex_home)?;

    let Some(file_name) = read_active_auth_pointer(codex_home)? else {
        return Ok(None);
    };

    let auth_file = codex_home.join(file_name);
    if auth_file.is_file() {
        Ok(Some(auth_file))
    } else {
        warn!(
            path = %auth_file.display(),
            "active auth pointer references a missing auth file"
        );
        Ok(None)
    }
}

pub(super) fn active_auth_file_name(codex_home: &Path) -> io::Result<Option<String>> {
    let Some(auth_file) = active_auth_file_path(codex_home)? else {
        return Ok(None);
    };

    Ok(auth_file
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .map(str::to_string))
}

pub(super) fn save_new_active_auth_file(
    codex_home: &Path,
    auth_dot_json: &AuthDotJson,
) -> io::Result<PathBuf> {
    migrate_legacy_auth_file_if_needed(codex_home)?;

    let auth_file = next_auth_file_path(codex_home);
    super::storage::write_auth_json_file(&auth_file, auth_dot_json)?;
    write_active_auth_pointer(codex_home, auth_file_name(&auth_file)?)?;
    Ok(auth_file)
}

pub(super) fn save_active_auth_file(
    codex_home: &Path,
    auth_dot_json: &AuthDotJson,
) -> io::Result<PathBuf> {
    let Some(auth_file) = active_auth_file_path(codex_home)? else {
        return save_new_active_auth_file(codex_home, auth_dot_json);
    };

    super::storage::write_auth_json_file(&auth_file, auth_dot_json)?;
    Ok(auth_file)
}

pub(super) fn delete_active_auth_file(codex_home: &Path) -> io::Result<bool> {
    migrate_legacy_auth_file_if_needed(codex_home)?;

    let current_auth_file = read_active_auth_pointer(codex_home)?;
    let pointer_removed = delete_active_auth_pointer(codex_home)?;
    let Some(file_name) = current_auth_file else {
        return Ok(pointer_removed);
    };

    let auth_file = codex_home.join(file_name);
    match std::fs::remove_file(&auth_file) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(pointer_removed),
        Err(err) => Err(err),
    }
}

pub(super) fn list_saved_auth_files(codex_home: &Path) -> io::Result<Vec<PathBuf>> {
    migrate_legacy_auth_file_if_needed(codex_home)?;

    let read_dir = match std::fs::read_dir(codex_home) {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut auth_files = Vec::new();
    for entry_result in read_dir {
        let entry = entry_result?;
        if !entry.file_type()?.is_file() {
            continue;
        }

        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|file_name| file_name.to_str()) else {
            continue;
        };
        if is_saved_auth_file_name(file_name) {
            auth_files.push(path);
        }
    }

    Ok(auth_files)
}

pub(super) fn switch_active_auth_file(codex_home: &Path, account_id: &str) -> io::Result<bool> {
    migrate_legacy_auth_file_if_needed(codex_home)?;
    validate_saved_auth_file_name(account_id)?;

    let auth_file = codex_home.join(account_id);
    if !auth_file.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("saved auth file not found: {account_id}"),
        ));
    }

    if active_auth_file_name(codex_home)?.as_deref() == Some(account_id) {
        return Ok(false);
    }

    write_active_auth_pointer(codex_home, account_id)?;
    Ok(true)
}

pub(super) fn is_saved_auth_file_name(file_name: &str) -> bool {
    file_name.starts_with(AUTH_FILE_PREFIX) && file_name.ends_with(AUTH_FILE_SUFFIX)
}

pub(super) fn validate_saved_auth_file_name(account_id: &str) -> io::Result<()> {
    let file_name = Path::new(account_id)
        .file_name()
        .and_then(|file_name| file_name.to_str());
    if file_name == Some(account_id) && is_saved_auth_file_name(account_id) {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid saved auth file name: {account_id}"),
    ))
}

pub(super) fn write_json_file_atomically<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let temp_path = next_temp_path(path);
    let json_data = serde_json::to_string_pretty(value).map_err(io::Error::other)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&temp_path)?;
    file.write_all(json_data.as_bytes())?;
    file.flush()?;
    drop(file);

    std::fs::rename(&temp_path, path)?;
    Ok(())
}

fn migrate_legacy_auth_file_if_needed(codex_home: &Path) -> io::Result<()> {
    if read_active_auth_pointer_if_present(codex_home)?.is_some() {
        return Ok(());
    }

    let legacy_auth_file = get_legacy_auth_file(codex_home);
    if !legacy_auth_file.is_file() {
        return Ok(());
    }

    let migrated_auth_file = next_auth_file_path(codex_home);
    std::fs::rename(&legacy_auth_file, &migrated_auth_file)?;

    if let Err(err) = write_active_auth_pointer(codex_home, auth_file_name(&migrated_auth_file)?) {
        if let Err(restore_err) = std::fs::rename(&migrated_auth_file, &legacy_auth_file) {
            return Err(io::Error::other(format!(
                "failed to migrate legacy auth file: {err}; failed to restore legacy auth file: {restore_err}"
            )));
        }
        return Err(err);
    }

    Ok(())
}

fn read_active_auth_pointer(codex_home: &Path) -> io::Result<Option<String>> {
    let Some(file_name) = read_active_auth_pointer_if_present(codex_home)? else {
        return Ok(None);
    };
    validate_saved_auth_file_name(&file_name)?;
    Ok(Some(file_name))
}

fn read_active_auth_pointer_if_present(codex_home: &Path) -> io::Result<Option<String>> {
    let pointer_path = active_auth_pointer_path(codex_home);
    let mut file = match std::fs::File::open(&pointer_path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let pointer: ActiveAuthPointer = serde_json::from_str(&contents).map_err(io::Error::other)?;
    Ok(Some(pointer.active_auth_file))
}

fn write_active_auth_pointer(codex_home: &Path, active_auth_file: &str) -> io::Result<()> {
    validate_saved_auth_file_name(active_auth_file)?;
    let pointer = ActiveAuthPointer {
        active_auth_file: active_auth_file.to_string(),
    };
    write_json_file_atomically(&active_auth_pointer_path(codex_home), &pointer)
}

fn delete_active_auth_pointer(codex_home: &Path) -> io::Result<bool> {
    let pointer_path = active_auth_pointer_path(codex_home);
    match std::fs::remove_file(pointer_path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn auth_file_name(auth_file: &Path) -> io::Result<&str> {
    auth_file
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .ok_or_else(|| io::Error::other("auth file name should be valid UTF-8"))
}

fn next_auth_file_path(codex_home: &Path) -> PathBuf {
    loop {
        let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
        let mut random_bytes = [0u8; 4];
        rand::rng().fill_bytes(&mut random_bytes);
        let suffix = u32::from_be_bytes(random_bytes);
        let path = codex_home.join(format!(
            "{AUTH_FILE_PREFIX}{timestamp}-{suffix:08x}{AUTH_FILE_SUFFIX}"
        ));
        if !path.exists() {
            return path;
        }
    }
}

fn active_auth_pointer_path(codex_home: &Path) -> PathBuf {
    codex_home.join(ACTIVE_AUTH_POINTER_FILE_NAME)
}

fn next_temp_path(path: &Path) -> PathBuf {
    loop {
        let mut random_bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut random_bytes);
        let suffix = u64::from_be_bytes(random_bytes);
        let file_name = path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .unwrap_or("auth");
        let temp_path = path.with_file_name(format!(".{file_name}.tmp-{suffix:016x}"));
        if !temp_path.exists() {
            return temp_path;
        }
    }
}
