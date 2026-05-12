#![forbid(unsafe_code)]

//! Audit file management for Aegis.
//!
//! Provides directory layout, secure file writing, and writable-check helpers.
//! Plans, AI reviews, and policy results are persisted under `$XDG_DATA_HOME/aegis`
//! (or `$HOME/.local/share/aegis`). Temporary caches live under
//! `$XDG_CACHE_HOME/aegis` (or `$HOME/.cache/aegis`).
//!
//! Files are written with mode `0o600` on Unix to prevent information leaks on
//! multi-user systems.

use anyhow::{Context, Result};
use serde::Serialize;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// Return the data directory for Aegis audit files.
///
/// Respects `$XDG_DATA_HOME`; falls back to `$HOME/.local/share/aegis`.
pub fn data_dir() -> Result<PathBuf> {
    if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join("aegis"));
    }
    let home = env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/share/aegis"))
}

/// Return the cache directory for Aegis temporary files.
///
/// Respects `$XDG_CACHE_HOME`; falls back to `$HOME/.cache/aegis`.
pub fn cache_dir() -> Result<PathBuf> {
    if let Ok(xdg) = env::var("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(xdg).join("aegis"));
    }
    let home = env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".cache/aegis"))
}

/// Ensure all required directories exist.
pub fn ensure_dirs() -> Result<()> {
    for dir in [
        data_dir()?,
        cache_dir()?,
        plans_dir()?,
        reviews_dir()?,
        policy_dir()?,
    ] {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    Ok(())
}

/// Return the directory where operation plans are stored.
pub fn plans_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("plans"))
}

/// Return the directory where AI review results are stored.
pub fn reviews_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("reviews"))
}

/// Return the directory where policy evaluation results are stored.
pub fn policy_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("policy"))
}

/// Write a JSON-serializable value to a file with restricted permissions.
///
/// The file is created with mode `0o600` on Unix to prevent other users from
/// reading audit data that may contain system state information.
pub fn write_json<T: Serialize>(dir: PathBuf, filename: &str, value: &T) -> Result<PathBuf> {
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(filename);
    let json = serde_json::to_string_pretty(value)?;
    write_with_restricted_permissions(&path, json.as_bytes())?;
    Ok(path)
}

/// Write a text value to a file with restricted permissions.
pub fn write_text(dir: PathBuf, filename: &str, value: &str) -> Result<PathBuf> {
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(filename);
    write_with_restricted_permissions(&path, value.as_bytes())?;
    Ok(path)
}

/// Check that the given directory is writable by creating and removing a test file.
pub fn check_writable(dir: PathBuf) -> Result<()> {
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let test_path = dir.join(".aegis-write-test");
    fs::write(&test_path, b"ok").with_context(|| format!("writing {}", test_path.display()))?;
    // Best-effort cleanup; failure to remove the test file is not fatal.
    let _ = fs::remove_file(&test_path);
    Ok(())
}

/// Write bytes to a file, setting mode `0o600` on Unix.
fn write_with_restricted_permissions(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let mut file =
        fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    file.write_all(data)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn ensure_dirs_creates_expected_paths() {
        let tmp = std::env::temp_dir().join("aegis-audit-test-dirs");
        let _ = fs::remove_dir_all(&tmp);
        std::env::set_var("XDG_DATA_HOME", tmp.join("data"));
        std::env::set_var("XDG_CACHE_HOME", tmp.join("cache"));
        ensure_dirs().expect("ensure_dirs should succeed");
        assert!(tmp.join("data/aegis/plans").is_dir());
        assert!(tmp.join("data/aegis/reviews").is_dir());
        assert!(tmp.join("data/aegis/policy").is_dir());
        assert!(tmp.join("cache/aegis").is_dir());
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn write_json_produces_valid_json() {
        let tmp = std::env::temp_dir().join("aegis-audit-test-json");
        let _ = fs::remove_dir_all(&tmp);
        let path = write_json(tmp.clone(), "test.json", &serde_json::json!({"a": 1}))
            .expect("write_json should succeed");
        let raw = fs::read_to_string(&path).unwrap();
        let _: serde_json::Value = serde_json::from_str(&raw).expect("should be valid JSON");
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_writable_fails_on_nonexistent_parent() {
        let bad = Path::new("/nonexistent-aegis-test-path/subdir");
        assert!(check_writable(bad.to_path_buf()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn written_files_have_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join("aegis-audit-test-perms");
        let _ = fs::remove_dir_all(&tmp);
        let path = write_text(tmp.clone(), "secret.txt", "sensitive data")
            .expect("write_text should succeed");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file should be owner-only readable");
        let _ = fs::remove_dir_all(&tmp);
    }
}
