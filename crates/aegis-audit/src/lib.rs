#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::PathBuf;

pub fn data_dir() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/share/aegis"))
}

pub fn cache_dir() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".cache/aegis"))
}

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

pub fn plans_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("plans"))
}

pub fn reviews_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("reviews"))
}

pub fn policy_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("policy"))
}

pub fn write_json<T: Serialize>(dir: PathBuf, filename: &str, value: &T) -> Result<PathBuf> {
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(filename);
    let json = serde_json::to_string_pretty(value)?;
    fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn write_text(dir: PathBuf, filename: &str, value: &str) -> Result<PathBuf> {
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(filename);
    fs::write(&path, value).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn check_writable(dir: PathBuf) -> Result<()> {
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let test_path = dir.join(".aegis-write-test");
    fs::write(&test_path, b"ok").with_context(|| format!("writing {}", test_path.display()))?;
    fs::remove_file(&test_path).with_context(|| format!("removing {}", test_path.display()))?;
    Ok(())
}
