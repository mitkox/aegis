#![forbid(unsafe_code)]

use aegis_core::{AuditEvent, AuditEventKind, PolicyDecision};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use uuid::Uuid;

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

pub fn audit_log_dir() -> PathBuf {
    data_dir()
        .map(|d| d.join("audit"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/aegis/audit"))
}

pub fn new_audit_event(
    kind: AuditEventKind,
    actor: Option<String>,
    plan_id: Option<String>,
    execution_plan_id: Option<String>,
    argv: Vec<String>,
    decision: Option<PolicyDecision>,
    details: Value,
) -> AuditEvent {
    let hostname = hostname();
    AuditEvent {
        schema_version: 1,
        sequence: 0,
        event_id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        host: hostname,
        kind,
        actor,
        plan_id,
        execution_plan_id,
        argv,
        decision,
        exit_status: None,
        stdout_sha256: None,
        stderr_sha256: None,
        details,
        previous_hash: None,
        event_hash: String::new(),
    }
}

pub fn append_audit_event(mut event: AuditEvent) -> Result<()> {
    let dir = audit_log_dir();
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let log_path = dir.join("audit.ndjson");

    // Read previous hash for hash chain
    let previous_hash = read_last_hash(&log_path);
    event.previous_hash = previous_hash.clone();

    // Assign sequence
    event.sequence = next_sequence(&log_path);

    // Compute event hash over the event (with event_hash empty)
    event.event_hash = String::new();
    let canonical = serde_json::to_string(&event).context("serializing audit event")?;
    let hash_input = if let Some(ref prev) = previous_hash {
        format!("{prev}:{canonical}")
    } else {
        canonical.clone()
    };
    event.event_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

    let line = serde_json::to_string(&event).context("serializing audit event")?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;
    writeln!(file, "{line}").with_context(|| format!("appending to {}", log_path.display()))?;
    Ok(())
}

fn read_last_hash(path: &PathBuf) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let reader = std::io::BufReader::new(file);
    let mut last_line = None;
    for line in reader.lines().map_while(Result::ok) {
        if !line.trim().is_empty() {
            last_line = Some(line);
        }
    }
    let last = last_line?;
    let value: Value = serde_json::from_str(&last).ok()?;
    value
        .get("event_hash")
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn next_sequence(path: &PathBuf) -> u64 {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return 1,
    };
    let reader = std::io::BufReader::new(file);
    let count = reader
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .count();
    (count as u64) + 1
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
