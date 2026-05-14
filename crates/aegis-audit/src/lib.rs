#![forbid(unsafe_code)]

use aegis_core::{AuditEvent, AuditEventKind, PolicyDecision};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
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
    if let Ok(path) = env::var("AEGIS_AUDIT_LOG_DIR") {
        return PathBuf::from(path);
    }
    data_dir()
        .map(|d| d.join("audit"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/aegis/audit"))
}

pub fn audit_log_path() -> PathBuf {
    audit_log_dir().join("audit.ndjson")
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

pub fn append_audit_event(event: AuditEvent) -> Result<()> {
    let dir = audit_log_dir();
    append_audit_event_to_dir(&dir, event)
}

fn append_audit_event_to_dir(dir: &Path, mut event: AuditEvent) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let log_path = dir.join("audit.ndjson");
    let _lock = AuditLock::acquire(dir)?;

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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuditVerification {
    pub path: PathBuf,
    pub events: u64,
    pub last_hash: Option<String>,
}

pub fn verify_audit_log() -> Result<AuditVerification> {
    verify_audit_log_path(audit_log_path())
}

pub fn verify_audit_log_path(path: impl AsRef<Path>) -> Result<AuditVerification> {
    let path = path.as_ref();
    let file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut previous_hash: Option<String> = None;
    let mut sequence = 0_u64;
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading line {}", index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        sequence += 1;
        let mut event: AuditEvent = serde_json::from_str(&line)
            .with_context(|| format!("parsing audit event line {}", index + 1))?;
        if event.sequence != sequence {
            bail!(
                "audit sequence mismatch at line {}: got {}, expected {}",
                index + 1,
                event.sequence,
                sequence
            );
        }
        if event.previous_hash != previous_hash {
            bail!("audit previous_hash mismatch at line {}", index + 1);
        }
        let actual_hash = event.event_hash.clone();
        event.event_hash = String::new();
        let canonical = serde_json::to_string(&event).context("serializing audit event")?;
        let hash_input = if let Some(ref prev) = previous_hash {
            format!("{prev}:{canonical}")
        } else {
            canonical
        };
        let expected_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));
        if actual_hash != expected_hash {
            bail!("audit event_hash mismatch at line {}", index + 1);
        }
        previous_hash = Some(actual_hash);
    }
    Ok(AuditVerification {
        path: path.to_path_buf(),
        events: sequence,
        last_hash: previous_hash,
    })
}

struct AuditLock {
    path: PathBuf,
}

impl AuditLock {
    fn acquire(dir: &Path) -> Result<Self> {
        let path = dir.join(".audit.lock");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("acquiring audit lock {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for AuditLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_hash_chain_and_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("aegis-audit-test-{}", Uuid::new_v4()));
        append_audit_event_to_dir(
            &dir,
            new_audit_event(
                AuditEventKind::ExecutionStarted,
                Some("tester".into()),
                Some("plan".into()),
                Some("exec".into()),
                vec!["apt-get".into(), "update".into()],
                Some(PolicyDecision::Allow),
                serde_json::json!({"test": true}),
            ),
        )
        .unwrap();
        append_audit_event_to_dir(
            &dir,
            new_audit_event(
                AuditEventKind::ExecutionCompleted,
                Some("tester".into()),
                Some("plan".into()),
                Some("exec".into()),
                vec!["apt-get".into(), "update".into()],
                Some(PolicyDecision::Allow),
                serde_json::json!({"test": true}),
            ),
        )
        .unwrap();
        let log = dir.join("audit.ndjson");
        let verification = verify_audit_log_path(&log).unwrap();
        assert_eq!(verification.events, 2);

        let tampered = fs::read_to_string(&log)
            .unwrap()
            .replace("\"sequence\":2", "\"sequence\":22");
        fs::write(&log, tampered).unwrap();
        assert!(verify_audit_log_path(&log).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
