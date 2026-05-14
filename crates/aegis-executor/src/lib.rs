#![forbid(unsafe_code)]

//! Constrained execution gate for signed Aegis execution plans.
//!
//! This crate owns deterministic preflight validation and argv allowlisting.
//! It deliberately accepts only narrow package-manager argv patterns.

use aegis_core::{ExecutionPlan, PolicyDecision};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub status: i32,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout: String,
    pub stderr: String,
}

pub fn preflight_execution_plan(plan: &ExecutionPlan) -> Result<()> {
    if plan.signature.is_none() {
        bail!("execution plan is unsigned");
    }
    if plan.policy_decision == PolicyDecision::Deny {
        bail!("policy decision denies execution");
    }
    if plan.policy_decision == PolicyDecision::RequireHuman && plan.approvals.is_empty() {
        bail!("human approval is required but no signed approval is attached");
    }
    if is_expired(&plan.expires_at)? {
        bail!("execution plan has expired");
    }
    validate_argv_allowlist(&plan.argv)?;
    Ok(())
}

pub fn execute_plan(plan: &ExecutionPlan) -> Result<ExecutionOutput> {
    preflight_execution_plan(plan)?;
    let (program, args) = plan
        .argv
        .split_first()
        .ok_or_else(|| anyhow!("execution argv is empty"))?;
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("executing allowlisted argv {:?}", plan.argv))?;
    Ok(ExecutionOutput {
        status: output.status.code().unwrap_or(-1),
        stdout_sha256: hex_sha256(&output.stdout),
        stderr_sha256: hex_sha256(&output.stderr),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub fn validate_argv_allowlist(argv: &[String]) -> Result<()> {
    if argv.is_empty() {
        bail!("argv is empty");
    }
    if argv.iter().any(|arg| contains_shell_metacharacter(arg)) {
        bail!("argv contains shell metacharacters");
    }
    match argv[0].as_str() {
        "apt-get" => validate_apt_get(argv),
        "npm" | "python3" | "docker" | "podman" | "dotnet" | "code" | "go" | "cargo" => {
            bail!(
                "{} mutation is not enabled for the production executor yet",
                argv[0]
            )
        }
        other => bail!("program {other} is not allowlisted for execution"),
    }
}

fn validate_apt_get(argv: &[String]) -> Result<()> {
    if argv.len() < 2 {
        bail!("apt-get argv is incomplete");
    }
    match argv[1].as_str() {
        "update" => {
            if argv.len() == 2 {
                Ok(())
            } else {
                bail!("apt-get update must not include extra flags")
            }
        }
        "upgrade" => {
            let allowed = [
                "apt-get",
                "upgrade",
                "-y",
                "-o",
                "Dpkg::Options::=--force-confold",
            ];
            if argv == allowed {
                Ok(())
            } else {
                bail!("apt-get upgrade argv does not match the production allowlist")
            }
        }
        "install" => {
            if argv.len() < 4 || argv[2] != "-y" {
                bail!("apt-get install must use exact form: apt-get install -y <pkg[=version]>...");
            }
            for package in &argv[3..] {
                validate_apt_target(package)?;
            }
            Ok(())
        }
        _ => bail!("apt-get subcommand is not allowlisted"),
    }
}

fn validate_apt_target(value: &str) -> Result<()> {
    if value.starts_with('-') || value.ends_with(".deb") || value.contains('/') {
        bail!("apt target must be a package name or name=version, not a flag/path");
    }
    let valid = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_' | ':' | '~' | '='));
    if !valid {
        bail!("apt target contains invalid characters");
    }
    Ok(())
}

fn is_expired(expires_at: &str) -> Result<bool> {
    let expires = DateTime::parse_from_rfc3339(expires_at)
        .context("parsing execution plan expires_at")?
        .with_timezone(&Utc);
    Ok(Utc::now() > expires)
}

fn contains_shell_metacharacter(value: &str) -> bool {
    value.chars().any(|c| {
        matches!(
            c,
            ';' | '&' | '|' | '`' | '$' | '(' | ')' | '<' | '>' | '\n' | '\r' | '\t'
        )
    })
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_shell_metacharacters() {
        let argv = vec![
            "apt-get".into(),
            "install".into(),
            "-y".into(),
            "nginx;id".into(),
        ];
        assert!(validate_argv_allowlist(&argv).is_err());
    }

    #[test]
    fn allows_exact_apt_install_targets() {
        let argv = vec![
            "apt-get".into(),
            "install".into(),
            "-y".into(),
            "nginx=1.24.0-1ubuntu1".into(),
        ];
        validate_argv_allowlist(&argv).unwrap();
    }

    #[test]
    fn denies_direct_deb_install() {
        let argv = vec![
            "apt-get".into(),
            "install".into(),
            "-y".into(),
            "./pkg.deb".into(),
        ];
        assert!(validate_argv_allowlist(&argv).is_err());
    }
}
