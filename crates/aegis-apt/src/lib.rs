#![forbid(unsafe_code)]

//! Apt package operation planning for Aegis.
//!
//! Generates read-only operation plans by running `apt-get -s` (simulated)
//! commands and parsing their output. Never runs real installs or upgrades.

use aegis_core::{push_unique, OperationPlan, Tool};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde_json::json;
use std::process::Command;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AptDryRunSummary {
    pub packages_upgraded: Vec<String>,
    pub packages_installed: Vec<String>,
    pub packages_removed: Vec<String>,
    pub packages_held_back: Vec<String>,
}

/// Validate an apt package name against allowed characters.
pub fn validate_apt_package_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("package name must not be empty"));
    }
    let valid = Regex::new(r"^[A-Za-z0-9.+_-]+$").expect("valid regex");
    if !valid.is_match(name) {
        return Err(anyhow!(
            "invalid apt package name: only A-Z a-z 0-9 . + - _ are allowed"
        ));
    }
    Ok(())
}

/// Create an operation plan for `apt-get update`.
///
/// MVP does not run `apt-get update`; the plan describes the intended
/// metadata refresh.
pub fn plan_update() -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Apt, "update", None);
    plan.command_preview = vec!["apt-get".into(), "update".into()];
    plan.mutates_system = true;
    plan.requires_root = true;
    plan.network_access = true;
    plan.risk_signals = vec!["requires-root".into(), "network-operation".into()];
    plan.warnings = vec![
        "MVP does not run apt-get update; this plan describes the intended metadata refresh".into(),
        "repository trust verification is required before applying package metadata changes".into(),
    ];
    plan.raw_evidence = json!({
        "description": "Would refresh apt package metadata from configured repositories.",
        "repository_trust_verification_required": true
    });
    plan
}

/// Create an operation plan for `apt-get upgrade` using a simulated dry-run.
pub fn plan_upgrade() -> Result<OperationPlan> {
    let output = Command::new("apt-get")
        .arg("-s")
        .arg("upgrade")
        .output()
        .context("running apt-get -s upgrade")?;
    let raw = command_output_to_string(&output);
    let parsed = parse_apt_dry_run(&raw);
    let mut plan = plan_from_summary(
        "upgrade",
        None,
        vec!["apt-get", "-s", "upgrade"],
        parsed,
        raw,
    );
    plan.network_access = false;
    Ok(plan)
}

/// Create an operation plan for `apt-get install <package>` using a simulated dry-run.
pub fn plan_install(package: &str) -> Result<OperationPlan> {
    validate_apt_package_name(package)?;
    let output = Command::new("apt-get")
        .arg("-s")
        .arg("install")
        .arg(package)
        .output()
        .with_context(|| format!("running apt-get -s install {package}"))?;
    let raw = command_output_to_string(&output);
    let parsed = parse_apt_dry_run(&raw);
    let mut plan = plan_from_summary(
        "install",
        Some(package.to_string()),
        vec!["apt-get", "-s", "install", package],
        parsed,
        raw,
    );
    plan.network_access = true;
    push_unique(&mut plan.risk_signals, "network-operation");
    Ok(plan)
}

fn command_output_to_string(output: &std::process::Output) -> String {
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    raw
}

fn plan_from_summary(
    operation: &str,
    target: Option<String>,
    command_preview: Vec<&str>,
    summary: AptDryRunSummary,
    raw: String,
) -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Apt, operation, target);
    plan.ecosystem = Some("apt".into());
    plan.command_preview = command_preview.into_iter().map(String::from).collect();
    plan.mutates_system = true;
    plan.requires_root = true;
    plan.packages_installed = summary.packages_installed;
    plan.packages_upgraded = summary.packages_upgraded;
    plan.packages_removed = summary.packages_removed;
    plan.packages_held_back = summary.packages_held_back;
    plan.raw_evidence = json!({ "raw_dry_run_output": raw });
    add_apt_risk_signals(&mut plan);
    plan
}

pub fn add_apt_risk_signals(plan: &mut OperationPlan) {
    push_unique(&mut plan.risk_signals, "requires-root");
    if !plan.packages_removed.is_empty() {
        push_unique(&mut plan.risk_signals, "package-removal");
    }
    if !plan.packages_installed.is_empty() {
        push_unique(&mut plan.risk_signals, "package-install");
    }
    if !plan.packages_upgraded.is_empty() {
        push_unique(&mut plan.risk_signals, "package-upgrade");
    }
    if any_package_matches(plan, is_kernel_package) {
        push_unique(&mut plan.risk_signals, "kernel-change");
    }
    if any_package_matches(plan, is_security_sensitive_package) {
        push_unique(&mut plan.risk_signals, "security-sensitive");
    }
}

fn any_package_matches(plan: &OperationPlan, predicate: fn(&str) -> bool) -> bool {
    plan.packages_installed
        .iter()
        .chain(plan.packages_upgraded.iter())
        .chain(plan.packages_removed.iter())
        .chain(plan.packages_downgraded.iter())
        .chain(plan.packages_held_back.iter())
        .any(|name| predicate(name))
}

fn is_kernel_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "linux-image",
        "linux-headers",
        "initramfs",
        "grub",
        "shim",
        "dkms",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_security_sensitive_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "openssl",
        "libssl",
        "sudo",
        "openssh",
        "pam",
        "systemd",
        "polkit",
        "ca-certificates",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Parse the text output of an `apt-get -s` dry-run into a structured summary.
pub fn parse_apt_dry_run(raw: &str) -> AptDryRunSummary {
    #[derive(Clone, Copy)]
    enum Section {
        Installed,
        Upgraded,
        Removed,
        HeldBack,
    }

    let mut summary = AptDryRunSummary::default();
    let mut section: Option<Section> = None;
    let mut continuation = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            section = None;
            continuation = false;
            continue;
        }

        if trimmed.starts_with("The following NEW packages will be installed:") {
            section = Some(Section::Installed);
            continuation = true;
            continue;
        }
        if trimmed.starts_with("The following packages will be upgraded:") {
            section = Some(Section::Upgraded);
            continuation = true;
            continue;
        }
        if trimmed.starts_with("The following packages will be REMOVED:") {
            section = Some(Section::Removed);
            continuation = true;
            continue;
        }
        if trimmed.starts_with("The following packages have been kept back:") {
            section = Some(Section::HeldBack);
            continuation = true;
            continue;
        }
        if trimmed.starts_with("The following")
            || trimmed.starts_with("Suggested packages:")
            || trimmed.starts_with("Recommended packages:")
            || trimmed.starts_with("Remv ")
            || trimmed.starts_with("Conf ")
            || trimmed.starts_with("Inst ")
            || looks_like_summary_line(trimmed)
        {
            section = None;
            continuation = false;
        }

        if let Some(active) = section {
            if continuation || line.starts_with(' ') {
                for pkg in package_tokens(trimmed) {
                    match active {
                        Section::Installed => push_unique(&mut summary.packages_installed, pkg),
                        Section::Upgraded => push_unique(&mut summary.packages_upgraded, pkg),
                        Section::Removed => push_unique(&mut summary.packages_removed, pkg),
                        Section::HeldBack => push_unique(&mut summary.packages_held_back, pkg),
                    }
                }
            }
        } else if let Some(pkg) = parse_inst_line(trimmed) {
            push_unique(&mut summary.packages_upgraded, pkg);
        } else if let Some(pkg) = parse_remv_line(trimmed) {
            push_unique(&mut summary.packages_removed, pkg);
        }
    }

    summary
}

fn looks_like_summary_line(line: &str) -> bool {
    line.contains(" upgraded, ")
        && line.contains(" newly installed, ")
        && line.contains(" to remove")
}

fn package_tokens(line: &str) -> Vec<String> {
    line.split_whitespace()
        .filter_map(|token| {
            let token = token.trim_matches(|c: char| c == ',' || c == '.');
            if token.is_empty() || token.starts_with('[') || token.contains(':') {
                None
            } else {
                Some(token.to_string())
            }
        })
        .collect()
}

fn parse_inst_line(line: &str) -> Option<String> {
    line.strip_prefix("Inst ")
        .and_then(|rest| rest.split_whitespace().next())
        .map(ToOwned::to_owned)
}

fn parse_remv_line(line: &str) -> Option<String> {
    line.strip_prefix("Remv ")
        .and_then(|rest| rest.split_whitespace().next())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_apt_package_names() {
        assert!(validate_apt_package_name("libssl3").is_ok());
        assert!(validate_apt_package_name("foo.bar+baz_1-2").is_ok());
        assert!(validate_apt_package_name("").is_err());
        assert!(validate_apt_package_name("nginx;rm").is_err());
        assert!(validate_apt_package_name("two words").is_err());
    }

    #[test]
    fn parses_upgrade_fixture() {
        let raw = include_str!("../../../tests/fixtures/apt/upgrade_simple.txt");
        let parsed = parse_apt_dry_run(raw);
        assert_eq!(parsed.packages_upgraded, vec!["bash", "openssl"]);
        assert!(parsed.packages_removed.is_empty());
    }

    #[test]
    fn parses_removal_fixture() {
        let raw = include_str!("../../../tests/fixtures/apt/upgrade_with_removal.txt");
        let parsed = parse_apt_dry_run(raw);
        assert_eq!(parsed.packages_removed, vec!["obsolete-lib"]);
        assert_eq!(parsed.packages_upgraded, vec!["coreutils"]);
    }

    #[test]
    fn detects_kernel_risk_signal_from_fixture() {
        let raw = include_str!("../../../tests/fixtures/apt/kernel_upgrade.txt");
        let parsed = parse_apt_dry_run(raw);
        let mut plan = plan_from_summary(
            "upgrade",
            None,
            vec!["apt-get", "-s", "upgrade"],
            parsed,
            raw.to_string(),
        );
        add_apt_risk_signals(&mut plan);
        assert!(plan.risk_signals.contains(&"kernel-change".into()));
    }

    #[test]
    fn command_preview_is_argv_array() {
        let plan = plan_update();
        assert_eq!(plan.command_preview, vec!["apt-get", "update"]);
        assert!(!plan
            .command_preview
            .iter()
            .any(|arg| arg.contains(' ') || arg.contains(';')));
    }
}
