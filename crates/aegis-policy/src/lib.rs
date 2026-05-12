#![forbid(unsafe_code)]

//! Deterministic policy engine for Aegis operation plans.
//!
//! This crate evaluates an [`OperationPlan`] against a [`PolicyConfig`] and
//! returns a [`PolicyResult`] with a decision, reasons, and required controls.
//! The policy engine is fully deterministic — it never calls external services
//! or uses AI judgement.

use aegis_core::{has_shell_metacharacters, OperationPlan, PolicyDecision, PolicyResult, Tool};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Policy configuration loaded from a TOML file.
///
/// Currently only the `[apt]` section is supported. Other ecosystems use
/// built-in defaults. See `policies/default-policy.toml` for the schema.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyConfig {
    /// Apt-specific policy settings.
    #[serde(default)]
    pub apt: AptPolicyConfig,
}

/// Apt-specific policy configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AptPolicyConfig {
    /// When `false` (default), any plan that removes apt packages is denied.
    /// When `true`, removals require human approval instead of being denied.
    #[serde(default)]
    pub allow_removals: bool,
}

/// Load policy configuration from a TOML file.
///
/// Returns [`PolicyConfig::default()`] if the file does not exist.
pub fn load_policy_config(path: impl AsRef<Path>) -> Result<PolicyConfig> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(PolicyConfig::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Evaluate an operation plan against the policy configuration.
///
/// Returns a [`PolicyResult`] with the deterministic decision. Evaluation
/// order: deny checks first, then risk-signal checks that require human
/// approval, then ecosystem-specific allow rules, and finally a fallback
/// `RequireHuman` for any uncovered operation.
pub fn evaluate(plan: &OperationPlan, config: &PolicyConfig) -> PolicyResult {
    let mut deny_reasons = Vec::new();
    let mut human_reasons = Vec::new();
    let mut controls = Vec::new();

    if plan
        .warnings
        .iter()
        .any(|warning| warning.contains("validation failed"))
    {
        deny_reasons.push("invalid target name".to_string());
    }
    if plan
        .command_preview
        .iter()
        .any(|arg| has_shell_metacharacters(arg))
    {
        deny_reasons.push("command preview contains shell metacharacters".to_string());
    }
    if matches!(plan.tool, Tool::Apt)
        && !config.apt.allow_removals
        && !plan.packages_removed.is_empty()
    {
        deny_reasons.push("apt package removal detected".to_string());
    }
    if plan.risk_signals.iter().any(|signal| {
        matches!(
            signal.as_str(),
            "direct-url-denied"
                | "url-denied"
                | "git-source-denied"
                | "local-path-denied"
                | "vsix-denied"
                | "requirements-file-denied"
                | "replace-directive-denied"
                | "embedded-command-flag-denied"
        )
    }) {
        deny_reasons.push("target source is denied in MVP".to_string());
    }
    if matches!(plan.tool, Tool::Npm) {
        let scripts = scripts_text(plan);
        if contains_word(
            &scripts,
            &["curl", "wget", "bash", "sh", "powershell", "nc", "netcat"],
        ) {
            deny_reasons.push("npm lifecycle script contains forbidden command".to_string());
        }
        if appears_obfuscated(&scripts) {
            deny_reasons.push("npm script appears obfuscated".to_string());
        }
    }
    let scripts = scripts_text(plan);
    if contains_word(&scripts, &["curl", "wget", "fetch", "download"])
        && contains_word(&scripts, &["bash", "sh", "powershell", "pwsh"])
    {
        deny_reasons.push("script combines network download with shell execution".to_string());
    }
    if appears_obfuscated(&scripts) {
        deny_reasons.push("script appears obfuscated".to_string());
    }

    if !deny_reasons.is_empty() {
        return PolicyResult {
            decision: PolicyDecision::Deny,
            reasons: deny_reasons,
            required_controls: controls,
        };
    }

    for signal in &plan.risk_signals {
        match signal.as_str() {
            "kernel-change" => {
                human_reasons.push("kernel package change requires human review".into())
            }
            "security-sensitive" => {
                human_reasons.push("security-sensitive package requires human review".into())
            }
            "lifecycle-scripts" => {
                human_reasons.push("npm lifecycle scripts require human review".into())
            }
            "native-build-risk" => {
                human_reasons.push("native build risk requires human review".into())
            }
            "binary-download-risk" => {
                human_reasons.push("binary download risk requires human review".into())
            }
            "package-removal" => human_reasons.push("package removal requires human review".into()),
            "build-backend-risk" => {
                human_reasons.push("Python build backend requires human review".into())
            }
            "setup-py-risk" => {
                human_reasons.push("setup.py execution risk requires human review".into())
            }
            "native-extension-risk" => {
                human_reasons.push("native Python extension requires human review".into())
            }
            "mutable-tag" => {
                human_reasons.push("mutable container tag requires human review".into())
            }
            "unknown-registry" => {
                human_reasons.push("unknown container registry requires human review".into())
            }
            "unsigned-image" => human_reasons.push("unsigned image requires human review".into()),
            "build-targets-risk" => {
                human_reasons.push("NuGet build targets require human review".into())
            }
            "powershell-risk" => {
                human_reasons.push("PowerShell package hook requires human review".into())
            }
            "native-dll-risk" => {
                human_reasons.push("native DLL package requires human review".into())
            }
            "aspnet-sensitive" => human_reasons
                .push("ASP.NET security-sensitive package requires human review".into()),
            "activation-events-risk" => {
                human_reasons.push("broad VS Code activation requires human review".into())
            }
            "workspace-contains-risk" => {
                human_reasons.push("workspaceContains activation requires human review".into())
            }
            "bundled-binary-risk" => {
                human_reasons.push("bundled binary artifact requires human review".into())
            }
            "gosumdb-disabled" => human_reasons.push("Go checksum database is disabled".into()),
            "private-module-bypass" => {
                human_reasons.push("Go module bypasses checksum database".into())
            }
            "mutable-version" => {
                human_reasons.push("unpinned Go module version requires human review".into())
            }
            "build-rs-risk" => human_reasons.push("Cargo build.rs requires human review".into()),
            "proc-macro-risk" => {
                human_reasons.push("Cargo proc-macro requires human review".into())
            }
            "native-link-risk" => {
                human_reasons.push("Cargo native link risk requires human review".into())
            }
            _ => {}
        }
    }
    if !plan.build_hooks_detected.is_empty() {
        human_reasons.push("build hooks require human review".into());
    }
    if !plan.scripts_detected.is_empty()
        && !matches!(plan.tool, Tool::Vscode)
        && !matches!(plan.tool, Tool::Nuget)
    {
        human_reasons.push("scripts require human review".into());
    }
    if plan.native_code_risk {
        human_reasons.push("native code risk requires human review".into());
    }
    if plan.binary_artifact_risk {
        human_reasons.push("binary artifact risk requires human review".into());
    }
    if plan.mutable_reference {
        human_reasons.push("mutable reference requires human review".into());
    }
    if plan.signature_or_checksum_status.as_deref() == Some("disabled") {
        human_reasons.push("artifact checksum or signature validation is disabled".into());
    }
    if plan
        .packages_installed
        .iter()
        .chain(plan.packages_upgraded.iter())
        .chain(plan.packages_removed.iter())
        .any(|name| is_system_sensitive_name(name))
    {
        human_reasons.push("systemd/sudo/pam/ssh-related package requires human review".into());
    }

    if !human_reasons.is_empty() {
        controls.push("human approval".to_string());
        return PolicyResult {
            decision: PolicyDecision::RequireHuman,
            reasons: dedup(human_reasons),
            required_controls: controls,
        };
    }

    if matches!(plan.tool, Tool::Apt)
        && plan.operation == "upgrade"
        && !plan.packages_removed.is_empty()
    {
        return PolicyResult {
            decision: PolicyDecision::RequireHuman,
            reasons: vec!["apt upgrade includes removals".into()],
            required_controls: vec!["human approval".into()],
        };
    }

    if matches!(plan.tool, Tool::Apt)
        && plan.operation == "upgrade"
        && plan.packages_removed.is_empty()
        && !plan.risk_signals.iter().any(|s| s == "kernel-change")
        && !plan.risk_signals.iter().any(|s| s == "security-sensitive")
    {
        return PolicyResult {
            decision: PolicyDecision::AllowWithSnapshot,
            reasons: vec![
                "apt dry-run upgrade has no removals or sensitive package changes".into(),
            ],
            required_controls: vec!["system snapshot".into()],
        };
    }

    if matches!(plan.tool, Tool::Npm) {
        return PolicyResult {
            decision: PolicyDecision::Allow,
            reasons: vec!["npm metadata inspection only; MVP does not install packages".into()],
            required_controls: controls,
        };
    }

    if matches!(
        plan.tool,
        Tool::Pip | Tool::Nuget | Tool::Vscode | Tool::Cargo | Tool::Container | Tool::Go
    ) {
        return PolicyResult {
            decision: PolicyDecision::Allow,
            reasons: vec![format!(
                "{} metadata-only plan has no policy-blocking risk signals",
                plan.ecosystem.as_deref().unwrap_or("ecosystem")
            )],
            required_controls: controls,
        };
    }

    if matches!(plan.tool, Tool::Apt) && plan.operation == "update" {
        return PolicyResult {
            decision: PolicyDecision::Allow,
            reasons: vec!["apt update is plan-only in MVP".into()],
            required_controls: controls,
        };
    }

    PolicyResult {
        decision: PolicyDecision::RequireHuman,
        reasons: vec!["operation is not covered by an allow rule".into()],
        required_controls: vec!["human approval".into()],
    }
}

fn scripts_text(plan: &OperationPlan) -> String {
    let mut text = plan
        .scripts_detected
        .iter()
        .chain(plan.build_hooks_detected.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(&plan.raw_evidence.to_string());
    let evidence_scripts = plan
        .raw_evidence
        .get("scripts")
        .or_else(|| {
            plan.raw_evidence
                .get("raw_npm_metadata")
                .and_then(|metadata| metadata.get("scripts"))
        })
        .map(|value| value.to_string().to_ascii_lowercase())
        .unwrap_or_default();
    text.push_str(&evidence_scripts);
    text.to_ascii_lowercase()
}

fn contains_word(text: &str, words: &[&str]) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '-')
        .any(|part| words.contains(&part))
}

fn appears_obfuscated(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '=')
        .any(|part| part.len() >= 80 && looks_base64ish(part))
}

fn looks_base64ish(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
}

fn is_system_sensitive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["systemd", "sudo", "pam", "ssh", "openssh"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn dedup(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{OperationPlan, Tool};
    use serde_json::json;

    #[test]
    fn denies_package_removals() {
        let mut plan = OperationPlan::new(Tool::Apt, "upgrade", None);
        plan.command_preview = vec!["apt-get".into(), "-s".into(), "upgrade".into()];
        plan.packages_removed = vec!["old-lib".into()];
        plan.risk_signals = vec!["package-removal".into()];
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn requires_human_for_kernel_package() {
        let mut plan = OperationPlan::new(Tool::Apt, "upgrade", None);
        plan.command_preview = vec!["apt-get".into(), "-s".into(), "upgrade".into()];
        plan.packages_upgraded = vec!["linux-image-generic".into()];
        plan.risk_signals = vec!["kernel-change".into()];
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, PolicyDecision::RequireHuman);
    }

    #[test]
    fn requires_human_for_npm_postinstall_without_forbidden_downloader() {
        let mut plan = OperationPlan::new(Tool::Npm, "install", Some("pkg".into()));
        plan.command_preview = vec!["npm".into(), "view".into(), "pkg".into(), "--json".into()];
        plan.risk_signals = vec!["npm-package".into(), "lifecycle-scripts".into()];
        plan.raw_evidence = json!({ "scripts": { "postinstall": "node setup.js" } });
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, PolicyDecision::RequireHuman);
    }

    #[test]
    fn command_preview_rejects_shell_string() {
        let mut plan = OperationPlan::new(Tool::Apt, "install", Some("nginx".into()));
        plan.command_preview = vec!["apt-get -s install nginx; rm -rf /".into()];
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, PolicyDecision::Deny);
    }
}
