#![forbid(unsafe_code)]

use aegis_core::{
    has_shell_metacharacters, AiRecommendation, AiReview, OperationPlan, OverallRisk,
    PolicyDecision, PolicyResult, RiskLevel, Tool,
};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

pub const POLICY_VERSION: &str = "0.2.7";

/// A deterministic identifier for this evaluator build.
///
/// In production this should be the SHA-256 of the evaluator binary.
/// During early releases this is a compile-time constant tied to the source version.
pub const EVALUATOR_HASH: &str = "aegis-policy-0.2.7";

fn result(
    plan_hash: &str,
    decision: PolicyDecision,
    reasons: Vec<String>,
    required_controls: Vec<String>,
) -> PolicyResult {
    PolicyResult {
        decision,
        reasons,
        required_controls,
        policy_version: POLICY_VERSION.to_string(),
        evaluator_hash: EVALUATOR_HASH.to_string(),
        plan_hash: plan_hash.to_string(),
        evidence_fresh_until: None,
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub apt: AptPolicyConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AptPolicyConfig {
    #[serde(default)]
    pub allow_removals: bool,
}

pub fn load_policy_config(path: impl AsRef<Path>) -> Result<PolicyConfig> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(PolicyConfig::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

pub fn evaluate(plan: &OperationPlan, config: &PolicyConfig) -> Result<PolicyResult> {
    evaluate_with_review(plan, config, None)
}

pub fn evaluate_with_review(
    plan: &OperationPlan,
    config: &PolicyConfig,
    review: Option<&AiReview>,
) -> Result<PolicyResult> {
    let plan_hash = aegis_core::sha256_hex(plan).context("hashing operation plan")?;
    let deterministic = evaluate_deterministic(plan, config, &plan_hash);
    Ok(apply_ai_review_restrictions(
        &plan_hash,
        deterministic,
        review,
    ))
}

fn evaluate_deterministic(
    plan: &OperationPlan,
    config: &PolicyConfig,
    plan_hash: &str,
) -> PolicyResult {
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
        deny_reasons.push("target source is denied by deterministic policy".to_string());
    }
    if plan
        .risk_signals
        .iter()
        .any(|signal| signal == "metadata-command-failed")
    {
        deny_reasons.push("metadata command failed during planning".to_string());
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
    if !matches!(plan.tool, Tool::Apt) {
        if plan.mutable_reference {
            deny_reasons.push(
                "mutable non-APT package or artifact reference is denied by deterministic policy"
                    .to_string(),
            );
        }
        if !has_strong_non_apt_apply_evidence(plan) {
            deny_reasons.push(format!(
                "{} production apply requires pinned, verified artifact evidence before execution",
                plan.ecosystem.as_deref().unwrap_or("non-APT")
            ));
        }
    }

    if !deny_reasons.is_empty() {
        return result(
            plan_hash,
            PolicyDecision::Deny,
            dedup(deny_reasons),
            controls,
        );
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
        return result(
            plan_hash,
            PolicyDecision::RequireHuman,
            dedup(human_reasons),
            controls,
        );
    }

    if plan
        .risk_signals
        .iter()
        .any(|signal| signal == "metadata-unavailable")
        || (plan.mutates_system
            && plan.network_access
            && !plan.metadata_available
            && !(matches!(plan.tool, Tool::Apt) && plan.operation == "update"))
    {
        return result(
            plan_hash,
            PolicyDecision::RequireHuman,
            vec!["package or artifact metadata is unavailable".into()],
            vec!["human approval".into()],
        );
    }

    if matches!(plan.tool, Tool::Apt)
        && plan.operation == "upgrade"
        && !plan.packages_removed.is_empty()
    {
        return result(
            plan_hash,
            PolicyDecision::RequireHuman,
            vec!["apt upgrade includes removals".into()],
            vec!["human approval".into()],
        );
    }

    if matches!(plan.tool, Tool::Apt)
        && plan.operation == "upgrade"
        && plan.packages_removed.is_empty()
        && !plan.risk_signals.iter().any(|s| s == "kernel-change")
        && !plan.risk_signals.iter().any(|s| s == "security-sensitive")
    {
        return result(
            plan_hash,
            PolicyDecision::AllowWithSnapshot,
            vec!["apt dry-run upgrade has no removals or sensitive package changes".into()],
            vec!["system snapshot".into()],
        );
    }

    if matches!(plan.tool, Tool::Container | Tool::Go) {
        return result(
            plan_hash,
            PolicyDecision::Allow,
            vec![format!(
                "{} package or artifact has pinned, verified apply evidence and no policy-blocking risk signals",
                plan.ecosystem.as_deref().unwrap_or("ecosystem")
            )],
            controls,
        );
    }

    if matches!(plan.tool, Tool::Apt) && plan.operation == "update" {
        return result(
            plan_hash,
            PolicyDecision::Allow,
            vec!["apt metadata refresh has no policy-blocking risk signals".into()],
            controls,
        );
    }

    result(
        plan_hash,
        PolicyDecision::RequireHuman,
        vec!["operation is not covered by an allow rule".into()],
        vec!["human approval".into()],
    )
}

fn apply_ai_review_restrictions(
    plan_hash: &str,
    mut policy: PolicyResult,
    review: Option<&AiReview>,
) -> PolicyResult {
    let Some(review) = review else {
        return policy;
    };
    if policy.decision == PolicyDecision::Deny {
        return policy;
    }
    if review.recommendation == AiRecommendation::Deny || review.risk == OverallRisk::Deny {
        let mut reasons = vec!["AI review classified the operation as deny".to_string()];
        reasons.extend(
            review
                .red_flags
                .iter()
                .map(|flag| format!("AI red flag: {flag}")),
        );
        return result(plan_hash, PolicyDecision::Deny, dedup(reasons), Vec::new());
    }
    if review_requires_human(review) {
        policy.decision = PolicyDecision::RequireHuman;
        policy
            .reasons
            .push("AI review escalated the operation to human approval".into());
        policy.reasons.extend(
            review
                .red_flags
                .iter()
                .map(|flag| format!("AI red flag: {flag}")),
        );
        policy.reasons.extend(
            review
                .required_controls
                .iter()
                .map(|control| format!("AI requested control: {control}")),
        );
        if !policy
            .required_controls
            .iter()
            .any(|control| control == "human approval")
        {
            policy.required_controls.push("human approval".into());
        }
        policy.reasons = dedup(policy.reasons);
    }
    policy
}

fn review_requires_human(review: &AiReview) -> bool {
    review.recommendation == AiRecommendation::RequireHuman
        || review.risk == OverallRisk::High
        || matches!(review.supply_chain_risk, RiskLevel::High)
        || matches!(review.privilege_risk, RiskLevel::High)
        || matches!(review.persistence_risk, RiskLevel::High)
        || matches!(review.availability_risk, RiskLevel::High)
        || !review.red_flags.is_empty()
}

fn has_strong_non_apt_apply_evidence(plan: &OperationPlan) -> bool {
    match plan.tool {
        Tool::Container => {
            plan.metadata_available
                && !plan.mutable_reference
                && plan.signature_or_checksum_status.as_deref() == Some("digest-pinned")
        }
        Tool::Go => {
            plan.metadata_available
                && !plan.mutable_reference
                && plan
                    .target_version
                    .as_deref()
                    .is_some_and(|version| !version.is_empty())
                && plan.signature_or_checksum_status.as_deref() != Some("disabled")
        }
        Tool::Apt => true,
        Tool::Npm | Tool::Pip | Tool::Nuget | Tool::Vscode | Tool::Cargo => false,
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
    use aegis_core::{OperationPlan, RollbackDifficulty, Tool};
    use serde_json::json;

    #[test]
    fn denies_package_removals() {
        let mut plan = OperationPlan::new(Tool::Apt, "upgrade", None);
        plan.command_preview = vec!["apt-get".into(), "-s".into(), "upgrade".into()];
        plan.packages_removed = vec!["old-lib".into()];
        plan.risk_signals = vec!["package-removal".into()];
        let result = evaluate(&plan, &PolicyConfig::default()).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
        assert_eq!(result.plan_hash, aegis_core::sha256_hex(&plan).unwrap());
    }

    #[test]
    fn requires_human_for_kernel_package() {
        let mut plan = OperationPlan::new(Tool::Apt, "upgrade", None);
        plan.command_preview = vec!["apt-get".into(), "-s".into(), "upgrade".into()];
        plan.packages_upgraded = vec!["linux-image-generic".into()];
        plan.risk_signals = vec!["kernel-change".into()];
        let result = evaluate(&plan, &PolicyConfig::default()).unwrap();
        assert_eq!(result.decision, PolicyDecision::RequireHuman);
    }

    #[test]
    fn denies_npm_postinstall_without_strong_apply_evidence() {
        let mut plan = OperationPlan::new(Tool::Npm, "install", Some("pkg".into()));
        plan.command_preview = vec!["npm".into(), "view".into(), "pkg".into(), "--json".into()];
        plan.risk_signals = vec!["npm-package".into(), "lifecycle-scripts".into()];
        plan.raw_evidence = json!({ "scripts": { "postinstall": "node setup.js" } });
        let result = evaluate(&plan, &PolicyConfig::default()).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn command_preview_rejects_shell_string() {
        let mut plan = OperationPlan::new(Tool::Apt, "install", Some("nginx".into()));
        plan.command_preview = vec!["apt-get -s install nginx; rm -rf /".into()];
        let result = evaluate(&plan, &PolicyConfig::default()).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn metadata_command_failure_is_denied() {
        let mut plan = OperationPlan::new(Tool::Npm, "install", Some("missing".into()));
        plan.mutates_system = true;
        plan.network_access = true;
        plan.risk_signals = vec!["metadata-command-failed".into()];
        let result = evaluate(&plan, &PolicyConfig::default()).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn unavailable_non_apt_metadata_is_denied_by_default() {
        let mut plan = OperationPlan::new(Tool::Cargo, "install", Some("ripgrep".into()));
        plan.mutates_system = true;
        plan.network_access = true;
        plan.risk_signals = vec!["metadata-unavailable".into()];
        let result = evaluate(&plan, &PolicyConfig::default()).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn ai_review_can_escalate_but_not_approve() {
        let mut plan = OperationPlan::new(Tool::Apt, "update", None);
        plan.command_preview = vec!["apt-get".into(), "update".into()];
        let review = ai_review(AiRecommendation::RequireHuman, OverallRisk::High);
        let result = evaluate_with_review(&plan, &PolicyConfig::default(), Some(&review)).unwrap();
        assert_eq!(result.decision, PolicyDecision::RequireHuman);
        assert!(result.required_controls.contains(&"human approval".into()));

        let denied = evaluate_with_review(
            &denied_plan_for_review(),
            &PolicyConfig::default(),
            Some(&ai_review(AiRecommendation::AutoApprove, OverallRisk::Low)),
        )
        .unwrap();
        assert_eq!(denied.decision, PolicyDecision::Deny);
    }

    #[test]
    fn ai_review_can_deny() {
        let mut plan = OperationPlan::new(Tool::Apt, "update", None);
        plan.command_preview = vec!["apt-get".into(), "update".into()];
        let result = evaluate_with_review(
            &plan,
            &PolicyConfig::default(),
            Some(&ai_review(AiRecommendation::Deny, OverallRisk::Deny)),
        )
        .unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    fn ai_review(recommendation: AiRecommendation, risk: OverallRisk) -> AiReview {
        AiReview {
            risk,
            summary: "review".into(),
            supply_chain_risk: RiskLevel::Low,
            privilege_risk: RiskLevel::Low,
            persistence_risk: RiskLevel::Low,
            availability_risk: RiskLevel::Low,
            rollback_difficulty: RollbackDifficulty::Easy,
            red_flags: Vec::new(),
            required_controls: Vec::new(),
            recommendation,
        }
    }

    fn denied_plan_for_review() -> OperationPlan {
        let mut plan = OperationPlan::new(Tool::Apt, "install", Some("nginx".into()));
        plan.command_preview = vec!["apt-get -s install nginx; rm -rf /".into()];
        plan
    }
}
