#![forbid(unsafe_code)]

use aegis_core::{
    denied_plan, has_shell_metacharacters, is_url_like, looks_like_local_path, push_unique,
    OperationPlan, Tool,
};
use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::process::Command;

pub fn validate_extension_id(extension: &str) -> Result<()> {
    if extension.is_empty()
        || extension.contains(char::is_whitespace)
        || has_shell_metacharacters(extension)
        || !extension.contains('.')
        || extension.starts_with('-')
    {
        return Err(anyhow!("invalid VS Code extension id"));
    }
    let valid = Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+$").expect("valid regex");
    if valid.is_match(extension) {
        Ok(())
    } else {
        Err(anyhow!("invalid VS Code extension id"))
    }
}

pub fn plan_install(extension: &str) -> Result<OperationPlan> {
    if is_url_like(extension) {
        return Ok(denied(
            "url-denied",
            extension,
            "URL extension installs are denied by deterministic policy",
        ));
    }
    if extension.ends_with(".vsix") || looks_like_local_path(extension) {
        return Ok(denied(
            "vsix-denied",
            extension,
            "local VSIX installs are denied by deterministic policy",
        ));
    }
    validate_extension_id(extension)?;

    let mut plan = base_plan(extension);
    match Command::new("code")
        .args(["--list-extensions", "--show-versions"])
        .output()
    {
        Ok(output) => {
            let raw = output_to_string(&output);
            plan.metadata_available = output.status.success();
            if !output.status.success() {
                plan.warnings
                    .push("code --list-extensions returned a non-zero status".into());
                push_unique(&mut plan.risk_signals, "metadata-command-failed");
            }
            plan.raw_evidence = json!({ "raw_installed_extensions": raw });
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            plan.warnings.push(
                "code is unavailable; installed extension metadata could not be collected".into(),
            );
            push_unique(&mut plan.risk_signals, "metadata-unavailable");
            plan.raw_evidence = json!({ "metadata_available": false });
        }
        Err(err) => return Err(err.into()),
    }
    Ok(plan)
}

fn base_plan(extension: &str) -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Vscode, "install", Some(extension.to_string()));
    plan.ecosystem = Some("vscode".into());
    plan.target_type = Some("vscode-extension".into());
    plan.command_preview = vec![
        "code".into(),
        "--list-extensions".into(),
        "--show-versions".into(),
    ];
    plan.mutates_system = true;
    plan.requires_root = false;
    plan.network_access = true;
    plan.packages_installed = vec![extension.to_string()];
    plan.publisher_or_maintainer = extension
        .split_once('.')
        .map(|(publisher, _)| publisher.to_string());
    plan.risk_signals = vec![
        "vscode-extension".into(),
        "developer-tooling".into(),
        "workspace-access-risk".into(),
    ];
    plan
}

fn denied(signal: &str, extension: &str, reason: &str) -> OperationPlan {
    let mut plan = denied_plan(Tool::Vscode, "vscode", "install", extension, signal, reason);
    plan.target_type = Some("vscode-extension".into());
    plan.risk_signals.push("vscode-extension".into());
    plan
}

pub fn enrich_plan_from_package_json(plan: &mut OperationPlan, metadata: &Value) {
    if let Some(events) = metadata.get("activationEvents").and_then(Value::as_array) {
        for event in events.iter().filter_map(Value::as_str) {
            if event == "*" {
                push_unique(&mut plan.risk_signals, "activation-events-risk");
                plan.scripts_detected.push("activation:*".into());
            }
            if event.starts_with("onCommand") {
                push_unique(&mut plan.risk_signals, "command-activation-risk");
                plan.scripts_detected.push(event.to_string());
            }
            if event.starts_with("workspaceContains") {
                push_unique(&mut plan.risk_signals, "workspace-contains-risk");
                plan.scripts_detected.push(event.to_string());
            }
        }
    }
    let raw = metadata.to_string().to_ascii_lowercase();
    if raw.contains("\"bin\"") || raw.contains("native") || raw.contains("executable") {
        push_unique(&mut plan.risk_signals, "bundled-binary-risk");
        plan.binary_artifact_risk = true;
    }
    plan.metadata_available = true;
    plan.raw_evidence = metadata.clone();
}

fn output_to_string(output: &std::process::Output) -> String {
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_policy::{evaluate, PolicyConfig};

    #[test]
    fn clean_extension_id() {
        assert!(validate_extension_id("ms-python.python").is_ok());
        assert!(validate_extension_id("-install.extension").is_err());
    }

    #[test]
    fn url_denied() {
        let plan = plan_install("https://example.invalid/ext.vsix").unwrap();
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::Deny);
    }

    #[test]
    fn vsix_path_denied() {
        let plan = plan_install("./extension.vsix").unwrap();
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::Deny);
    }

    #[test]
    fn broad_activation_requires_human() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/vscode/broad_activation_package.json"
        ))
        .unwrap();
        let mut plan = base_plan("publisher.extension");
        enrich_plan_from_package_json(&mut plan, &fixture);
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn workspace_contains_requires_human() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/vscode/workspace_contains_package.json"
        ))
        .unwrap();
        let mut plan = base_plan("publisher.extension");
        enrich_plan_from_package_json(&mut plan, &fixture);
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }
}
