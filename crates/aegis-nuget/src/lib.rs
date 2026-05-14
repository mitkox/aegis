#![forbid(unsafe_code)]

use aegis_core::{has_shell_metacharacters, push_unique, OperationPlan, Tool};
use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::process::Command;

pub fn validate_nuget_package_id(package: &str) -> Result<()> {
    if package.is_empty()
        || package.starts_with('-')
        || package.contains(char::is_whitespace)
        || has_shell_metacharacters(package)
    {
        return Err(anyhow!("invalid NuGet package id"));
    }
    let valid = Regex::new(r"^[A-Za-z0-9._-]+$").expect("valid regex");
    if valid.is_match(package) {
        Ok(())
    } else {
        Err(anyhow!("invalid NuGet package id"))
    }
}

pub fn plan_install(package: &str) -> Result<OperationPlan> {
    validate_nuget_package_id(package)?;
    let mut plan = base_plan(package);
    match Command::new("dotnet")
        .args(["nuget", "search", package])
        .output()
    {
        Ok(output) => {
            let raw = output_to_string(&output);
            plan.metadata_available = output.status.success();
            if !output.status.success() {
                plan.warnings
                    .push("dotnet nuget search returned a non-zero status".into());
                push_unique(&mut plan.risk_signals, "metadata-command-failed");
            }
            plan.raw_evidence = json!({ "raw_dotnet_nuget_search_output": raw });
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            plan.warnings
                .push("dotnet is unavailable; NuGet metadata could not be collected".into());
            push_unique(&mut plan.risk_signals, "metadata-unavailable");
            plan.raw_evidence = json!({ "metadata_available": false });
        }
        Err(err) => return Err(err.into()),
    }
    add_name_risks(&mut plan, package);
    Ok(plan)
}

fn base_plan(package: &str) -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Nuget, "install", Some(package.to_string()));
    plan.ecosystem = Some("nuget".into());
    plan.target_type = Some("dotnet-package".into());
    plan.source_registry = Some("NuGet".into());
    plan.command_preview = vec![
        "dotnet".into(),
        "nuget".into(),
        "search".into(),
        package.into(),
    ];
    plan.mutates_system = true;
    plan.requires_root = false;
    plan.network_access = true;
    plan.packages_installed = vec![package.to_string()];
    plan.risk_signals = vec![
        "nuget-package".into(),
        "dotnet-package".into(),
        "network-operation".into(),
    ];
    add_name_risks(&mut plan, package);
    plan
}

fn add_name_risks(plan: &mut OperationPlan, package: &str) {
    let lower = package.to_ascii_lowercase();
    if [
        "aspnet",
        "identity",
        "authentication",
        "authorization",
        "jwt",
        "oauth",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        push_unique(&mut plan.risk_signals, "aspnet-sensitive");
    }
}

pub fn enrich_plan_from_metadata(plan: &mut OperationPlan, metadata: &Value) {
    let raw = metadata.to_string().to_ascii_lowercase();
    if raw.contains(".targets") || raw.contains(".props") || raw.contains("buildtransitive") {
        push_unique(&mut plan.risk_signals, "build-targets-risk");
        plan.build_hooks_detected.push("msbuild-targets".into());
    }
    if raw.contains("powershell") || raw.contains("pwsh") || raw.contains(".ps1") {
        push_unique(&mut plan.risk_signals, "powershell-risk");
        plan.scripts_detected.push("powershell".into());
    }
    if raw.contains("native") || raw.contains(".dll") || raw.contains("runtimes/") {
        push_unique(&mut plan.risk_signals, "native-dll-risk");
        plan.native_code_risk = true;
    }
    if let Some(name) = metadata.get("name").and_then(Value::as_str) {
        add_name_risks(plan, name);
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
    fn clean_nuget_package() {
        assert!(validate_nuget_package_id("Newtonsoft.Json").is_ok());
        assert!(validate_nuget_package_id("-ConfigFile").is_err());
    }

    #[test]
    fn semicolon_package_rejected() {
        assert!(validate_nuget_package_id("Newtonsoft.Json;id").is_err());
    }

    #[test]
    fn aspnet_identity_requires_human() {
        let plan = base_plan("Microsoft.AspNetCore.Identity");
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn targets_fixture_requires_human() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nuget/build_targets_package.json"
        ))
        .unwrap();
        let mut plan = base_plan("BuildTargets.Package");
        enrich_plan_from_metadata(&mut plan, &fixture);
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn powershell_fixture_requires_human_or_deny() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nuget/powershell_package.json"
        ))
        .unwrap();
        let mut plan = base_plan("PowerShell.Package");
        enrich_plan_from_metadata(&mut plan, &fixture);
        let result = evaluate(&plan, &PolicyConfig::default());
        assert!(matches!(
            result.decision,
            aegis_core::PolicyDecision::RequireHuman | aegis_core::PolicyDecision::Deny
        ));
    }
}
