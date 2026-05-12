#![forbid(unsafe_code)]

//! Npm package operation planning for Aegis.
//!
//! Generates read-only operation plans by querying `npm view` for registry
//! metadata. Never runs `npm install`.

use aegis_core::{push_unique, OperationPlan, Tool};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::process::Command;

/// Validate an npm package name (scoped or unscoped).
pub fn validate_npm_package_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("package name must not be empty"));
    }
    if name.len() > 214 {
        return Err(anyhow!("npm package name is too long"));
    }
    if name.contains(char::is_whitespace) {
        return Err(anyhow!("npm package name must not contain whitespace"));
    }
    let unscoped = Regex::new(r"^[A-Za-z0-9._-]+$").expect("valid regex");
    let scoped = Regex::new(r"^@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$").expect("valid regex");
    if unscoped.is_match(name) || scoped.is_match(name) {
        Ok(())
    } else {
        Err(anyhow!("invalid npm package name"))
    }
}

/// Create an operation plan for `npm install <package>`.
pub fn plan_install(package: &str) -> Result<OperationPlan> {
    validate_npm_package_name(package)?;
    let mut plan = OperationPlan::new(Tool::Npm, "install", Some(package.to_string()));
    plan.command_preview = vec!["npm".into(), "view".into(), package.into(), "--json".into()];
    plan.mutates_system = true;
    plan.requires_root = false;
    plan.network_access = true;
    plan.packages_installed = vec![package.to_string()];
    plan.risk_signals = vec![
        "npm-package".into(),
        "network-operation".into(),
        "no-root-required".into(),
    ];

    match Command::new("npm")
        .arg("view")
        .arg(package)
        .arg("--json")
        .output()
    {
        Ok(output) => {
            let raw = command_output_to_string(&output);
            let metadata: Value = serde_json::from_str(&raw).unwrap_or_else(|_| {
                plan.warnings
                    .push("npm returned metadata that was not valid JSON".into());
                json!({ "raw": raw })
            });
            enrich_plan_from_metadata(&mut plan, &metadata);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            plan.warnings
                .push("npm is unavailable; metadata inspection could not be performed".into());
            plan.raw_evidence = json!({ "npm_available": false });
        }
        Err(err) => return Err(err).context("running npm view"),
    }

    Ok(plan)
}

fn command_output_to_string(output: &std::process::Output) -> String {
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    raw
}

/// Enrich a plan with risk signals extracted from npm registry metadata.
pub fn enrich_plan_from_metadata(plan: &mut OperationPlan, metadata: &Value) {
    let latest_version = metadata
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let dist_tarball = metadata
        .get("dist")
        .and_then(|dist| dist.get("tarball"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let dependencies_count = metadata
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|deps| deps.len())
        .unwrap_or(0);
    let maintainers_count = metadata
        .get("maintainers")
        .and_then(Value::as_array)
        .map(|maintainers| maintainers.len())
        .unwrap_or(0);

    let scripts = metadata
        .get("scripts")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut script_text = String::new();
    for (name, value) in &scripts {
        script_text.push_str(name);
        script_text.push(' ');
        if let Some(value) = value.as_str() {
            script_text.push_str(value);
        }
        script_text.push('\n');
    }

    if scripts.keys().any(|name| {
        matches!(
            name.as_str(),
            "install" | "postinstall" | "preinstall" | "prepare"
        )
    }) {
        push_unique(&mut plan.risk_signals, "lifecycle-scripts");
    }
    let lower_scripts = script_text.to_ascii_lowercase();
    if [
        "node-gyp", "prebuild", "cmake", "make", "gcc", "g++", "python",
    ]
    .iter()
    .any(|needle| lower_scripts.contains(needle))
    {
        push_unique(&mut plan.risk_signals, "native-build-risk");
    }
    if ["curl", "wget", "fetch", "download"]
        .iter()
        .any(|needle| lower_scripts.contains(needle))
    {
        push_unique(&mut plan.risk_signals, "binary-download-risk");
    }

    plan.raw_evidence = json!({
        "package": plan.target,
        "latest_version": latest_version,
        "dist_tarball": dist_tarball,
        "scripts": scripts,
        "dependencies_count": dependencies_count,
        "maintainers_count": maintainers_count,
        "raw_npm_metadata": metadata
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_npm_package_names() {
        assert!(validate_npm_package_name("lodash").is_ok());
        assert!(validate_npm_package_name("@scope/pkg.name").is_ok());
        assert!(validate_npm_package_name("").is_err());
        assert!(validate_npm_package_name("left pad").is_err());
        assert!(validate_npm_package_name("pkg;curl").is_err());
    }

    #[test]
    fn extracts_npm_risk_signals() {
        let metadata: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/npm/package_with_postinstall.json"
        ))
        .unwrap();
        let mut plan = OperationPlan::new(Tool::Npm, "install", Some("risky".into()));
        plan.risk_signals = vec!["npm-package".into(), "network-operation".into()];
        enrich_plan_from_metadata(&mut plan, &metadata);
        assert!(plan.risk_signals.contains(&"lifecycle-scripts".into()));
        assert!(plan.risk_signals.contains(&"binary-download-risk".into()));
    }

    #[test]
    fn clean_npm_metadata_has_no_lifecycle_signal() {
        let metadata: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/npm/package_clean.json"
        ))
        .unwrap();
        let mut plan = OperationPlan::new(Tool::Npm, "install", Some("clean-package".into()));
        plan.risk_signals = vec!["npm-package".into(), "network-operation".into()];
        enrich_plan_from_metadata(&mut plan, &metadata);
        assert!(!plan.risk_signals.contains(&"lifecycle-scripts".into()));
        assert_eq!(
            plan.raw_evidence
                .get("dependencies_count")
                .and_then(Value::as_u64),
            Some(2)
        );
    }
}
