#![forbid(unsafe_code)]

use aegis_core::{
    denied_plan, has_shell_metacharacters, is_url_like, looks_like_local_path, push_unique,
    OperationPlan, Tool,
};
use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::env;
use std::process::Command;

pub fn validate_pip_package_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("package name must not be empty"));
    }
    let valid = Regex::new(r"^[A-Za-z0-9._-]+$").expect("valid regex");
    if valid.is_match(name) {
        Ok(())
    } else {
        Err(anyhow!("invalid pip package name"))
    }
}

pub fn plan_install(package: &str) -> Result<OperationPlan> {
    if is_url_like(package) {
        return Ok(denied(
            "direct-url-denied",
            package,
            "direct URLs are denied in MVP",
        ));
    }
    if package == "-r" || package.ends_with("requirements.txt") {
        return Ok(denied(
            "requirements-file-denied",
            package,
            "requirements files are denied in MVP",
        ));
    }
    if looks_like_local_path(package) {
        return Ok(denied(
            "local-path-denied",
            package,
            "local paths are denied in MVP",
        ));
    }
    if has_shell_metacharacters(package) || package.contains(char::is_whitespace) {
        return Err(anyhow!("invalid pip package name"));
    }
    validate_pip_package_name(package)?;

    let mut plan = base_plan(package);
    plan.command_preview = vec![
        "python3".into(),
        "-m".into(),
        "pip".into(),
        "index".into(),
        "versions".into(),
        package.into(),
    ];

    match Command::new("python3")
        .args(["-m", "pip", "index", "versions", package])
        .output()
    {
        Ok(output) => {
            plan.metadata_available = output.status.success();
            let raw = output_to_string(&output);
            if !output.status.success() {
                plan.warnings
                    .push("pip metadata command returned a non-zero status".into());
            }
            plan.raw_evidence = json!({
                "metadata_command": plan.command_preview,
                "raw_pip_index_output": raw,
                "inside_virtualenv": inside_virtualenv(),
                "python_user_base": env::var("PYTHONUSERBASE").ok()
            });
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            plan.warnings
                .push("python3 or pip is unavailable; metadata could not be collected".into());
            plan.raw_evidence = json!({ "metadata_available": false });
        }
        Err(err) => return Err(err.into()),
    }

    add_environment_risk(&mut plan);
    Ok(plan)
}

fn base_plan(package: &str) -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Pip, "install", Some(package.to_string()));
    plan.ecosystem = Some("pip".into());
    plan.target_type = Some("python-package".into());
    plan.source_registry = Some("PyPI".into());
    plan.mutates_system = true;
    plan.requires_root = false;
    plan.network_access = true;
    plan.packages_installed = vec![package.to_string()];
    plan.risk_signals = vec![
        "pip-package".into(),
        "python-package".into(),
        "network-operation".into(),
    ];
    plan
}

fn denied(signal: &str, package: &str, reason: &str) -> OperationPlan {
    let mut plan = denied_plan(Tool::Pip, "pip", "install", package, signal, reason);
    plan.target_type = Some("python-package".into());
    plan.risk_signals.push("pip-package".into());
    plan
}

fn output_to_string(output: &std::process::Output) -> String {
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    raw
}

fn inside_virtualenv() -> bool {
    env::var("VIRTUAL_ENV").is_ok()
}

fn add_environment_risk(plan: &mut OperationPlan) {
    if !inside_virtualenv() {
        push_unique(&mut plan.risk_signals, "virtualenv-missing");
    }
    if env::var("PYTHONUSERBASE").is_ok() {
        push_unique(&mut plan.risk_signals, "user-site-risk");
    }
}

pub fn enrich_plan_from_metadata(plan: &mut OperationPlan, metadata: &Value) {
    if metadata
        .get("pyproject_toml")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || metadata.get("build_backend").is_some()
    {
        push_unique(&mut plan.risk_signals, "build-backend-risk");
        plan.build_hooks_detected.push("pyproject.toml".into());
    }
    if metadata
        .get("setup_py")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        push_unique(&mut plan.risk_signals, "setup-py-risk");
        plan.build_hooks_detected.push("setup.py".into());
    }
    if metadata
        .get("native_extension")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        push_unique(&mut plan.risk_signals, "native-extension-risk");
        plan.native_code_risk = true;
    }
    plan.raw_evidence = metadata.clone();
    plan.metadata_available = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_policy::{evaluate, PolicyConfig};

    #[test]
    fn clean_package_name() {
        assert!(validate_pip_package_name("requests_toolbelt-1.0").is_ok());
    }

    #[test]
    fn malicious_semicolon_rejected() {
        assert!(plan_install("requests;rm").is_err());
    }

    #[test]
    fn url_install_is_denied() {
        let plan = plan_install("https://example.invalid/pkg.tar.gz").unwrap();
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::Deny);
    }

    #[test]
    fn local_path_install_is_denied() {
        let plan = plan_install("./pkg").unwrap();
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::Deny);
    }

    #[test]
    fn setup_py_fixture_requires_human() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/pip/setup_py_package.json"
        ))
        .unwrap();
        let mut plan = base_plan("legacy");
        enrich_plan_from_metadata(&mut plan, &fixture);
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn native_extension_fixture_requires_human() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/pip/native_extension_package.json"
        ))
        .unwrap();
        let mut plan = base_plan("native");
        enrich_plan_from_metadata(&mut plan, &fixture);
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }
}
