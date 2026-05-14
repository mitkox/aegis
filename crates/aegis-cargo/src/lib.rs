#![forbid(unsafe_code)]

use aegis_core::{
    denied_plan, has_shell_metacharacters, is_url_like, looks_like_local_path, push_unique,
    OperationPlan, Tool,
};
use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::process::Command;

pub fn validate_crate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('-')
        || name.contains(char::is_whitespace)
        || has_shell_metacharacters(name)
    {
        return Err(anyhow!("invalid crate name"));
    }
    let valid = Regex::new(r"^[A-Za-z0-9_-]+$").expect("valid regex");
    if valid.is_match(name) {
        Ok(())
    } else {
        Err(anyhow!("invalid crate name"))
    }
}

pub fn plan_install(name: &str) -> Result<OperationPlan> {
    if is_url_like(name) || name.starts_with("git+") {
        return Ok(denied(
            "git-source-denied",
            name,
            "git sources are denied by deterministic policy",
        ));
    }
    if looks_like_local_path(name) {
        return Ok(denied(
            "local-path-denied",
            name,
            "local paths are denied by deterministic policy",
        ));
    }
    validate_crate_name(name)?;
    let mut plan = base_plan(name);
    match Command::new("cargo")
        .args(["search", name, "--limit", "5"])
        .output()
    {
        Ok(output) => {
            let raw = output_to_string(&output);
            plan.metadata_available = output.status.success();
            if !output.status.success() {
                plan.warnings
                    .push("cargo search returned a non-zero status".into());
                push_unique(&mut plan.risk_signals, "metadata-command-failed");
            }
            plan.raw_evidence = json!({ "raw_cargo_search_output": raw });
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            plan.warnings
                .push("cargo is unavailable; crate metadata could not be collected".into());
            push_unique(&mut plan.risk_signals, "metadata-unavailable");
            plan.raw_evidence = json!({ "metadata_available": false });
        }
        Err(err) => return Err(err.into()),
    }
    Ok(plan)
}

fn base_plan(name: &str) -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Cargo, "install", Some(name.to_string()));
    plan.ecosystem = Some("cargo".into());
    plan.target_type = Some("rust-crate".into());
    plan.source_registry = Some("crates.io".into());
    plan.command_preview = vec![
        "cargo".into(),
        "search".into(),
        name.into(),
        "--limit".into(),
        "5".into(),
    ];
    plan.mutates_system = true;
    plan.requires_root = false;
    plan.network_access = true;
    plan.packages_installed = vec![name.to_string()];
    plan.risk_signals = vec![
        "cargo-crate".into(),
        "rust-package".into(),
        "network-operation".into(),
    ];
    plan
}

fn denied(signal: &str, name: &str, reason: &str) -> OperationPlan {
    let mut plan = denied_plan(Tool::Cargo, "cargo", "install", name, signal, reason);
    plan.target_type = Some("rust-crate".into());
    plan.risk_signals.push("cargo-crate".into());
    plan
}

pub fn enrich_plan_from_metadata(plan: &mut OperationPlan, metadata: &Value) {
    if metadata
        .get("build_rs")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        push_unique(&mut plan.risk_signals, "build-rs-risk");
        plan.build_hooks_detected.push("build.rs".into());
    }
    if metadata
        .get("proc_macro")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        push_unique(&mut plan.risk_signals, "proc-macro-risk");
        plan.build_hooks_detected.push("proc-macro".into());
    }
    let raw = metadata.to_string().to_ascii_lowercase();
    if metadata.get("links").is_some()
        || raw.contains("cc")
        || raw.contains("cmake")
        || raw.contains("pkg-config")
    {
        push_unique(&mut plan.risk_signals, "native-link-risk");
        plan.native_code_risk = true;
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
    fn clean_crate_name() {
        assert!(validate_crate_name("ripgrep").is_ok());
        assert!(validate_crate_name("--git").is_err());
    }

    #[test]
    fn semicolon_rejected() {
        assert!(validate_crate_name("ripgrep;id").is_err());
    }

    #[test]
    fn git_url_denied() {
        let plan = plan_install("https://github.com/org/repo").unwrap();
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::Deny);
    }

    #[test]
    fn local_path_denied() {
        let plan = plan_install("./crate").unwrap();
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::Deny);
    }

    #[test]
    fn build_rs_fixture_requires_human() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/cargo/build_rs_crate.json"
        ))
        .unwrap();
        let mut plan = base_plan("native-build");
        enrich_plan_from_metadata(&mut plan, &fixture);
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn proc_macro_fixture_requires_human() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/cargo/proc_macro_crate.json"
        ))
        .unwrap();
        let mut plan = base_plan("macro-crate");
        enrich_plan_from_metadata(&mut plan, &fixture);
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }
}
