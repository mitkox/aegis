#![forbid(unsafe_code)]

use aegis_core::{
    has_shell_metacharacters, looks_like_local_path, push_unique, OperationPlan, Tool,
};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
pub struct GoEnv {
    pub gosumdb: Option<String>,
    pub goproxy: Option<String>,
    pub goprivate: Option<String>,
    pub gonosumdb: Option<String>,
}

pub fn validate_go_module(module: &str) -> Result<()> {
    if module.is_empty()
        || module.contains(char::is_whitespace)
        || has_shell_metacharacters(module)
        || looks_like_local_path(module)
        || module.contains(" replace ")
    {
        return Err(anyhow!("invalid Go module reference"));
    }
    let valid = Regex::new(r"^[A-Za-z0-9./_~@+-]+$").expect("valid regex");
    if valid.is_match(module) {
        if let Some((path, version)) = module.split_once('@') {
            if path.is_empty() || version.is_empty() || version.contains('@') {
                return Err(anyhow!("invalid Go module reference"));
            }
        }
        Ok(())
    } else {
        Err(anyhow!("invalid Go module reference"))
    }
}

pub fn plan_get(module: &str) -> Result<OperationPlan> {
    validate_go_module(module)?;
    let mut plan = base_plan(module);
    let env_info = collect_go_env(&mut plan)?;
    apply_go_env_risks(&mut plan, &env_info);
    collect_go_list(module, &mut plan)?;
    Ok(plan)
}

fn base_plan(module: &str) -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Go, "get", Some(module.to_string()));
    plan.ecosystem = Some("go".into());
    plan.target_type = Some("go-module".into());
    plan.command_preview = vec![
        "go".into(),
        "list".into(),
        "-m".into(),
        "-json".into(),
        module.into(),
    ];
    plan.mutates_system = true;
    plan.requires_root = false;
    plan.network_access = true;
    plan.packages_installed = vec![module.to_string()];
    plan.risk_signals = vec!["go-module".into(), "network-operation".into()];
    if let Some((_, version)) = module.rsplit_once('@') {
        plan.target_version = Some(version.to_string());
        if looks_like_pseudo_version(version) {
            push_unique(&mut plan.risk_signals, "pseudo-version-risk");
        }
    } else {
        push_unique(&mut plan.risk_signals, "mutable-version");
        plan.mutable_reference = true;
    }
    plan
}

fn collect_go_env(plan: &mut OperationPlan) -> Result<GoEnv> {
    match Command::new("go")
        .args(["env", "GOSUMDB", "GOPROXY", "GOPRIVATE", "GONOSUMDB"])
        .output()
    {
        Ok(output) => {
            let raw = output_to_string(&output);
            let mut lines = raw.lines();
            let env_info = GoEnv {
                gosumdb: lines.next().map(str::to_string),
                goproxy: lines.next().map(str::to_string),
                goprivate: lines.next().map(str::to_string),
                gonosumdb: lines.next().map(str::to_string),
            };
            plan.raw_evidence = json!({ "go_env": {
                "GOSUMDB": env_info.gosumdb,
                "GOPROXY": env_info.goproxy,
                "GOPRIVATE": env_info.goprivate,
                "GONOSUMDB": env_info.gonosumdb
            }});
            Ok(env_info)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            plan.warnings
                .push("go is unavailable; module metadata could not be collected".into());
            push_unique(&mut plan.risk_signals, "metadata-unavailable");
            Ok(GoEnv::default())
        }
        Err(err) => Err(err.into()),
    }
}

fn collect_go_list(module: &str, plan: &mut OperationPlan) -> Result<()> {
    let tmp = temp_dir()?;
    fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let result = Command::new("go")
        .current_dir(&tmp)
        .args(["list", "-m", "-json", module])
        .output();
    let _ = fs::remove_dir_all(&tmp);
    match result {
        Ok(output) => {
            let raw = output_to_string(&output);
            plan.metadata_available = output.status.success();
            if let Ok(metadata) = serde_json::from_str::<Value>(&raw) {
                plan.raw_evidence["go_list"] = metadata;
            } else {
                plan.raw_evidence["raw_go_list_output"] = json!(raw);
            }
            if !output.status.success() {
                plan.warnings
                    .push("go list returned a non-zero status".into());
                push_unique(&mut plan.risk_signals, "metadata-command-failed");
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            push_unique(&mut plan.risk_signals, "metadata-unavailable");
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn temp_dir() -> Result<std::path::PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_nanos();
    Ok(aegis_audit::cache_dir()?
        .join("tmp")
        .join(format!("go-{nonce}")))
}

pub fn apply_go_env_risks(plan: &mut OperationPlan, env_info: &GoEnv) {
    if env_info.gosumdb.as_deref() == Some("off") {
        push_unique(&mut plan.risk_signals, "gosumdb-disabled");
        plan.signature_or_checksum_status = Some("disabled".into());
    } else if env_info.gosumdb.as_ref().is_some_and(|v| !v.is_empty()) {
        push_unique(&mut plan.risk_signals, "checksum-db-enabled");
        plan.signature_or_checksum_status = Some("checksum-db-enabled".into());
    }
    if let Some(target) = plan.target.clone() {
        if matches_pattern_list(&target, env_info.goprivate.as_deref())
            || matches_pattern_list(&target, env_info.gonosumdb.as_deref())
        {
            push_unique(&mut plan.risk_signals, "private-module-bypass");
        }
    }
}

fn matches_pattern_list(module: &str, value: Option<&str>) -> bool {
    value
        .unwrap_or_default()
        .split(',')
        .filter(|part| !part.is_empty())
        .any(|part| module.starts_with(part.trim_end_matches("/*")))
}

fn looks_like_pseudo_version(version: &str) -> bool {
    Regex::new(r"^v\d+\.\d+\.\d+-\d{14}-[0-9a-f]{12}$")
        .expect("valid regex")
        .is_match(version)
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
    fn module_without_version_requires_human() {
        let mut plan = base_plan("github.com/gin-gonic/gin");
        apply_go_env_risks(
            &mut plan,
            &GoEnv {
                gosumdb: Some("sum.golang.org".into()),
                ..GoEnv::default()
            },
        );
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn module_with_version_allowed() {
        let mut plan = base_plan("github.com/gin-gonic/gin@v1.10.0");
        plan.metadata_available = true;
        apply_go_env_risks(
            &mut plan,
            &GoEnv {
                gosumdb: Some("sum.golang.org".into()),
                ..GoEnv::default()
            },
        );
        let result = evaluate(&plan, &PolicyConfig::default());
        assert!(matches!(
            result.decision,
            aegis_core::PolicyDecision::Allow | aegis_core::PolicyDecision::AllowWithSnapshot
        ));
    }

    #[test]
    fn gosumdb_off_requires_human() {
        let mut plan = base_plan("github.com/gin-gonic/gin@v1.10.0");
        apply_go_env_risks(
            &mut plan,
            &GoEnv {
                gosumdb: Some("off".into()),
                ..GoEnv::default()
            },
        );
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn local_path_rejected() {
        assert!(validate_go_module("../local").is_err());
    }

    #[test]
    fn semicolon_rejected() {
        assert!(validate_go_module("github.com/a/b;id").is_err());
    }

    #[test]
    fn malformed_version_pin_rejected() {
        assert!(validate_go_module("github.com/a/b@").is_err());
        assert!(validate_go_module("@v1.0.0").is_err());
        assert!(validate_go_module("github.com/a/b@v1.0.0@evil").is_err());
    }
}
