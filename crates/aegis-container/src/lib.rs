#![forbid(unsafe_code)]

use aegis_core::{has_shell_metacharacters, push_unique, OperationPlan, Tool};
use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

impl ContainerRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

pub fn validate_image_reference(image: &str) -> Result<()> {
    if image.is_empty()
        || image.contains(char::is_whitespace)
        || has_shell_metacharacters(image)
        || image.starts_with('-')
        || image.contains(" --")
        || image.contains('\n')
        || image.contains('\t')
    {
        return Err(anyhow!("invalid container image reference"));
    }
    let valid = Regex::new(r"^[A-Za-z0-9._:/@+-]+$").expect("valid regex");
    if valid.is_match(image) {
        Ok(())
    } else {
        Err(anyhow!("invalid container image reference"))
    }
}

pub fn plan_pull(image: &str, runtime: ContainerRuntime) -> Result<OperationPlan> {
    validate_image_reference(image)?;
    let mut plan = base_plan(image, runtime);
    add_image_reference_risks(&mut plan, image);

    let runtime_name = runtime.as_str();
    match Command::new(runtime_name)
        .args(["manifest", "inspect", image])
        .output()
    {
        Ok(output) => {
            let raw = output_to_string(&output);
            plan.metadata_available = output.status.success();
            if output.status.success() {
                let metadata: Value =
                    serde_json::from_str(&raw).unwrap_or_else(|_| json!({ "raw": raw }));
                enrich_plan_from_manifest(&mut plan, &metadata);
            } else {
                plan.warnings.push(format!(
                    "{runtime_name} manifest inspect returned a non-zero status"
                ));
                plan.raw_evidence = json!({ "raw_manifest_output": raw });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            plan.warnings.push(format!(
                "{runtime_name} is unavailable; manifest metadata could not be collected"
            ));
            plan.raw_evidence = json!({ "metadata_available": false });
        }
        Err(err) => return Err(err.into()),
    }

    Ok(plan)
}

fn base_plan(image: &str, runtime: ContainerRuntime) -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Container, "pull", Some(image.to_string()));
    plan.ecosystem = Some("container".into());
    plan.target_type = Some("container-image".into());
    plan.command_preview = vec![
        runtime.as_str().into(),
        "manifest".into(),
        "inspect".into(),
        image.into(),
    ];
    plan.mutates_system = true;
    plan.requires_root = false;
    plan.network_access = true;
    plan.risk_signals = vec!["container-image".into(), "network-operation".into()];
    plan
}

fn add_image_reference_risks(plan: &mut OperationPlan, image: &str) {
    if let Some((registry, _)) = image.split_once('/') {
        if registry.contains('.') || registry.contains(':') || registry == "localhost" {
            plan.source_registry = Some(registry.to_string());
        }
    }
    if plan.source_registry.is_none() {
        push_unique(&mut plan.risk_signals, "unknown-registry");
        push_unique(&mut plan.risk_signals, "dockerhub-default");
    }

    if let Some((_, digest)) = image.split_once("@sha256:") {
        if digest.len() >= 32 && digest.chars().all(|c| c.is_ascii_hexdigit()) {
            plan.signature_or_checksum_status = Some("digest-pinned".into());
            return;
        }
    }

    let tag = image.rsplit_once(':').map(|(_, tag)| tag);
    if tag.is_none()
        || tag == Some("latest")
        || image
            .rsplit_once('/')
            .map(|(_, last)| !last.contains(':'))
            .unwrap_or(!image.contains(':'))
    {
        push_unique(&mut plan.risk_signals, "mutable-tag");
        plan.mutable_reference = true;
    }
    push_unique(&mut plan.risk_signals, "unsigned-image");
    plan.signature_or_checksum_status = Some("unknown".into());
}

pub fn enrich_plan_from_manifest(plan: &mut OperationPlan, manifest: &Value) {
    plan.metadata_available = true;
    if manifest.get("signatures").is_none() && plan.signature_or_checksum_status.is_none() {
        push_unique(&mut plan.risk_signals, "unsigned-image");
        plan.signature_or_checksum_status = Some("unknown".into());
    }
    plan.raw_evidence = manifest.clone();
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

    fn test_plan(image: &str) -> OperationPlan {
        validate_image_reference(image).unwrap();
        let mut plan = base_plan(image, ContainerRuntime::Docker);
        add_image_reference_risks(&mut plan, image);
        plan
    }

    #[test]
    fn ubuntu_latest_requires_human() {
        let plan = test_plan("ubuntu:latest");
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn nginx_without_tag_requires_human() {
        let plan = test_plan("nginx");
        let result = evaluate(&plan, &PolicyConfig::default());
        assert_eq!(result.decision, aegis_core::PolicyDecision::RequireHuman);
    }

    #[test]
    fn digest_reference_allowed() {
        let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let plan = test_plan(&format!("ghcr.io/org/image@sha256:{digest}"));
        let result = evaluate(&plan, &PolicyConfig::default());
        assert!(matches!(
            result.decision,
            aegis_core::PolicyDecision::Allow | aegis_core::PolicyDecision::AllowWithSnapshot
        ));
    }

    #[test]
    fn semicolon_image_rejected() {
        assert!(validate_image_reference("ubuntu:latest;id").is_err());
    }

    #[test]
    fn embedded_flag_rejected() {
        assert!(validate_image_reference("--privileged").is_err());
    }
}
