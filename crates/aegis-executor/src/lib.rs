#![forbid(unsafe_code)]

//! Constrained execution gate for signed Aegis execution plans.
//!
//! This crate owns deterministic preflight validation and argv allowlisting.
//! It deliberately accepts only narrow package-manager argv patterns.

use aegis_core::{Approval, ControlProof, ExecutionPlan, PolicyDecision};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

const AEGIS_STATE_DIR: &str = "/var/lib/aegis";
const NPM_PREFIX: &str = "/var/lib/aegis/npm-global";
const PIP_TARGET: &str = "/var/lib/aegis/pip-packages";
const NUGET_OUTPUT_DIR: &str = "/var/lib/aegis/nuget/packages";
const VSCODE_USER_DATA_DIR: &str = "/var/lib/aegis/vscode/user-data";
const VSCODE_EXTENSIONS_DIR: &str = "/var/lib/aegis/vscode/extensions";
const CARGO_ROOT: &str = "/var/lib/aegis/cargo";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub status: i32,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout: String,
    pub stderr: String,
}

pub fn preflight_execution_plan(plan: &ExecutionPlan) -> Result<()> {
    preflight_execution_plan_inner(plan, None)
}

pub fn preflight_execution_plan_with_approval_keys(
    plan: &ExecutionPlan,
    approval_public_keys: &[String],
) -> Result<()> {
    preflight_execution_plan_inner(plan, Some(approval_public_keys))
}

fn preflight_execution_plan_inner(
    plan: &ExecutionPlan,
    approval_public_keys: Option<&[String]>,
) -> Result<()> {
    if plan.signature.is_none() {
        bail!("execution plan is unsigned");
    }
    if plan.policy_decision == PolicyDecision::Deny {
        bail!("policy decision denies execution");
    }
    if is_expired(&plan.expires_at)? {
        bail!("execution plan has expired");
    }
    validate_policy_freshness(plan)?;
    validate_embedded_plan_policy_binding(plan)?;
    validate_argv_allowlist(&plan.argv)?;
    validate_exact_targets_match_argv(plan)?;
    validate_required_controls(plan, approval_public_keys)?;
    Ok(())
}

pub fn execute_plan(plan: &ExecutionPlan) -> Result<ExecutionOutput> {
    preflight_execution_plan(plan)?;
    let (program, args) = plan
        .argv
        .split_first()
        .ok_or_else(|| anyhow!("execution argv is empty"))?;
    let mut command = Command::new(program);
    command.args(args);
    ensure_managed_directories(program)?;
    apply_managed_environment(&mut command, program);
    let output = command
        .output()
        .with_context(|| format!("executing allowlisted argv {:?}", plan.argv))?;
    Ok(ExecutionOutput {
        status: output.status.code().unwrap_or(-1),
        stdout_sha256: hex_sha256(&output.stdout),
        stderr_sha256: hex_sha256(&output.stderr),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn validate_policy_freshness(plan: &ExecutionPlan) -> Result<()> {
    parse_timestamp(&plan.created_at, "execution plan created_at")?;
    if let Some(fresh_until) = &plan.policy_result.evidence_fresh_until {
        if is_expired(fresh_until)? {
            bail!("policy evidence freshness window has expired");
        }
    }
    Ok(())
}

fn validate_embedded_plan_policy_binding(plan: &ExecutionPlan) -> Result<()> {
    if plan.operation_plan.plan_id != plan.operation_plan_id {
        bail!("embedded operation plan id does not match execution plan operation_plan_id");
    }
    let operation_plan_hash =
        aegis_core::sha256_hex(&plan.operation_plan).context("hashing embedded operation plan")?;
    if operation_plan_hash != plan.operation_plan_hash {
        bail!("embedded operation plan hash does not match execution plan hash");
    }
    if plan.policy_result.plan_hash != plan.operation_plan_hash {
        bail!("policy result is not bound to the embedded operation plan hash");
    }
    let policy_result_hash =
        aegis_core::sha256_hex(&plan.policy_result).context("hashing embedded policy result")?;
    if policy_result_hash != plan.policy_result_hash {
        bail!("embedded policy result hash does not match execution plan hash");
    }
    if plan.policy_decision != plan.policy_result.decision {
        bail!("execution policy decision does not match embedded policy result");
    }
    if plan.policy_version != plan.policy_result.policy_version {
        bail!("execution policy version does not match embedded policy result");
    }
    if plan.evaluator_hash != plan.policy_result.evaluator_hash {
        bail!("execution evaluator hash does not match embedded policy result");
    }
    if plan.required_controls != plan.policy_result.required_controls {
        bail!("execution required controls do not match embedded policy result");
    }
    let expected_targets: Vec<String> = plan.operation_plan.target.iter().cloned().collect();
    if plan.exact_targets != expected_targets {
        bail!("execution exact_targets do not match embedded operation plan target");
    }
    Ok(())
}

fn validate_required_controls(
    plan: &ExecutionPlan,
    approval_public_keys: Option<&[String]>,
) -> Result<()> {
    if plan.policy_decision == PolicyDecision::RequireHuman
        && !plan
            .required_controls
            .iter()
            .any(|control| control == "human approval")
    {
        bail!("require-human policy result must require human approval control");
    }
    if plan.policy_decision == PolicyDecision::AllowWithSnapshot
        && !plan
            .required_controls
            .iter()
            .any(|control| control == "system snapshot")
    {
        bail!("allow-with-snapshot policy result must require system snapshot control");
    }
    for control in &plan.required_controls {
        match control.as_str() {
            "human approval" => validate_human_approval(plan, approval_public_keys)?,
            "system snapshot" => validate_system_snapshot(plan)?,
            other => validate_generic_control_proof(plan, other)?,
        }
    }
    Ok(())
}

fn validate_human_approval(
    plan: &ExecutionPlan,
    approval_public_keys: Option<&[String]>,
) -> Result<()> {
    if plan.approvals.is_empty() {
        bail!("human approval is required but no signed approval is attached");
    }
    let mut trusted_signature_verified = false;
    for approval in &plan.approvals {
        validate_approval_structural(approval, &plan.operation_plan_hash)?;
        if let Some(keys) = approval_public_keys {
            for key in keys {
                if aegis_signing::verify_approval(approval, key).is_ok() {
                    trusted_signature_verified = true;
                    break;
                }
            }
        }
    }
    if let Some(keys) = approval_public_keys {
        if keys.is_empty() {
            bail!("trusted approval public key is required for human-approved execution");
        }
        if !trusted_signature_verified {
            bail!("no approval signature verified with a trusted approval public key");
        }
    }
    Ok(())
}

fn validate_approval_structural(approval: &Approval, operation_plan_hash: &str) -> Result<()> {
    if approval.signer.trim().is_empty() {
        bail!("approval signer is empty");
    }
    if approval.role.trim().is_empty() {
        bail!("approval role is empty");
    }
    if approval.reason.trim().is_empty() {
        bail!("approval reason is empty");
    }
    if approval.plan_hash != operation_plan_hash {
        bail!("approval plan hash does not match execution plan operation hash");
    }
    parse_timestamp(&approval.approved_at, "approval approved_at")?;
    if is_expired(&approval.expires_at)? {
        bail!("approval has expired");
    }
    let signature = approval
        .signature
        .as_ref()
        .ok_or_else(|| anyhow!("approval is unsigned"))?;
    if signature.algorithm != aegis_signing::SIGNATURE_ALGORITHM {
        bail!("approval signature algorithm is not ed25519");
    }
    if signature.key_id.trim().is_empty() || signature.signature.trim().is_empty() {
        bail!("approval signature is incomplete");
    }
    if signature.signature == "covered-by-execution-plan-signature" {
        bail!("placeholder approval signatures are not accepted");
    }
    Ok(())
}

fn validate_system_snapshot(plan: &ExecutionPlan) -> Result<()> {
    let proof = plan
        .control_proofs
        .iter()
        .find(|proof| proof.control == "system snapshot")
        .ok_or_else(|| anyhow!("system snapshot control requires a snapshot proof"))?;
    validate_control_proof_common(proof)?;
    if !matches!(
        proof.proof_type.as_str(),
        "snapshot-id" | "btrfs-snapshot" | "zfs-snapshot" | "lvm-snapshot"
    ) {
        bail!("system snapshot proof type is not supported");
    }
    Ok(())
}

fn validate_generic_control_proof(plan: &ExecutionPlan, control: &str) -> Result<()> {
    let proof = plan
        .control_proofs
        .iter()
        .find(|proof| proof.control == control)
        .ok_or_else(|| anyhow!("required control {control} has no proof"))?;
    validate_control_proof_common(proof)
}

fn validate_control_proof_common(proof: &ControlProof) -> Result<()> {
    if proof.control.trim().is_empty()
        || proof.proof_type.trim().is_empty()
        || proof.value.trim().is_empty()
    {
        bail!("control proof is incomplete");
    }
    parse_timestamp(&proof.created_at, "control proof created_at")?;
    if let Some(expires_at) = &proof.expires_at {
        if is_expired(expires_at)? {
            bail!("control proof has expired");
        }
    }
    Ok(())
}

pub fn validate_argv_allowlist(argv: &[String]) -> Result<()> {
    if argv.is_empty() {
        bail!("argv is empty");
    }
    if argv.iter().any(|arg| contains_shell_metacharacter(arg)) {
        bail!("argv contains shell metacharacters");
    }
    match argv[0].as_str() {
        "apt-get" => validate_apt_get(argv),
        "npm" => validate_npm(argv),
        "python3" => validate_pip(argv),
        "docker" => validate_docker(argv),
        "podman" => validate_podman(argv),
        "nuget" => validate_nuget(argv),
        "code" => validate_vscode(argv),
        "go" => validate_go(argv),
        "cargo" => validate_cargo(argv),
        other => bail!("program {other} is not allowlisted for execution"),
    }
}

fn validate_apt_get(argv: &[String]) -> Result<()> {
    if argv.len() < 2 {
        bail!("apt-get argv is incomplete");
    }
    match argv[1].as_str() {
        "update" => {
            if argv.len() == 2 {
                Ok(())
            } else {
                bail!("apt-get update must not include extra flags")
            }
        }
        "upgrade" => {
            let allowed = [
                "apt-get",
                "upgrade",
                "-y",
                "-o",
                "Dpkg::Options::=--force-confold",
            ];
            if argv == allowed {
                Ok(())
            } else {
                bail!("apt-get upgrade argv does not match the production allowlist")
            }
        }
        "install" => {
            if argv.len() < 4 || argv[2] != "-y" {
                bail!("apt-get install must use exact form: apt-get install -y <pkg[=version]>...");
            }
            for package in &argv[3..] {
                validate_apt_target(package)?;
            }
            Ok(())
        }
        _ => bail!("apt-get subcommand is not allowlisted"),
    }
}

fn validate_apt_target(value: &str) -> Result<()> {
    if value.is_empty() || value.starts_with('-') || value.ends_with(".deb") || value.contains('/')
    {
        bail!("apt target must be a package name or name=version, not a flag/path");
    }
    let valid = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_' | ':' | '~' | '='));
    if !valid {
        bail!("apt target contains invalid characters");
    }
    Ok(())
}

fn validate_npm(argv: &[String]) -> Result<()> {
    let expected_prefix = [
        "npm",
        "install",
        "--global",
        "--prefix",
        NPM_PREFIX,
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    ];
    if argv.len() != expected_prefix.len() + 1 || !argv_has_prefix(argv, &expected_prefix) {
        bail!("npm install must use the production allowlist with managed prefix and disabled lifecycle scripts");
    }
    validate_npm_package_name(argv.last().expect("checked len"))
}

fn validate_pip(argv: &[String]) -> Result<()> {
    let expected_prefix = [
        "python3",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--target",
        PIP_TARGET,
    ];
    if argv.len() != expected_prefix.len() + 1 || !argv_has_prefix(argv, &expected_prefix) {
        bail!("pip install must use the production allowlist with managed target directory");
    }
    validate_simple_package_name(argv.last().expect("checked len"), "pip package")
}

fn validate_docker(argv: &[String]) -> Result<()> {
    if argv.len() != 3 || argv[1] != "pull" {
        bail!("docker must use exact form: docker pull <image>");
    }
    validate_image_reference(&argv[2])
}

fn validate_podman(argv: &[String]) -> Result<()> {
    let expected_prefix = [
        "podman",
        "--root",
        "/var/lib/aegis/podman/storage",
        "--runroot",
        "/run/aegis/podman",
        "pull",
    ];
    if argv.len() != expected_prefix.len() + 1 || !argv_has_prefix(argv, &expected_prefix) {
        bail!("podman pull must use the production allowlist with managed storage roots");
    }
    validate_image_reference(argv.last().expect("checked len"))
}

fn validate_nuget(argv: &[String]) -> Result<()> {
    let expected_prefix = ["nuget", "install"];
    let expected_suffix = ["-OutputDirectory", NUGET_OUTPUT_DIR, "-NonInteractive"];
    if argv.len() != 6 || !argv_has_prefix(argv, &expected_prefix) || argv[3..] != expected_suffix {
        bail!("nuget install must use the production allowlist with managed output directory");
    }
    validate_simple_package_name(&argv[2], "NuGet package")
}

fn validate_vscode(argv: &[String]) -> Result<()> {
    let expected_prefix = ["code", "--install-extension"];
    let expected_suffix = [
        "--user-data-dir",
        VSCODE_USER_DATA_DIR,
        "--extensions-dir",
        VSCODE_EXTENSIONS_DIR,
    ];
    if argv.len() != 7 || !argv_has_prefix(argv, &expected_prefix) || argv[3..] != expected_suffix {
        bail!("VS Code extension install must use the production allowlist with managed extension directories");
    }
    validate_vscode_extension_id(&argv[2])
}

fn validate_go(argv: &[String]) -> Result<()> {
    if argv.len() != 3 || argv[1] != "install" {
        bail!("go install must use exact form: go install <module>@<version>");
    }
    let module = &argv[2];
    validate_go_module(module)?;
    if !module.contains('@') {
        bail!("go install requires an explicit module version");
    }
    Ok(())
}

fn validate_cargo(argv: &[String]) -> Result<()> {
    let expected_prefix = ["cargo", "install", "--locked", "--root", CARGO_ROOT];
    if argv.len() != expected_prefix.len() + 1 || !argv_has_prefix(argv, &expected_prefix) {
        bail!("cargo install must use the production allowlist with --locked and managed root");
    }
    validate_crate_name(argv.last().expect("checked len"))
}

fn argv_has_prefix(argv: &[String], expected: &[&str]) -> bool {
    argv.len() >= expected.len()
        && argv
            .iter()
            .zip(expected.iter())
            .all(|(actual, expected)| actual == expected)
}

fn validate_npm_package_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 214 || name.contains(char::is_whitespace) {
        bail!("invalid npm package name");
    }
    if let Some((scope, package)) = name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        if valid_npm_part(scope) && valid_npm_part(package) {
            return Ok(());
        }
        bail!("invalid npm package name");
    }
    if valid_npm_part(name) {
        Ok(())
    } else {
        bail!("invalid npm package name")
    }
}

fn valid_npm_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn validate_simple_package_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.contains(char::is_whitespace)
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("invalid {label} name");
    }
    Ok(())
}

fn validate_image_reference(image: &str) -> Result<()> {
    if image.is_empty()
        || image.starts_with('-')
        || image.contains(char::is_whitespace)
        || image.contains(" --")
        || !image.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '@' | '+' | '-')
        })
    {
        bail!("invalid container image reference");
    }
    if let Some((_, digest)) = image.split_once('@') {
        let Some(hex_digest) = digest.strip_prefix("sha256:") else {
            bail!("only sha256 image digest pins are supported");
        };
        if hex_digest.len() != 64 || !hex_digest.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("invalid sha256 image digest");
        }
    }
    Ok(())
}

fn validate_vscode_extension_id(extension: &str) -> Result<()> {
    let Some((publisher, name)) = extension.split_once('.') else {
        bail!("invalid VS Code extension id");
    };
    if valid_vscode_part(publisher)
        && !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        Ok(())
    } else {
        bail!("invalid VS Code extension id")
    }
}

fn valid_vscode_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

fn validate_go_module(module: &str) -> Result<()> {
    if module.is_empty()
        || module.starts_with('-')
        || module.contains(char::is_whitespace)
        || module.starts_with("./")
        || module.starts_with("../")
        || module.starts_with('/')
        || module.starts_with('~')
        || module.contains('\\')
        || module.contains(" replace ")
        || !module.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '_' | '~' | '@' | '+' | '-')
        })
    {
        bail!("invalid Go module reference");
    }
    let Some((path, version)) = module.split_once('@') else {
        bail!("go install requires an explicit module version");
    };
    if path.is_empty() || version.is_empty() || version.contains('@') {
        bail!("invalid Go module reference");
    }
    Ok(())
}

fn validate_exact_targets_match_argv(plan: &ExecutionPlan) -> Result<()> {
    if plan.argv.is_empty() {
        bail!("execution argv is empty");
    }
    let Some(actual) = argv_target(&plan.argv) else {
        return Ok(());
    };
    if plan.exact_targets.is_empty() {
        bail!("execution plan exact_targets is empty");
    }
    for target in &plan.exact_targets {
        if target.is_empty() {
            bail!("execution plan exact_targets contains an empty target");
        }
    }
    if !plan.exact_targets.iter().any(|target| {
        target == actual
            || actual
                .strip_prefix(target)
                .is_some_and(|suffix| suffix.starts_with('='))
    }) {
        bail!("execution argv target does not match execution plan exact_targets");
    }
    Ok(())
}

fn argv_target(argv: &[String]) -> Option<&str> {
    match argv.first().map(String::as_str) {
        Some("apt-get") if argv.get(1).map(String::as_str) == Some("install") => {
            argv.last().map(String::as_str)
        }
        Some("npm") | Some("python3") | Some("docker") | Some("podman") | Some("nuget")
        | Some("code") | Some("go") | Some("cargo") => argv.last().map(String::as_str),
        _ => None,
    }
}

fn validate_crate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('-')
        || name.contains(char::is_whitespace)
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        bail!("invalid crate name");
    }
    Ok(())
}

fn apply_managed_environment(command: &mut Command, program: &str) {
    match program {
        "npm" => {
            command.env("HOME", AEGIS_STATE_DIR);
            command.env("NPM_CONFIG_CACHE", "/var/lib/aegis/npm-cache");
        }
        "python3" => {
            command.env("HOME", AEGIS_STATE_DIR);
            command.env("PIP_CACHE_DIR", "/var/lib/aegis/pip-cache");
        }
        "docker" => {
            command.env("DOCKER_CONFIG", "/var/lib/aegis/docker-config");
        }
        "nuget" => {
            command.env("HOME", AEGIS_STATE_DIR);
            command.env("NUGET_PACKAGES", NUGET_OUTPUT_DIR);
        }
        "code" => {
            command.env("HOME", AEGIS_STATE_DIR);
        }
        "go" => {
            command.env("HOME", AEGIS_STATE_DIR);
            command.env("GOPATH", "/var/lib/aegis/go");
            command.env("GOBIN", "/var/lib/aegis/go/bin");
            command.env("GOCACHE", "/var/lib/aegis/go-build-cache");
        }
        "cargo" => {
            command.env("HOME", AEGIS_STATE_DIR);
            command.env("CARGO_HOME", "/var/lib/aegis/cargo-home");
        }
        _ => {}
    }
}

fn ensure_managed_directories(program: &str) -> Result<()> {
    let dirs: &[&str] = match program {
        "npm" => &[NPM_PREFIX, "/var/lib/aegis/npm-cache"],
        "python3" => &[PIP_TARGET, "/var/lib/aegis/pip-cache"],
        "docker" => &["/var/lib/aegis/docker-config"],
        "podman" => &["/var/lib/aegis/podman/storage", "/run/aegis/podman"],
        "nuget" => &[NUGET_OUTPUT_DIR, "/var/lib/aegis/dotnet"],
        "code" => &[VSCODE_USER_DATA_DIR, VSCODE_EXTENSIONS_DIR],
        "go" => &[
            "/var/lib/aegis/go",
            "/var/lib/aegis/go/bin",
            "/var/lib/aegis/go-build-cache",
        ],
        "cargo" => &[CARGO_ROOT, "/var/lib/aegis/cargo-home"],
        _ => &[],
    };
    for dir in dirs {
        fs::create_dir_all(dir).with_context(|| format!("creating managed directory {dir}"))?;
    }
    Ok(())
}

fn is_expired(expires_at: &str) -> Result<bool> {
    let expires = parse_timestamp(expires_at, "expires_at")?;
    Ok(Utc::now() > expires)
}

fn parse_timestamp(value: &str, label: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("parsing {label}"))
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn contains_shell_metacharacter(value: &str) -> bool {
    value.chars().any(|c| {
        matches!(
            c,
            ';' | '&' | '|' | '`' | '$' | '(' | ')' | '<' | '>' | '\n' | '\r' | '\t'
        )
    })
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_shell_metacharacters() {
        let argv = vec![
            "apt-get".into(),
            "install".into(),
            "-y".into(),
            "nginx;id".into(),
        ];
        assert!(validate_argv_allowlist(&argv).is_err());
    }

    #[test]
    fn allows_exact_apt_install_targets() {
        let argv = vec![
            "apt-get".into(),
            "install".into(),
            "-y".into(),
            "nginx=1.24.0-1ubuntu1".into(),
        ];
        validate_argv_allowlist(&argv).unwrap();
    }

    #[test]
    fn denies_direct_deb_install() {
        let argv = vec![
            "apt-get".into(),
            "install".into(),
            "-y".into(),
            "./pkg.deb".into(),
        ];
        assert!(validate_argv_allowlist(&argv).is_err());
    }

    #[test]
    fn allows_managed_npm_install_without_lifecycle_scripts() {
        let argv = vec![
            "npm".into(),
            "install".into(),
            "--global".into(),
            "--prefix".into(),
            NPM_PREFIX.into(),
            "--ignore-scripts".into(),
            "--no-audit".into(),
            "--no-fund".into(),
            "@scope/pkg".into(),
        ];
        validate_argv_allowlist(&argv).unwrap();
    }

    #[test]
    fn denies_npm_install_that_can_run_lifecycle_scripts() {
        let argv = vec!["npm".into(), "install".into(), "pkg".into()];
        assert!(validate_argv_allowlist(&argv).is_err());
    }

    #[test]
    fn allows_managed_pip_install() {
        let argv = vec![
            "python3".into(),
            "-m".into(),
            "pip".into(),
            "install".into(),
            "--disable-pip-version-check".into(),
            "--no-input".into(),
            "--target".into(),
            PIP_TARGET.into(),
            "requests".into(),
        ];
        validate_argv_allowlist(&argv).unwrap();
    }

    #[test]
    fn allows_container_pulls() {
        let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        validate_argv_allowlist(&[
            "docker".into(),
            "pull".into(),
            format!("ghcr.io/org/image@sha256:{digest}"),
        ])
        .unwrap();
        validate_argv_allowlist(&[
            "podman".into(),
            "--root".into(),
            "/var/lib/aegis/podman/storage".into(),
            "--runroot".into(),
            "/run/aegis/podman".into(),
            "pull".into(),
            "registry.example.com/ns/image:1.0".into(),
        ])
        .unwrap();
    }

    #[test]
    fn allows_managed_developer_tool_installs() {
        validate_argv_allowlist(&[
            "nuget".into(),
            "install".into(),
            "Newtonsoft.Json".into(),
            "-OutputDirectory".into(),
            NUGET_OUTPUT_DIR.into(),
            "-NonInteractive".into(),
        ])
        .unwrap();
        validate_argv_allowlist(&[
            "code".into(),
            "--install-extension".into(),
            "ms-python.python".into(),
            "--user-data-dir".into(),
            VSCODE_USER_DATA_DIR.into(),
            "--extensions-dir".into(),
            VSCODE_EXTENSIONS_DIR.into(),
        ])
        .unwrap();
        validate_argv_allowlist(&[
            "go".into(),
            "install".into(),
            "github.com/example/tool@v1.2.3".into(),
        ])
        .unwrap();
        validate_argv_allowlist(&[
            "cargo".into(),
            "install".into(),
            "--locked".into(),
            "--root".into(),
            CARGO_ROOT.into(),
            "ripgrep".into(),
        ])
        .unwrap();
    }

    #[test]
    fn denies_unpinned_go_install() {
        let argv = vec![
            "go".into(),
            "install".into(),
            "github.com/example/tool".into(),
        ];
        assert!(validate_argv_allowlist(&argv).is_err());
    }

    #[test]
    fn denies_malformed_container_digest() {
        let argv = vec![
            "docker".into(),
            "pull".into(),
            "ghcr.io/org/image@sha256:abc123".into(),
        ];
        assert!(validate_argv_allowlist(&argv).is_err());
    }

    #[test]
    fn preflight_denies_argv_target_drift() {
        let drift = test_execution_plan(
            aegis_core::Tool::Npm,
            "install",
            Some("lodash"),
            npm_argv("left-pad"),
            PolicyDecision::Allow,
            Vec::new(),
        );
        assert!(preflight_execution_plan(&drift).is_err());

        let valid = test_execution_plan(
            aegis_core::Tool::Npm,
            "install",
            Some("left-pad"),
            npm_argv("left-pad"),
            PolicyDecision::Allow,
            Vec::new(),
        );
        preflight_execution_plan(&valid).unwrap();
    }

    #[test]
    fn preflight_denies_embedded_policy_plan_hash_drift() {
        let mut plan = test_execution_plan(
            aegis_core::Tool::Apt,
            "update",
            None,
            vec!["apt-get".into(), "update".into()],
            PolicyDecision::Allow,
            Vec::new(),
        );
        plan.policy_result.plan_hash = "different".into();
        assert!(preflight_execution_plan(&plan).is_err());
    }

    #[test]
    fn preflight_requires_snapshot_proof() {
        let mut plan = test_execution_plan(
            aegis_core::Tool::Apt,
            "upgrade",
            None,
            vec![
                "apt-get".into(),
                "upgrade".into(),
                "-y".into(),
                "-o".into(),
                "Dpkg::Options::=--force-confold".into(),
            ],
            PolicyDecision::AllowWithSnapshot,
            vec!["system snapshot".into()],
        );
        assert!(preflight_execution_plan(&plan).is_err());
        plan.control_proofs.push(aegis_core::ControlProof {
            control: "system snapshot".into(),
            proof_type: "snapshot-id".into(),
            value: "snap-123".into(),
            created_at: "2026-05-14T00:00:00Z".into(),
            expires_at: Some("2999-01-01T00:00:00Z".into()),
        });
        preflight_execution_plan(&plan).unwrap();
    }

    #[test]
    fn preflight_rejects_placeholder_human_approval() {
        let mut plan = test_execution_plan(
            aegis_core::Tool::Npm,
            "install",
            Some("left-pad"),
            npm_argv("left-pad"),
            PolicyDecision::RequireHuman,
            vec!["human approval".into()],
        );
        plan.approvals.push(aegis_core::Approval {
            signer: "alice".into(),
            role: "human-approver".into(),
            reason: "reviewed".into(),
            approved_at: "2026-05-14T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            plan_hash: plan.operation_plan_hash.clone(),
            signature: Some(aegis_core::SignatureEnvelope {
                algorithm: "ed25519".into(),
                key_id: "approval".into(),
                signature: "covered-by-execution-plan-signature".into(),
            }),
        });
        assert!(preflight_execution_plan(&plan).is_err());
    }

    #[test]
    fn preflight_verifies_trusted_approval_key() {
        const SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let mut plan = test_execution_plan(
            aegis_core::Tool::Npm,
            "install",
            Some("left-pad"),
            npm_argv("left-pad"),
            PolicyDecision::RequireHuman,
            vec!["human approval".into()],
        );
        let mut approval = aegis_core::Approval {
            signer: "alice".into(),
            role: "human-approver".into(),
            reason: "reviewed".into(),
            approved_at: "2026-05-14T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            plan_hash: plan.operation_plan_hash.clone(),
            signature: None,
        };
        aegis_signing::sign_approval(&mut approval, "approval", SECRET).unwrap();
        plan.approvals.push(approval);
        let public_key = aegis_signing::public_key_from_secret_hex(SECRET).unwrap();
        preflight_execution_plan_with_approval_keys(&plan, &[public_key]).unwrap();
        assert!(preflight_execution_plan_with_approval_keys(&plan, &[]).is_err());
    }

    fn test_execution_plan(
        tool: aegis_core::Tool,
        operation: &str,
        target: Option<&str>,
        argv: Vec<String>,
        decision: PolicyDecision,
        required_controls: Vec<String>,
    ) -> ExecutionPlan {
        let op = aegis_core::OperationPlan::new(tool, operation, target.map(str::to_string));
        let op_hash = aegis_core::sha256_hex(&op).unwrap();
        let policy = aegis_core::PolicyResult {
            decision,
            reasons: vec!["test".into()],
            required_controls,
            policy_version: "test".into(),
            evaluator_hash: "test".into(),
            plan_hash: op_hash.clone(),
            evidence_fresh_until: None,
        };
        let policy_hash = aegis_core::sha256_hex(&policy).unwrap();
        let mut plan = ExecutionPlan::new(
            &op,
            &policy,
            argv,
            "test",
            "2999-01-01T00:00:00Z",
            op_hash,
            policy_hash,
        );
        plan.signature = Some(aegis_core::SignatureEnvelope {
            algorithm: "ed25519".into(),
            key_id: "test".into(),
            signature: "test".into(),
        });
        plan
    }

    fn npm_argv(target: &str) -> Vec<String> {
        vec![
            "npm".into(),
            "install".into(),
            "--global".into(),
            "--prefix".into(),
            NPM_PREFIX.into(),
            "--ignore-scripts".into(),
            "--no-audit".into(),
            "--no-fund".into(),
            target.into(),
        ]
    }
}
