#![forbid(unsafe_code)]

use aegis_core::{
    Approval, ExecutionPlan, OperationPlan, PolicyDecision, PolicyResult, SignatureEnvelope,
};
use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const NPM_PREFIX: &str = "/var/lib/aegis/npm-global";
const PIP_TARGET: &str = "/var/lib/aegis/pip-packages";
const NUGET_OUTPUT_DIR: &str = "/var/lib/aegis/nuget/packages";
const VSCODE_USER_DATA_DIR: &str = "/var/lib/aegis/vscode/user-data";
const VSCODE_EXTENSIONS_DIR: &str = "/var/lib/aegis/vscode/extensions";
const CARGO_ROOT: &str = "/var/lib/aegis/cargo";

#[derive(Debug, Parser)]
#[command(name = "aegisctl", version, about = "Production control CLI for Aegis")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create and sign an execution plan from an operation plan and policy result.
    Sign {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        secret_key_hex: Option<String>,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        signer: String,
        #[arg(long)]
        approval_reason: Option<String>,
        #[arg(long, default_value_t = 30)]
        expires_in_minutes: i64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify and apply a signed execution plan through the local constrained executor.
    Apply {
        #[arg(long)]
        execution_plan: PathBuf,
        #[arg(long)]
        public_key_hex: String,
        #[arg(long, default_value = "/run/aegis/aegisd.sock")]
        socket: PathBuf,
    },
    /// Verify a signed execution plan without executing it.
    Verify {
        #[arg(long)]
        execution_plan: PathBuf,
        #[arg(long)]
        public_key_hex: String,
    },
    /// Generate an Ed25519 signing keypair for execution-plan signing.
    Keygen,
    /// Print the production audit log path.
    AuditPath,
}

struct SignRequest {
    plan_path: PathBuf,
    policy_path: PathBuf,
    secret_key_hex: Option<String>,
    key_id: String,
    signer: String,
    approval_reason: Option<String>,
    expires_in_minutes: i64,
    out: Option<PathBuf>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Sign {
            plan,
            policy,
            secret_key_hex,
            key_id,
            signer,
            approval_reason,
            expires_in_minutes,
            out,
        } => sign(SignRequest {
            plan_path: plan,
            policy_path: policy,
            secret_key_hex,
            key_id,
            signer,
            approval_reason,
            expires_in_minutes,
            out,
        }),
        Command::Apply {
            execution_plan,
            public_key_hex,
            socket,
        } => apply(&execution_plan, &public_key_hex, &socket),
        Command::Verify {
            execution_plan,
            public_key_hex,
        } => verify(&execution_plan, &public_key_hex),
        Command::Keygen => keygen(),
        Command::AuditPath => {
            println!("{}", aegis_audit::audit_log_dir().display());
            Ok(())
        }
    }
}

fn sign(request: SignRequest) -> Result<()> {
    let plan: OperationPlan = read_json(&request.plan_path)?;
    let policy: PolicyResult = read_json(&request.policy_path)?;
    validate_policy_result_version(&policy)?;
    if policy.decision == PolicyDecision::Deny {
        bail!(
            "refusing to sign denied policy result: {}",
            policy.reasons.join("; ")
        );
    }
    if policy.decision == PolicyDecision::RequireHuman && request.approval_reason.is_none() {
        bail!("policy requires human approval; pass --approval-reason");
    }
    let secret = request
        .secret_key_hex
        .or_else(|| std::env::var("AEGIS_SIGNING_SECRET_KEY_HEX").ok())
        .context("missing --secret-key-hex or AEGIS_SIGNING_SECRET_KEY_HEX")?;
    let expires_at = (Utc::now() + Duration::minutes(request.expires_in_minutes)).to_rfc3339();
    let op_hash = aegis_signing::sha256_hex(&plan)?;
    let policy_hash = aegis_signing::sha256_hex(&policy)?;
    let argv = execution_argv_from_plan(&plan)?;
    let mut execution_plan = ExecutionPlan::new(
        &plan,
        &policy,
        argv,
        request.signer.clone(),
        expires_at.clone(),
        op_hash.clone(),
        policy_hash,
    );
    if let Some(reason) = request.approval_reason {
        execution_plan.approvals.push(Approval {
            signer: request.signer.clone(),
            reason,
            approved_at: Utc::now().to_rfc3339(),
            expires_at,
            plan_hash: op_hash,
            signature: SignatureEnvelope {
                algorithm: "ed25519".into(),
                key_id: request.key_id.clone(),
                signature: "covered-by-execution-plan-signature".into(),
            },
        });
    }
    aegis_signing::sign_execution_plan(&mut execution_plan, request.key_id, &secret)?;
    aegis_executor::preflight_execution_plan(&execution_plan)?;
    let raw = serde_json::to_string_pretty(&execution_plan)?;
    if let Some(path) = request.out {
        fs::write(&path, &raw).with_context(|| format!("writing {}", path.display()))?;
        println!("execution_plan_path: {}", path.display());
    }
    println!("{raw}");
    Ok(())
}

fn apply(path: &Path, public_key_hex: &str, socket: &Path) -> Result<()> {
    let plan: ExecutionPlan = read_json(path)?;
    aegis_signing::verify_execution_plan(&plan, public_key_hex)?;
    aegis_executor::preflight_execution_plan(&plan)?;
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("connecting {}", socket.display()))?;
    stream
        .write_all(serde_json::to_string(&plan)?.as_bytes())
        .context("sending execution plan to aegisd")?;
    stream.shutdown(std::net::Shutdown::Write).ok();
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("reading aegisd response")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::from_str::<serde_json::Value>(&response)?)?
    );
    Ok(())
}

fn verify(path: &Path, public_key_hex: &str) -> Result<()> {
    let plan: ExecutionPlan = read_json(path)?;
    aegis_signing::verify_execution_plan(&plan, public_key_hex)?;
    aegis_executor::preflight_execution_plan(&plan)?;
    println!("ok: execution plan signature and preflight are valid");
    Ok(())
}

fn keygen() -> Result<()> {
    let keypair = aegis_signing::generate_keypair()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "algorithm": aegis_signing::SIGNATURE_ALGORITHM,
            "secret_key_hex": keypair.secret_key_hex,
            "public_key_hex": keypair.public_key_hex,
        }))?
    );
    Ok(())
}

fn execution_argv_from_plan(plan: &OperationPlan) -> Result<Vec<String>> {
    match (plan.tool.clone(), plan.operation.as_str()) {
        (aegis_core::Tool::Apt, "update") => Ok(vec!["apt-get".into(), "update".into()]),
        (aegis_core::Tool::Apt, "upgrade") => Ok(vec![
            "apt-get".into(),
            "upgrade".into(),
            "-y".into(),
            "-o".into(),
            "Dpkg::Options::=--force-confold".into(),
        ]),
        (aegis_core::Tool::Apt, "install") => {
            let target = plan
                .target
                .as_ref()
                .context("apt install plan is missing target package")?;
            let exact = plan
                .target_version
                .as_ref()
                .map(|version| format!("{target}={version}"))
                .unwrap_or_else(|| target.clone());
            Ok(vec!["apt-get".into(), "install".into(), "-y".into(), exact])
        }
        (aegis_core::Tool::Npm, "install") => {
            let target = required_target(plan, "npm install")?;
            aegis_npm::validate_npm_package_name(target)?;
            Ok(vec![
                "npm".into(),
                "install".into(),
                "--global".into(),
                "--prefix".into(),
                NPM_PREFIX.into(),
                "--ignore-scripts".into(),
                "--no-audit".into(),
                "--no-fund".into(),
                target.into(),
            ])
        }
        (aegis_core::Tool::Pip, "install") => {
            let target = required_target(plan, "pip install")?;
            aegis_pip::validate_pip_package_name(target)?;
            Ok(vec![
                "python3".into(),
                "-m".into(),
                "pip".into(),
                "install".into(),
                "--disable-pip-version-check".into(),
                "--no-input".into(),
                "--target".into(),
                PIP_TARGET.into(),
                target.into(),
            ])
        }
        (aegis_core::Tool::Container, "pull") => {
            let target = required_target(plan, "container pull")?;
            aegis_container::validate_image_reference(target)?;
            let runtime = plan
                .command_preview
                .first()
                .map(String::as_str)
                .unwrap_or("docker");
            match runtime {
                "docker" => Ok(vec!["docker".into(), "pull".into(), target.into()]),
                "podman" => Ok(vec![
                    "podman".into(),
                    "--root".into(),
                    "/var/lib/aegis/podman/storage".into(),
                    "--runroot".into(),
                    "/run/aegis/podman".into(),
                    "pull".into(),
                    target.into(),
                ]),
                other => bail!("unsupported container runtime in plan: {other}"),
            }
        }
        (aegis_core::Tool::Nuget, "install") => {
            let target = required_target(plan, "nuget install")?;
            aegis_nuget::validate_nuget_package_id(target)?;
            Ok(vec![
                "nuget".into(),
                "install".into(),
                target.into(),
                "-OutputDirectory".into(),
                NUGET_OUTPUT_DIR.into(),
                "-NonInteractive".into(),
            ])
        }
        (aegis_core::Tool::Vscode, "install") => {
            let target = required_target(plan, "VS Code extension install")?;
            aegis_vscode::validate_extension_id(target)?;
            Ok(vec![
                "code".into(),
                "--install-extension".into(),
                target.into(),
                "--user-data-dir".into(),
                VSCODE_USER_DATA_DIR.into(),
                "--extensions-dir".into(),
                VSCODE_EXTENSIONS_DIR.into(),
            ])
        }
        (aegis_core::Tool::Go, "get") => {
            let target = required_target(plan, "go get")?;
            aegis_go::validate_go_module(target)?;
            if target
                .rsplit_once('@')
                .is_none_or(|(_, version)| version.is_empty())
            {
                bail!("production Go execution requires an explicit module version");
            }
            Ok(vec!["go".into(), "install".into(), target.into()])
        }
        (aegis_core::Tool::Cargo, "install") => {
            let target = required_target(plan, "cargo install")?;
            aegis_cargo::validate_crate_name(target)?;
            Ok(vec![
                "cargo".into(),
                "install".into(),
                "--locked".into(),
                "--root".into(),
                CARGO_ROOT.into(),
                target.into(),
            ])
        }
        _ => bail!("operation is not enabled for production execution"),
    }
}

fn required_target<'a>(plan: &'a OperationPlan, operation: &str) -> Result<&'a str> {
    plan.target
        .as_deref()
        .with_context(|| format!("{operation} plan is missing target"))
}

fn validate_policy_result_version(policy: &PolicyResult) -> Result<()> {
    if policy.policy_version != aegis_policy::POLICY_VERSION {
        bail!(
            "policy result version {} does not match evaluator {}",
            policy.policy_version,
            aegis_policy::POLICY_VERSION
        );
    }
    if policy.evaluator_hash != aegis_policy::EVALUATOR_HASH {
        bail!(
            "policy result evaluator hash {} does not match {}",
            policy.evaluator_hash,
            aegis_policy::EVALUATOR_HASH
        );
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{OperationPlan, Tool};

    fn plan(tool: Tool, operation: &str, target: &str) -> OperationPlan {
        OperationPlan::new(tool, operation, Some(target.to_string()))
    }

    #[test]
    fn derives_npm_execution_argv_with_scripts_disabled() {
        let argv = execution_argv_from_plan(&plan(Tool::Npm, "install", "lodash")).unwrap();
        assert_eq!(
            argv,
            vec![
                "npm",
                "install",
                "--global",
                "--prefix",
                NPM_PREFIX,
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "lodash"
            ]
        );
    }

    #[test]
    fn derives_managed_execution_argv_for_all_non_apt_ecosystems() {
        assert_eq!(
            execution_argv_from_plan(&plan(Tool::Pip, "install", "requests")).unwrap(),
            vec![
                "python3",
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--target",
                PIP_TARGET,
                "requests"
            ]
        );
        let mut container = plan(Tool::Container, "pull", "ubuntu:24.04");
        container.command_preview = vec!["docker".into(), "manifest".into(), "inspect".into()];
        assert_eq!(
            execution_argv_from_plan(&container).unwrap(),
            vec!["docker", "pull", "ubuntu:24.04"]
        );
        assert_eq!(
            execution_argv_from_plan(&plan(Tool::Nuget, "install", "Newtonsoft.Json")).unwrap(),
            vec![
                "nuget",
                "install",
                "Newtonsoft.Json",
                "-OutputDirectory",
                NUGET_OUTPUT_DIR,
                "-NonInteractive"
            ]
        );
        assert_eq!(
            execution_argv_from_plan(&plan(Tool::Vscode, "install", "ms-python.python")).unwrap(),
            vec![
                "code",
                "--install-extension",
                "ms-python.python",
                "--user-data-dir",
                VSCODE_USER_DATA_DIR,
                "--extensions-dir",
                VSCODE_EXTENSIONS_DIR
            ]
        );
        assert_eq!(
            execution_argv_from_plan(&plan(Tool::Cargo, "install", "ripgrep")).unwrap(),
            vec!["cargo", "install", "--locked", "--root", CARGO_ROOT, "ripgrep"]
        );
    }

    #[test]
    fn derives_podman_execution_argv_with_managed_storage() {
        let mut container = plan(Tool::Container, "pull", "registry.example.com/ns/image:1.0");
        container.command_preview = vec!["podman".into(), "manifest".into(), "inspect".into()];
        assert_eq!(
            execution_argv_from_plan(&container).unwrap(),
            vec![
                "podman",
                "--root",
                "/var/lib/aegis/podman/storage",
                "--runroot",
                "/run/aegis/podman",
                "pull",
                "registry.example.com/ns/image:1.0"
            ]
        );
    }

    #[test]
    fn requires_pinned_go_module_for_execution() {
        assert!(execution_argv_from_plan(&plan(Tool::Go, "get", "github.com/acme/tool")).is_err());
        assert!(execution_argv_from_plan(&plan(Tool::Go, "get", "github.com/acme/tool@")).is_err());
        assert_eq!(
            execution_argv_from_plan(&plan(Tool::Go, "get", "github.com/acme/tool@v1.0.0"))
                .unwrap(),
            vec!["go", "install", "github.com/acme/tool@v1.0.0"]
        );
    }

    #[test]
    fn rejects_stale_policy_result_version() {
        let policy = PolicyResult {
            decision: PolicyDecision::Allow,
            reasons: vec!["ok".into()],
            required_controls: Vec::new(),
            policy_version: "0.2.5".into(),
            evaluator_hash: aegis_policy::EVALUATOR_HASH.into(),
            evidence_fresh_until: None,
        };
        assert!(validate_policy_result_version(&policy).is_err());
    }
}
