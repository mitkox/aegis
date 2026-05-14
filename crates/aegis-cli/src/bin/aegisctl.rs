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
        _ => bail!("production execution is currently enabled only for APT plans"),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}
