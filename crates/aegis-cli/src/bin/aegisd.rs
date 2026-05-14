#![forbid(unsafe_code)]

use aegis_core::{AuditEventKind, ExecutionPlan};
use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;

#[derive(Debug, Parser)]
#[command(
    name = "aegisd",
    version,
    about = "Aegis production root execution gate"
)]
struct Cli {
    #[arg(long, default_value = "/run/aegis/aegisd.sock")]
    socket: PathBuf,
    #[arg(long)]
    public_key_hex: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let public_key_hex = cli
        .public_key_hex
        .or_else(|| std::env::var("AEGIS_SIGNING_PUBLIC_KEY_HEX").ok())
        .context("missing --public-key-hex or AEGIS_SIGNING_PUBLIC_KEY_HEX")?;

    if let Some(parent) = cli.socket.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if cli.socket.exists() {
        fs::remove_file(&cli.socket)
            .with_context(|| format!("removing stale {}", cli.socket.display()))?;
    }
    let listener = UnixListener::bind(&cli.socket)
        .with_context(|| format!("binding {}", cli.socket.display()))?;
    set_socket_permissions(&cli.socket)?;
    println!("aegisd listening on {}", cli.socket.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let public_key_hex = public_key_hex.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_client(stream, &public_key_hex) {
                        eprintln!("request failed: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("accept failed: {error:#}"),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_socket_permissions(socket: &PathBuf) -> Result<()> {
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660))
        .with_context(|| format!("setting permissions on {}", socket.display()))
}

#[cfg(not(unix))]
fn set_socket_permissions(_socket: &PathBuf) -> Result<()> {
    Ok(())
}

fn handle_client(mut stream: UnixStream, public_key_hex: &str) -> Result<()> {
    let mut raw = String::new();
    stream.read_to_string(&mut raw).context("reading request")?;
    let plan: ExecutionPlan = serde_json::from_str(&raw).context("parsing execution plan")?;
    let response = match apply_plan(&plan, public_key_hex) {
        Ok(output) => serde_json::json!({ "ok": true, "output": output }),
        Err(error) => {
            let event = aegis_audit::new_audit_event(
                AuditEventKind::ExecutionDenied,
                Some(plan.signer_identity.clone()),
                Some(plan.operation_plan_id.clone()),
                Some(plan.execution_plan_id.clone()),
                plan.argv.clone(),
                Some(plan.policy_decision.clone()),
                serde_json::json!({ "error": error.to_string() }),
            );
            let _ = aegis_audit::append_audit_event(event);
            serde_json::json!({ "ok": false, "error": error.to_string() })
        }
    };
    writeln!(stream, "{}", serde_json::to_string(&response)?).context("writing response")?;
    Ok(())
}

fn apply_plan(
    plan: &ExecutionPlan,
    public_key_hex: &str,
) -> Result<aegis_executor::ExecutionOutput> {
    aegis_signing::verify_execution_plan(plan, public_key_hex)?;
    aegis_executor::preflight_execution_plan(plan)?;
    aegis_audit::append_audit_event(aegis_audit::new_audit_event(
        AuditEventKind::ExecutionStarted,
        Some(plan.signer_identity.clone()),
        Some(plan.operation_plan_id.clone()),
        Some(plan.execution_plan_id.clone()),
        plan.argv.clone(),
        Some(plan.policy_decision.clone()),
        serde_json::json!({ "source": "aegisd" }),
    ))?;
    let output = aegis_executor::execute_plan(plan)?;
    let mut completed = aegis_audit::new_audit_event(
        AuditEventKind::ExecutionCompleted,
        Some(plan.signer_identity.clone()),
        Some(plan.operation_plan_id.clone()),
        Some(plan.execution_plan_id.clone()),
        plan.argv.clone(),
        Some(plan.policy_decision.clone()),
        serde_json::json!({ "source": "aegisd" }),
    );
    completed.exit_status = Some(output.status);
    completed.stdout_sha256 = Some(output.stdout_sha256.clone());
    completed.stderr_sha256 = Some(output.stderr_sha256.clone());
    aegis_audit::append_audit_event(completed)?;
    Ok(output)
}
