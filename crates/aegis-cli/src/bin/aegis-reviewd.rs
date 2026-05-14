#![forbid(unsafe_code)]

use aegis_core::{AuditEventKind, OperationPlan};
use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "aegis-reviewd",
    version,
    about = "Unprivileged Aegis local model reviewer"
)]
struct Cli {
    #[arg(long, default_value = "/run/aegis/aegis-reviewd.sock")]
    socket: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
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
    println!("aegis-reviewd listening on {}", cli.socket.display());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_client(stream) {
                    eprintln!("review request failed: {error:#}");
                }
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

fn handle_client(mut stream: UnixStream) -> Result<()> {
    let mut raw = String::new();
    stream.read_to_string(&mut raw).context("reading request")?;
    let plan: OperationPlan = serde_json::from_str(&raw).context("parsing operation plan")?;
    let response = match aegis_ai::review_plan(&plan) {
        Ok(aegis_ai::ReviewOutcome::Valid(review)) => {
            let _ = aegis_audit::append_audit_event(aegis_audit::new_audit_event(
                AuditEventKind::ReviewCompleted,
                Some("aegis-reviewd".into()),
                Some(plan.plan_id.clone()),
                None,
                Vec::new(),
                None,
                serde_json::json!({ "risk": review.risk }),
            ));
            serde_json::json!({ "ok": true, "review": review })
        }
        Ok(aegis_ai::ReviewOutcome::Invalid {
            error,
            raw_response,
        }) => {
            serde_json::json!({ "ok": false, "error": error, "raw_response": raw_response })
        }
        Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
    };
    writeln!(stream, "{}", serde_json::to_string(&response)?).context("writing response")?;
    Ok(())
}
