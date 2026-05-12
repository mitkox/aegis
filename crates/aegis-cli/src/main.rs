#![forbid(unsafe_code)]

use aegis_ai::ReviewOutcome;
use aegis_core::OperationPlan;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Parser)]
#[command(
    name = "aegis",
    version,
    about = "Local zero-trust package operation broker"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Doctor,
    Apt {
        #[command(subcommand)]
        command: AptCommand,
    },
    Npm {
        #[command(subcommand)]
        command: NpmCommand,
    },
    Pip {
        #[command(subcommand)]
        command: PipCommand,
    },
    Container {
        #[command(subcommand)]
        command: ContainerCommand,
    },
    Docker {
        #[command(subcommand)]
        command: DockerCommand,
    },
    Podman {
        #[command(subcommand)]
        command: PodmanCommand,
    },
    Nuget {
        #[command(subcommand)]
        command: NugetCommand,
    },
    Vscode {
        #[command(subcommand)]
        command: VscodeCommand,
    },
    Go {
        #[command(subcommand)]
        command: GoCommand,
    },
    Cargo {
        #[command(subcommand)]
        command: CargoCommand,
    },
    Review {
        plan_file: PathBuf,
    },
    Policy {
        plan_file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AptCommand {
    Update(PlanApplyArgs),
    Upgrade(PlanApplyArgs),
    Install {
        package: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Subcommand)]
enum NpmCommand {
    Install {
        package: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Subcommand)]
enum PipCommand {
    Install {
        package: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Subcommand)]
enum ContainerCommand {
    Pull {
        image: String,
        #[arg(long, default_value = "docker")]
        runtime: RuntimeArg,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum RuntimeArg {
    Docker,
    Podman,
}

impl From<RuntimeArg> for aegis_container::ContainerRuntime {
    fn from(value: RuntimeArg) -> Self {
        match value {
            RuntimeArg::Docker => Self::Docker,
            RuntimeArg::Podman => Self::Podman,
        }
    }
}

#[derive(Debug, Subcommand)]
enum DockerCommand {
    Pull {
        image: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Subcommand)]
enum PodmanCommand {
    Pull {
        image: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Subcommand)]
enum NugetCommand {
    Install {
        package: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Subcommand)]
enum VscodeCommand {
    Install {
        extension: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Subcommand)]
enum GoCommand {
    Get {
        module: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Subcommand)]
enum CargoCommand {
    Install {
        crate_name: String,
        #[command(flatten)]
        args: PlanApplyArgs,
    },
}

#[derive(Debug, Args)]
struct PlanApplyArgs {
    #[arg(long)]
    plan: bool,
    #[arg(long)]
    apply: bool,
    #[arg(long)]
    plan_id: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => doctor(),
        Commands::Apt { command } => handle_apt(command),
        Commands::Npm { command } => handle_npm(command),
        Commands::Pip { command } => handle_pip(command),
        Commands::Container { command } => handle_container(command),
        Commands::Docker { command } => handle_docker(command),
        Commands::Podman { command } => handle_podman(command),
        Commands::Nuget { command } => handle_nuget(command),
        Commands::Vscode { command } => handle_vscode(command),
        Commands::Go { command } => handle_go(command),
        Commands::Cargo { command } => handle_cargo(command),
        Commands::Review { plan_file } => review(&plan_file),
        Commands::Policy { plan_file } => policy(&plan_file),
    }
}

fn handle_apt(command: AptCommand) -> Result<()> {
    match command {
        AptCommand::Update(args) => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_apt::plan_update())
        }
        AptCommand::Upgrade(args) => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_apt::plan_upgrade()?)
        }
        AptCommand::Install { package, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_apt::plan_install(&package)?)
        }
    }
}

fn handle_npm(command: NpmCommand) -> Result<()> {
    match command {
        NpmCommand::Install { package, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_npm::plan_install(&package)?)
        }
    }
}

fn handle_pip(command: PipCommand) -> Result<()> {
    match command {
        PipCommand::Install { package, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_pip::plan_install(&package)?)
        }
    }
}

fn handle_container(command: ContainerCommand) -> Result<()> {
    match command {
        ContainerCommand::Pull {
            image,
            runtime,
            args,
        } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_container::plan_pull(&image, runtime.into())?)
        }
    }
}

fn handle_docker(command: DockerCommand) -> Result<()> {
    match command {
        DockerCommand::Pull { image, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_container::plan_pull(
                &image,
                aegis_container::ContainerRuntime::Docker,
            )?)
        }
    }
}

fn handle_podman(command: PodmanCommand) -> Result<()> {
    match command {
        PodmanCommand::Pull { image, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_container::plan_pull(
                &image,
                aegis_container::ContainerRuntime::Podman,
            )?)
        }
    }
}

fn handle_nuget(command: NugetCommand) -> Result<()> {
    match command {
        NugetCommand::Install { package, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_nuget::plan_install(&package)?)
        }
    }
}

fn handle_vscode(command: VscodeCommand) -> Result<()> {
    match command {
        VscodeCommand::Install { extension, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_vscode::plan_install(&extension)?)
        }
    }
}

fn handle_go(command: GoCommand) -> Result<()> {
    match command {
        GoCommand::Get { module, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_go::plan_get(&module)?)
        }
    }
}

fn handle_cargo(command: CargoCommand) -> Result<()> {
    match command {
        CargoCommand::Install { crate_name, args } => {
            ensure_plan_or_apply(&args)?;
            if args.apply {
                print_apply_unimplemented();
                return Ok(());
            }
            save_plan(aegis_cargo::plan_install(&crate_name)?)
        }
    }
}

fn ensure_plan_or_apply(args: &PlanApplyArgs) -> Result<()> {
    if args.apply {
        if args.plan_id.is_none() {
            bail!("--apply requires --plan-id <id>");
        }
        return Ok(());
    }
    if !args.plan {
        bail!("MVP supports planning only; pass --plan");
    }
    Ok(())
}

fn print_apply_unimplemented() {
    println!("apply is not implemented in MVP; only signed plan generation is supported");
}

fn save_plan(plan: OperationPlan) -> Result<()> {
    aegis_audit::ensure_dirs()?;
    let filename = format!("{}.json", plan.plan_id);
    let path = aegis_audit::write_json(aegis_audit::plans_dir()?, &filename, &plan)?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    println!("plan_path: {}", path.display());
    Ok(())
}

fn read_plan(path: &Path) -> Result<OperationPlan> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn review(plan_file: &Path) -> Result<()> {
    aegis_audit::ensure_dirs()?;
    let plan = read_plan(plan_file)?;
    match aegis_ai::review_plan(&plan)? {
        ReviewOutcome::Valid(review) => {
            let filename = format!("{}.review.json", plan.plan_id);
            let path = aegis_audit::write_json(aegis_audit::reviews_dir()?, &filename, &review)?;
            println!("{}", serde_json::to_string_pretty(&review)?);
            println!("review_path: {}", path.display());
            Ok(())
        }
        ReviewOutcome::Invalid {
            raw_response,
            error,
        } => {
            let filename = format!("{}.review.raw", plan.plan_id);
            let path =
                aegis_audit::write_text(aegis_audit::reviews_dir()?, &filename, &raw_response)?;
            bail!(
                "AI review response was invalid JSON/schema: {error}; raw_response_path: {}",
                path.display()
            )
        }
    }
}

fn policy(plan_file: &Path) -> Result<()> {
    aegis_audit::ensure_dirs()?;
    let plan = read_plan(plan_file)?;
    let config = aegis_policy::load_policy_config(resolve_policy_path())?;
    let result = aegis_policy::evaluate(&plan, &config);
    let filename = format!("{}.policy.json", plan.plan_id);
    let path = aegis_audit::write_json(aegis_audit::policy_dir()?, &filename, &result)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    println!("policy_path: {}", path.display());
    Ok(())
}

/// Resolve the policy configuration file path.
///
/// Priority: `$AEGIS_POLICY_FILE` > `$XDG_CONFIG_HOME/aegis/policy.toml`
/// > `$HOME/.config/aegis/policy.toml` > `policies/default-policy.toml`.
fn resolve_policy_path() -> PathBuf {
    if let Ok(path) = std::env::var("AEGIS_POLICY_FILE") {
        return PathBuf::from(path);
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(xdg).join("aegis/policy.toml");
        if path.exists() {
            return path;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let path = PathBuf::from(home).join(".config/aegis/policy.toml");
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("policies/default-policy.toml")
}

fn doctor() -> Result<()> {
    let checks = vec![
        (
            "apt-get",
            "required for apt planning",
            command_available("apt-get"),
        ),
        (
            "apt-cache",
            "required for apt doctor checks",
            command_available("apt-cache"),
        ),
        ("npm", "optional for npm metadata", command_available("npm")),
        (
            "python3",
            "optional for pip metadata",
            command_available("python3"),
        ),
        (
            "python3 -m pip",
            "optional for pip metadata",
            python_pip_available(),
        ),
        (
            "docker",
            "optional for container manifests",
            command_available("docker"),
        ),
        (
            "podman",
            "optional for container manifests",
            command_available("podman"),
        ),
        (
            "dotnet",
            "optional for NuGet metadata",
            command_available("dotnet"),
        ),
        (
            "code",
            "optional for VS Code extension metadata",
            command_available("code"),
        ),
        (
            "go",
            "optional for Go module metadata",
            command_available("go"),
        ),
        (
            "cargo",
            "optional for Cargo crate metadata",
            command_available("cargo"),
        ),
    ];
    for (name, note, ok) in checks {
        if ok {
            println!("available: {name} ({note})");
        } else {
            println!("missing: {name} ({note})");
        }
    }

    match aegis_ai::check_models_endpoint() {
        Ok(()) => {
            println!(
                "available: model endpoint at {}/models",
                aegis_ai::configured_base_url()
            );
            match aegis_ai::check_default_model_available() {
                Ok(Some(true)) => println!("available: model {}", aegis_ai::configured_model()),
                Ok(Some(false)) => println!(
                    "missing: model {} not listed by endpoint",
                    aegis_ai::configured_model()
                ),
                Ok(None) => println!("optional: model list did not expose a data array"),
                Err(err) => println!("optional: could not inspect model list: {err}"),
            }
        }
        Err(err) => println!(
            "missing: model endpoint unavailable at {}/models: {err}",
            aegis_ai::configured_base_url()
        ),
    }

    let data = aegis_audit::data_dir()?;
    match aegis_audit::check_writable(data.clone()) {
        Ok(()) => println!("ok: can write {}", data.display()),
        Err(err) => println!("error: cannot write data dir: {err}"),
    }
    let cache = aegis_audit::cache_dir()?;
    match aegis_audit::check_writable(cache.clone()) {
        Ok(()) => println!("ok: can write {}", cache.display()),
        Err(err) => println!("error: cannot write cache dir: {err}"),
    }
    Ok(())
}

fn command_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|output| {
            output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty()
        })
        .unwrap_or(false)
}

fn python_pip_available() -> bool {
    Command::new("python3")
        .args(["-m", "pip", "--version"])
        .output()
        .map(|output| {
            output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty()
        })
        .unwrap_or(false)
}
