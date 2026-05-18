// crates/aegis-brew/src/lib.rs
//
// Homebrew planning adapter for Aegis. Skeleton only — no apply path.
//
// Conventions match crates/aegis-apt/src/lib.rs (canonical template)
// and crates/aegis-cargo/src/lib.rs (unprivileged-ecosystem template).
//
// Invariants (per AGENTS.md):
//   - No sudo, no shell=True, no model-generated commands.
//   - --plan is read-only. Only `brew info --json=v2` and
//     `brew install --dry-run` are invoked.
//   - Deny-path tests must exist before happy-path tests for new logic.
//   - Command preview is an argv array, not a shell string.
//   - Formula name is validated before being placed in subprocess argv.
//
// Apply path is intentionally absent. `Tool::Brew` is deterministically
// denied at apply time until v0.4 introduces signed-argv enforcement
// with bottle-sha256 pinning.

#![forbid(unsafe_code)]

use aegis_core::{
    denied_plan, has_shell_metacharacters, is_url_like, looks_like_local_path, push_unique,
    OperationPlan, Tool,
};
use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::process::Command;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a Homebrew formula name. Accepts plain names (`poppler`),
/// versioned names (`postgresql@16`), and tap-qualified names
/// (`homebrew/core/gh`). Rejects URLs, paths, and shell metacharacters.
pub fn validate_formula_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('-')
        || name.contains(char::is_whitespace)
        || has_shell_metacharacters(name)
    {
        return Err(anyhow!("invalid homebrew formula name"));
    }
    // Allow A-Z a-z 0-9 . _ @ / + -  (slash allows tap/name; @ allows version pin).
    let valid = Regex::new(r"^[A-Za-z0-9._@/+-]+$").expect("valid regex");
    if !valid.is_match(name) {
        return Err(anyhow!(
            "invalid homebrew formula name: only A-Z a-z 0-9 . _ @ / + - allowed"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public planning entrypoint
// ---------------------------------------------------------------------------

/// Build a deterministic `OperationPlan` for `brew install <formula>`.
///
/// Validates input first, then reads `brew info --json=v2` and
/// `brew install --dry-run`. Does not mutate the system. Returns a
/// `denied_plan` for URL/local-path inputs and a plan with the
/// `metadata-command-failed` signal when `brew info` exits non-zero
/// or the formula is not parseable. If `brew` is not on PATH the
/// returned plan carries the `metadata-unavailable` signal.
pub fn plan_install(formula: &str) -> Result<OperationPlan> {
    // Validation runs first so deny-paths are deterministic regardless
    // of platform. Platform support is reflected via a risk signal
    // rather than a denial — callers should pair this with deterministic
    // policy that requires the right host class.
    if is_url_like(formula) {
        return Ok(denied(
            "url-source-denied",
            formula,
            "URL sources are denied by deterministic policy",
        ));
    }
    if looks_like_local_path(formula) {
        return Ok(denied(
            "local-path-denied",
            formula,
            "local paths are denied by deterministic policy",
        ));
    }
    validate_formula_name(formula)?;

    let mut plan = base_plan(formula);
    if !cfg!(target_os = "macos") {
        push_unique(&mut plan.risk_signals, "brew-non-macos-host");
        plan.warnings
            .push("homebrew is primarily a macOS package manager".into());
    }

    // 1. brew info --json=v2 <formula>
    let info_raw = match run_brew_info(formula, &mut plan) {
        Ok(raw) => raw,
        Err(_) => {
            // brew not available; signal and return early with the base plan.
            push_unique(&mut plan.risk_signals, "metadata-unavailable");
            plan.warnings
                .push("brew is unavailable; formula metadata could not be collected".into());
            plan.raw_evidence = json!({ "metadata_available": false });
            add_brew_risk_signals(&mut plan);
            return Ok(plan);
        }
    };
    let info_json: Option<Value> = serde_json::from_str(&info_raw).ok();

    // 2. brew install --dry-run <formula>
    let dry_raw = run_brew_dry_run(formula, &mut plan).unwrap_or_default();

    // Enrich plan from parsed metadata.
    if let Some(info) = info_json.as_ref() {
        enrich_plan_from_info(&mut plan, info);
    }

    plan.raw_evidence = json!({
        "brew_info": info_raw,
        "brew_dry_run": dry_raw,
    });

    add_brew_risk_signals(&mut plan);
    Ok(plan)
}

// ---------------------------------------------------------------------------
// Base plan construction
// ---------------------------------------------------------------------------

fn base_plan(formula: &str) -> OperationPlan {
    let mut plan = OperationPlan::new(Tool::Brew, "install", Some(formula.to_string()));
    plan.ecosystem = Some("homebrew".into());
    plan.target_type = Some("homebrew-formula".into());
    plan.source_registry = Some("homebrew/core".into()); // overwritten if non-core tap
    plan.command_preview = vec![
        "brew".into(),
        "info".into(),
        "--json=v2".into(),
        formula.into(),
    ];
    plan.mutates_system = false; // planning only
    plan.requires_root = false; // overridden if requires-sudo-touch fires
    plan.network_access = true;
    plan.packages_installed = vec![formula.to_string()];
    plan
}

fn denied(signal: &str, name: &str, reason: &str) -> OperationPlan {
    let mut plan = denied_plan(Tool::Brew, "brew", "install", name, signal, reason);
    plan.ecosystem = Some("homebrew".into());
    plan.target_type = Some("homebrew-formula".into());
    push_unique(&mut plan.risk_signals, "homebrew-formula");
    plan
}

// ---------------------------------------------------------------------------
// Subprocess wrappers (allowlisted by AGENTS.md)
// ---------------------------------------------------------------------------

fn run_brew_info(formula: &str, plan: &mut OperationPlan) -> Result<String> {
    let output = Command::new("brew")
        .args(["info", "--json=v2", formula])
        .output()?;
    let raw = command_output_to_string(&output);
    plan.metadata_available = output.status.success();
    if !output.status.success() {
        plan.warnings
            .push("brew info returned non-zero status".into());
        push_unique(&mut plan.risk_signals, "metadata-command-failed");
    }
    Ok(raw)
}

fn run_brew_dry_run(formula: &str, plan: &mut OperationPlan) -> Result<String> {
    let output = Command::new("brew")
        .args(["install", "--dry-run", formula])
        .output()?;
    let raw = command_output_to_string(&output);
    if !output.status.success() {
        plan.warnings
            .push("brew install --dry-run returned non-zero status".into());
    }
    Ok(raw)
}

fn command_output_to_string(output: &std::process::Output) -> String {
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    raw
}

// ---------------------------------------------------------------------------
// Metadata parsing + plan enrichment
// ---------------------------------------------------------------------------

/// Strongly-typed view of the bits of `brew info --json=v2` we care about.
/// Kept narrow on purpose — easier to fixture in tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrewFormulaFacts {
    pub tap: Option<String>,
    pub stable_version: Option<String>,
    pub has_bottle_for_current_platform: bool,
    pub keg_only: bool,
    pub head_only: bool,
    pub caveats_present: bool,
    pub has_service_block: bool,
    pub has_post_install: bool,
    pub bottle_sha256: Option<String>,
    pub dependency_count: usize,
    pub build_dependency_count: usize,
}

/// Parse the subset of `brew info --json=v2` we need into `BrewFormulaFacts`.
///
/// `raw` is the parsed top-level JSON value. The v2 schema returns an
/// object with a `"formulae"` array; we look at the first entry. Returns
/// the default `BrewFormulaFacts` when the shape doesn't match — callers
/// should treat that as "no metadata".
pub fn parse_brew_info_v2(raw: &Value) -> BrewFormulaFacts {
    let formula = raw
        .get("formulae")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first());
    let Some(f) = formula else {
        return BrewFormulaFacts::default();
    };

    let tap = f.get("tap").and_then(Value::as_str).map(str::to_string);
    let stable_version = f
        .get("versions")
        .and_then(|v| v.get("stable"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let head_only = f
        .get("versions")
        .and_then(|v| v.get("stable"))
        .map(Value::is_null)
        .unwrap_or(false)
        || stable_version.is_none();
    let keg_only = f.get("keg_only").and_then(Value::as_bool).unwrap_or(false);
    let caveats_present = matches!(f.get("caveats"), Some(v) if !v.is_null());
    let has_service_block = matches!(f.get("service"), Some(v) if !v.is_null());
    let has_post_install = f
        .get("post_install_defined")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Bottle availability for the host platform. We look at any architecture
    // entry under bottle.stable.files; if at least one has a sha256, we say
    // a bottle exists. v0.4 will tighten this to a per-platform pin.
    let bottle_files = f
        .get("bottle")
        .and_then(|b| b.get("stable"))
        .and_then(|s| s.get("files"))
        .and_then(Value::as_object);
    let (has_bottle, bottle_sha256) = match bottle_files {
        Some(map) => {
            let any_sha = map
                .values()
                .filter_map(|v| v.get("sha256").and_then(Value::as_str))
                .next()
                .map(str::to_string);
            (any_sha.is_some(), any_sha)
        }
        None => (false, None),
    };

    let dependency_count = f
        .get("dependencies")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let build_dependency_count = f
        .get("build_dependencies")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);

    BrewFormulaFacts {
        tap,
        stable_version,
        has_bottle_for_current_platform: has_bottle,
        keg_only,
        head_only,
        caveats_present,
        has_service_block,
        has_post_install,
        bottle_sha256,
        dependency_count,
        build_dependency_count,
    }
}

fn enrich_plan_from_info(plan: &mut OperationPlan, info: &Value) {
    let facts = parse_brew_info_v2(info);

    if let Some(tap) = facts.tap.as_ref() {
        plan.source_registry = Some(tap.clone());
        if tap != "homebrew/core" {
            push_unique(&mut plan.risk_signals, "non-core-tap");
        }
    }
    if let Some(v) = facts.stable_version.as_ref() {
        plan.target_version = Some(v.clone());
    }
    if facts.head_only {
        push_unique(&mut plan.risk_signals, "head-only");
    }
    if facts.keg_only {
        push_unique(&mut plan.risk_signals, "keg-only");
    }
    if facts.caveats_present {
        push_unique(&mut plan.risk_signals, "caveats-present");
    }
    if facts.has_service_block {
        push_unique(&mut plan.risk_signals, "service-installer");
        push_unique(&mut plan.risk_signals, "requires-sudo-touch");
        plan.requires_root = true;
    }
    if facts.has_post_install {
        push_unique(&mut plan.risk_signals, "post-install-script");
        push_unique(&mut plan.scripts_detected, "post_install");
    }
    if facts.has_bottle_for_current_platform {
        push_unique(&mut plan.risk_signals, "linkage-binary-artifact");
        plan.binary_artifact_risk = true;
        if facts.bottle_sha256.is_some() {
            plan.signature_or_checksum_status = Some("sha256-bottle".into());
        }
    } else {
        push_unique(&mut plan.risk_signals, "bottle-missing");
        push_unique(&mut plan.risk_signals, "source-build-risk");
    }

    let total_deps = facts.dependency_count + facts.build_dependency_count;
    plan.transitive_dependency_count = Some(total_deps);
    if total_deps > 20 {
        push_unique(&mut plan.risk_signals, "large-dep-fanout");
    }
}

// ---------------------------------------------------------------------------
// Risk-signal finalization
// ---------------------------------------------------------------------------

/// Final pass — sets always-on signals and any signals derived from the
/// already-populated plan fields. Mirrors `add_apt_risk_signals`.
pub fn add_brew_risk_signals(plan: &mut OperationPlan) {
    push_unique(&mut plan.risk_signals, "homebrew-formula");
    push_unique(&mut plan.risk_signals, "network-operation");
    // Note: kernel-change / security-sensitive analogs are intentionally
    // omitted. Brew runs unprivileged and does not touch the kernel.
    // Sudo-touch is only set when the formula's service/caveats indicate it.
}

// ---------------------------------------------------------------------------
// Executor stub (apply path)
// ---------------------------------------------------------------------------

/// Apply path is not implemented in v0.3.0. `aegisctl apply` for
/// `Tool::Brew` must return a deterministic deny via policy. This stub
/// exists so the policy crate can reference a single canonical reason.
pub const APPLY_NOT_SUPPORTED_REASON: &str =
    "brew-apply-not-yet-supported: planning is supported; apply lands in v0.4 \
     with bottle-sha256 + tap pin enforcement";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Deny-path tests first, per AGENTS.md -----------------------------

    #[test]
    fn rejects_url_input() {
        let plan = plan_install("https://example.com/evil.rb").unwrap();
        assert!(plan.risk_signals.iter().any(|s| s == "url-source-denied"));
    }

    #[test]
    fn rejects_local_path_input() {
        let plan = plan_install("./local/formula.rb").unwrap();
        assert!(plan.risk_signals.iter().any(|s| s == "local-path-denied"));
    }

    #[test]
    fn rejects_shell_metachars() {
        assert!(validate_formula_name("poppler;rm -rf /").is_err());
        assert!(validate_formula_name("poppler|cat").is_err());
        assert!(validate_formula_name("two words").is_err());
        assert!(validate_formula_name("-o").is_err());
        assert!(validate_formula_name("").is_err());
    }

    // --- Happy-path validation --------------------------------------------

    #[test]
    fn accepts_plain_names() {
        assert!(validate_formula_name("poppler").is_ok());
        assert!(validate_formula_name("ripgrep").is_ok());
        assert!(validate_formula_name("gh").is_ok());
    }

    #[test]
    fn accepts_version_pinned_names() {
        assert!(validate_formula_name("postgresql@16").is_ok());
        assert!(validate_formula_name("python@3.12").is_ok());
    }

    #[test]
    fn accepts_tap_qualified_names() {
        assert!(validate_formula_name("homebrew/core/gh").is_ok());
    }

    // --- Fixture-driven parsing -------------------------------------------

    fn load_fixture(name: &str) -> Value {
        let path = format!("../../tests/fixtures/brew/info_{name}.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {path}: {e}"));
        serde_json::from_str(&raw).expect("fixture is valid JSON")
    }

    #[test]
    fn parses_poppler_fixture_low_risk() {
        let v = load_fixture("poppler");
        let facts = parse_brew_info_v2(&v);
        assert_eq!(facts.tap.as_deref(), Some("homebrew/core"));
        assert!(facts.has_bottle_for_current_platform);
        assert!(facts.stable_version.is_some());
        assert!(!facts.head_only);
        assert!(!facts.keg_only);
        assert!(facts.dependency_count > 0);
    }

    #[test]
    fn parses_yq_fixture_low_risk() {
        let v = load_fixture("yq");
        let facts = parse_brew_info_v2(&v);
        assert_eq!(facts.tap.as_deref(), Some("homebrew/core"));
        assert!(facts.has_bottle_for_current_platform);
        assert!(facts.bottle_sha256.is_some());
    }

    #[test]
    fn parses_ripgrep_fixture_has_bottle() {
        let v = load_fixture("ripgrep");
        let facts = parse_brew_info_v2(&v);
        assert!(facts.has_bottle_for_current_platform);
        assert_eq!(facts.tap.as_deref(), Some("homebrew/core"));
    }

    #[test]
    fn parses_gh_fixture_has_bottle() {
        let v = load_fixture("gh");
        let facts = parse_brew_info_v2(&v);
        assert!(facts.has_bottle_for_current_platform);
        assert_eq!(facts.tap.as_deref(), Some("homebrew/core"));
    }

    #[test]
    fn enrich_sets_signals_from_fixture() {
        let v = load_fixture("poppler");
        let mut plan = base_plan("poppler");
        enrich_plan_from_info(&mut plan, &v);
        assert!(plan
            .risk_signals
            .iter()
            .any(|s| s == "linkage-binary-artifact"));
        assert_eq!(
            plan.signature_or_checksum_status.as_deref(),
            Some("sha256-bottle")
        );
        assert!(plan.target_version.is_some());
    }

    #[test]
    fn empty_json_yields_default_facts() {
        let v: Value = serde_json::from_str("{}").unwrap();
        let facts = parse_brew_info_v2(&v);
        assert_eq!(facts, BrewFormulaFacts::default());
    }

    #[test]
    fn command_preview_is_argv_array() {
        let plan = base_plan("poppler");
        assert_eq!(
            plan.command_preview,
            vec!["brew", "info", "--json=v2", "poppler"]
        );
        assert!(!plan
            .command_preview
            .iter()
            .any(|arg| arg.contains(' ') || arg.contains(';')));
    }
}
