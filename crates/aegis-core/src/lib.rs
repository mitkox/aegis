#![forbid(unsafe_code)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Apt,
    Npm,
    Pip,
    Container,
    Nuget,
    Vscode,
    Go,
    Cargo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    AllowWithSnapshot,
    RequireHuman,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyResult {
    pub decision: PolicyDecision,
    pub reasons: Vec<String>,
    pub required_controls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OverallRisk {
    Low,
    Medium,
    High,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RollbackDifficulty {
    Easy,
    Moderate,
    Hard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiRecommendation {
    AutoApprove,
    ApproveWithSnapshot,
    RequireHuman,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiReview {
    pub risk: OverallRisk,
    pub summary: String,
    pub supply_chain_risk: RiskLevel,
    pub privilege_risk: RiskLevel,
    pub persistence_risk: RiskLevel,
    pub availability_risk: RiskLevel,
    pub rollback_difficulty: RollbackDifficulty,
    pub red_flags: Vec<String>,
    pub required_controls: Vec<String>,
    pub recommendation: AiRecommendation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OperationPlan {
    pub plan_id: String,
    pub created_at: String,
    pub tool: Tool,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_registry: Option<String>,
    pub metadata_available: bool,
    pub command_preview: Vec<String>,
    pub mutates_system: bool,
    pub requires_root: bool,
    pub network_access: bool,
    pub packages_installed: Vec<String>,
    pub packages_upgraded: Vec<String>,
    pub packages_removed: Vec<String>,
    pub packages_downgraded: Vec<String>,
    pub packages_held_back: Vec<String>,
    pub scripts_detected: Vec<String>,
    pub build_hooks_detected: Vec<String>,
    pub native_code_risk: bool,
    pub binary_artifact_risk: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_or_checksum_status: Option<String>,
    pub mutable_reference: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_or_maintainer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transitive_dependency_count: Option<usize>,
    pub risk_signals: Vec<String>,
    pub warnings: Vec<String>,
    pub raw_evidence: Value,
}

impl OperationPlan {
    pub fn new(tool: Tool, operation: impl Into<String>, target: Option<String>) -> Self {
        Self {
            plan_id: Uuid::new_v4().to_string(),
            created_at: Utc::now().to_rfc3339(),
            tool,
            operation: operation.into(),
            ecosystem: None,
            target_type: None,
            target,
            target_version: None,
            source_registry: None,
            metadata_available: false,
            command_preview: Vec::new(),
            mutates_system: false,
            requires_root: false,
            network_access: false,
            packages_installed: Vec::new(),
            packages_upgraded: Vec::new(),
            packages_removed: Vec::new(),
            packages_downgraded: Vec::new(),
            packages_held_back: Vec::new(),
            scripts_detected: Vec::new(),
            build_hooks_detected: Vec::new(),
            native_code_risk: false,
            binary_artifact_risk: false,
            signature_or_checksum_status: None,
            mutable_reference: false,
            publisher_or_maintainer: None,
            transitive_dependency_count: None,
            risk_signals: Vec::new(),
            warnings: Vec::new(),
            raw_evidence: json!({}),
        }
    }
}

pub fn has_shell_metacharacters(s: &str) -> bool {
    s.chars().any(|c| {
        matches!(
            c,
            ';' | '&' | '|' | '`' | '$' | '(' | ')' | '<' | '>' | '\n' | '\r' | '\t'
        )
    })
}

pub fn is_url_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("git://")
        || lower.starts_with("ssh://")
}

pub fn looks_like_local_path(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with('~')
        || value.contains('\\')
}

pub fn denied_plan(
    tool: Tool,
    ecosystem: &str,
    operation: &str,
    target: &str,
    signal: &str,
    reason: &str,
) -> OperationPlan {
    let mut plan = OperationPlan::new(tool, operation, Some(target.to_string()));
    plan.ecosystem = Some(ecosystem.to_string());
    plan.target_type = Some("package".to_string());
    plan.mutates_system = true;
    plan.network_access = true;
    plan.warnings = vec![format!("validation failed: {reason}")];
    plan.risk_signals = vec![signal.to_string()];
    plan.raw_evidence = json!({ "validation_error": reason });
    plan
}

pub fn push_unique(values: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}
