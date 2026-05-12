#![forbid(unsafe_code)]

use aegis_core::{AiReview, OperationPlan};
use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::time::Duration;

pub const DEFAULT_BASE_URL: &str = "http://localhost:8000/v1";
pub const DEFAULT_MODEL: &str = "deepseek-v4-flash";
pub const DEFAULT_PREFILL_TOKENS_PER_SECOND: f64 = 330.0;
pub const DEFAULT_DECODE_TOKENS_PER_SECOND: f64 = 17.0;
pub const DEFAULT_MAX_OUTPUT_TOKENS: u16 = 1024;
pub const DEFAULT_MODEL_STARTUP_ALLOWANCE_SECS: u64 = 120;
pub const DEFAULT_MIN_REVIEW_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_MODELS_TIMEOUT_SECS: u64 = 15;

const SYSTEM_PROMPT: &str = "Aegis local package/artifact risk reviewer. Do not execute commands, approve execution, or generate argv. Return exactly one compact JSON object as the whole response. Start with { and end with }. No markdown, prose, analysis, or chain of thought. Deterministic policy decides.";

#[derive(Debug)]
pub enum ReviewOutcome {
    Valid(AiReview),
    Invalid { raw_response: String, error: String },
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    temperature: u8,
    max_tokens: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
    messages: Vec<ChatMessage>,
}

#[derive(Debug, Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: String,
}

pub fn review_plan(plan: &OperationPlan) -> Result<ReviewOutcome> {
    let url = format!(
        "{}/chat/completions",
        configured_base_url().trim_end_matches('/')
    );
    let expected_shape = serde_json::to_string(&expected_review_shape())?;
    let operation_plan = serde_json::to_string(&review_input(plan))?;
    let user_content = format!(
        "Classify this plan. Return only JSON matching this shape: {expected_shape}\nPlan: {operation_plan}"
    );
    let max_tokens = configured_max_output_tokens();
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(DEFAULT_MODELS_TIMEOUT_SECS))
        .timeout(configured_review_timeout(
            SYSTEM_PROMPT.len() + user_content.len(),
            max_tokens,
        ))
        .build()
        .context("building HTTP client")?;
    let request = ChatRequest {
        model: configured_model(),
        temperature: 0,
        max_tokens,
        response_format: configured_json_response_format().then_some(ResponseFormat {
            kind: "json_object",
        }),
        messages: vec![
            ChatMessage {
                role: "system".into(),
                content: SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".into(),
                content: user_content,
            },
        ],
    };

    let response: ChatResponse = client
        .post(url)
        .json(&request)
        .send()
        .context("calling local model endpoint")?
        .error_for_status()
        .context("local model endpoint returned an error")?
        .json()
        .context("parsing chat completion response")?;

    let raw_response = response
        .choices
        .first()
        .map(|choice| choice.message.content.clone())
        .ok_or_else(|| anyhow!("chat completion response contained no choices"))?;

    match parse_review_json(&raw_response) {
        Ok(review) => Ok(ReviewOutcome::Valid(review)),
        Err(error) => Ok(ReviewOutcome::Invalid {
            raw_response,
            error: error.to_string(),
        }),
    }
}

pub fn check_models_endpoint() -> Result<()> {
    let client = Client::builder()
        .timeout(configured_models_timeout())
        .build()
        .context("building HTTP client")?;
    let url = format!("{}/models", configured_base_url().trim_end_matches('/'));
    client
        .get(url)
        .send()
        .context("calling local models endpoint")?
        .error_for_status()
        .context("local models endpoint returned an error")?;
    Ok(())
}

pub fn check_default_model_available() -> Result<Option<bool>> {
    let client = Client::builder()
        .timeout(configured_models_timeout())
        .build()
        .context("building HTTP client")?;
    let url = format!("{}/models", configured_base_url().trim_end_matches('/'));
    let expected_model = configured_model();
    let value: Value = client
        .get(url)
        .send()
        .context("calling local models endpoint")?
        .error_for_status()
        .context("local models endpoint returned an error")?
        .json()
        .context("parsing models response")?;
    let Some(models) = value.get("data").and_then(Value::as_array) else {
        return Ok(None);
    };
    Ok(Some(models.iter().any(|model| {
        model
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id == expected_model)
    })))
}

pub fn configured_base_url() -> String {
    env::var("AEGIS_AI_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string())
}

pub fn configured_model() -> String {
    env::var("AEGIS_AI_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string())
}

pub fn configured_max_output_tokens() -> u16 {
    configured_u16("AEGIS_AI_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS)
}

pub fn configured_json_response_format() -> bool {
    env::var("AEGIS_AI_RESPONSE_FORMAT_JSON")
        .map(|value| {
            !matches!(
                value.as_str(),
                "0" | "false" | "False" | "FALSE" | "no" | "NO"
            )
        })
        .unwrap_or(true)
}

pub fn configured_models_timeout() -> Duration {
    Duration::from_secs(configured_u64(
        "AEGIS_AI_MODELS_TIMEOUT_SECS",
        DEFAULT_MODELS_TIMEOUT_SECS,
    ))
}

pub fn configured_review_timeout(prompt_chars: usize, max_output_tokens: u16) -> Duration {
    if let Some(timeout_secs) = positive_env_u64("AEGIS_AI_REVIEW_TIMEOUT_SECS") {
        return Duration::from_secs(timeout_secs);
    }

    let prefill_tokens_per_second = configured_f64(
        "AEGIS_AI_PREFILL_TOKENS_PER_SEC",
        DEFAULT_PREFILL_TOKENS_PER_SECOND,
    );
    let decode_tokens_per_second = configured_f64(
        "AEGIS_AI_DECODE_TOKENS_PER_SEC",
        DEFAULT_DECODE_TOKENS_PER_SECOND,
    );
    let startup_allowance_secs = configured_u64(
        "AEGIS_AI_MODEL_STARTUP_ALLOWANCE_SECS",
        DEFAULT_MODEL_STARTUP_ALLOWANCE_SECS,
    );
    review_timeout_from_rates(
        prompt_chars,
        max_output_tokens,
        prefill_tokens_per_second,
        decode_tokens_per_second,
        startup_allowance_secs,
        DEFAULT_MIN_REVIEW_TIMEOUT_SECS,
    )
}

fn parse_review_json(raw: &str) -> Result<AiReview> {
    let mut last_error = None;
    for candidate in review_json_candidates(raw) {
        match serde_json::from_str::<Value>(candidate) {
            Ok(value) => match serde_json::from_value::<AiReview>(value) {
                Ok(review) => return Ok(review),
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => last_error = Some(error.to_string()),
        }
    }

    Err(anyhow!(
        "response did not contain a JSON object matching ai-review schema: {}",
        last_error.unwrap_or_else(|| "no JSON candidates found".to_string())
    ))
}

pub fn expected_review_shape() -> Value {
    json!({
        "risk": "low|medium|high|deny",
        "summary": "string",
        "supply_chain_risk": "low|medium|high",
        "privilege_risk": "low|medium|high",
        "persistence_risk": "low|medium|high",
        "availability_risk": "low|medium|high",
        "rollback_difficulty": "easy|moderate|hard",
        "red_flags": ["string"],
        "required_controls": ["string"],
        "recommendation": "auto_approve|approve_with_snapshot|require_human|deny"
    })
}

fn estimate_tokens(chars: usize) -> usize {
    chars.div_ceil(4).max(1)
}

fn review_input(plan: &OperationPlan) -> Value {
    json!({
        "tool": plan.tool,
        "operation": plan.operation,
        "ecosystem": plan.ecosystem,
        "target_type": plan.target_type,
        "target": plan.target,
        "target_version": plan.target_version,
        "source_registry": plan.source_registry,
        "metadata_available": plan.metadata_available,
        "command_preview": plan.command_preview,
        "mutates_system": plan.mutates_system,
        "requires_root": plan.requires_root,
        "network_access": plan.network_access,
        "packages_installed": plan.packages_installed,
        "packages_upgraded": plan.packages_upgraded,
        "packages_removed": plan.packages_removed,
        "packages_downgraded": plan.packages_downgraded,
        "packages_held_back": plan.packages_held_back,
        "scripts_detected": plan.scripts_detected,
        "build_hooks_detected": plan.build_hooks_detected,
        "native_code_risk": plan.native_code_risk,
        "binary_artifact_risk": plan.binary_artifact_risk,
        "signature_or_checksum_status": plan.signature_or_checksum_status,
        "mutable_reference": plan.mutable_reference,
        "publisher_or_maintainer": plan.publisher_or_maintainer,
        "transitive_dependency_count": plan.transitive_dependency_count,
        "risk_signals": plan.risk_signals,
        "warnings": plan.warnings,
        "raw_evidence_summary": raw_evidence_summary(&plan.raw_evidence),
    })
}

fn raw_evidence_summary(raw_evidence: &Value) -> Value {
    match raw_evidence {
        Value::Object(map) => json!({
            "type": "object",
            "top_level_keys": map.keys().collect::<Vec<_>>(),
            "bytes": raw_evidence.to_string().len(),
        }),
        Value::Array(values) => json!({
            "type": "array",
            "items": values.len(),
            "bytes": raw_evidence.to_string().len(),
        }),
        other => json!({
            "type": value_type(other),
            "bytes": raw_evidence.to_string().len(),
        }),
    }
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn review_json_candidates(raw: &str) -> Vec<&str> {
    let trimmed = raw.trim();
    let mut candidates = vec![trimmed];
    if let Some(fenced) = strip_json_fence(trimmed) {
        candidates.push(fenced);
    }
    if let Some(object) = first_balanced_json_object(trimmed) {
        candidates.push(object);
    }
    candidates
}

fn strip_json_fence(raw: &str) -> Option<&str> {
    let without_prefix = raw
        .strip_prefix("```json")
        .or_else(|| raw.strip_prefix("```JSON"))
        .or_else(|| raw.strip_prefix("```"))?;
    without_prefix.trim().strip_suffix("```").map(str::trim)
}

fn first_balanced_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in raw[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let end = start + offset + ch.len_utf8();
                    return Some(&raw[start..end]);
                }
            }
            _ => {}
        }
    }
    None
}

fn review_timeout_from_rates(
    prompt_chars: usize,
    max_output_tokens: u16,
    prefill_tokens_per_second: f64,
    decode_tokens_per_second: f64,
    startup_allowance_secs: u64,
    min_timeout_secs: u64,
) -> Duration {
    let prompt_tokens = estimate_tokens(prompt_chars);
    let prefill_secs = ceil_div_f64(prompt_tokens as f64, prefill_tokens_per_second);
    let decode_secs = ceil_div_f64(max_output_tokens as f64, decode_tokens_per_second);
    let estimated_secs = startup_allowance_secs + prefill_secs + decode_secs + 30;

    Duration::from_secs(estimated_secs.max(min_timeout_secs))
}

fn ceil_div_f64(value: f64, divisor: f64) -> u64 {
    (value / divisor).ceil() as u64
}

fn configured_u16(name: &str, default: u16) -> u16 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn configured_u64(name: &str, default: u64) -> u64 {
    positive_env_u64(name).unwrap_or(default)
}

fn positive_env_u64(name: &str) -> Option<u64> {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
}

fn configured_f64(name: &str, default: f64) -> f64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_REVIEW: &str = r#"{"risk":"medium","summary":"Mutable container tag with unknown signature status requires human review.","supply_chain_risk":"medium","privilege_risk":"low","persistence_risk":"low","availability_risk":"medium","rollback_difficulty":"moderate","red_flags":["mutable tag","unknown signature status"],"required_controls":["pin image digest","verify publisher"],"recommendation":"require_human"}"#;

    #[test]
    fn review_timeout_uses_rate_based_floor_for_normal_prompts() {
        let timeout = review_timeout_from_rates(
            4_000,
            DEFAULT_MAX_OUTPUT_TOKENS,
            DEFAULT_PREFILL_TOKENS_PER_SECOND,
            DEFAULT_DECODE_TOKENS_PER_SECOND,
            DEFAULT_MODEL_STARTUP_ALLOWANCE_SECS,
            DEFAULT_MIN_REVIEW_TIMEOUT_SECS,
        );
        assert!(timeout >= Duration::from_secs(DEFAULT_MIN_REVIEW_TIMEOUT_SECS));
    }

    #[test]
    fn review_timeout_grows_for_large_prompts() {
        let normal = review_timeout_from_rates(
            4_000,
            DEFAULT_MAX_OUTPUT_TOKENS,
            DEFAULT_PREFILL_TOKENS_PER_SECOND,
            DEFAULT_DECODE_TOKENS_PER_SECOND,
            DEFAULT_MODEL_STARTUP_ALLOWANCE_SECS,
            DEFAULT_MIN_REVIEW_TIMEOUT_SECS,
        );
        let large = review_timeout_from_rates(
            1_000_000,
            DEFAULT_MAX_OUTPUT_TOKENS,
            DEFAULT_PREFILL_TOKENS_PER_SECOND,
            DEFAULT_DECODE_TOKENS_PER_SECOND,
            DEFAULT_MODEL_STARTUP_ALLOWANCE_SECS,
            DEFAULT_MIN_REVIEW_TIMEOUT_SECS,
        );
        assert!(large > normal);
    }

    #[test]
    fn token_estimate_rounds_up() {
        assert_eq!(estimate_tokens(1), 1);
        assert_eq!(estimate_tokens(4), 1);
        assert_eq!(estimate_tokens(5), 2);
    }

    #[test]
    fn parse_review_accepts_strict_json() {
        let review = parse_review_json(VALID_REVIEW).expect("valid review");
        assert_eq!(
            review.summary,
            "Mutable container tag with unknown signature status requires human review."
        );
    }

    #[test]
    fn parse_review_accepts_fenced_json() {
        let raw = format!("```json\n{VALID_REVIEW}\n```");
        let review = parse_review_json(&raw).expect("fenced review");
        assert_eq!(review.red_flags.len(), 2);
    }

    #[test]
    fn parse_review_extracts_embedded_json_object() {
        let raw = format!("Here is the JSON:\n{VALID_REVIEW}\nDone.");
        let review = parse_review_json(&raw).expect("embedded review");
        assert_eq!(review.required_controls.len(), 2);
    }

    #[test]
    fn parse_review_rejects_reasoning_without_json() {
        let error =
            parse_review_json("I will analyze the plan first.").expect_err("invalid review");
        assert!(error.to_string().contains("ai-review schema"));
    }
}
