#![forbid(unsafe_code)]

//! Ed25519 signing helpers for Aegis execution plans.
//!
//! Signing is deterministic over canonical JSON with the plan signature field
//! removed. The model never participates in signing or argv generation.

use aegis_core::{ExecutionPlan, SignatureEnvelope};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;

pub const SIGNATURE_ALGORITHM: &str = "ed25519";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedKeypair {
    pub secret_key_hex: String,
    pub public_key_hex: String,
}

pub fn generate_keypair() -> Result<GeneratedKeypair> {
    let mut key_bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .context("opening /dev/urandom")?
        .read_exact(&mut key_bytes)
        .context("reading Ed25519 secret key material")?;
    let key = SigningKey::from_bytes(&key_bytes);
    Ok(GeneratedKeypair {
        secret_key_hex: hex::encode(key_bytes),
        public_key_hex: hex::encode(key.verifying_key().to_bytes()),
    })
}

pub fn sha256_hex<T: Serialize>(value: &T) -> Result<String> {
    let bytes = canonical_json_bytes(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn sign_execution_plan(
    plan: &mut ExecutionPlan,
    key_id: impl Into<String>,
    secret_key_hex: &str,
) -> Result<()> {
    let key = signing_key_from_hex(secret_key_hex)?;
    plan.signature = None;
    let payload = canonical_json_bytes(plan)?;
    let signature = key.sign(&payload);
    plan.signature = Some(SignatureEnvelope {
        algorithm: SIGNATURE_ALGORITHM.to_string(),
        key_id: key_id.into(),
        signature: BASE64.encode(signature.to_bytes()),
    });
    Ok(())
}

pub fn verify_execution_plan(plan: &ExecutionPlan, public_key_hex: &str) -> Result<()> {
    let envelope = plan
        .signature
        .as_ref()
        .ok_or_else(|| anyhow!("execution plan is unsigned"))?;
    if envelope.algorithm != SIGNATURE_ALGORITHM {
        return Err(anyhow!(
            "unsupported signature algorithm {}",
            envelope.algorithm
        ));
    }
    let key = verifying_key_from_hex(public_key_hex)?;
    let mut unsigned = plan.clone();
    unsigned.signature = None;
    let payload = canonical_json_bytes(&unsigned)?;
    let signature_bytes = BASE64
        .decode(&envelope.signature)
        .context("decoding execution plan signature")?;
    let signature = Signature::from_slice(&signature_bytes).context("parsing signature")?;
    key.verify(&payload, &signature)
        .context("execution plan signature verification failed")
}

pub fn public_key_from_secret_hex(secret_key_hex: &str) -> Result<String> {
    let key = signing_key_from_hex(secret_key_hex)?;
    Ok(hex::encode(key.verifying_key().to_bytes()))
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).context("serializing value for signing")?;
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted).context("encoding canonical JSON")
}

fn signing_key_from_hex(secret_key_hex: &str) -> Result<SigningKey> {
    let bytes = hex::decode(secret_key_hex.trim()).context("decoding Ed25519 secret key hex")?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("Ed25519 secret key must be 32 bytes encoded as 64 hex chars"))?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(public_key_hex.trim()).context("decoding Ed25519 public key hex")?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("Ed25519 public key must be 32 bytes encoded as 64 hex chars"))?;
    VerifyingKey::from_bytes(&key_bytes).context("parsing Ed25519 public key")
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, value) in entries {
                sorted.insert(key, sort_json(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{ExecutionPlan, OperationPlan, PolicyDecision, PolicyResult, Tool};

    const SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn signs_and_verifies_execution_plan() {
        let op = OperationPlan::new(Tool::Apt, "upgrade", None);
        let policy = PolicyResult {
            decision: PolicyDecision::AllowWithSnapshot,
            reasons: vec!["ok".into()],
            required_controls: vec!["system snapshot".into()],
            policy_version: "test".into(),
            evaluator_hash: "test-hash".into(),
            evidence_fresh_until: None,
        };
        let mut plan = ExecutionPlan::new(
            &op,
            &policy,
            vec!["apt-get".into(), "upgrade".into()],
            "local-admin",
            "2999-01-01T00:00:00Z",
            sha256_hex(&op).unwrap(),
            sha256_hex(&policy).unwrap(),
        );
        sign_execution_plan(&mut plan, "test-key", SECRET).unwrap();
        let public = public_key_from_secret_hex(SECRET).unwrap();
        verify_execution_plan(&plan, &public).unwrap();
    }

    #[test]
    fn generated_keypair_can_sign_and_verify() {
        let keypair = generate_keypair().unwrap();
        let op = OperationPlan::new(Tool::Apt, "update", None);
        let policy = PolicyResult {
            decision: PolicyDecision::Allow,
            reasons: vec!["ok".into()],
            required_controls: Vec::new(),
            policy_version: "test".into(),
            evaluator_hash: "test-hash".into(),
            evidence_fresh_until: None,
        };
        let mut plan = ExecutionPlan::new(
            &op,
            &policy,
            vec!["apt-get".into(), "update".into()],
            "local-admin",
            "2999-01-01T00:00:00Z",
            sha256_hex(&op).unwrap(),
            sha256_hex(&policy).unwrap(),
        );
        sign_execution_plan(&mut plan, "generated-test-key", &keypair.secret_key_hex).unwrap();
        verify_execution_plan(&plan, &keypair.public_key_hex).unwrap();
    }
}
