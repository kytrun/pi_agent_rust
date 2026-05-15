#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/remote-validation-proof-ledger-contract.json";
const EXAMPLES_PATH: &str = "tests/golden_corpus/remote_validation_proof_ledger/examples.json";
const RUNBOOK_PATH: &str = "docs/swarm-operations-runbook.md";
const README_PATH: &str = "README.md";
const EXPECTED_CONTRACT_SCHEMA: &str = "pi.remote_validation.proof_ledger_contract.v1";
const EXPECTED_LEDGER_SCHEMA: &str = "pi.remote_validation.proof_ledger.v1";
const EXPECTED_ENTRY_SCHEMA: &str = "pi.remote_validation.proof_entry.v1";
const EXPECTED_EXAMPLE_SCHEMA: &str = "pi.remote_validation.proof_ledger.example_corpus.v1";
const EXPECTED_BEAD_ID: &str = "bd-e5le6.1";
const EXPECTED_PARENT_BEAD_ID: &str = "bd-e5le6";

const REQUIRED_CASE_IDS: &[&str] = &[
    "pass_remote_clean",
    "local_fallback_refusal",
    "queue_backoff",
    "retrieval_warning",
];

const REQUIRED_ENTRY_FIELDS: &[&str] = &[
    "schema",
    "entry_id",
    "bead_id",
    "command",
    "command_class",
    "runner",
    "timing",
    "exit",
    "paths",
    "artifact_retrieval",
    "warnings",
    "evidence_classification",
];

type TestResult = Result<(), String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(relative_path: &str) -> Result<Value, String> {
    let path = repo_root().join(relative_path);
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", path.display()))
}

fn load_text(relative_path: &str) -> Result<String, String> {
    let path = repo_root().join(relative_path);
    std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn pointer<'a>(value: &'a Value, path: &str) -> Result<&'a Value, String> {
    value
        .pointer(path)
        .ok_or_else(|| format!("missing JSON pointer {path}"))
}

fn pointer_str<'a>(value: &'a Value, path: &str) -> Result<&'a str, String> {
    pointer(value, path)?
        .as_str()
        .ok_or_else(|| format!("{path} must be a string"))
}

fn pointer_bool(value: &Value, path: &str) -> Result<bool, String> {
    pointer(value, path)?
        .as_bool()
        .ok_or_else(|| format!("{path} must be a bool"))
}

fn pointer_array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], String> {
    pointer(value, path)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{path} must be an array"))
}

fn string_set<'a>(value: &'a Value, path: &str) -> Result<HashSet<&'a str>, String> {
    let mut entries = HashSet::new();
    let non_string_message = format!("{path} entries must be strings");
    let blank_message = format!("{path} entry is blank");
    for entry in pointer_array(value, path)? {
        let Some(raw) = entry.as_str() else {
            return Err(non_string_message);
        };
        if raw.trim().is_empty() {
            return Err(blank_message);
        }
        entries.insert(raw);
    }
    Ok(entries)
}

fn require_set(value: &Value, path: &str, expected: &[&str], label: &str) -> TestResult {
    let observed = string_set(value, path)?;
    if let Some(missing) = expected
        .iter()
        .find(|required| !observed.contains(**required))
    {
        return Err(format!("missing {label}: {missing}"));
    }
    Ok(())
}

fn require_object_keys(value: &Value, keys: &[&str], label: &str) -> TestResult {
    if let Some(missing) = keys.iter().find(|key| value.get(**key).is_none()) {
        return Err(format!("{label} missing key {missing}"));
    }
    Ok(())
}

fn is_utc_rfc3339_z(value: &str) -> bool {
    value.len() >= 20 && value.contains('T') && value.ends_with('Z')
}

fn require_utc_rfc3339_z(value: &str, path: &str) -> TestResult {
    require(is_utc_rfc3339_z(value), format!("{path} must be UTC Z"))
}

fn first_entry(case: &Value) -> Result<&Value, String> {
    pointer_array(case, "/ledger/entries")?
        .first()
        .ok_or_else(|| "case must contain at least one ledger entry".to_string())
}

#[test]
fn remote_validation_contract_declares_required_identity_and_boundaries() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;

    require(
        pointer_str(&contract, "/schema")? == EXPECTED_CONTRACT_SCHEMA,
        "contract schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/ledger_schema")? == EXPECTED_LEDGER_SCHEMA,
        "ledger schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/entry_schema")? == EXPECTED_ENTRY_SCHEMA,
        "entry schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/example_corpus_schema")? == EXPECTED_EXAMPLE_SCHEMA,
        "example schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/bead_id")? == EXPECTED_BEAD_ID,
        "bead linkage mismatch",
    )?;
    require(
        pointer_str(&contract, "/parent_bead_id")? == EXPECTED_PARENT_BEAD_ID,
        "parent bead linkage mismatch",
    )?;
    require(
        pointer_str(&contract, "/purpose")?
            == "operator_remote_validation_evidence_not_release_performance_claim",
        "purpose must keep proof ledger out of release claim authority",
    )?;
    require(
        !pointer_bool(
            &contract,
            "/claim_boundaries/release_performance_claims_allowed",
        )?,
        "release performance claims must be forbidden",
    )?;
    require(
        !pointer_bool(&contract, "/claim_boundaries/strict_dropin_claims_allowed")?,
        "strict drop-in claims must be forbidden",
    )?;
    require(
        pointer_str(&contract, "/claim_boundaries/required_phrase")?
            == "operator evidence only; not release performance evidence",
        "claim boundary phrase mismatch",
    )?;
    require_set(
        &contract,
        "/non_goals",
        &[
            "replace_rch_scheduler_or_worker_logs",
            "replace_cargo_headroom_admission",
            "treat_local_fallback_as_remote_proof",
            "treat_artifact_retrieval_warnings_as_clean_remote_proof",
            "support_release_facing_speed_memory_or_dropin_claims",
        ],
        "non-goal",
    )
}

#[test]
fn remote_validation_contract_covers_acceptance_fields() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;

    require_set(
        &contract,
        "/required_entry_keys",
        REQUIRED_ENTRY_FIELDS,
        "entry key",
    )?;
    require_set(
        &contract,
        "/command_contract/required_fields",
        &[
            "argv",
            "rendered",
            "cwd",
            "command_fingerprint",
            "feature_flags",
            "env_allowlist",
        ],
        "command field",
    )?;
    require_set(
        &contract,
        "/runner_contract/required_fields",
        &[
            "requested_runner",
            "resolved_runner",
            "runner_requirement",
            "remote_execution",
            "local_fallback",
            "fallback_reason",
            "rch_job_id",
            "worker_id",
            "worker_host",
            "queue_state",
            "worker_state",
            "command_rewrite",
            "status_excerpt",
        ],
        "runner field",
    )?;
    require_set(
        &contract,
        "/timing_contract/required_fields",
        &[
            "started_at_utc",
            "ended_at_utc",
            "duration_ms",
            "heartbeat_at_utc",
            "stale_progress_detected",
        ],
        "timing field",
    )?;
    require_set(
        &contract,
        "/exit_contract/required_fields",
        &[
            "exit_code",
            "success",
            "termination_reason",
            "stderr_excerpt",
            "stdout_excerpt",
        ],
        "exit field",
    )?;
    require_set(
        &contract,
        "/paths_contract/required_fields",
        &[
            "cargo_target_dir",
            "tmpdir",
            "remote_target_dir",
            "remote_tmpdir",
            "artifact_paths",
        ],
        "path field",
    )?;
    require_set(
        &contract,
        "/artifact_retrieval_contract/required_fields",
        &[
            "status",
            "retrieved_paths",
            "missing_paths",
            "warning_details",
            "retrieval_exit_code",
            "retrieval_elapsed_ms",
        ],
        "artifact retrieval field",
    )?;
    require_set(
        &contract,
        "/warning_contract/required_warning_ids",
        &[
            "local_fallback_observed",
            "local_fallback_refused",
            "queue_backoff",
            "artifact_retrieval_warning",
            "stale_progress",
        ],
        "warning id",
    )
}

#[test]
fn golden_examples_cover_required_remote_proof_outcomes() -> TestResult {
    let examples = load_json(EXAMPLES_PATH)?;
    require(
        pointer_str(&examples, "/schema")? == EXPECTED_EXAMPLE_SCHEMA,
        "example corpus schema mismatch",
    )?;
    require(
        pointer_str(&examples, "/contract_schema")? == EXPECTED_CONTRACT_SCHEMA,
        "example contract schema mismatch",
    )?;

    let cases = pointer_array(&examples, "/cases")?;
    let observed_case_ids: HashSet<&str> = cases
        .iter()
        .map(|case| pointer_str(case, "/case_id"))
        .collect::<Result<HashSet<_>, _>>()?;
    if let Some(missing) = REQUIRED_CASE_IDS
        .iter()
        .find(|required| !observed_case_ids.contains(**required))
    {
        return Err(format!("missing golden case {missing}"));
    }

    for case in cases {
        validate_case(case)?;
    }

    Ok(())
}

fn validate_case(case: &Value) -> TestResult {
    let entry = first_entry(case)?;
    require_object_keys(entry, REQUIRED_ENTRY_FIELDS, "proof entry")?;
    require(
        pointer_str(case, "/ledger/schema")? == EXPECTED_LEDGER_SCHEMA,
        "ledger schema mismatch",
    )?;
    require(
        pointer_str(entry, "/schema")? == EXPECTED_ENTRY_SCHEMA,
        "entry schema mismatch",
    )?;
    require(
        pointer_str(entry, "/bead_id")? == EXPECTED_BEAD_ID,
        "entry bead id mismatch",
    )?;
    for path in [
        "/ledger/generated_at_utc",
        "/timing/started_at_utc",
        "/timing/ended_at_utc",
        "/timing/heartbeat_at_utc",
    ] {
        let target = if path.starts_with("/ledger/") {
            pointer_str(case, path)?
        } else {
            pointer_str(entry, path)?
        };
        require_utc_rfc3339_z(target, path)?;
    }

    require_object_keys(
        pointer(entry, "/command")?,
        &[
            "argv",
            "rendered",
            "cwd",
            "command_fingerprint",
            "feature_flags",
            "env_allowlist",
        ],
        "command",
    )?;
    require_object_keys(
        pointer(entry, "/runner")?,
        &[
            "requested_runner",
            "resolved_runner",
            "runner_requirement",
            "remote_execution",
            "local_fallback",
            "fallback_reason",
            "rch_job_id",
            "worker_id",
            "worker_host",
            "queue_state",
            "worker_state",
            "command_rewrite",
            "status_excerpt",
        ],
        "runner",
    )?;
    require_object_keys(
        pointer(entry, "/paths")?,
        &[
            "cargo_target_dir",
            "tmpdir",
            "remote_target_dir",
            "remote_tmpdir",
            "artifact_paths",
        ],
        "paths",
    )?;
    require_object_keys(
        pointer(entry, "/artifact_retrieval")?,
        &[
            "status",
            "retrieved_paths",
            "missing_paths",
            "warning_details",
            "retrieval_exit_code",
            "retrieval_elapsed_ms",
        ],
        "artifact retrieval",
    )?;

    let expected_classification = pointer_str(case, "/expected_classification")?;
    require(
        pointer_str(entry, "/evidence_classification/status")? == expected_classification,
        "classification status must match expected case classification",
    )?;
    require(
        pointer_bool(entry, "/evidence_classification/operator_evidence_only")?,
        "examples must remain operator evidence only",
    )?;
    require_set(
        entry,
        "/evidence_classification/suppressed_claims",
        &[
            "release_performance",
            "strict_dropin",
            "benchmark_throughput",
            "memory_or_startup_claim",
        ],
        "suppressed claim",
    )?;

    let case_id = pointer_str(case, "/case_id")?;
    match case_id {
        "pass_remote_clean" => {
            require(
                pointer_bool(entry, "/runner/remote_execution")?,
                "clean pass must prove remote execution",
            )?;
            require(
                pointer_str(entry, "/runner/local_fallback")? == "none",
                "clean pass must not have local fallback",
            )?;
            require(
                pointer_str(entry, "/artifact_retrieval/status")? == "clean",
                "clean pass must retrieve artifacts cleanly",
            )?;
            require(
                pointer_bool(entry, "/evidence_classification/clean_remote_proof")?,
                "clean pass must classify as clean remote proof",
            )?;
        }
        "local_fallback_refusal" => {
            require(
                pointer_str(entry, "/runner/local_fallback")? == "refused",
                "fallback refusal case must record refused fallback",
            )?;
            require(
                pointer_str(entry, "/exit/termination_reason")? == "local_fallback_refused",
                "fallback refusal case must use explicit termination reason",
            )?;
            require(
                !pointer_bool(entry, "/evidence_classification/clean_remote_proof")?,
                "fallback refusal is not clean proof",
            )?;
        }
        "queue_backoff" => {
            require(
                pointer_str(entry, "/exit/termination_reason")? == "queue_backoff",
                "queue case must use explicit termination reason",
            )?;
        }
        "retrieval_warning" => {
            require(
                pointer_str(entry, "/artifact_retrieval/status")? == "warning",
                "retrieval warning case must expose warning status",
            )?;
            require(
                !pointer_bool(entry, "/evidence_classification/clean_remote_proof")?,
                "retrieval warning is degraded, not clean proof",
            )?;
        }
        other => return Err(format!("unexpected golden case {other}")),
    }

    Ok(())
}

#[test]
fn operator_docs_reference_contract_and_claim_boundary() -> TestResult {
    let runbook = load_text(RUNBOOK_PATH)?;
    let readme = load_text(README_PATH)?;

    let required_runbook_fragments = [
        "docs/contracts/remote-validation-proof-ledger-contract.json",
        "pi.remote_validation.proof_ledger.v1",
        "operator evidence only",
        "not release performance evidence",
        "local fallback",
        "artifact retrieval",
    ];
    if let Some(missing) = required_runbook_fragments
        .iter()
        .find(|fragment| !runbook.contains(**fragment))
    {
        return Err(format!("runbook missing fragment {missing:?}"));
    }
    require(
        readme.contains("remote-validation-proof-ledger-contract.json"),
        "README documentation index must mention proof ledger contract",
    )
}
