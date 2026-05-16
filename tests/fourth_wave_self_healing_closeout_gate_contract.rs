#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/fourth-wave-self-healing-closeout-gate-contract.json";
const EVIDENCE_PATH: &str = "docs/evidence/fourth-wave-self-healing-closeout-gate.json";
const RUNBOOK_PATH: &str = "docs/swarm-operations-runbook.md";
const README_PATH: &str = "README.md";
const EXPECTED_CONTRACT_SCHEMA: &str =
    "pi.swarm.fourth_wave_self_healing.closeout_gate_contract.v1";
const EXPECTED_EVIDENCE_SCHEMA: &str = "pi.swarm.fourth_wave_self_healing.closeout_gate.v1";
const EXPECTED_PURPOSE: &str =
    "prompt_to_artifact_fourth_wave_self_healing_closeout_gate_not_source_of_truth";

type TestResult<T = ()> = Result<T, String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &str) -> TestResult<Value> {
    let full_path = repo_root().join(path);
    let raw = std::fs::read_to_string(&full_path)
        .map_err(|err| format!("failed to read {}: {err}", full_path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", full_path.display()))
}

fn load_text(path: &str) -> TestResult<String> {
    let full_path = repo_root().join(path);
    std::fs::read_to_string(&full_path)
        .map_err(|err| format!("failed to read {}: {err}", full_path.display()))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn require_lazy(condition: bool, message: impl FnOnce() -> String) -> TestResult {
    if condition { Ok(()) } else { Err(message()) }
}

fn pointer<'a>(value: &'a Value, path: &str) -> TestResult<&'a Value> {
    value
        .pointer(path)
        .ok_or_else(|| format!("missing JSON pointer {path}"))
}

fn pointer_mut<'a>(value: &'a mut Value, path: &str) -> TestResult<&'a mut Value> {
    value
        .pointer_mut(path)
        .ok_or_else(|| format!("missing mutable JSON pointer {path}"))
}

fn pointer_str<'a>(value: &'a Value, path: &str) -> TestResult<&'a str> {
    pointer(value, path)?
        .as_str()
        .ok_or_else(|| format!("{path} must be a string"))
}

fn pointer_bool(value: &Value, path: &str) -> TestResult<bool> {
    pointer(value, path)?
        .as_bool()
        .ok_or_else(|| format!("{path} must be a bool"))
}

fn pointer_array<'a>(value: &'a Value, path: &str) -> TestResult<&'a [Value]> {
    pointer(value, path)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{path} must be an array"))
}

fn pointer_array_mut<'a>(value: &'a mut Value, path: &str) -> TestResult<&'a mut Vec<Value>> {
    pointer_mut(value, path)?
        .as_array_mut()
        .ok_or_else(|| format!("{path} must be an array"))
}

fn string_set<'a>(value: &'a Value, path: &str) -> TestResult<HashSet<&'a str>> {
    let mut entries = HashSet::new();
    for entry in pointer_array(value, path)? {
        let raw = entry
            .as_str()
            .ok_or_else(|| format!("{path} entries must be strings"))?;
        let normalized = raw.trim();
        require(
            !normalized.is_empty(),
            format!("{path} entries must be non-empty"),
        )?;
        entries.insert(normalized);
    }
    Ok(entries)
}

fn checklist_row<'a>(evidence: &'a Value, id: &str) -> TestResult<&'a Value> {
    pointer_array(evidence, "/checklist")?
        .iter()
        .find(|row| row.pointer("/id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("missing checklist row {id}"))
}

fn checklist_row_mut<'a>(evidence: &'a mut Value, id: &str) -> TestResult<&'a mut Value> {
    pointer_array_mut(evidence, "/checklist")?
        .iter_mut()
        .find(|row| row.pointer("/id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("missing mutable checklist row {id}"))
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn require_existing_paths(row: &Value, path: &str) -> TestResult {
    for entry in pointer_array(row, path)? {
        let relative_path = entry
            .as_str()
            .ok_or_else(|| format!("{path} entries must be strings"))?;
        require_lazy(repo_root().join(relative_path).exists(), || {
            format!("{path} entry does not exist: {relative_path}")
        })?;
    }
    Ok(())
}

fn verify_child_artifact_map(contract: &Value, evidence: &Value) -> TestResult {
    let required = string_set(contract, "/required_child_bead_ids")?;
    let rows = pointer_array(evidence, "/child_artifact_map")?;
    require(
        rows.len() == required.len(),
        "child_artifact_map must have exactly one row per required child",
    )?;
    let mut seen = HashSet::new();
    for row in rows {
        let bead_id = pointer_str(row, "/bead_id")?;
        require(
            required.contains(bead_id),
            format!("unexpected child bead mapping {bead_id}"),
        )?;
        require(
            seen.insert(bead_id),
            format!("duplicate child bead mapping {bead_id}"),
        )?;
        require(
            pointer_str(row, "/status")? == "closed",
            format!("{bead_id} must be closed"),
        )?;
        require(
            !pointer_str(row, "/close_reason")?.trim().is_empty(),
            format!("{bead_id} close_reason must be non-empty"),
        )?;
        require(
            is_hex_commit(pointer_str(row, "/commit")?),
            format!("{bead_id} commit must be a 40-character hex commit"),
        )?;
        require_existing_paths(row, "/code_paths")?;
        require_existing_paths(row, "/test_paths")?;
        require_existing_paths(row, "/docs_or_evidence_paths")?;
        require(
            !pointer_array(row, "/docs_or_evidence_paths")?.is_empty(),
            format!("{bead_id} docs_or_evidence_paths must not be empty"),
        )?;
        require(
            !pointer_array(row, "/validation_commands")?.is_empty(),
            format!("{bead_id} validation_commands must not be empty"),
        )?;
        let claim_boundary = pointer_str(row, "/claim_boundary_text")?;
        require(
            claim_boundary.contains("does not") || claim_boundary.contains("not "),
            format!("{bead_id} claim_boundary_text must explicitly limit claims"),
        )?;
    }
    require(
        seen == required,
        "child_artifact_map ids must exactly match required child bead ids",
    )
}

fn verify_checklist(contract: &Value, evidence: &Value) -> TestResult {
    let required = string_set(contract, "/required_check_ids")?;
    let rows = pointer_array(evidence, "/checklist")?;
    let mut seen = HashSet::new();
    for row in rows {
        let id = pointer_str(row, "/id")?;
        require(
            required.contains(id),
            format!("unexpected checklist id {id}"),
        )?;
        require(seen.insert(id), format!("duplicate checklist id {id}"))?;
        require(
            pointer_str(row, "/status")? == "pass",
            format!("checklist row {id} must pass"),
        )?;
        require(
            !pointer_array(row, "/evidence")?.is_empty(),
            format!("checklist row {id} evidence must not be empty"),
        )?;
    }
    require(
        seen == required,
        "checklist ids must exactly match required check ids",
    )
}

fn verify_source_boundaries(contract: &Value, evidence: &Value) -> TestResult {
    let required = string_set(contract, "/required_source_boundary_ids")?;
    let rows = pointer_array(evidence, "/source_boundary_checks")?;
    let mut seen = HashSet::new();
    for row in rows {
        let id = pointer_str(row, "/id")?;
        require(
            required.contains(id),
            format!("unexpected source boundary id {id}"),
        )?;
        require(
            seen.insert(id),
            format!("duplicate source boundary id {id}"),
        )?;
        require(
            pointer_str(row, "/status")? == "pass",
            format!("source boundary {id} must pass"),
        )?;
        require(
            !pointer_array(row, "/evidence")?.is_empty(),
            format!("source boundary {id} evidence must not be empty"),
        )?;
        require(
            !pointer_str(row, "/boundary")?.trim().is_empty(),
            format!("source boundary {id} text must not be empty"),
        )?;
    }
    require(
        seen == required,
        "source boundary ids must exactly match required ids",
    )
}

fn verify_quality_gates(contract: &Value, evidence: &Value) -> TestResult {
    let required = string_set(contract, "/required_quality_gate_ids")?;
    let quality_row = checklist_row(evidence, "quality_gates")?;
    let payload = pointer_array(quality_row, "/evidence")?
        .first()
        .ok_or_else(|| String::from("quality_gates evidence must not be empty"))?;
    require(
        pointer_bool(payload, "/heavy_cargo_uses_rch")?,
        "quality gate evidence must prove heavy Cargo gates use RCH",
    )?;
    let rows = pointer_array(payload, "/provided_quality_gates")?;
    let mut seen = HashSet::new();
    for row in rows {
        let id = pointer_str(row, "/id")?;
        require(
            required.contains(id),
            format!("unexpected quality gate id {id}"),
        )?;
        require(seen.insert(id), format!("duplicate quality gate id {id}"))?;
        require(
            pointer_str(row, "/status")? == "pass",
            format!("quality gate {id} must pass"),
        )?;
        let command = pointer_str(row, "/command")?;
        require(
            !command.trim().is_empty(),
            format!("quality gate {id} command must not be empty"),
        )?;
        if matches!(
            id,
            "fourth_wave_closeout_gate_contract_rch"
                | "cargo_check_all_targets_rch"
                | "cargo_clippy_all_targets_rch"
        ) {
            require(
                command.contains("rch exec --"),
                format!("quality gate {id} must prove RCH execution"),
            )?;
        }
    }
    require(
        seen == required,
        "quality gate ids must exactly match required ids",
    )
}

fn verify_claim_boundaries(evidence: &Value) -> TestResult {
    require(
        !pointer_bool(
            evidence,
            "/claim_boundaries/strict_dropin_or_release_claim_authorized",
        )?,
        "strict drop-in or release claims must not be authorized",
    )?;
    require(
        !pointer_bool(
            evidence,
            "/claim_boundaries/self_healing_artifacts_mutate_sources",
        )?,
        "self-healing artifacts must not mutate sources",
    )?;
    require(
        !pointer_bool(
            evidence,
            "/claim_boundaries/work_admission_gate_enforces_runtime_throttle",
        )?,
        "work admission gate must not claim runtime enforcement",
    )?;
    require(
        !pointer_bool(
            evidence,
            "/claim_boundaries/closeout_replaces_source_artifacts",
        )?,
        "closeout must not replace source artifacts",
    )?;
    require(
        pointer_bool(
            evidence,
            "/claim_boundaries/human_confirmation_required_for_mutation",
        )?,
        "human confirmation must be required for mutation",
    )
}

fn verify_docs(contract: &Value, evidence: &Value) -> TestResult {
    let readme = load_text(README_PATH)?;
    let runbook = load_text(RUNBOOK_PATH)?;
    require(
        readme.contains(EXPECTED_EVIDENCE_SCHEMA),
        "README must mention fourth-wave evidence schema",
    )?;
    require(
        readme.contains(CONTRACT_PATH) && readme.contains(EVIDENCE_PATH),
        "README must link fourth-wave contract and evidence",
    )?;
    require(
        runbook.contains(EXPECTED_EVIDENCE_SCHEMA),
        "runbook must mention fourth-wave evidence schema",
    )?;
    require(
        runbook.contains(CONTRACT_PATH) && runbook.contains(EVIDENCE_PATH),
        "runbook must link fourth-wave contract and evidence",
    )?;
    require(
        pointer_str(contract, "/purpose")? == EXPECTED_PURPOSE
            && pointer_str(evidence, "/purpose")? == EXPECTED_PURPOSE,
        "contract and evidence purposes must match expected boundary",
    )
}

#[test]
fn fourth_wave_closeout_contract_and_evidence_have_expected_identity() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;
    require(
        pointer_str(&contract, "/schema")? == EXPECTED_CONTRACT_SCHEMA,
        "contract schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/decision_gate_schema")? == EXPECTED_EVIDENCE_SCHEMA,
        "contract decision gate schema mismatch",
    )?;
    require(
        pointer_str(&evidence, "/schema")? == EXPECTED_EVIDENCE_SCHEMA,
        "evidence schema mismatch",
    )?;
    require(
        pointer_str(&evidence, "/status")? == "pass",
        "evidence must pass",
    )?;
    require(
        pointer_bool(&evidence, "/epic_can_close_after_this_commit")?,
        "epic_can_close_after_this_commit must be true",
    )?;
    require(
        pointer_array(&evidence, "/missing_checks")?.is_empty(),
        "missing_checks must be empty",
    )
}

#[test]
fn fourth_wave_closeout_child_artifact_map_is_complete() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;
    verify_child_artifact_map(&contract, &evidence)
}

#[test]
fn fourth_wave_closeout_checklist_quality_gates_and_docs_are_complete() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;
    verify_checklist(&contract, &evidence)?;
    verify_quality_gates(&contract, &evidence)?;
    verify_docs(&contract, &evidence)
}

#[test]
fn fourth_wave_closeout_source_boundaries_and_claims_pass() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;
    verify_source_boundaries(&contract, &evidence)?;
    verify_claim_boundaries(&evidence)
}

#[test]
fn fourth_wave_closeout_rejects_missing_open_or_weak_child_evidence() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;

    let mut missing_child = evidence.clone();
    pointer_array_mut(&mut missing_child, "/child_artifact_map")?.pop();
    require(
        verify_child_artifact_map(&contract, &missing_child).is_err(),
        "missing child row must fail",
    )?;

    let mut open_child = evidence.clone();
    *pointer_mut(&mut open_child, "/child_artifact_map/0/status")? =
        Value::String(String::from("open"));
    require(
        verify_child_artifact_map(&contract, &open_child).is_err(),
        "open child row must fail",
    )?;

    let mut missing_validation = evidence.clone();
    pointer_array_mut(
        &mut missing_validation,
        "/child_artifact_map/0/validation_commands",
    )?
    .clear();
    require(
        verify_child_artifact_map(&contract, &missing_validation).is_err(),
        "child row without validation commands must fail",
    )?;

    let mut missing_claim_boundary = evidence;
    *pointer_mut(
        &mut missing_claim_boundary,
        "/child_artifact_map/0/claim_boundary_text",
    )? = Value::String(String::new());
    require(
        verify_child_artifact_map(&contract, &missing_claim_boundary).is_err(),
        "child row without claim-boundary text must fail",
    )
}

#[test]
fn fourth_wave_closeout_rejects_missing_quality_gate_or_claim_boundary_drift() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;

    let mut missing_quality = evidence.clone();
    let quality_row = checklist_row_mut(&mut missing_quality, "quality_gates")?;
    let provided = pointer_array_mut(quality_row, "/evidence/0/provided_quality_gates")?;
    provided.retain(|row| {
        row.pointer("/id").and_then(Value::as_str) != Some("fourth_wave_closeout_gate_contract_rch")
    });
    require(
        verify_quality_gates(&contract, &missing_quality).is_err(),
        "missing fourth-wave contract quality gate must fail",
    )?;

    let mut non_rch_contract_gate = evidence.clone();
    let quality_row = checklist_row_mut(&mut non_rch_contract_gate, "quality_gates")?;
    for row in pointer_array_mut(quality_row, "/evidence/0/provided_quality_gates")? {
        if row.pointer("/id").and_then(Value::as_str)
            == Some("fourth_wave_closeout_gate_contract_rch")
        {
            *pointer_mut(row, "/command")? = Value::String(String::from(
                "cargo test --test fourth_wave_self_healing_closeout_gate_contract",
            ));
        }
    }
    require(
        verify_quality_gates(&contract, &non_rch_contract_gate).is_err(),
        "non-RCH contract gate command must fail",
    )?;

    let mut bad_claim = evidence;
    *pointer_mut(
        &mut bad_claim,
        "/claim_boundaries/strict_dropin_or_release_claim_authorized",
    )? = Value::Bool(true);
    require(
        verify_claim_boundaries(&bad_claim).is_err(),
        "claim boundary drift must fail",
    )
}
