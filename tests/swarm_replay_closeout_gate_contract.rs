#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/swarm-replay-closeout-gate-contract.json";
const EVIDENCE_PATH: &str = "docs/evidence/swarm-replay-closeout-gate.json";
const EXPECTED_CONTRACT_SCHEMA: &str = "pi.swarm.replay_closeout_gate_contract.v1";
const EXPECTED_EVIDENCE_SCHEMA: &str = "pi.swarm.replay_closeout_gate.v1";
const EXPECTED_PURPOSE: &str = "prompt_to_artifact_swarm_replay_closeout_gate_not_source_of_truth";

type TestResult = Result<(), String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &str) -> Result<Value, String> {
    let full_path = repo_root().join(path);
    let raw = std::fs::read_to_string(&full_path)
        .map_err(|err| format!("failed to read {}: {err}", full_path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", full_path.display()))
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
    for entry in pointer_array(value, path)? {
        let raw = entry.as_str().ok_or("string set entries must be strings")?;
        require(
            !raw.trim().is_empty(),
            "string set entries must be non-empty",
        )?;
        entries.insert(raw);
    }
    Ok(entries)
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn require_hex_commit(value: &Value, path: &str) -> TestResult {
    let commit = pointer_str(value, path)?;
    require(
        is_hex_commit(commit),
        format!("{path} must be a 40-character hex commit, got {commit}"),
    )
}

fn require_non_empty_array(value: &Value, path: &str) -> TestResult {
    require(
        !pointer_array(value, path)?.is_empty(),
        "required array must not be empty",
    )
}

fn checklist_row<'a>(evidence: &'a Value, id: &str) -> Result<&'a Value, String> {
    pointer_array(evidence, "/checklist")?
        .iter()
        .find(|row| row.pointer("/id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("missing checklist row {id}"))
}

#[test]
fn swarm_replay_closeout_contract_and_evidence_have_expected_identity() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;

    require(
        pointer_str(&contract, "/schema")? == EXPECTED_CONTRACT_SCHEMA,
        "contract schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/decision_gate_schema")? == EXPECTED_EVIDENCE_SCHEMA,
        "contract decision_gate_schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/purpose")? == EXPECTED_PURPOSE,
        "contract purpose mismatch",
    )?;
    require(
        pointer_str(&evidence, "/schema")? == EXPECTED_EVIDENCE_SCHEMA,
        "evidence schema mismatch",
    )?;
    require(
        pointer_str(&evidence, "/purpose")? == EXPECTED_PURPOSE,
        "evidence purpose mismatch",
    )?;
    require(
        pointer_str(&evidence, "/status")? == "pass",
        "evidence status must be pass",
    )?;
    require(
        pointer_str(&evidence, "/parent_epic/id")? == "bd-in57w",
        "parent epic id mismatch",
    )?;
    require(
        pointer_str(&evidence, "/final_gate_bead/id")? == "bd-in57w.12",
        "final gate bead id mismatch",
    )?;
    require(
        pointer_bool(&evidence, "/epic_can_close_after_this_commit")?,
        "passing closeout gate must allow parent close after this commit",
    )?;

    for key in string_set(&contract, "/required_top_level_keys")? {
        require(
            evidence.get(key).is_some(),
            "evidence missing required top-level key",
        )?;
    }
    Ok(())
}

#[test]
fn swarm_replay_closeout_child_artifact_map_is_complete() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;
    let required_children = string_set(&contract, "/required_child_bead_ids")?;
    let child_map = pointer_array(&evidence, "/child_artifact_map")?;

    require(
        child_map.len() == required_children.len(),
        "child_artifact_map must have exactly one row per required child",
    )?;

    let mut observed = HashSet::new();
    for row in child_map {
        let bead = pointer_str(row, "/bead_id")?;
        require(
            required_children.contains(bead),
            "unexpected child bead mapping",
        )?;
        require(observed.insert(bead), "duplicate child bead mapping")?;
        require(
            pointer_str(row, "/status")? == "closed",
            "child bead must be closed",
        )?;
        require(
            !pointer_str(row, "/close_reason")?.trim().is_empty(),
            "child close_reason must be non-empty",
        )?;
        require_hex_commit(row, "/commit")?;
        require_non_empty_array(row, "/code_paths")?;
        require_non_empty_array(row, "/test_paths")?;
        require_non_empty_array(row, "/docs_or_evidence_paths")?;
        require_non_empty_array(row, "/validation_commands")?;
    }

    require(
        observed == required_children,
        "child_artifact_map ids must exactly match required child bead ids",
    )
}

#[test]
fn swarm_replay_closeout_checklist_and_quality_gates_are_complete() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;
    let required_checks = string_set(&contract, "/required_check_ids")?;
    let required_quality_gates = string_set(&contract, "/required_quality_gate_ids")?;

    require(
        string_set(&evidence, "/required_checks")? == required_checks,
        "required_checks must exactly match the contract",
    )?;
    require(
        pointer_array(&evidence, "/missing_checks")?.is_empty(),
        "missing_checks must be empty for a passing gate",
    )?;
    require(
        !pointer_bool(&evidence, "/follow_up_required")?,
        "follow_up_required must be false for a passing gate",
    )?;
    require(
        pointer_array(&evidence, "/follow_up_beads")?.is_empty(),
        "follow_up_beads must be empty for a passing gate",
    )?;

    let mut checklist_ids = HashSet::new();
    for row in pointer_array(&evidence, "/checklist")? {
        let id = pointer_str(row, "/id")?;
        require(required_checks.contains(id), "unexpected checklist id")?;
        require(
            pointer_str(row, "/status")? == "pass",
            "checklist row must pass",
        )?;
        require_non_empty_array(row, "/evidence")?;
        checklist_ids.insert(id);
    }
    require(
        checklist_ids == required_checks,
        "checklist ids must exactly match required checks",
    )?;

    let mut quality_gate_ids = HashSet::new();
    for gate in pointer_array(&evidence, "/quality_gate_results")? {
        let id = pointer_str(gate, "/id")?;
        require(
            required_quality_gates.contains(id),
            "unexpected quality gate id",
        )?;
        require(
            pointer_str(gate, "/status")? == "pass",
            "quality gate must pass",
        )?;
        require(
            !pointer_str(gate, "/command")?.trim().is_empty(),
            "quality gate command must be non-empty",
        )?;
        quality_gate_ids.insert(id);
    }
    require(
        quality_gate_ids == required_quality_gates,
        "quality gate ids must exactly match required quality gates",
    )
}

#[test]
fn swarm_replay_closeout_source_boundaries_and_push_evidence_pass() -> TestResult {
    let evidence = load_json(EVIDENCE_PATH)?;

    for id in [
        "trace_contract",
        "preview_runpack_integration",
        "no_mock_e2e",
        "operator_docs",
        "readme_freshness",
        "pushed_commits",
    ] {
        let row = checklist_row(&evidence, id)?;
        require(
            pointer_str(row, "/status")? == "pass",
            "checklist row must pass",
        )?;
    }

    let pushed = checklist_row(&evidence, "pushed_commits")?;
    let snapshot = pointer_array(pushed, "/evidence")?
        .first()
        .ok_or_else(|| "pushed_commits evidence must not be empty".to_string())?;
    require_hex_commit(snapshot, "/head_before_closeout_commit")?;
    require_hex_commit(snapshot, "/origin_main_before_closeout_commit")?;
    require_hex_commit(snapshot, "/origin_master_before_closeout_commit")?;

    let child_commits = pointer_array(snapshot, "/child_commits")?;
    require(
        child_commits.len() == 11,
        "pushed snapshot must list 11 child commits",
    )?;
    for commit in child_commits {
        let commit = commit
            .as_str()
            .ok_or("child commit entries must be strings")?;
        require(
            is_hex_commit(commit),
            "child commits must be 40-character hex hashes",
        )?;
    }

    let quality = checklist_row(&evidence, "quality_gates")?;
    let quality_evidence = pointer_array(quality, "/evidence")?;
    let first = quality_evidence
        .first()
        .ok_or_else(|| "quality_gates evidence must not be empty".to_string())?;
    require(
        pointer_bool(first, "/heavy_cargo_uses_rch")?,
        "quality gate evidence must prove heavy Cargo gates used RCH",
    )
}
