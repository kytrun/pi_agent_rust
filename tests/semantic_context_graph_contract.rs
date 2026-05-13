#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/semantic-context-graph-contract.json";
const EXPECTED_SCHEMA: &str = "pi.context.semantic_graph_contract.v1";
const EXPECTED_BEAD_ID: &str = "bd-ircr3.1";
const EXPECTED_PARENT_BEAD_ID: &str = "bd-ircr3";

const REQUIRED_NODE_TYPES: &[&str] = &[
    "code_symbol",
    "file_region",
    "test_case",
    "doc_section",
    "evidence_artifact",
    "bead",
    "provider_surface",
    "validation_command",
];

const REQUIRED_EDGE_TYPES: &[&str] = &[
    "contains",
    "defines",
    "exercises",
    "validates",
    "cites_evidence",
    "tracks",
    "blocks",
    "depends_on",
    "suggests_validation",
    "supersedes",
];

const REQUIRED_FRESHNESS_STATES: &[&str] = &[
    "current",
    "stale",
    "missing",
    "malformed",
    "uncertified",
    "freshness_unknown",
];

const REQUIRED_REDACTION_STATES: &[&str] =
    &["none", "redacted", "sensitive_omitted", "unsafe_to_emit"];

const REQUIRED_OVERLAP_BEADS: &[&str] = &["bd-h3uv0", "bd-07cku", "bd-dklqn"];
const REQUIRED_UNBLOCKED_BEADS: &[&str] = &["bd-ircr3.2", "bd-ircr3.3"];

type ValidationResult<T> = Result<T, String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_contract() -> ValidationResult<Value> {
    let path = repo_root().join(CONTRACT_PATH);
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", path.display()))
}

fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn require(condition: bool, message: impl Into<String>) -> ValidationResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn field<'a>(value: &'a Value, name: &str) -> ValidationResult<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| format!("missing field {name}"))
}

fn field_str<'a>(value: &'a Value, name: &str) -> ValidationResult<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| format!("{name} must be a string"))
}

fn field_bool(value: &Value, name: &str) -> ValidationResult<bool> {
    field(value, name)?
        .as_bool()
        .ok_or_else(|| format!("{name} must be a bool"))
}

fn pointer_array<'a>(value: &'a Value, pointer: &str) -> ValidationResult<&'a [Value]> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("expected JSON array at pointer {pointer}"))
}

fn pointer_bool(value: &Value, pointer: &str) -> ValidationResult<bool> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("expected bool at pointer {pointer}"))
}

fn pointer_str<'a>(value: &'a Value, pointer: &str) -> ValidationResult<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("expected string at pointer {pointer}"))
}

fn pointer_array_mut<'a>(
    value: &'a mut Value,
    pointer: &str,
) -> ValidationResult<&'a mut Vec<Value>> {
    value
        .pointer_mut(pointer)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("expected mutable array at pointer {pointer}"))
}

fn non_empty_string_set(value: &Value, pointer: &str) -> ValidationResult<HashSet<String>> {
    let mut out = HashSet::new();
    for entry in pointer_array(value, pointer)? {
        let raw = entry
            .as_str()
            .ok_or_else(|| format!("expected string entry at {pointer}"))?;
        let normalized = raw.trim();
        require(
            !normalized.is_empty(),
            format!("entry at {pointer} must be non-empty"),
        )?;
        out.insert(normalized.to_string());
    }
    Ok(out)
}

fn validate_required_set(
    contract: &Value,
    pointer: &str,
    required_values: &[&str],
    label: &str,
) -> ValidationResult<()> {
    let values = non_empty_string_set(contract, pointer)?;
    for required in required_values {
        if !values.contains(*required) {
            return Err(format!("missing {label}: {required}"));
        }
    }
    Ok(())
}

fn validate_top_level(contract: &Value) -> ValidationResult<()> {
    let schema = pointer_str(contract, "/schema")?;
    require(
        schema == EXPECTED_SCHEMA,
        format!("schema expected {EXPECTED_SCHEMA}, got {schema}"),
    )?;

    let version = pointer_str(contract, "/contract_version")?;
    require(
        parse_semver(version).is_some(),
        "contract_version must be semantic version x.y.z",
    )?;

    let bead_id = pointer_str(contract, "/bead_id")?;
    require(
        bead_id == EXPECTED_BEAD_ID,
        format!("bead_id must be {EXPECTED_BEAD_ID}"),
    )?;

    let parent_bead_id = pointer_str(contract, "/parent_bead_id")?;
    require(
        parent_bead_id == EXPECTED_PARENT_BEAD_ID,
        format!("parent_bead_id must be {EXPECTED_PARENT_BEAD_ID}"),
    )?;

    require(
        pointer_str(contract, "/purpose").is_ok_and(|purpose| !purpose.is_empty()),
        "purpose must be non-empty",
    )
}

fn validate_graph_schema(contract: &Value) -> ValidationResult<()> {
    validate_required_set(
        contract,
        "/graph_schema/required_node_types",
        REQUIRED_NODE_TYPES,
        "node type",
    )?;
    validate_required_set(
        contract,
        "/graph_schema/required_edge_types",
        REQUIRED_EDGE_TYPES,
        "edge type",
    )?;
    validate_required_set(
        contract,
        "/graph_schema/allowed_freshness_states",
        REQUIRED_FRESHNESS_STATES,
        "freshness state",
    )?;
    validate_required_set(
        contract,
        "/graph_schema/allowed_redaction_states",
        REQUIRED_REDACTION_STATES,
        "redaction state",
    )?;

    let node_type_contracts = pointer_array(contract, "/graph_schema/node_type_contracts")?;
    let mut covered_node_types = HashSet::new();
    for entry in node_type_contracts {
        covered_node_types.insert(field_str(entry, "node_type")?);
    }
    for node_type in REQUIRED_NODE_TYPES {
        if !covered_node_types.contains(node_type) {
            return Err(format!("missing node_type_contract for {node_type}"));
        }
    }

    for entry in node_type_contracts {
        let node_type = field_str(entry, "node_type")?;
        if pointer_array(entry, "/required_fields")?.is_empty() {
            return Err(format!("{node_type} must define required_fields"));
        }
        let _freshness_required = field_bool(entry, "freshness_required")?;
        let _redaction_required = field_bool(entry, "redaction_required")?;
    }
    Ok(())
}

fn validate_overlap_boundaries(contract: &Value) -> ValidationResult<()> {
    let boundaries = pointer_array(contract, "/overlap_boundaries")?;
    let mut bead_ids = HashSet::new();
    for entry in boundaries {
        bead_ids.insert(field_str(entry, "existing_bead_id")?);
    }
    for bead_id in REQUIRED_OVERLAP_BEADS {
        if !bead_ids.contains(bead_id) {
            return Err(format!("missing overlap boundary for {bead_id}"));
        }
    }
    for entry in boundaries {
        let bead_id = field_str(entry, "existing_bead_id")?;
        require(
            field_str(entry, "boundary").is_ok_and(|boundary| !boundary.is_empty()),
            format!("overlap boundary for {bead_id} must be non-empty"),
        )?;
    }
    Ok(())
}

fn validate_source_surfaces(contract: &Value) -> ValidationResult<()> {
    let surfaces = pointer_array(contract, "/source_surfaces")?;
    let mut surface_ids = HashSet::new();
    for entry in surfaces {
        surface_ids.insert(field_str(entry, "surface_id")?);
    }
    for required in ["rust_source", "rust_tests", "docs", "beads"] {
        if !surface_ids.contains(required) {
            return Err(format!("missing source surface {required}"));
        }
    }
    for entry in surfaces {
        let surface_id = field_str(entry, "surface_id")?;
        if pointer_array(entry, "/path_globs")?.is_empty() {
            return Err(format!("{surface_id} must define path_globs"));
        }
        if pointer_array(entry, "/node_types")?.is_empty() {
            return Err(format!("{surface_id} must define node_types"));
        }
        require(
            field_str(entry, "extraction_policy").is_ok_and(|policy| !policy.is_empty()),
            format!("{surface_id} must define extraction_policy"),
        )?;
    }
    Ok(())
}

fn validate_fail_closed_policies(contract: &Value) -> ValidationResult<()> {
    for pointer in [
        "/freshness_policy/fail_closed",
        "/redaction_policy/fail_closed",
    ] {
        if !pointer_bool(contract, pointer)? {
            return Err(format!("{pointer} must be true"));
        }
    }
    require(
        pointer_bool(
            contract,
            "/freshness_policy/direct_read_fallback_on_uncertainty",
        )?,
        "freshness_policy.direct_read_fallback_on_uncertainty must be true",
    )?;
    require(
        pointer_bool(
            contract,
            "/freshness_policy/stale_evidence_must_be_suppressed",
        )?,
        "freshness_policy.stale_evidence_must_be_suppressed must be true",
    )?;
    require(
        pointer_bool(
            contract,
            "/freshness_policy/release_claims_require_certified_gate",
        )?,
        "freshness_policy.release_claims_require_certified_gate must be true",
    )
}

fn validate_gap_audit_and_handoff(contract: &Value) -> ValidationResult<()> {
    for pointer in [
        "/gap_audit/current_strengths",
        "/gap_audit/missing_for_bd_ircr3_2",
        "/gap_audit/missing_for_bd_ircr3_3",
        "/gap_audit/handoff_requirements",
    ] {
        if pointer_array(contract, pointer)?.is_empty() {
            return Err(format!("{pointer} must not be empty"));
        }
    }
    validate_required_set(
        contract,
        "/downstream_dependencies/unblocked_beads",
        REQUIRED_UNBLOCKED_BEADS,
        "unblocked bead",
    )
}

fn validate_contract(contract: &Value) -> ValidationResult<()> {
    validate_top_level(contract)?;
    validate_graph_schema(contract)?;
    validate_overlap_boundaries(contract)?;
    validate_source_surfaces(contract)?;
    validate_fail_closed_policies(contract)?;
    validate_gap_audit_and_handoff(contract)
}

fn remove_string_entry(contract: &mut Value, pointer: &str, value: &str) -> ValidationResult<bool> {
    let entries = pointer_array_mut(contract, pointer)?;
    let before = entries.len();
    entries.retain(|entry| entry.as_str().map(str::trim) != Some(value));
    Ok(before != entries.len())
}

fn remove_overlap_boundary(contract: &mut Value, bead_id: &str) -> ValidationResult<bool> {
    let boundaries = pointer_array_mut(contract, "/overlap_boundaries")?;
    let before = boundaries.len();
    boundaries
        .retain(|entry| entry.get("existing_bead_id").and_then(Value::as_str) != Some(bead_id));
    Ok(before != boundaries.len())
}

fn set_bool(contract: &mut Value, pointer: &str, enabled: bool) -> ValidationResult<()> {
    let field = contract
        .pointer_mut(pointer)
        .ok_or_else(|| format!("expected mutable field at {pointer}"))?;
    *field = Value::Bool(enabled);
    Ok(())
}

fn require_validation_error(
    result: ValidationResult<()>,
    expected_text: &str,
) -> ValidationResult<()> {
    match result {
        Ok(()) => Err(format!(
            "contract should fail with error containing {expected_text}"
        )),
        Err(err) => require(
            err.contains(expected_text),
            format!("expected error to reference {expected_text}, got: {err}"),
        ),
    }
}

#[test]
fn semantic_context_graph_contract_exists_and_is_valid_json() -> ValidationResult<()> {
    let path = repo_root().join(CONTRACT_PATH);
    require(
        path.is_file(),
        format!(
            "missing semantic context graph contract artifact: {}",
            path.display()
        ),
    )?;
    let _contract = load_contract()?;
    Ok(())
}

#[test]
fn semantic_context_graph_contract_is_complete() -> ValidationResult<()> {
    let contract = load_contract()?;
    validate_contract(&contract)
}

#[test]
fn semantic_context_graph_contract_fails_closed_when_node_type_missing() -> ValidationResult<()> {
    let mut contract = load_contract()?;
    require(
        remove_string_entry(
            &mut contract,
            "/graph_schema/required_node_types",
            "evidence_artifact",
        )?,
        "mutation should remove required node type",
    )?;

    require_validation_error(validate_graph_schema(&contract), "evidence_artifact")
}

#[test]
fn semantic_context_graph_contract_fails_closed_when_stale_state_missing() -> ValidationResult<()> {
    let mut contract = load_contract()?;
    require(
        remove_string_entry(
            &mut contract,
            "/graph_schema/allowed_freshness_states",
            "stale",
        )?,
        "mutation should remove required freshness state",
    )?;

    require_validation_error(validate_graph_schema(&contract), "stale")
}

#[test]
fn semantic_context_graph_contract_fails_closed_when_policy_is_not_fail_closed()
-> ValidationResult<()> {
    let mut contract = load_contract()?;
    set_bool(&mut contract, "/freshness_policy/fail_closed", false)?;

    require_validation_error(validate_fail_closed_policies(&contract), "fail_closed")
}

#[test]
fn semantic_context_graph_contract_fails_closed_when_overlap_boundary_missing()
-> ValidationResult<()> {
    let mut contract = load_contract()?;
    require(
        remove_overlap_boundary(&mut contract, "bd-dklqn")?,
        "mutation should remove shared source-cache boundary",
    )?;

    require_validation_error(validate_overlap_boundaries(&contract), "bd-dklqn")
}

#[test]
fn semantic_context_graph_contract_fails_closed_when_downstream_bead_missing()
-> ValidationResult<()> {
    let mut contract = load_contract()?;
    require(
        remove_string_entry(
            &mut contract,
            "/downstream_dependencies/unblocked_beads",
            "bd-ircr3.3",
        )?,
        "mutation should remove required downstream bead",
    )?;

    require_validation_error(validate_gap_audit_and_handoff(&contract), "bd-ircr3.3")
}
