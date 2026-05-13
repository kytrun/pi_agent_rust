#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/semantic-workspace-graph-contract.json";

type TestResult = Result<(), String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_contract() -> Result<Value, String> {
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

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("missing field {name}"))
}

fn field_str<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| format!("{name} must be a string"))
}

fn field_bool(value: &Value, name: &str) -> Result<bool, String> {
    field(value, name)?
        .as_bool()
        .ok_or_else(|| format!("{name} must be a bool"))
}

fn field_array<'a>(value: &'a Value, name: &str) -> Result<&'a [Value], String> {
    field(value, name)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{name} must be an array"))
}

fn pointer_array<'a>(value: &'a Value, pointer: &str) -> Result<&'a [Value], String> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{pointer} must be an array"))
}

fn string_set<'a>(value: &'a Value, field_name: &str) -> Result<HashSet<&'a str>, String> {
    let mut set = HashSet::new();
    for entry in field_array(value, field_name)? {
        let raw = entry
            .as_str()
            .ok_or_else(|| format!("{field_name} entries must be strings"))?;
        set.insert(raw);
    }
    Ok(set)
}

fn require_str_field(value: &Value, field_name: &str, expected: &str) -> TestResult {
    let observed = field_str(value, field_name)?;
    require(
        observed == expected,
        format!("{field_name} expected {expected}, got {observed}"),
    )
}

fn require_bool_field(value: &Value, field_name: &str, expected: bool) -> TestResult {
    let observed = field_bool(value, field_name)?;
    require(
        observed == expected,
        format!("{field_name} expected {expected}, got {observed}"),
    )
}

#[test]
fn semantic_workspace_graph_contract_exists_and_has_expected_identity() -> TestResult {
    let path = repo_root().join(CONTRACT_PATH);
    require(
        path.is_file(),
        format!(
            "missing semantic workspace graph contract artifact: {}",
            path.display()
        ),
    )?;

    let contract = load_contract()?;
    require_str_field(
        &contract,
        "schema",
        "pi.semantic_workspace_graph.contract.v1",
    )?;
    require_str_field(&contract, "graph_schema", "pi.semantic_workspace_graph.v1")?;
    require_str_field(&contract, "bead_id", "bd-ircr3.1")?;
    require_str_field(&contract, "parent_bead_id", "bd-ircr3")?;

    let version = field_str(&contract, "contract_version")?;
    require(
        parse_semver(version).is_some(),
        format!("contract_version must be semantic version x.y.z, got: {version}"),
    )?;

    require_str_field(
        &contract,
        "purpose",
        "evidence_aware_context_intelligence_contract_not_source_of_truth",
    )
}

#[test]
fn required_node_schemas_are_complete_and_fail_closed() -> TestResult {
    let contract = load_contract()?;
    let required_node_types = string_set(&contract, "required_node_types")?;
    for required in [
        "code_symbol",
        "file_region",
        "test_case",
        "doc_section",
        "evidence_artifact",
        "bead",
        "provider_surface",
        "validation_command",
    ] {
        require(
            required_node_types.contains(required),
            format!("required_node_types missing {required}"),
        )?;
    }

    let node_schemas = field_array(&contract, "node_schemas")?;
    require(
        node_schemas.len() == required_node_types.len(),
        "every required node type must have exactly one schema row",
    )?;

    let mut observed = HashSet::new();
    for schema in node_schemas {
        let node_type = field_str(schema, "node_type")?;
        require(
            observed.insert(node_type),
            format!("duplicate node schema for {node_type}"),
        )?;
        require(
            required_node_types.contains(node_type),
            format!("node_schemas contains unexpected node type {node_type}"),
        )?;

        for array_field in ["required_fields", "stable_id_fields", "freshness_inputs"] {
            let entries = field_array(schema, array_field)?;
            require(
                !entries.is_empty(),
                format!("{node_type}.{array_field} must not be empty"),
            )?;
        }

        let failure_mode = field_str(schema, "failure_mode")?;
        require(
            failure_mode.contains("omit")
                || failure_mode.contains("required")
                || failure_mode.contains("suppress")
                || failure_mode.contains("classify")
                || failure_mode.contains("warning")
                || failure_mode.contains("infer")
                || failure_mode.contains("fail")
                || failure_mode.contains("candidate"),
            format!(
                "{node_type}.failure_mode must describe a fail-closed behavior, got {failure_mode}"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn surface_inventory_covers_current_context_and_evidence_sources() -> TestResult {
    let contract = load_contract()?;
    let surfaces = field_array(&contract, "current_surface_inventory")?;
    let mut ids = HashSet::new();
    for surface in surfaces {
        ids.insert(field_str(surface, "surface_id")?);
    }

    for required in [
        "rust_code_modules",
        "integration_and_contract_tests",
        "readme_and_docs",
        "readme_evidence_freshness",
        "dropin_and_parity_evidence",
        "tool_output_context_cache_evidence",
        "session_store_and_index",
        "resource_loader",
        "beads_issue_graph",
        "swarm_operator_runpack",
        "provider_surfaces",
    ] {
        require(
            ids.contains(required),
            format!("surface inventory missing {required}"),
        )?;
    }

    for surface in surfaces {
        let id = field_str(surface, "surface_id")?;
        for array_field in ["paths", "freshness_inputs"] {
            let entries = field_array(surface, array_field)?;
            require(
                !entries.is_empty(),
                format!("{id}.{array_field} must not be empty"),
            )?;
        }
        require(
            field_str(surface, "graph_role").is_ok_and(|value| !value.is_empty()),
            format!("{id}.graph_role must be non-empty"),
        )?;
    }
    Ok(())
}

#[test]
fn freshness_and_bead_actionability_statuses_are_explicit() -> TestResult {
    let contract = load_contract()?;
    let freshness = string_set(&contract, "allowed_evidence_freshness_statuses")?;
    for required in [
        "current",
        "historical_snapshot",
        "stale",
        "missing",
        "malformed",
        "uncertified",
        "freshness_unknown",
    ] {
        require(
            freshness.contains(required),
            format!("freshness statuses missing {required}"),
        )?;
    }

    let actionability = string_set(&contract, "allowed_bead_actionability_statuses")?;
    for required in [
        "actionable_open",
        "claimed_in_progress",
        "stalled_reopen_candidate",
        "blocked",
        "closed_reference_only",
        "tombstone_reference_only",
        "unknown_fail_closed",
    ] {
        require(
            actionability.contains(required),
            format!("bead actionability statuses missing {required}"),
        )?;
    }

    let freshness_rules = pointer_array(&contract, "/freshness_policy/classification_rules")?;
    require(
        freshness_rules.iter().any(|rule| {
            field_str(rule, "status").is_ok_and(|status| status == "stale")
                && field_bool(rule, "release_claim_allowed").is_ok_and(|allowed| !allowed)
        }),
        "stale evidence must explicitly block release claims".to_string(),
    )?;
    require(
        freshness_rules.iter().any(|rule| {
            field_str(rule, "status").is_ok_and(|status| status == "uncertified")
                && field_bool(rule, "release_claim_allowed").is_ok_and(|allowed| !allowed)
        }),
        "uncertified evidence must explicitly block release claims".to_string(),
    )?;

    let bead_rules = pointer_array(&contract, "/bead_actionability_policy/classification_rules")?;
    let mut rule_statuses = HashSet::new();
    for rule in bead_rules {
        rule_statuses.insert(field_str(rule, "actionability_status")?);
    }
    for required in [
        "closed_reference_only",
        "tombstone_reference_only",
        "unknown_fail_closed",
    ] {
        require(
            rule_statuses.contains(required),
            format!("bead actionability rule missing {required}"),
        )?;
    }
    Ok(())
}

#[test]
fn classification_fixtures_cover_stale_evidence_and_non_actionable_beads() -> TestResult {
    let contract = load_contract()?;
    let fixtures = field_array(&contract, "classification_fixtures")?;

    let mut by_id: HashMap<&str, &Value> = HashMap::new();
    for fixture in fixtures {
        by_id.insert(field_str(fixture, "fixture_id")?, fixture);
    }

    let stale = by_id
        .get("stale-evidence-generated-at-expired")
        .ok_or_else(|| "missing stale evidence fixture".to_string())?;
    let stale_expected = field(stale, "expected")?;
    require_str_field(stale_expected, "freshness_status", "stale")?;
    require_bool_field(stale_expected, "release_claim_allowed", false)?;

    let closed = by_id
        .get("closed-bead-reference-only")
        .ok_or_else(|| "missing closed bead fixture".to_string())?;
    let closed_expected = field(closed, "expected")?;
    require_str_field(
        closed_expected,
        "actionability_status",
        "closed_reference_only",
    )?;
    require_bool_field(closed_expected, "planner_may_claim", false)?;

    let tombstone = by_id
        .get("tombstone-bead-reference-only")
        .ok_or_else(|| "missing tombstone bead fixture".to_string())?;
    let tombstone_expected = field(tombstone, "expected")?;
    require_str_field(
        tombstone_expected,
        "actionability_status",
        "tombstone_reference_only",
    )?;
    require_str_field(
        tombstone_expected,
        "reason",
        "tombstone_is_never_actionable",
    )?;

    let malformed = by_id
        .get("malformed-bead-fails-closed")
        .ok_or_else(|| "missing malformed bead fixture".to_string())?;
    let malformed_expected = field(malformed, "expected")?;
    require_str_field(
        malformed_expected,
        "actionability_status",
        "unknown_fail_closed",
    )
}

#[test]
fn contract_preserves_existing_authorities_and_declares_redaction_policy() -> TestResult {
    let contract = load_contract()?;
    let graph_must_not = pointer_array(&contract, "/authority_boundaries/graph_must_not")?;
    for required in [
        "Beads",
        "Agent Mail",
        "README evidence",
        "swarm operator runpacks",
    ] {
        require(
            graph_must_not
                .iter()
                .filter_map(Value::as_str)
                .any(|entry| entry.contains(required)),
            format!("authority boundary must mention {required}"),
        )?;
    }

    let relationships = field_array(&contract, "relationship_to_existing_systems")?;
    let mut systems = HashSet::new();
    for entry in relationships {
        require_bool_field(entry, "not_replaced", true)?;
        systems.insert(field_str(entry, "system_id")?);
    }
    for required in [
        "tool_output_context_cache",
        "session_index_cache",
        "swarm_operator_runpack",
        "readme_evidence_freshness_gate",
        "beads",
        "agent_mail",
    ] {
        require(
            systems.contains(required),
            format!("missing relationship for {required}"),
        )?;
    }

    let overlap_boundaries = field_array(&contract, "overlap_boundaries")?;
    let mut overlap_beads = HashSet::new();
    for boundary in overlap_boundaries {
        overlap_beads.insert(field_str(boundary, "existing_bead_id")?);
        require(
            !field_str(boundary, "boundary")?.is_empty(),
            "overlap boundary text must be non-empty",
        )?;
    }
    for required in ["bd-h3uv0", "bd-07cku", "bd-dklqn"] {
        require(
            overlap_beads.contains(required),
            format!("missing overlap boundary for {required}"),
        )?;
    }

    let redaction = field(&contract, "redaction_policy")?;
    require_bool_field(redaction, "redaction_summary_required", true)?;
    require_bool_field(
        redaction,
        "raw_bytes_emitted_must_be_zero_for_secret_classes",
        true,
    )?;
    let forbidden = field_array(redaction, "forbidden_raw_fields")?;
    let forbidden_set: HashSet<&str> = forbidden.iter().filter_map(Value::as_str).collect();
    for required in [
        "authorization",
        "prompt",
        "registration_token",
        "secret",
        "token",
    ] {
        require(
            forbidden_set.contains(required),
            format!("redaction policy missing forbidden field {required}"),
        )?;
    }
    Ok(())
}
