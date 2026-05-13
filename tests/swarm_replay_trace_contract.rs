#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/swarm-replay-trace-contract.json";
const EXPECTED_CONTRACT_SCHEMA: &str = "pi.swarm.replay_trace_contract.v1";
const EXPECTED_TRACE_SCHEMA: &str = "pi.swarm.replay_trace.v1";
const EXPECTED_BEAD_ID: &str = "bd-in57w.1";
const EXPECTED_PARENT_BEAD_ID: &str = "bd-in57w";
const AGENT_MAIL_UNAVAILABLE_FIXTURE: &str =
    "tests/fixtures/swarm_replay_trace/agent_mail_unavailable_trace.json";
const SOURCE_INVENTORY_SCENARIO_FIXTURE: &str =
    "tests/fixtures/swarm_replay_trace/source_inventory_scenarios.json";

const REQUIRED_SOURCE_IDS: &[&str] = &[
    "beads_jsonl",
    "beads_db",
    "agent_mail_archive",
    "doctor_swarm_diagnostics",
    "rch_queue_status",
    "operator_runpack",
    "git_refs",
    "validation_command_records",
    "context_intelligence_evidence",
    "swarm_flight_recorder",
    "swarm_activity_ledger",
];

const REQUIRED_EVENT_TYPES: &[&str] = &[
    "bead_lifecycle",
    "reservation_intent",
    "reservation_conflict",
    "agent_message",
    "build_slot_state",
    "rch_job_state",
    "cargo_gate_result",
    "worktree_state",
    "doctor_finding",
    "runpack_recommendation",
    "validation_artifact",
    "operator_handoff",
];

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

fn pointer_u64(value: &Value, path: &str) -> Result<u64, String> {
    pointer(value, path)?
        .as_u64()
        .ok_or_else(|| format!("{path} must be an unsigned integer"))
}

fn pointer_array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], String> {
    pointer(value, path)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{path} must be an array"))
}

fn pointer_array_mut<'a>(value: &'a mut Value, path: &str) -> Result<&'a mut Vec<Value>, String> {
    value
        .pointer_mut(path)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("{path} must be a mutable array"))
}

fn string_set(value: &Value, path: &str) -> Result<HashSet<String>, String> {
    let mut entries = HashSet::new();
    for entry in pointer_array(value, path)? {
        let raw = entry
            .as_str()
            .ok_or_else(|| format!("{path} entries must be strings"))?;
        require(
            !raw.trim().is_empty(),
            format!("{path} entry must be non-empty"),
        )?;
        entries.insert(raw.to_string());
    }
    Ok(entries)
}

fn required_set(contract: &Value, path: &str, expected: &[&str], label: &str) -> TestResult {
    let observed = string_set(contract, path)?;
    for required in expected {
        if !observed.contains(*required) {
            return Err(format!("missing {label}: {required}"));
        }
    }
    Ok(())
}

fn non_empty_array(value: &Value, path: &str, label: &str) -> TestResult {
    require(
        !pointer_array(value, path)?.is_empty(),
        format!("{label} is empty"),
    )
}

fn is_utc_rfc3339_z(value: &str) -> bool {
    value.len() >= 20 && value.contains('T') && value.ends_with('Z')
}

fn validate_contract_identity(contract: &Value) -> TestResult {
    require(
        pointer_str(contract, "/schema")? == EXPECTED_CONTRACT_SCHEMA,
        "contract schema mismatch",
    )?;
    require(
        pointer_str(contract, "/trace_schema")? == EXPECTED_TRACE_SCHEMA,
        "trace schema mismatch",
    )?;
    require(
        pointer_str(contract, "/bead_id")? == EXPECTED_BEAD_ID,
        "bead linkage mismatch",
    )?;
    require(
        pointer_str(contract, "/parent_bead_id")? == EXPECTED_PARENT_BEAD_ID,
        "parent bead linkage mismatch",
    )?;
    require(
        pointer_str(contract, "/purpose")?
            == "offline_swarm_replay_trace_contract_not_live_control",
        "purpose must keep the trace out of live-control authority",
    )
}

fn validate_source_inventory_contract(contract: &Value) -> TestResult {
    required_set(
        contract,
        "/required_trace_top_level_keys",
        &[
            "schema",
            "trace_id",
            "generated_at",
            "contract_version",
            "source_inventory",
            "ordering",
            "events",
            "redaction_summary",
            "uncertainty_summary",
            "replay_guards",
        ],
        "trace top-level key",
    )?;
    required_set(
        contract,
        "/source_inventory_contract/required_source_ids",
        REQUIRED_SOURCE_IDS,
        "source id",
    )?;
    required_set(
        contract,
        "/source_inventory_contract/required_source_fields",
        &[
            "source_id",
            "source_kind",
            "path",
            "availability",
            "freshness_state",
            "source_hash",
            "redaction_state",
            "authoritative_for",
            "uncertainty",
        ],
        "source field",
    )?;
    required_set(
        contract,
        "/source_inventory_contract/allowed_availability",
        &["available", "unavailable", "partial", "malformed", "stale"],
        "availability state",
    )?;
    require(
        pointer_str(
            contract,
            "/source_inventory_contract/unavailable_source_policy",
        )?
        .contains("silently inferred"),
        "unavailable source policy must forbid inferred timeline facts",
    )
}

fn validate_event_contract(contract: &Value) -> TestResult {
    required_set(
        contract,
        "/event_contract/required_event_types",
        REQUIRED_EVENT_TYPES,
        "event type",
    )?;
    required_set(
        contract,
        "/event_contract/required_event_fields",
        &[
            "event_id",
            "sequence",
            "occurred_at_utc",
            "observed_at_utc",
            "event_type",
            "actor",
            "source_ref",
            "source_hash",
            "redaction_state",
            "uncertainty",
            "payload",
        ],
        "event field",
    )?;
    required_set(
        contract,
        "/event_contract/required_uncertainty_fields",
        &["state", "reasons", "suppressed_claims"],
        "uncertainty field",
    )?;

    let mut contracts = HashSet::new();
    for row in pointer_array(contract, "/event_contract/event_type_contracts")? {
        let event_type = pointer_str(row, "/event_type")?;
        contracts.insert(event_type.to_string());
        non_empty_array(row, "/authoritative_sources", event_type)?;
        non_empty_array(row, "/required_payload_fields", event_type)?;
    }
    for event_type in REQUIRED_EVENT_TYPES {
        if !contracts.contains(*event_type) {
            return Err(format!("missing event_type_contract for {event_type}"));
        }
    }
    Ok(())
}

fn validate_fail_closed_policies(contract: &Value) -> TestResult {
    require(
        pointer_bool(contract, "/ordering_contract/monotonic_sequence_required")?,
        "ordering must require monotonic sequence",
    )?;
    require(
        pointer_str(contract, "/ordering_contract/timestamp_normalization")? == "utc_rfc3339_z",
        "timestamps must normalize to UTC RFC3339 Z",
    )?;
    require(
        pointer_bool(contract, "/redaction_policy/fail_closed")?,
        "redaction policy must fail closed",
    )?;
    require(
        pointer_bool(contract, "/uncertainty_policy/fail_closed")?,
        "uncertainty policy must fail closed",
    )?;
    required_set(
        contract,
        "/redaction_policy/allowed_redaction_states",
        &["none", "redacted", "sensitive_omitted", "unsafe_to_emit"],
        "redaction state",
    )?;
    required_set(
        contract,
        "/uncertainty_policy/allowed_uncertainty_states",
        &[
            "certain",
            "inferred",
            "partial",
            "missing_source",
            "malformed_source",
            "uncertain",
        ],
        "uncertainty state",
    )?;
    require(
        pointer_bool(contract, "/replay_guards/read_only")?,
        "replay guard must be read-only",
    )?;
    require(
        pointer_bool(contract, "/replay_guards/no_live_mutation")?,
        "replay guard must forbid live mutation",
    )?;
    required_set(
        contract,
        "/replay_guards/disallowed_live_actions",
        &[
            "claim_bead",
            "close_bead",
            "send_agent_mail",
            "reserve_file",
            "release_file",
            "acquire_build_slot",
            "cancel_rch_job",
            "git_commit",
            "git_push",
        ],
        "disallowed live action",
    )
}

fn validate_contract_fixtures(contract: &Value) -> TestResult {
    let fixtures = pointer_array(contract, "/contract_test_fixtures")?;
    for (fixture_id, expected_path) in [
        (
            "agent_mail_unavailable_beads_rch_doctor_usable",
            AGENT_MAIL_UNAVAILABLE_FIXTURE,
        ),
        (
            "source_inventory_scenario_suite",
            SOURCE_INVENTORY_SCENARIO_FIXTURE,
        ),
    ] {
        let fixture = fixtures
            .iter()
            .find(|row| row.pointer("/fixture_id").and_then(Value::as_str) == Some(fixture_id))
            .ok_or_else(|| format!("missing contract fixture {fixture_id}"))?;
        require(
            pointer_str(fixture, "/path")? == expected_path,
            format!("{fixture_id} fixture path mismatch"),
        )?;
        non_empty_array(fixture, "/must_prove", fixture_id)?;
    }
    Ok(())
}

fn scenario_row<'a>(suite: &'a Value, scenario_id: &str) -> Result<&'a Value, String> {
    pointer_array(suite, "/scenarios")?
        .iter()
        .find(|row| row.pointer("/scenario_id").and_then(Value::as_str) == Some(scenario_id))
        .ok_or_else(|| format!("missing source inventory scenario {scenario_id}"))
}

fn validate_downstream_dependencies(contract: &Value) -> TestResult {
    required_set(
        contract,
        "/downstream_dependencies/unblocked_beads",
        &["bd-in57w.2", "bd-in57w.3", "bd-in57w.12"],
        "downstream bead",
    )
}

fn validate_contract(contract: &Value) -> TestResult {
    validate_contract_identity(contract)?;
    validate_source_inventory_contract(contract)?;
    validate_event_contract(contract)?;
    validate_fail_closed_policies(contract)?;
    validate_contract_fixtures(contract)?;
    validate_downstream_dependencies(contract)
}

fn inventory_source_ids(trace: &Value) -> Result<HashSet<String>, String> {
    let mut ids = HashSet::new();
    for source in pointer_array(trace, "/source_inventory")? {
        let source_id = pointer_str(source, "/source_id")?;
        require(
            ids.insert(source_id.to_string()),
            format!("duplicate source_id {source_id}"),
        )?;
    }
    Ok(ids)
}

fn validate_trace_source_inventory(trace: &Value) -> TestResult {
    for key in [
        "/schema",
        "/trace_id",
        "/generated_at",
        "/contract_version",
        "/source_inventory",
        "/ordering",
        "/events",
        "/redaction_summary",
        "/uncertainty_summary",
        "/replay_guards",
    ] {
        let _value = pointer(trace, key)?;
    }

    let ids = inventory_source_ids(trace)?;
    for source_id in REQUIRED_SOURCE_IDS {
        if !ids.contains(*source_id) {
            return Err(format!("trace missing source inventory entry {source_id}"));
        }
    }

    let agent_mail = pointer_array(trace, "/source_inventory")?
        .iter()
        .find(|source| {
            source.pointer("/source_id").and_then(Value::as_str) == Some("agent_mail_archive")
        })
        .ok_or_else(|| "missing agent_mail_archive source".to_string())?;
    require(
        pointer_str(agent_mail, "/availability")? == "unavailable",
        "Agent Mail fixture must mark archive unavailable",
    )?;
    require(
        pointer_str(agent_mail, "/freshness_state")? == "missing",
        "Agent Mail fixture must mark archive missing",
    )?;
    non_empty_array(agent_mail, "/uncertainty", "agent_mail_archive uncertainty")?;

    for source_id in [
        "beads_jsonl",
        "rch_queue_status",
        "doctor_swarm_diagnostics",
    ] {
        let source = pointer_array(trace, "/source_inventory")?
            .iter()
            .find(|row| row.pointer("/source_id").and_then(Value::as_str) == Some(source_id))
            .ok_or_else(|| format!("missing {source_id} source"))?;
        require(
            pointer_str(source, "/availability")? == "available",
            format!("{source_id} must stay usable when Agent Mail is unavailable"),
        )?;
    }
    Ok(())
}

fn validate_trace_events(trace: &Value) -> TestResult {
    let source_ids = inventory_source_ids(trace)?;
    let event_types: HashSet<String> = REQUIRED_EVENT_TYPES
        .iter()
        .map(|v| (*v).to_string())
        .collect();
    let redaction_states: HashSet<String> =
        ["none", "redacted", "sensitive_omitted", "unsafe_to_emit"]
            .into_iter()
            .map(str::to_string)
            .collect();

    let mut last_sequence = 0;
    for event in pointer_array(trace, "/events")? {
        let sequence = pointer_u64(event, "/sequence")?;
        require(
            sequence > last_sequence,
            format!("event sequence {sequence} must be monotonic"),
        )?;
        last_sequence = sequence;

        let event_type = pointer_str(event, "/event_type")?;
        require(
            event_types.contains(event_type),
            format!("unknown event_type {event_type}"),
        )?;
        let source_ref = pointer_str(event, "/source_ref")?;
        require(
            source_ids.contains(source_ref),
            format!("event references unknown source {source_ref}"),
        )?;
        for path in ["/occurred_at_utc", "/observed_at_utc"] {
            let timestamp = pointer_str(event, path)?;
            require(
                is_utc_rfc3339_z(timestamp),
                format!("{path} must be UTC RFC3339 Z, got {timestamp}"),
            )?;
        }
        let redaction_state = pointer_str(event, "/redaction_state")?;
        require(
            redaction_states.contains(redaction_state),
            format!("invalid redaction_state {redaction_state}"),
        )?;
        for uncertainty_field in ["state", "reasons", "suppressed_claims"] {
            let path = format!("/uncertainty/{uncertainty_field}");
            let _field = pointer(event, &path)?;
        }
        let _payload = pointer(event, "/payload")?;
    }

    let agent_message = pointer_array(trace, "/events")?
        .iter()
        .find(|event| event.pointer("/event_type").and_then(Value::as_str) == Some("agent_message"))
        .ok_or_else(|| {
            "fixture must include Agent Mail unavailable agent_message event".to_string()
        })?;
    require(
        pointer_str(agent_message, "/uncertainty/state")? == "missing_source",
        "Agent Mail event must record missing_source uncertainty",
    )?;
    required_set(
        agent_message,
        "/uncertainty/suppressed_claims",
        &[
            "ack_latency",
            "active_reservation_holder",
            "mail_thread_completeness",
        ],
        "suppressed Agent Mail claim",
    )
}

fn validate_agent_mail_unavailable_fixture(trace: &Value) -> TestResult {
    require(
        pointer_str(trace, "/schema")? == EXPECTED_TRACE_SCHEMA,
        "fixture trace schema mismatch",
    )?;
    require(
        pointer_bool(trace, "/replay_guards/read_only")?,
        "fixture replay guard must be read-only",
    )?;
    require(
        pointer_bool(trace, "/replay_guards/no_live_mutation")?,
        "fixture replay guard must forbid live mutation",
    )?;
    validate_trace_source_inventory(trace)?;
    validate_trace_events(trace)
}

fn validate_source_inventory_scenario_suite(suite: &Value) -> TestResult {
    require(
        pointer_str(suite, "/schema")? == "pi.swarm.replay_trace.fixture_suite.v1",
        "source inventory fixture suite schema mismatch",
    )?;
    require(
        pointer_str(suite, "/contract_schema")? == EXPECTED_CONTRACT_SCHEMA,
        "source inventory fixture contract_schema mismatch",
    )?;
    require(
        pointer_str(suite, "/trace_schema")? == EXPECTED_TRACE_SCHEMA,
        "source inventory fixture trace_schema mismatch",
    )?;

    let mail_scenario = scenario_row(
        suite,
        "agent-mail-unavailable-keeps-beads-rch-doctor-usable",
    )?;
    let mail_sources = pointer_array(mail_scenario, "/source_statuses")?;
    for (source_id, status) in [
        ("agent_mail_archive", "unavailable"),
        ("beads_jsonl", "usable"),
        ("rch_queue_status", "usable"),
        ("doctor_swarm_diagnostics", "usable"),
    ] {
        let row = mail_sources
            .iter()
            .find(|source| source.pointer("/source_id").and_then(Value::as_str) == Some(source_id))
            .ok_or_else(|| format!("mail scenario missing {source_id}"))?;
        require(
            pointer_str(row, "/status")? == status,
            format!("mail scenario {source_id} status mismatch"),
        )?;
    }
    require(
        !pointer_bool(mail_scenario, "/expected/silently_dropped_events_allowed")?,
        "Agent Mail unavailable scenario must forbid silent drops",
    )?;

    let malformed_scenario = scenario_row(suite, "malformed-rch-snapshot-fails-closed")?;
    let rch_source = pointer_array(malformed_scenario, "/source_statuses")?
        .iter()
        .find(|source| {
            source.pointer("/source_id").and_then(Value::as_str) == Some("rch_queue_status")
        })
        .ok_or_else(|| "malformed scenario missing rch_queue_status".to_string())?;
    require(
        pointer_str(rch_source, "/status")? == "malformed",
        "malformed RCH scenario must mark source malformed",
    )?;
    required_set(
        malformed_scenario,
        "/expected/suppressed_claims",
        &["queue_depth", "worker_availability", "cargo_admission"],
        "malformed RCH suppressed claim",
    )?;
    let emitted_raw_bytes = pointer_u64(
        malformed_scenario,
        "/trace/redaction_summary/raw_secret_bytes_emitted",
    )?;
    require(
        matches!(emitted_raw_bytes, 0),
        "malformed RCH fixture must not emit raw secret bytes",
    )
}

fn remove_string_entry(value: &mut Value, path: &str, removed: &str) -> Result<bool, String> {
    let entries = pointer_array_mut(value, path)?;
    let before = entries.len();
    entries.retain(|entry| entry.as_str().map(str::trim) != Some(removed));
    Ok(entries.len() != before)
}

fn remove_event_contract(value: &mut Value, event_type: &str) -> Result<bool, String> {
    let entries = pointer_array_mut(value, "/event_contract/event_type_contracts")?;
    let before = entries.len();
    entries
        .retain(|entry| entry.pointer("/event_type").and_then(Value::as_str) != Some(event_type));
    Ok(entries.len() != before)
}

fn set_bool(value: &mut Value, path: &str, enabled: bool) -> TestResult {
    let field = value
        .pointer_mut(path)
        .ok_or_else(|| format!("missing mutable JSON pointer {path}"))?;
    *field = Value::Bool(enabled);
    Ok(())
}

fn require_validation_error(result: TestResult, expected_text: &str) -> TestResult {
    match result {
        Ok(()) => Err(format!("validation should fail with {expected_text}")),
        Err(err) => require(
            err.contains(expected_text),
            format!("expected error to contain {expected_text}, got {err}"),
        ),
    }
}

#[test]
fn swarm_replay_trace_contract_exists_and_is_valid_json() -> TestResult {
    let path = repo_root().join(CONTRACT_PATH);
    require(
        path.is_file(),
        format!("missing swarm replay trace contract: {}", path.display()),
    )?;
    let _contract = load_json(CONTRACT_PATH)?;
    Ok(())
}

#[test]
fn swarm_replay_trace_contract_is_complete() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    validate_contract(&contract)
}

#[test]
fn agent_mail_unavailable_fixture_remains_replayable_from_other_sources() -> TestResult {
    let fixture = load_json(AGENT_MAIL_UNAVAILABLE_FIXTURE)?;
    validate_agent_mail_unavailable_fixture(&fixture)
}

#[test]
fn source_inventory_scenario_suite_covers_unavailable_and_malformed_inputs() -> TestResult {
    let suite = load_json(SOURCE_INVENTORY_SCENARIO_FIXTURE)?;
    validate_source_inventory_scenario_suite(&suite)
}

#[test]
fn contract_fails_closed_when_required_source_is_missing() -> TestResult {
    let mut contract = load_json(CONTRACT_PATH)?;
    require(
        remove_string_entry(
            &mut contract,
            "/source_inventory_contract/required_source_ids",
            "agent_mail_archive",
        )?,
        "mutation should remove agent_mail_archive source",
    )?;

    require_validation_error(
        validate_source_inventory_contract(&contract),
        "agent_mail_archive",
    )
}

#[test]
fn contract_fails_closed_when_required_event_type_is_missing() -> TestResult {
    let mut contract = load_json(CONTRACT_PATH)?;
    require(
        remove_string_entry(
            &mut contract,
            "/event_contract/required_event_types",
            "build_slot_state",
        )?,
        "mutation should remove build_slot_state event type",
    )?;

    require_validation_error(validate_event_contract(&contract), "build_slot_state")
}

#[test]
fn contract_fails_closed_when_event_contract_is_missing() -> TestResult {
    let mut contract = load_json(CONTRACT_PATH)?;
    require(
        remove_event_contract(&mut contract, "reservation_conflict")?,
        "mutation should remove reservation_conflict event contract",
    )?;

    require_validation_error(validate_event_contract(&contract), "reservation_conflict")
}

#[test]
fn contract_fails_closed_when_replay_guard_allows_live_mutation() -> TestResult {
    let mut contract = load_json(CONTRACT_PATH)?;
    set_bool(&mut contract, "/replay_guards/no_live_mutation", false)?;

    require_validation_error(validate_fail_closed_policies(&contract), "live mutation")
}
