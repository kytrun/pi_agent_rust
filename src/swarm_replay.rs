//! Read-only ingestor for offline swarm replay traces.
//!
//! The ingestor consumes already-captured repository artifacts and normalizes
//! them into `pi.swarm.replay_trace.v1`. It never claims beads, sends mail,
//! reserves files, starts builds, or performs network I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};

/// Schema emitted by normalized replay traces.
pub const SWARM_REPLAY_TRACE_SCHEMA: &str = "pi.swarm.replay_trace.v1";

/// Contract version implemented by this ingestor.
pub const SWARM_REPLAY_TRACE_CONTRACT_VERSION: &str = "1.0.0";

const SENSITIVE_REDACTION: &str = "[REDACTED]";
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "authorization",
    "body",
    "cookie",
    "key",
    "password",
    "prompt",
    "registration_token",
    "secret",
    "token",
    "transcript",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceInputFormat {
    Json,
    JsonLines,
    Opaque,
}

#[derive(Debug, Clone, Copy)]
struct SourceTemplate {
    source_id: &'static str,
    source_kind: &'static str,
    default_path: &'static str,
    authoritative_for: &'static [&'static str],
    format: SourceInputFormat,
    default_redaction_state: &'static str,
}

const SOURCE_TEMPLATES: &[SourceTemplate] = &[
    SourceTemplate {
        source_id: "beads_jsonl",
        source_kind: "beads",
        default_path: ".beads/issues.jsonl",
        authoritative_for: &["bead_lifecycle"],
        format: SourceInputFormat::JsonLines,
        default_redaction_state: "none",
    },
    SourceTemplate {
        source_id: "beads_db",
        source_kind: "beads",
        default_path: ".beads/beads.db",
        authoritative_for: &["bead_lifecycle"],
        format: SourceInputFormat::Opaque,
        default_redaction_state: "none",
    },
    SourceTemplate {
        source_id: "agent_mail_archive",
        source_kind: "agent_mail",
        default_path: "/home/ubuntu/.mcp_agent_mail_git_mailbox_repo/storage.sqlite3",
        authoritative_for: &[
            "reservation_intent",
            "reservation_conflict",
            "agent_message",
            "build_slot_state",
        ],
        format: SourceInputFormat::Json,
        default_redaction_state: "sensitive_omitted",
    },
    SourceTemplate {
        source_id: "doctor_swarm_diagnostics",
        source_kind: "doctor",
        default_path: "docs/evidence/doctor-swarm.json",
        authoritative_for: &["doctor_finding"],
        format: SourceInputFormat::Json,
        default_redaction_state: "redacted",
    },
    SourceTemplate {
        source_id: "rch_queue_status",
        source_kind: "rch",
        default_path: "docs/evidence/rch-queue-status.json",
        authoritative_for: &["rch_job_state"],
        format: SourceInputFormat::Json,
        default_redaction_state: "none",
    },
    SourceTemplate {
        source_id: "operator_runpack",
        source_kind: "runpack",
        default_path: "docs/evidence/swarm-operator-runpack.json",
        authoritative_for: &["runpack_recommendation", "operator_handoff"],
        format: SourceInputFormat::Json,
        default_redaction_state: "redacted",
    },
    SourceTemplate {
        source_id: "git_refs",
        source_kind: "git",
        default_path: ".git",
        authoritative_for: &["worktree_state"],
        format: SourceInputFormat::Json,
        default_redaction_state: "none",
    },
    SourceTemplate {
        source_id: "validation_command_records",
        source_kind: "validation",
        default_path: "tests/e2e_results",
        authoritative_for: &["cargo_gate_result", "validation_artifact"],
        format: SourceInputFormat::Json,
        default_redaction_state: "none",
    },
    SourceTemplate {
        source_id: "context_intelligence_evidence",
        source_kind: "context_intelligence",
        default_path: "docs/evidence/context-intelligence-closeout-gate.json",
        authoritative_for: &["validation_artifact"],
        format: SourceInputFormat::Json,
        default_redaction_state: "redacted",
    },
    SourceTemplate {
        source_id: "swarm_flight_recorder",
        source_kind: "flight_recorder",
        default_path: "tests/full_suite_gate/swarm_flight_recorder.jsonl",
        authoritative_for: &["validation_artifact"],
        format: SourceInputFormat::JsonLines,
        default_redaction_state: "redacted",
    },
    SourceTemplate {
        source_id: "swarm_activity_ledger",
        source_kind: "activity_ledger",
        default_path: "tests/full_suite_gate/swarm_activity_ledger.jsonl",
        authoritative_for: &["operator_handoff", "validation_artifact"],
        format: SourceInputFormat::JsonLines,
        default_redaction_state: "redacted",
    },
];

/// Request used to build a replay trace from existing artifacts.
#[derive(Debug, Clone)]
pub struct SwarmReplayIngestRequest {
    /// Stable trace identifier.
    pub trace_id: String,
    /// Fixed generation timestamp in UTC RFC3339 `Z` format.
    pub generated_at_utc: String,
    /// Workspace root used for relative source paths.
    pub workspace_root: PathBuf,
    /// Optional git commit recorded in worktree and provenance payloads.
    pub git_commit: Option<String>,
    /// Optional git branch recorded in worktree payloads.
    pub git_branch: Option<String>,
    /// Per-source path overrides. Relative paths are resolved under `workspace_root`.
    pub source_overrides: BTreeMap<String, PathBuf>,
}

impl SwarmReplayIngestRequest {
    /// Create a new replay ingest request.
    pub fn new(
        trace_id: impl Into<String>,
        generated_at_utc: impl Into<String>,
        workspace_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            generated_at_utc: generated_at_utc.into(),
            workspace_root: workspace_root.into(),
            git_commit: None,
            git_branch: None,
            source_overrides: BTreeMap::new(),
        }
    }

    /// Attach immutable git identity metadata for the trace.
    #[must_use]
    pub fn with_git_identity(
        mut self,
        git_commit: impl Into<String>,
        git_branch: impl Into<String>,
    ) -> Self {
        self.git_commit = Some(git_commit.into());
        self.git_branch = Some(git_branch.into());
        self
    }

    /// Override one source path.
    #[must_use]
    pub fn with_source_override(
        mut self,
        source_id: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> Self {
        self.source_overrides.insert(source_id.into(), path.into());
        self
    }
}

/// One row in the trace source inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplaySourceInventoryRow {
    pub source_id: String,
    pub source_kind: String,
    pub path: String,
    pub availability: String,
    pub freshness_state: String,
    pub source_hash: Option<String>,
    pub redaction_state: String,
    pub authoritative_for: Vec<String>,
    pub uncertainty: Vec<String>,
}

/// Uncertainty attached to one normalized event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayEventUncertainty {
    pub state: String,
    pub reasons: Vec<String>,
    pub suppressed_claims: Vec<String>,
}

/// One normalized replay event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayEvent {
    pub event_id: String,
    pub sequence: u64,
    pub occurred_at_utc: String,
    pub observed_at_utc: String,
    pub event_type: String,
    pub actor: String,
    pub source_ref: String,
    pub source_hash: Option<String>,
    pub redaction_state: String,
    pub uncertainty: SwarmReplayEventUncertainty,
    pub payload: Value,
}

/// Ordering policy recorded in every trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayOrdering {
    pub monotonic_sequence_required: bool,
    pub timestamp_normalization: String,
    pub tie_breakers: Vec<String>,
}

/// Redaction accounting for the trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayRedactionSummary {
    pub redacted_count: u64,
    pub sensitive_omitted_count: u64,
    pub raw_secret_bytes_emitted: u64,
    pub redacted_fields: Vec<String>,
}

/// Uncertainty accounting for the trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayUncertaintySummary {
    pub missing_sources: Vec<String>,
    pub malformed_sources: Vec<String>,
    pub stale_sources: Vec<String>,
    pub suppressed_claims: Vec<String>,
    pub event_count_by_uncertainty: BTreeMap<String, u64>,
}

/// Guards proving the trace is offline evidence, not live control.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayGuards {
    pub read_only: bool,
    pub no_live_mutation: bool,
    pub no_network_required: bool,
    pub fail_closed_on_missing_required_sources: bool,
    pub requires_source_inventory: bool,
    pub disallowed_live_actions: Vec<String>,
}

/// Normalized offline replay trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayTrace {
    pub schema: String,
    pub trace_id: String,
    pub generated_at: String,
    pub contract_version: String,
    pub source_inventory: Vec<SwarmReplaySourceInventoryRow>,
    pub ordering: SwarmReplayOrdering,
    pub events: Vec<SwarmReplayEvent>,
    pub redaction_summary: SwarmReplayRedactionSummary,
    pub uncertainty_summary: SwarmReplayUncertaintySummary,
    pub replay_guards: SwarmReplayGuards,
}

/// Schema emitted by the deterministic replay engine.
pub const SWARM_REPLAY_REPORT_SCHEMA: &str = "pi.swarm.replay_report.v1";

/// Deterministic report emitted after replaying a normalized trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayReport {
    pub schema: String,
    pub trace_id: String,
    pub replayed_event_count: u64,
    pub final_logical_clock: u64,
    pub snapshots: Vec<SwarmReplayStateSnapshot>,
    pub final_state: SwarmReplayState,
    pub diagnostics: Vec<SwarmReplayDiagnostic>,
    pub replay_guards: SwarmReplayEngineGuards,
}

/// Replay-engine guards proving the engine stayed offline and read-only.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayEngineGuards {
    pub read_only: bool,
    pub no_live_mutation: bool,
    pub no_network_required: bool,
    pub consumed_trace_only: bool,
}

/// Full swarm state after one replayed event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayStateSnapshot {
    pub logical_clock: u64,
    pub event_id: String,
    pub occurred_at_utc: String,
    pub state: SwarmReplayState,
    pub diagnostic_count: u64,
}

/// Diagnostic emitted for invariant violations or uncertain replay evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayDiagnostic {
    pub code: String,
    pub severity: String,
    pub event_id: Option<String>,
    pub logical_clock: Option<u64>,
    pub message: String,
    pub details: Value,
}

/// Reconstructed swarm state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayState {
    pub beads: BTreeMap<String, SwarmReplayBeadState>,
    pub agents: BTreeMap<String, SwarmReplayAgentState>,
    pub reservations: BTreeMap<String, SwarmReplayReservationState>,
    pub build_slots: BTreeMap<String, SwarmReplayBuildSlotState>,
    pub rch_jobs: BTreeMap<String, SwarmReplayRchJobState>,
    pub validation_gates: BTreeMap<String, SwarmReplayValidationGateState>,
    pub runpack_recommendations: BTreeMap<String, SwarmReplayRunpackRecommendationState>,
    pub operator_handoffs: BTreeMap<String, SwarmReplayOperatorHandoffState>,
    pub coordination: SwarmReplayCoordinationState,
}

impl Default for SwarmReplayState {
    fn default() -> Self {
        Self {
            beads: BTreeMap::new(),
            agents: BTreeMap::new(),
            reservations: BTreeMap::new(),
            build_slots: BTreeMap::new(),
            rch_jobs: BTreeMap::new(),
            validation_gates: BTreeMap::new(),
            runpack_recommendations: BTreeMap::new(),
            operator_handoffs: BTreeMap::new(),
            coordination: SwarmReplayCoordinationState {
                agent_mail_available: true,
                missing_agent_mail_evidence: false,
                reservation_conflict_count: 0,
                last_operator_action: None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayBeadState {
    pub bead_id: String,
    pub status: String,
    pub priority: i64,
    pub assignee: String,
    pub last_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayAgentState {
    pub agent_name: String,
    pub last_event_id: String,
    pub last_seen_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayReservationState {
    pub reservation_id: String,
    pub holder: String,
    pub path_patterns: Vec<String>,
    pub exclusive: bool,
    pub state: String,
    pub active: bool,
    pub last_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayBuildSlotState {
    pub slot: String,
    pub holder: String,
    pub state: String,
    pub expires_at_utc: String,
    pub last_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayRchJobState {
    pub job_id: String,
    pub state: String,
    pub worker: String,
    pub command: String,
    pub queue_position: i64,
    pub stale_progress: bool,
    pub last_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayValidationGateState {
    pub gate_id: String,
    pub command: String,
    pub runner: String,
    pub exit_code: i64,
    pub target_dir: String,
    pub tmpdir: String,
    pub last_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayRunpackRecommendationState {
    pub action: String,
    pub severity: String,
    pub evidence_paths: Vec<String>,
    pub last_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayOperatorHandoffState {
    pub handoff_id: String,
    pub summary: String,
    pub next_actions: Vec<String>,
    pub evidence_paths: Vec<String>,
    pub last_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayCoordinationState {
    pub agent_mail_available: bool,
    pub missing_agent_mail_evidence: bool,
    pub reservation_conflict_count: u64,
    pub last_operator_action: Option<String>,
}

/// Replay a normalized trace into deterministic state snapshots and diagnostics.
pub fn replay_swarm_trace(trace: &SwarmReplayTrace) -> Result<SwarmReplayReport> {
    validate_trace_for_replay(trace)?;

    let mut state = SwarmReplayState::default();
    let mut diagnostics = Vec::new();
    let mut snapshots = Vec::new();
    let mut seen_event_ids = BTreeSet::new();
    let mut last_timestamp: Option<String> = None;
    let mut logical_clock = 0_u64;

    for event in ordered_trace_events(trace) {
        if !seen_event_ids.insert(event.event_id.clone()) {
            diagnostics.push(replay_diagnostic(
                "duplicate_event_id_skipped",
                "warning",
                Some(event),
                Some(logical_clock),
                "duplicate replay event id skipped to preserve deterministic state",
                json!({ "event_id": event.event_id }),
            ));
            continue;
        }

        logical_clock = logical_clock.saturating_add(1);
        if let Some(previous) = &last_timestamp
            && timestamp_is_before(&event.occurred_at_utc, previous)
        {
            diagnostics.push(replay_diagnostic(
                "event_timestamp_regressed",
                "warning",
                Some(event),
                Some(logical_clock),
                "event timestamp is earlier than a previously replayed event; logical clock order preserved",
                json!({
                    "previous_occurred_at_utc": previous,
                    "event_occurred_at_utc": event.occurred_at_utc
                }),
            ));
        }
        if last_timestamp
            .as_ref()
            .is_none_or(|previous| timestamp_is_before(previous, &event.occurred_at_utc))
        {
            last_timestamp = Some(event.occurred_at_utc.clone());
        }

        observe_actor(event, &mut state);
        apply_replay_event(event, logical_clock, &mut state, &mut diagnostics);
        snapshots.push(SwarmReplayStateSnapshot {
            logical_clock,
            event_id: event.event_id.clone(),
            occurred_at_utc: event.occurred_at_utc.clone(),
            state: state.clone(),
            diagnostic_count: u64::try_from(diagnostics.len()).unwrap_or(u64::MAX),
        });
    }

    emit_end_of_trace_invariants(&state, &mut diagnostics);

    Ok(SwarmReplayReport {
        schema: SWARM_REPLAY_REPORT_SCHEMA.to_string(),
        trace_id: trace.trace_id.clone(),
        replayed_event_count: logical_clock,
        final_logical_clock: logical_clock,
        snapshots,
        final_state: state,
        diagnostics,
        replay_guards: SwarmReplayEngineGuards {
            read_only: true,
            no_live_mutation: true,
            no_network_required: true,
            consumed_trace_only: true,
        },
    })
}

fn validate_trace_for_replay(trace: &SwarmReplayTrace) -> Result<()> {
    if trace.schema != SWARM_REPLAY_TRACE_SCHEMA {
        return Err(Error::validation(format!(
            "unsupported swarm replay trace schema {}",
            trace.schema
        )));
    }
    if !trace.replay_guards.read_only || !trace.replay_guards.no_live_mutation {
        return Err(Error::validation(
            "swarm replay trace guards must prove read-only no-mutation evidence",
        ));
    }
    Ok(())
}

fn ordered_trace_events(trace: &SwarmReplayTrace) -> Vec<&SwarmReplayEvent> {
    let mut events = trace.events.iter().collect::<Vec<_>>();
    events.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| left.source_ref.cmp(&right.source_ref))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    events
}

fn apply_replay_event(
    event: &SwarmReplayEvent,
    logical_clock: u64,
    state: &mut SwarmReplayState,
    diagnostics: &mut Vec<SwarmReplayDiagnostic>,
) {
    match event.event_type.as_str() {
        "bead_lifecycle" => apply_bead_event(event, logical_clock, state, diagnostics),
        "reservation_intent" => apply_reservation_event(event, logical_clock, state, diagnostics),
        "reservation_conflict" => apply_reservation_conflict(event, state),
        "agent_message" => apply_agent_message_event(event, logical_clock, state, diagnostics),
        "build_slot_state" => apply_build_slot_event(event, state),
        "rch_job_state" => apply_rch_event(event, logical_clock, state, diagnostics),
        "cargo_gate_result" => apply_cargo_gate_event(event, logical_clock, state, diagnostics),
        "runpack_recommendation" => apply_runpack_recommendation(event, state),
        "operator_handoff" => apply_operator_handoff(event, state),
        "worktree_state" | "doctor_finding" | "validation_artifact" => {}
        _ => diagnostics.push(replay_diagnostic(
            "unknown_event_type_ignored",
            "info",
            Some(event),
            Some(logical_clock),
            "unknown replay event type ignored without mutation",
            json!({ "event_type": event.event_type }),
        )),
    }
}

fn observe_actor(event: &SwarmReplayEvent, state: &mut SwarmReplayState) {
    if event.actor.trim().is_empty() || event.actor == "unknown" {
        return;
    }
    state.agents.insert(
        event.actor.clone(),
        SwarmReplayAgentState {
            agent_name: event.actor.clone(),
            last_event_id: event.event_id.clone(),
            last_seen_at_utc: event.occurred_at_utc.clone(),
        },
    );
}

fn apply_bead_event(
    event: &SwarmReplayEvent,
    logical_clock: u64,
    state: &mut SwarmReplayState,
    diagnostics: &mut Vec<SwarmReplayDiagnostic>,
) {
    let bead_id = payload_string(&event.payload, &["bead_id"], "unknown");
    let to_status = payload_string(&event.payload, &["to_status", "status"], "unknown");
    if let Some(existing) = state.beads.get(&bead_id)
        && existing.status == "closed"
        && matches!(to_status.as_str(), "open" | "in_progress")
        && !event_explicitly_reopens(event)
    {
        diagnostics.push(replay_diagnostic(
            "closed_bead_reopened_without_explicit_reopen",
            "error",
            Some(event),
            Some(logical_clock),
            "closed bead transitioned back to open state without explicit reopen evidence",
            json!({
                "bead_id": bead_id,
                "previous_status": existing.status,
                "to_status": to_status
            }),
        ));
    }

    state.beads.insert(
        bead_id.clone(),
        SwarmReplayBeadState {
            bead_id,
            status: to_status,
            priority: payload_i64(&event.payload, "priority", 0),
            assignee: payload_string(&event.payload, &["assignee"], "unassigned"),
            last_event_id: event.event_id.clone(),
        },
    );
}

fn event_explicitly_reopens(event: &SwarmReplayEvent) -> bool {
    event
        .payload
        .get("reopen")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || event
            .payload
            .get("reopened")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || ["action", "reason", "close_reason"]
            .iter()
            .filter_map(|key| event.payload.get(*key).and_then(Value::as_str))
            .any(|value| value.to_ascii_lowercase().contains("reopen"))
}

fn apply_reservation_event(
    event: &SwarmReplayEvent,
    logical_clock: u64,
    state: &mut SwarmReplayState,
    diagnostics: &mut Vec<SwarmReplayDiagnostic>,
) {
    let reservation_id = payload_string(&event.payload, &["reservation_id"], "unknown");
    let reservation_state = payload_string(&event.payload, &["state"], "active");
    let release_state = matches!(
        reservation_state.as_str(),
        "released" | "expired" | "cancelled" | "canceled"
    );
    if release_state && !state.reservations.contains_key(&reservation_id) {
        diagnostics.push(replay_diagnostic(
            "impossible_reservation_release",
            "error",
            Some(event),
            Some(logical_clock),
            "reservation release observed before an active reservation intent",
            json!({
                "reservation_id": reservation_id,
                "state": reservation_state
            }),
        ));
    }

    state.reservations.insert(
        reservation_id.clone(),
        SwarmReplayReservationState {
            reservation_id,
            holder: payload_string(&event.payload, &["holder", "agent"], event.actor.as_str()),
            path_patterns: payload_string_array(&event.payload, "path_patterns"),
            exclusive: event
                .payload
                .get("exclusive")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            active: !release_state,
            state: reservation_state,
            last_event_id: event.event_id.clone(),
        },
    );
}

fn apply_reservation_conflict(event: &SwarmReplayEvent, state: &mut SwarmReplayState) {
    state.coordination.reservation_conflict_count = state
        .coordination
        .reservation_conflict_count
        .saturating_add(1);
    state.coordination.last_operator_action = Some(payload_string(
        &event.payload,
        &["conflict_reason"],
        "reservation_conflict",
    ));
}

fn apply_agent_message_event(
    event: &SwarmReplayEvent,
    logical_clock: u64,
    state: &mut SwarmReplayState,
    diagnostics: &mut Vec<SwarmReplayDiagnostic>,
) {
    let missing_mail = event.source_ref == "agent_mail_archive"
        && (event.uncertainty.state == "missing_source"
            || event
                .uncertainty
                .reasons
                .iter()
                .any(|reason| reason == "source_missing"));
    if missing_mail {
        state.coordination.agent_mail_available = false;
        state.coordination.missing_agent_mail_evidence = true;
        diagnostics.push(replay_diagnostic(
            "agent_mail_source_unavailable",
            "warning",
            Some(event),
            Some(logical_clock),
            "Agent Mail source unavailable; coordination facts remain suppressed",
            json!({ "suppressed_claims": event.uncertainty.suppressed_claims }),
        ));
    }
}

fn apply_build_slot_event(event: &SwarmReplayEvent, state: &mut SwarmReplayState) {
    let slot = payload_string(&event.payload, &["slot"], "unknown");
    state.build_slots.insert(
        slot.clone(),
        SwarmReplayBuildSlotState {
            slot,
            holder: payload_string(&event.payload, &["holder"], "unknown"),
            state: payload_string(&event.payload, &["state"], "unknown"),
            expires_at_utc: payload_string(&event.payload, &["expires_at_utc"], "unknown"),
            last_event_id: event.event_id.clone(),
        },
    );
}

fn apply_rch_event(
    event: &SwarmReplayEvent,
    logical_clock: u64,
    state: &mut SwarmReplayState,
    diagnostics: &mut Vec<SwarmReplayDiagnostic>,
) {
    let job_id = payload_string(&event.payload, &["job_id"], "unknown");
    let queue_position = payload_i64(&event.payload, "queue_position", 0);
    if queue_position < 0 {
        diagnostics.push(replay_diagnostic(
            "negative_rch_queue_position",
            "error",
            Some(event),
            Some(logical_clock),
            "RCH queue position cannot be negative",
            json!({ "job_id": job_id, "queue_position": queue_position }),
        ));
    }
    let stale_progress = event.uncertainty.state != "certain"
        || event
            .uncertainty
            .reasons
            .iter()
            .any(|reason| reason == "source_stale" || reason == "source_declared_stale");
    if stale_progress {
        diagnostics.push(replay_diagnostic(
            "rch_progress_from_uncertain_source",
            "warning",
            Some(event),
            Some(logical_clock),
            "RCH job progress came from stale or uncertain evidence",
            json!({ "job_id": job_id, "uncertainty": event.uncertainty }),
        ));
    }

    state.rch_jobs.insert(
        job_id.clone(),
        SwarmReplayRchJobState {
            job_id,
            state: payload_string(&event.payload, &["state"], "unknown"),
            worker: payload_string(&event.payload, &["worker"], "unknown"),
            command: payload_string(&event.payload, &["command"], "unknown"),
            queue_position,
            stale_progress,
            last_event_id: event.event_id.clone(),
        },
    );
}

fn apply_cargo_gate_event(
    event: &SwarmReplayEvent,
    logical_clock: u64,
    state: &mut SwarmReplayState,
    diagnostics: &mut Vec<SwarmReplayDiagnostic>,
) {
    let command = payload_string(&event.payload, &["command"], "unknown");
    let exit_code = payload_i64(&event.payload, "exit_code", 0);
    if exit_code == 0 && (command.trim().is_empty() || command == "unknown") {
        diagnostics.push(replay_diagnostic(
            "successful_cargo_gate_missing_command_evidence",
            "error",
            Some(event),
            Some(logical_clock),
            "successful cargo gate requires concrete command evidence",
            json!({ "event_id": event.event_id }),
        ));
    }
    let gate_id = stable_id(&format!("cargo-gate-{command}"));
    state.validation_gates.insert(
        gate_id.clone(),
        SwarmReplayValidationGateState {
            gate_id,
            command,
            runner: payload_string(&event.payload, &["runner"], "unknown"),
            exit_code,
            target_dir: payload_string(&event.payload, &["target_dir"], "unknown"),
            tmpdir: payload_string(&event.payload, &["tmpdir"], "unknown"),
            last_event_id: event.event_id.clone(),
        },
    );
}

fn apply_runpack_recommendation(event: &SwarmReplayEvent, state: &mut SwarmReplayState) {
    let action = payload_string(&event.payload, &["action"], "unknown");
    state.coordination.last_operator_action = Some(action.clone());
    state.runpack_recommendations.insert(
        action.clone(),
        SwarmReplayRunpackRecommendationState {
            action,
            severity: payload_string(&event.payload, &["severity"], "info"),
            evidence_paths: payload_string_array(&event.payload, "evidence_paths"),
            last_event_id: event.event_id.clone(),
        },
    );
}

fn apply_operator_handoff(event: &SwarmReplayEvent, state: &mut SwarmReplayState) {
    let handoff_id = payload_string(&event.payload, &["handoff_id"], "unknown");
    state.operator_handoffs.insert(
        handoff_id.clone(),
        SwarmReplayOperatorHandoffState {
            handoff_id,
            summary: payload_string(&event.payload, &["summary"], ""),
            next_actions: payload_string_array(&event.payload, "next_actions"),
            evidence_paths: payload_string_array(&event.payload, "evidence_paths"),
            last_event_id: event.event_id.clone(),
        },
    );
}

fn emit_end_of_trace_invariants(
    state: &SwarmReplayState,
    diagnostics: &mut Vec<SwarmReplayDiagnostic>,
) {
    for reservation in state
        .reservations
        .values()
        .filter(|reservation| reservation.active)
    {
        diagnostics.push(SwarmReplayDiagnostic {
            code: "reservation_missing_release_event".to_string(),
            severity: "warning".to_string(),
            event_id: Some(reservation.last_event_id.clone()),
            logical_clock: None,
            message: "reservation remained active at end of replay without release evidence"
                .to_string(),
            details: json!({
                "reservation_id": reservation.reservation_id,
                "holder": reservation.holder,
                "path_patterns": reservation.path_patterns
            }),
        });
    }
}

fn replay_diagnostic(
    code: &str,
    severity: &str,
    event: Option<&SwarmReplayEvent>,
    logical_clock: Option<u64>,
    message: &str,
    details: Value,
) -> SwarmReplayDiagnostic {
    SwarmReplayDiagnostic {
        code: code.to_string(),
        severity: severity.to_string(),
        event_id: event.map(|item| item.event_id.clone()),
        logical_clock,
        message: message.to_string(),
        details,
    }
}

fn timestamp_is_before(left: &str, right: &str) -> bool {
    match (
        DateTime::parse_from_rfc3339(left),
        DateTime::parse_from_rfc3339(right),
    ) {
        (Ok(left), Ok(right)) => left < right,
        _ => left < right,
    }
}

fn payload_string(value: &Value, keys: &[&str], fallback: &str) -> String {
    optional_string_field(value, keys).unwrap_or_else(|| fallback.to_string())
}

fn payload_string_array(value: &Value, key: &str) -> Vec<String> {
    string_array_field(value, key)
}

fn payload_i64(value: &Value, key: &str, fallback: i64) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(fallback)
}

#[derive(Debug, Clone)]
struct SourceAnalysis {
    row: SwarmReplaySourceInventoryRow,
    parsed: Option<ParsedSource>,
}

#[derive(Debug, Clone)]
enum ParsedSource {
    Json(Value),
    JsonLines(Vec<Value>),
}

#[derive(Debug, Clone)]
struct PendingEvent {
    candidate_id: String,
    occurred_at_utc: String,
    observed_at_utc: String,
    event_type: String,
    actor: String,
    source_ref: String,
    source_hash: Option<String>,
    redaction_state: String,
    uncertainty: SwarmReplayEventUncertainty,
    payload: Value,
}

#[derive(Debug)]
struct PendingEventSeed {
    event_type: &'static str,
    candidate_id: String,
    actor: String,
    occurred_at_utc: String,
    payload: Value,
}

#[derive(Debug, Default)]
struct RedactionAccumulator {
    redacted_count: u64,
    sensitive_omitted_count: u64,
    redacted_fields: BTreeSet<String>,
}

/// Build a normalized replay trace from source artifacts.
#[allow(clippy::too_many_lines)]
pub fn build_swarm_replay_trace(request: &SwarmReplayIngestRequest) -> Result<SwarmReplayTrace> {
    validate_request(request)?;

    let mut source_inventory = Vec::new();
    let mut events = Vec::new();
    let mut redaction = RedactionAccumulator::default();
    let mut missing_sources = BTreeSet::new();
    let mut malformed_sources = BTreeSet::new();
    let mut stale_sources = BTreeSet::new();
    let mut suppressed_claims = BTreeSet::new();

    for template in SOURCE_TEMPLATES {
        let analysis = analyze_source(request, template);
        match analysis.row.availability.as_str() {
            "unavailable" => {
                missing_sources.insert(analysis.row.source_id.clone());
                suppressed_claims.extend(
                    suppressed_claims_for_source(&analysis.row.source_id)
                        .iter()
                        .map(ToString::to_string),
                );
            }
            "malformed" => {
                malformed_sources.insert(analysis.row.source_id.clone());
                suppressed_claims.extend(
                    suppressed_claims_for_source(&analysis.row.source_id)
                        .iter()
                        .map(ToString::to_string),
                );
            }
            "stale" => {
                stale_sources.insert(analysis.row.source_id.clone());
                suppressed_claims.extend(
                    suppressed_claims_for_source(&analysis.row.source_id)
                        .iter()
                        .map(ToString::to_string),
                );
            }
            _ => {}
        }

        if let Some(parsed) = &analysis.parsed {
            events.extend(events_from_source(
                request,
                template,
                &analysis.row,
                parsed,
                &mut redaction,
            ));
        } else if analysis.row.availability == "unavailable" {
            events.extend(missing_source_events(
                template,
                &analysis.row,
                request.generated_at_utc.as_str(),
            ));
        }

        source_inventory.push(analysis.row);
    }

    let events = finalize_events(events);
    let mut event_count_by_uncertainty = BTreeMap::new();
    for event in &events {
        *event_count_by_uncertainty
            .entry(event.uncertainty.state.clone())
            .or_insert(0) += 1;
    }

    Ok(SwarmReplayTrace {
        schema: SWARM_REPLAY_TRACE_SCHEMA.to_string(),
        trace_id: request.trace_id.clone(),
        generated_at: request.generated_at_utc.clone(),
        contract_version: SWARM_REPLAY_TRACE_CONTRACT_VERSION.to_string(),
        source_inventory,
        ordering: SwarmReplayOrdering {
            monotonic_sequence_required: true,
            timestamp_normalization: "utc_rfc3339_z".to_string(),
            tie_breakers: vec![
                "sequence".to_string(),
                "source_ref".to_string(),
                "event_id".to_string(),
            ],
        },
        events,
        redaction_summary: SwarmReplayRedactionSummary {
            redacted_count: redaction.redacted_count,
            sensitive_omitted_count: redaction.sensitive_omitted_count,
            raw_secret_bytes_emitted: 0,
            redacted_fields: redaction.redacted_fields.into_iter().collect(),
        },
        uncertainty_summary: SwarmReplayUncertaintySummary {
            missing_sources: missing_sources.into_iter().collect(),
            malformed_sources: malformed_sources.into_iter().collect(),
            stale_sources: stale_sources.into_iter().collect(),
            suppressed_claims: suppressed_claims.into_iter().collect(),
            event_count_by_uncertainty,
        },
        replay_guards: SwarmReplayGuards {
            read_only: true,
            no_live_mutation: true,
            no_network_required: true,
            fail_closed_on_missing_required_sources: true,
            requires_source_inventory: true,
            disallowed_live_actions: [
                "claim_bead",
                "close_bead",
                "send_agent_mail",
                "reserve_file",
                "release_file",
                "acquire_build_slot",
                "cancel_rch_job",
                "git_commit",
                "git_push",
            ]
            .iter()
            .map(ToString::to_string)
            .collect(),
        },
    })
}

fn validate_request(request: &SwarmReplayIngestRequest) -> Result<()> {
    if request.trace_id.trim().is_empty() {
        return Err(Error::validation("swarm replay trace_id cannot be empty"));
    }
    if !is_rfc3339_z(&request.generated_at_utc) {
        return Err(Error::validation(
            "swarm replay generated_at_utc must be RFC3339 UTC ending in Z",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn analyze_source(request: &SwarmReplayIngestRequest, template: &SourceTemplate) -> SourceAnalysis {
    let path = source_path(request, template);
    let inventory_path = display_path(&request.workspace_root, &path);
    let authoritative_for = template
        .authoritative_for
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    if !path.exists() {
        return SourceAnalysis {
            row: SwarmReplaySourceInventoryRow {
                source_id: template.source_id.to_string(),
                source_kind: template.source_kind.to_string(),
                path: inventory_path,
                availability: "unavailable".to_string(),
                freshness_state: "missing".to_string(),
                source_hash: None,
                redaction_state: template.default_redaction_state.to_string(),
                authoritative_for,
                uncertainty: vec!["source_missing".to_string()],
            },
            parsed: None,
        };
    }

    if path.is_dir() || template.format == SourceInputFormat::Opaque {
        return SourceAnalysis {
            row: SwarmReplaySourceInventoryRow {
                source_id: template.source_id.to_string(),
                source_kind: template.source_kind.to_string(),
                path: inventory_path,
                availability: "available".to_string(),
                freshness_state: "freshness_unknown".to_string(),
                source_hash: None,
                redaction_state: template.default_redaction_state.to_string(),
                authoritative_for,
                uncertainty: vec!["opaque_or_directory_source_not_parsed".to_string()],
            },
            parsed: None,
        };
    }

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return SourceAnalysis {
                row: SwarmReplaySourceInventoryRow {
                    source_id: template.source_id.to_string(),
                    source_kind: template.source_kind.to_string(),
                    path: inventory_path,
                    availability: "unavailable".to_string(),
                    freshness_state: "missing".to_string(),
                    source_hash: None,
                    redaction_state: template.default_redaction_state.to_string(),
                    authoritative_for,
                    uncertainty: vec![format!("source_read_error:{err}")],
                },
                parsed: None,
            };
        }
    };
    let source_hash = Some(sha256_prefixed(&bytes));
    let text = String::from_utf8_lossy(&bytes);
    let parsed = match template.format {
        SourceInputFormat::Json => serde_json::from_str::<Value>(&text)
            .map(ParsedSource::Json)
            .map_err(|err| format!("json_parse_error:{err}")),
        SourceInputFormat::JsonLines => parse_json_lines(&text).map(ParsedSource::JsonLines),
        SourceInputFormat::Opaque => unreachable!("opaque sources returned before parsing"),
    };

    match parsed {
        Ok(parsed_source) => {
            let stale = parsed_source_is_stale(&parsed_source);
            SourceAnalysis {
                row: SwarmReplaySourceInventoryRow {
                    source_id: template.source_id.to_string(),
                    source_kind: template.source_kind.to_string(),
                    path: inventory_path,
                    availability: if stale { "stale" } else { "available" }.to_string(),
                    freshness_state: if stale { "stale" } else { "current" }.to_string(),
                    source_hash,
                    redaction_state: template.default_redaction_state.to_string(),
                    authoritative_for,
                    uncertainty: if stale {
                        vec!["source_declared_stale".to_string()]
                    } else {
                        Vec::new()
                    },
                },
                parsed: Some(parsed_source),
            }
        }
        Err(reason) => SourceAnalysis {
            row: SwarmReplaySourceInventoryRow {
                source_id: template.source_id.to_string(),
                source_kind: template.source_kind.to_string(),
                path: inventory_path,
                availability: "malformed".to_string(),
                freshness_state: "malformed".to_string(),
                source_hash,
                redaction_state: template.default_redaction_state.to_string(),
                authoritative_for,
                uncertainty: vec![reason],
            },
            parsed: None,
        },
    }
}

fn source_path(request: &SwarmReplayIngestRequest, template: &SourceTemplate) -> PathBuf {
    let path = request
        .source_overrides
        .get(template.source_id)
        .cloned()
        .unwrap_or_else(|| PathBuf::from(template.default_path));
    if path.is_absolute() {
        path
    } else {
        request.workspace_root.join(path)
    }
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map_or(path, |relative| relative)
        .to_string_lossy()
        .replace('\\', "/")
}

fn parse_json_lines(text: &str) -> std::result::Result<Vec<Value>, String> {
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        rows.push(
            serde_json::from_str(trimmed)
                .map_err(|err| format!("jsonl_parse_error:line_{}:{err}", index + 1))?,
        );
    }
    Ok(rows)
}

fn parsed_source_is_stale(parsed: &ParsedSource) -> bool {
    match parsed {
        ParsedSource::Json(value) => value_declares_stale(value),
        ParsedSource::JsonLines(rows) => rows.iter().any(value_declares_stale),
    }
}

fn value_declares_stale(value: &Value) -> bool {
    value
        .get("freshness_state")
        .and_then(Value::as_str)
        .is_some_and(|state| state.eq_ignore_ascii_case("stale"))
        || value
            .get("availability")
            .and_then(Value::as_str)
            .is_some_and(|state| state.eq_ignore_ascii_case("stale"))
        || value.get("stale").and_then(Value::as_bool).unwrap_or(false)
}

fn events_from_source(
    request: &SwarmReplayIngestRequest,
    template: &SourceTemplate,
    row: &SwarmReplaySourceInventoryRow,
    parsed: &ParsedSource,
    redaction: &mut RedactionAccumulator,
) -> Vec<PendingEvent> {
    match (template.source_id, parsed) {
        ("beads_jsonl", ParsedSource::JsonLines(rows)) => rows
            .iter()
            .map(|row_value| bead_lifecycle_event(request, row, row_value, redaction))
            .collect(),
        ("agent_mail_archive", ParsedSource::Json(value)) => {
            agent_mail_events(request, row, value, redaction)
        }
        ("doctor_swarm_diagnostics", ParsedSource::Json(value)) => {
            doctor_events(request, row, value, redaction)
        }
        ("rch_queue_status", ParsedSource::Json(value)) => {
            rch_events(request, row, value, redaction)
        }
        ("operator_runpack", ParsedSource::Json(value)) => {
            runpack_events(request, row, value, redaction)
        }
        ("git_refs", ParsedSource::Json(value)) => {
            vec![git_event(request, row, Some(value), redaction)]
        }
        ("validation_command_records", ParsedSource::Json(value)) => {
            validation_events(request, row, value, redaction)
        }
        ("context_intelligence_evidence", ParsedSource::Json(value)) => {
            vec![context_intelligence_event(request, row, value, redaction)]
        }
        ("swarm_flight_recorder", ParsedSource::JsonLines(rows)) => rows
            .iter()
            .map(|value| flight_recorder_event(request, row, value, redaction))
            .collect(),
        ("swarm_activity_ledger", ParsedSource::JsonLines(rows)) => rows
            .iter()
            .map(|value| activity_ledger_event(request, row, value, redaction))
            .collect(),
        ("git_refs", _) => vec![git_event(request, row, None, redaction)],
        _ => Vec::new(),
    }
}

fn missing_source_events(
    template: &SourceTemplate,
    row: &SwarmReplaySourceInventoryRow,
    generated_at_utc: &str,
) -> Vec<PendingEvent> {
    if template.source_id != "agent_mail_archive" {
        return Vec::new();
    }

    let suppressed_claims = suppressed_claims_for_source(template.source_id)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    vec![PendingEvent {
        candidate_id: format!("{}-missing-agent-message", template.source_id),
        occurred_at_utc: generated_at_utc.to_string(),
        observed_at_utc: generated_at_utc.to_string(),
        event_type: "agent_message".to_string(),
        actor: "agent-mail".to_string(),
        source_ref: row.source_id.clone(),
        source_hash: row.source_hash.clone(),
        redaction_state: "sensitive_omitted".to_string(),
        uncertainty: SwarmReplayEventUncertainty {
            state: "missing_source".to_string(),
            reasons: row.uncertainty.clone(),
            suppressed_claims,
        },
        payload: json!({
            "thread_id": "unknown",
            "sender": "unknown",
            "recipients": [],
            "importance": "unknown",
            "ack_required": false
        }),
    }]
}

fn bead_lifecycle_event(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let bead_id = string_field(value, &["id", "bead_id"], "unknown");
    let occurred = timestamp_field(value, request.generated_at_utc.as_str());
    let payload = json!({
        "bead_id": bead_id,
        "from_status": string_field(value, &["previous_status", "from_status"], "unknown"),
        "to_status": string_field(value, &["status", "to_status"], "unknown"),
        "priority": value.get("priority").and_then(Value::as_i64).unwrap_or_default(),
        "assignee": string_field(value, &["assignee"], "unassigned")
    });
    pending_event(
        request,
        row,
        event_seed(
            "bead_lifecycle",
            format!("bead-{bead_id}"),
            string_field(value, &["assignee", "created_by"], "beads"),
            occurred,
            payload,
        ),
        redaction,
    )
}

fn agent_mail_events(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> Vec<PendingEvent> {
    let mut events = Vec::new();
    for message in array_field(value, "messages") {
        let thread_id = string_field(message, &["thread_id", "threadId"], "unknown");
        let sender = string_field(message, &["sender", "from"], "unknown");
        let payload = json!({
            "thread_id": thread_id,
            "sender": sender,
            "recipients": string_array_field(message, "recipients"),
            "importance": string_field(message, &["importance"], "normal"),
            "ack_required": message.get("ack_required").and_then(Value::as_bool).unwrap_or(false)
        });
        let payload = with_optional_string(
            payload,
            message,
            &["body", "body_md", "content", "text"],
            "body",
        );
        events.push(pending_event(
            request,
            row,
            event_seed(
                "agent_message",
                format!("mail-{thread_id}-{sender}"),
                sender,
                timestamp_field(message, request.generated_at_utc.as_str()),
                payload,
            ),
            redaction,
        ));
    }
    for reservation in array_field(value, "reservations") {
        let reservation_id = string_field(reservation, &["reservation_id", "id"], "unknown");
        let payload = json!({
            "reservation_id": reservation_id,
            "path_patterns": string_array_field(reservation, "path_patterns"),
            "exclusive": reservation.get("exclusive").and_then(Value::as_bool).unwrap_or(false),
            "ttl_seconds": reservation.get("ttl_seconds").and_then(Value::as_u64).unwrap_or_default(),
            "reason": string_field(reservation, &["reason"], "unknown"),
            "holder": string_field(reservation, &["holder", "agent"], "unknown"),
            "state": string_field(reservation, &["state"], "active")
        });
        events.push(pending_event(
            request,
            row,
            event_seed(
                "reservation_intent",
                format!("reservation-{reservation_id}"),
                string_field(reservation, &["holder", "agent"], "agent-mail"),
                timestamp_field(reservation, request.generated_at_utc.as_str()),
                payload,
            ),
            redaction,
        ));
    }
    for conflict in array_field(value, "reservation_conflicts") {
        let path_pattern = string_field(conflict, &["path_pattern", "path"], "unknown");
        let payload = json!({
            "path_pattern": path_pattern,
            "holder": string_field(conflict, &["holder"], "unknown"),
            "conflict_reason": string_field(conflict, &["conflict_reason", "reason"], "unknown")
        });
        events.push(pending_event(
            request,
            row,
            event_seed(
                "reservation_conflict",
                format!("reservation-conflict-{path_pattern}"),
                string_field(conflict, &["holder"], "agent-mail"),
                timestamp_field(conflict, request.generated_at_utc.as_str()),
                payload,
            ),
            redaction,
        ));
    }
    for slot in array_field(value, "build_slots") {
        let slot_name = string_field(slot, &["slot"], "unknown");
        let payload = json!({
            "slot": slot_name,
            "holder": string_field(slot, &["holder"], "unknown"),
            "state": string_field(slot, &["state"], "unknown"),
            "expires_at_utc": string_field(slot, &["expires_at_utc", "expires_at"], "unknown")
        });
        events.push(pending_event(
            request,
            row,
            event_seed(
                "build_slot_state",
                format!("build-slot-{slot_name}"),
                string_field(slot, &["holder"], "agent-mail"),
                timestamp_field(slot, request.generated_at_utc.as_str()),
                payload,
            ),
            redaction,
        ));
    }
    events
}

fn doctor_events(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> Vec<PendingEvent> {
    let findings = array_field(value, "findings");
    if findings.is_empty() {
        return vec![doctor_event_from_value(request, row, value, redaction)];
    }
    findings
        .into_iter()
        .map(|finding| doctor_event_from_value(request, row, finding, redaction))
        .collect()
}

fn doctor_event_from_value(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let finding_id = string_field(value, &["finding_id", "id", "check"], "doctor-swarm");
    let payload = json!({
        "finding_id": finding_id,
        "severity": string_field(value, &["severity", "level"], "info"),
        "surface": string_field(value, &["surface", "category"], "swarm"),
        "status": string_field(value, &["status", "verdict"], "unknown")
    });
    pending_event(
        request,
        row,
        event_seed(
            "doctor_finding",
            format!("doctor-{finding_id}"),
            "doctor",
            timestamp_field(value, request.generated_at_utc.as_str()),
            payload,
        ),
        redaction,
    )
}

fn rch_events(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> Vec<PendingEvent> {
    let jobs = array_field(value, "jobs");
    let rows = if jobs.is_empty() {
        array_field(value, "queue")
    } else {
        jobs
    };
    if rows.is_empty() {
        return vec![rch_event_from_value(request, row, value, redaction)];
    }
    rows.into_iter()
        .map(|job| rch_event_from_value(request, row, job, redaction))
        .collect()
}

fn rch_event_from_value(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let job_id = string_field(value, &["job_id", "id"], "rch-status");
    let payload = json!({
        "job_id": job_id,
        "state": string_field(value, &["state", "status"], "unknown"),
        "worker": string_field(value, &["worker"], "unknown"),
        "command": string_field(value, &["command"], "unknown"),
        "queue_position": value.get("queue_position").and_then(Value::as_u64).unwrap_or_default()
    });
    pending_event(
        request,
        row,
        event_seed(
            "rch_job_state",
            format!("rch-{job_id}"),
            "rch",
            timestamp_field(value, request.generated_at_utc.as_str()),
            payload,
        ),
        redaction,
    )
}

fn runpack_events(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> Vec<PendingEvent> {
    let mut events = Vec::new();
    for recommendation in array_field(value, "recommendations") {
        let action = string_field(recommendation, &["action", "selected_action"], "unknown");
        let payload = json!({
            "action": action,
            "severity": string_field(recommendation, &["severity"], "info"),
            "evidence_paths": string_array_field(recommendation, "evidence_paths"),
            "operator_notes": string_field(recommendation, &["operator_notes", "notes"], "")
        });
        events.push(pending_event(
            request,
            row,
            event_seed(
                "runpack_recommendation",
                format!("runpack-{action}"),
                "operator_runpack",
                timestamp_field(recommendation, request.generated_at_utc.as_str()),
                payload,
            ),
            redaction,
        ));
    }
    if let Some(handoff) = value.get("operator_handoff") {
        events.push(operator_handoff_event(request, row, handoff, redaction));
    }
    if events.is_empty() {
        events.push(operator_handoff_event(request, row, value, redaction));
    }
    events
}

fn operator_handoff_event(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let handoff_id = string_field(value, &["handoff_id", "id"], "operator-handoff");
    let payload = json!({
        "handoff_id": handoff_id,
        "summary": string_field(value, &["summary"], ""),
        "next_actions": string_array_field(value, "next_actions"),
        "evidence_paths": string_array_field(value, "evidence_paths")
    });
    pending_event(
        request,
        row,
        event_seed(
            "operator_handoff",
            format!("handoff-{handoff_id}"),
            "operator_runpack",
            timestamp_field(value, request.generated_at_utc.as_str()),
            payload,
        ),
        redaction,
    )
}

fn git_event(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: Option<&Value>,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let payload = json!({
        "head": value.map_or_else(
            || request.git_commit.clone().unwrap_or_else(|| "unknown".to_string()),
            |v| string_field(v, &["head", "commit"], request.git_commit.as_deref().unwrap_or("unknown")),
        ),
        "branch": value.map_or_else(
            || request.git_branch.clone().unwrap_or_else(|| "unknown".to_string()),
            |v| string_field(v, &["branch"], request.git_branch.as_deref().unwrap_or("unknown")),
        ),
        "dirty": value.and_then(|v| v.get("dirty")).and_then(Value::as_bool).unwrap_or(false),
        "changed_paths": value.map_or_else(Vec::new, |v| string_array_field(v, "changed_paths"))
    });
    pending_event(
        request,
        row,
        event_seed(
            "worktree_state",
            "git-worktree",
            "git",
            value.map_or_else(
                || request.generated_at_utc.clone(),
                |v| timestamp_field(v, request.generated_at_utc.as_str()),
            ),
            payload,
        ),
        redaction,
    )
}

fn validation_events(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> Vec<PendingEvent> {
    let mut events = Vec::new();
    for command in array_field(value, "commands") {
        let command_text = string_field(command, &["command"], "unknown");
        let payload = json!({
            "command": command_text,
            "runner": string_field(command, &["runner"], "unknown"),
            "exit_code": command.get("exit_code").and_then(Value::as_i64).unwrap_or_default(),
            "target_dir": string_field(command, &["target_dir"], "unknown"),
            "tmpdir": string_field(command, &["tmpdir"], "unknown")
        });
        events.push(pending_event(
            request,
            row,
            event_seed(
                "cargo_gate_result",
                format!("cargo-gate-{command_text}"),
                "validation",
                timestamp_field(command, request.generated_at_utc.as_str()),
                payload,
            ),
            redaction,
        ));
    }
    for artifact in array_field(value, "artifacts") {
        events.push(validation_artifact_event(request, row, artifact, redaction));
    }
    if events.is_empty() {
        events.push(validation_artifact_event(request, row, value, redaction));
    }
    events
}

fn context_intelligence_event(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let payload = json!({
        "artifact_path": row.path,
        "artifact_schema": string_field(value, &["schema"], "context_intelligence_evidence"),
        "verdict": string_field(value, &["verdict", "status", "overall_verdict"], "unknown"),
        "command": "context-intelligence-closeout-gate"
    });
    pending_event(
        request,
        row,
        event_seed(
            "validation_artifact",
            "context-intelligence-evidence",
            "context_intelligence",
            timestamp_field(value, request.generated_at_utc.as_str()),
            payload,
        ),
        redaction,
    )
}

fn flight_recorder_event(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let event_kind = string_field(value, &["event_kind", "eventKind"], "flight-recorder");
    let payload = json!({
        "artifact_path": row.path,
        "artifact_schema": string_field(value, &["schema"], "pi.swarm.flight_recorder.event.v1"),
        "verdict": "observed",
        "command": event_kind
    });
    pending_event(
        request,
        row,
        event_seed(
            "validation_artifact",
            format!("flight-{event_kind}"),
            string_field(value, &["agent_name", "agent"], "flight_recorder"),
            timestamp_field(value, request.generated_at_utc.as_str()),
            payload,
        ),
        redaction,
    )
}

fn activity_ledger_event(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let event_kind = string_field(value, &["event_kind", "kind"], "activity-ledger");
    if event_kind.contains("handoff") {
        return operator_handoff_event(request, row, value, redaction);
    }
    let payload = json!({
        "artifact_path": row.path,
        "artifact_schema": string_field(value, &["schema"], "pi.swarm.activity_ledger.v1"),
        "verdict": "observed",
        "command": event_kind
    });
    pending_event(
        request,
        row,
        event_seed(
            "validation_artifact",
            format!("activity-{event_kind}"),
            string_field(value, &["agent_name", "agent"], "activity_ledger"),
            timestamp_field(value, request.generated_at_utc.as_str()),
            payload,
        ),
        redaction,
    )
}

fn validation_artifact_event(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    value: &Value,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let artifact_path = string_field(value, &["artifact_path", "path"], row.path.as_str());
    let payload = json!({
        "artifact_path": artifact_path,
        "artifact_schema": string_field(value, &["artifact_schema", "schema"], "unknown"),
        "verdict": string_field(value, &["verdict", "status"], "unknown"),
        "command": string_field(value, &["command"], "unknown")
    });
    pending_event(
        request,
        row,
        event_seed(
            "validation_artifact",
            format!("validation-artifact-{artifact_path}"),
            "validation",
            timestamp_field(value, request.generated_at_utc.as_str()),
            payload,
        ),
        redaction,
    )
}

fn event_seed(
    event_type: &'static str,
    candidate_id: impl Into<String>,
    actor: impl Into<String>,
    occurred_at_utc: String,
    payload: Value,
) -> PendingEventSeed {
    PendingEventSeed {
        event_type,
        candidate_id: candidate_id.into(),
        actor: actor.into(),
        occurred_at_utc,
        payload,
    }
}

fn pending_event(
    request: &SwarmReplayIngestRequest,
    row: &SwarmReplaySourceInventoryRow,
    seed: PendingEventSeed,
    redaction: &mut RedactionAccumulator,
) -> PendingEvent {
    let mut redacted_payload = seed.payload;
    let redacted_fields = redact_value(&mut redacted_payload);
    let redaction_state = if redacted_fields.is_empty() {
        row.redaction_state.clone()
    } else {
        redaction.redacted_count += 1;
        redaction.sensitive_omitted_count +=
            u64::try_from(redacted_fields.len()).unwrap_or(u64::MAX);
        redaction.redacted_fields.extend(redacted_fields);
        "redacted".to_string()
    };
    let mut reasons = row.uncertainty.clone();
    let state = match row.availability.as_str() {
        "stale" => {
            reasons.push("source_stale".to_string());
            "partial"
        }
        _ if reasons.is_empty() => "certain",
        _ => "uncertain",
    };
    PendingEvent {
        candidate_id: stable_id(&seed.candidate_id),
        occurred_at_utc: seed.occurred_at_utc,
        observed_at_utc: request.generated_at_utc.clone(),
        event_type: seed.event_type.to_string(),
        actor: seed.actor,
        source_ref: row.source_id.clone(),
        source_hash: row.source_hash.clone(),
        redaction_state,
        uncertainty: SwarmReplayEventUncertainty {
            state: state.to_string(),
            reasons,
            suppressed_claims: Vec::new(),
        },
        payload: redacted_payload,
    }
}

fn finalize_events(mut pending: Vec<PendingEvent>) -> Vec<SwarmReplayEvent> {
    pending.sort_by(|left, right| {
        left.occurred_at_utc
            .cmp(&right.occurred_at_utc)
            .then_with(|| left.source_ref.cmp(&right.source_ref))
            .then_with(|| left.candidate_id.cmp(&right.candidate_id))
    });

    let mut seen = BTreeMap::<String, u64>::new();
    pending
        .into_iter()
        .enumerate()
        .map(|(index, mut event)| {
            let count = seen.entry(event.candidate_id.clone()).or_insert(0);
            *count += 1;
            let event_id = if *count == 1 {
                event.candidate_id.clone()
            } else {
                event
                    .uncertainty
                    .reasons
                    .push("duplicate_source_event_id_deduplicated".to_string());
                event.uncertainty.state = "uncertain".to_string();
                format!("{}-dup-{}", event.candidate_id, count)
            };
            SwarmReplayEvent {
                event_id,
                sequence: u64::try_from(index + 1).unwrap_or(u64::MAX),
                occurred_at_utc: event.occurred_at_utc,
                observed_at_utc: event.observed_at_utc,
                event_type: event.event_type,
                actor: event.actor,
                source_ref: event.source_ref,
                source_hash: event.source_hash,
                redaction_state: event.redaction_state,
                uncertainty: event.uncertainty,
                payload: event.payload,
            }
        })
        .collect()
}

fn suppressed_claims_for_source(source_id: &str) -> &'static [&'static str] {
    match source_id {
        "agent_mail_archive" => &[
            "ack_latency",
            "active_reservation_holder",
            "mail_thread_completeness",
            "build_slot_ownership",
        ],
        "rch_queue_status" => &[
            "queue_depth",
            "remote_admission_state",
            "rch_worker_assignment",
        ],
        "operator_runpack" => &["operator_next_action", "operator_handoff_completeness"],
        "doctor_swarm_diagnostics" => &["swarm_health_verdict"],
        "validation_command_records" => &["cargo_gate_success", "validation_artifact_verdict"],
        "context_intelligence_evidence" => &["context_intelligence_freshness"],
        "swarm_flight_recorder" => &["flight_recorder_replay_completeness"],
        "swarm_activity_ledger" => &["activity_ledger_handoff_completeness"],
        _ => &[],
    }
}

fn redact_value(value: &mut Value) -> BTreeSet<String> {
    let mut redacted = BTreeSet::new();
    redact_value_inner(value, "", &mut redacted);
    redacted
}

fn redact_value_inner(value: &mut Value, path: &str, redacted: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let nested_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if is_sensitive_key(key) {
                    *nested = Value::String(SENSITIVE_REDACTION.to_string());
                    redacted.insert(nested_path);
                } else {
                    redact_value_inner(nested, &nested_path, redacted);
                }
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter_mut().enumerate() {
                redact_value_inner(nested, &format!("{path}[{index}]"), redacted);
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

fn string_field(value: &Value, keys: &[&str], fallback: &str) -> String {
    optional_string_field(value, keys).unwrap_or_else(|| fallback.to_string())
}

fn optional_string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .filter(|raw| !raw.trim().is_empty())
        .map(ToString::to_string)
}

fn with_optional_string(
    mut payload: Value,
    source: &Value,
    source_keys: &[&str],
    payload_key: &str,
) -> Value {
    if let (Some(value), Value::Object(map)) =
        (optional_string_field(source, source_keys), &mut payload)
    {
        map.insert(payload_key.to_string(), Value::String(value));
    }
    payload
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn array_field<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| items.iter().collect())
}

fn timestamp_field(value: &Value, fallback: &str) -> String {
    let raw = [
        "occurred_at_utc",
        "occurred_at",
        "updated_at",
        "created_at",
        "generated_at",
        "timestamp",
    ]
    .iter()
    .find_map(|key| value.get(*key).and_then(Value::as_str))
    .unwrap_or(fallback);
    normalize_utc_timestamp(raw).unwrap_or_else(|| fallback.to_string())
}

fn normalize_utc_timestamp(raw: &str) -> Option<String> {
    if is_rfc3339_z(raw) {
        return Some(raw.to_string());
    }
    DateTime::parse_from_rfc3339(raw).ok().map(|datetime| {
        datetime
            .with_timezone(&Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    })
}

fn is_rfc3339_z(value: &str) -> bool {
    value.len() >= 20 && value.contains('T') && value.ends_with('Z')
}

fn stable_id(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut previous_dash = false;
    for byte in raw.bytes() {
        let ch = char::from(byte).to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            previous_dash = false;
        } else if !previous_dash {
            out.push('-');
            previous_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "event".to_string()
    } else {
        trimmed.to_string()
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

#[allow(dead_code)]
fn object_from_pairs(pairs: &[(&str, Value)]) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert((*key).to_string(), value.clone());
    }
    Value::Object(map)
}
