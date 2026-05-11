#!/usr/bin/env python3
"""Build a read-only swarm operator runpack from existing evidence artifacts.

The runpack is an operator handoff bundle. It is not a release performance
claim, and it does not replace Beads, Agent Mail, doctor, cargo_headroom, or
claim-readiness artifacts as sources of truth.
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUNPACK_SCHEMA = "pi.swarm.operator_runpack.v1"
RUNPACK_CONTRACT_SCHEMA = "pi.swarm.operator_runpack_contract.v1"
SAFETY_SCORECARD_SCHEMA = "pi.swarm.safety_scorecard.v1"
TAIL_LATENCY_SCHEMA = "pi.operator_tail_latency.v1"
BOTTLENECK_ATTRIBUTION_SCHEMA = "pi.swarm.bottleneck_attribution_dashboard.v1"
FLIGHT_RECORDER_REPORT_SCHEMA = "pi.swarm.flight_recorder.report.v1"
HOST_PREFLIGHT_SCHEMA = "pi.doctor.swarm_resource_preflight.v1"
HOSTCALL_SWARM_PROFILE_SCHEMA = "pi.ext.hostcall_admission_swarm_profile.v1"
SESSION_RECOVERY_SWARM_PROFILE_SCHEMA = "pi.session_store_v2.recovery_swarm_profile.v1"
RPC_SWARM_E2E_SCHEMA = "pi.rpc.concurrent_swarm_e2e.v1"
RCH_ARTIFACT_SYNC_SCHEMA = "pi.rch.artifact_sync_preflight.v1"
RUNPACK_CONTRACT_PATH = Path("docs/contracts/swarm-operator-runpack-contract.json")
GOLDEN_REPORT_DIRECTORY = Path("tests/golden_corpus/swarm_operator_runpack")
COMPLETE_RUNPACK_GOLDEN = "complete_runpack_projection.json"
UPDATE_GOLDEN_ENV = "UPDATE_SWARM_OPERATOR_RUNPACK_GOLDEN"
DEFAULT_MAX_ITEMS = 8
DEFAULT_STALE_AFTER_HOURS = 24
SCORECARD_MAX_PER_DIMENSION = 2
SENSITIVE_KEY_FRAGMENTS = (
    "authorization",
    "bearer",
    "body",
    "cookie",
    "key",
    "password",
    "prompt",
    "registration_token",
    "secret",
    "token",
    "transcript",
)
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(bearer\s+[A-Za-z0-9._~+/=-]+|"
    r"(?:api[_-]?key|authorization|password|registration_token|secret|token)"
    r"\s*[:=]\s*[\"']?[^\"'\s,}]+)"
)
BOTTLENECK_CORE_SOURCE_IDS = (
    "doctor_swarm",
    "smoke_harness",
    "activity_digest",
    "cargo_admission",
)
BOTTLENECK_OPTIONAL_SOURCE_IDS = (
    "tail_latency",
    "flight_recorder",
    "host_preflight",
    "hostcall_swarm_profile",
    "session_recovery_swarm_profile",
    "rpc_swarm_e2e",
    "rch_artifact_sync",
)
BOTTLENECK_SURFACES: dict[str, tuple[str, ...]] = {
    "provider_streaming": ("tail_latency", "flight_recorder", "rpc_swarm_e2e"),
    "local_tools": ("smoke_harness", "flight_recorder", "rpc_swarm_e2e"),
    "extension_hostcalls": ("hostcall_swarm_profile", "tail_latency", "flight_recorder"),
    "persistence": (
        "session_recovery_swarm_profile",
        "smoke_harness",
        "flight_recorder",
        "rpc_swarm_e2e",
    ),
    "rch_sync_retrieval": ("rch_artifact_sync", "cargo_admission"),
    "queue_pressure": ("cargo_admission", "activity_digest", "hostcall_swarm_profile"),
    "cgroup_numa_context": ("host_preflight", "doctor_swarm"),
}
TIMESTAMP_KEYS = (
    "generated_at",
    "generatedAt",
    "timestamp",
    "created_at",
    "started_at",
    "run_started_at",
    "completed_at",
)


class RunpackError(RuntimeError):
    """Raised when a provided source cannot safely contribute to the runpack."""


@dataclass(frozen=True)
class SourcePayload:
    id: str
    path: str | None
    status: str
    schema: str | None
    payload: Any | None
    issue: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    redacted_count: int = 0
    redacted_fields: tuple[str, ...] = ()

    def to_status(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "status": self.status,
            "schema": self.schema,
            "issue": self.issue,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


@dataclass
class RedactionStats:
    redacted_count: int = 0
    fields: set[str] | None = None

    def __post_init__(self) -> None:
        if self.fields is None:
            self.fields = set()

    def merge(self, other: "RedactionStats") -> None:
        self.redacted_count += other.redacted_count
        self.fields.update(other.fields or set())

    def to_json(self) -> dict[str, Any]:
        return {
            "redacted_count": self.redacted_count,
            "fields": sorted(self.fields or []),
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact_string(value: str, field: str) -> tuple[str, RedactionStats]:
    stats = RedactionStats()
    if SENSITIVE_VALUE_RE.search(value):
        stats.redacted_count += 1
        stats.fields.add(field)
        return SENSITIVE_VALUE_RE.sub("[REDACTED]", value), stats
    return value, stats


def redact_json(value: Any, field: str = "value") -> tuple[Any, RedactionStats]:
    stats = RedactionStats()
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            child_field = f"{field}.{key}" if field else str(key)
            if is_sensitive_key(str(key)):
                out[key] = "[REDACTED]"
                stats.redacted_count += 1
                stats.fields.add(child_field)
                continue
            redacted, child_stats = redact_json(item, child_field)
            stats.merge(child_stats)
            out[key] = redacted
        return out, stats
    if isinstance(value, list):
        out_list = []
        for index, item in enumerate(value):
            redacted, child_stats = redact_json(item, f"{field}[{index}]")
            stats.merge(child_stats)
            out_list.append(redacted)
        return out_list, stats
    if isinstance(value, str):
        return redact_string(value, field)
    return value, stats


def json_dumps(payload: Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def file_fingerprint(path: Path) -> tuple[int, str]:
    data = path.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()


def json_schema(value: Any) -> str | None:
    if isinstance(value, dict):
        schema = value.get("schema")
        if isinstance(schema, str):
            return schema
    return None


def load_json_source(
    source_id: str,
    path: Path | None,
    *,
    expected_schema: str | None = None,
) -> SourcePayload:
    if path is None:
        return SourcePayload(source_id, None, "not_provided", None, None)
    if not path.exists():
        raise RunpackError(f"{source_id} source path does not exist: {path}")
    size_bytes, sha256 = file_fingerprint(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RunpackError(f"{source_id} source is malformed JSON: {path}: {exc}") from exc
    redacted, stats = redact_json(payload, source_id)
    schema = json_schema(redacted)
    if expected_schema is not None and schema != expected_schema:
        raise RunpackError(
            f"{source_id} source schema mismatch: expected {expected_schema}, got {schema}"
        )
    return SourcePayload(
        source_id,
        str(path),
        "ok",
        schema,
        redacted,
        size_bytes=size_bytes,
        sha256=sha256,
        redacted_count=stats.redacted_count,
        redacted_fields=tuple(sorted(stats.fields or [])),
    )


def load_cargo_admission(path: Path | None) -> SourcePayload:
    if path is None:
        return SourcePayload("cargo_admission", None, "not_provided", None, None)
    if not path.exists():
        raise RunpackError(f"cargo_admission source path does not exist: {path}")
    size_bytes, sha256 = file_fingerprint(path)
    text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        redacted, stats = redact_json(payload, "cargo_admission")
        return SourcePayload(
            "cargo_admission",
            str(path),
            "ok",
            json_schema(redacted),
            redacted,
            size_bytes=size_bytes,
            sha256=sha256,
            redacted_count=stats.redacted_count,
            redacted_fields=tuple(sorted(stats.fields or [])),
        )
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            redacted, stats = redact_json(payload, "cargo_admission")
            return SourcePayload(
                "cargo_admission",
                str(path),
                "ok",
                json_schema(redacted),
                redacted,
                size_bytes=size_bytes,
                sha256=sha256,
                redacted_count=stats.redacted_count,
                redacted_fields=tuple(sorted(stats.fields or [])),
            )
    raise RunpackError(f"cargo_admission source did not contain a JSON object: {path}")


def load_git_status(path: Path | None) -> SourcePayload:
    if path is None:
        return SourcePayload("git_status", None, "not_provided", None, None)
    if not path.exists():
        raise RunpackError(f"git_status source path does not exist: {path}")
    size_bytes, sha256 = file_fingerprint(path)
    lines = [line.rstrip("\n") for line in path.read_text(encoding="utf-8").splitlines()]
    return SourcePayload(
        "git_status",
        str(path),
        "ok",
        None,
        {"dirty": bool(lines), "porcelain_lines": lines},
        size_bytes=size_bytes,
        sha256=sha256,
    )


def source_payloads(args: argparse.Namespace) -> list[SourcePayload]:
    sources = [
        load_json_source("doctor_swarm", args.doctor_json),
        load_json_source(
            "claim_readiness",
            args.claim_readiness_json,
            expected_schema="pi.swarm.claim_readiness_report.v1",
        ),
        load_json_source(
            "smoke_harness",
            args.smoke_summary_json,
            expected_schema="pi.swarm.smoke_harness.v1",
        ),
        load_json_source(
            "activity_digest",
            args.activity_digest_json,
            expected_schema="pi.swarm.activity_digest.v1",
        ),
        load_cargo_admission(args.cargo_admission_json),
        load_json_source("beads", args.beads_json),
        load_git_status(args.git_status_file),
    ]
    if args.tail_latency_json is not None:
        sources.append(
            load_json_source(
                "tail_latency",
                args.tail_latency_json,
                expected_schema=TAIL_LATENCY_SCHEMA,
            )
        )
    if args.flight_recorder_report_json is not None:
        sources.append(
            load_json_source(
                "flight_recorder",
                args.flight_recorder_report_json,
                expected_schema=FLIGHT_RECORDER_REPORT_SCHEMA,
            )
        )
    if args.host_preflight_json is not None:
        sources.append(
            load_json_source(
                "host_preflight",
                args.host_preflight_json,
                expected_schema=HOST_PREFLIGHT_SCHEMA,
            )
        )
    if args.hostcall_swarm_profile_json is not None:
        sources.append(
            load_json_source(
                "hostcall_swarm_profile",
                args.hostcall_swarm_profile_json,
                expected_schema=HOSTCALL_SWARM_PROFILE_SCHEMA,
            )
        )
    if args.session_recovery_swarm_profile_json is not None:
        sources.append(
            load_json_source(
                "session_recovery_swarm_profile",
                args.session_recovery_swarm_profile_json,
                expected_schema=SESSION_RECOVERY_SWARM_PROFILE_SCHEMA,
            )
        )
    if args.rpc_swarm_e2e_json is not None:
        sources.append(
            load_json_source(
                "rpc_swarm_e2e",
                args.rpc_swarm_e2e_json,
                expected_schema=RPC_SWARM_E2E_SCHEMA,
            )
        )
    if args.rch_artifact_sync_json is not None:
        sources.append(
            load_json_source(
                "rch_artifact_sync",
                args.rch_artifact_sync_json,
                expected_schema=RCH_ARTIFACT_SYNC_SCHEMA,
            )
        )
    return sources


def bounded(items: list[Any], max_items: int) -> list[Any]:
    return items[: max(0, max_items)]


def summarize_doctor(source: SourcePayload, max_items: int) -> dict[str, Any]:
    payload = source.payload
    if not isinstance(payload, dict):
        return {"status": source.status, "findings": []}
    findings = payload.get("findings")
    if not isinstance(findings, list):
        findings = []
    swarm_findings: list[dict[str, Any]] = []
    agent_mail_findings: list[dict[str, Any]] = []
    build_slot_finding: dict[str, Any] | None = None
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("category") != "swarm":
            continue
        item = {
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "detail": finding.get("detail"),
            "remediation": finding.get("remediation"),
            "data": finding.get("data"),
        }
        swarm_findings.append(item)
        title = str(finding.get("title") or "")
        data = finding.get("data") if isinstance(finding.get("data"), dict) else {}
        data_schema = data.get("schema") if isinstance(data, dict) else None
        if "Agent Mail" in title or "reservation" in title:
            agent_mail_findings.append(item)
        if data_schema == "pi.doctor.agent_mail_build_slots.v1" or "build slot" in title.lower():
            build_slot_finding = item
    severity_counts = Counter(str(item.get("severity") or "unknown") for item in swarm_findings)
    return {
        "status": source.status,
        "overall": payload.get("overall"),
        "summary": payload.get("summary"),
        "finding_count": len(swarm_findings),
        "severity_counts": dict(sorted(severity_counts.items())),
        "findings": bounded(swarm_findings, max_items),
        "agent_mail_findings": bounded(agent_mail_findings, max_items),
        "agent_mail_build_slots": build_slot_finding,
    }


def summarize_claim_readiness(source: SourcePayload, max_items: int) -> dict[str, Any]:
    payload = source.payload
    if not isinstance(payload, dict):
        return {"status": source.status}
    artifact_statuses = payload.get("artifact_statuses")
    if not isinstance(artifact_statuses, list):
        artifact_statuses = []
    counts = Counter(str(item.get("status") or "unknown") for item in artifact_statuses if isinstance(item, dict))
    blocking = [
        {
            "id": item.get("id"),
            "category": item.get("category"),
            "status": item.get("status"),
            "issue_kinds": item.get("issue_kinds"),
        }
        for item in artifact_statuses
        if isinstance(item, dict)
        and item.get("release_blocking") is True
        and item.get("status") not in {"ready", "historical_snapshot"}
    ]
    return {
        "status": source.status,
        "overall_status": payload.get("overall_status"),
        "max_age_days": payload.get("max_age_days"),
        "artifact_status_counts": dict(sorted(counts.items())),
        "blocking_artifacts": bounded(blocking, max_items),
        "stale_claims": payload.get("stale_claims", {}).get("summary")
        if isinstance(payload.get("stale_claims"), dict)
        else None,
    }


def summarize_tail_latency(source: SourcePayload, max_items: int) -> dict[str, Any]:
    payload = source.payload
    if not isinstance(payload, dict):
        return {"status": source.status}
    metrics = payload.get("metrics")
    if not isinstance(metrics, list):
        metrics = []
    summarized_metrics: list[dict[str, Any]] = []
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        snapshot = metric.get("snapshot") if isinstance(metric.get("snapshot"), dict) else {}
        tail = snapshot.get("tail") if isinstance(snapshot.get("tail"), dict) else {}
        summarized_metrics.append(
            {
                "id": metric.get("id"),
                "label": metric.get("label"),
                "count": snapshot.get("count"),
                "sample_count": tail.get("sample_count"),
                "p95_us": tail.get("p95_us"),
                "p99_us": tail.get("p99_us"),
                "p999_us": tail.get("p999_us"),
                "max_us": snapshot.get("max_us"),
            }
        )
    return {
        "status": source.status,
        "schema": payload.get("schema"),
        "generated_at": payload.get("generated_at"),
        "purpose": payload.get("purpose"),
        "telemetry_enabled": payload.get("telemetry_enabled"),
        "sample_window": payload.get("sample_window"),
        "redaction_summary": payload.get("redaction_summary"),
        "metrics": bounded(summarized_metrics, max_items),
    }


def top_level_timestamp(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in TIMESTAMP_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def classify_bottleneck_source(
    source: SourcePayload,
    *,
    generated_at: datetime,
    stale_after_hours: int,
    required: bool,
) -> dict[str, Any]:
    if source.status != "ok":
        return {
            "id": source.id,
            "role": "required_surface" if required else "optional_diagnostic",
            "status": source.status,
            "schema": source.schema,
            "classification": "blocker" if required else "optional_diagnostic",
            "freshness_hours": None,
            "timestamp": None,
            "issue": source.issue or "source was not provided",
        }
    timestamp = top_level_timestamp(source.payload)
    if required and timestamp is None:
        return {
            "id": source.id,
            "role": "required_surface",
            "status": source.status,
            "schema": source.schema,
            "classification": "fresh",
            "freshness_hours": None,
            "timestamp": None,
            "issue": None,
        }
    if timestamp is None:
        return {
            "id": source.id,
            "role": "optional_diagnostic",
            "status": source.status,
            "schema": source.schema,
            "classification": "optional_diagnostic",
            "freshness_hours": None,
            "timestamp": None,
            "issue": "provided optional diagnostic is missing a top-level timestamp",
        }
    try:
        source_time = parse_utc(timestamp)
    except ValueError:
        return {
            "id": source.id,
            "role": "optional_diagnostic",
            "status": source.status,
            "schema": source.schema,
            "classification": "blocker",
            "freshness_hours": None,
            "timestamp": timestamp,
            "issue": "provided optional diagnostic has an invalid timestamp",
        }
    age_hours = (generated_at - source_time).total_seconds() / 3600
    if age_hours < 0:
        return {
            "id": source.id,
            "role": "optional_diagnostic",
            "status": source.status,
            "schema": source.schema,
            "classification": "blocker",
            "freshness_hours": round(age_hours, 2),
            "timestamp": source_time.isoformat(),
            "issue": "provided optional diagnostic timestamp is in the future",
        }
    if age_hours > stale_after_hours:
        return {
            "id": source.id,
            "role": "optional_diagnostic",
            "status": source.status,
            "schema": source.schema,
            "classification": "historical_snapshot",
            "freshness_hours": round(age_hours, 2),
            "timestamp": source_time.isoformat(),
            "issue": f"source is older than stale_after_hours={stale_after_hours}",
        }
    return {
        "id": source.id,
        "role": "optional_diagnostic",
        "status": source.status,
        "schema": source.schema,
        "classification": "fresh",
        "freshness_hours": round(age_hours, 2),
        "timestamp": source_time.isoformat(),
        "issue": None,
    }


def surface_status(classifications: list[dict[str, Any]]) -> str:
    if any(item.get("classification") == "blocker" for item in classifications):
        return "blocked"
    if any(item.get("classification") == "fresh" for item in classifications):
        return "covered"
    if any(item.get("classification") == "historical_snapshot" for item in classifications):
        return "historical_snapshot"
    return "optional_diagnostic_missing"


def summarize_surface(
    surface_id: str,
    source_ids: tuple[str, ...],
    classifications_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    classifications = [
        classifications_by_id[source_id]
        for source_id in source_ids
        if source_id in classifications_by_id
    ]
    return {
        "id": surface_id,
        "status": surface_status(classifications),
        "source_ids": list(source_ids),
        "classifications": [
            {
                "id": item.get("id"),
                "classification": item.get("classification"),
                "issue": item.get("issue"),
            }
            for item in classifications
        ],
    }


def extract_tail_latency_bottlenecks(
    source: SourcePayload, max_items: int
) -> list[dict[str, Any]]:
    payload = source.payload if isinstance(source.payload, dict) else {}
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), list) else []
    findings: list[dict[str, Any]] = []
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        snapshot = metric.get("snapshot") if isinstance(metric.get("snapshot"), dict) else {}
        tail = snapshot.get("tail") if isinstance(snapshot.get("tail"), dict) else {}
        p99 = tail.get("p99_us")
        p999 = tail.get("p999_us")
        findings.append(
            {
                "surface": "provider_streaming",
                "source": source.id,
                "label": metric.get("label") or metric.get("id"),
                "signal": "tail_latency",
                "p99_us": p99,
                "p999_us": p999,
                "max_us": snapshot.get("max_us"),
            }
        )
    return bounded(findings, max_items)


def extract_flight_recorder_bottlenecks(
    source: SourcePayload, max_items: int
) -> list[dict[str, Any]]:
    payload = source.payload if isinstance(source.payload, dict) else {}
    components = payload.get("dominant_latency_components")
    if not isinstance(components, list):
        components = []
    findings: list[dict[str, Any]] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        findings.append(
            {
                "surface": "provider_streaming",
                "source": source.id,
                "label": component.get("component") or component.get("name"),
                "signal": "flight_recorder_dominant_latency_component",
                "count": component.get("count"),
                "total_us": component.get("total_us"),
            }
        )
    failures = payload.get("coordination_failures")
    if isinstance(failures, list) and failures:
        findings.append(
            {
                "surface": "queue_pressure",
                "source": source.id,
                "label": "coordination_failures",
                "signal": "flight_recorder_coordination_failures",
                "count": len(failures),
            }
        )
    return bounded(findings, max_items)


def extract_hostcall_bottlenecks(source: SourcePayload, max_items: int) -> list[dict[str, Any]]:
    payload = source.payload if isinstance(source.payload, dict) else {}
    profiles = payload.get("profiles") if isinstance(payload.get("profiles"), list) else []
    findings: list[dict[str, Any]] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        findings.append(
            {
                "surface": "extension_hostcalls",
                "source": source.id,
                "label": profile.get("mode") or profile.get("name"),
                "signal": "hostcall_swarm_profile",
                "accepted_requests": profile.get("accepted_requests"),
                "completed_requests": profile.get("completed_requests"),
                "p99_tail_latency_steps": profile.get("p99_tail_latency_steps"),
                "max_tail_latency_steps": profile.get("max_tail_latency_steps"),
            }
        )
    return bounded(findings, max_items)


def extract_session_bottlenecks(source: SourcePayload) -> list[dict[str, Any]]:
    payload = source.payload if isinstance(source.payload, dict) else {}
    timings = payload.get("timings_us") if isinstance(payload.get("timings_us"), dict) else {}
    if not timings:
        return []
    slowest = sorted(
        ((key, value) for key, value in timings.items() if isinstance(value, (int, float))),
        key=lambda item: item[1],
        reverse=True,
    )
    if not slowest:
        return []
    name, value = slowest[0]
    return [
        {
            "surface": "persistence",
            "source": source.id,
            "label": name,
            "signal": "session_recovery_swarm_profile_slowest_timing",
            "elapsed_us": value,
        }
    ]


def extract_rch_sync_bottlenecks(source: SourcePayload) -> list[dict[str, Any]]:
    payload = source.payload if isinstance(source.payload, dict) else {}
    violations = payload.get("violations") if isinstance(payload.get("violations"), list) else []
    status = payload.get("status")
    if not violations and status in {None, "pass", "ok"}:
        return []
    return [
        {
            "surface": "rch_sync_retrieval",
            "source": source.id,
            "label": "rch_artifact_sync",
            "signal": "artifact_sync_preflight",
            "status": status,
            "violation_count": len(violations),
        }
    ]


def extract_core_bottlenecks(runpack: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    rch = runpack["rch_admission"]
    queue_forecast = (
        rch.get("queue_forecast")
        if isinstance(rch.get("queue_forecast"), dict)
        else {}
    )
    if rch.get("decision") in {"backoff", "degraded", "deny"}:
        findings.append(
            {
                "surface": "rch_sync_retrieval",
                "source": "cargo_admission",
                "label": "cargo/RCH admission",
                "signal": "admission_decision",
                "decision": rch.get("decision"),
                "recommended_action": queue_forecast.get("recommended_action"),
                "slot_pressure": queue_forecast.get("slot_pressure"),
            }
        )
    if queue_forecast.get("recommended_action") in {"backoff", "split"}:
        findings.append(
            {
                "surface": "queue_pressure",
                "source": "cargo_admission",
                "label": "RCH queue forecast",
                "signal": "queue_forecast",
                "recommended_action": queue_forecast.get("recommended_action"),
                "queue_depth": queue_forecast.get("queue_depth"),
                "active_builds": queue_forecast.get("active_builds"),
                "queued_builds": queue_forecast.get("queued_builds"),
            }
        )
    activity = runpack["activity_digest"]
    if activity.get("saturated") is True:
        findings.append(
            {
                "surface": "queue_pressure",
                "source": "activity_digest",
                "label": "swarm activity saturation",
                "signal": "activity_digest_saturation",
                "reasons": activity.get("reasons"),
                "evidence_pointers": activity.get("evidence_pointers"),
            }
        )
    doctor = runpack["doctor_swarm"]
    severity_counts = (
        doctor.get("severity_counts")
        if isinstance(doctor.get("severity_counts"), dict)
        else {}
    )
    if doctor.get("overall") in {"warn", "fail"} or severity_counts.get("warn") or severity_counts.get("fail"):
        findings.append(
            {
                "surface": "cgroup_numa_context",
                "source": "doctor_swarm",
                "label": "doctor swarm findings",
                "signal": "doctor_swarm_overall",
                "overall": doctor.get("overall"),
                "severity_counts": severity_counts,
            }
        )
    return findings


def build_bottleneck_attribution(
    runpack: dict[str, Any],
    by_id: dict[str, SourcePayload],
    *,
    generated_at: datetime,
    stale_after_hours: int,
    max_items: int,
) -> dict[str, Any]:
    classifications: list[dict[str, Any]] = []
    for source_id in BOTTLENECK_CORE_SOURCE_IDS:
        source = by_id[source_id]
        classifications.append(
            classify_bottleneck_source(
                source,
                generated_at=generated_at,
                stale_after_hours=stale_after_hours,
                required=True,
            )
        )
    for source_id in BOTTLENECK_OPTIONAL_SOURCE_IDS:
        source = by_id.get(source_id, SourcePayload(source_id, None, "not_provided", None, None))
        classifications.append(
            classify_bottleneck_source(
                source,
                generated_at=generated_at,
                stale_after_hours=stale_after_hours,
                required=False,
            )
        )
    classifications_by_id = {item["id"]: item for item in classifications}
    surface_coverage = {
        surface_id: summarize_surface(surface_id, source_ids, classifications_by_id)
        for surface_id, source_ids in BOTTLENECK_SURFACES.items()
    }
    bottlenecks = extract_core_bottlenecks(runpack)
    if by_id.get("tail_latency") is not None:
        bottlenecks.extend(extract_tail_latency_bottlenecks(by_id["tail_latency"], max_items))
    if by_id.get("flight_recorder") is not None:
        bottlenecks.extend(extract_flight_recorder_bottlenecks(by_id["flight_recorder"], max_items))
    if by_id.get("hostcall_swarm_profile") is not None:
        bottlenecks.extend(extract_hostcall_bottlenecks(by_id["hostcall_swarm_profile"], max_items))
    if by_id.get("session_recovery_swarm_profile") is not None:
        bottlenecks.extend(extract_session_bottlenecks(by_id["session_recovery_swarm_profile"]))
    if by_id.get("rch_artifact_sync") is not None:
        bottlenecks.extend(extract_rch_sync_bottlenecks(by_id["rch_artifact_sync"]))
    blocked_sources = [
        item["id"] for item in classifications if item.get("classification") == "blocker"
    ]
    historical_sources = [
        item["id"] for item in classifications if item.get("classification") == "historical_snapshot"
    ]
    missing_optional = [
        item["id"] for item in classifications if item.get("classification") == "optional_diagnostic"
    ]
    blocked_surfaces = [
        surface_id
        for surface_id, surface in surface_coverage.items()
        if surface.get("status") == "blocked"
    ]
    status = "ready"
    if blocked_sources or historical_sources or blocked_surfaces:
        status = "degraded"
    return {
        "schema": BOTTLENECK_ATTRIBUTION_SCHEMA,
        "generated_at": generated_at.isoformat(),
        "status": status,
        "purpose": "operator_diagnostic_not_release_performance_claim",
        "stale_after_hours": stale_after_hours,
        "surface_coverage": surface_coverage,
        "input_classification": classifications,
        "bottlenecks": bounded(bottlenecks, max_items),
        "missing_optional_diagnostics": missing_optional,
        "historical_snapshots": historical_sources,
        "blocked_inputs": blocked_sources,
        "operator_notes": [
            "Use this dashboard for swarm bottleneck attribution only.",
            "Do not turn diagnostic evidence into release-facing performance or drop-in claims without claim-integrity gates.",
        ],
    }


def parse_issue_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("issues"), list):
        return [item for item in payload["issues"] if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def summarize_beads(
    source: SourcePayload,
    *,
    generated_at: datetime,
    stale_after_hours: int,
    max_items: int,
) -> dict[str, Any]:
    issues = parse_issue_list(source.payload)
    status_counts = Counter(str(issue.get("status") or "unknown") for issue in issues)
    active = [issue for issue in issues if issue.get("status") in {"open", "in_progress"}]
    stale: list[dict[str, Any]] = []
    for issue in active:
        updated_at = str(issue.get("updated_at") or "")
        try:
            updated = parse_utc(updated_at)
        except ValueError:
            age_hours = None
        else:
            age_hours = max(0.0, (generated_at - updated).total_seconds() / 3600)
        if age_hours is None or age_hours >= stale_after_hours:
            stale.append(
                {
                    "id": issue.get("id"),
                    "title": issue.get("title"),
                    "status": issue.get("status"),
                    "assignee": issue.get("assignee"),
                    "updated_at": updated_at,
                    "age_hours": round(age_hours, 2) if age_hours is not None else None,
                }
            )
    return {
        "status": source.status,
        "total_issues": len(issues),
        "status_counts": dict(sorted(status_counts.items())),
        "active_count": len(active),
        "stale_after_hours": stale_after_hours,
        "stale": bounded(stale, max_items),
    }


def summarize_smoke_harness(source: SourcePayload, max_items: int) -> dict[str, Any]:
    payload = source.payload
    if not isinstance(payload, dict):
        return {"status": source.status}
    scenarios = payload.get("scenarios") if isinstance(payload.get("scenarios"), dict) else {}
    scenario_statuses = {
        name: scenario.get("status")
        for name, scenario in scenarios.items()
        if isinstance(scenario, dict)
    }
    return {
        "status": source.status,
        "harness_status": payload.get("status"),
        "correlation_id": payload.get("correlation_id"),
        "scenario_statuses": scenario_statuses,
        "failed_scenarios": bounded(payload.get("failed_scenarios") or [], max_items),
        "reservation_count": len(payload.get("reservation_ids") or []),
        "artifact_paths": payload.get("artifacts"),
        "artifact_manifest": bounded(payload.get("artifact_manifest") or [], max_items),
    }


def summarize_activity_digest(source: SourcePayload, max_items: int) -> dict[str, Any]:
    payload = source.payload
    if not isinstance(payload, dict):
        return {"status": source.status}
    saturation = payload.get("saturation") if isinstance(payload.get("saturation"), dict) else {}
    recommendations = payload.get("recommendations") if isinstance(payload.get("recommendations"), list) else []
    return {
        "status": source.status,
        "source_path": source.path,
        "saturated": saturation.get("saturated"),
        "signals": bounded(saturation.get("signals") or [], max_items),
        "reasons": bounded(saturation.get("reasons") or [], max_items),
        "evidence_pointers": bounded(saturation.get("evidence_pointers") or [], max_items),
        "recommendations": bounded(recommendations, max_items),
    }


def summarize_cargo_admission(source: SourcePayload) -> dict[str, Any]:
    payload = source.payload
    if not isinstance(payload, dict):
        return {"status": source.status}
    forecast = payload.get("rch_queue_forecast")
    queue_forecast = forecast if isinstance(forecast, dict) else {}
    return {
        "status": source.status,
        "decision": payload.get("decision"),
        "reason": payload.get("reason"),
        "requested_runner": payload.get("requested_runner"),
        "resolved_runner": payload.get("resolved_runner"),
        "command_class": payload.get("command_class"),
        "allow_local_fallback": payload.get("allow_local_fallback"),
        "cargo_target_dir": payload.get("cargo_target_dir"),
        "tmpdir": payload.get("tmpdir"),
        "storage_remediation": payload.get("storage_remediation"),
        "queue_forecast": {
            "status": queue_forecast.get("status"),
            "recommended_action": queue_forecast.get("recommended_action"),
            "reason": queue_forecast.get("reason"),
            "slot_pressure": queue_forecast.get("slot_pressure"),
            "queue_depth": queue_forecast.get("queue_depth"),
            "active_builds": queue_forecast.get("active_builds"),
            "queued_builds": queue_forecast.get("queued_builds"),
            "slots_available": queue_forecast.get("slots_available"),
            "slots_total": queue_forecast.get("slots_total"),
            "workers_healthy": queue_forecast.get("workers_healthy"),
            "workers_total": queue_forecast.get("workers_total"),
            "estimated_wait_seconds": queue_forecast.get("estimated_wait_seconds"),
        },
    }


def summarize_git_status(source: SourcePayload, max_items: int) -> dict[str, Any]:
    payload = source.payload
    if not isinstance(payload, dict):
        return {"status": source.status}
    lines = payload.get("porcelain_lines") if isinstance(payload.get("porcelain_lines"), list) else []
    entries = []
    for line in lines:
        text = str(line)
        entries.append({"status": text[:2], "path": text[3:] if len(text) > 3 else text})
    return {
        "status": source.status,
        "dirty": bool(lines),
        "change_count": len(lines),
        "sample": bounded(entries, max_items),
    }


def int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return 0


def source_status_for(runpack: dict[str, Any], source_id: str) -> str | None:
    for source in runpack.get("source_statuses", []):
        if isinstance(source, dict) and source.get("id") == source_id:
            status = source.get("status")
            return str(status) if status is not None else None
    return None


def required_evidence_gaps(
    runpack: dict[str, Any],
    *,
    required_source_ids: tuple[str, ...],
    evidence_paths: tuple[str, ...],
) -> list[str]:
    missing = [
        f"source_statuses[{source_id}].status"
        for source_id in required_source_ids
        if source_status_for(runpack, source_id) != "ok"
    ]
    for path in evidence_paths:
        try:
            value = get_dotted(runpack, path)
        except KeyError:
            missing.append(path)
            continue
        if value is None:
            missing.append(path)
    return missing


def scorecard_dimension(
    *,
    runpack: dict[str, Any],
    dimension_id: str,
    title: str,
    required_source_ids: tuple[str, ...],
    evidence_paths: tuple[str, ...],
    blockers: list[str],
    warnings: list[str],
    detail: str,
) -> dict[str, Any]:
    missing_evidence = required_evidence_gaps(
        runpack,
        required_source_ids=required_source_ids,
        evidence_paths=evidence_paths,
    )
    all_blockers = list(blockers)
    if missing_evidence:
        all_blockers.insert(0, "missing required evidence")
    if all_blockers:
        score = 0
        status = "red"
    elif warnings:
        score = 1
        status = "yellow"
    else:
        score = SCORECARD_MAX_PER_DIMENSION
        status = "green"
    return {
        "id": dimension_id,
        "title": title,
        "status": status,
        "score": score,
        "max_score": SCORECARD_MAX_PER_DIMENSION,
        "required_source_ids": list(required_source_ids),
        "evidence_paths": list(evidence_paths),
        "missing_evidence": missing_evidence,
        "green_requires": {
            "all_required_sources_ok": all(
                source_status_for(runpack, source_id) == "ok"
                for source_id in required_source_ids
            ),
            "all_required_evidence_present": not missing_evidence,
            "no_blockers": not all_blockers,
        },
        "blockers": all_blockers,
        "warnings": warnings,
        "detail": detail,
    }


def build_swarm_scale_safety_scorecard(runpack: dict[str, Any]) -> dict[str, Any]:
    doctor = runpack["doctor_swarm"]
    agent_mail = runpack["agent_mail"]
    rch = runpack["rch_admission"]
    evidence = runpack["evidence_readiness"]
    git_state = runpack["git_state"]
    beads = runpack["beads"]
    activity = runpack["activity_digest"]
    smoke = runpack["smoke_harness"]

    severity_counts = (
        doctor.get("severity_counts")
        if isinstance(doctor.get("severity_counts"), dict)
        else {}
    )
    coordination_blockers: list[str] = []
    coordination_warnings: list[str] = []
    if doctor.get("overall") == "fail" or int_value(severity_counts.get("fail")):
        coordination_blockers.append("doctor swarm findings include failures")
    if doctor.get("overall") == "warn" or int_value(severity_counts.get("warn")):
        coordination_warnings.append("doctor swarm findings include warnings")
    if not agent_mail.get("build_slots"):
        coordination_blockers.append("Agent Mail build-slot evidence is absent")

    queue_forecast = (
        rch.get("queue_forecast")
        if isinstance(rch.get("queue_forecast"), dict)
        else {}
    )
    rch_decision = rch.get("decision")
    queue_action = queue_forecast.get("recommended_action")
    cargo_blockers: list[str] = []
    cargo_warnings: list[str] = []
    if rch_decision in {"backoff", "deny"}:
        cargo_blockers.append(f"cargo/RCH admission decision is {rch_decision}")
    elif rch_decision == "degraded":
        cargo_warnings.append("cargo/RCH admission fell back to degraded mode")
    elif rch_decision not in {"allow", "admit"}:
        cargo_warnings.append(f"cargo/RCH admission decision is {rch_decision}")
    if queue_action == "backoff":
        cargo_blockers.append("RCH queue forecast recommends backoff")
    elif queue_action == "split":
        cargo_warnings.append("RCH queue forecast recommends split validation")
    if queue_forecast.get("slot_pressure") == "saturated":
        cargo_blockers.append("RCH queue forecast reports saturated slots")

    stale_claims = (
        evidence.get("stale_claims")
        if isinstance(evidence.get("stale_claims"), dict)
        else {}
    )
    stale_count = int_value(stale_claims.get("stale_count"))
    perf_blockers: list[str] = []
    perf_warnings: list[str] = []
    if evidence.get("overall_status") != "ready":
        perf_blockers.append("claim-readiness evidence is not ready")
    if evidence.get("blocking_artifacts"):
        perf_blockers.append("claim-readiness evidence has blocking artifacts")
    if stale_count:
        perf_warnings.append(f"claim-readiness evidence has {stale_count} stale claims")

    scenario_statuses = (
        smoke.get("scenario_statuses")
        if isinstance(smoke.get("scenario_statuses"), dict)
        else {}
    )
    dirty_scenario = scenario_statuses.get("dirty_worktree_preserved")
    dirty_blockers: list[str] = []
    dirty_warnings: list[str] = []
    if dirty_scenario != "pass":
        dirty_blockers.append("smoke harness did not prove dirty-worktree preservation")
    if git_state.get("dirty"):
        dirty_warnings.append("current captured git state is dirty")

    stalled_blockers: list[str] = []
    stalled_warnings: list[str] = []
    stale_beads = beads.get("stale") if isinstance(beads.get("stale"), list) else []
    if stale_beads:
        stalled_blockers.append(f"{len(stale_beads)} active Beads entries are stale")
    if int_value(beads.get("active_count")) == 0:
        stalled_warnings.append("Beads capture has no active work entries")

    resource_blockers: list[str] = []
    resource_warnings: list[str] = []
    if activity.get("saturated") is True:
        resource_blockers.append("activity digest reports swarm saturation")
    if queue_action == "backoff":
        resource_blockers.append("RCH queue forecast is in backoff")
    elif queue_action == "split":
        resource_warnings.append("RCH queue forecast needs split validation")
    if queue_forecast.get("slot_pressure") == "saturated":
        resource_blockers.append("RCH slot pressure is saturated")

    failed_scenarios = (
        smoke.get("failed_scenarios")
        if isinstance(smoke.get("failed_scenarios"), list)
        else []
    )
    non_pass_scenarios = [
        name
        for name, status in scenario_statuses.items()
        if status != "pass"
    ]
    coverage_blockers: list[str] = []
    coverage_warnings: list[str] = []
    if smoke.get("harness_status") != "pass":
        coverage_blockers.append("smoke harness status is not pass")
    if failed_scenarios:
        coverage_blockers.append("smoke harness reports failed scenarios")
    if non_pass_scenarios:
        coverage_blockers.append("smoke harness has non-pass scenario statuses")
    if not smoke.get("artifact_manifest"):
        coverage_blockers.append("smoke harness artifact manifest is empty")

    bottleneck = runpack["bottleneck_attribution"]
    bottleneck_blockers: list[str] = []
    bottleneck_warnings: list[str] = []
    blocked_inputs = bottleneck.get("blocked_inputs")
    historical_snapshots = bottleneck.get("historical_snapshots")
    missing_optional = bottleneck.get("missing_optional_diagnostics")
    if isinstance(blocked_inputs, list) and blocked_inputs:
        bottleneck_blockers.append("bottleneck attribution has blocked inputs")
    if isinstance(historical_snapshots, list) and historical_snapshots:
        bottleneck_warnings.append("bottleneck attribution includes historical snapshots")
    if isinstance(missing_optional, list) and missing_optional:
        bottleneck_warnings.append("bottleneck attribution has missing optional diagnostics")
    if bottleneck.get("status") != "ready":
        bottleneck_warnings.append("bottleneck attribution dashboard is degraded")

    dimensions = [
        scorecard_dimension(
            runpack=runpack,
            dimension_id="coordination_health",
            title="Coordination health",
            required_source_ids=("doctor_swarm", "smoke_harness"),
            evidence_paths=(
                "doctor_swarm.overall",
                "doctor_swarm.agent_mail_build_slots",
                "agent_mail.build_slots",
                "agent_mail.smoke_reservation_count",
            ),
            blockers=coordination_blockers,
            warnings=coordination_warnings,
            detail="Agent Mail and doctor evidence show whether coordination lanes are observable and unstuck.",
        ),
        scorecard_dimension(
            runpack=runpack,
            dimension_id="cargo_rch_posture",
            title="Cargo/RCH posture",
            required_source_ids=("cargo_admission",),
            evidence_paths=(
                "rch_admission.decision",
                "rch_admission.queue_forecast.status",
                "rch_admission.queue_forecast.recommended_action",
            ),
            blockers=cargo_blockers,
            warnings=cargo_warnings,
            detail="Cargo admission and RCH queue evidence decide whether heavy validation can start safely.",
        ),
        scorecard_dimension(
            runpack=runpack,
            dimension_id="perf_evidence_freshness",
            title="Performance evidence freshness",
            required_source_ids=("claim_readiness",),
            evidence_paths=(
                "evidence_readiness.overall_status",
                "evidence_readiness.blocking_artifacts",
                "evidence_readiness.stale_claims",
            ),
            blockers=perf_blockers,
            warnings=perf_warnings,
            detail="Claim-readiness artifacts must be ready, non-blocking, and fresh enough for release handoff.",
        ),
        scorecard_dimension(
            runpack=runpack,
            dimension_id="dirty_worktree_tolerance",
            title="Dirty-worktree tolerance",
            required_source_ids=("git_status", "smoke_harness"),
            evidence_paths=(
                "git_state.dirty",
                "git_state.sample",
                "smoke_harness.scenario_statuses",
            ),
            blockers=dirty_blockers,
            warnings=dirty_warnings,
            detail="Git status and the smoke harness prove unrelated dirty files are accounted for and preserved.",
        ),
        scorecard_dimension(
            runpack=runpack,
            dimension_id="stalled_bead_hygiene",
            title="Stalled-Bead hygiene",
            required_source_ids=("beads",),
            evidence_paths=(
                "beads.stale",
                "beads.stale_after_hours",
                "beads.active_count",
            ),
            blockers=stalled_blockers,
            warnings=stalled_warnings,
            detail="Beads evidence must not show stale active ownership before launching more swarm work.",
        ),
        scorecard_dimension(
            runpack=runpack,
            dimension_id="resource_governor_readiness",
            title="Resource-governor readiness",
            required_source_ids=("activity_digest", "cargo_admission"),
            evidence_paths=(
                "activity_digest.saturated",
                "activity_digest.evidence_pointers",
                "rch_admission.queue_forecast.recommended_action",
                "rch_admission.queue_forecast.slot_pressure",
            ),
            blockers=resource_blockers,
            warnings=resource_warnings,
            detail="Activity saturation and RCH queue posture decide whether the swarm should admit more work.",
        ),
        scorecard_dimension(
            runpack=runpack,
            dimension_id="bottleneck_attribution_coverage",
            title="Bottleneck attribution coverage",
            required_source_ids=(
                "doctor_swarm",
                "smoke_harness",
                "activity_digest",
                "cargo_admission",
            ),
            evidence_paths=(
                "bottleneck_attribution.status",
                "bottleneck_attribution.surface_coverage",
                "bottleneck_attribution.input_classification",
                "bottleneck_attribution.operator_notes",
            ),
            blockers=bottleneck_blockers,
            warnings=bottleneck_warnings,
            detail="Diagnostic bottleneck attribution must classify source freshness without promoting evidence to release claims.",
        ),
        scorecard_dimension(
            runpack=runpack,
            dimension_id="test_coverage",
            title="Test coverage",
            required_source_ids=("smoke_harness",),
            evidence_paths=(
                "smoke_harness.harness_status",
                "smoke_harness.scenario_statuses",
                "smoke_harness.artifact_manifest",
            ),
            blockers=coverage_blockers,
            warnings=coverage_warnings,
            detail="The smoke harness must pass and retain artifact-manifest evidence for the operator workflow.",
        ),
    ]
    total_score = sum(int_value(dimension["score"]) for dimension in dimensions)
    max_score = SCORECARD_MAX_PER_DIMENSION * len(dimensions)
    status_counts = Counter(str(dimension["status"]) for dimension in dimensions)
    return {
        "schema": SAFETY_SCORECARD_SCHEMA,
        "overall_status": "ready" if status_counts.get("green") == len(dimensions) else "degraded",
        "total_score": total_score,
        "max_score": max_score,
        "status_counts": dict(sorted(status_counts.items())),
        "green_requires_all_required_evidence": True,
        "dimensions": dimensions,
    }


def derive_status(runpack: dict[str, Any]) -> str:
    source_statuses = [item["status"] for item in runpack["source_statuses"]]
    if any(status == "ok" for status in source_statuses):
        status = "ready"
    else:
        status = "degraded"
    if any(status in {"missing", "not_provided"} for status in source_statuses):
        status = "degraded"
    doctor = runpack["doctor_swarm"]
    if doctor.get("overall") == "fail" or doctor.get("severity_counts", {}).get("fail", 0):
        status = "degraded"
    if runpack["evidence_readiness"].get("overall_status") not in {None, "ready"}:
        status = "degraded"
    if runpack["rch_admission"].get("decision") in {"backoff", "degraded", "deny"}:
        status = "degraded"
    if runpack["smoke_harness"].get("harness_status") == "fail":
        status = "degraded"
    if runpack["bottleneck_attribution"].get("status") != "ready":
        status = "degraded"
    scorecard = runpack.get("swarm_scale_safety_scorecard")
    if isinstance(scorecard, dict) and scorecard.get("overall_status") != "ready":
        status = "degraded"
    return status


def build_runpack(args: argparse.Namespace) -> dict[str, Any]:
    generated_at = parse_utc(args.generated_at) if args.generated_at else parse_utc(utc_now_iso())
    sources = source_payloads(args)
    by_id = {source.id: source for source in sources}
    redaction = RedactionStats()
    for source in sources:
        redaction.redacted_count += source.redacted_count
        redaction.fields.update(source.redacted_fields)
    doctor_summary = summarize_doctor(by_id["doctor_swarm"], args.max_items)
    smoke_summary = summarize_smoke_harness(by_id["smoke_harness"], args.max_items)
    runpack = {
        "schema": RUNPACK_SCHEMA,
        "generated_at": generated_at.isoformat(),
        "status": "unknown",
        "purpose": "operator_handoff_not_release_performance_claim",
        "source_statuses": [source.to_status() for source in sources],
        "doctor_swarm": doctor_summary,
        "beads": summarize_beads(
            by_id["beads"],
            generated_at=generated_at,
            stale_after_hours=args.stale_after_hours,
            max_items=args.max_items,
        ),
        "agent_mail": {
            "doctor_findings": doctor_summary.get("agent_mail_findings", []),
            "build_slots": doctor_summary.get("agent_mail_build_slots"),
            "smoke_reservation_count": smoke_summary.get("reservation_count"),
        },
        "rch_admission": summarize_cargo_admission(by_id["cargo_admission"]),
        "evidence_readiness": summarize_claim_readiness(by_id["claim_readiness"], args.max_items),
        "git_state": summarize_git_status(by_id["git_status"], args.max_items),
        "activity_digest": summarize_activity_digest(by_id["activity_digest"], args.max_items),
        "smoke_harness": smoke_summary,
        "redaction_summary": redaction.to_json(),
    }
    if "tail_latency" in by_id:
        runpack["tail_latency"] = summarize_tail_latency(
            by_id["tail_latency"],
            args.max_items,
        )
    runpack["bottleneck_attribution"] = build_bottleneck_attribution(
        runpack,
        by_id,
        generated_at=generated_at,
        stale_after_hours=args.stale_after_hours,
        max_items=args.max_items,
    )
    runpack["swarm_scale_safety_scorecard"] = build_swarm_scale_safety_scorecard(runpack)
    runpack["status"] = derive_status(runpack)
    runpack["operator_next_actions"] = operator_next_actions(runpack)
    return runpack


def operator_next_actions(runpack: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    missing = [
        item["id"]
        for item in runpack["source_statuses"]
        if item.get("status") in {"missing", "not_provided"}
    ]
    if missing:
        actions.append("Capture missing source artifacts: " + ", ".join(sorted(missing)))
    if runpack["doctor_swarm"].get("severity_counts", {}).get("fail", 0):
        actions.append("Resolve failing `pi doctor --only swarm --format json` findings")
    if runpack["beads"].get("stale"):
        actions.append("Review stale in-progress Beads before assigning more work")
    if runpack["rch_admission"].get("decision") in {"backoff", "degraded", "deny"}:
        actions.append("Treat cargo/RCH admission as blocked or degraded before heavy builds")
    forecast_action = runpack["rch_admission"].get("queue_forecast", {}).get("recommended_action")
    if forecast_action == "split":
        actions.append("Split heavy cargo validation based on RCH queue forecast pressure")
    elif forecast_action == "backoff":
        actions.append("Back off heavy cargo validation until the RCH queue forecast recovers")
    if runpack["activity_digest"].get("saturated"):
        actions.append("Use activity-digest saturation evidence to narrow or redirect the swarm")
    if runpack["git_state"].get("dirty"):
        actions.append("Account for dirty files before using the runpack as handoff evidence")
    bottleneck = runpack.get("bottleneck_attribution")
    if isinstance(bottleneck, dict) and bottleneck.get("status") != "ready":
        actions.append(
            "Review degraded bottleneck attribution dashboard before using it as current diagnostic evidence"
        )
    scorecard = runpack.get("swarm_scale_safety_scorecard")
    if isinstance(scorecard, dict) and scorecard.get("overall_status") != "ready":
        actions.append("Review degraded swarm-scale safety scorecard dimensions before release runpack signoff")
    if not actions:
        actions.append("Runpack sources are ready; proceed with the next unblocked Beads task")
    return actions


def render_markdown(runpack: dict[str, Any]) -> str:
    lines = [
        "# Swarm Operator Runpack",
        "",
        f"- Schema: `{runpack['schema']}`",
        f"- Status: `{runpack['status']}`",
        f"- Generated: `{runpack['generated_at']}`",
        f"- Purpose: `{runpack['purpose']}`",
        "",
        "## Sources",
    ]
    for source in runpack["source_statuses"]:
        lines.append(
            f"- `{source['id']}`: `{source['status']}`"
            + (f" ({source['path']})" if source.get("path") else "")
        )
    lines.extend(["", "## Next Actions"])
    lines.extend(f"- {action}" for action in runpack["operator_next_actions"])
    lines.extend(["", "## Summaries"])
    lines.append(f"- Doctor swarm overall: `{runpack['doctor_swarm'].get('overall')}`")
    lines.append(f"- Beads active/stale: `{runpack['beads'].get('active_count')}` active, `{len(runpack['beads'].get('stale') or [])}` stale")
    lines.append(f"- RCH admission: `{runpack['rch_admission'].get('decision')}`")
    lines.append(f"- RCH queue forecast: `{runpack['rch_admission'].get('queue_forecast', {}).get('recommended_action')}`")
    lines.append(f"- Evidence readiness: `{runpack['evidence_readiness'].get('overall_status')}`")
    lines.append(f"- Git dirty: `{runpack['git_state'].get('dirty')}`")
    lines.append(f"- Activity saturated: `{runpack['activity_digest'].get('saturated')}`")
    lines.append(f"- Bottleneck attribution: `{runpack['bottleneck_attribution'].get('status')}`")
    if isinstance(runpack.get("tail_latency"), dict):
        tail_latency = runpack["tail_latency"]
        lines.append(
            f"- Tail latency telemetry: `{tail_latency.get('telemetry_enabled')}` "
            f"({len(tail_latency.get('metrics') or [])} metrics)"
        )
    scorecard = runpack["swarm_scale_safety_scorecard"]
    lines.extend(["", "## Safety Scorecard"])
    lines.append(
        f"- Overall: `{scorecard.get('overall_status')}` "
        f"({scorecard.get('total_score')}/{scorecard.get('max_score')})"
    )
    for dimension in scorecard.get("dimensions", []):
        lines.append(
            f"- `{dimension['id']}`: `{dimension['status']}` "
            f"({dimension['score']}/{dimension['max_score']})"
        )
    bottleneck = runpack["bottleneck_attribution"]
    lines.extend(["", "## Bottleneck Attribution"])
    for surface_id, surface in bottleneck.get("surface_coverage", {}).items():
        lines.append(f"- `{surface_id}`: `{surface.get('status')}`")
    for item in bottleneck.get("bottlenecks", []):
        lines.append(
            f"- `{item.get('surface')}` from `{item.get('source')}`: "
            f"{item.get('signal')}"
        )
    lines.append("")
    return "\n".join(lines)


def write_outputs(args: argparse.Namespace, runpack: dict[str, Any]) -> None:
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        if args.out_json.exists():
            raise RunpackError(f"refusing to overwrite existing JSON runpack: {args.out_json}")
        args.out_json.write_text(json_dumps(runpack, pretty=True), encoding="utf-8")
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        if args.out_md.exists():
            raise RunpackError(f"refusing to overwrite existing Markdown runpack: {args.out_md}")
        args.out_md.write_text(render_markdown(runpack), encoding="utf-8")


def write_json(path: Path, payload: Any) -> Path:
    path.write_text(json_dumps(payload, pretty=True), encoding="utf-8")
    return path


def get_dotted(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(path)
        current = current[part]
    return current


def assert_runpack_contract(runpack: dict[str, Any]) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    contract_path = repo_root / RUNPACK_CONTRACT_PATH
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AssertionError(f"missing runpack contract: {contract_path}") from exc
    except json.JSONDecodeError as exc:
        raise AssertionError(f"runpack contract is malformed JSON: {contract_path}: {exc}") from exc
    assert contract.get("schema") == RUNPACK_CONTRACT_SCHEMA
    assert contract.get("runpack_schema") == RUNPACK_SCHEMA
    assert runpack.get("schema") == contract["runpack_schema"]
    assert runpack.get("purpose") == contract.get("purpose")
    assert runpack.get("status") in set(contract.get("allowed_statuses", []))
    for key in contract.get("required_top_level_keys", []):
        assert key in runpack, f"missing top-level runpack key: {key}"
    source_ids = {
        item.get("id")
        for item in runpack.get("source_statuses", [])
        if isinstance(item, dict)
    }
    required_source_ids = set(contract.get("required_source_ids", []))
    optional_source_ids = set(contract.get("optional_source_ids", []))
    assert source_ids.issuperset(required_source_ids)
    unknown_source_ids = source_ids - required_source_ids - optional_source_ids
    assert not unknown_source_ids, f"unexpected source ids: {sorted(unknown_source_ids)}"
    for path in contract.get("required_summary_paths", []):
        get_dotted(runpack, path)
    for path in contract.get("optional_summary_paths", []):
        top_level_key = path.split(".", maxsplit=1)[0]
        if top_level_key in runpack:
            get_dotted(runpack, path)
    scorecard = runpack.get("swarm_scale_safety_scorecard")
    assert isinstance(scorecard, dict)
    assert scorecard.get("schema") == contract.get("scorecard_schema")
    assert scorecard.get("overall_status") in set(contract.get("allowed_scorecard_statuses", []))
    dimensions = scorecard.get("dimensions")
    assert isinstance(dimensions, list) and dimensions
    dimension_ids = {
        dimension.get("id")
        for dimension in dimensions
        if isinstance(dimension, dict)
    }
    assert dimension_ids == set(contract.get("required_scorecard_dimensions", []))
    for dimension in dimensions:
        assert isinstance(dimension, dict)
        assert dimension.get("status") in set(contract.get("allowed_dimension_statuses", []))
        assert dimension.get("max_score") == SCORECARD_MAX_PER_DIMENSION
        assert isinstance(dimension.get("required_source_ids"), list) and dimension.get(
            "required_source_ids"
        )
        assert isinstance(dimension.get("evidence_paths"), list) and dimension.get("evidence_paths")
        assert isinstance(dimension.get("missing_evidence"), list)
        green_requires = dimension.get("green_requires")
        assert isinstance(green_requires, dict)
        all_required_evidence_present = not dimension["missing_evidence"]
        assert (
            green_requires.get("all_required_evidence_present")
            is all_required_evidence_present
        )
        if dimension.get("status") == "green":
            assert not dimension["missing_evidence"]
            assert green_requires.get("all_required_sources_ok") is True
            assert green_requires.get("all_required_evidence_present") is True
            assert green_requires.get("no_blockers") is True
    for field in contract.get("required_source_status_fields", []):
        for source in runpack.get("source_statuses", []):
            if isinstance(source, dict) and source.get("status") == "ok":
                assert source.get(field) not in {None, ""}, (
                    f"source {source.get('id')} missing required status field {field}"
                )
    redaction = runpack.get("redaction_summary")
    assert isinstance(redaction, dict)
    assert redaction.get("redacted_count", 0) >= contract.get("minimum_redacted_count", 0)
    fields = set(redaction.get("fields", []))
    assert fields.issuperset(set(contract.get("required_redacted_fields", [])))
    actions = runpack.get("operator_next_actions")
    assert isinstance(actions, list) and actions
    action_text = "\n".join(str(action) for action in actions)
    for fragment in contract.get("required_next_action_fragments", []):
        assert fragment in action_text, f"missing next-action fragment: {fragment}"


def canonicalize_for_golden(value: Any, workspace: Path) -> Any:
    workspace_text = str(workspace)
    if isinstance(value, dict):
        return {
            key: "[SHA256]"
            if key == "sha256" and isinstance(item, str)
            else canonicalize_for_golden(item, workspace)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [canonicalize_for_golden(item, workspace) for item in value]
    if isinstance(value, str):
        return value.replace(workspace_text, "[WORKSPACE]")
    return value


def assert_runpack_golden(runpack: dict[str, Any], workspace: Path) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    golden_path = repo_root / GOLDEN_REPORT_DIRECTORY / COMPLETE_RUNPACK_GOLDEN
    actual_projection = canonicalize_for_golden(runpack, workspace)
    actual = json_dumps(actual_projection, pretty=True)
    if os.environ.get(UPDATE_GOLDEN_ENV) == "1":
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(actual, encoding="utf-8")
        return
    try:
        expected = golden_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AssertionError(
            f"missing runpack golden {golden_path}; rerun with {UPDATE_GOLDEN_ENV}=1"
        ) from exc
    if actual != expected:
        diff = "\n".join(
            difflib.unified_diff(
                expected.splitlines(),
                actual.splitlines(),
                fromfile=str(golden_path),
                tofile="actual swarm operator runpack projection",
                lineterm="",
            )
        )
        raise AssertionError(
            "swarm operator runpack projection changed; update the golden only "
            f"after reviewing the diff with `{UPDATE_GOLDEN_ENV}=1 "
            "python3 scripts/build_swarm_operator_runpack.py --self-test`\n"
            + diff
        )


def run_self_test() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="pi_swarm_runpack_"))
    generated_at = "2026-05-09T09:00:00+00:00"
    doctor_path = write_json(
        workspace / "doctor.json",
        {
            "overall": "warn",
            "summary": {"pass": 1, "info": 0, "warn": 1, "fail": 0},
            "findings": [
                {
                    "category": "swarm",
                    "severity": "warn",
                    "title": "Agent Mail reservations expire soon",
                    "detail": "token=super-secret-value should be redacted",
                    "remediation": "Renew active reservations before long-running verification",
                    "data": {"schema": "pi.doctor.agent_mail_build_slots.v1", "active": 1},
                    "fixability": "not_fixable",
                }
            ],
        },
    )
    claim_path = write_json(
        workspace / "claim.json",
        {
            "schema": "pi.swarm.claim_readiness_report.v1",
            "overall_status": "ready",
            "max_age_days": 14,
            "artifact_statuses": [
                {
                    "id": "activity_ledger_digest",
                    "category": "activity_ledger",
                    "status": "ready",
                    "release_blocking": True,
                    "issue_kinds": [],
                }
            ],
            "stale_claims": {"summary": {"stale_count": 0}},
        },
    )
    smoke_path = write_json(
        workspace / "smoke.json",
        {
            "schema": "pi.swarm.smoke_harness.v1",
            "status": "pass",
            "correlation_id": "selftest",
            "reservation_ids": [1],
            "failed_scenarios": [],
            "scenarios": {
                "reservation_conflict": {"status": "pass"},
                "dirty_worktree_preserved": {"status": "pass"},
            },
            "artifacts": {"summary_json": str(workspace / "smoke.json")},
            "artifact_manifest": [
                {
                    "id": "events_jsonl",
                    "path": str(workspace / "events.jsonl"),
                    "size_bytes": 128,
                    "sha256": "a" * 64,
                }
            ],
        },
    )
    activity_path = write_json(
        workspace / "activity.json",
        {
            "schema": "pi.swarm.activity_digest.v1",
            "saturation": {
                "saturated": True,
                "signals": ["high_chatter_low_throughput"],
                "reasons": ["7 coordination events and 1 throughput event"],
                "evidence_pointers": ["agent:MagentaOak"],
            },
            "recommendations": [{"mode": "testing-golden-artifacts"}],
        },
    )
    cargo_path = write_json(
        workspace / "cargo.json",
        {
            "schema": "pi.cargo_headroom.admission.v1",
            "decision": "backoff",
            "reason": "rch_queue_saturated",
            "requested_runner": "auto",
            "resolved_runner": "none",
            "command_class": "heavy",
            "allow_local_fallback": False,
            "cargo_target_dir": "/data/tmp/pi_agent_rust_cargo/test/target",
            "tmpdir": "/data/tmp/pi_agent_rust_cargo/test/tmp",
            "rch_queue_forecast": {
                "schema": "pi.cargo_headroom.rch_queue_forecast.v1",
                "status": "ok",
                "recommended_action": "backoff",
                "reason": "queue_saturated",
                "slot_pressure": "saturated",
                "queue_depth": 4,
                "active_builds": 8,
                "queued_builds": 4,
                "slots_available": 0,
                "slots_total": 8,
                "workers_healthy": 1,
                "workers_total": 8,
                "estimated_wait_seconds": 240,
            },
        },
    )
    beads_path = write_json(
        workspace / "beads.json",
        {
            "issues": [
                {
                    "id": "bd-stale",
                    "title": "Stale fixture",
                    "status": "in_progress",
                    "assignee": "GreenStone",
                    "updated_at": "2026-05-08T00:00:00+00:00",
                },
                {
                    "id": "bd-open",
                    "title": "Open fixture",
                    "status": "open",
                    "updated_at": generated_at,
                },
            ]
        },
    )
    git_path = workspace / "git-status.txt"
    git_path.write_text(" M src/doctor.rs\n?? scripts/new-tool.py\n", encoding="utf-8")
    tail_latency_path = write_json(
        workspace / "tail-latency.json",
        {
            "schema": TAIL_LATENCY_SCHEMA,
            "generated_at": generated_at,
            "purpose": "operator_observability_not_release_performance_claim",
            "telemetry_enabled": True,
            "sample_window": 512,
            "redaction_summary": {
                "redacted_count": 0,
                "fields": [],
                "policy": "timing_only_no_prompt_or_tool_payload_fields",
            },
            "metrics": [
                {
                    "id": "provider_streaming",
                    "label": "Provider streaming",
                    "snapshot": {
                        "count": 3,
                        "total_us": 600,
                        "max_us": 300,
                        "avg_us": 200,
                        "tail": {
                            "sample_window": 512,
                            "sample_count": 3,
                            "p95_us": 300,
                            "p99_us": 300,
                            "p999_us": 300,
                        },
                    },
                }
            ],
        },
    )
    flight_recorder_path = write_json(
        workspace / "flight-recorder-report.json",
        {
            "schema": FLIGHT_RECORDER_REPORT_SCHEMA,
            "generated_at": generated_at,
            "dominant_latency_components": [
                {"component": "provider_streaming", "count": 3, "total_us": 900},
                {"component": "tool_execution", "count": 2, "total_us": 250},
            ],
            "component_counts": {"provider": 3, "tool": 2, "session": 2},
            "coordination_failures": [],
        },
    )
    host_preflight_path = write_json(
        workspace / "host-preflight.json",
        {
            "schema": HOST_PREFLIGHT_SCHEMA,
            "generated_at": generated_at,
            "status": "pass",
            "cpu": {
                "logical": 16,
                "effective": 8,
                "cgroup_quota": {"quota_cores": 8.0, "unlimited": False},
                "cpuset_cpus": 8,
            },
            "numa": {"node_count": 2, "nodes": [0, 1]},
            "memory": {"cgroup_limit_bytes": 34359738368},
            "recommended_budgets": {"agent_fanout": 4, "rch_verification_fanout": 2},
            "critical_failures": [],
        },
    )
    hostcall_profile_path = write_json(
        workspace / "hostcall-profile.json",
        {
            "schema": HOSTCALL_SWARM_PROFILE_SCHEMA,
            "generated_at": generated_at,
            "agents": 4,
            "hostcalls_per_agent": 32,
            "profiles": [
                {
                    "mode": "compat",
                    "accepted_requests": 128,
                    "completed_requests": 128,
                    "p99_tail_latency_steps": 4,
                    "max_tail_latency_steps": 6,
                }
            ],
        },
    )
    session_profile_path = write_json(
        workspace / "session-recovery-profile.json",
        {
            "schema": SESSION_RECOVERY_SWARM_PROFILE_SCHEMA,
            "generated_at": generated_at,
            "counts": {
                "base_entries": 200,
                "tail_entries_appended": 32,
                "recovered_entries_after_truncation": 200,
            },
            "timings_us": {"recover": 800, "index": 1500, "save": 700},
        },
    )
    rpc_swarm_path = write_json(
        workspace / "rpc-swarm-e2e.json",
        {
            "schema": RPC_SWARM_E2E_SCHEMA,
            "generated_at": generated_at,
            "status": "pass",
            "sessions": 3,
            "command_ids": ["cmd-a", "cmd-b", "cmd-c"],
            "filesystem_state": "preserved",
            "session_index": "updated",
        },
    )
    rch_artifact_sync_path = write_json(
        workspace / "rch-artifact-sync.json",
        {
            "schema": RCH_ARTIFACT_SYNC_SCHEMA,
            "generated_at": generated_at,
            "status": "pass",
            "required_paths": [
                {"path": "tests/perf/reports/bench_schema_registry.json", "included": True}
            ],
            "violations": [],
        },
    )

    args = argparse.Namespace(
        doctor_json=doctor_path,
        claim_readiness_json=claim_path,
        smoke_summary_json=smoke_path,
        activity_digest_json=activity_path,
        cargo_admission_json=cargo_path,
        beads_json=beads_path,
        git_status_file=git_path,
        tail_latency_json=tail_latency_path,
        flight_recorder_report_json=flight_recorder_path,
        host_preflight_json=host_preflight_path,
        hostcall_swarm_profile_json=hostcall_profile_path,
        session_recovery_swarm_profile_json=session_profile_path,
        rpc_swarm_e2e_json=rpc_swarm_path,
        rch_artifact_sync_json=rch_artifact_sync_path,
        out_json=workspace / "runpack.json",
        out_md=workspace / "runpack.md",
        generated_at=generated_at,
        stale_after_hours=24,
        max_items=4,
    )
    try:
        runpack = build_runpack(args)
        write_outputs(args, runpack)
        assert runpack["schema"] == RUNPACK_SCHEMA
        assert runpack["status"] == "degraded"
        assert runpack["agent_mail"]["build_slots"]["data"]["active"] == 1
        assert runpack["beads"]["stale"][0]["id"] == "bd-stale"
        assert runpack["rch_admission"]["queue_forecast"]["recommended_action"] == "backoff"
        assert runpack["activity_digest"]["saturated"] is True
        assert runpack["git_state"]["dirty"] is True
        dashboard = runpack["bottleneck_attribution"]
        assert dashboard["schema"] == BOTTLENECK_ATTRIBUTION_SCHEMA
        assert dashboard["purpose"] == "operator_diagnostic_not_release_performance_claim"
        assert dashboard["surface_coverage"]["provider_streaming"]["status"] == "covered"
        assert dashboard["surface_coverage"]["local_tools"]["status"] == "covered"
        assert dashboard["surface_coverage"]["extension_hostcalls"]["status"] == "covered"
        assert dashboard["surface_coverage"]["persistence"]["status"] == "covered"
        assert dashboard["surface_coverage"]["rch_sync_retrieval"]["status"] == "covered"
        assert dashboard["surface_coverage"]["queue_pressure"]["status"] == "covered"
        assert dashboard["surface_coverage"]["cgroup_numa_context"]["status"] == "covered"
        assert any(
            item["id"] == "rpc_swarm_e2e" and item["classification"] == "fresh"
            for item in dashboard["input_classification"]
        )
        assert any(
            item["id"] == "session_recovery_swarm_profile"
            and item["classification"] == "fresh"
            for item in dashboard["input_classification"]
        )
        scorecard = runpack["swarm_scale_safety_scorecard"]
        assert scorecard["schema"] == SAFETY_SCORECARD_SCHEMA
        assert scorecard["overall_status"] == "degraded"
        scorecard_dimensions = {
            dimension["id"]: dimension for dimension in scorecard["dimensions"]
        }
        assert set(scorecard_dimensions) == {
            "coordination_health",
            "cargo_rch_posture",
            "perf_evidence_freshness",
            "dirty_worktree_tolerance",
            "stalled_bead_hygiene",
            "resource_governor_readiness",
            "bottleneck_attribution_coverage",
            "test_coverage",
        }
        assert scorecard_dimensions["cargo_rch_posture"]["status"] == "red"
        assert scorecard_dimensions["test_coverage"]["status"] == "green"
        for dimension in scorecard_dimensions.values():
            assert dimension["evidence_paths"]
            if dimension["status"] == "green":
                assert dimension["missing_evidence"] == []
        assert runpack["tail_latency"]["schema"] == TAIL_LATENCY_SCHEMA
        assert runpack["tail_latency"]["redaction_summary"]["policy"] == (
            "timing_only_no_prompt_or_tool_payload_fields"
        )
        assert runpack["tail_latency"]["metrics"][0]["p999_us"] == 300
        assert runpack["smoke_harness"]["artifact_manifest"][0]["sha256"] == "a" * 64
        for source in runpack["source_statuses"]:
            assert source["size_bytes"] is not None
            assert len(source["sha256"]) == 64
        assert runpack["redaction_summary"]["redacted_count"] >= 1
        assert args.out_json.exists() and args.out_md.exists()
        assert "Tail latency telemetry" in args.out_md.read_text(encoding="utf-8")
        assert "Bottleneck Attribution" in args.out_md.read_text(encoding="utf-8")
        assert_runpack_contract(runpack)
        assert_runpack_golden(runpack, workspace)
        malformed = workspace / "malformed.json"
        malformed.write_text("{not valid json", encoding="utf-8")
        bad_args = argparse.Namespace(**{**vars(args), "doctor_json": malformed})
        try:
            build_runpack(bad_args)
        except RunpackError as exc:
            assert "malformed JSON" in str(exc)
        else:
            raise AssertionError("malformed provided source should fail closed")
        no_tail_args = argparse.Namespace(**{**vars(args), "tail_latency_json": None})
        no_tail_runpack = build_runpack(no_tail_args)
        assert "tail_latency" not in no_tail_runpack
        no_tail_dashboard = no_tail_runpack["bottleneck_attribution"]
        assert "tail_latency" in no_tail_dashboard["missing_optional_diagnostics"]
        assert_runpack_contract(no_tail_runpack)
        no_optional_args = argparse.Namespace(
            **{
                **vars(args),
                "tail_latency_json": None,
                "flight_recorder_report_json": None,
                "host_preflight_json": None,
                "hostcall_swarm_profile_json": None,
                "session_recovery_swarm_profile_json": None,
                "rpc_swarm_e2e_json": None,
                "rch_artifact_sync_json": None,
            }
        )
        no_optional_runpack = build_runpack(no_optional_args)
        assert no_optional_runpack["bottleneck_attribution"]["surface_coverage"][
            "provider_streaming"
        ]["status"] == "optional_diagnostic_missing"
        assert (
            "flight_recorder"
            in no_optional_runpack["bottleneck_attribution"]["missing_optional_diagnostics"]
        )
        assert_runpack_contract(no_optional_runpack)
        stale_rpc_path = write_json(
            workspace / "stale-rpc-swarm-e2e.json",
            {
                "schema": RPC_SWARM_E2E_SCHEMA,
                "generated_at": "2026-05-07T09:00:00+00:00",
                "status": "pass",
            },
        )
        stale_args = argparse.Namespace(**{**vars(args), "rpc_swarm_e2e_json": stale_rpc_path})
        stale_runpack = build_runpack(stale_args)
        assert stale_runpack["bottleneck_attribution"]["status"] == "degraded"
        assert (
            "rpc_swarm_e2e"
            in stale_runpack["bottleneck_attribution"]["historical_snapshots"]
        )
        bad_rpc_schema_path = write_json(
            workspace / "bad-rpc-swarm-e2e.json",
            {"schema": "pi.rpc.concurrent_swarm_e2e.v0", "generated_at": generated_at},
        )
        bad_rpc_schema_args = argparse.Namespace(
            **{**vars(args), "rpc_swarm_e2e_json": bad_rpc_schema_path}
        )
        try:
            build_runpack(bad_rpc_schema_args)
        except RunpackError as exc:
            assert "rpc_swarm_e2e source schema mismatch" in str(exc)
        else:
            raise AssertionError("schema-mismatched optional diagnostic should fail closed")
    except (AssertionError, RunpackError) as exc:
        print(f"SELF-TEST FAIL: {exc}")
        return 2
    print("SELF-TEST PASS")
    print(json_dumps({"workspace": str(workspace), "runpack": runpack}, pretty=True))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--doctor-json",
        type=Path,
        help="JSON from `pi doctor --only swarm --format json`",
    )
    parser.add_argument(
        "--claim-readiness-json",
        type=Path,
        help="JSON from report_swarm_claim_readiness.py",
    )
    parser.add_argument(
        "--smoke-summary-json",
        type=Path,
        help="summary.json from run_swarm_smoke_harness.py",
    )
    parser.add_argument("--activity-digest-json", type=Path, help="pi.swarm.activity_digest.v1 JSON")
    parser.add_argument(
        "--cargo-admission-json",
        type=Path,
        help="JSON or JSONL from cargo_headroom.sh --admit-only",
    )
    parser.add_argument(
        "--beads-json",
        type=Path,
        help="JSON from `br list --json` or `br list --status=in_progress --json`",
    )
    parser.add_argument(
        "--git-status-file",
        type=Path,
        help="captured `git status --porcelain` output",
    )
    parser.add_argument(
        "--tail-latency-json",
        type=Path,
        help="pi.operator_tail_latency.v1 JSON from PI_PERF_TELEMETRY",
    )
    parser.add_argument(
        "--flight-recorder-report-json",
        type=Path,
        help="pi.swarm.flight_recorder.report.v1 JSON",
    )
    parser.add_argument(
        "--host-preflight-json",
        type=Path,
        help="pi.doctor.swarm_resource_preflight.v1 JSON",
    )
    parser.add_argument(
        "--hostcall-swarm-profile-json",
        type=Path,
        help="pi.ext.hostcall_admission_swarm_profile.v1 JSON",
    )
    parser.add_argument(
        "--session-recovery-swarm-profile-json",
        type=Path,
        help="pi.session_store_v2.recovery_swarm_profile.v1 JSON",
    )
    parser.add_argument(
        "--rpc-swarm-e2e-json",
        type=Path,
        help="pi.rpc.concurrent_swarm_e2e.v1 JSON",
    )
    parser.add_argument(
        "--rch-artifact-sync-json",
        type=Path,
        help="pi.rch.artifact_sync_preflight.v1 JSON",
    )
    parser.add_argument("--out-json", type=Path, help="write runpack JSON; refuses to overwrite")
    parser.add_argument("--out-md", type=Path, help="write runpack Markdown; refuses to overwrite")
    parser.add_argument("--generated-at", help="override generated timestamp for deterministic tests")
    parser.add_argument("--stale-after-hours", type=int, default=DEFAULT_STALE_AFTER_HOURS)
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--json", action="store_true", help="print the runpack JSON")
    parser.add_argument("--self-test", action="store_true", help="run fixture-backed self-test")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()
    if args.stale_after_hours < 0:
        print("ERROR: --stale-after-hours must be non-negative", file=sys.stderr)
        return 2
    if args.max_items < 0:
        print("ERROR: --max-items must be non-negative", file=sys.stderr)
        return 2
    try:
        runpack = build_runpack(args)
        write_outputs(args, runpack)
    except (RunpackError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json or (not args.out_json and not args.out_md):
        print(json_dumps(runpack, pretty=True))
    return 0


if __name__ == "__main__":
    with contextlib.suppress(BrokenPipeError):
        sys.exit(main())
