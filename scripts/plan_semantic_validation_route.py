#!/usr/bin/env python3
"""Build a read-only semantic validation route plan.

The route plan maps touched paths to validation obligations, RCH-only command
templates, proof-memory reuse posture, cache/coalescing hints, and coordination
admission warnings. It never runs cargo/RCH, mutates Beads or Agent Mail, edits
git state, or deletes files.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROUTE_PLAN_SCHEMA = "pi.validation.semantic_route_plan.v1"
PURPOSE = "read_only_semantic_validation_route_planning"
DEFAULT_SOURCE_BEAD = "bd-4w2mw.2"
DEFAULT_SCHEDULER_PATH = Path("docs/evidence/validation-scheduler-plan.json")
DEFAULT_PROOF_MEMORY_PATH = Path("docs/evidence/validation-proof-memory-index.json")
DEFAULT_BEADS_PATH = Path(".beads/issues.jsonl")

REQUIRED_TOP_LEVEL_KEYS = (
    "schema",
    "generated_at",
    "status",
    "decision",
    "purpose",
    "source_bead",
    "inputs",
    "changed_path_classification",
    "proof_obligations",
    "proof_memory_assessment",
    "cache_heat",
    "coalescing_advice",
    "coordination_risk",
    "coordination_admission",
    "would_run_order",
    "deferred_or_blocked",
    "negative_controls",
    "summary",
    "claim_boundaries",
)

RCH_ENV = {
    "CARGO_TARGET_DIR": "/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target",
    "TMPDIR": "/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp",
}

BUCKETS: tuple[dict[str, Any], ...] = (
    {
        "bucket": "provider",
        "patterns": (
            "src/providers/**",
            "src/provider.rs",
            "src/provider_metadata.rs",
            "src/sse.rs",
        ),
        "proof_groups": (
            "focused_tests",
            "e2e_conformance",
            "all_targets_check",
            "clippy",
        ),
        "focused_command": "test provider_streaming",
    },
    {
        "bucket": "tools",
        "patterns": (
            "src/tools.rs",
            "tests/conformance*",
            "tests/fixtures/**",
        ),
        "proof_groups": (
            "focused_tests",
            "e2e_conformance",
            "all_targets_check",
            "clippy",
        ),
        "focused_command": "test tools",
    },
    {
        "bucket": "session",
        "patterns": (
            "src/session.rs",
            "src/session_index.rs",
            "src/session_sqlite.rs",
            "docs/session.md",
        ),
        "proof_groups": ("focused_tests", "all_targets_check", "clippy"),
        "focused_command": "test session",
    },
    {
        "bucket": "extension",
        "patterns": (
            "src/extensions.rs",
            "src/extensions_js.rs",
            "src/extension_dispatcher.rs",
            "tests/ext_conformance/**",
            "docs/extension-*.md",
        ),
        "proof_groups": (
            "focused_tests",
            "e2e_conformance",
            "all_targets_check",
            "clippy",
        ),
        "focused_command": "test extension",
    },
    {
        "bucket": "interactive_rpc",
        "patterns": (
            "src/interactive.rs",
            "src/interactive/**",
            "src/rpc.rs",
            "src/main.rs",
        ),
        "proof_groups": (
            "focused_tests",
            "e2e_conformance",
            "all_targets_check",
            "clippy",
        ),
        "focused_command": "test e2e_rpc",
    },
    {
        "bucket": "core_runtime",
        "patterns": ("src/*.rs", "src/http/**"),
        "proof_groups": ("focused_tests", "all_targets_check", "clippy"),
        "focused_command": "test --lib",
    },
    {
        "bucket": "scripts_docs_evidence",
        "patterns": ("scripts/**", "docs/**", "tests/golden_corpus/**", ".beads/**"),
        "proof_groups": ("fast_script_checks", "evidence_regeneration"),
        "focused_command": None,
    },
)

FALLBACK_GROUPS: tuple[dict[str, Any], ...] = (
    {
        "id": "fast_script_checks",
        "title": "Fast script and metadata checks",
        "command_class": "fast_script",
        "dependency_rank": 1,
        "cache_reuse": "not_applicable",
        "requires_rch": False,
        "no_local_fallback": False,
        "exact_commands": [
            "python3 -m json.tool docs/evidence/semantic-validation-route-inventory.json >/dev/null",
            "git diff --check",
            "./scripts/reconcile_beads_ledger.sh",
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": {},
        "local_fallback_rejection_reason": None,
    },
    {
        "id": "evidence_regeneration",
        "title": "Runpack evidence regeneration self-test",
        "command_class": "script_self_test",
        "dependency_rank": 2,
        "cache_reuse": "not_applicable",
        "requires_rch": False,
        "no_local_fallback": False,
        "exact_commands": ["python3 scripts/build_swarm_operator_runpack.py --self-test"],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": {},
        "local_fallback_rejection_reason": None,
    },
    {
        "id": "focused_tests",
        "title": "Focused Rust tests for touched surfaces",
        "command_class": "cargo_test_focused",
        "dependency_rank": 3,
        "cache_reuse": "target_dir_reuse_if_clean",
        "requires_rch": True,
        "no_local_fallback": True,
        "exact_commands": [
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo test <focused-target>"
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": RCH_ENV,
        "local_fallback_rejection_reason": "RCH-required validation must not fail open into a local cargo build.",
    },
    {
        "id": "e2e_conformance",
        "title": "E2E and conformance validation",
        "command_class": "cargo_test_e2e_conformance",
        "dependency_rank": 4,
        "cache_reuse": "target_dir_reuse_if_clean",
        "requires_rch": True,
        "no_local_fallback": True,
        "exact_commands": [
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo test conformance",
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo test e2e",
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": RCH_ENV,
        "local_fallback_rejection_reason": "RCH-required validation must not fail open into a local cargo build.",
    },
    {
        "id": "all_targets_check",
        "title": "All-targets compiler check",
        "command_class": "cargo_check_all_targets",
        "dependency_rank": 5,
        "cache_reuse": "target_dir_reuse_if_clean",
        "requires_rch": True,
        "no_local_fallback": True,
        "exact_commands": [
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo check --all-targets"
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": RCH_ENV,
        "local_fallback_rejection_reason": "RCH-required validation must not fail open into a local cargo build.",
    },
    {
        "id": "clippy",
        "title": "All-targets clippy",
        "command_class": "cargo_clippy_all_targets",
        "dependency_rank": 6,
        "cache_reuse": "target_dir_reuse_if_clean",
        "requires_rch": True,
        "no_local_fallback": True,
        "exact_commands": [
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo clippy --all-targets -- -D warnings"
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": RCH_ENV,
        "local_fallback_rejection_reason": "RCH-required validation must not fail open into a local cargo build.",
    },
)

NEGATIVE_CONTROLS: tuple[dict[str, str], ...] = (
    {
        "id": "missing_scheduler_plan_fails_closed",
        "expected_status": "blocked",
        "reason": "Missing scheduler input blocks authoritative import of current validation group semantics.",
    },
    {
        "id": "stale_proof_memory_fails_closed_for_reuse",
        "expected_status": "degraded",
        "reason": "Stale proof-memory can inform routing but cannot authorize proof reuse.",
    },
    {
        "id": "local_cargo_fallback_rejected",
        "expected_status": "blocked",
        "reason": "Heavy cargo groups require rch exec -- and no local fallback.",
    },
    {
        "id": "dirty_worktree_mismatch_denies_reuse",
        "expected_status": "degraded",
        "reason": "Dirty/mismatched worktree state invalidates proof-memory reuse.",
    },
    {
        "id": "agent_mail_degraded_uses_beads_soft_lock",
        "expected_status": "degraded",
        "reason": "Degraded coordination sources require Beads soft-lock or explicit blocker reporting.",
    },
    {
        "id": "advisory_route_as_authority_rejected",
        "expected_status": "blocked",
        "reason": "Route plans cannot claim, reserve, launch validation, mutate source systems, or certify claims.",
    },
)


class RoutePlanError(Exception):
    """Raised when route-plan inputs are unusable."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def json_dumps(value: Any, *, pretty: bool) -> str:
    if pretty:
        return json.dumps(value, indent=2, sort_keys=True) + "\n"
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RoutePlanError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RoutePlanError(f"malformed JSON file {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RoutePlanError(f"JSON file must contain an object: {path}")
    return payload


def load_optional_json(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    try:
        return load_json(path), {"path": str(path), "status": "loaded"}
    except RoutePlanError as exc:
        return None, {"path": str(path), "status": "missing_or_invalid", "reason": str(exc)}


def load_changed_paths_json(path: Path) -> list[str]:
    payload = load_json(path)
    raw = payload.get("changed_paths")
    if raw is None:
        raw = payload.get("paths")
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise RoutePlanError(f"{path} must contain changed_paths or paths as a string list")
    return sorted(set(raw))


def git_changed_paths(root: Path) -> list[str]:
    commands = (
        ("git", "diff", "--name-only"),
        ("git", "diff", "--cached", "--name-only"),
    )
    paths: set[str] = set()
    for command in commands:
        result = subprocess.run(
            command,
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if result.returncode == 0:
            paths.update(line.strip() for line in result.stdout.splitlines() if line.strip())
    return sorted(paths)


def normalize_path(raw: str) -> str:
    clean = raw.strip().replace("\\", "/")
    if clean.startswith("./"):
        return clean[2:]
    return clean


def matches_pattern(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        return path == pattern[:-3] or path.startswith(pattern[:-3] + "/")
    return fnmatch.fnmatchcase(path, pattern)


def classify_path(path: str) -> dict[str, Any]:
    clean = normalize_path(path)
    for spec in BUCKETS:
        for pattern in spec["patterns"]:
            if matches_pattern(clean, pattern):
                return {
                    "path": clean,
                    "bucket": spec["bucket"],
                    "matched_pattern": pattern,
                    "proof_groups": list(spec["proof_groups"]),
                    "focused_command": spec.get("focused_command"),
                    "status": "classified",
                }
    return {
        "path": clean,
        "bucket": "unknown",
        "matched_pattern": "*",
        "proof_groups": ["fast_script_checks", "all_targets_check"],
        "focused_command": None,
        "status": "unknown_path_bucket",
    }


def classify_changed_paths(paths: list[str]) -> dict[str, Any]:
    records = [classify_path(path) for path in sorted(set(map(normalize_path, paths)))]
    counts = Counter(record["bucket"] for record in records)
    unknown = [record["path"] for record in records if record["bucket"] == "unknown"]
    if not records:
        profile = "empty_queue"
    elif set(counts) == {"scripts_docs_evidence"}:
        profile = "docs_scripts_evidence_only"
    elif any(record["bucket"] != "scripts_docs_evidence" for record in records) and counts.get(
        "scripts_docs_evidence"
    ):
        profile = "mixed_source_and_docs"
    else:
        profile = "source_only"
    return {
        "changed_path_count": len(records),
        "profile_id": profile,
        "bucket_counts": dict(sorted(counts.items())),
        "records": records,
        "unknown_paths": unknown,
    }


def command_groups_from_scheduler(scheduler: dict[str, Any] | None) -> list[dict[str, Any]]:
    groups = scheduler.get("command_groups") if isinstance(scheduler, dict) else None
    if not isinstance(groups, list) or not all(isinstance(group, dict) for group in groups):
        return [dict(group) for group in FALLBACK_GROUPS]
    by_id = {str(group.get("id")): dict(group) for group in groups if group.get("id")}
    merged: list[dict[str, Any]] = []
    for fallback in FALLBACK_GROUPS:
        current = dict(fallback)
        current.update(by_id.get(fallback["id"], {}))
        current.setdefault("dependency_rank", fallback["dependency_rank"])
        current.setdefault("exact_commands", fallback["exact_commands"])
        current.setdefault("requires_rch", fallback["requires_rch"])
        current.setdefault("no_local_fallback", fallback["no_local_fallback"])
        current.setdefault("required_env", RCH_ENV if current.get("requires_rch") else {})
        current.setdefault(
            "local_fallback_rejection_reason",
            fallback["local_fallback_rejection_reason"],
        )
        merged.append(current)
    return merged


def focused_rch_command(cargo_args: str) -> str:
    return (
        "rch exec -- env "
        f"CARGO_TARGET_DIR={RCH_ENV['CARGO_TARGET_DIR']} "
        f"TMPDIR={RCH_ENV['TMPDIR']} cargo {cargo_args}"
    )


def required_group_ids(classification: dict[str, Any]) -> list[str]:
    ids: set[str] = set()
    for record in classification["records"]:
        ids.update(record["proof_groups"])
    if not ids:
        ids.add("fast_script_checks")
    return sorted(ids, key=lambda group_id: group_rank(group_id))


def group_rank(group_id: str) -> int:
    for group in FALLBACK_GROUPS:
        if group["id"] == group_id:
            return int(group["dependency_rank"])
    return 99


def build_proof_obligations(
    classification: dict[str, Any],
    command_groups: list[dict[str, Any]],
) -> dict[str, Any]:
    wanted = required_group_ids(classification)
    groups_by_id = {str(group["id"]): group for group in command_groups}
    obligations: list[dict[str, Any]] = []
    focused_commands = sorted(
        {
            focused_rch_command(str(record["focused_command"]))
            for record in classification["records"]
            if record.get("focused_command")
        }
    )
    for group_id in wanted:
        group = groups_by_id.get(group_id)
        if group is None:
            obligations.append(
                {
                    "group_id": group_id,
                    "status": "missing_group_definition",
                    "requires_rch": None,
                    "exact_commands": [],
                    "reasons": ["validation group is absent from scheduler/fallback catalog"],
                }
            )
            continue
        exact_commands = list(group.get("exact_commands") or [])
        if group_id == "focused_tests" and focused_commands:
            exact_commands = focused_commands
        obligations.append(
            {
                "group_id": group_id,
                "title": group.get("title"),
                "command_class": group.get("command_class"),
                "requires_rch": bool(group.get("requires_rch")),
                "no_local_fallback": bool(group.get("no_local_fallback")),
                "exact_commands": exact_commands,
                "required_env": group.get("required_env") or (RCH_ENV if group.get("requires_rch") else {}),
                "local_fallback_rejection_reason": group.get("local_fallback_rejection_reason"),
                "scheduler_action": group.get("action", "would_run"),
                "scheduler_backoff_reasons": group.get("backoff_reasons") or [],
                "cache_reuse": group.get("cache_reuse"),
                "status": "required",
            }
        )
    missing = [item["group_id"] for item in obligations if item["status"] != "required"]
    return {
        "required_group_ids": wanted,
        "groups": obligations,
        "missing_group_ids": missing,
        "heavy_group_count": sum(1 for item in obligations if item.get("requires_rch")),
    }


def proof_entry_touched_paths(entry: dict[str, Any]) -> set[str]:
    paths = entry.get("touched_paths")
    if isinstance(paths, list):
        return {normalize_path(path) for path in paths if isinstance(path, str)}
    coverage = entry.get("path_coverage")
    if isinstance(coverage, dict):
        covered = coverage.get("covered_paths")
        if isinstance(covered, list):
            return {normalize_path(path) for path in covered if isinstance(path, str)}
    return set()


def assess_proof_memory(
    proof_memory: dict[str, Any] | None,
    changed_paths: list[str],
) -> dict[str, Any]:
    if not isinstance(proof_memory, dict):
        return {
            "source_status": "missing_or_invalid",
            "entry_count": 0,
            "classification_counts": {},
            "reusable_records": [],
            "invalidating_records": [],
            "route_decision": "refresh_validation",
            "invalidation_reasons": ["proof_memory_missing_or_invalid"],
        }
    entries = proof_memory.get("entries")
    if not isinstance(entries, list):
        entries = []
    current_paths = {normalize_path(path) for path in changed_paths}
    reusable: list[dict[str, Any]] = []
    invalidating: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    reasons: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        classification = str(entry.get("classification") or "unknown")
        counts[classification] += 1
        eligibility = entry.get("reuse_eligibility")
        reusable_flag = bool(isinstance(eligibility, dict) and eligibility.get("reuse_allowed"))
        entry_paths = proof_entry_touched_paths(entry)
        path_covers_current = not current_paths or current_paths.issubset(entry_paths)
        record = {
            "record_id": entry.get("record_id"),
            "fixture_id": entry.get("fixture_id"),
            "classification": classification,
            "command": (entry.get("command") or {}).get("rendered")
            if isinstance(entry.get("command"), dict)
            else None,
            "path_covers_current": path_covers_current,
            "reuse_allowed": reusable_flag and path_covers_current,
        }
        if reusable_flag and path_covers_current:
            reusable.append(record)
        else:
            if classification != "reusable" or current_paths:
                invalidating.append(record)
            if classification in {
                "stale",
                "missing_artifact",
                "local_fallback",
                "dirty_worktree_mismatch",
                "command_mismatch",
                "path_coverage_mismatch",
                "not_authoritative",
            }:
                reasons.add(classification)
            if reusable_flag and not path_covers_current:
                reasons.add("path_coverage_mismatch")
    route_decision = "reuse_available" if reusable else "refresh_validation"
    return {
        "source_status": proof_memory.get("status", "unknown"),
        "source_decision": proof_memory.get("decision"),
        "entry_count": len(entries),
        "classification_counts": dict(sorted(counts.items())),
        "reusable_records": reusable[:5],
        "invalidating_records": invalidating[:8],
        "route_decision": route_decision,
        "invalidation_reasons": sorted(reasons),
    }


def group_cache_intensity(group: dict[str, Any]) -> str:
    group_id = str(group["group_id"])
    if group_id in {"all_targets_check", "clippy"}:
        return "high"
    if group.get("requires_rch"):
        return "medium"
    return "low"


def group_cache_key(group: dict[str, Any]) -> str:
    if group.get("requires_rch"):
        command_class = str(group.get("command_class") or group["group_id"])
        return f"cargo-target:{RCH_ENV['CARGO_TARGET_DIR']}:{command_class}"
    return f"local-script:{group['group_id']}"


def route_heat_level(groups: list[dict[str, Any]]) -> str:
    heavy_count = sum(1 for group in groups if group.get("requires_rch"))
    if heavy_count >= 3:
        return "high"
    if heavy_count:
        return "medium"
    return "low"


def build_cache_heat(
    obligations: dict[str, Any],
    *,
    classification: dict[str, Any],
    proof_memory: dict[str, Any],
) -> dict[str, Any]:
    groups = obligations["groups"]
    heat: list[dict[str, Any]] = []
    heavy_groups = [str(group["group_id"]) for group in groups if group.get("requires_rch")]
    for group in groups:
        group_id = str(group["group_id"])
        requires_rch = bool(group.get("requires_rch"))
        intensity = group_cache_intensity(group)
        advice = "run_before_heavy_rust" if not requires_rch else "coalesce_with_same_target_dir"
        shares_with = [
            other
            for other in heavy_groups
            if other != group_id and requires_rch
        ]
        reusable_after: list[str] = []
        if group_id == "all_targets_check":
            reusable_after.append("focused_tests")
        if group_id == "clippy":
            advice = "run_after_check_or_focused_tests_to_reuse_target_cache"
            reusable_after.extend(["focused_tests", "all_targets_check"])
        if group_id == "e2e_conformance":
            reusable_after.append("focused_tests")
        heat.append(
            {
                "group_id": group_id,
                "cache_intensity": intensity,
                "cache_key": group_cache_key(group),
                "cache_reuse": group.get("cache_reuse"),
                "requires_rch": requires_rch,
                "command_count": len(group.get("exact_commands") or []),
                "shares_target_cache_with": shares_with,
                "reusable_after_groups": sorted(set(reusable_after), key=group_rank),
                "advice": advice,
            }
        )
    proof_hint = "proof_memory_not_reusable_for_current_route"
    if proof_memory.get("route_decision") == "reuse_available":
        proof_hint = "proof_memory_reusable_only_for_exact_matching_context"
    return {
        "status": "ready",
        "route_heat_level": route_heat_level(groups),
        "changed_bucket_counts": classification["bucket_counts"],
        "shared_rch_env": RCH_ENV if heavy_groups else {},
        "heavy_group_ids": heavy_groups,
        "items": heat,
        "proof_memory_cache_hint": {
            "decision": proof_memory.get("route_decision"),
            "hint": proof_hint,
            "invalidation_reasons": proof_memory.get("invalidation_reasons") or [],
            "authority_boundary": "Cache hints may influence ordering only; proof-memory reuse remains governed by proof_memory_assessment.",
        },
        "coalescing_summary": "Run cheap scripts first; when heavy validation is admitted, keep RCH target/tmp env stable and coalesce Rust groups by touched surface.",
    }


def build_coalescing_advice(
    obligations: dict[str, Any],
    *,
    classification: dict[str, Any],
    proof_memory: dict[str, Any],
) -> dict[str, Any]:
    groups = sorted(obligations["groups"], key=lambda item: group_rank(str(item["group_id"])))
    ordering: list[dict[str, Any]] = []
    for group in groups:
        group_id = str(group["group_id"])
        requires_rch = bool(group.get("requires_rch"))
        if group_id == "fast_script_checks":
            rationale = "Run first; cheap checks catch metadata and ledger drift before any Rust cache work."
        elif group_id == "evidence_regeneration":
            rationale = "Run after fast scripts when docs/evidence changed; does not warm Rust target cache."
        elif group_id == "focused_tests":
            rationale = "Run before broad Rust gates to warm the relevant target cache and isolate route failures."
        elif group_id == "e2e_conformance":
            rationale = "Run after focused tests when conformance/E2E obligations are required; reuse the same RCH target env."
        elif group_id == "all_targets_check":
            rationale = "Run before clippy so clippy can reuse compiler artifacts where the worker cache keeps them."
        elif group_id == "clippy":
            rationale = "Run last among broad Rust gates; it benefits most from check/focused-test cache warmth."
        else:
            rationale = "Run in dependency-rank order from the route planner."
        ordering.append(
            {
                "rank": len(ordering) + 1,
                "group_id": group_id,
                "requires_rch": requires_rch,
                "cache_key": group_cache_key(group),
                "rationale": rationale,
            }
        )
    docs_only = set(classification["bucket_counts"]) == {"scripts_docs_evidence"}
    return {
        "status": "ready",
        "profile_id": classification["profile_id"],
        "docs_only_or_scripts_only": docs_only,
        "recommended_order": ordering,
        "shared_rch_env": RCH_ENV if any(item["requires_rch"] for item in ordering) else {},
        "proof_memory_guidance": {
            "route_decision": proof_memory.get("route_decision"),
            "reuse_authority": "Do not treat cache-warm hints as validation proof reuse authority.",
            "cache_hint": "Stale or mismatched proof-memory records may still suggest which command families share target cache, but they require fresh validation before closeout.",
        },
        "local_fallback_policy": "Heavy cargo validation remains RCH-only and must not fail open into local cargo.",
        "advisory_only": True,
    }


def load_beads_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"source_status": "missing", "open_count": 0, "in_progress_count": 0, "ready_hint": None}
    open_count = 0
    in_progress_count = 0
    active: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                issue = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(issue, dict):
                continue
            status = issue.get("status")
            if status == "open":
                open_count += 1
            elif status == "in_progress":
                in_progress_count += 1
            if status in {"open", "in_progress"}:
                active.append(
                    {
                        "id": issue.get("id"),
                        "title": issue.get("title"),
                        "status": status,
                        "assignee": issue.get("assignee"),
                        "updated_at": issue.get("updated_at"),
                        "created_at": issue.get("created_at"),
                    }
                )
    return {
        "source_status": "loaded",
        "open_count": open_count,
        "ready_count": open_count,
        "in_progress_count": in_progress_count,
        "active_sample": active[:8],
    }


def agent_mail_health_state(agent_mail_health: dict[str, Any] | None) -> dict[str, str]:
    health = agent_mail_health or {}
    recovery = health.get("recovery") if isinstance(health.get("recovery"), dict) else {}
    recovery_mode = str(recovery.get("mode") or "not_provided")
    health_level = str(health.get("health_level") or health.get("status") or "not_provided")
    effective = health_level
    if recovery_mode not in {"not_provided", "normal", "none", "ok"}:
        effective = recovery_mode
    return {
        "health_level": health_level,
        "recovery_mode": recovery_mode,
        "effective_status": effective,
    }


def route_reservation_paths(classification: dict[str, Any]) -> list[str]:
    paths = sorted(
        {
            record["path"]
            for record in classification["records"]
            if record["bucket"] != "unknown"
        }
    )
    if paths:
        return paths
    return ["docs/evidence/semantic-validation-route-inventory.json"]


def path_patterns_from_record(record: dict[str, Any]) -> list[str]:
    for key in ("path_patterns", "reservation_paths", "reserved_paths", "paths"):
        raw = record.get(key)
        if isinstance(raw, list):
            return [normalize_path(item) for item in raw if isinstance(item, str)]
    raw_pattern = record.get("path_pattern")
    if isinstance(raw_pattern, str):
        return [normalize_path(raw_pattern)]
    return []


def collect_active_reservations(
    *,
    agent_mail_health: dict[str, Any] | None,
    beads_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source, payload in (
        ("agent_mail_health", agent_mail_health or {}),
        ("beads", beads_summary),
    ):
        raw_reservations = payload.get("active_reservations") if isinstance(payload, dict) else None
        if isinstance(raw_reservations, list):
            for item in raw_reservations:
                if not isinstance(item, dict):
                    continue
                patterns = path_patterns_from_record(item)
                if not patterns:
                    continue
                records.append(
                    {
                        "source": source,
                        "holder": item.get("holder") or item.get("agent") or item.get("assignee"),
                        "thread_id": item.get("thread_id") or item.get("reason"),
                        "path_patterns": patterns,
                    }
                )
    for item in beads_summary.get("active_sample") or []:
        if not isinstance(item, dict):
            continue
        patterns = path_patterns_from_record(item)
        if patterns:
            records.append(
                {
                    "source": "beads_active_sample",
                    "holder": item.get("assignee"),
                    "thread_id": item.get("id"),
                    "path_patterns": patterns,
                }
            )
    return records


def reservation_overlaps(route_path: str, pattern: str) -> bool:
    normalized_route = normalize_path(route_path)
    normalized_pattern = normalize_path(pattern)
    return matches_pattern(normalized_route, normalized_pattern) or matches_pattern(
        normalized_pattern,
        normalized_route,
    )


def overlapping_reservations(
    route_paths: list[str],
    reservations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    overlaps: list[dict[str, Any]] = []
    for reservation in reservations:
        matched = sorted(
            {
                route_path
                for route_path in route_paths
                for pattern in reservation["path_patterns"]
                if reservation_overlaps(route_path, pattern)
            }
        )
        if matched:
            overlaps.append({**reservation, "matched_route_paths": matched})
    return overlaps


def stale_in_progress_issues(beads_summary: dict[str, Any]) -> list[dict[str, Any]]:
    stale: list[dict[str, Any]] = []
    for item in beads_summary.get("active_sample") or []:
        if not isinstance(item, dict) or item.get("status") != "in_progress":
            continue
        if item.get("stale") is True or item.get("stale_candidate") is True:
            stale.append(
                {
                    "id": item.get("id"),
                    "assignee": item.get("assignee"),
                    "updated_at": item.get("updated_at"),
                    "reason": item.get("stale_reason") or "fixture_or_source_marked_stale",
                }
            )
    return stale


def dirty_paths_outside_route(
    *,
    beads_summary: dict[str, Any],
    route_paths: list[str],
) -> list[str]:
    raw_paths = beads_summary.get("dirty_worktree_paths") or []
    if not isinstance(raw_paths, list):
        return []
    route_set = {normalize_path(path) for path in route_paths}
    dirty_paths = {normalize_path(path) for path in raw_paths if isinstance(path, str)}
    return sorted(path for path in dirty_paths if path not in route_set)


def build_coordination_risk(
    *,
    agent_mail_health: dict[str, Any] | None,
    beads_summary: dict[str, Any],
    classification: dict[str, Any],
) -> dict[str, Any]:
    route_paths = route_reservation_paths(classification)
    health_state = agent_mail_health_state(agent_mail_health)
    active_reservations = collect_active_reservations(
        agent_mail_health=agent_mail_health,
        beads_summary=beads_summary,
    )
    overlaps = overlapping_reservations(route_paths, active_reservations)
    stale_issues = stale_in_progress_issues(beads_summary)
    dirty_mismatch = dirty_paths_outside_route(beads_summary=beads_summary, route_paths=route_paths)
    risk_factors: list[dict[str, Any]] = []

    if health_state["effective_status"] not in {"green", "ok"}:
        risk_factors.append(
            {
                "id": "agent_mail_not_authoritative",
                "severity": "degraded",
                "source": "agent_mail_health",
                "reason": f"agent_mail_effective_status={health_state['effective_status']}",
                "recommended_action": "claim_with_beads_soft_lock",
            }
        )
    ready_count = int(beads_summary.get("ready_count", beads_summary.get("open_count", 0)) or 0)
    if ready_count == 0:
        risk_factors.append(
            {
                "id": "ready_queue_empty",
                "severity": "blocking",
                "source": "beads",
                "reason": "no ready/open bead is available for this route",
                "recommended_action": "stop_surface_blocker",
            }
        )
    if beads_summary.get("in_progress_count", 0) > 0:
        risk_factors.append(
            {
                "id": "active_in_progress_beads_present",
                "severity": "degraded",
                "source": "beads",
                "reason": "in-progress bead ownership exists and must be checked before claiming",
                "recommended_action": "claim_with_beads_soft_lock",
            }
        )
    if overlaps:
        risk_factors.append(
            {
                "id": "active_overlap",
                "severity": "blocking",
                "source": "agent_mail_or_beads",
                "reason": "route paths overlap an active reservation or claimed surface",
                "affected_paths": sorted({path for item in overlaps for path in item["matched_route_paths"]}),
                "recommended_action": "defer_due_to_collision",
            }
        )
    if stale_issues:
        risk_factors.append(
            {
                "id": "stale_in_progress_issue",
                "severity": "degraded",
                "source": "beads",
                "reason": "in-progress issue is marked stale and needs explicit reopen or soft-lock handling",
                "issue_ids": [str(item["id"]) for item in stale_issues],
                "recommended_action": "claim_with_beads_soft_lock",
            }
        )
    if dirty_mismatch:
        risk_factors.append(
            {
                "id": "dirty_worktree_mismatch",
                "severity": "blocking",
                "source": "git_status",
                "reason": "dirty paths outside the requested route make admission unsafe",
                "affected_paths": dirty_mismatch,
                "recommended_action": "stop_surface_blocker",
            }
        )
    if classification["unknown_paths"]:
        risk_factors.append(
            {
                "id": "unknown_changed_path_bucket",
                "severity": "blocking",
                "source": "changed_path_classification",
                "reason": "changed path has no known proof route",
                "affected_paths": classification["unknown_paths"],
                "recommended_action": "stop_surface_blocker",
            }
        )

    blocking = [item for item in risk_factors if item["severity"] == "blocking"]
    degraded = [item for item in risk_factors if item["severity"] == "degraded"]
    if blocking:
        status = "blocked"
    elif degraded:
        status = "degraded"
    else:
        status = "ready"
    if any(item["recommended_action"] == "defer_due_to_collision" for item in blocking):
        recommended_action = "defer_due_to_collision"
    elif blocking:
        recommended_action = "stop_surface_blocker"
    elif degraded:
        recommended_action = "claim_with_beads_soft_lock"
    else:
        recommended_action = "safe_to_claim"
    return {
        "status": status,
        "risk_level": "blocking" if blocking else ("medium" if degraded else "low"),
        "recommended_action": recommended_action,
        "agent_mail_health": health_state,
        "beads_source_status": beads_summary.get("source_status"),
        "ready_bead_count": ready_count,
        "open_bead_count": beads_summary.get("open_count", 0),
        "in_progress_bead_count": beads_summary.get("in_progress_count", 0),
        "route_paths": route_paths,
        "active_overlap": overlaps,
        "stale_in_progress_issues": stale_issues,
        "dirty_worktree_mismatch_paths": dirty_mismatch,
        "risk_factors": risk_factors,
        "source_authority": {
            "beads": "source_of_truth_for_issue_status_and_assignment",
            "agent_mail": "source_of_truth_for_reservations_and_coordination_messages",
            "git_status": "source_of_truth_for_dirty_path_admission",
            "semantic_route_plan": "advisory_only",
        },
        "advisory_only": True,
    }


def build_coordination_admission(coordination_risk: dict[str, Any], *, source_bead: str) -> dict[str, Any]:
    reasons = [str(item["id"]) for item in coordination_risk["risk_factors"]]
    return {
        "status": coordination_risk["status"],
        "recommended_action": coordination_risk["recommended_action"],
        "agent_mail_health": coordination_risk["agent_mail_health"]["effective_status"],
        "agent_mail_recovery_mode": coordination_risk["agent_mail_health"]["recovery_mode"],
        "beads_source_status": coordination_risk["beads_source_status"],
        "ready_bead_count": coordination_risk["ready_bead_count"],
        "open_bead_count": coordination_risk["open_bead_count"],
        "in_progress_bead_count": coordination_risk["in_progress_bead_count"],
        "reservation_paths": coordination_risk["route_paths"],
        "thread_id_hint": source_bead,
        "reservation_reason_hint": source_bead,
        "reasons": reasons,
        "claim_boundary": "Advisory only; agents must claim with br and reserve with Agent Mail or Beads soft-lock explicitly.",
    }


def build_schedule(
    obligations: dict[str, Any],
    *,
    coordination: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    would_run: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    blocked_coordination = coordination["status"] == "blocked"
    for group in sorted(obligations["groups"], key=lambda item: group_rank(str(item["group_id"]))):
        action = "would_run"
        reasons = list(group.get("scheduler_backoff_reasons") or [])
        if blocked_coordination:
            action = "block"
            reasons.append("coordination_admission_blocked")
        elif group.get("scheduler_action") in {"block", "defer"}:
            action = str(group.get("scheduler_action"))
        target = deferred if action != "would_run" else would_run
        for command in group.get("exact_commands") or []:
            target.append(
                {
                    "rank": len(target) + 1,
                    "group_id": group["group_id"],
                    "action": action,
                    "command": command,
                    "requires_rch": bool(group.get("requires_rch")),
                    "required_env": group.get("required_env") or {},
                    "local_fallback_rejection_reason": group.get("local_fallback_rejection_reason"),
                    "rationale": route_rationale(group, action, reasons),
                    "reasons": sorted(set(reasons)),
                }
            )
    return would_run, deferred


def route_rationale(group: dict[str, Any], action: str, reasons: list[str]) -> str:
    title = group.get("title") or group["group_id"]
    if action == "would_run":
        return f"{title} is required by the changed-path route."
    joined = ", ".join(sorted(set(reasons))) if reasons else action
    return f"{title} is {action} because {joined}."


def claim_boundaries() -> dict[str, bool]:
    return {
        "read_only": True,
        "operator_evidence_only": True,
        "does_not_execute_commands": True,
        "does_not_launch_rch": True,
        "does_not_mutate_agent_mail": True,
        "does_not_mutate_beads": True,
        "does_not_mutate_git": True,
        "does_not_delete_files": True,
        "does_not_replace_validation_scheduler": True,
        "does_not_replace_validation_proof_memory": True,
        "does_not_replace_beads_or_agent_mail": True,
        "does_not_authorize_release_performance_claims": True,
        "does_not_authorize_dropin_claims": True,
        "beads_mutation_authorized": False,
        "agent_mail_authority_authorized": False,
        "rch_authority_authorized": False,
        "git_mutation_authorized": False,
        "file_deletion_authorized": False,
        "advisory_evidence_as_source_of_truth_authorized": False,
    }


def determine_status(
    *,
    source_issues: list[dict[str, str]],
    classification: dict[str, Any],
    proof_memory: dict[str, Any],
    coordination: dict[str, Any],
    deferred_or_blocked: list[dict[str, Any]],
) -> tuple[str, str]:
    if any(issue.get("severity") == "blocking" for issue in source_issues):
        return "blocked", "route_plan_blocked_refresh_sources"
    if classification["unknown_paths"]:
        return "blocked", "route_plan_blocked_refresh_sources"
    if coordination["status"] == "blocked":
        return "blocked", "route_plan_blocked_refresh_sources"
    if deferred_or_blocked or proof_memory.get("route_decision") == "refresh_validation":
        return "degraded", "route_plan_degraded_use_manual_validation"
    if coordination["status"] == "degraded":
        return "degraded", "route_plan_degraded_use_manual_validation"
    return "ready", "route_plan_ready"


def validate_plan_shape(plan: dict[str, Any]) -> None:
    missing = [key for key in REQUIRED_TOP_LEVEL_KEYS if key not in plan]
    if missing:
        raise RoutePlanError(f"route plan missing required keys: {', '.join(missing)}")
    boundaries = plan["claim_boundaries"]
    true_keys = (
        "read_only",
        "does_not_execute_commands",
        "does_not_launch_rch",
        "does_not_mutate_agent_mail",
        "does_not_mutate_beads",
        "does_not_mutate_git",
        "does_not_delete_files",
    )
    false_keys = (
        "beads_mutation_authorized",
        "agent_mail_authority_authorized",
        "rch_authority_authorized",
        "git_mutation_authorized",
        "file_deletion_authorized",
        "advisory_evidence_as_source_of_truth_authorized",
    )
    for key in true_keys:
        if boundaries.get(key) is not True:
            raise RoutePlanError(f"claim boundary must be true: {key}")
    for key in false_keys:
        if boundaries.get(key) is not False:
            raise RoutePlanError(f"claim boundary must be false: {key}")
    for item in plan["proof_obligations"]["groups"]:
        if item.get("requires_rch"):
            commands = item.get("exact_commands") or []
            if not commands or not all(str(command).startswith("rch exec --") for command in commands):
                raise RoutePlanError(f"RCH-required group lacks rch exec command: {item.get('group_id')}")
            if not item.get("local_fallback_rejection_reason"):
                raise RoutePlanError(f"RCH-required group lacks local fallback rejection: {item.get('group_id')}")
    coordination_risk = plan["coordination_risk"]
    if coordination_risk.get("advisory_only") is not True:
        raise RoutePlanError("coordination risk must remain advisory")
    if plan["coordination_admission"].get("recommended_action") not in {
        "safe_to_claim",
        "claim_with_beads_soft_lock",
        "defer_due_to_collision",
        "stop_surface_blocker",
    }:
        raise RoutePlanError("coordination admission has unknown recommended action")


def build_route_plan(
    *,
    changed_paths: list[str],
    scheduler: dict[str, Any] | None,
    scheduler_source: dict[str, Any],
    proof_memory: dict[str, Any] | None,
    proof_memory_source: dict[str, Any],
    beads_summary: dict[str, Any],
    agent_mail_health: dict[str, Any] | None,
    generated_at: str,
    source_bead: str,
) -> dict[str, Any]:
    source_issues: list[dict[str, str]] = []
    if scheduler is None:
        source_issues.append(
            {
                "source": "validation_scheduler_plan",
                "severity": "blocking",
                "reason": scheduler_source["reason"],
            }
        )
    if proof_memory is None:
        source_issues.append(
            {
                "source": "validation_proof_memory_index",
                "severity": "warning",
                "reason": proof_memory_source["reason"],
            }
        )
    classification = classify_changed_paths(changed_paths)
    command_groups = command_groups_from_scheduler(scheduler)
    obligations = build_proof_obligations(classification, command_groups)
    proof_assessment = assess_proof_memory(proof_memory, changed_paths)
    cache_heat = build_cache_heat(
        obligations,
        classification=classification,
        proof_memory=proof_assessment,
    )
    coalescing_advice = build_coalescing_advice(
        obligations,
        classification=classification,
        proof_memory=proof_assessment,
    )
    coordination_risk = build_coordination_risk(
        agent_mail_health=agent_mail_health,
        beads_summary=beads_summary,
        classification=classification,
    )
    coordination = build_coordination_admission(coordination_risk, source_bead=source_bead)
    would_run, deferred = build_schedule(obligations, coordination=coordination)
    status, decision = determine_status(
        source_issues=source_issues,
        classification=classification,
        proof_memory=proof_assessment,
        coordination=coordination,
        deferred_or_blocked=deferred,
    )
    plan = {
        "schema": ROUTE_PLAN_SCHEMA,
        "generated_at": generated_at,
        "status": status,
        "decision": decision,
        "purpose": PURPOSE,
        "source_bead": source_bead,
        "inputs": {
            "changed_paths": sorted(set(map(normalize_path, changed_paths))),
            "validation_scheduler_plan": scheduler_source,
            "validation_proof_memory_index": proof_memory_source,
            "beads": {
                "path": str(DEFAULT_BEADS_PATH),
                "status": beads_summary.get("source_status"),
            },
            "agent_mail_health": agent_mail_health or {"status": "not_provided"},
            "source_issues": source_issues,
        },
        "changed_path_classification": classification,
        "proof_obligations": obligations,
        "proof_memory_assessment": proof_assessment,
        "cache_heat": cache_heat,
        "coalescing_advice": coalescing_advice,
        "coordination_risk": coordination_risk,
        "coordination_admission": coordination,
        "would_run_order": would_run,
        "deferred_or_blocked": deferred,
        "negative_controls": list(NEGATIVE_CONTROLS),
        "summary": {
            "changed_path_count": classification["changed_path_count"],
            "required_group_count": len(obligations["required_group_ids"]),
            "would_run_count": len(would_run),
            "deferred_or_blocked_count": len(deferred),
            "unknown_path_count": len(classification["unknown_paths"]),
            "proof_memory_route_decision": proof_assessment["route_decision"],
            "coordination_status": coordination["status"],
            "heavy_group_count": obligations["heavy_group_count"],
        },
        "claim_boundaries": claim_boundaries(),
    }
    validate_plan_shape(plan)
    return plan


def no_overwrite_write(path: Path, text: str) -> None:
    if path.exists():
        raise RoutePlanError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fixture_scheduler(*, heavy_allowed: bool = True) -> dict[str, Any]:
    groups = []
    for group in FALLBACK_GROUPS:
        item = dict(group)
        if item["requires_rch"] and not heavy_allowed:
            item["action"] = "defer"
            item["backoff_reasons"] = ["slot_pressure=saturated"]
        groups.append(item)
    return {
        "schema": "pi.swarm.validation_scheduler_plan.v1",
        "status": "ready" if heavy_allowed else "degraded",
        "command_groups": groups,
        "rch_posture": {"heavy_validation_allowed": heavy_allowed},
    }


def fixture_proof_memory(*, reusable: bool = True) -> dict[str, Any]:
    classification = "reusable" if reusable else "stale"
    return {
        "schema": "pi.validation.proof_memory_index.v1",
        "status": "pass",
        "decision": "proof_memory_index_ready",
        "entries": [
            {
                "record_id": "fixture-proof",
                "fixture_id": "self_test",
                "classification": classification,
                "command": {"rendered": "rch exec -- cargo check --all-targets"},
                "touched_paths": ["src/providers/openai.rs", "src/doctor.rs"],
                "reuse_eligibility": {
                    "reuse_allowed": reusable,
                    "invalidation_reasons": [] if reusable else ["stale_proof"],
                },
            }
        ],
    }


def run_self_test() -> dict[str, Any]:
    cases = [
        {
            "id": "docs_only",
            "paths": ["docs/swarm-operations-runbook.md"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"ready", "degraded"},
            "expect_bucket": "scripts_docs_evidence",
            "expect_heat": "low",
        },
        {
            "id": "scripts_only",
            "paths": ["scripts/build_swarm_operator_runpack.py"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"ready", "degraded"},
            "expect_bucket": "scripts_docs_evidence",
            "expect_heat": "low",
        },
        {
            "id": "provider_rust",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"ready"},
            "expect_bucket": "provider",
            "expect_heat": "high",
            "expect_admission": "safe_to_claim",
            "expect_coordination_status": "ready",
        },
        {
            "id": "mixed_python_rust",
            "paths": ["src/doctor.rs", "scripts/new-tool.py"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"degraded"},
            "expect_bucket": "scripts_docs_evidence",
            "expect_heat": "high",
        },
        {
            "id": "agent_mail_degraded_read_only",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "agent_mail": {
                "health_level": "green",
                "status": "ok",
                "recovery": {"mode": "degraded_read_only"},
            },
            "expect_status": {"degraded"},
            "expect_bucket": "provider",
            "expect_heat": "high",
            "expect_admission": "claim_with_beads_soft_lock",
            "expect_coordination_status": "degraded",
        },
        {
            "id": "empty_ready_queue",
            "paths": ["docs/swarm-operations-runbook.md"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "beads": {"source_status": "fixture", "open_count": 0, "ready_count": 0, "in_progress_count": 0},
            "expect_status": {"blocked"},
            "expect_bucket": "scripts_docs_evidence",
            "expect_heat": "low",
            "expect_admission": "stop_surface_blocker",
            "expect_coordination_status": "blocked",
        },
        {
            "id": "active_overlap",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "agent_mail": {
                "health_level": "green",
                "status": "ok",
                "active_reservations": [
                    {
                        "holder": "OtherAgent",
                        "thread_id": "bd-other",
                        "path_patterns": ["src/providers/**"],
                    }
                ],
            },
            "expect_status": {"blocked"},
            "expect_bucket": "provider",
            "expect_heat": "high",
            "expect_admission": "defer_due_to_collision",
            "expect_coordination_status": "blocked",
        },
        {
            "id": "stale_in_progress_issue",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "beads": {
                "source_status": "fixture",
                "open_count": 1,
                "ready_count": 1,
                "in_progress_count": 1,
                "active_sample": [
                    {
                        "id": "bd-stale",
                        "status": "in_progress",
                        "assignee": "OldAgent",
                        "stale": True,
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                ],
            },
            "expect_status": {"degraded"},
            "expect_bucket": "provider",
            "expect_heat": "high",
            "expect_admission": "claim_with_beads_soft_lock",
            "expect_coordination_status": "degraded",
        },
        {
            "id": "dirty_worktree_admission_denied",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "beads": {
                "source_status": "fixture",
                "open_count": 1,
                "ready_count": 1,
                "in_progress_count": 0,
                "dirty_worktree_paths": ["src/session.rs"],
            },
            "expect_status": {"blocked"},
            "expect_bucket": "provider",
            "expect_heat": "high",
            "expect_admission": "stop_surface_blocker",
            "expect_coordination_status": "blocked",
        },
        {
            "id": "unknown_path",
            "paths": ["weird.binary"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"blocked"},
            "expect_bucket": "unknown",
            "expect_heat": "medium",
            "expect_admission": "stop_surface_blocker",
            "expect_coordination_status": "blocked",
        },
        {
            "id": "stale_proof",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(reusable=False),
            "expect_status": {"degraded"},
            "expect_bucket": "provider",
            "expect_heat": "high",
        },
        {
            "id": "rch_unavailable",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(heavy_allowed=False),
            "proof": fixture_proof_memory(),
            "expect_status": {"degraded"},
            "expect_bucket": "provider",
            "expect_heat": "high",
        },
    ]
    results: list[dict[str, Any]] = []
    for case in cases:
        plan = build_route_plan(
            changed_paths=case["paths"],
            scheduler=case["scheduler"],
            scheduler_source={"path": "fixture", "status": "loaded"},
            proof_memory=case["proof"],
            proof_memory_source={"path": "fixture", "status": "loaded"},
            beads_summary=case.get(
                "beads",
                {"source_status": "fixture", "open_count": 1, "ready_count": 1, "in_progress_count": 0},
            ),
            agent_mail_health=case.get("agent_mail", {"health_level": "green", "status": "ok"}),
            generated_at="2026-05-19T00:00:00+00:00",
            source_bead=DEFAULT_SOURCE_BEAD,
        )
        buckets = set(plan["changed_path_classification"]["bucket_counts"])
        assertions = [
            {
                "id": "status_expected",
                "status": "pass" if plan["status"] in case["expect_status"] else "fail",
                "message": f"status={plan['status']}",
            },
            {
                "id": "bucket_expected",
                "status": "pass" if case["expect_bucket"] in buckets else "fail",
                "message": f"buckets={sorted(buckets)}",
            },
            {
                "id": "rch_commands_guarded",
                "status": "pass"
                if all(
                    (not item["requires_rch"]) or item["command"].startswith("rch exec --")
                    for item in plan["would_run_order"] + plan["deferred_or_blocked"]
                )
                else "fail",
                "message": "RCH-required commands use rch exec --",
            },
            {
                "id": "cache_heat_expected",
                "status": "pass"
                if plan["cache_heat"]["route_heat_level"] == case["expect_heat"]
                else "fail",
                "message": f"route_heat_level={plan['cache_heat']['route_heat_level']}",
            },
            {
                "id": "coalescing_advice_present",
                "status": "pass"
                if plan["coalescing_advice"]["recommended_order"]
                and plan["coalescing_advice"]["advisory_only"] is True
                else "fail",
                "message": "coalescing advice has ordered advisory guidance",
            },
            {
                "id": "coordination_admission_expected",
                "status": "pass"
                if plan["coordination_admission"]["recommended_action"]
                == case.get("expect_admission", "safe_to_claim")
                else "fail",
                "message": f"admission={plan['coordination_admission']['recommended_action']}",
            },
            {
                "id": "coordination_status_expected",
                "status": "pass"
                if plan["coordination_admission"]["status"]
                == case.get("expect_coordination_status", "ready")
                else "fail",
                "message": f"coordination_status={plan['coordination_admission']['status']}",
            },
        ]
        results.append(
            {
                "case_id": case["id"],
                "status": "pass" if all(item["status"] == "pass" for item in assertions) else "fail",
                "assertions": assertions,
                "summary": plan["summary"],
            }
        )
    status = "pass" if all(item["status"] == "pass" for item in results) else "fail"
    return {
        "schema": "pi.validation.semantic_route_plan.self_test.v1",
        "generated_at": utc_now_iso(),
        "status": status,
        "case_count": len(results),
        "results": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changed-path", action="append", default=[], help="Changed path to route; repeatable.")
    parser.add_argument("--changed-paths-json", type=Path, help="JSON object with changed_paths or paths list.")
    parser.add_argument(
        "--from-git",
        action="store_true",
        help="Read changed paths from git diff and git diff --cached.",
    )
    parser.add_argument("--source-root", type=Path, default=Path("."), help="Repository root.")
    parser.add_argument("--scheduler-json", type=Path, default=DEFAULT_SCHEDULER_PATH)
    parser.add_argument("--proof-memory-json", type=Path, default=DEFAULT_PROOF_MEMORY_PATH)
    parser.add_argument("--agent-mail-health-json", type=Path)
    parser.add_argument("--beads-jsonl", type=Path, default=DEFAULT_BEADS_PATH)
    parser.add_argument("--source-bead", default=DEFAULT_SOURCE_BEAD)
    parser.add_argument("--out", type=Path, help="Write JSON output; refuses to overwrite.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    parser.add_argument("--self-test", action="store_true", help="Run deterministic built-in fixtures.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        payload = run_self_test()
        text = json_dumps(payload, pretty=True)
        if args.out:
            no_overwrite_write(args.out, text)
        else:
            sys.stdout.write(text)
        return 0 if payload["status"] == "pass" else 1

    root = args.source_root.resolve()
    changed_paths = [normalize_path(path) for path in args.changed_path]
    if args.changed_paths_json:
        changed_paths.extend(load_changed_paths_json(args.changed_paths_json))
    if args.from_git or not changed_paths:
        changed_paths.extend(git_changed_paths(root))
    changed_paths = sorted(set(path for path in changed_paths if path))

    scheduler, scheduler_source = load_optional_json(root / args.scheduler_json)
    proof_memory, proof_source = load_optional_json(root / args.proof_memory_json)
    agent_mail_health = load_json(root / args.agent_mail_health_json) if args.agent_mail_health_json else None
    beads_summary = load_beads_summary(root / args.beads_jsonl)
    plan = build_route_plan(
        changed_paths=changed_paths,
        scheduler=scheduler,
        scheduler_source=scheduler_source,
        proof_memory=proof_memory,
        proof_memory_source=proof_source,
        beads_summary=beads_summary,
        agent_mail_health=agent_mail_health,
        generated_at=utc_now_iso(),
        source_bead=args.source_bead,
    )
    text = json_dumps(plan, pretty=args.pretty)
    if args.out:
        no_overwrite_write(args.out, text)
    else:
        sys.stdout.write(text)
    return 0 if plan["status"] != "blocked" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RoutePlanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
