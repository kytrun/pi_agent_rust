#!/usr/bin/env python3
"""Generate the operator maintenance dashboard artifact.

The dashboard tracks the weekly burn-down inputs that matter for release
resilience: open critical/high parity-ledger gaps, open Beads work, RCH
artifact retrieval drift, and the current drop-in hard-gate verdict trend.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "pi.operations.maintenance_dashboard.v1"
DEFAULT_OUTPUT = Path("docs/evidence/maintenance-dashboard.json")
LEDGER_PATH = Path("docs/evidence/dropin-parity-gap-ledger.json")
VERDICT_PATH = Path("docs/evidence/dropin-certification-verdict.json")
JSON_DECODER = json.JSONDecoder()
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
DEFAULT_RCH_LOG_GLOBS = ("tests/e2e_results/*/build.log",)
MAX_RCH_LOG_FILES = 64
MAX_RCH_LOG_BYTES = 2 * 1024 * 1024
MAX_EXAMPLE_CHARS = 240


RCH_DRIFT_CATEGORIES: dict[str, dict[str, Any]] = {
    "missing_remote_target_directory": {
        "drift_class": "infrastructure_drift",
        "blocks": "evidence_refresh",
        "release_blocking": False,
        "remediation": "Create or remap the worker-side target/output directory before rerunning the RCH-backed evidence refresh.",
    },
    "rsync_mkstemp_no_such_file": {
        "drift_class": "evidence_retrieval_drift",
        "blocks": "specific_evidence_refresh",
        "release_blocking": False,
        "remediation": "Fix RCH artifact retrieval/writeback path creation or rerun with worker-local output paths.",
    },
    "disk_pressure": {
        "drift_class": "infrastructure_drift",
        "blocks": "release_gate_until_retried",
        "release_blocking": True,
        "remediation": "Move CARGO_TARGET_DIR and TMPDIR to high-capacity scratch, clear disposable build pressure with approved cleanup, then rerun the gate.",
    },
    "remote_dependency_preflight_blocked": {
        "drift_class": "code_regression",
        "blocks": "release_gate_until_fixed",
        "release_blocking": True,
        "remediation": "Fix the dependency/source preflight failure or pin the missing dependency before rerunning RCH validation.",
    },
    "worker_workspace_shadow": {
        "drift_class": "infrastructure_drift",
        "blocks": "release_gate_until_worker_workspace_fixed",
        "release_blocking": True,
        "remediation": "Fix the RCH worker checkout/workdir so cargo resolves pi_agent_rust directly; do not treat parent-workspace manifest failures as local code regressions.",
    },
    "artifact_retrieval_warning_after_success": {
        "drift_class": "evidence_retrieval_drift",
        "blocks": "specific_evidence_refresh",
        "release_blocking": False,
        "remediation": "Treat the remote command as inconclusive for evidence until artifact retrieval is clean or the expected artifacts are regenerated locally.",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root. Defaults to this script's parent repository.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Dashboard output path, relative to repo root unless absolute.",
    )
    parser.add_argument(
        "--generated-at",
        help="Override generated_at_utc for deterministic tests.",
    )
    parser.add_argument(
        "--rch-log-glob",
        action="append",
        default=None,
        help=(
            "Repository-relative glob for RCH/e2e build logs to classify. "
            "May be repeated; defaults to tests/e2e_results/*/build.log."
        ),
    )
    parser.add_argument(
        "--max-rch-log-files",
        type=int,
        default=MAX_RCH_LOG_FILES,
        help="Maximum number of RCH log files to scan.",
    )
    parser.add_argument(
        "--max-rch-log-bytes",
        type=int,
        default=MAX_RCH_LOG_BYTES,
        help="Maximum bytes to scan per RCH log file.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run fixture checks for RCH artifact retrieval drift classification.",
    )
    return parser.parse_args()


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_json_value(payload: str, context: str) -> Any:
    try:
        return JSON_DECODER.decode(payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{context}: invalid JSON: {exc}") from exc


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return parse_json_value(path.read_text(encoding="utf-8"), str(path))


def read_issues(path: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not path.exists():
        return issues
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        record = parse_json_value(stripped, f"{path}:{line_number}: invalid JSONL record")
        if isinstance(record, dict):
            issues.append(record)
    return issues


def git_metadata_dir(repo_root: Path) -> Path | None:
    git_path = repo_root / ".git"
    if git_path.is_dir():
        return git_path
    if git_path.is_file():
        try:
            gitdir_line = git_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        prefix = "gitdir: "
        if gitdir_line.startswith(prefix):
            gitdir = Path(gitdir_line[len(prefix) :])
            return gitdir if gitdir.is_absolute() else (repo_root / gitdir).resolve()
    return None


def read_packed_ref(git_dir: Path, ref_name: str) -> str | None:
    packed_refs = git_dir / "packed-refs"
    if not packed_refs.exists():
        return None
    try:
        lines = packed_refs.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "^")):
            continue
        parts = stripped.split(" ", 1)
        if len(parts) == 2 and parts[1] == ref_name:
            return parts[0]
    return None


def git_commit(repo_root: Path) -> str:
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    git_dir = git_metadata_dir(repo_root)
    if git_dir is None:
        return "unknown"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    ref_prefix = "ref: "
    if not head.startswith(ref_prefix):
        return head or "unknown"
    ref_name = head[len(ref_prefix) :]
    try:
        ref_value = (git_dir / ref_name).read_text(encoding="utf-8").strip()
    except OSError:
        ref_value = read_packed_ref(git_dir, ref_name)
    return ref_value or "unknown"


def is_open_ledger_gap(entry: dict[str, Any]) -> bool:
    if entry.get("severity") not in {"critical", "high"}:
        return False
    retired_values = {"retired", "resolved", "closed"}
    status = str(entry.get("status", "")).lower()
    mismatch_kind = str(entry.get("mismatch_kind", "")).lower()
    return status not in retired_values and mismatch_kind not in retired_values


def summarize_ledger(ledger: dict[str, Any]) -> dict[str, Any]:
    entries = [entry for entry in ledger.get("entries", []) if isinstance(entry, dict)]
    open_gaps = [entry for entry in entries if is_open_ledger_gap(entry)]
    by_severity = Counter(str(entry.get("severity", "unknown")) for entry in open_gaps)
    by_area = Counter(str(entry.get("area", "unknown")) for entry in open_gaps)
    return {
        "open_critical_high_count": len(open_gaps),
        "open_by_severity": dict(sorted(by_severity.items())),
        "open_by_area": dict(sorted(by_area.items())),
        "open_gaps": [
            {
                "gap_id": entry.get("gap_id"),
                "severity": entry.get("severity"),
                "area": entry.get("area"),
                "status": entry.get("status"),
                "owner_issue_primary": entry.get("owner_issue_primary"),
            }
            for entry in sorted(open_gaps, key=lambda e: str(e.get("gap_id", "")))
        ],
    }


def summarize_beads(issues: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = Counter(str(issue.get("status", "unknown")) for issue in issues)
    open_issues = [issue for issue in issues if issue.get("status") == "open"]
    in_progress = [issue for issue in issues if issue.get("status") == "in_progress"]
    open_by_priority = Counter(str(issue.get("priority", "unknown")) for issue in open_issues)
    open_by_type = Counter(str(issue.get("issue_type", "unknown")) for issue in open_issues)
    return {
        "total_count": len(issues),
        "by_status": dict(sorted(by_status.items())),
        "open_count": len(open_issues),
        "in_progress_count": len(in_progress),
        "open_by_priority": dict(sorted(open_by_priority.items())),
        "open_by_type": dict(sorted(open_by_type.items())),
        "open_high_priority": [
            {
                "id": issue.get("id"),
                "priority": issue.get("priority"),
                "title": issue.get("title"),
                "labels": issue.get("labels", []),
            }
            for issue in sorted(
                open_issues,
                key=lambda i: (int(i.get("priority", 99)), str(i.get("id", ""))),
            )
            if int(issue.get("priority", 99)) <= 1
        ],
    }


def summarize_verdict(verdict: dict[str, Any]) -> dict[str, Any]:
    gates = verdict.get("hard_gate_results", [])
    if not isinstance(gates, list):
        gates = []
    status_counts = Counter(str(gate.get("status", "unknown")) for gate in gates if isinstance(gate, dict))
    blocking_not_pass = [
        {
            "gate_id": gate.get("gate_id"),
            "status": gate.get("status"),
            "detail": gate.get("detail"),
            "artifact_path": gate.get("artifact_path"),
            "bead": gate.get("bead"),
        }
        for gate in gates
        if isinstance(gate, dict) and gate.get("blocking") and gate.get("status") != "pass"
    ]
    return {
        "overall_verdict": verdict.get("overall_verdict", "unknown"),
        "generated_at_utc": verdict.get("generated_at_utc"),
        "git_commit": verdict.get("git_commit"),
        "hard_gate_count": len(gates),
        "hard_gate_status_counts": dict(sorted(status_counts.items())),
        "blocking_not_pass": blocking_not_pass,
    }


def truncate_example(line: str) -> str:
    compact = " ".join(ANSI_ESCAPE_RE.sub("", line).strip().split())
    if len(compact) <= MAX_EXAMPLE_CHARS:
        return compact
    return f"{compact[: MAX_EXAMPLE_CHARS - 3]}..."


def classify_rch_drift_line(line: str, saw_success: bool) -> str | None:
    lowered = line.lower()
    if "mkstemp" in lowered and "rsync" in lowered and "no such file" in lowered:
        return "rsync_mkstemp_no_such_file"
    if "no space left on device" in lowered or "enospc" in lowered:
        return "disk_pressure"
    if (
        ("remote target dir" in lowered or "remote target directory" in lowered)
        and any(term in lowered for term in ("missing", "not found", "no such file"))
    ):
        return "missing_remote_target_directory"
    if any(
        term in lowered
        for term in (
            "remote dependency preflight blocked",
            "dependency preflight blocked",
            "failed to load source for dependency",
            "failed to get `",
        )
    ):
        return "remote_dependency_preflight_blocked"
    if (
        ("failed to load manifest for workspace member" in lowered)
        or ("referenced by workspace at" in lowered and "cargo.toml" in lowered)
        or (
            "failed to read" in lowered
            and "cargo.toml" in lowered
            and any(path in lowered for path in ("/data/toon_rust", "/data/projects/crates/"))
        )
    ):
        return "worker_workspace_shadow"
    if (
        "artifact retrieval warning" in lowered
        or "no artifacts retrieved" in lowered
        or "rsync reported partial transfer" in lowered
    ):
        if saw_success:
            return "artifact_retrieval_warning_after_success"
        return None
    return None


def line_indicates_remote_success(line: str) -> bool:
    lowered = line.lower()
    stripped = lowered.strip()
    return (
        "remote command finished: exit=0" in lowered
        or "test result: ok" in lowered
        or (" finished `" in lowered and "target(s)" in lowered)
        or (stripped.startswith("finished ") and "target(s)" in lowered)
    )


def empty_rch_category(category_id: str) -> dict[str, Any]:
    metadata = RCH_DRIFT_CATEGORIES[category_id]
    return {
        "id": category_id,
        "count": 0,
        "drift_class": metadata["drift_class"],
        "blocks": metadata["blocks"],
        "release_blocking": metadata["release_blocking"],
        "remediation": metadata["remediation"],
        "first_example": None,
        "last_example": None,
        "source_count": 0,
    }


def resolve_rch_log_paths(repo_root: Path, patterns: list[str], max_files: int) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in sorted(repo_root.glob(pattern)):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            try:
                resolved.relative_to(repo_root.resolve())
            except ValueError:
                continue
            seen.add(resolved)
            paths.append(path)
            if len(paths) >= max_files:
                return paths
    return paths


def scan_rch_log_file(
    repo_root: Path,
    path: Path,
    max_bytes: int,
    categories: dict[str, dict[str, Any]],
) -> tuple[int, bool]:
    scanned_bytes = 0
    saw_success = False
    matched_categories: set[str] = set()
    truncated = False
    relative_path = str(path.relative_to(repo_root))
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            scanned_bytes += len(line.encode("utf-8", errors="replace"))
            if scanned_bytes > max_bytes:
                truncated = True
                break
            if line_indicates_remote_success(line):
                saw_success = True
            category_id = classify_rch_drift_line(line, saw_success)
            if category_id is None:
                continue
            category = categories[category_id]
            example = {
                "path": relative_path,
                "line_number": line_number,
                "line": truncate_example(line),
                "after_success": saw_success,
            }
            category["count"] += 1
            category["first_example"] = category["first_example"] or example
            category["last_example"] = example
            matched_categories.add(category_id)
    for category_id in matched_categories:
        categories[category_id]["source_count"] += 1
    return scanned_bytes, truncated


def summarize_rch_artifact_retrieval_drift(
    repo_root: Path,
    patterns: list[str],
    max_files: int,
    max_bytes_per_file: int,
) -> dict[str, Any]:
    categories = {
        category_id: empty_rch_category(category_id)
        for category_id in RCH_DRIFT_CATEGORIES
    }
    log_paths = resolve_rch_log_paths(repo_root, patterns, max_files)
    total_scanned_bytes = 0
    truncated_files: list[str] = []
    for path in log_paths:
        scanned_bytes, truncated = scan_rch_log_file(
            repo_root,
            path,
            max_bytes_per_file,
            categories,
        )
        total_scanned_bytes += scanned_bytes
        if truncated:
            truncated_files.append(str(path.relative_to(repo_root)))
    nonzero_categories = {
        category_id: category
        for category_id, category in categories.items()
        if category["count"] > 0
    }
    by_drift_class = Counter(
        category["drift_class"]
        for category in nonzero_categories.values()
        for _ in range(int(category["count"]))
    )
    release_blocking_categories = sorted(
        category_id
        for category_id, category in nonzero_categories.items()
        if category["release_blocking"]
    )
    return {
        "status": "degraded" if nonzero_categories else "clear",
        "scan_limits": {
            "patterns": patterns,
            "max_files": max_files,
            "max_bytes_per_file": max_bytes_per_file,
        },
        "scanned_file_count": len(log_paths),
        "scanned_bytes": total_scanned_bytes,
        "truncated_files": truncated_files,
        "total_match_count": sum(int(category["count"]) for category in nonzero_categories.values()),
        "by_drift_class": dict(sorted(by_drift_class.items())),
        "release_blocking_categories": release_blocking_categories,
        "categories": dict(sorted(nonzero_categories.items())),
    }


def update_trend_history(
    existing_dashboard: dict[str, Any],
    generated_at: str,
    ledger_summary: dict[str, Any],
    bead_summary: dict[str, Any],
    verdict_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    snapshot = {
        "date_utc": generated_at[:10],
        "open_critical_high_ledger_gaps": ledger_summary["open_critical_high_count"],
        "open_beads": bead_summary["open_count"],
        "in_progress_beads": bead_summary["in_progress_count"],
        "overall_verdict": verdict_summary["overall_verdict"],
        "hard_gate_status_counts": verdict_summary["hard_gate_status_counts"],
    }
    history = existing_dashboard.get("trend_history", [])
    if not isinstance(history, list):
        history = []
    history = [
        item for item in history if isinstance(item, dict) and item.get("date_utc") != snapshot["date_utc"]
    ]
    history.append(snapshot)
    return history[-26:]


def build_dashboard(
    repo_root: Path,
    output_path: Path,
    generated_at: str,
    rch_log_patterns: list[str],
    max_rch_log_files: int,
    max_rch_log_bytes: int,
) -> dict[str, Any]:
    ledger_path = repo_root / LEDGER_PATH
    verdict_path = repo_root / VERDICT_PATH
    issues_path = repo_root / ".beads" / "issues.jsonl"

    ledger = read_json(ledger_path, {"entries": []})
    verdict = read_json(verdict_path, {"hard_gate_results": []})
    issues = read_issues(issues_path)
    existing_dashboard = read_json(output_path, {})

    ledger_summary = summarize_ledger(ledger)
    bead_summary = summarize_beads(issues)
    verdict_summary = summarize_verdict(verdict)
    rch_drift_summary = summarize_rch_artifact_retrieval_drift(
        repo_root,
        rch_log_patterns,
        max_rch_log_files,
        max_rch_log_bytes,
    )

    dashboard = {
        "schema": SCHEMA,
        "generated_at_utc": generated_at,
        "git_commit": git_commit(repo_root),
        "source_files": {
            "ledger": str(ledger_path.relative_to(repo_root)),
            "beads": str(issues_path.relative_to(repo_root)),
            "verdict": str(verdict_path.relative_to(repo_root)),
            "rch_artifact_logs": rch_log_patterns,
        },
        "metrics": {
            "ledger": ledger_summary,
            "beads": bead_summary,
            "hard_gates": verdict_summary,
            "rch_artifact_retrieval_drift": rch_drift_summary,
        },
        "trend_history": update_trend_history(
            existing_dashboard,
            generated_at,
            ledger_summary,
            bead_summary,
            verdict_summary,
        ),
    }
    return dashboard


def write_dashboard(repo_root: Path, output_path: Path, dashboard: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dashboard, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test() -> int:
    repo_root = Path(tempfile.mkdtemp(prefix="pi-maintenance-dashboard-"))
    try:
        def write_json(path: str, payload: Any) -> None:
            target = repo_root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(payload) + "\n", encoding="utf-8")

        (repo_root / ".git").mkdir(parents=True)
        (repo_root / ".git/HEAD").write_text("fixture-head\n", encoding="utf-8")
        (repo_root / ".beads").mkdir(parents=True)
        (repo_root / ".beads/issues.jsonl").write_text(
            json.dumps(
                {
                    "id": "bd-fixture",
                    "status": "open",
                    "priority": 2,
                    "issue_type": "task",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        write_json("docs/evidence/dropin-parity-gap-ledger.json", {"entries": []})
        write_json(
            "docs/evidence/dropin-certification-verdict.json",
            {"hard_gate_results": [], "overall_verdict": "FIXTURE"},
        )
        log_dir = repo_root / "tests/e2e_results/fixture"
        log_dir.mkdir(parents=True)
        (log_dir / "build.log").write_text(
            "\n".join(
                [
                    "remote target directory /worker/missing-target not found",
                    "rsync: mkstemp \"/tmp/out/.artifact.tmp\" failed: No such file or directory (2)",
                    "error: No space left on device while retrieving artifacts",
                    "remote dependency preflight blocked: failed to load source for dependency `asupersync`",
                    "error: failed to load manifest for workspace member `/data/projects/crates/fwc` referenced by workspace at `/data/projects/Cargo.toml`",
                    "Caused by: failed to read `/data/toon_rust/Cargo.toml`",
                    "WARN rch::transfer: No artifacts retrieved before remote success",
                    "Remote command finished: exit=0 in 100ms",
                    "WARN rch::transfer: No artifacts retrieved from worker - build may have failed or artifact patterns may be misconfigured",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        dashboard = build_dashboard(
            repo_root=repo_root,
            output_path=repo_root / "docs/evidence/maintenance-dashboard.json",
            generated_at="2026-05-15T00:00:00Z",
            rch_log_patterns=["tests/e2e_results/*/build.log"],
            max_rch_log_files=8,
            max_rch_log_bytes=4096,
        )
        drift = dashboard["metrics"]["rch_artifact_retrieval_drift"]
        expected = set(RCH_DRIFT_CATEGORIES)
        observed = set(drift["categories"])
        if observed != expected:
            print(json.dumps(drift, indent=2, sort_keys=True))
            print(f"SELF-TEST FAIL: expected categories {sorted(expected)}, observed {sorted(observed)}")
            return 2
        if drift["by_drift_class"] != {
            "code_regression": 1,
            "evidence_retrieval_drift": 2,
            "infrastructure_drift": 4,
        }:
            print(json.dumps(drift, indent=2, sort_keys=True))
            print("SELF-TEST FAIL: drift classes should distinguish code, infra, and retrieval drift")
            return 2
        if set(drift["release_blocking_categories"]) != {
            "disk_pressure",
            "remote_dependency_preflight_blocked",
            "worker_workspace_shadow",
        }:
            print(json.dumps(drift, indent=2, sort_keys=True))
            print("SELF-TEST FAIL: release-blocking categories are wrong")
            return 2
        if drift["categories"]["worker_workspace_shadow"]["count"] != 2:
            print(json.dumps(drift, indent=2, sort_keys=True))
            print("SELF-TEST FAIL: worker workspace shadow lines should be classified")
            return 2
        if drift["categories"]["artifact_retrieval_warning_after_success"]["count"] != 1:
            print(json.dumps(drift, indent=2, sort_keys=True))
            print("SELF-TEST FAIL: pre-success artifact retrieval warnings must not count as after-success drift")
            return 2
    except Exception as exc:
        print(f"SELF-TEST ERROR in {repo_root}: {exc}")
        return 2
    print(f"SELF-TEST PASS: fixture repo left at {repo_root}")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()
    repo_root = args.repo_root.resolve()
    output_path = args.output if args.output.is_absolute() else repo_root / args.output
    generated_at = args.generated_at or os.environ.get("GENERATED_AT_UTC") or utc_now()
    rch_log_patterns = args.rch_log_glob or list(DEFAULT_RCH_LOG_GLOBS)

    dashboard = build_dashboard(
        repo_root=repo_root,
        output_path=output_path,
        generated_at=generated_at,
        rch_log_patterns=rch_log_patterns,
        max_rch_log_files=args.max_rch_log_files,
        max_rch_log_bytes=args.max_rch_log_bytes,
    )
    write_dashboard(repo_root, output_path, dashboard)
    try:
        display_path = output_path.relative_to(repo_root)
    except ValueError:
        display_path = output_path
    print(f"Wrote {display_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
