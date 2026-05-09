#!/usr/bin/env python3
"""Preflight performance budget evidence inputs.

This is a fast, read-only check for agents before starting expensive perf runs.
It mirrors the artifact paths used by tests/perf_budgets.rs and emits stable
JSON describing missing or stale inputs, suggested RCH commands, and known
blocker context.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "pi.perf.budget_preflight.v1"
DEFAULT_MAX_ARTIFACT_AGE_HOURS = 24.0
EXTENSION_BLOCKER_BEAD = "bd-2zcs5.51"


@dataclass(frozen=True)
class BudgetContract:
    name: str
    category: str
    methodology: str
    ci_enforced: bool


@dataclass(frozen=True)
class ArtifactGroup:
    contract_id: str
    budget_names: tuple[str, ...]
    candidates: tuple[Path, ...]
    suggested_commands: tuple[str, ...]
    reason: str
    expected_outputs: tuple[Path, ...]
    blocker: str | None = None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_target_dir(repo_root: Path, raw_target_dir: str | None) -> Path:
    if raw_target_dir:
        target_dir = Path(raw_target_dir).expanduser()
        if target_dir.is_absolute():
            return target_dir
        return repo_root / target_dir
    return repo_root / "target"


def rel_or_abs(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def parse_budget_contracts(perf_budgets_rs: Path) -> list[BudgetContract]:
    text = perf_budgets_rs.read_text(encoding="utf-8")
    contracts: list[BudgetContract] = []
    for block in re.findall(r"Budget\s*\{(.*?)\},", text, flags=re.S):
        name = re.search(r'name:\s*"([^"]+)"', block)
        category = re.search(r'category:\s*"([^"]+)"', block)
        methodology = re.search(r'methodology:\s*"([^"]+)"', block)
        ci_enforced = re.search(r"ci_enforced:\s*(true|false)", block)
        if not name or not category or not methodology or not ci_enforced:
            continue
        contracts.append(
            BudgetContract(
                name=name.group(1),
                category=category.group(1),
                methodology=methodology.group(1),
                ci_enforced=ci_enforced.group(1) == "true",
            )
        )
    return contracts


def file_age_hours(path: Path, now: datetime) -> float | None:
    try:
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None
    return (now - modified).total_seconds() / 3600.0


def existing_fresh_candidates(
    candidates: tuple[Path, ...], max_age_hours: float, now: datetime
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    fresh: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    for path in candidates:
        if not path.is_file():
            continue
        age = file_age_hours(path, now)
        artifact = {
            "path": str(path),
            "age_hours": age,
            "max_age_hours": max_age_hours,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        if age is not None and age <= max_age_hours:
            fresh.append(artifact)
        else:
            stale.append(artifact)
    return fresh, stale


def glob_estimates(base: Path) -> tuple[Path, ...]:
    pattern = str(base / "*" / "new" / "estimates.json")
    matches = tuple(Path(path) for path in sorted(glob.glob(pattern)))
    return matches or (base,)


def pijs_candidates(target_dir: Path) -> tuple[Path, ...]:
    perf_dir = target_dir / "perf"
    return tuple(
        perf_dir / relative
        for relative in (
            "perf/pijs_workload_perf.jsonl",
            "release/pijs_workload_release.jsonl",
            "debug/pijs_workload_debug.jsonl",
            "pijs_workload.jsonl",
            "results/pijs_workload.jsonl",
        )
    )


def binary_candidates(target_dir: Path, release_override: str | None) -> tuple[Path, ...]:
    paths: list[Path] = []
    if release_override:
        paths.append(Path(release_override).expanduser())
    paths.extend((target_dir / "release" / "pi", target_dir / "perf" / "pi"))
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            deduped.append(path)
    return tuple(deduped)


def artifact_groups(repo_root: Path, target_dir: Path) -> list[ArtifactGroup]:
    cargo_env = (
        'export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target}" '
        'TMPDIR="${TMPDIR:-/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp}" && '
        'mkdir -p "$CARGO_TARGET_DIR" "$TMPDIR"'
    )
    bench_prefix = f"{cargo_env} && rch exec -- cargo"
    return [
        ArtifactGroup(
            contract_id="startup_version_p95",
            budget_names=("startup_version_p95",),
            candidates=(target_dir / "criterion/startup/version/warm/new/estimates.json",),
            suggested_commands=(
                f"{bench_prefix} bench --bench system --profile perf startup",
            ),
            reason="startup/version Criterion estimate required by tests/perf_budgets.rs",
            expected_outputs=(target_dir / "criterion/startup/version/warm/new/estimates.json",),
        ),
        ArtifactGroup(
            contract_id="extension_criterion_load_init",
            budget_names=("ext_cold_load_simple_p95",),
            candidates=(
                target_dir
                / "criterion/ext_load_init/load_init_cold/hello/new/estimates.json",
            ),
            suggested_commands=(
                f"{bench_prefix} bench --bench extensions --profile perf ext_load_init",
            ),
            reason="ext_load_init/load_init_cold/hello Criterion estimate required by tests/perf_budgets.rs",
            expected_outputs=(
                target_dir
                / "criterion/ext_load_init/load_init_cold/hello/new/estimates.json",
            ),
            blocker=EXTENSION_BLOCKER_BEAD,
        ),
        ArtifactGroup(
            contract_id="pijs_workload",
            budget_names=("tool_call_latency_p99", "tool_call_throughput_min"),
            candidates=pijs_candidates(target_dir),
            suggested_commands=(
                f"{bench_prefix} build --profile perf --no-default-features --bin pijs_workload",
                f"{cargo_env} && BENCH_CARGO_RUNNER=rch ./scripts/bench_extension_workloads.sh",
            ),
            reason="pijs_workload JSONL required for tool-call latency and throughput budgets",
            expected_outputs=pijs_candidates(target_dir),
        ),
        ArtifactGroup(
            contract_id="extension_criterion_policy",
            budget_names=("policy_eval_p99",),
            candidates=glob_estimates(target_dir / "criterion/ext_policy/evaluate"),
            suggested_commands=(
                f"{bench_prefix} bench --bench extensions --profile perf ext_policy",
            ),
            reason="ext_policy/evaluate Criterion estimates required by tests/perf_budgets.rs",
            expected_outputs=(target_dir / "criterion/ext_policy/evaluate/*/new/estimates.json",),
            blocker=EXTENSION_BLOCKER_BEAD,
        ),
        ArtifactGroup(
            contract_id="release_binary",
            budget_names=("binary_size_release",),
            candidates=binary_candidates(target_dir, os.environ.get("PERF_RELEASE_BINARY_PATH")),
            suggested_commands=(
                f"{bench_prefix} build --bin pi --release",
            ),
            reason="release pi binary required for binary_size_release budget",
            expected_outputs=(target_dir / "release/pi",),
        ),
        ArtifactGroup(
            contract_id="extension_criterion_protocol",
            budget_names=("protocol_parse_p99",),
            candidates=glob_estimates(target_dir / "criterion/ext_protocol/parse_and_validate"),
            suggested_commands=(
                f"{bench_prefix} bench --bench extensions --profile perf ext_protocol",
            ),
            reason="ext_protocol/parse_and_validate Criterion estimates required by tests/perf_budgets.rs",
            expected_outputs=(
                target_dir / "criterion/ext_protocol/parse_and_validate/*/new/estimates.json",
            ),
            blocker=EXTENSION_BLOCKER_BEAD,
        ),
        ArtifactGroup(
            contract_id="extension_benchmark_stratification",
            budget_names=(),
            candidates=(
                target_dir / "perf/extension_benchmark_stratification.json",
                target_dir / "perf/results/extension_benchmark_stratification.json",
                repo_root / "tests/perf/reports/extension_benchmark_stratification.json",
            ),
            suggested_commands=(
                f"{bench_prefix} test --test perf_budgets --profile perf generate_budget_report -- --nocapture",
            ),
            reason="global extension claim data contract consumed by collect_data_contract_failures",
            expected_outputs=(
                target_dir / "perf/extension_benchmark_stratification.json",
                repo_root / "tests/perf/reports/extension_benchmark_stratification.json",
            ),
        ),
        ArtifactGroup(
            contract_id="phase1_matrix_validation",
            budget_names=(),
            candidates=(
                target_dir / "perf/results/phase1_matrix_validation.json",
                repo_root / "tests/perf/reports/phase1_matrix_validation.json",
            ),
            suggested_commands=(
                f"{bench_prefix} test --test perf_budgets --profile perf generate_budget_report -- --nocapture",
            ),
            reason="phase1 weighted attribution data contract consumed by collect_data_contract_failures",
            expected_outputs=(
                target_dir / "perf/results/phase1_matrix_validation.json",
                repo_root / "tests/perf/reports/phase1_matrix_validation.json",
            ),
        ),
    ]


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def report_status(repo_root: Path, now: datetime) -> dict[str, Any]:
    path = repo_root / "tests/perf/reports/budget_summary.json"
    payload = read_json(path)
    base: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "age_hours": file_age_hours(path, now) if path.exists() else None,
        "schema": payload.get("schema") if payload else None,
        "generated_at": payload.get("generated_at") if payload else None,
    }
    if payload:
        for key in ("ci_fail", "ci_no_data", "data_contract_failures_count"):
            base[key] = payload.get(key)
    return base


def rch_status(skip: bool) -> dict[str, Any]:
    path = shutil.which("rch")
    if path is None:
        return {
            "available": False,
            "healthy": False,
            "checked": False,
            "command": "rch check --quiet",
            "detail": "rch executable not found in PATH",
        }
    if skip:
        return {
            "available": True,
            "healthy": None,
            "checked": False,
            "command": "rch check --quiet",
            "detail": "skipped by --skip-rch-check",
        }
    try:
        result = subprocess.run(
            [path, "check", "--quiet"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "healthy": False,
            "checked": True,
            "command": "rch check --quiet",
            "detail": "timed out after 10s",
        }
    detail = (result.stderr or result.stdout or "").strip()
    return {
        "available": True,
        "healthy": result.returncode == 0,
        "checked": True,
        "command": "rch check --quiet",
        "detail": detail,
    }


def build_report(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    repo_root = Path(args.repo_root).resolve() if args.repo_root else repo_root_from_script()
    now = utc_now()
    target_dir = resolve_target_dir(repo_root, args.cargo_target_dir or os.environ.get("CARGO_TARGET_DIR"))
    max_age_hours = args.max_age_hours
    contracts = parse_budget_contracts(repo_root / "tests/perf_budgets.rs")
    ci_contracts = [contract for contract in contracts if contract.ci_enforced]

    missing: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    fresh: list[dict[str, Any]] = []
    suggestions: list[str] = []
    expected_outputs: list[str] = []
    recognized_blockers: list[dict[str, Any]] = []

    groups = artifact_groups(repo_root, target_dir)
    for group in groups:
        group_fresh, group_stale = existing_fresh_candidates(group.candidates, max_age_hours, now)
        expected_outputs.extend(str(path) for path in group.expected_outputs)
        if group_fresh:
            fresh.append(
                {
                    "contract_id": group.contract_id,
                    "budget_names": list(group.budget_names),
                    "artifacts": group_fresh,
                }
            )
            continue
        issue = {
            "contract_id": group.contract_id,
            "budget_names": list(group.budget_names),
            "reason": group.reason,
            "expected_paths": [str(path) for path in group.candidates],
            "suggested_commands": list(group.suggested_commands),
            "blocker": group.blocker,
        }
        missing.append(issue)
        suggestions.extend(group.suggested_commands)
        if group_stale:
            for artifact in group_stale:
                artifact["contract_id"] = group.contract_id
                artifact["budget_names"] = list(group.budget_names)
                stale.append(artifact)
        if group.blocker:
            recognized_blockers.append(
                {
                    "bead": group.blocker,
                    "contract_id": group.contract_id,
                    "budget_names": list(group.budget_names),
                    "detail": "missing or stale extension Criterion input for bd-2zcs5.51",
                }
            )

    report = report_status(repo_root, now)
    report_blockers: list[str] = []
    for key in ("ci_fail", "ci_no_data", "data_contract_failures_count"):
        value = report.get(key)
        if isinstance(value, int | float) and value != 0:
            report_blockers.append(f"budget_summary.{key}={value}")

    dedup_suggestions = list(dict.fromkeys(suggestions))
    dedup_expected = list(dict.fromkeys(expected_outputs))
    ready = not missing and not stale and not report_blockers
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": iso_now(),
        "repo_root": str(repo_root),
        "budget_contract_source": {
            "path": str(repo_root / "tests/perf_budgets.rs"),
            "sha256": sha256_file(repo_root / "tests/perf_budgets.rs"),
            "total_budgets": len(contracts),
            "ci_enforced_budgets": [contract.name for contract in ci_contracts],
        },
        "cargo_target_dir": str(target_dir),
        "max_artifact_age_hours": max_age_hours,
        "rch": rch_status(args.skip_rch_check),
        "current_report": report,
        "readiness": "ready" if ready else "blocked",
        "missing_budget_artifacts": missing,
        "stale_artifacts": stale,
        "fresh_artifacts": fresh,
        "recognized_blockers": recognized_blockers,
        "suggested_commands": dedup_suggestions,
        "expected_output_paths": dedup_expected,
        "safety_notes": [
            "All CPU-intensive cargo refresh commands must be run through rch exec -- ...",
            "Set CARGO_TARGET_DIR and TMPDIR to /data/tmp/pi_agent_rust_cargo/${USER:-agent}/... before refreshing evidence.",
            "Do not refresh tests/perf/reports/budget_summary.json until missing_budget_artifacts and stale_artifacts are empty.",
        ],
        "report_blockers": report_blockers,
    }
    return (0 if ready else 1), payload


def write_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def run_self_test() -> int:
    def write_fixture(root: Path, include_policy: bool) -> None:
        (root / "tests/perf/reports").mkdir(parents=True)
        (root / "target/criterion/ext_load_init/load_init_cold/hello/new").mkdir(parents=True)
        if include_policy:
            (root / "target/criterion/ext_policy/evaluate/safe/new").mkdir(parents=True)
        (root / "target/criterion/ext_protocol/parse_and_validate/log/new").mkdir(parents=True)
        (root / "target/perf/perf").mkdir(parents=True)
        (root / "target/release").mkdir(parents=True)
        (root / "target/perf/results").mkdir(parents=True)
        (root / "tests/perf_budgets.rs").write_text(
            """
            const BUDGETS: &[Budget] = &[
              Budget { name: "startup_version_p95", category: "startup", metric: "p95", unit: "ms", threshold: 100.0, methodology: "criterion: startup", ci_enforced: true },
              Budget { name: "ext_cold_load_simple_p95", category: "extension", metric: "p95", unit: "ms", threshold: 5.0, methodology: "criterion: ext_load_init", ci_enforced: true },
              Budget { name: "tool_call_latency_p99", category: "tool_call", metric: "p99", unit: "us", threshold: 200.0, methodology: "pijs_workload", ci_enforced: true },
              Budget { name: "tool_call_throughput_min", category: "tool_call", metric: "min", unit: "calls/sec", threshold: 5000.0, methodology: "pijs_workload", ci_enforced: true },
              Budget { name: "policy_eval_p99", category: "policy", metric: "p99", unit: "ns", threshold: 500.0, methodology: "criterion: ext_policy", ci_enforced: true },
              Budget { name: "idle_memory_rss", category: "memory", metric: "RSS", unit: "MB", threshold: 50.0, methodology: "sysinfo", ci_enforced: true },
              Budget { name: "binary_size_release", category: "binary", metric: "size", unit: "MB", threshold: BINARY_SIZE_RELEASE_BUDGET_MB, methodology: "ls", ci_enforced: true },
              Budget { name: "protocol_parse_p99", category: "protocol", metric: "p99", unit: "us", threshold: 50.0, methodology: "criterion: ext_protocol", ci_enforced: true },
            ];
            """,
            encoding="utf-8",
        )
        fresh_payload = {"mean": {"point_estimate": 1000.0}}
        estimate_paths = [
            root / "target/criterion/startup/version/warm/new/estimates.json",
            root / "target/criterion/ext_load_init/load_init_cold/hello/new/estimates.json",
            root / "target/criterion/ext_protocol/parse_and_validate/log/new/estimates.json",
        ]
        if include_policy:
            estimate_paths.append(root / "target/criterion/ext_policy/evaluate/safe/new/estimates.json")
        for path in estimate_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(fresh_payload), encoding="utf-8")
        (root / "target/perf/perf/pijs_workload_perf.jsonl").write_text(
            '{"schema":"pi.perf.workload.v1","tool_calls_per_iteration":1}\n',
            encoding="utf-8",
        )
        (root / "target/release/pi").write_bytes(b"binary")
        (root / "tests/perf/reports/extension_benchmark_stratification.json").write_text(
            '{"schema":"pi.perf.extension_benchmark_stratification.v1"}',
            encoding="utf-8",
        )
        (root / "target/perf/results/phase1_matrix_validation.json").write_text(
            '{"schema":"pi.perf.phase1_matrix_validation.v1"}',
            encoding="utf-8",
        )
        (root / "tests/perf/reports/budget_summary.json").write_text(
            json.dumps(
                {
                    "schema": "pi.perf.budget_summary.v1",
                    "generated_at": iso_now(),
                    "ci_fail": 0,
                    "ci_no_data": 0,
                    "data_contract_failures_count": 0,
                }
            ),
            encoding="utf-8",
        )

    ok_root = Path(tempfile.mkdtemp(prefix="pi-perf-preflight-ok-"))
    write_fixture(ok_root, include_policy=True)
    ok_code, ok_payload = build_report(
        argparse.Namespace(
            repo_root=str(ok_root),
            cargo_target_dir=str(ok_root / "target"),
            max_age_hours=24.0,
            skip_rch_check=True,
        )
    )
    assert ok_code == 0, ok_payload
    assert ok_payload["readiness"] == "ready", ok_payload

    blocked_root = Path(tempfile.mkdtemp(prefix="pi-perf-preflight-blocked-"))
    write_fixture(blocked_root, include_policy=False)
    blocked_code, blocked_payload = build_report(
        argparse.Namespace(
            repo_root=str(blocked_root),
            cargo_target_dir=str(blocked_root / "target"),
            max_age_hours=24.0,
            skip_rch_check=True,
        )
    )
    assert blocked_code == 1, blocked_payload
    assert blocked_payload["readiness"] == "blocked", blocked_payload
    assert any(
        item["contract_id"] == "extension_criterion_policy"
        for item in blocked_payload["missing_budget_artifacts"]
    ), blocked_payload
    assert any(
        item["bead"] == EXTENSION_BLOCKER_BEAD
        for item in blocked_payload["recognized_blockers"]
    ), blocked_payload
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", help="Repository root. Defaults to this script's repo.")
    parser.add_argument(
        "--cargo-target-dir",
        help="Cargo target directory to inspect. Defaults to CARGO_TARGET_DIR or ./target.",
    )
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=float(os.environ.get("PI_PERF_MAX_ARTIFACT_AGE_HOURS", DEFAULT_MAX_ARTIFACT_AGE_HOURS)),
        help="Maximum accepted artifact age in hours.",
    )
    parser.add_argument(
        "--skip-rch-check",
        action="store_true",
        help="Do not run rch check --quiet; useful in hermetic self-tests.",
    )
    parser.add_argument("--self-test", action="store_true", help="Run disposable self-tests.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    code, payload = build_report(args)
    write_json(payload)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
