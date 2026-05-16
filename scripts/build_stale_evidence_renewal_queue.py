#!/usr/bin/env python3
"""Build a read-only stale-evidence renewal queue.

The queue is operator guidance. It scans JSON evidence artifacts and contract
files, then recommends bounded, safe renewal commands. It never rewrites
evidence, runs heavy validation, mutates Beads, edits configuration, or calls
the network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


QUEUE_SCHEMA = "pi.swarm.stale_evidence_renewal_queue.v1"
CONTRACT_SCHEMA = "pi.swarm.stale_evidence_renewal_queue_contract.v1"
FIXTURE_SCHEMA = "pi.swarm.stale_evidence_renewal_queue_fixtures.v1"
ACTION_PLAN_SCHEMA = "pi.swarm.action_plan.v1"
RUNPACK_INTEGRATION_SCHEMA = "pi.swarm.stale_evidence_renewal_runpack.v1"
CONTRACT_PATH = Path("docs/contracts/stale-evidence-renewal-queue-contract.json")
FIXTURE_PATH = Path("tests/fixtures/stale_evidence_renewal_queue/scenarios.json")
DEFAULT_FRESHNESS_HOURS = 336
DEFAULT_MAX_ITEMS = 20
MTIME_SKEW_SECONDS = 2.0
PATH_KEY_FRAGMENTS = ("path", "paths", "artifact", "artifacts", "evidence", "source")
PATH_SUFFIXES = (".json", ".jsonl", ".md", ".rs", ".py", ".toml", ".sh", ".txt")
FORBIDDEN_ACTIONS = (
    "automatic evidence regeneration",
    "automatic evidence overwrite",
    "heavy validation auto-run",
    "drop-in release gate override",
    "network fetch",
    "file deletion",
    "git mutation",
    "Beads mutation",
    "Agent Mail mutation",
)
SAFETY_CLASSES = (
    "read_only_probe",
    "evidence_capture",
    "validation_probe",
    "contract_review",
    "manual_regeneration_requires_operator",
    "rch_blocked_wait",
)
REASON_CODES = (
    "fresh",
    "expired",
    "missing_source_ref",
    "contract_schema_changed",
    "contract_newer_than_artifact",
    "blocked_rch",
    "known_safe_renewal_command",
    "malformed_json",
    "missing_generated_at",
)
STATUS_ORDER = {"fresh": 0, "renewal_recommended": 1, "blocked": 2}
SEVERITY_ORDER = {"info": 0, "medium": 1, "high": 2, "critical": 3}


class RenewalQueueError(Exception):
    """Raised when renewal queue inputs or contracts are unusable."""


@dataclass(frozen=True)
class ContractRef:
    contract_path: Path
    output_schema: str
    contract_schema: str | None


@dataclass(frozen=True)
class ArtifactRef:
    path: Path
    payload: dict[str, Any] | None
    schema: str | None
    generated_at: datetime | None
    size_bytes: int | None
    sha256: str | None
    malformed_error: str | None = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_utc(raw: object) -> datetime | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def json_dumps(value: Any, *, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(value, indent=2, sort_keys=True) + "\n"
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RenewalQueueError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RenewalQueueError(f"malformed JSON file {path}: {exc}") from exc


def no_overwrite_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise RenewalQueueError(f"refusing to overwrite existing output: {path}")
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def top_level_timestamp(payload: dict[str, Any]) -> datetime | None:
    for key in ("generated_at", "generated_at_utc", "observed_at_utc", "created_at"):
        timestamp = parse_utc(payload.get(key))
        if timestamp is not None:
            return timestamp
    return None


def schema_of(payload: Any) -> str | None:
    if isinstance(payload, dict) and isinstance(payload.get("schema"), str):
        return payload["schema"]
    return None


def read_artifact(path: Path) -> ArtifactRef:
    if not path.exists() or not path.is_file():
        return ArtifactRef(path, None, None, None, None, None, "artifact path is missing")
    size_bytes = path.stat().st_size
    sha256 = sha256_file(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return ArtifactRef(path, None, None, None, size_bytes, sha256, str(exc))
    if not isinstance(payload, dict):
        return ArtifactRef(path, None, None, None, size_bytes, sha256, "artifact JSON must be an object")
    return ArtifactRef(path, payload, schema_of(payload), top_level_timestamp(payload), size_bytes, sha256)


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def looks_like_path(value: str) -> bool:
    text = value.strip()
    if not text or text.startswith(("http://", "https://", "mailto:")):
        return False
    if "#" in text:
        text = text.split("#", 1)[0]
    return "/" in text or text.endswith(PATH_SUFFIXES)


def iter_path_refs(value: Any, *, key_hint: str = "") -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_hint = f"{key_hint}.{key}" if key_hint else str(key)
            refs.extend(iter_path_refs(child, key_hint=child_hint))
    elif isinstance(value, list):
        for child in value:
            refs.extend(iter_path_refs(child, key_hint=key_hint))
    elif isinstance(value, str):
        lowered_hint = key_hint.lower()
        if any(fragment in lowered_hint for fragment in PATH_KEY_FRAGMENTS) and looks_like_path(value):
            refs.append(value.split("#", 1)[0])
    return refs


def resolve_ref(ref: str, source_root: Path) -> Path:
    path = Path(ref)
    if not path.is_absolute():
        path = source_root / path
    return path


def contract_output_schema_values(payload: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key, value in payload.items():
        if not isinstance(value, str):
            continue
        if key in {"schema"}:
            continue
        if key.endswith("_schema") or key in {"output_schema", "runpack_schema", "action_plan_schema"}:
            values.append(value)
    return sorted(set(values))


def build_contract_index(contract_paths: list[Path]) -> dict[str, ContractRef]:
    index: dict[str, ContractRef] = {}
    for path in contract_paths:
        payload = load_json(path)
        if not isinstance(payload, dict):
            raise RenewalQueueError(f"contract must be a JSON object: {path}")
        contract_schema = schema_of(payload)
        for output_schema in contract_output_schema_values(payload):
            index.setdefault(
                output_schema,
                ContractRef(
                    contract_path=path,
                    output_schema=output_schema,
                    contract_schema=contract_schema,
                ),
            )
    return index


def command(purpose: str, text: str, safety_class: str) -> dict[str, Any]:
    if safety_class not in SAFETY_CLASSES:
        raise RenewalQueueError(f"unknown safety class: {safety_class}")
    lowered = text.lower()
    forbidden_fragments = ("git reset --hard", "git clean -fd", "rm -rf", " > ")
    if any(fragment in lowered for fragment in forbidden_fragments):
        raise RenewalQueueError(f"unsafe renewal command generated: {text}")
    return {
        "purpose": purpose,
        "command": text,
        "safety_class": safety_class,
        "commands_require_operator_execution": True,
    }


def renewal_commands(
    artifact: ArtifactRef,
    *,
    source_root: Path,
    contract: ContractRef | None,
    blocked_rch: bool,
) -> list[dict[str, Any]]:
    artifact_text = shlex.quote(relative_path(artifact.path, source_root))
    commands = [
        command(
            "Inspect artifact freshness",
            f"python3 scripts/build_stale_evidence_renewal_queue.py --artifact {artifact_text} --json",
            "read_only_probe",
        )
    ]
    if contract is not None:
        commands.append(
            command(
                "Validate referenced contract JSON",
                f"python3 -m json.tool {shlex.quote(relative_path(contract.contract_path, source_root))} >/dev/null",
                "contract_review",
            )
        )
    if blocked_rch:
        commands.append(
            command(
                "Check remote compilation posture before renewal validation",
                "rch status",
                "rch_blocked_wait",
            )
        )
    else:
        commands.append(
            command(
                "Inspect source drift before manual renewal",
                f"python3 scripts/check_swarm_runpack_freshness.py {artifact_text} --json",
                "read_only_probe",
            )
        )
    return commands


def rch_blocked(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    stack = [payload]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key).lower()
                if "rch" in key_text or "remote_validation" in key_text:
                    if isinstance(child, str) and child.lower() in {"blocked", "failed", "degraded", "deny", "backoff"}:
                        return True
                    if isinstance(child, dict):
                        status = child.get("status") or child.get("decision")
                        if isinstance(status, str) and status.lower() in {"blocked", "failed", "degraded", "deny", "backoff"}:
                            return True
                stack.append(child)
        elif isinstance(value, list):
            stack.extend(value)
    return False


def build_item(
    artifact: ArtifactRef,
    *,
    source_root: Path,
    contract_index: dict[str, ContractRef],
    generated_at: datetime,
    freshness_hours: int,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    missing_refs: list[str] = []
    contract_ref = contract_index.get(artifact.schema or "")
    if artifact.malformed_error:
        reason_codes.append("malformed_json")
    if artifact.generated_at is None:
        reason_codes.append("missing_generated_at")
        age_hours = None
    else:
        age_hours = round((generated_at - artifact.generated_at).total_seconds() / 3600, 2)
        if age_hours > freshness_hours:
            reason_codes.append("expired")
    if artifact.payload is not None:
        for ref in sorted(set(iter_path_refs(artifact.payload))):
            resolved = resolve_ref(ref, source_root)
            if not resolved.exists():
                missing_refs.append(ref)
        if missing_refs:
            reason_codes.append("missing_source_ref")
    blocked_rch = rch_blocked(artifact.payload)
    if blocked_rch:
        reason_codes.append("blocked_rch")
    if contract_ref is not None:
        embedded_contract_schema = (
            artifact.payload.get("contract_schema")
            if isinstance(artifact.payload, dict)
            else None
        )
        if (
            isinstance(embedded_contract_schema, str)
            and contract_ref.contract_schema is not None
            and embedded_contract_schema != contract_ref.contract_schema
        ):
            reason_codes.append("contract_schema_changed")
        contract_mtime = datetime.fromtimestamp(
            contract_ref.contract_path.stat().st_mtime,
            timezone.utc,
        )
        artifact_mtime = datetime.fromtimestamp(artifact.path.stat().st_mtime, timezone.utc)
        if contract_mtime - artifact_mtime > timedelta(seconds=MTIME_SKEW_SECONDS):
            reason_codes.append("contract_newer_than_artifact")
    if not reason_codes:
        reason_codes.append("fresh")

    commands = renewal_commands(
        artifact,
        source_root=source_root,
        contract=contract_ref,
        blocked_rch=blocked_rch,
    )
    if commands:
        reason_codes.append("known_safe_renewal_command")

    actionable = [code for code in reason_codes if code not in {"fresh", "known_safe_renewal_command"}]
    if "malformed_json" in reason_codes or "blocked_rch" in reason_codes:
        status = "blocked"
        severity = "critical" if "malformed_json" in reason_codes else "high"
    elif actionable:
        status = "renewal_recommended"
        severity = "high" if "missing_source_ref" in reason_codes or "contract_newer_than_artifact" in reason_codes else "medium"
    else:
        status = "fresh"
        severity = "info"
    priority = SEVERITY_ORDER[severity] * 100
    if age_hours is not None:
        priority += max(0, int(age_hours - freshness_hours))
    priority += len(missing_refs) * 10

    return {
        "id": artifact.path.stem.replace(".", "_").replace("-", "_"),
        "artifact_path": relative_path(artifact.path, source_root),
        "artifact_schema": artifact.schema,
        "generated_at": artifact.generated_at.isoformat() if artifact.generated_at else None,
        "freshness_hours": age_hours,
        "freshness_window_hours": freshness_hours,
        "status": status,
        "severity": severity,
        "priority": priority,
        "reason_codes": sorted(set(reason_codes), key=reason_codes.index),
        "missing_source_refs": missing_refs,
        "contract_refs": [
            {
                "path": relative_path(contract_ref.contract_path, source_root),
                "schema": contract_ref.contract_schema,
                "output_schema": contract_ref.output_schema,
            }
        ]
        if contract_ref
        else [],
        "source_fingerprint": {
            "size_bytes": artifact.size_bytes,
            "sha256": artifact.sha256,
        },
        "renewal_commands": commands,
        "blocks_dropin_claim": artifact.schema == "pi.dropin.certification_verdict.v1"
        and status != "fresh",
    }


def discover_files(root: Path, patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        for path in root.glob(pattern):
            if path.is_file():
                files.append(path)
    return sorted(set(files))


def build_queue(
    *,
    artifacts: list[Path],
    contract_paths: list[Path],
    source_root: Path,
    generated_at: datetime,
    freshness_hours: int,
    max_items: int,
) -> dict[str, Any]:
    contract_index = build_contract_index(contract_paths)
    items = [
        build_item(
            read_artifact(path),
            source_root=source_root,
            contract_index=contract_index,
            generated_at=generated_at,
            freshness_hours=freshness_hours,
        )
        for path in artifacts
    ]
    items.sort(
        key=lambda item: (
            -STATUS_ORDER.get(str(item.get("status")), 0),
            -int(item.get("priority") or 0),
            str(item.get("artifact_path")),
        )
    )
    queue = [item for item in items if item["status"] != "fresh"]
    blocked = sum(1 for item in queue if item["status"] == "blocked")
    recommended = sum(1 for item in queue if item["status"] == "renewal_recommended")
    fresh = sum(1 for item in items if item["status"] == "fresh")
    status = "blocked" if blocked else "degraded" if recommended else "ready"
    action_decision = "renew_stale_evidence" if queue else "implement_ready_work"
    payload = {
        "schema": QUEUE_SCHEMA,
        "generated_at": generated_at.isoformat(),
        "status": status,
        "purpose": "operator_guidance_not_auto_regeneration",
        "source_root": str(source_root),
        "freshness_window_hours": freshness_hours,
        "summary": {
            "scanned_artifacts": len(items),
            "fresh_artifacts": fresh,
            "renewal_item_count": len(queue),
            "renewal_recommended_count": recommended,
            "blocked_count": blocked,
            "contract_count": len(contract_paths),
        },
        "queue": queue[:max_items],
        "fresh_samples": [item for item in items if item["status"] == "fresh"][:max_items],
        "action_plan_integration": {
            "schema": ACTION_PLAN_SCHEMA,
            "status": "blocked" if blocked else "degraded" if queue else "ready",
            "recommended_decision": action_decision,
            "evidence_paths": [f"queue[{index}]" for index, _ in enumerate(queue[:max_items])],
            "commands_require_operator_execution": True,
            "does_not_replace_action_planner": True,
        },
        "runpack_integration": {
            "schema": RUNPACK_INTEGRATION_SCHEMA,
            "status": status,
            "operator_next_action": (
                "Renew stale evidence before using runpack or release claims"
                if queue
                else "Evidence renewal queue is clean"
            ),
            "source_status": "ok",
            "summary_paths": [
                "stale_evidence_renewal_queue.status",
                "stale_evidence_renewal_queue.summary.renewal_item_count",
                "stale_evidence_renewal_queue.queue",
            ],
        },
        "guardrails": {
            "dry_run_only": True,
            "no_source_mutation": True,
            "no_output_overwrite": True,
            "no_heavy_validation_auto_run": True,
            "commands_require_operator_execution": True,
            "dropin_claim_gate_preserved": True,
        },
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
    }
    assert_queue_contract(payload)
    return payload


def assert_queue_contract(queue: dict[str, Any]) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    contract = load_json(repo_root / CONTRACT_PATH)
    if not isinstance(contract, dict):
        raise AssertionError("renewal queue contract must be an object")
    assert contract.get("schema") == CONTRACT_SCHEMA
    assert contract.get("queue_schema") == QUEUE_SCHEMA
    assert queue.get("schema") == QUEUE_SCHEMA
    assert queue.get("purpose") == contract.get("purpose")
    assert queue.get("status") in set(contract.get("allowed_statuses", []))
    for key in contract.get("required_top_level_keys", []):
        assert key in queue, f"missing renewal queue key: {key}"
    guards = queue.get("guardrails")
    assert isinstance(guards, dict)
    for guard in contract.get("required_true_guardrails", []):
        assert guards.get(guard) is True, f"guardrail must be true: {guard}"
    allowed_reasons = set(contract.get("reason_codes", []))
    allowed_safety = set(contract.get("operator_command_safety_classes", []))
    for item in queue.get("queue", []):
        assert item.get("status") in set(contract.get("allowed_item_statuses", []))
        for reason in item.get("reason_codes", []):
            assert reason in allowed_reasons, f"unknown reason code: {reason}"
        for command_item in item.get("renewal_commands", []):
            assert command_item.get("safety_class") in allowed_safety
            assert command_item.get("commands_require_operator_execution") is True
    assert set(queue.get("forbidden_actions", [])).issuperset(
        set(contract.get("required_forbidden_actions", []))
    )


def write_fixture_files(root: Path, scenario: dict[str, Any]) -> tuple[list[Path], list[Path]]:
    artifacts: list[Path] = []
    contracts: list[Path] = []
    for item in scenario.get("files", []):
        if not isinstance(item, dict):
            continue
        path = root / str(item.get("path") or "")
        path.parent.mkdir(parents=True, exist_ok=True)
        if "json" in item:
            path.write_text(json_dumps(item["json"]), encoding="utf-8")
        else:
            path.write_text(str(item.get("content") or ""), encoding="utf-8")
        mtime = parse_utc(item.get("mtime"))
        if mtime is not None:
            ts = mtime.timestamp()
            path.touch()
            os.utime(path, (ts, ts))
        role = item.get("role")
        if role == "artifact":
            artifacts.append(path)
        elif role == "contract":
            contracts.append(path)
    return artifacts, contracts


def run_self_test() -> int:
    fixtures = load_json(Path(__file__).resolve().parent.parent / FIXTURE_PATH)
    if not isinstance(fixtures, dict) or fixtures.get("schema") != FIXTURE_SCHEMA:
        raise RenewalQueueError("fixture file has wrong schema")
    results = []
    for scenario in fixtures.get("scenarios", []):
        if not isinstance(scenario, dict):
            continue
        with tempfile.TemporaryDirectory(prefix="pi_stale_evidence_") as tmp:
            root = Path(tmp)
            artifacts, contracts = write_fixture_files(root, scenario)
            queue = build_queue(
                artifacts=artifacts,
                contract_paths=contracts,
                source_root=root,
                generated_at=parse_utc(scenario.get("generated_at")) or datetime.now(timezone.utc),
                freshness_hours=int(scenario.get("freshness_hours") or DEFAULT_FRESHNESS_HOURS),
                max_items=DEFAULT_MAX_ITEMS,
            )
            expected = scenario.get("expected") if isinstance(scenario.get("expected"), dict) else {}
            assert queue["status"] == expected.get("status"), scenario.get("id")
            assert queue["summary"]["renewal_item_count"] == expected.get("renewal_item_count"), scenario.get("id")
            if expected.get("reason_code"):
                assert any(
                    expected["reason_code"] in item.get("reason_codes", [])
                    for item in queue.get("queue", [])
                ), scenario.get("id")
            if expected.get("action_plan_decision"):
                assert (
                    queue["action_plan_integration"]["recommended_decision"]
                    == expected["action_plan_decision"]
                ), scenario.get("id")
            if expected.get("requires_safe_command"):
                assert any(
                    command_item.get("commands_require_operator_execution") is True
                    for item in queue.get("queue", [])
                    for command_item in item.get("renewal_commands", [])
                ), scenario.get("id")
            results.append(
                {
                    "id": scenario.get("id"),
                    "status": queue["status"],
                    "renewal_item_count": queue["summary"]["renewal_item_count"],
                }
            )
    print(
        json_dumps(
            {
                "schema": "pi.swarm.stale_evidence_renewal_queue_self_test.v1",
                "status": "pass",
                "scenario_count": len(results),
                "scenarios": results,
            }
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--artifact", dest="artifacts", action="append", type=Path, default=[])
    parser.add_argument("--contract", dest="contracts", action="append", type=Path, default=[])
    parser.add_argument("--evidence-dir", type=Path, default=Path("docs/evidence"))
    parser.add_argument("--contract-dir", type=Path, default=Path("docs/contracts"))
    parser.add_argument("--freshness-hours", type=int, default=DEFAULT_FRESHNESS_HOURS)
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--generated-at", help="override generated timestamp")
    parser.add_argument("--out-json", type=Path, help="write queue JSON; refuses to overwrite")
    parser.add_argument("--json", action="store_true", help="print queue JSON")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            return run_self_test()
        if args.freshness_hours < 0:
            raise RenewalQueueError("--freshness-hours must be non-negative")
        if args.max_items < 0:
            raise RenewalQueueError("--max-items must be non-negative")
        source_root = args.source_root.resolve()
        artifacts = [path if path.is_absolute() else source_root / path for path in args.artifacts]
        contracts = [path if path.is_absolute() else source_root / path for path in args.contracts]
        if not artifacts:
            evidence_dir = args.evidence_dir if args.evidence_dir.is_absolute() else source_root / args.evidence_dir
            artifacts = discover_files(evidence_dir, ["*.json"])
        if not contracts:
            contract_dir = args.contract_dir if args.contract_dir.is_absolute() else source_root / args.contract_dir
            contracts = discover_files(contract_dir, ["*.json"])
        queue = build_queue(
            artifacts=artifacts,
            contract_paths=contracts,
            source_root=source_root,
            generated_at=parse_utc(args.generated_at) or datetime.now(timezone.utc),
            freshness_hours=args.freshness_hours,
            max_items=args.max_items,
        )
        if args.out_json:
            no_overwrite_write(args.out_json, json_dumps(queue))
        if args.json or not args.out_json:
            print(json_dumps(queue))
        return 0
    except (RenewalQueueError, AssertionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
