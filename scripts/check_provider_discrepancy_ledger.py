#!/usr/bin/env python3
"""Validate docs/provider-discrepancy-ledger.json freshness.

The checker is intentionally read-only. It cross-checks the ledger summary,
remediation evidence, provider crosswalk docs, and provider metadata counts so
the discrepancy ledger cannot silently drift after provider/doc updates.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "pi.qa.provider_discrepancy_ledger_audit.v1"
DEFAULT_LEDGER = Path("docs/provider-discrepancy-ledger.json")
METADATA_PATH = Path("src/provider_metadata.rs")
PROVIDERS_DOC = Path("docs/providers.md")
AUTH_DOC = Path("docs/provider-auth-troubleshooting.md")
ISSUES_PATH = Path(".beads/issues.jsonl")

ALLOWED_STATUSES = {"fixed", "partially_fixed", "open"}
OWNER_REQUIRED_SEVERITIES = {"high", "medium"}
PATH_RE = re.compile(r"\b(?:docs|src|tests|scripts)/[A-Za-z0-9_.:/-]+")
BEAD_RE = re.compile(r"\bbd-[A-Za-z0-9][A-Za-z0-9.-]*\b")
COUNT_CLAIM_RE = re.compile(
    r"(?P<providers>\d+)\s+canonical providers?\D+"
    r"(?P<aliases>\d+)\s+aliases?",
    re.IGNORECASE,
)
PROVIDER_BLOCK_RE = re.compile(
    r"ProviderMetadata\s*\{(?P<body>.*?)\n\s*\},",
    re.DOTALL,
)


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    message: str
    path: str
    remediation: str


@dataclass(frozen=True)
class ProviderMetadataCounts:
    provider_count: int
    alias_count: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate provider discrepancy ledger freshness",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root; defaults to current working directory",
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=DEFAULT_LEDGER,
        help="Ledger path relative to repo root unless absolute",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal fixture tests instead of checking the repository",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def resolve_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def load_issue_ids(repo_root: Path) -> set[str]:
    path = repo_root / ISSUES_PATH
    if not path.exists():
        return set()

    issue_ids: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                issue = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSONL: {exc}") from exc
            issue_id = issue.get("id")
            if isinstance(issue_id, str):
                issue_ids.add(issue_id)
    return issue_ids


def parse_provider_metadata(repo_root: Path) -> ProviderMetadataCounts:
    path = repo_root / METADATA_PATH
    text = path.read_text(encoding="utf-8")
    provider_count = 0
    alias_count = 0

    for match in PROVIDER_BLOCK_RE.finditer(text):
        body = match.group("body")
        if not re.search(r'canonical_id:\s*"[^"]+"', body):
            continue
        aliases_match = re.search(r"aliases:\s*&\[(?P<aliases>.*?)\]", body, re.DOTALL)
        if aliases_match is None:
            raise ValueError(f"{path}: provider metadata entry missing aliases field")
        provider_count += 1
        alias_count += len(re.findall(r'"([^"]+)"', aliases_match.group("aliases")))

    if provider_count == 0:
        raise ValueError(f"{path}: no provider metadata entries found")

    return ProviderMetadataCounts(provider_count=provider_count, alias_count=alias_count)


def evidence_path_candidates(raw: str) -> list[Path]:
    cleaned = raw.rstrip(".,);]}'\":")
    candidates = [cleaned]
    while ":" in cleaned:
        cleaned, suffix = cleaned.rsplit(":", 1)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:-\d+)?", suffix):
            candidates.append(cleaned.rstrip(".,);]}'\":"))
            continue
        break
    return [Path(candidate) for candidate in candidates if candidate]


def existing_evidence_paths(repo_root: Path, entry: dict[str, Any]) -> list[str]:
    text = " ".join(
        str(entry.get(key, ""))
        for key in ("evidence", "remediation_note", "user_impact")
    )
    paths: list[str] = []
    for raw in PATH_RE.findall(text):
        for evidence_path in evidence_path_candidates(raw):
            if (repo_root / evidence_path).exists():
                paths.append(evidence_path.as_posix())
                break
    return sorted(set(paths))


def bead_refs(entry: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    remediation_beads = entry.get("remediation_beads", [])
    if isinstance(remediation_beads, list):
        refs.update(str(item) for item in remediation_beads if isinstance(item, str))
    text = " ".join(str(entry.get(key, "")) for key in ("evidence", "remediation_note"))
    refs.update(BEAD_RE.findall(text))
    return refs


def count_entries(discrepancies: list[dict[str, Any]], key: str) -> dict[str, int]:
    counter: collections.Counter[str] = collections.Counter()
    for entry in discrepancies:
        value = entry.get(key)
        if isinstance(value, str):
            counter[value] += 1
    return dict(sorted(counter.items()))


def compare_count_map(
    findings: list[Finding],
    expected: dict[str, int],
    actual: dict[str, int],
    path: str,
    check: str,
) -> None:
    keys = sorted(set(expected) | set(actual))
    for key in keys:
        if expected.get(key, 0) != actual.get(key, 0):
            findings.append(
                Finding(
                    check=check,
                    severity="error",
                    path=path,
                    message=(
                        f"{key!r} count is {expected.get(key, 0)}, "
                        f"but ledger entries contain {actual.get(key, 0)}"
                    ),
                    remediation="Refresh the summary counts from the discrepancies array.",
                )
            )


def check_summary(
    ledger_path: Path,
    ledger: dict[str, Any],
    discrepancies: list[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    summary = ledger.get("summary")
    if not isinstance(summary, dict):
        return [
            Finding(
                check="summary_present",
                severity="error",
                path=ledger_path.as_posix(),
                message="Ledger is missing a summary object.",
                remediation="Add summary.total_discrepancies and count buckets.",
            )
        ]

    total = summary.get("total_discrepancies")
    if total != len(discrepancies):
        findings.append(
            Finding(
                check="summary_total",
                severity="error",
                path=ledger_path.as_posix(),
                message=(
                    f"summary.total_discrepancies is {total!r}, "
                    f"but discrepancies contains {len(discrepancies)} entries"
                ),
                remediation="Refresh summary.total_discrepancies.",
            )
        )

    for summary_key, entry_key in (
        ("by_severity", "severity"),
        ("by_root_cause", "root_cause"),
        ("by_remediation_status", "remediation_status"),
    ):
        expected = summary.get(summary_key, {})
        if not isinstance(expected, dict):
            findings.append(
                Finding(
                    check=f"{summary_key}_present",
                    severity="error",
                    path=ledger_path.as_posix(),
                    message=f"summary.{summary_key} must be an object.",
                    remediation=f"Add summary.{summary_key} with count buckets.",
                )
            )
            continue
        expected_counts = {
            str(key): int(value)
            for key, value in expected.items()
            if isinstance(value, int)
        }
        compare_count_map(
            findings=findings,
            expected=expected_counts,
            actual=count_entries(discrepancies, entry_key),
            path=f"{ledger_path.as_posix()}#summary.{summary_key}",
            check=f"{summary_key}_counts",
        )

    return findings


def check_entry_statuses(
    ledger_path: Path,
    discrepancies: list[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    for entry in discrepancies:
        entry_id = str(entry.get("id", "<missing-id>"))
        status = entry.get("remediation_status")
        if status not in ALLOWED_STATUSES:
            findings.append(
                Finding(
                    check="allowed_status",
                    severity="error",
                    path=f"{ledger_path.as_posix()}#{entry_id}",
                    message=(
                        f"{entry_id} has remediation_status {status!r}; "
                        f"allowed statuses are {sorted(ALLOWED_STATUSES)}"
                    ),
                    remediation="Use fixed, partially_fixed, or open.",
                )
            )
    return findings


def check_evidence_refs(
    repo_root: Path,
    ledger_path: Path,
    discrepancies: list[dict[str, Any]],
    issue_ids: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for entry in discrepancies:
        entry_id = str(entry.get("id", "<missing-id>"))
        status = entry.get("remediation_status")
        if status not in {"fixed", "partially_fixed"}:
            continue

        paths = existing_evidence_paths(repo_root, entry)
        refs = bead_refs(entry)
        existing_refs = sorted(ref for ref in refs if ref in issue_ids)
        if paths or existing_refs:
            continue

        findings.append(
            Finding(
                check="remediation_evidence",
                severity="error",
                path=f"{ledger_path.as_posix()}#{entry_id}",
                message=(
                    f"{entry_id} is {status!r} but cites no existing repo path "
                    "or known bead reference."
                ),
                remediation=(
                    "Add a concrete evidence path or remediation_beads entry, "
                    "or downgrade the remediation_status."
                ),
            )
        )
    return findings


def check_open_owner_refs(
    ledger_path: Path,
    discrepancies: list[dict[str, Any]],
    issue_ids: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for entry in discrepancies:
        entry_id = str(entry.get("id", "<missing-id>"))
        severity = entry.get("severity")
        status = entry.get("remediation_status")
        if status == "fixed" or severity not in OWNER_REQUIRED_SEVERITIES:
            continue

        refs = sorted(ref for ref in bead_refs(entry) if ref in issue_ids)
        note = str(entry.get("remediation_note", "")).lower()
        has_blocker = "blocker" in note or "deferred" in note or "owner" in note
        if refs or has_blocker:
            continue

        findings.append(
            Finding(
                check="non_fixed_owner",
                severity="error",
                path=f"{ledger_path.as_posix()}#{entry_id}",
                message=(
                    f"{entry_id} is unresolved {severity!r} work but has no "
                    "known owner bead or explicit blocker/defer note."
                ),
                remediation=(
                    "Add remediation_beads that exist in .beads/issues.jsonl "
                    "or document the blocker in remediation_note."
                ),
            )
        )
    return findings


def read_optional_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def check_crosswalk_docs(
    repo_root: Path,
    ledger_path: Path,
    discrepancies: list[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    providers_text = read_optional_text(repo_root / PROVIDERS_DOC)
    auth_text = read_optional_text(repo_root / AUTH_DOC)
    expected_markers = [
        (PROVIDERS_DOC, providers_text, "Canonical Provider Matrix"),
        (PROVIDERS_DOC, providers_text, "Alias-to-Canonical Mapping Table"),
        (AUTH_DOC, auth_text, "Provider name crosswalk"),
    ]
    docs_fresh = all(marker in text for _, text, marker in expected_markers)

    for entry in discrepancies:
        if entry.get("id") != "DISC-017":
            continue
        status = entry.get("remediation_status")
        if status in {"fixed", "partially_fixed"} and not docs_fresh:
            missing = [
                f"{path.as_posix()}::{marker}"
                for path, text, marker in expected_markers
                if marker not in text
            ]
            findings.append(
                Finding(
                    check="crosswalk_doc_markers",
                    severity="error",
                    path=f"{ledger_path.as_posix()}#DISC-017",
                    message=(
                        "DISC-017 is marked remediated but crosswalk docs "
                        f"are missing required markers: {', '.join(missing)}"
                    ),
                    remediation="Restore the provider crosswalk docs or reopen DISC-017.",
                )
            )
    return findings


def count_claims_for_entry(entry: dict[str, Any]) -> list[tuple[int, int]]:
    text = " ".join(
        str(entry.get(key, ""))
        for key in ("evidence", "remediation_note", "user_impact")
    )
    return [
        (int(match.group("providers")), int(match.group("aliases")))
        for match in COUNT_CLAIM_RE.finditer(text)
    ]


def count_claims_for_doc(text: str) -> list[tuple[int, int]]:
    return [
        (int(match.group("providers")), int(match.group("aliases")))
        for match in COUNT_CLAIM_RE.finditer(text)
    ]


def check_provider_count_claims(
    repo_root: Path,
    ledger_path: Path,
    discrepancies: list[dict[str, Any]],
    metadata: ProviderMetadataCounts,
) -> list[Finding]:
    findings: list[Finding] = []
    expected = (metadata.provider_count, metadata.alias_count)

    for entry in discrepancies:
        entry_id = str(entry.get("id", "<missing-id>"))
        for providers, aliases in count_claims_for_entry(entry):
            if (providers, aliases) == expected:
                continue
            findings.append(
                Finding(
                    check="ledger_provider_count_claim",
                    severity="error",
                    path=f"{ledger_path.as_posix()}#{entry_id}",
                    message=(
                        f"{entry_id} claims {providers} canonical providers "
                        f"and {aliases} aliases, but provider metadata has "
                        f"{metadata.provider_count} and {metadata.alias_count}."
                    ),
                    remediation="Refresh the ledger count claim from src/provider_metadata.rs.",
                )
            )

    auth_text = read_optional_text(repo_root / AUTH_DOC)
    for providers, aliases in count_claims_for_doc(auth_text):
        if (providers, aliases) == expected:
            continue
        findings.append(
            Finding(
                check="auth_doc_provider_count_claim",
                severity="error",
                path=AUTH_DOC.as_posix(),
                message=(
                    f"Auth crosswalk claims {providers} canonical providers "
                    f"and {aliases} aliases, but provider metadata has "
                    f"{metadata.provider_count} and {metadata.alias_count}."
                ),
                remediation="Refresh docs/provider-auth-troubleshooting.md from provider metadata.",
            )
        )

    return findings


def validate(
    repo_root: Path,
    ledger_path: Path,
) -> tuple[dict[str, Any], list[Finding]]:
    ledger = read_json(ledger_path)
    discrepancies_raw = ledger.get("discrepancies")
    if not isinstance(discrepancies_raw, list):
        raise ValueError(f"{ledger_path}: discrepancies must be an array")

    discrepancies: list[dict[str, Any]] = []
    for index, entry in enumerate(discrepancies_raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{ledger_path}: discrepancies[{index}] must be an object")
        discrepancies.append(entry)

    issue_ids = load_issue_ids(repo_root)
    metadata = parse_provider_metadata(repo_root)

    findings: list[Finding] = []
    findings.extend(check_summary(ledger_path, ledger, discrepancies))
    findings.extend(check_entry_statuses(ledger_path, discrepancies))
    findings.extend(check_evidence_refs(repo_root, ledger_path, discrepancies, issue_ids))
    findings.extend(check_open_owner_refs(ledger_path, discrepancies, issue_ids))
    findings.extend(check_crosswalk_docs(repo_root, ledger_path, discrepancies))
    findings.extend(
        check_provider_count_claims(repo_root, ledger_path, discrepancies, metadata)
    )

    report = {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "pass" if not findings else "fail",
        "ledger_path": ledger_path.relative_to(repo_root).as_posix()
        if ledger_path.is_relative_to(repo_root)
        else ledger_path.as_posix(),
        "summary": {
            "discrepancy_count": len(discrepancies),
            "finding_fail_count": len(findings),
        },
        "metadata": {
            "provider_count": metadata.provider_count,
            "alias_count": metadata.alias_count,
        },
        "findings": [finding.__dict__ for finding in findings],
    }
    return report, findings


def write_fixture(repo_root: Path, ledger: dict[str, Any]) -> None:
    (repo_root / "docs").mkdir(parents=True)
    (repo_root / "src").mkdir(parents=True)
    (repo_root / "tests").mkdir(parents=True)
    (repo_root / ".beads").mkdir(parents=True)
    (repo_root / DEFAULT_LEDGER).write_text(
        json.dumps(ledger, indent=2) + "\n",
        encoding="utf-8",
    )
    (repo_root / PROVIDERS_DOC).write_text(
        "## Canonical Provider Matrix\n\n### Alias-to-Canonical Mapping Table\n",
        encoding="utf-8",
    )
    (repo_root / AUTH_DOC).write_text(
        "## Provider name crosswalk\n\n**Total**: 2 canonical providers, 1 alias.\n",
        encoding="utf-8",
    )
    (repo_root / "src/provider_metadata.rs").write_text(
        """
pub const PROVIDER_METADATA: &[ProviderMetadata] = &[
    ProviderMetadata {
        canonical_id: "openai",
        aliases: &[],
    },
    ProviderMetadata {
        canonical_id: "google",
        aliases: &["gemini"],
    },
];
""".lstrip(),
        encoding="utf-8",
    )
    (repo_root / "src/provider.rs").write_text("// evidence\n", encoding="utf-8")
    (repo_root / ISSUES_PATH).write_text(
        json.dumps({"id": "bd-owner", "status": "open"}) + "\n",
        encoding="utf-8",
    )


def base_fixture_ledger() -> dict[str, Any]:
    return {
        "schema": "test",
        "summary": {
            "total_discrepancies": 3,
            "by_severity": {"high": 1, "medium": 1, "low": 1},
            "by_root_cause": {"alias_mismatch": 1, "docs_mismatch": 2},
            "by_remediation_status": {
                "fixed": 1,
                "partially_fixed": 1,
                "open": 1,
            },
        },
        "discrepancies": [
            {
                "id": "DISC-003",
                "root_cause": "alias_mismatch",
                "severity": "high",
                "evidence": "src/provider.rs",
                "remediation_status": "partially_fixed",
                "remediation_note": (
                    "Provider docs now report 2 canonical providers and 1 aliases. "
                    "Remaining work is tracked by bd-owner."
                ),
                "remediation_beads": ["bd-owner"],
            },
            {
                "id": "DISC-017",
                "root_cause": "docs_mismatch",
                "severity": "medium",
                "evidence": "docs/providers.md and docs/provider-auth-troubleshooting.md",
                "remediation_status": "fixed",
                "remediation_note": "Crosswalk docs are present.",
                "remediation_beads": ["bd-owner"],
            },
            {
                "id": "DISC-020",
                "root_cause": "docs_mismatch",
                "severity": "low",
                "evidence": "docs/missing.md",
                "remediation_status": "open",
                "remediation_note": "Deferred owner path bd-owner.",
                "remediation_beads": ["bd-owner"],
            },
        ],
    }


def run_fixture(
    mutator: Any | None,
    expected_status: str,
    expected_check: str | None = None,
) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_root = Path(temp_dir)
        ledger = base_fixture_ledger()
        if mutator is not None:
            mutator(repo_root, ledger)
        write_fixture(repo_root, ledger)
        report, _ = validate(repo_root, repo_root / DEFAULT_LEDGER)
        if report["status"] != expected_status:
            raise AssertionError(
                f"expected {expected_status}, got {report['status']}: {report['findings']}"
            )
        if expected_check is not None:
            checks = {finding["check"] for finding in report["findings"]}
            if expected_check not in checks:
                raise AssertionError(
                    f"expected finding {expected_check!r}, got {sorted(checks)}"
                )


def run_self_tests() -> dict[str, Any]:
    def stale_summary(_repo_root: Path, ledger: dict[str, Any]) -> None:
        ledger["summary"]["total_discrepancies"] = 99

    def invalid_status(_repo_root: Path, ledger: dict[str, Any]) -> None:
        ledger["discrepancies"][0]["remediation_status"] = "done"

    def missing_evidence(_repo_root: Path, ledger: dict[str, Any]) -> None:
        ledger["discrepancies"][1]["evidence"] = "docs/missing.md"
        ledger["discrepancies"][1]["remediation_beads"] = ["bd-missing"]

    def missing_owner(_repo_root: Path, ledger: dict[str, Any]) -> None:
        ledger["discrepancies"][0]["remediation_status"] = "open"
        ledger["discrepancies"][0]["remediation_note"] = "Needs follow-up."
        ledger["discrepancies"][0]["remediation_beads"] = []
        ledger["summary"]["by_remediation_status"] = {
            "fixed": 1,
            "partially_fixed": 0,
            "open": 2,
        }

    def stale_count(_repo_root: Path, ledger: dict[str, Any]) -> None:
        ledger["discrepancies"][0]["remediation_note"] = (
            "Provider docs now report 9 canonical providers and 9 aliases."
        )

    cases: list[tuple[str, Any | None, str, str | None]] = [
        ("valid ledger", None, "pass", None),
        ("stale summary", stale_summary, "fail", "summary_total"),
        ("invalid status", invalid_status, "fail", "allowed_status"),
        ("missing evidence", missing_evidence, "fail", "remediation_evidence"),
        ("missing owner", missing_owner, "fail", "non_fixed_owner"),
        ("stale count", stale_count, "fail", "ledger_provider_count_claim"),
    ]

    passed = 0
    for name, mutator, expected_status, expected_check in cases:
        try:
            run_fixture(mutator, expected_status, expected_check)
        except Exception as exc:
            raise AssertionError(f"self-test case failed: {name}: {exc}") from exc
        passed += 1

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_root = Path(temp_dir)
        ledger = base_fixture_ledger()
        write_fixture(repo_root, ledger)
        (repo_root / PROVIDERS_DOC).write_text("missing markers\n", encoding="utf-8")
        report, _ = validate(repo_root, repo_root / DEFAULT_LEDGER)
        checks = {finding["check"] for finding in report["findings"]}
        if report["status"] != "fail" or "crosswalk_doc_markers" not in checks:
            raise AssertionError(f"stale crosswalk case failed: {report['findings']}")
        passed += 1

    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "pass",
        "self_tests": passed,
    }


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            report = run_self_tests()
            print(json.dumps(report, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2))
            return 0

        repo_root = args.repo_root.resolve()
        ledger_path = resolve_path(repo_root, args.ledger).resolve()
        report, findings = validate(repo_root, ledger_path)
        print(
            json.dumps(
                report,
                separators=(",", ":") if args.compact else None,
                indent=None if args.compact else 2,
            )
        )
        return 1 if findings else 0
    except Exception as exc:
        error_report = {
            "schema": SCHEMA,
            "generated_at": utc_now(),
            "status": "error",
            "error": str(exc),
        }
        print(
            json.dumps(
                error_report,
                separators=(",", ":") if args.compact else None,
                indent=None if args.compact else 2,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
