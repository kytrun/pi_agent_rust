#!/usr/bin/env python3
"""Check README evidence artifact freshness for CI governance.

This guard enforces that artifact citations in README.md are fresh (≤14 days old).
Citations have the format: *(from artifact-path, run correlation-id)*

If any cited artifact is missing or >14 days stale, the check fails to prevent
stale or unverifiable evidence from misleading users about current project
capabilities.

Usage:
    python3 scripts/check_readme_evidence_freshness.py
    python3 scripts/check_readme_evidence_freshness.py --self-test

Exit codes:
    0 - All citations are fresh
    1 - One or more missing or stale citations found
    2 - Script error (missing files, parse failures, etc.)
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import NamedTuple


class CitationCheck(NamedTuple):
    """Result of checking a single citation."""
    artifact_path: str
    correlation_id: str
    file_exists: bool
    file_mtime: datetime | None
    days_old: float | None
    is_stale: bool


def strip_markdown_code(text: str) -> str:
    """Remove Markdown code blocks/spans so examples are not treated as claims."""
    without_fenced_blocks = re.sub(r"(?ms)^```.*?^```", "", text)
    return re.sub(r"`[^`\n]*`", "", without_fenced_blocks)


def is_placeholder_citation(artifact_path: str, correlation_id: str) -> bool:
    """Return true for documentation placeholders, not real evidence claims."""
    return artifact_path.startswith("[") or correlation_id.startswith("[")


def parse_citations(readme_text: str) -> list[tuple[str, str]]:
    """Parse real README artifact citations, excluding examples and placeholders."""
    # Pattern: *(from artifact-path, run correlation-id)*
    citation_pattern = r'\*\(from ([^,]+), run ([^)]+)\)\*'
    stripped = strip_markdown_code(readme_text)
    citations = []
    for artifact_path, correlation_id in re.findall(citation_pattern, stripped):
        artifact_path = artifact_path.strip()
        correlation_id = correlation_id.strip()
        if is_placeholder_citation(artifact_path, correlation_id):
            continue
        citations.append((artifact_path, correlation_id))
    return citations


def check_readme(repo_root: Path, now: datetime | None = None) -> int:
    """Check the README under repo_root for missing or stale artifact citations."""
    readme_path = repo_root / "README.md"
    if not readme_path.exists():
        print(f"ERROR: README.md not found at {readme_path}")
        return 2

    try:
        readme_text = readme_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"ERROR: Failed to read README.md: {e}")
        return 2

    citations = parse_citations(readme_text)

    if not citations:
        print("INFO: No artifact citations found in README.md")
        return 0

    print(f"INFO: Checking {len(citations)} artifact citations for freshness...")

    # Check each citation
    stale_count = 0
    missing_count = 0
    results: list[CitationCheck] = []

    # 14-day staleness threshold
    staleness_threshold = timedelta(days=14)
    now = now or datetime.now()

    for artifact_path, correlation_id in citations:
        # Resolve artifact path relative to repo root
        full_path = repo_root / artifact_path

        if not full_path.exists():
            print(f"WARNING: Cited artifact does not exist: {artifact_path}")
            missing_count += 1
            results.append(CitationCheck(
                artifact_path=artifact_path,
                correlation_id=correlation_id,
                file_exists=False,
                file_mtime=None,
                days_old=None,
                is_stale=False,
            ))
            continue

        try:
            # Get file modification time
            mtime = datetime.fromtimestamp(full_path.stat().st_mtime)
            age = now - mtime
            days_old = age.total_seconds() / 86400  # Convert to days
            is_stale = age > staleness_threshold

            if is_stale:
                print(f"STALE: {artifact_path} (age: {days_old:.1f} days, limit: 14 days)")
                stale_count += 1
            else:
                print(f"FRESH: {artifact_path} (age: {days_old:.1f} days)")

            results.append(CitationCheck(
                artifact_path=artifact_path,
                correlation_id=correlation_id,
                file_exists=True,
                file_mtime=mtime,
                days_old=days_old,
                is_stale=is_stale
            ))

        except Exception as e:
            print(f"ERROR: Failed to check {artifact_path}: {e}")
            return 2

    # Summary
    print(f"\nSUMMARY:")
    print(f"  Total citations: {len(citations)}")
    print(f"  Fresh artifacts: {len([r for r in results if r.file_exists and not r.is_stale])}")
    print(f"  Stale artifacts: {stale_count}")
    print(f"  Missing artifacts: {missing_count}")

    if stale_count > 0:
        print(f"\nFAIL: {stale_count} cited artifact(s) are >14 days stale.")
        print("Evidence claims in README must be backed by fresh artifacts.")
        print("Re-run evidence generation and update citations to resolve this.")
        return 1

    if missing_count > 0:
        print(f"\nFAIL: {missing_count} cited artifact(s) are missing.")
        print("Evidence claims in README must reference checked-in artifacts.")
        return 1

    print("\nPASS: All cited artifacts are fresh (≤14 days old).")
    return 0


def run_self_test() -> int:
    """Run a small fixture test for examples, placeholders, freshness, and missing files."""
    with TemporaryDirectory() as temp_dir:
        repo_root = Path(temp_dir)
        artifact = repo_root / "tests/perf/reports/fresh.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"ok": true}\n', encoding="utf-8")
        now = datetime(2026, 5, 1, 12, 0, 0)
        fresh_ts = now.timestamp()
        os.utime(artifact, (fresh_ts, fresh_ts))

        readme = repo_root / "README.md"
        readme.write_text(
            "\n".join([
                "Example: `*(from [artifact-path], run [correlation-id])*`",
                "```",
                "*(from missing-in-code-block.json, run example)*",
                "```",
                "Claim: *(from tests/perf/reports/fresh.json, run fixture-run)*",
                "",
            ]),
            encoding="utf-8",
        )

        first_output = io.StringIO()
        with contextlib.redirect_stdout(first_output):
            first_result = check_readme(repo_root, now=now)
        first_text = first_output.getvalue()
        if first_result != 0:
            print(first_text)
            print("SELF-TEST FAIL: fresh real citation should pass")
            return 2
        if "[artifact-path]" in first_text or "missing-in-code-block" in first_text:
            print(first_text)
            print("SELF-TEST FAIL: examples/placeholders must not be parsed as claims")
            return 2

        readme.write_text(
            readme.read_text(encoding="utf-8")
            + "Broken claim: *(from tests/perf/reports/missing.json, run fixture-run)*\n",
            encoding="utf-8",
        )
        second_output = io.StringIO()
        with contextlib.redirect_stdout(second_output):
            second_result = check_readme(repo_root, now=now)
        if second_result != 1:
            print(second_output.getvalue())
            print("SELF-TEST FAIL: missing real citation should fail")
            return 2

    print("SELF-TEST PASS")
    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run fixture-based checks for citation parsing behavior",
    )
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    repo_root = Path(__file__).resolve().parent.parent
    return check_readme(repo_root)


if __name__ == "__main__":
    sys.exit(main())
