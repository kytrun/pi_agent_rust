# Swarm Operations Runbook

Practical workflow for launching, monitoring, throttling, recovering, and handing off large Pi agent swarms.

This runbook is operator guidance. It does not replace Beads as the work ledger, Agent Mail as the reservation/message ledger, `pi doctor` as the live diagnostic surface, or the release evidence gates as claim authority.

## Source Of Truth

| Surface | Authority | Command or artifact |
|---------|-----------|---------------------|
| Work ownership | Beads issue state and comments | `br ready --json`, `br show <id>`, `br update <id> --claim --actor "$AGENT_NAME"` |
| Cross-agent coordination | Agent Mail messages, reservations, and build slots | MCP Agent Mail `macro_start_session`, `file_reservation_paths`, `fetch_inbox` |
| Live swarm readiness | Doctor swarm diagnostics | `pi doctor --only swarm --format json` |
| Cargo/RCH admission | Cargo headroom preflight | `scripts/cargo_headroom.sh --runner rch --admit-only check --all-targets` |
| Remote build status | RCH queue and worker state | `rch status`, `rch queue`, `rch doctor` |
| Handoff bundle | Operator runpack | `python3 scripts/build_swarm_operator_runpack.py --capture-current ...` |
| Saturation and timeline evidence | Redacted swarm activity ledger | `docs/swarm-activity-ledger.md`, schema `pi.swarm.activity_digest.v1` |
| Deterministic replay evidence | Swarm flight recorder | `docs/swarm-flight-recorder.md`, schema `pi.swarm.flight_recorder.report.v1` |

## Startup Checklist

Run these before claiming work in a multi-agent session:

```bash
export AGENT_NAME="${AGENT_NAME:-$(whoami)}"
export PI_CARGO_AGENT_SUFFIX="$AGENT_NAME"
export CARGO_TARGET_DIR="/data/tmp/pi_agent_rust_cargo/${AGENT_NAME}/target"
export TMPDIR="/data/tmp/pi_agent_rust_cargo/${AGENT_NAME}/tmp"
mkdir -p "$CARGO_TARGET_DIR" "$TMPDIR"

git status --short --branch
br ready --json
bv --recipe actionable --robot-plan
pi doctor --only swarm --format json > /data/tmp/pi_swarm_runpack/doctor.json
scripts/cargo_headroom.sh --runner rch --admit-only check --all-targets \
  --decision-json /data/tmp/pi_swarm_runpack/cargo-admission.json
rch status
rch queue
```

Green startup means:

- `git status --short --branch` has no uncommitted work from this agent.
- `br ready --json` has a real open issue, not a tombstone or deleted item.
- `pi doctor --only swarm --format json` has no red finding that says new swarm work must stop.
- `scripts/cargo_headroom.sh --runner rch --admit-only ...` returns `admit` or `allow`.
- `rch queue` does not show saturated or stale heavy builds that would make more cargo work irresponsible.

If any check is degraded, keep the raw command output and choose the response from the recovery table below. Do not convert degraded coordination or RCH state into a vague "tests failed" note.

## Claim A Bead

Use `bv` for prioritization and `br` for the actual claim:

```bash
bv --recipe actionable --robot-plan
br ready --json
br show <issue-id>
br update <issue-id> --claim --actor "$AGENT_NAME"
br comments add <issue-id> --author "$AGENT_NAME" --message \
  "Claimed by $AGENT_NAME. Scope: <files/modules>. Validation: <commands>. Coordination: <Agent Mail status>."
```

Before editing, reserve the narrowest practical file set in Agent Mail:

```text
file_reservation_paths(
  project_key="/data/projects/pi_agent_rust",
  agent_name="$AGENT_NAME",
  paths=["src/module.rs", "tests/module_tests.rs"],
  ttl_seconds=3600,
  exclusive=true,
  reason="<issue-id>"
)
```

If Agent Mail writes fail because the MCP database is unavailable or corrupt, record the failure in the Beads comment and continue with the Beads claim as the soft lock. Do not wait in coordination-only loops when useful non-overlapping work is available.

## Cargo And Test Policy

CPU-heavy Rust commands must go through RCH:

```bash
env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" TMPDIR="$TMPDIR" \
  rch exec -- cargo check --all-targets

env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" TMPDIR="$TMPDIR" \
  rch exec -- cargo clippy --all-targets -- -D warnings

env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" TMPDIR="$TMPDIR" \
  rch exec -- cargo test <focused-filter> -- --nocapture
```

Use local commands only for non-heavy checks:

```bash
cargo fmt --check
git diff --check
timeout 60s ubs --staged --only=rust .
python3 scripts/check_ubs_staged_delta.py
./scripts/reconcile_beads_ledger.sh
```

If `timeout 60s ubs --staged --only=rust .` times out or is dominated by whole-file baseline noise, run `python3 scripts/check_ubs_staged_delta.py`. The delta gate is acceptable only when it reports no warning or critical finding on staged changed lines. Keep the raw timeout or baseline-noise summary in the handoff.

## Monitor An Active Swarm

Use this status loop while work is in progress:

```bash
git status --short --branch
br list --status=in_progress --json
br ready --json
rch status
rch queue
pi doctor --only swarm --format json
```

Watch for:

- Multiple agents editing the same file without Agent Mail reservations or Beads comments.
- `br list --status=in_progress --json` entries with old `updated_at` timestamps and no recent comments.
- `rch queue` entries with stale progress, repeated artifact retrieval failures, or slot pressure.
- `pi doctor --only swarm --format json` findings for Agent Mail build slots, reservation conflicts, cgroup memory pressure, target/TMPDIR headroom, or RCH classifier failures.
- Dirty worktree entries outside your claimed file set.

Do not revert unrelated dirty files. Treat them as another agent's work unless the owning bead or the user explicitly says otherwise.

## Throttle Or Pause

Back off new claims when any of these are true:

| Signal | Command | Action |
|--------|---------|--------|
| RCH admission denies or backs off | `scripts/cargo_headroom.sh --runner rch --admit-only check --all-targets` | Stop starting heavy cargo jobs. Continue docs, source inspection, or small non-cargo fixes. |
| Queue pressure is high | `rch queue` | Wait for active jobs to finish before launching more cargo. |
| Agent Mail reservations conflict | `pi doctor --only swarm --format json` or Agent Mail reservation response | Narrow the file set, choose a different bead, or coordinate with the holder. |
| Beads has stale in-progress work | `br list --status=in_progress --json` | Comment on the stale issue, verify no recent owner activity, then reopen only if it is clearly abandoned. |
| Drop-in or release evidence is stale | `scripts/report_swarm_claim_readiness.py` | Do not make release-facing claims. File or work the evidence gap. |
| Worktree is dirty outside your scope | `git status --short --branch` | Ignore unrelated changes and keep your commit narrowly staged. |

## Stalled Bead Recovery

Use this only for clearly abandoned work:

```bash
br show <issue-id>
br comments list <issue-id>
git log --oneline --decorate --all -- <claimed-file>
br update <issue-id> --status open --assignee "" --actor "$AGENT_NAME"
br comments add <issue-id> --author "$AGENT_NAME" --message \
  "Reopened as stale: no recent owner activity found; no file changes reverted."
```

Do not reopen an in-progress bead just because Agent Mail is degraded. A current Beads comment, recent commit, or active file reservation is enough evidence that another agent may still own it.

## Recovery Drills

### Agent Mail Degraded

1. Run `pi doctor --only swarm --format json` and save the finding.
2. Try the MCP read path: `fetch_inbox` or `list_agents`.
3. If writes fail, use Beads status/comments as the soft lock.
4. Keep work on a narrow file set and mention the degraded Mail state in the final handoff.

### RCH Retrieval Or Disk Pressure

1. Run `rch status` and `rch queue`.
2. Run `scripts/cargo_headroom.sh --runner rch --admit-only check --all-targets`.
3. If the classifier points at local target/TMPDIR headroom, move `CARGO_TARGET_DIR` and `TMPDIR` under `/data/tmp/pi_agent_rust_cargo/$AGENT_NAME`.
4. If the remote command failed, treat it as a code or remote-build failure only after the raw RCH output identifies that class.

### Dirty Worktree

1. Run `git status --short --branch`.
2. Stage only files for the current bead.
3. Do not use `git reset --hard`, `git clean`, `git checkout --`, or `rm` cleanup commands.
4. If unrelated dirty files block a command, record the exact blocker and ask for direction.

### Saturated Review Loop

1. Build or read the swarm activity digest described in `docs/swarm-activity-ledger.md`.
2. If saturation reasons show duplicate work, stale introductions, repeated blockers, or low validation throughput, stop launching broad review agents.
3. Pick one narrow implementation bead, a focused `testing-*` skill, or a concrete follow-up bead from the digest recommendation.

## Handoff Bundle

Capture a handoff bundle before ending a swarm shift:

```bash
capture_dir="/data/tmp/pi_swarm_runpack/${AGENT_NAME}-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$capture_dir"

python3 scripts/build_swarm_operator_runpack.py \
  --capture-current \
  --capture-dir "$capture_dir" \
  --project-root /data/projects/pi_agent_rust \
  --agent-name "$AGENT_NAME" \
  --out-json "$capture_dir/operator-runpack.json" \
  --out-md "$capture_dir/operator-runpack.md" \
  --out-autopilot-input-pack-json "$capture_dir/autopilot-input-pack.json" \
  --out-autopilot-plan-json "$capture_dir/autopilot-plan.json"
```

The runpack schema is governed by `docs/contracts/swarm-operator-runpack-contract.json`. The runpack is a redacted index over existing evidence, not a release performance claim and not a replacement for the source artifacts.
The autopilot input pack schema is governed by `docs/contracts/swarm-autopilot-input-pack-contract.json`. It normalizes source statuses for the dry-run planner, but it is still advisory and never replaces Doctor, Beads, Agent Mail, RCH, git, or the source artifacts themselves.
The autopilot plan schema is governed by `docs/contracts/swarm-autopilot-plan-contract.json`. It maps the input pack to ordered dry-run actions such as `claim_ready_bead`, `wait_for_rch`, `adjust_swarm_budget`, `use_beads_soft_lock`, `reopen_stale_bead_candidate`, `run_docs_only_work`, `capture_handoff`, or `stop_and_surface_blocker`.
The plan also includes `work_partitions` for ready Beads. Those entries recommend reservation globs, likely collision surfaces to avoid, alternate file families, confidence, and degraded caveats. They are diagnostic only; operators still claim through Beads and reserve through Agent Mail when it is healthy.
The input pack and plan also carry `budget_drift` evidence with schema `pi.swarm.budget_drift.v1`. It compares the last accepted swarm resource preflight profile with live cgroup, memory, scratch-path, RCH queue, and active-owner observations. Status `stable` keeps the current ceiling, `degraded` recommends reduced fanout with hysteresis, and `deny_new_work` recommends admitting no new agents or heavyweight RCH verification until the live signals recover.
The plan also includes `failure_actions` for common operational blockers. Those entries use stable catalog IDs for RCH artifact retrieval, local Cargo target/TMPDIR pressure, remote compiler failures, Agent Mail schema/read-only degradation, Beads JSONL drift, stale Beads ownership, and unknown operational failures. Unknown entries fail closed with a redacted raw excerpt and safe inspection commands instead of guessing a root cause.

## Completion Checklist

Before closing a bead:

```bash
env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" TMPDIR="$TMPDIR" \
  rch exec -- cargo check --all-targets
env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" TMPDIR="$TMPDIR" \
  rch exec -- cargo clippy --all-targets -- -D warnings
cargo fmt --check
git diff --check
git add <changed-files> .beads/issues.jsonl
timeout 60s ubs --staged --only=rust .
python3 scripts/check_ubs_staged_delta.py
./scripts/reconcile_beads_ledger.sh
br close <issue-id> --reason "<completed evidence>"
br sync --flush-only
git add .beads/issues.jsonl
AGENT_NAME="$AGENT_NAME" git commit -m "<type>: <summary>"
git pull --rebase
git push
git push origin main:master
git status --short --branch
```

For docs-only changes, use docs-focused validation instead of forcing cargo:

```bash
command -v git br bv rch cargo jq python3
python3 scripts/build_swarm_operator_runpack.py --self-test
python3 -m json.tool docs/contracts/swarm-operator-runpack-contract.json >/dev/null
python3 -m json.tool docs/contracts/swarm-autopilot-input-pack-contract.json >/dev/null
python3 -m json.tool docs/contracts/swarm-autopilot-plan-contract.json >/dev/null
cargo fmt --check
git diff --check
./scripts/reconcile_beads_ledger.sh
```

## Schema Examples

Doctor swarm preflight evidence:

```json
{
  "schema": "pi.doctor.swarm_resource_preflight.v1",
  "status": "pass",
  "effective_cpu_cores": 64,
  "memory_limit_bytes": 274877906944,
  "recommended_budgets": {
    "agent_fanout": 8,
    "rch_verification_fanout": 4
  }
}
```

Cargo/RCH admission evidence:

```json
{
  "schema": "pi.cargo_headroom.admission.v1",
  "decision": "admit",
  "requested_runner": "rch",
  "resolved_runner": "rch",
  "cargo_command": "cargo check --all-targets",
  "rch_queue_forecast": {
    "schema": "pi.cargo_headroom.rch_queue_forecast.v1",
    "recommended_action": "proceed"
  }
}
```

Operator runpack evidence:

```json
{
  "schema": "pi.swarm.operator_runpack.v1",
  "purpose": "operator_handoff_not_release_performance_claim",
  "status": "ready",
  "swarm_scale_safety_scorecard": {
    "schema": "pi.swarm.safety_scorecard.v1",
    "overall_status": "ready"
  }
}
```

Autopilot input-pack evidence:

```json
{
  "schema": "pi.swarm.autopilot_input_pack.v1",
  "purpose": "dry_run_swarm_autopilot_input_not_source_of_truth",
  "status": "degraded",
  "normalized_inputs": {
    "agent_mail": {
      "status": "degraded",
      "fallback_action": "use_beads_soft_lock"
    },
    "budget_drift": {
      "schema": "pi.swarm.budget_drift.v1",
      "status": "deny_new_work",
      "signals": [
        {
          "id": "rch_queue_saturated",
          "severity": "critical",
          "recommendation": "deny new heavyweight work until RCH queue pressure clears"
        }
      ],
      "recommended_adjustments": {
        "admit_new_agents": 0,
        "rch_verification_fanout": 0,
        "reason": "deny_new_work until critical budget drift clears"
      }
    }
  },
  "planner_guards": {
    "dry_run_only": true,
    "no_prose_scraping": true
  }
}
```

Autopilot plan evidence:

```json
{
  "schema": "pi.swarm.autopilot_plan.v1",
  "purpose": "dry_run_swarm_autopilot_plan_not_source_of_truth",
  "status": "degraded",
  "budget_drift": {
    "schema": "pi.swarm.budget_drift.v1",
    "status": "deny_new_work",
    "profile_status": "ok",
    "recommended_adjustments": {
      "admit_new_agents": 0,
      "rch_verification_fanout": 0
    }
  },
  "work_partitions": [
    {
      "issue_id": "bd-provider",
      "surface_ids": [
        "provider_streaming"
      ],
      "suggested_reservation": [
        "src/provider.rs",
        "src/providers/**/*.rs",
        "tests/provider_streaming*.rs"
      ],
      "avoid": [],
      "confidence": "high",
      "degraded_caveats": []
    }
  ],
  "failure_actions": [
    {
      "id": "FAIL-AGENT-MAIL-SCHEMA",
      "catalog_schema": "pi.swarm.failure_action_catalog.v1",
      "category": "agent_mail",
      "title": "Agent Mail database schema is missing required tables",
      "match_confidence": "high",
      "explanation": "Agent Mail coordination cannot be trusted for reservations or inbox state until the mailbox schema is repaired or restored.",
      "evidence_paths": [
        "normalized_inputs.agent_mail"
      ],
      "matched_source": "agent_mail",
      "safe_commands": [
        {
          "purpose": "Preview Agent Mail repair",
          "command": "am doctor repair --dry-run"
        }
      ],
      "escalation": "Continue with Beads soft locks until Mail health is green.",
      "raw_excerpt": "status=degraded issue=database schema missing required tables",
      "redaction_summary": {
        "redacted_count": 0,
        "fields": []
      }
    }
  ],
  "actions": [
    {
      "rank": 1,
      "action": "adjust_swarm_budget",
      "evidence_paths": [
        "normalized_inputs.budget_drift.status",
        "normalized_inputs.budget_drift.signals"
      ],
      "commands": [
        {
          "purpose": "Refresh swarm resource preflight",
          "command": "pi doctor --only swarm --format json"
        }
      ]
    },
    {
      "rank": 2,
      "action": "use_beads_soft_lock",
      "evidence_paths": [
        "normalized_inputs.agent_mail.status"
      ],
      "commands": [
        {
          "purpose": "Inspect active ownership",
          "command": "br list --status=in_progress --json"
        }
      ]
    }
  ]
}
```

Swarm flight-recorder report evidence:

```json
{
  "schema": "pi.swarm.flight_recorder.report.v1",
  "event_count": 12,
  "coordination_failures": [],
  "replay_command": "cargo test --test e2e_swarm_flight_recorder -- --exact multi_agent_flight_recorder_bundle_replays_without_credentials --nocapture"
}
```

## Validation Record

When this runbook changes, run at least:

```bash
command -v git br bv rch cargo jq python3
python3 scripts/build_swarm_operator_runpack.py --self-test
python3 -m json.tool docs/contracts/swarm-operator-runpack-contract.json >/dev/null
python3 -m json.tool docs/contracts/swarm-autopilot-input-pack-contract.json >/dev/null
python3 -m json.tool docs/contracts/swarm-autopilot-plan-contract.json >/dev/null
cargo fmt --check
git diff --check
./scripts/reconcile_beads_ledger.sh
```

If a validation command is unavailable or degraded, record the command, exit code, and stderr in the Beads closeout instead of claiming the runbook is fully validated.
