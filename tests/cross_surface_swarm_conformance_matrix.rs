#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const EVIDENCE_PATH: &str = "docs/evidence/cross-surface-swarm-conformance-matrix.json";
const EXPECTED_SCHEMA: &str = "pi.swarm.cross_surface_conformance_matrix.v1";
const EXPECTED_BEAD: &str = "bd-zeccr.2";

const REQUIRED_SURFACES: &[&str] = &[
    "provider_stream_ordering",
    "tool_mutation_barriers",
    "rpc_event_framing",
    "session_replay_index_consistency",
    "extension_policy_denial",
    "tui_frame_budget_non_blocking",
];

const ALLOWED_LEVELS: &[&str] = &["must", "should"];
const ALLOWED_STATUSES: &[&str] = &["pass", "fail", "intentional_divergence", "blocked"];
const NEGATIVE_FAILURE_MODES: &[&str] = &[
    "missing_required_surface",
    "missing_required_field",
    "invalid_status",
];

type TestResult<T = ()> = Result<T, String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &str) -> TestResult<Value> {
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

fn pointer<'a>(value: &'a Value, path: &str) -> TestResult<&'a Value> {
    value
        .pointer(path)
        .ok_or_else(|| format!("missing JSON pointer {path}"))
}

fn pointer_str<'a>(value: &'a Value, path: &str) -> TestResult<&'a str> {
    pointer(value, path)?
        .as_str()
        .ok_or_else(|| format!("{path} must be a string"))
}

fn pointer_array<'a>(value: &'a Value, path: &str) -> TestResult<&'a [Value]> {
    pointer(value, path)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{path} must be an array"))
}

fn pointer_array_mut<'a>(value: &'a mut Value, path: &str) -> TestResult<&'a mut Vec<Value>> {
    value
        .pointer_mut(path)
        .ok_or_else(|| format!("missing JSON pointer {path}"))?
        .as_array_mut()
        .ok_or_else(|| format!("{path} must be an array"))
}

fn string_set(value: &Value, path: &str) -> TestResult<BTreeSet<String>> {
    pointer_array(value, path)?
        .iter()
        .map(|entry| {
            let raw = entry
                .as_str()
                .ok_or_else(|| format!("{path} entries must be strings"))?;
            let normalized = raw.trim();
            require(
                !normalized.is_empty(),
                format!("{path} entries must be non-empty"),
            )?;
            Ok(normalized.to_string())
        })
        .collect()
}

fn required_string(value: &Value, path: &str, errors: &mut Vec<String>) -> Option<String> {
    match pointer_str(value, path) {
        Ok(raw) if !raw.trim().is_empty() => Some(raw.trim().to_string()),
        Ok(_) => {
            errors.push(format!("{path} must be non-empty"));
            None
        }
        Err(err) => {
            errors.push(err);
            None
        }
    }
}

fn array_for_validation<'a>(
    value: &'a Value,
    path: &str,
    errors: &mut Vec<String>,
) -> Option<&'a [Value]> {
    match pointer_array(value, path) {
        Ok(entries) => Some(entries),
        Err(err) => {
            errors.push(err);
            None
        }
    }
}

fn validate_allowed(value: &str, allowed: &[&str], path: &str, errors: &mut Vec<String>) {
    if !allowed.contains(&value) {
        errors.push(format!(
            "{path} has invalid value {value}; allowed values are {}",
            allowed.join(", ")
        ));
    }
}

fn validate_known_divergence(row: &Value, path: &str, errors: &mut Vec<String>) {
    match row.get("known_divergence") {
        Some(Value::Null) => {}
        Some(Value::String(text)) if !text.trim().is_empty() => {}
        Some(_) => errors.push(format!(
            "{path}/known_divergence must be null or a non-empty string"
        )),
        None => errors.push(format!("{path}/known_divergence is required")),
    }
}

fn validate_evidence_refs(row: &Value, path: &str, root: &Path, errors: &mut Vec<String>) {
    let Some(refs) = array_for_validation(row, "/evidence_refs", errors) else {
        return;
    };
    if refs.is_empty() {
        errors.push(format!("{path}/evidence_refs must not be empty"));
    }
    for entry in refs {
        let Some(relative_path) = entry.as_str() else {
            errors.push(format!("{path}/evidence_refs entries must be strings"));
            continue;
        };
        if relative_path.trim().is_empty() {
            errors.push(format!("{path}/evidence_refs entries must be non-empty"));
            continue;
        }
        if !root.join(relative_path).exists() {
            errors.push(format!(
                "{path}/evidence_refs entry does not exist: {relative_path}"
            ));
        }
    }
}

fn validate_row(
    row: &Value,
    index: usize,
    root: &Path,
    ids: &mut BTreeSet<String>,
    surfaces: &mut BTreeSet<String>,
    provider_row_count: &mut usize,
    errors: &mut Vec<String>,
) {
    let path = format!("/rows/{index}");
    let id = required_string(row, "/requirement_id", errors);
    if let Some(requirement_id) = id {
        if !ids.insert(requirement_id.clone()) {
            errors.push(format!("duplicate requirement_id {requirement_id}"));
        }
        if !requirement_id.starts_with("CSWARM-") {
            errors.push(format!("{path}/requirement_id must use the CSWARM prefix"));
        }
    }

    if let Some(level) = required_string(row, "/level", errors) {
        validate_allowed(&level, ALLOWED_LEVELS, &format!("{path}/level"), errors);
    }
    if let Some(status) = required_string(row, "/status", errors) {
        validate_allowed(&status, ALLOWED_STATUSES, &format!("{path}/status"), errors);
    }
    if let Some(surface) = required_string(row, "/source_surface", errors) {
        surfaces.insert(surface.clone());
        if surface == "provider_stream_ordering" {
            *provider_row_count += 1;
            if row
                .get("cross_links_provider_specific_rows")
                .and_then(Value::as_bool)
                != Some(true)
            {
                errors
                    .push("provider stream row must cross-link provider-specific rows".to_string());
            }
        }
    }
    for field in ["/invariant", "/test_command"] {
        let _ = required_string(row, field, errors);
    }
    validate_known_divergence(row, &path, errors);
    validate_evidence_refs(row, &path, root, errors);
}

fn validate_negative_controls(value: &Value, errors: &mut Vec<String>) {
    let Some(controls) = array_for_validation(value, "/negative_controls", errors) else {
        return;
    };
    if controls.is_empty() {
        errors.push("/negative_controls must not be empty".to_string());
    }

    let mut modes = BTreeSet::new();
    for (index, control) in controls.iter().enumerate() {
        let path = format!("/negative_controls/{index}");
        for field in ["/control_id", "/description", "/test_command", "/status"] {
            let _ = required_string(control, field, errors);
        }
        if let Some(mode) = required_string(control, "/failure_mode", errors) {
            validate_allowed(
                &mode,
                NEGATIVE_FAILURE_MODES,
                &format!("{path}/failure_mode"),
                errors,
            );
            modes.insert(mode);
        }
        if control.get("status").and_then(Value::as_str) != Some("pass") {
            errors.push(format!("{path}/status must be pass"));
        }
        if !control
            .get("test_command")
            .and_then(Value::as_str)
            .is_some_and(|command| command.contains("cross_surface_swarm_conformance_matrix"))
        {
            errors.push(format!(
                "{path}/test_command must point at the matrix harness"
            ));
        }
    }

    let required_modes = NEGATIVE_FAILURE_MODES
        .iter()
        .map(|mode| (*mode).to_string())
        .collect::<BTreeSet<_>>();
    if modes != required_modes {
        errors.push("negative_controls must cover every required failure mode".to_string());
    }
}

fn validate_matrix(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let root = repo_root();

    match pointer_str(value, "/schema") {
        Ok(schema) if schema == EXPECTED_SCHEMA => {}
        Ok(schema) => errors.push(format!("schema mismatch: {schema}")),
        Err(err) => errors.push(err),
    }
    match pointer_str(value, "/bead") {
        Ok(bead) if bead == EXPECTED_BEAD => {}
        Ok(bead) => errors.push(format!("bead mismatch: {bead}")),
        Err(err) => errors.push(err),
    }
    if pointer_str(value, "/status") != Ok("pass") {
        errors.push("/status must be pass".to_string());
    }
    if !value
        .get("claim_boundary")
        .and_then(Value::as_str)
        .is_some_and(|boundary| {
            boundary.contains("not release certification")
                && boundary.contains("drop-in certification")
                && boundary.contains("permission to skip")
        })
    {
        errors.push("/claim_boundary must reject release-facing claims".to_string());
    }

    match string_set(value, "/required_surfaces") {
        Ok(required_surfaces) => {
            let expected = REQUIRED_SURFACES
                .iter()
                .map(|surface| (*surface).to_string())
                .collect::<BTreeSet<_>>();
            if required_surfaces != expected {
                errors.push("/required_surfaces must exactly match the required set".to_string());
            }
        }
        Err(err) => errors.push(err),
    }

    let mut ids = BTreeSet::new();
    let mut observed_surfaces = BTreeSet::new();
    let mut provider_row_count = 0;
    if let Some(rows) = array_for_validation(value, "/rows", &mut errors) {
        if rows.is_empty() {
            errors.push("/rows must not be empty".to_string());
        }
        for (index, row) in rows.iter().enumerate() {
            validate_row(
                row,
                index,
                &root,
                &mut ids,
                &mut observed_surfaces,
                &mut provider_row_count,
                &mut errors,
            );
        }
    }

    for required in REQUIRED_SURFACES {
        if !observed_surfaces.contains(*required) {
            errors.push(format!("missing required surface {required}"));
        }
    }
    if provider_row_count != 1 {
        errors.push("provider stream ordering must have exactly one aggregate row".to_string());
    }

    validate_negative_controls(value, &mut errors);
    errors
}

fn require_no_errors(errors: &[String]) -> TestResult {
    require(
        errors.is_empty(),
        format!("matrix validation failed:\n{}", errors.join("\n")),
    )
}

fn require_error_contains(errors: &[String], needle: &str) -> TestResult {
    require(
        errors.iter().any(|error| error.contains(needle)),
        format!(
            "expected validation error containing {needle:?}; got:\n{}",
            errors.join("\n")
        ),
    )
}

#[test]
fn cross_surface_swarm_matrix_matches_required_surfaces_and_schema() -> TestResult {
    let evidence = load_json(EVIDENCE_PATH)?;
    require_no_errors(&validate_matrix(&evidence))
}

#[test]
fn cross_surface_swarm_matrix_cross_links_provider_rows_instead_of_duplicating() -> TestResult {
    let evidence = load_json(EVIDENCE_PATH)?;
    let rows = pointer_array(&evidence, "/rows")?;
    let provider_rows = rows
        .iter()
        .filter(|row| {
            row.get("source_surface").and_then(Value::as_str) == Some("provider_stream_ordering")
        })
        .collect::<Vec<_>>();
    require(
        provider_rows.len() == 1,
        "provider-specific suites must be represented by one aggregate row",
    )?;

    let provider_row = provider_rows
        .first()
        .copied()
        .ok_or_else(|| "missing provider stream ordering row".to_string())?;
    require(
        provider_row
            .get("cross_links_provider_specific_rows")
            .and_then(Value::as_bool)
            == Some(true),
        "provider row must declare provider-specific cross-linking",
    )?;
    let refs = string_set(provider_row, "/evidence_refs")?;
    require(
        refs.contains("tests/provider_streaming.rs")
            && refs.iter().any(|path| {
                path.starts_with("tests/provider_streaming/")
                    && Path::new(path)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
            }),
        "provider row must link the aggregate harness and provider-specific modules",
    )
}

#[test]
fn cross_surface_swarm_matrix_negative_controls_fail_closed() -> TestResult {
    let evidence = load_json(EVIDENCE_PATH)?;

    let mut missing_surface = evidence.clone();
    pointer_array_mut(&mut missing_surface, "/rows")?.retain(|row| {
        row.get("source_surface").and_then(Value::as_str) != Some("tui_frame_budget_non_blocking")
    });
    require_error_contains(
        &validate_matrix(&missing_surface),
        "missing required surface tui_frame_budget_non_blocking",
    )?;

    let mut missing_field = evidence.clone();
    let first_row = pointer_array_mut(&mut missing_field, "/rows")?
        .first_mut()
        .ok_or_else(|| "matrix fixture must contain at least one row".to_string())?;
    first_row
        .as_object_mut()
        .ok_or_else(|| "matrix rows must be JSON objects".to_string())?
        .remove("test_command");
    require_error_contains(&validate_matrix(&missing_field), "test_command")?;

    let mut invalid_status = evidence;
    let first_row = pointer_array_mut(&mut invalid_status, "/rows")?
        .first_mut()
        .ok_or_else(|| "matrix fixture must contain at least one row".to_string())?;
    first_row
        .as_object_mut()
        .ok_or_else(|| "matrix rows must be JSON objects".to_string())?
        .insert("status".to_string(), json!("unknown"));
    require_error_contains(&validate_matrix(&invalid_status), "invalid value unknown")
}
