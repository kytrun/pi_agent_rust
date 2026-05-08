//! Host-scale resource admission control for swarm workloads.
//!
//! The governor is intentionally conservative and dependency-light: Linux hosts
//! get live `/proc` sampling, while other platforms keep deterministic fallback
//! budgets and only enforce request-local limits such as tool-output caps.

use serde::Serialize;
use serde_json::{Value, json};

const PROC_PAGE_SIZE_BYTES: u64 = 4096;
const DEFAULT_MEMORY_BYTES: u64 = 1_073_741_824;
const DEFAULT_FD_LIMIT: u64 = 1024;
const DEFAULT_TOOL_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;
const MIN_PROCESS_BUDGET: u64 = 64;
const MIN_FD_BUDGET: u64 = 128;
const MIN_LOAD_BUDGET: f64 = 2.0;

/// Host resource budgets used by admission checks.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostResourceBudgets {
    /// Logical CPU cores available to this process.
    pub cpu_cores: u64,
    /// Maximum acceptable one-minute load average before denial.
    pub max_load_avg_1m: f64,
    /// Maximum RSS for this process.
    pub max_rss_bytes: u64,
    /// Maximum observed process count on the host.
    pub max_processes: u64,
    /// Maximum file descriptors open by this process.
    pub max_fds: u64,
    /// Maximum tool-output bytes admitted for one hostcall.
    pub max_tool_output_bytes: u64,
    /// Ratio at which the governor starts delaying work.
    pub backpressure_ratio: f64,
    /// Ratio at which the governor rejects work fail-closed.
    pub deny_ratio: f64,
}

impl HostResourceBudgets {
    /// Derive conservative budgets from the current host.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn from_host() -> Self {
        let cpu_cores = std::thread::available_parallelism()
            .ok()
            .and_then(|value| u64::try_from(value.get()).ok())
            .unwrap_or(1);
        let mem_total = read_mem_total_bytes().unwrap_or(DEFAULT_MEMORY_BYTES);
        let max_rss_bytes = (mem_total / 2).clamp(512 * 1024 * 1024, 8 * 1024 * 1024 * 1024);
        let fd_soft_limit = read_open_files_soft_limit().unwrap_or(DEFAULT_FD_LIMIT);

        Self {
            cpu_cores,
            max_load_avg_1m: ((cpu_cores as f64) * 4.0).max(MIN_LOAD_BUDGET),
            max_rss_bytes,
            max_processes: cpu_cores.saturating_mul(128).max(MIN_PROCESS_BUDGET),
            max_fds: ((fd_soft_limit.saturating_mul(4)) / 5).max(MIN_FD_BUDGET),
            max_tool_output_bytes: DEFAULT_TOOL_OUTPUT_BYTES,
            backpressure_ratio: 0.85,
            deny_ratio: 1.10,
        }
    }

    /// Test helper for fixed budgets.
    #[must_use]
    pub const fn fixed(
        max_load_avg_1m: f64,
        max_rss_bytes: u64,
        max_processes: u64,
        max_fds: u64,
        max_tool_output_bytes: u64,
    ) -> Self {
        Self {
            cpu_cores: 1,
            max_load_avg_1m,
            max_rss_bytes,
            max_processes,
            max_fds,
            max_tool_output_bytes,
            backpressure_ratio: 0.85,
            deny_ratio: 1.10,
        }
    }
}

impl Default for HostResourceBudgets {
    fn default() -> Self {
        Self::from_host()
    }
}

/// Current host sample used for one admission decision.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostResourceSample {
    /// One-minute load average, when available.
    pub load_avg_1m: Option<f64>,
    /// Current process RSS in bytes, when available.
    pub rss_bytes: Option<u64>,
    /// Current host process count, when available.
    pub process_count: Option<u64>,
    /// Current open file descriptor count for this process, when available.
    pub fd_count: Option<u64>,
}

impl HostResourceSample {
    /// Sample the current process/host state.
    #[must_use]
    pub fn current() -> Self {
        Self {
            load_avg_1m: read_load_avg_1m(),
            rss_bytes: read_self_rss_bytes(),
            process_count: count_proc_processes(),
            fd_count: count_self_fds(),
        }
    }
}

/// Hostcall class submitted to the resource governor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceOperationKind {
    /// Built-in or extension-provided tool call.
    Tool,
    /// Shell command hostcall.
    Exec,
    /// HTTP hostcall.
    Http,
    /// Session metadata or persistence hostcall.
    Session,
    /// Extension UI hostcall.
    Ui,
    /// Extension event hostcall.
    Events,
    /// Extension log/telemetry hostcall.
    Log,
    /// Unknown or future hostcall kind.
    Unknown,
}

/// One unit of work being considered for admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceRequest {
    /// Operation class.
    pub operation: ResourceOperationKind,
    /// Required capability label.
    pub capability: String,
    /// Estimated maximum output bytes retained by the operation.
    pub estimated_tool_output_bytes: u64,
    /// Current scheduler queue depth.
    pub queue_depth: usize,
}

impl ResourceRequest {
    /// Create a request for the given operation/capability.
    #[must_use]
    pub fn new(operation: ResourceOperationKind, capability: impl Into<String>) -> Self {
        Self {
            operation,
            capability: capability.into(),
            estimated_tool_output_bytes: 0,
            queue_depth: 1,
        }
    }

    /// Attach estimated output bytes.
    #[must_use]
    pub const fn with_estimated_tool_output_bytes(mut self, bytes: u64) -> Self {
        self.estimated_tool_output_bytes = bytes;
        self
    }

    /// Attach queue depth.
    #[must_use]
    pub const fn with_queue_depth(mut self, queue_depth: usize) -> Self {
        self.queue_depth = queue_depth;
        self
    }
}

/// Admission action selected by the governor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionAction {
    /// Dispatch immediately.
    Admit,
    /// Delay briefly, then dispatch.
    Backpressure,
    /// Reject before dispatch.
    Deny,
}

/// Resource dimension that dominated a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDimension {
    /// CPU load average.
    CpuLoad,
    /// Process resident memory.
    Rss,
    /// Host process count.
    Processes,
    /// Open file descriptors.
    FileDescriptors,
    /// Estimated tool output.
    ToolOutput,
    /// No dimension is currently pressurized.
    None,
}

/// Result of one admission check.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AdmissionDecision {
    /// Selected action.
    pub action: AdmissionAction,
    /// Resource dimension with the highest budget ratio.
    pub dominant_dimension: ResourceDimension,
    /// Highest observed budget ratio.
    pub dominant_ratio: f64,
    /// Human-readable reason for telemetry and errors.
    pub reason: String,
    /// Delay to apply for [`AdmissionAction::Backpressure`].
    pub retry_after_ms: u64,
    /// Sample used by this decision.
    pub sample: HostResourceSample,
    /// Budgets used by this decision.
    pub budgets: HostResourceBudgets,
}

impl AdmissionDecision {
    /// Render a stable JSON telemetry payload.
    #[must_use]
    pub fn telemetry(&self, request: &ResourceRequest) -> Value {
        json!({
            "schema": "pi.resource_governor.admission.v1",
            "request": request,
            "decision": self,
        })
    }
}

/// Stateless resource governor.
#[derive(Debug, Clone)]
pub struct ResourceGovernor {
    budgets: HostResourceBudgets,
}

impl ResourceGovernor {
    /// Build a governor from host-derived budgets.
    #[must_use]
    pub fn from_host() -> Self {
        Self {
            budgets: HostResourceBudgets::from_host(),
        }
    }

    /// Build a governor with explicit budgets.
    #[must_use]
    pub const fn with_budgets(budgets: HostResourceBudgets) -> Self {
        Self { budgets }
    }

    /// Return the active budgets.
    #[must_use]
    pub const fn budgets(&self) -> &HostResourceBudgets {
        &self.budgets
    }

    /// Evaluate a request against the live host sample.
    #[must_use]
    pub fn admit(&self, request: &ResourceRequest) -> AdmissionDecision {
        self.admit_sample(request, HostResourceSample::current())
    }

    /// Evaluate a request against an injected sample.
    #[must_use]
    pub fn admit_sample(
        &self,
        request: &ResourceRequest,
        sample: HostResourceSample,
    ) -> AdmissionDecision {
        let (dominant_dimension, dominant_ratio) =
            dominant_pressure(&self.budgets, &sample, request);
        let action = if dominant_ratio >= self.budgets.deny_ratio {
            AdmissionAction::Deny
        } else if dominant_ratio >= self.budgets.backpressure_ratio {
            AdmissionAction::Backpressure
        } else {
            AdmissionAction::Admit
        };
        let retry_after_ms = match action {
            AdmissionAction::Backpressure => retry_after_ms(dominant_ratio),
            AdmissionAction::Admit | AdmissionAction::Deny => 0,
        };
        AdmissionDecision {
            action,
            dominant_dimension,
            dominant_ratio,
            reason: decision_reason(action, dominant_dimension, dominant_ratio),
            retry_after_ms,
            sample,
            budgets: self.budgets.clone(),
        }
    }
}

impl Default for ResourceGovernor {
    fn default() -> Self {
        Self::from_host()
    }
}

fn dominant_pressure(
    budgets: &HostResourceBudgets,
    sample: &HostResourceSample,
    request: &ResourceRequest,
) -> (ResourceDimension, f64) {
    let mut dominant = (ResourceDimension::None, 0.0);
    consider_ratio(
        &mut dominant,
        ResourceDimension::CpuLoad,
        sample.load_avg_1m,
        budgets.max_load_avg_1m,
    );
    consider_ratio_u64(
        &mut dominant,
        ResourceDimension::Rss,
        sample.rss_bytes,
        budgets.max_rss_bytes,
    );
    consider_ratio_u64(
        &mut dominant,
        ResourceDimension::Processes,
        sample.process_count,
        budgets.max_processes,
    );
    consider_ratio_u64(
        &mut dominant,
        ResourceDimension::FileDescriptors,
        sample.fd_count,
        budgets.max_fds,
    );
    consider_ratio_u64(
        &mut dominant,
        ResourceDimension::ToolOutput,
        Some(request.estimated_tool_output_bytes),
        budgets.max_tool_output_bytes,
    );
    dominant
}

fn consider_ratio(
    dominant: &mut (ResourceDimension, f64),
    dimension: ResourceDimension,
    observed: Option<f64>,
    budget: f64,
) {
    let Some(observed) = observed else {
        return;
    };
    if budget <= 0.0 {
        return;
    }
    let ratio = observed.max(0.0) / budget;
    if ratio > dominant.1 {
        *dominant = (dimension, ratio);
    }
}

#[allow(clippy::cast_precision_loss)]
fn consider_ratio_u64(
    dominant: &mut (ResourceDimension, f64),
    dimension: ResourceDimension,
    observed: Option<u64>,
    budget: u64,
) {
    if budget == 0 {
        return;
    }
    consider_ratio(
        dominant,
        dimension,
        observed.map(|value| value as f64),
        budget as f64,
    );
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn retry_after_ms(ratio: f64) -> u64 {
    let excess = (ratio - 0.85).max(0.0);
    (50.0 + (excess * 1_000.0)).clamp(50.0, 500.0) as u64
}

fn decision_reason(
    action: AdmissionAction,
    dominant_dimension: ResourceDimension,
    dominant_ratio: f64,
) -> String {
    match action {
        AdmissionAction::Admit => "host resources within budgets".to_string(),
        AdmissionAction::Backpressure => format!(
            "host resource pressure on {dominant_dimension:?} at {dominant_ratio:.2}x budget"
        ),
        AdmissionAction::Deny => format!(
            "host resource limit exceeded on {dominant_dimension:?} at {dominant_ratio:.2}x budget"
        ),
    }
}

#[cfg(target_os = "linux")]
fn read_load_avg_1m() -> Option<f64> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(not(target_os = "linux"))]
const fn read_load_avg_1m() -> Option<f64> {
    None
}

#[cfg(target_os = "linux")]
fn read_self_rss_bytes() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages: u64 = content.split_whitespace().nth(1)?.parse().ok()?;
    resident_pages.checked_mul(PROC_PAGE_SIZE_BYTES)
}

#[cfg(not(target_os = "linux"))]
const fn read_self_rss_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn read_mem_total_bytes() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("MemTotal:") else {
            continue;
        };
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        return kb.checked_mul(1024);
    }
    None
}

#[cfg(not(target_os = "linux"))]
const fn read_mem_total_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn count_proc_processes() -> Option<u64> {
    let mut count = 0_u64;
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()) {
            count = count.saturating_add(1);
        }
    }
    Some(count)
}

#[cfg(not(target_os = "linux"))]
const fn count_proc_processes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn count_self_fds() -> Option<u64> {
    let count = std::fs::read_dir("/proc/self/fd").ok()?.count();
    u64::try_from(count).ok()
}

#[cfg(not(target_os = "linux"))]
const fn count_self_fds() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn read_open_files_soft_limit() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/self/limits").ok()?;
    for line in content.lines() {
        if !line.starts_with("Max open files") {
            continue;
        }
        let token = line.split_whitespace().nth(3)?;
        if token == "unlimited" {
            return None;
        }
        return token.parse().ok();
    }
    None
}

#[cfg(not(target_os = "linux"))]
const fn read_open_files_soft_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionAction, HostResourceBudgets, HostResourceSample, ResourceDimension,
        ResourceGovernor, ResourceOperationKind, ResourceRequest,
    };

    fn budgets() -> HostResourceBudgets {
        HostResourceBudgets::fixed(10.0, 1_000, 100, 100, 1_000)
    }

    fn sample() -> HostResourceSample {
        HostResourceSample {
            load_avg_1m: Some(2.0),
            rss_bytes: Some(200),
            process_count: Some(20),
            fd_count: Some(20),
        }
    }

    #[test]
    fn admits_when_all_dimensions_are_below_backpressure_ratio() {
        let governor = ResourceGovernor::with_budgets(budgets());
        let request = ResourceRequest::new(ResourceOperationKind::Tool, "read")
            .with_estimated_tool_output_bytes(200);

        let decision = governor.admit_sample(&request, sample());

        assert_eq!(decision.action, AdmissionAction::Admit);
        assert_eq!(decision.dominant_dimension, ResourceDimension::CpuLoad);
    }

    #[test]
    fn backpressures_before_hard_overload() {
        let governor = ResourceGovernor::with_budgets(budgets());
        let request = ResourceRequest::new(ResourceOperationKind::Tool, "read")
            .with_estimated_tool_output_bytes(900);

        let decision = governor.admit_sample(&request, sample());

        assert_eq!(decision.action, AdmissionAction::Backpressure);
        assert_eq!(decision.dominant_dimension, ResourceDimension::ToolOutput);
        assert!(decision.retry_after_ms >= 50);
    }

    #[test]
    fn denies_when_a_dimension_exceeds_the_deny_ratio() {
        let governor = ResourceGovernor::with_budgets(budgets());
        let request = ResourceRequest::new(ResourceOperationKind::Exec, "exec")
            .with_estimated_tool_output_bytes(1_200);

        let decision = governor.admit_sample(&request, sample());

        assert_eq!(decision.action, AdmissionAction::Deny);
        assert_eq!(decision.dominant_dimension, ResourceDimension::ToolOutput);
    }

    #[test]
    fn ignores_unavailable_host_metrics_but_still_checks_request_size() {
        let governor = ResourceGovernor::with_budgets(budgets());
        let request = ResourceRequest::new(ResourceOperationKind::Exec, "exec")
            .with_estimated_tool_output_bytes(1_200);
        let sample = HostResourceSample {
            load_avg_1m: None,
            rss_bytes: None,
            process_count: None,
            fd_count: None,
        };

        let decision = governor.admit_sample(&request, sample);

        assert_eq!(decision.action, AdmissionAction::Deny);
        assert_eq!(decision.dominant_dimension, ResourceDimension::ToolOutput);
    }

    #[test]
    fn telemetry_contains_stable_schema() {
        let governor = ResourceGovernor::with_budgets(budgets());
        let request = ResourceRequest::new(ResourceOperationKind::Session, "session");
        let decision = governor.admit_sample(&request, sample());

        let telemetry = decision.telemetry(&request);

        assert_eq!(
            telemetry.get("schema").and_then(serde_json::Value::as_str),
            Some("pi.resource_governor.admission.v1")
        );
        assert_eq!(
            telemetry
                .get("decision")
                .and_then(|value| value.get("action"))
                .and_then(serde_json::Value::as_str),
            Some("admit")
        );
    }
}
