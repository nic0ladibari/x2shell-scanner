//! The `Detector` trait the core drives uniformly, plus the shared outcome and
//! options types.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::http::HttpClient;
use super::report::State;
use super::targets::{Scope, Target};

/// Knobs the core passes into every detector scan. Per-detector configuration
/// (e.g. react's safe-check vs active mode) lives in the detector's own struct;
/// this carries only what is common across all three.
#[derive(Debug, Clone, Default)]
pub struct ScanOpts {
    pub follow_redirects: bool,
    pub verbose: bool,
    /// Low-impact mode: a detector must **not** start a heavy/DoS probe (php's
    /// crash probes, node's 23 MiB probe). Set by `all`, which promises only
    /// low-impact checks; a detector that can't conclude without a heavy probe
    /// returns `Unknown` with a reason. Default `false` (heavy probes allowed),
    /// so the per-detector subcommands are unaffected.
    pub low_impact: bool,
    /// Caps concurrent heavy probes across the whole run (`--max-heavy`),
    /// independent of `--threads`. A detector takes a permit around its large
    /// streamed probe; `None` means uncapped.
    pub heavy: Option<Arc<Semaphore>>,
    /// The `--scope` allowlist, when set. A detector that follows redirects to a
    /// new host (php's `--follow-redirects`) must re-check each hop against it,
    /// so a redirect can never carry the scan to an out-of-scope host. `None`
    /// means no allowlist was given (every host already passed CLI resolution).
    pub scope: Option<Arc<Scope>>,
}

impl ScanOpts {
    /// Acquire a heavy-probe permit if a cap is set; hold the returned guard
    /// across the heavy send. `None` when uncapped (or the semaphore is closed,
    /// which never happens in practice).
    pub async fn heavy_permit(&self) -> Option<OwnedSemaphorePermit> {
        match &self.heavy {
            Some(sem) => Arc::clone(sem).acquire_owned().await.ok(),
            None => None,
        }
    }
}

/// A detector's result for one target: the unified verdict plus the native
/// label (for fidelity), a reason, the actual tested URL, and
/// detector-specific keys under `extra`.
#[derive(Debug, Clone)]
pub struct DetectorOutcome {
    pub state: State,
    pub native_verdict: String,
    pub status_code: Option<u16>,
    pub reason: Option<String>,
    pub error: Option<String>,
    /// URL used for the verdict, including any redirect or path change.
    pub tested_url: String,
    /// Detector-specific result keys (e.g. react's `final_url`).
    pub extra: Value,
}

impl DetectorOutcome {
    pub fn new(state: State, native: &str, tested_url: &str) -> Self {
        Self {
            state,
            native_verdict: native.to_string(),
            status_code: None,
            reason: None,
            error: None,
            tested_url: tested_url.to_string(),
            extra: Value::Null,
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status_code = Some(status);
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

#[async_trait]
pub trait Detector: Send + Sync {
    /// Stable id: `"php" | "node" | "react"`.
    fn id(&self) -> &'static str;

    /// Paths to test when the caller supplies none.
    fn default_paths(&self) -> &[&str];

    /// Scan one target and return the native verdict + evidence.
    async fn scan(&self, target: &Target, http: &HttpClient, opts: &ScanOpts) -> DetectorOutcome;
}
