//! Detector `react`; React Server Components / Next.js.
//!
//! Default mode is the non-executing **safe-check** side-channel. The active
//! confirmation mode is compiled only under the `active-confirm` feature and is
//! gated at runtime by `--i-am-authorized`; it confirms via a benign reflected
//! marker only (its verdict logic lives in [`detect::evaluate_active`]).

pub mod detect;
pub mod payload;
pub mod redirect;

use async_trait::async_trait;
use serde_json::json;

use crate::core::detector::{Detector, DetectorOutcome, ScanOpts};
use crate::core::http::HttpClient;
use crate::core::report::State;
use crate::core::targets::Target;

/// react detector modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReactMode {
    /// Side-channel, non-executing. The default for this tool.
    #[default]
    SafeCheck,
    /// Active confirmation via a benign reflected marker. Compiled only under the
    /// `active-confirm` feature and gated at runtime by `--i-am-authorized`.
    #[cfg(feature = "active-confirm")]
    Active,
}

#[derive(Debug, Clone, Default)]
pub struct ReactDetector {
    pub mode: ReactMode,
    /// `--seed` for deterministic `--waf-bypass` junk (active mode only).
    #[cfg(feature = "active-confirm")]
    pub seed: Option<u64>,
    /// `--waf-bypass` (active mode only).
    #[cfg(feature = "active-confirm")]
    pub waf_bypass: bool,
}

impl ReactDetector {
    pub fn safe_check() -> Self {
        // Default already selects SafeCheck mode (and no active opts).
        Self::default()
    }

    /// Active-confirmation detector. Only the authorized-use path in the binary
    /// constructs this (feature + `--i-am-authorized`).
    #[cfg(feature = "active-confirm")]
    pub fn active(seed: Option<u64>, waf_bypass: bool) -> Self {
        Self {
            mode: ReactMode::Active,
            seed,
            waf_bypass,
        }
    }

    /// The probe to send for this mode.
    fn probe_request(&self) -> crate::core::http::HttpRequest {
        match self.mode {
            ReactMode::SafeCheck => payload::safe_check_request(),
            #[cfg(feature = "active-confirm")]
            ReactMode::Active => payload::active_request(self.seed, self.waf_bypass),
        }
    }

    /// The mode label recorded in the result's `mode` key.
    fn mode_label(&self) -> &'static str {
        match self.mode {
            ReactMode::SafeCheck => "safe-check",
            #[cfg(feature = "active-confirm")]
            ReactMode::Active => "active",
        }
    }
}

#[async_trait]
impl Detector for ReactDetector {
    fn id(&self) -> &'static str {
        "react"
    }

    fn default_paths(&self) -> &[&str] {
        &["/"]
    }

    async fn scan(&self, target: &Target, http: &HttpClient, opts: &ScanOpts) -> DetectorOutcome {
        let tested = target.as_str().to_string();

        // Pick the probe, the verdict evaluator, and the mode label by mode. Both
        // evaluators return a ReactDecision, and the redirect-retest flow below is
        // shared, so the two modes differ only here.
        let evaluate: fn(&crate::core::http::RawResponse) -> detect::ReactDecision = match self.mode
        {
            ReactMode::SafeCheck => detect::evaluate_safe_check,
            #[cfg(feature = "active-confirm")]
            ReactMode::Active => detect::evaluate_active,
        };
        let request = self.probe_request();
        let mode_str = self.mode_label();

        let resp = match http.send(target, request.clone()).await {
            Ok(r) => r,
            Err(e) => {
                // A transport failure (incl. timeout) describes the check, not the
                // asset → Unknown, never a negative.
                return DetectorOutcome::new(State::Unknown, "ERROR", &tested)
                    .with_error(e.to_string());
            }
        };

        let mut decision = evaluate(&resp);
        let mut status: Option<u16> = Some(resp.status);
        let mut final_url = tested.clone();
        let mut error: Option<String> = None;

        // If the original URL redirects same-host and retesting is allowed, the
        // final URL is the authoritative answer; adopt its verdict whatever it is
        // (including Unknown). If the final retest itself errors, that is also
        // inconclusive (the attempted URL + error), never the pre-redirect
        // negative; a redirect we could not follow to a verdict is not a
        // demonstrated "not vulnerable".
        if opts.follow_redirects
            && redirect::REDIRECT_STATUSES.contains(&resp.status)
            && decision.state != State::Vulnerable
        {
            if let Some(final_target) = redirect::resolve_same_host(http, target, 10).await {
                final_url = final_target.as_str().to_string();
                match http.send(&final_target, request.clone()).await {
                    Ok(resp2) => {
                        decision = evaluate(&resp2);
                        status = Some(resp2.status);
                    }
                    Err(e) => {
                        decision =
                            detect::unknown("redirect retest failed; final URL unverifiable");
                        error = Some(e.to_string());
                        // The final URL never produced a status; don't attribute
                        // the pre-redirect 302's status to it.
                        status = None;
                    }
                }
            }
        }

        // tested_url is the URL that actually produced the verdict: after a
        // redirect retest, report the final URL that was tested.
        let mut outcome = DetectorOutcome::new(decision.state, decision.native, &final_url)
            .with_reason(decision.reason)
            .with_extra(json!({
                "final_url": final_url,
                "cve": detect::PRIMARY_CVE,
                "mode": mode_str,
            }));
        if let Some(s) = status {
            outcome = outcome.with_status(s);
        }
        if let Some(e) = error {
            outcome = outcome.with_error(e);
        }
        outcome
    }
}
