//! Detector `php`; PHP multipart-parser memory exhaustion.
//!
//! Pure verdict core: [`version`] (fixed-patch table + `X-Powered-By`
//! classification) and [`detect`] (crash signals + SAPI gating + the patched-OOM
//! false-positive guard). The I/O wiring here drives a benign control, the
//! phpMyAdmin retarget, and up to three streamed heavy probes that stop at the
//! first settled signal.

pub mod detect;
pub mod payload;
pub mod redirect;
pub mod version;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::core::detector::{Detector, DetectorOutcome, ScanOpts};
use crate::core::http::{HttpClient, RawResponse};
use crate::core::report::State;
use crate::core::targets::Target;

use detect::{PhpSignal, Sapi};

/// Detector `php`. **Passive is the no-flag default** (control + version check,
/// zero heavy probes; safe fleet triage). The crash probes run only
/// when `active` is set explicitly (`--active`).
#[derive(Debug, Clone, Default)]
pub struct PhpDetector {
    pub sapi: Sapi,
    pub active: bool,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

#[async_trait]
impl Detector for PhpDetector {
    fn id(&self) -> &'static str {
        "php"
    }

    fn default_paths(&self) -> &[&str] {
        &["/index.php"]
    }

    async fn scan(&self, target: &Target, http: &HttpClient, opts: &ScanOpts) -> DetectorOutcome {
        // Control request establishes the baseline (status, body-present, version).
        let mut active_target = target.clone();
        let mut control = match http.send(&active_target, payload::control_request()).await {
            Ok(r) => r,
            Err(e) => {
                return DetectorOutcome::new(State::Unknown, "ERROR", target.as_str())
                    .with_error(e.to_string())
            }
        };

        // phpMyAdmin special case: retarget and re-baseline.
        let retargeted = contains(&control.body, payload::PHPMYADMIN_MARKER);
        if retargeted {
            active_target = active_target.with_path("/show_config_errors.php");
            match http.send(&active_target, payload::control_request()).await {
                Ok(r) => control = r,
                Err(e) => {
                    return DetectorOutcome::new(State::Unknown, "ERROR", active_target.as_str())
                        .with_error(e.to_string())
                }
            }
        }

        // Keep operator headers off all later requests once the chain crosses origins.
        let mut redirect_client: Option<HttpClient> = None;
        if opts.follow_redirects && redirect::REDIRECT_STATUSES.contains(&control.status) {
            if let Some(res) = redirect::resolve(
                http,
                &active_target,
                redirect::MAX_REDIRECT_HOPS,
                opts.scope.as_deref(),
            )
            .await
            {
                active_target = res.target;
                if res.crossed_origin {
                    redirect_client = Some(http.without_extra_headers());
                }
                let client = redirect_client.as_ref().unwrap_or(http);
                match client
                    .send(&active_target, payload::control_request())
                    .await
                {
                    Ok(r) => control = r,
                    Err(e) => {
                        return DetectorOutcome::new(
                            State::Unknown,
                            "ERROR",
                            active_target.as_str(),
                        )
                        .with_error(e.to_string())
                    }
                }
            }
        }
        // The client for every remaining request: stripped iff a hop crossed the
        // origin, otherwise the original (with the operator headers intact).
        let client = redirect_client.as_ref().unwrap_or(http);

        let tested = active_target.as_str();
        let powered_by = control.header("x-powered-by");
        let version = powered_by.and_then(version::classify_powered_by);
        let powered_by = powered_by.map(|value| http.evidence_header("x-powered-by", value));

        let active = self.active && !opts.low_impact;
        let finish = |decision: detect::PhpDecision, probes: Vec<Value>| {
            DetectorOutcome::new(decision.state, decision.native, tested)
                .with_status(control.status)
                .with_reason(decision.reason)
                .with_extra(json!({
                    "sapi": format!("{:?}", self.sapi).to_lowercase(),
                    "powered_by": powered_by,
                    "mode": if active { "active" } else { "passive" },
                    "phpmyadmin_retarget": retargeted,
                    "control": {
                        "status": control.status,
                        "body_empty": control.body.is_empty(),
                    },
                    "probes": probes,
                    "final_url": tested,
                }))
        };

        let mut version_decision = detect::resolve(&PhpSignal::NoSignal, version);
        if !active || version_decision.state != State::Unknown {
            if self.active && opts.low_impact && version_decision.state == State::Unknown {
                version_decision = detect::resolve(
                    &PhpSignal::Inconclusive("heavy probes skipped in low-impact mode"),
                    version,
                );
            }
            return finish(version_decision, Vec::new());
        }

        // Up to 3 streamed probes, stop at the first settled signal.
        // Hold a heavy-probe permit (`--max-heavy`) across the whole probe phase
        // so the fleet never runs more large bodies at once than the cap.
        let _heavy = opts.heavy_permit().await;
        let mut probes = Vec::new();
        let mut settled: Option<PhpSignal> = None;
        for size in payload::PROBE_SIZES {
            match client
                .send_streaming(&active_target, payload::probe_request(size))
                .await
            {
                Ok(probe) => {
                    let signal = detect::probe_signal(&control, &probe, self.sapi);
                    probes.push(probe_json(size, Some(&probe), None, &signal));
                    match signal {
                        PhpSignal::NoSignal => continue, // escalate to a bigger probe
                        other => {
                            settled = Some(other);
                            break;
                        }
                    }
                }
                Err(e) => {
                    // A request-level failure is fail-safe: inconclusive, not a
                    // guessed crash. Record it and stop escalating.
                    let signal = PhpSignal::Inconclusive("probe request failed");
                    probes.push(probe_json(size, None, Some(e.to_string()), &signal));
                    settled = Some(signal);
                    break;
                }
            }
        }

        let signal = settled.unwrap_or(PhpSignal::NoSignal);
        let decision = detect::resolve(&signal, version);
        finish(decision, probes)
    }
}

/// One probe's evidence row for the JSON output (`probes`).
fn probe_json(
    size: usize,
    probe: Option<&RawResponse>,
    error: Option<String>,
    signal: &PhpSignal,
) -> Value {
    let signal_str = match signal {
        PhpSignal::Crash(r) => format!("crash: {r}"),
        PhpSignal::NoSignal => "no signal".to_string(),
        PhpSignal::Inconclusive(r) => format!("inconclusive: {r}"),
    };
    json!({
        "target_size": size,
        "status": probe.map(|p| p.status),
        "body_empty": probe.map(|p| p.body.is_empty()),
        "body_truncated": probe.map(|p| p.body_truncated),
        "error": error,
        "signal": signal_str,
    })
}
