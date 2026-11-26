//! Detector `node`; Node encoded-body response-class confusion.
//!
//! Learns the route's valid/malformed response classes from controls, then sends
//! one large Brotli-labeled probe and checks which class it lands in. No
//! signatures, no status thresholds, no version table. The pure decision lives in
//! [`detect`] and [`compare`]; this module drives the six measured exchanges and
//! short-circuits before the 23 MiB probe when the controls fail.

pub mod compare;
pub mod detect;
pub mod stages;

use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Map, Value};

use crate::core::detector::{Detector, DetectorOutcome, ScanOpts};
use crate::core::http::{HttpClient, HttpError, ProbeResponse};
use crate::core::report::State;
use crate::core::targets::Target;

use compare::{choose_comparison, matches, Comparison, StageResponse};
use detect::{evaluate, Stages};
use stages::StageSpec;

/// Interim-100 wait for the probe (~1 s).
const CONTINUE_WAIT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Default)]
pub struct NodeDetector;

#[async_trait]
impl Detector for NodeDetector {
    fn id(&self) -> &'static str {
        "node"
    }

    fn default_paths(&self) -> &[&str] {
        &["/"]
    }

    // NOTE: tests the target's own path. Multi-path expansion and the
    // "first vulnerable path wins" fallback belong to the shared path
    // feature, which no detector wires yet; add here when it lands.
    async fn scan(&self, target: &Target, http: &HttpClient, opts: &ScanOpts) -> DetectorOutcome {
        let tested = target.as_str().to_string();
        let mut responses: Map<String, Value> = Map::new();
        let mut powered_by: Option<String> = None;

        // Helper: run a stage, record its evidence, and capture X-Powered-By.
        macro_rules! run {
            ($spec:expr) => {{
                let spec: StageSpec = $spec;
                let name = spec.name;
                match run_stage(http, target, spec).await {
                    Ok(p) => {
                        if powered_by.is_none() {
                            powered_by = p
                                .header("x-powered-by")
                                .map(|s| http.evidence_header("x-powered-by", s).to_owned());
                        }
                        responses.insert(name.to_string(), resp_json(&p, http));
                        p
                    }
                    Err(e) => {
                        responses.insert(name.to_string(), err_json(&e));
                        return inconclusive(&tested, &e, powered_by.clone(), responses);
                    }
                }
            }};
        }

        let bypass = to_stage(&run!(stages::content_type_bypass()));
        let valid = to_stage(&run!(stages::valid_empty_brotli()));
        if valid.status != bypass.status {
            return no_signal(
                &tested,
                "valid control status differs from the bypass control",
                None,
                powered_by,
                responses,
            );
        }

        let malformed = to_stage(&run!(stages::malformed_brotli_stage()));
        let comparison = match choose_comparison(&bypass, &valid, &malformed) {
            Some(c) => c,
            None => {
                return no_signal(
                    &tested,
                    "controls did not establish distinct classes",
                    None,
                    powered_by,
                    responses,
                )
            }
        };

        let unsupported = to_stage(&run!(stages::unsupported_encoding()));
        if matches(&unsupported, &valid, comparison) {
            return no_signal(
                &tested,
                "unsupported encoding landed in the valid class",
                Some(comparison),
                powered_by,
                responses,
            );
        }
        // Exact comparison requires the complete control response. Stop here if it was truncated.
        if comparison == Comparison::ExactResponse && unsupported.truncated {
            return no_signal(
                &tested,
                "unsupported-encoding control was truncated; cannot confirm rejection",
                Some(comparison),
                powered_by,
                responses,
            );
        }

        // Low-impact mode (`all`): the controls are harmless, but node cannot
        // conclude without the 23 MiB probe, which is a heavy/DoS probe. Stop here
        // rather than fire it implicitly; `all` promised low-impact only.
        if opts.low_impact {
            return no_signal(
                &tested,
                "heavy probe skipped in low-impact mode; run the `node` subcommand to confirm",
                Some(comparison),
                powered_by,
                responses,
            );
        }

        // Controls established two classes: only now is the heavy probe
        // justified. Hold a heavy-probe permit (`--max-heavy`) across it so the
        // fleet never runs more 23 MiB bodies at once than the cap.
        let probe = {
            let _heavy = opts.heavy_permit().await;
            to_stage(&run!(stages::cve_probe()))
        };
        let final_valid = to_stage(&run!(stages::final_valid_empty_brotli()));

        let all = Stages {
            bypass,
            valid,
            malformed,
            unsupported,
            probe,
            final_valid,
        };
        let decision = evaluate(&all);

        DetectorOutcome::new(decision.state, decision.native, &tested)
            .with_status(all.probe.status)
            .with_reason(decision.reason)
            .with_extra(extra(
                decision.comparison,
                &powered_by,
                &tested,
                Value::Object(responses),
            ))
    }
}

async fn run_stage(
    http: &HttpClient,
    target: &Target,
    spec: StageSpec,
) -> Result<ProbeResponse, HttpError> {
    http.send_counted(
        target,
        "POST",
        &spec.headers,
        spec.body,
        spec.expect_continue,
        CONTINUE_WAIT,
    )
    .await
}

fn to_stage(p: &ProbeResponse) -> StageResponse {
    StageResponse {
        status: p.status,
        content_type: p.header("content-type").map(|s| s.to_string()),
        body: p.body.clone(),
        truncated: p.body_truncated,
        error: false,
        bytes_sent: p.bytes_sent,
    }
}

fn resp_json(p: &ProbeResponse, http: &HttpClient) -> Value {
    json!({
        "status_code": p.status,
        "content_type": p.header("content-type").map(|s| http.evidence_header("content-type", s)),
        "response_bytes": p.body.len(),
        "response_truncated": p.body_truncated,
        "bytes_sent": p.bytes_sent,
        "error": Value::Null,
    })
}

fn err_json(e: &HttpError) -> Value {
    json!({
        "status_code": Value::Null,
        "content_type": Value::Null,
        "response_bytes": Value::Null,
        "response_truncated": Value::Null,
        "bytes_sent": Value::Null,
        "error": e.to_string(),
    })
}

fn extra(
    comparison: Option<Comparison>,
    powered_by: &Option<String>,
    tested: &str,
    responses: Value,
) -> Value {
    json!({
        "comparison": comparison.map(|c| c.as_str()),
        "powered_by": powered_by,
        "responses": responses,
        "final_url": tested,
    })
}

fn no_signal(
    tested: &str,
    reason: &str,
    comparison: Option<Comparison>,
    powered_by: Option<String>,
    responses: Map<String, Value>,
) -> DetectorOutcome {
    DetectorOutcome::new(State::Unknown, "NO SIGNAL", tested)
        .with_reason(reason)
        .with_extra(extra(
            comparison,
            &powered_by,
            tested,
            Value::Object(responses),
        ))
}

fn inconclusive(
    tested: &str,
    error: &HttpError,
    powered_by: Option<String>,
    responses: Map<String, Value>,
) -> DetectorOutcome {
    DetectorOutcome::new(State::Unknown, "INCONCLUSIVE", tested)
        .with_reason("a stage request failed before a verdict could be reached")
        .with_error(error.to_string())
        .with_extra(extra(None, &powered_by, tested, Value::Object(responses)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::HttpConfig;

    #[test]
    fn evidence_hides_reflections_and_preserves_the_original_content_type() {
        let http = HttpClient::new(HttpConfig {
            extra_headers: vec![("X-Token".into(), "sample-token".into())],
            ..Default::default()
        });
        let value = "text/plain; account=sample-token";
        let response = ProbeResponse {
            status: 200,
            headers: vec![("Content-Type".into(), value.into())],
            body: vec![],
            body_truncated: false,
            bytes_sent: 0,
            negotiated_alpn: None,
        };
        assert_eq!(resp_json(&response, &http)["content_type"], "<redacted>");
        assert_eq!(response.header("content-type"), Some(value));
    }
}
