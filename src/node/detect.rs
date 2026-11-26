//! Node verdict evaluation.
//!
//! The I/O lives in [`super`]; this is the pure decision over the six captured
//! stage responses, so every branch is table-testable. A request-level
//! failure on any stage is handled by the orchestrator (→ `Inconclusive`) before
//! this runs, so here every stage is a real response.

use crate::core::report::State;

use super::compare::{choose_comparison, matches, Comparison, StageResponse};
use super::stages::PROBE_LEN;

/// Responses from the six stages of a Node scan.
#[derive(Debug, Clone)]
pub struct Stages {
    /// 1. malformed body, no Content-Type (content-type bypass).
    pub bypass: StageResponse,
    /// 2. valid minimal brotli, application/json (the valid control).
    pub valid: StageResponse,
    /// 3. malformed brotli, application/json.
    pub malformed: StageResponse,
    /// 4. unsupported Content-Encoding.
    pub unsupported: StageResponse,
    /// 5. the large probe, Expect: 100-continue.
    pub probe: StageResponse,
    /// 6. the valid control, re-sent.
    pub final_valid: StageResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDecision {
    pub state: State,
    pub native: &'static str,
    pub reason: String,
    /// The comparison the controls established, if any (for the output).
    pub comparison: Option<Comparison>,
}

const VULNERABLE: &str = "VULNERABLE";
const NOT_VULNERABLE: &str = "NOT VULNERABLE";
const NO_SIGNAL: &str = "NO SIGNAL";

/// `Unknown` (the check could not decide); not a demonstrated negative.
fn no_signal(reason: &str, comparison: Option<Comparison>) -> NodeDecision {
    NodeDecision {
        state: State::Unknown,
        native: NO_SIGNAL,
        reason: reason.to_string(),
        comparison,
    }
}

/// Decide the verdict from the six responses (all non-errored; errors become
/// `Inconclusive` in the orchestrator). Returns `VULNERABLE` only when the probe
/// lands in the learned *valid* class and every control check held.
pub fn evaluate(s: &Stages) -> NodeDecision {
    // Stage 2: the valid control's status must equal stage 1's, or the two
    // supposedly-accepted controls are not even in one class.
    if s.valid.status != s.bypass.status {
        return no_signal("valid control status differs from the bypass control", None);
    }

    // Stage 3: establish the comparison that separates valid from malformed.
    let comparison = match choose_comparison(&s.bypass, &s.valid, &s.malformed) {
        Some(c) => c,
        None => return no_signal("controls did not establish distinct classes", None),
    };

    // Stage 4: an unsupported encoding must land in the malformed class. If it
    // matches the valid control, the route accepts anything → no usable signal.
    if matches(&s.unsupported, &s.valid, comparison) {
        return no_signal(
            "unsupported encoding landed in the valid class",
            Some(comparison),
        );
    }
    // Under exact-response, a *truncated* unsupported control also reads as "not
    // valid" purely from missing bytes; that cannot confirm it was rejected, so
    // stay inconclusive instead of letting the evaluation proceed to a positive.
    if comparison == Comparison::ExactResponse && s.unsupported.truncated {
        return no_signal(
            "unsupported-encoding control was truncated; cannot confirm rejection",
            Some(comparison),
        );
    }

    // Stage 5: the probe must have been sent in full, or we cannot conclude.
    if s.probe.bytes_sent < PROBE_LEN {
        return no_signal(
            "probe body was not sent in full before the server responded",
            Some(comparison),
        );
    }

    // Stage 6: the valid class must be stable across the run.
    if !matches(&s.final_valid, &s.valid, comparison) {
        return no_signal("route response class changed mid-run", Some(comparison));
    }

    // Verdict: which class did the probe land in?
    if matches(&s.probe, &s.valid, comparison) {
        NodeDecision {
            state: State::Vulnerable,
            native: VULNERABLE,
            reason: format!(
                "the {PROBE_LEN}-byte probe reached the learned valid route response class"
            ),
            comparison: Some(comparison),
        }
    } else if matches(&s.probe, &s.malformed, comparison) {
        // The probe clearly landed in the malformed class → demonstrated negative.
        NodeDecision {
            state: State::NotVulnerable,
            native: NOT_VULNERABLE,
            reason: "the probe landed in the learned malformed response class".to_string(),
            comparison: Some(comparison),
        }
    } else {
        // Neither class → we cannot claim a negative.
        no_signal("probe matched neither response class", Some(comparison))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(status: u16, ct: &str, body: &[u8]) -> StageResponse {
        StageResponse {
            status,
            content_type: Some(ct.to_string()),
            body: body.to_vec(),
            truncated: false,
            error: false,
            bytes_sent: 0,
        }
    }

    /// A scenario where status separates the classes: valid class = 200, malformed
    /// = 400. Probe sent in full and landing in the valid class → VULNERABLE.
    fn vulnerable_by_status() -> Stages {
        let ok = r(200, "application/json", b"ok");
        let bad = r(400, "text/plain", b"bad");
        let mut probe = r(200, "application/json", b"ok");
        probe.bytes_sent = PROBE_LEN;
        Stages {
            bypass: ok.clone(),
            valid: ok.clone(),
            malformed: bad.clone(),
            unsupported: bad, // malformed class, good
            probe,
            final_valid: ok,
        }
    }

    #[test]
    fn probe_in_valid_class_is_vulnerable() {
        let d = evaluate(&vulnerable_by_status());
        assert_eq!(d.state, State::Vulnerable);
        assert_eq!(d.comparison, Some(Comparison::Status));
    }

    #[test]
    fn probe_in_malformed_class_is_demonstrated_negative() {
        let mut s = vulnerable_by_status();
        s.probe.status = 400; // probe rejected like the malformed control
        let d = evaluate(&s);
        assert_eq!(d.state, State::NotVulnerable);
        assert_eq!(d.native, "NOT VULNERABLE");
    }

    #[test]
    fn probe_in_neither_class_is_unknown() {
        let mut s = vulnerable_by_status();
        s.probe.status = 503; // matches neither valid (200) nor malformed (400)
        assert_eq!(evaluate(&s).state, State::Unknown);
    }

    #[test]
    fn partial_probe_send_is_unknown() {
        let mut s = vulnerable_by_status();
        s.probe.bytes_sent = PROBE_LEN - 1;
        let d = evaluate(&s);
        assert_eq!(d.state, State::Unknown);
        assert!(d.reason.contains("not sent in full"));
    }

    #[test]
    fn valid_status_mismatch_is_unknown() {
        let mut s = vulnerable_by_status();
        s.valid.status = 201; // != bypass 200
        assert_eq!(evaluate(&s).state, State::Unknown);
    }

    #[test]
    fn indistinct_controls_is_unknown() {
        let mut s = vulnerable_by_status();
        s.malformed = s.valid.clone(); // malformed == valid → no two classes
        assert_eq!(evaluate(&s).state, State::Unknown);
    }

    #[test]
    fn unsupported_in_valid_class_is_unknown() {
        let mut s = vulnerable_by_status();
        s.unsupported = s.valid.clone(); // unsupported accepted as valid
        assert_eq!(evaluate(&s).state, State::Unknown);
    }

    #[test]
    fn truncated_unsupported_control_is_unknown_not_vulnerable() {
        // Exact-response scenario. When the unsupported control is complete it
        // lands in the valid class → Unknown. Truncating *only* that response must
        // not flip the verdict to Vulnerable via the missing-bytes artifact.
        let valid = r(200, "application/json", b"VALID");
        let malformed = r(200, "application/json", b"MALFORMED");
        let mut probe = r(200, "application/json", b"VALID");
        probe.bytes_sent = PROBE_LEN;
        let build = |unsupported: StageResponse| Stages {
            bypass: valid.clone(),
            valid: valid.clone(),
            malformed: malformed.clone(),
            unsupported,
            probe: probe.clone(),
            final_valid: valid.clone(),
        };
        let complete = r(200, "application/json", b"VALID");
        assert_eq!(evaluate(&build(complete)).state, State::Unknown);
        let mut truncated = r(200, "application/json", b"VALID");
        truncated.truncated = true;
        assert_eq!(evaluate(&build(truncated)).state, State::Unknown);
    }

    #[test]
    fn route_class_change_is_unknown() {
        let mut s = vulnerable_by_status();
        s.final_valid.status = 500; // valid class no longer stable
        assert_eq!(evaluate(&s).state, State::Unknown);
    }

    #[test]
    fn vulnerable_by_exact_response() {
        // Same status everywhere; classes separated by body bytes.
        let valid = r(200, "application/json", b"VALID");
        let malformed = r(200, "application/json", b"MALFORMED");
        let mut probe = r(200, "application/json", b"VALID");
        probe.bytes_sent = PROBE_LEN;
        let s = Stages {
            bypass: valid.clone(),
            valid: valid.clone(),
            malformed,
            unsupported: r(200, "application/json", b"MALFORMED"),
            probe,
            final_valid: valid,
        };
        let d = evaluate(&s);
        assert_eq!(d.state, State::Vulnerable);
        assert_eq!(d.comparison, Some(Comparison::ExactResponse));
    }
}
