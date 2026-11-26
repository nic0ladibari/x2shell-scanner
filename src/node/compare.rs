//! Response-class comparison for the node detector.
//!
//! The node detector does not match signatures or status thresholds. It *learns*
//! the route's two response classes from controls, then checks which class the
//! large probe lands in. All of that reduces to one primitive; "do these two
//! responses count as the same class?"; under one of two comparison modes, and
//! the pure logic lives here so it is table-testable.

/// How two responses are judged to be in the same class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    /// Equal status codes.
    Status,
    /// Equal status + case-insensitive Content-Type + exact body bytes, with no
    /// error and no truncation on either side.
    ExactResponse,
}

impl Comparison {
    pub fn as_str(self) -> &'static str {
        match self {
            Comparison::Status => "status",
            Comparison::ExactResponse => "exact-response",
        }
    }
}

/// A captured stage response, reduced to what the comparison and the output
/// need. `body` is kept for exact-response equality; the JSON reports only its
/// length (`response_bytes`), never the bytes.
#[derive(Debug, Clone, Default)]
pub struct StageResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub truncated: bool,
    /// The request itself failed (connection/transport error).
    pub error: bool,
    /// Body bytes actually written on the wire (meaningful for the probe).
    pub bytes_sent: u64,
}

fn content_type_eq(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        (None, None) => true,
        _ => false,
    }
}

/// Are `a` and `b` in the same response class under `cmp`? An errored response is
/// never in any class (it never settled), so it matches nothing.
pub fn matches(a: &StageResponse, b: &StageResponse, cmp: Comparison) -> bool {
    if a.error || b.error {
        return false;
    }
    match cmp {
        Comparison::Status => a.status == b.status,
        Comparison::ExactResponse => {
            !a.truncated
                && !b.truncated
                && a.status == b.status
                && content_type_eq(&a.content_type, &b.content_type)
                && a.body == b.body
        }
    }
}

/// Pick the comparison that distinguishes the valid class (the `valid` control,
/// stage 2) from the malformed class (`malformed`, stage 3), given the first
/// malformed-but-accepted control (`bypass`, stage 1). Returns `None` when the
/// controls did not establish two distinct classes (stage 3).
pub fn choose_comparison(
    bypass: &StageResponse,
    valid: &StageResponse,
    malformed: &StageResponse,
) -> Option<Comparison> {
    if malformed.error || valid.error || bypass.error {
        return None;
    }
    // Statuses differ from the valid control → the classes are separable by status.
    if malformed.status != valid.status {
        Some(Comparison::Status)
    }
    // Same status: separable only if the valid baseline is byte-stable
    // (bypass == valid exactly) and the malformed response is a *complete*
    // response that genuinely differs. A truncated malformed control also makes
    // `matches(..) == false`, but that is a missing-bytes artifact, not a proven
    // difference; treating it as distinct could reach VULNERABLE without ever
    // establishing two classes, so require the malformed control to be untruncated.
    else if matches(bypass, valid, Comparison::ExactResponse)
        && !malformed.truncated
        && !matches(valid, malformed, Comparison::ExactResponse)
    {
        Some(Comparison::ExactResponse)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, ct: &str, body: &[u8]) -> StageResponse {
        StageResponse {
            status,
            content_type: Some(ct.to_string()),
            body: body.to_vec(),
            truncated: false,
            error: false,
            bytes_sent: 0,
        }
    }

    #[test]
    fn status_comparison_ignores_body() {
        let a = resp(200, "application/json", b"one");
        let b = resp(200, "text/plain", b"two");
        assert!(matches(&a, &b, Comparison::Status));
        assert!(!matches(&a, &b, Comparison::ExactResponse));
    }

    #[test]
    fn exact_response_needs_status_ct_and_body() {
        let a = resp(200, "application/json", b"same");
        let b = resp(200, "APPLICATION/JSON", b"same"); // CT case-insensitive
        assert!(matches(&a, &b, Comparison::ExactResponse));
        let c = resp(200, "application/json", b"different");
        assert!(!matches(&a, &c, Comparison::ExactResponse));
    }

    #[test]
    fn truncation_or_error_never_exact_matches() {
        let a = resp(200, "application/json", b"x");
        let mut t = a.clone();
        t.truncated = true;
        assert!(!matches(&a, &t, Comparison::ExactResponse));
        let mut e = a.clone();
        e.error = true;
        assert!(!matches(&a, &e, Comparison::Status));
        assert!(!matches(&a, &e, Comparison::ExactResponse));
    }

    #[test]
    fn choose_status_when_malformed_status_differs() {
        let bypass = resp(200, "application/json", b"ok");
        let valid = resp(200, "application/json", b"ok");
        let malformed = resp(400, "text/plain", b"bad");
        assert_eq!(
            choose_comparison(&bypass, &valid, &malformed),
            Some(Comparison::Status)
        );
    }

    #[test]
    fn choose_exact_when_status_equal_but_bodies_distinct() {
        // Same status across all three, but valid baseline is byte-stable and the
        // malformed body differs → exact-response can still separate them.
        let bypass = resp(200, "application/json", b"valid-body");
        let valid = resp(200, "application/json", b"valid-body");
        let malformed = resp(200, "application/json", b"error-body");
        assert_eq!(
            choose_comparison(&bypass, &valid, &malformed),
            Some(Comparison::ExactResponse)
        );
    }

    #[test]
    fn no_signal_when_classes_indistinct() {
        // Same status, and malformed is byte-identical to valid → no two classes.
        let bypass = resp(200, "application/json", b"same");
        let valid = resp(200, "application/json", b"same");
        let malformed = resp(200, "application/json", b"same");
        assert_eq!(choose_comparison(&bypass, &valid, &malformed), None);
    }

    #[test]
    fn truncated_malformed_control_does_not_establish_classes() {
        // Same status; the malformed control would differ, but it is truncated;
        // the difference is unproven, so no comparison is established.
        let bypass = resp(200, "application/json", b"valid-body");
        let valid = resp(200, "application/json", b"valid-body");
        let mut malformed = resp(200, "application/json", b"error");
        malformed.truncated = true;
        assert_eq!(choose_comparison(&bypass, &valid, &malformed), None);
    }

    #[test]
    fn no_signal_when_valid_baseline_unstable() {
        // bypass != valid exactly (baseline not byte-stable) and statuses equal →
        // cannot trust exact-response → None.
        let bypass = resp(200, "application/json", b"one");
        let valid = resp(200, "application/json", b"two");
        let malformed = resp(200, "application/json", b"three");
        assert_eq!(choose_comparison(&bypass, &valid, &malformed), None);
    }
}
