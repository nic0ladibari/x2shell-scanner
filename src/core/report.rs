//! Unified verdict model, the `vulnerable` tri-state mapping, the
//! per-result JSON record and evidence redaction.

use serde::Serialize;

use super::detector::DetectorOutcome;
use super::targets::Target;

/// Header names whose values are replaced with `<redacted>` in persisted
/// evidence.
pub const REDACTED_HEADERS: [&str; 5] = [
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
];

#[derive(Default)]
pub(super) struct HeaderRedaction {
    names: Vec<String>,
    values: Vec<String>,
}

impl std::fmt::Debug for HeaderRedaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeaderRedaction")
    }
}

impl HeaderRedaction {
    pub(super) fn new(headers: &[(String, String)]) -> Self {
        let mut policy = Self::default();
        for (name, value) in headers {
            policy.names.push(name.clone());
            policy.values.push(value.clone());
            // A response can reflect just the credential from a structured header.
            if name.eq_ignore_ascii_case("authorization")
                || name.eq_ignore_ascii_case("proxy-authorization")
            {
                if let Some((_, credential)) = value.split_once(char::is_whitespace) {
                    policy.values.push(credential.trim().to_owned());
                }
            } else if name.eq_ignore_ascii_case("cookie") {
                for cookie in value.split(';') {
                    if let Some((_, value)) = cookie.split_once('=') {
                        policy
                            .values
                            .push(value.trim().trim_matches('"').to_owned());
                    }
                }
            }
        }
        policy.values.retain(|v| !v.is_empty());
        policy
    }

    pub(super) fn allows_body_preview(&self) -> bool {
        self.names.is_empty()
    }

    pub(super) fn headers(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        redact_headers(headers, &self.names, &self.values)
    }

    pub(super) fn header<'a>(&self, name: &str, value: &'a str) -> &'a str {
        redact_header_value(name, value, &self.names, &self.values)
    }

    pub(super) fn text<'a>(&self, value: &'a str) -> &'a str {
        redact_text(value, &self.values)
    }

    /// A redirect may repeat a request secret in its URL or in an error. Apply
    /// value redaction to report evidence before any output format sees it.
    pub(super) fn redact_result(&self, row: &mut ScanResult) {
        if self.values.is_empty() {
            return;
        }
        let secrets = &self.values;
        for value in std::iter::once(&mut row.tested_url)
            .chain(std::iter::once(&mut row.host))
            .chain(row.error.iter_mut())
            .chain(row.reason.iter_mut())
        {
            redact_string(value, secrets);
        }
        redact_json_strings(&mut row.extra, secrets);
    }
}

/// Return a copy of `headers` with sensitive values redacted. Immutable: the
/// input is untouched. A header value is redacted when:
/// - its name is in [`REDACTED_HEADERS`] **or** in `also_names` (the operator's
///   `-H` names, so a command-line secret like `X-Auth-Token: …` is never
///   exposed even though it isn't a well-known name); **or**
/// - its value contains one of `secret_values` (the operator's `-H` *values*): a
///   server can reflect a secret back under a *different* header name, and
///   name-only redaction would let it through, so value matching closes that
///   channel. Empty values never match (they would redact indiscriminately).
pub fn redact_headers(
    headers: &[(String, String)],
    also_names: &[String],
    secret_values: &[String],
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                redact_text(name, secret_values).to_owned(),
                redact_header_value(name, value, also_names, secret_values).to_owned(),
            )
        })
        .collect()
}

fn redact_text<'a>(value: &'a str, secrets: &[String]) -> &'a str {
    if secrets.iter().any(|s| !s.is_empty() && value.contains(s)) {
        "<redacted>"
    } else {
        value
    }
}

fn redact_header_value<'a>(
    name: &str,
    value: &'a str,
    also_names: &[String],
    secrets: &[String],
) -> &'a str {
    if REDACTED_HEADERS
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
        || also_names.iter().any(|n| name.eq_ignore_ascii_case(n))
    {
        "<redacted>"
    } else {
        redact_text(value, secrets)
    }
}

fn redact_string(value: &mut String, secrets: &[String]) {
    let safe = redact_text(value, secrets);
    if safe != value {
        *value = safe.to_owned();
    }
}

fn redact_json_strings(value: &mut serde_json::Value, secrets: &[String]) {
    use serde_json::Value;
    match value {
        Value::String(s) => redact_string(s, secrets),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|v| redact_json_strings(v, secrets)),
        Value::Object(fields) => fields
            .values_mut()
            .for_each(|v| redact_json_strings(v, secrets)),
        _ => {}
    }
}

/// One result row for the JSON/terminal output. Detector-specific keys
/// are flattened in from the outcome's `extra`.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub host: String,
    pub detector: String,
    pub vulnerable: Option<bool>,
    /// Native verdict label, preserved for fidelity.
    pub verdict: String,
    pub status_code: Option<u16>,
    pub reason: Option<String>,
    pub error: Option<String>,
    pub tested_url: String,
    #[serde(flatten, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

impl ScanResult {
    pub fn from_outcome(target: &Target, detector_id: &str, outcome: DetectorOutcome) -> Self {
        // Attribute the result to the host that actually produced the verdict:
        // after a redirect, `tested_url` is the final URL, so the `host` field and
        // the terminal line must follow it, not the pre-redirect target. Fall back
        // to the original target's host if `tested_url` can't be parsed.
        let host = url::Url::parse(&outcome.tested_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| target.url().host_str().unwrap_or("").to_string());
        Self {
            host,
            detector: detector_id.to_string(),
            vulnerable: outcome.state.vulnerable(),
            verdict: outcome.native_verdict,
            status_code: outcome.status_code,
            reason: outcome.reason,
            error: outcome.error,
            tested_url: outcome.tested_url,
            extra: outcome.extra,
        }
    }
}

/// The tri-state asset verdict every detector maps into. It answers
/// a question about the **asset**, so it must never disagree with the native
/// label; each detector keeps its own label string for fidelity (see
/// [`crate::core::detector::DetectorOutcome`]). `Unknown` always carries a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Positive evidence of vulnerability.
    Vulnerable,
    /// Positive evidence of NOT vulnerable; a *demonstrated* negative (version
    /// at/above the fix; a probe clearly in a non-vulnerable class).
    NotVulnerable,
    /// The check could not decide: no baseline/class, a rejection status, a
    /// changed route class, a timeout, a transport/protocol error, HTTP/2-only,
    /// a masking CDN/WAF, or a response compatible with both builds.
    Unknown,
}

impl State {
    /// Tri-state `vulnerable` per: `Some(true)` positive, `Some(false)`
    /// demonstrated negative, `None` undecided.
    pub fn vulnerable(self) -> Option<bool> {
        match self {
            State::Vulnerable => Some(true),
            State::NotVulnerable => Some(false),
            State::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use State::*;

    #[test]
    fn host_follows_the_tested_url_after_a_redirect() {
        // The verdict was produced at a different host than the original target
        // (a followed redirect): the `host` field must name where it actually ran.
        let target = Target::parse("http://orig.example/index.php").unwrap();
        let outcome =
            DetectorOutcome::new(State::Vulnerable, "VULNERABLE", "http://final.example/x");
        let r = ScanResult::from_outcome(&target, "php", outcome);
        assert_eq!(r.host, "final.example");
        // With no usable tested_url, fall back to the original target host.
        let target2 = Target::parse("http://orig.example/").unwrap();
        let outcome2 = DetectorOutcome::new(State::Unknown, "ERROR", "not-a-url");
        assert_eq!(
            ScanResult::from_outcome(&target2, "php", outcome2).host,
            "orig.example"
        );
    }

    #[test]
    fn vulnerable_tristate_mapping() {
        assert_eq!(Vulnerable.vulnerable(), Some(true));
        assert_eq!(NotVulnerable.vulnerable(), Some(false));
        assert_eq!(Unknown.vulnerable(), None);
    }

    #[test]
    fn redaction_replaces_only_sensitive_values() {
        let headers = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("Cookie".to_string(), "sid=abc".to_string()),
            ("X-Powered-By".to_string(), "PHP/8.4.27".to_string()),
        ];
        let redacted = redact_headers(&headers, &[], &[]);
        assert_eq!(redacted[0].1, "<redacted>");
        assert_eq!(redacted[1].1, "<redacted>");
        assert_eq!(redacted[2].1, "PHP/8.4.27"); // non-sensitive survives
        assert_eq!(headers[0].1, "Bearer secret"); // input untouched
    }

    #[test]
    fn redaction_covers_custom_header_names() {
        let headers = vec![("X-Auth-Token".to_string(), "sk-live-xyz".to_string())];
        // not a well-known name, but named via -H → must be redacted
        let redacted = redact_headers(&headers, &["x-auth-token".to_string()], &[]);
        assert_eq!(redacted[0].1, "<redacted>");
        // without the -H name it would leak; proves `also_names` is what protects it
        assert_eq!(redact_headers(&headers, &[], &[])[0].1, "sk-live-xyz");
    }

    #[test]
    fn reflected_credentials_are_removed_from_urls_and_nested_evidence() {
        let policy = HeaderRedaction::new(&[
            ("Cookie".into(), "theme=dark; sid=session-token".into()),
            ("Authorization".into(), "Bearer access-token".into()),
        ]);
        let target = Target::parse("https://example.org").unwrap();
        let outcome = DetectorOutcome::new(
            Unknown,
            "INCONCLUSIVE",
            "https://example.org/?sid=session-token",
        )
        .with_error("response contained access-token")
        .with_extra(
            serde_json::json!({"probes":[{"error":"account=session-token"}], "status":200}),
        );
        let mut row = ScanResult::from_outcome(&target, "php", outcome);
        policy.redact_result(&mut row);
        assert_eq!(row.tested_url, "<redacted>");
        assert_eq!(row.error.as_deref(), Some("<redacted>"));
        assert_eq!(row.extra["probes"][0]["error"], "<redacted>");
        assert_eq!(row.extra["status"], 200);
    }

    #[test]
    fn redaction_covers_a_secret_reflected_under_a_different_name() {
        // The server reflects the operator's secret VALUE back under a header
        // name that is neither well-known nor the -H name. Name matching misses
        // it; value matching must catch it.
        let headers = vec![(
            "X-Reflected-By-Server".to_string(),
            "sk-live-xyz".to_string(),
        )];
        let redacted = redact_headers(&headers, &[], &["sk-live-xyz".to_string()]);
        assert_eq!(redacted[0].1, "<redacted>");
        // An empty secret value must never redact indiscriminately.
        let empties = vec![("X-Empty".to_string(), "".to_string())];
        assert_eq!(redact_headers(&empties, &[], &["".to_string()])[0].1, "");
    }
}
