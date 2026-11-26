//! React Server Components detection logic.
//!
//! Primary CVE is **CVE-2025-55182** (the React RSC flaw). Next.js findings use
//! the same id; **CVE-2025-66478** is a rejected duplicate kept only as a
//! historical reference, never emitted as a distinct finding.
//!
//! The verdict decisions are pure functions over a [`RawResponse`] so they are
//! table-testable without a network.

use crate::core::http::RawResponse;
use crate::core::report::State;

/// Primary CVE id for every react finding.
pub const PRIMARY_CVE: &str = "CVE-2025-55182";
/// Historical alias (NVD-rejected duplicate); reference only.
pub const ALIAS_CVE: &str = "CVE-2025-66478";

/// Safe-check marker: a vulnerable RSC error response carries this digest prefix.
pub const SAFE_CHECK_MARKER: &[u8] = br#"E{"digest""#;
/// Active/Vercel-bypass marker: the benign reflected value in `X-Action-Redirect`.
/// This is a marker, never a real command payload.
pub const ACTIVE_REDIRECT_NEEDLE: &str = "/login?a=11111";

/// Outcome of a react signature evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactDecision {
    pub state: State,
    pub native: &'static str,
    pub reason: &'static str,
}

const VULNERABLE: &str = "VULNERABLE";
const NOT_VULNERABLE: &str = "NOT VULNERABLE";
const INCONCLUSIVE: &str = "INCONCLUSIVE";

fn vulnerable(reason: &'static str) -> ReactDecision {
    ReactDecision {
        state: State::Vulnerable,
        native: VULNERABLE,
        reason,
    }
}

fn not_vulnerable(reason: &'static str) -> ReactDecision {
    ReactDecision {
        state: State::NotVulnerable,
        native: NOT_VULNERABLE,
        reason,
    }
}

/// `Unknown`: the check could not confirm; never a demonstrated negative.
pub fn unknown(reason: &'static str) -> ReactDecision {
    ReactDecision {
        state: State::Unknown,
        native: INCONCLUSIVE,
        reason,
    }
}

/// Safe-check (side-channel) verdict. `Some(false)` is emitted **only** for a
/// complete, non-excluded response that definitively lacks the signature;
/// anything that blocks confirmation (CDN mask, truncation, `401/403/429`, other
/// `5xx`) is `None`, never a negative.
pub fn evaluate_safe_check(resp: &RawResponse) -> ReactDecision {
    if missing_representation(resp) {
        return unknown("safe-check: empty or partial representation");
    }
    if let Some(reason) = cdn_exclusion(resp) {
        return unknown(reason);
    }
    // A truncated error page can contain the marker in quoted log text.
    if resp.body_truncated {
        return unknown("safe-check: response body truncated; cannot confirm");
    }
    // A definitive verdict needs proof the response actually came from an RSC /
    // Next.js component: a generic HTML page can neither confirm the flaw (it may
    // merely cite the marker in log/error text) nor disprove it (it isn't even
    // the target app), so without that evidence the verdict is INCONCLUSIVE.
    let is_rsc = looks_like_rsc(resp);
    if resp.status == 500 && is_rsc && contains(&resp.body, SAFE_CHECK_MARKER) {
        return vulnerable("safe-check: RSC 500 response with the digest marker");
    }
    if matches!(resp.status, 401 | 403 | 429) {
        return unknown("safe-check: auth/rate-limit status blocks confirmation");
    }
    if resp.status >= 500 {
        return unknown("safe-check: non-signature 5xx (or non-RSC 500) blocks confirmation");
    }
    // A demonstrated negative needs a complete 2xx *and* RSC evidence: a 302/404/
    // 405 never reached the component, and a generic 200 page is not the target
    // app; both are inconclusive, never "not vulnerable".
    if (200..300).contains(&resp.status) {
        return if is_rsc {
            not_vulnerable("safe-check: complete RSC 2xx without the digest marker")
        } else {
            unknown("safe-check: 2xx but not identifiably an RSC/Next.js app; cannot confirm")
        };
    }
    unknown("safe-check: non-2xx status did not reach the component; cannot confirm")
}

/// These responses cannot establish a component verdict, even when their
/// media type is Flight and the transport delivered all the advertised bytes.
fn missing_representation(resp: &RawResponse) -> bool {
    matches!(resp.status, 204..=206)
        || resp.header("content-range").is_some()
        || ((200..300).contains(&resp.status) && resp.body.trim_ascii().is_empty())
}

/// Framework-wide headers can also accompany static HTML. Only a single,
/// unambiguous Flight media type identifies the representation being evaluated.
fn looks_like_rsc(resp: &RawResponse) -> bool {
    let mut types = resp
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    let Some((_, value)) = types.next() else {
        return false;
    };
    !resp.headers_truncated
        && types.next().is_none()
        && !resp
            .body
            .strip_prefix(b"\xef\xbb\xbf")
            .unwrap_or(&resp.body)
            .trim_ascii_start()
            .starts_with(b"<")
        && value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/x-component"))
}

/// Active/Vercel-bypass verdict: vulnerable when `X-Action-Redirect` reflects
/// the benign marker. Same negative-vs-unknown discipline as the safe-check.
pub fn evaluate_active(resp: &RawResponse) -> ReactDecision {
    if missing_representation(resp) {
        return unknown("active: empty or partial representation");
    }
    // A CDN can mask the origin response. Check for it before interpreting the status or marker.
    if let Some(reason) = cdn_exclusion(resp) {
        return unknown(reason);
    }
    if let Some(v) = resp.header("x-action-redirect") {
        if v.contains(ACTIVE_REDIRECT_NEEDLE)
            && (matches!(resp.status, 301 | 302 | 303 | 307 | 308) || looks_like_rsc(resp))
        {
            return vulnerable("active: X-Action-Redirect reflected the marker");
        }
    }
    if resp.body_truncated {
        return unknown("active: response body truncated; cannot confirm");
    }
    // A demonstrated negative needs a complete 2xx *and* RSC evidence: a 302/404/
    // 405/auth/5xx never reached the component, and a generic 200 page is not the
    // target app; both are inconclusive, not a negative.
    if (200..300).contains(&resp.status) {
        return if looks_like_rsc(resp) {
            not_vulnerable("active: complete RSC 2xx without the reflected marker")
        } else {
            unknown("active: 2xx but not identifiably an RSC/Next.js app; cannot confirm")
        };
    }
    unknown("active: non-2xx status did not reach the component; cannot confirm")
}

/// Return an exclusion reason if the response bears a Netlify/Vercel signature
/// that would otherwise look like a hit.
fn cdn_exclusion(resp: &RawResponse) -> Option<&'static str> {
    if resp.header("netlify-vary").is_some() {
        return Some("excluded: Netlify-Vary header present");
    }
    if let Some(server) = resp.header("server") {
        if server.eq_ignore_ascii_case("netlify") {
            return Some("excluded: Server: netlify");
        }
        if server.eq_ignore_ascii_case("vercel") {
            return Some("excluded: Server: vercel");
        }
    }
    None
}

/// Case-sensitive substring search over bytes (the marker is literal).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: &[(&str, &str)], body: &[u8]) -> RawResponse {
        RawResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
            body_truncated: false,
            headers_truncated: false,
            negotiated_alpn: None,
        }
    }

    /// An RSC flight content-type; the evidence a definitive verdict requires.
    const RSC: (&str, &str) = ("Content-Type", "text/x-component");

    #[test]
    fn safe_check_hit_on_500_with_marker() {
        let r = resp(500, &[RSC], br#"1:E{"digest":"abc"}"#);
        assert_eq!(evaluate_safe_check(&r).state, State::Vulnerable);
    }

    #[test]
    fn safe_check_generic_500_with_marker_is_inconclusive() {
        // A non-RSC 500 (plain HTML) that merely cites the marker in error/log
        // text must NOT be VULNERABLE; no proof it came from an RSC component.
        let r = resp(
            500,
            &[("Content-Type", "text/html")],
            br#"log: E{"digest":"x"}"#,
        );
        assert_eq!(evaluate_safe_check(&r).state, State::Unknown);
    }

    #[test]
    fn safe_check_generic_200_page_is_inconclusive_not_negative() {
        // A static 200 HTML page is not identifiably the target app → cannot be a
        // demonstrated negative.
        let r = resp(200, &[("Content-Type", "text/html")], b"<html>ok</html>");
        assert_eq!(evaluate_safe_check(&r).state, State::Unknown);
    }

    #[test]
    fn safe_check_500_without_marker_is_unknown() {
        // A 500 is a non-signature 5xx → cannot confirm → Unknown, not a negative.
        let r = resp(500, &[], b"Internal Server Error");
        assert_eq!(evaluate_safe_check(&r).state, State::Unknown);
    }

    #[test]
    fn safe_check_clean_rsc_response_is_demonstrated_negative() {
        let r = resp(200, &[RSC], b"0:null");
        assert_eq!(evaluate_safe_check(&r).state, State::NotVulnerable);
    }

    #[test]
    fn safe_check_marker_but_not_500_is_not_vulnerable() {
        // RSC 200 whose body happens to contain the marker but status isn't 500 →
        // negative (the flaw is a 500 signal).
        let r = resp(200, &[RSC], br#"E{"digest"}"#);
        assert_eq!(evaluate_safe_check(&r).state, State::NotVulnerable);
    }

    #[test]
    fn framework_headers_do_not_identify_a_component_response() {
        for header in [
            ("X-Powered-By", "Next.js"),
            ("X-Powered-By", "Nextcloud"),
            ("Next-Page", "2"),
        ] {
            for status in [200, 500] {
                let r = resp(
                    status,
                    &[("Content-Type", "text/html"), header],
                    br#"<html>log: E{"digest":"x"}</html>"#,
                );
                assert_eq!(evaluate_safe_check(&r).state, State::Unknown);
                assert_eq!(evaluate_active(&r).state, State::Unknown);
            }
        }
        let html = resp(
            200,
            &[RSC, ("X-Action-Redirect", ACTIVE_REDIRECT_NEEDLE)],
            b"  <html>static</html>",
        );
        assert_eq!(evaluate_safe_check(&html).state, State::Unknown);
        assert_eq!(evaluate_active(&html).state, State::Unknown);
        for value in ["text/x-component-extra", "text/html; note=text/x-component"] {
            assert!(!looks_like_rsc(&resp(200, &[("Content-Type", value)], b"")));
        }
        assert!(!looks_like_rsc(&resp(
            200,
            &[RSC, ("Content-Type", "text/html")],
            b""
        )));
        assert!(looks_like_rsc(&resp(
            200,
            &[("Content-Type", "Text/X-Component; charset=utf-8")],
            b""
        )));
    }

    #[test]
    fn safe_check_403_and_429_block_confirmation() {
        for status in [401, 403, 429] {
            let r = resp(status, &[], b"nope");
            assert_eq!(
                evaluate_safe_check(&r).state,
                State::Unknown,
                "status {status} must be Unknown, never a negative"
            );
        }
    }

    #[test]
    fn safe_check_truncated_body_is_unknown() {
        let mut r = resp(200, &[], b"partial");
        r.body_truncated = true;
        assert_eq!(evaluate_safe_check(&r).state, State::Unknown);
    }

    #[test]
    fn safe_check_truncated_500_with_marker_is_inconclusive() {
        // A truncated 500 body is inconclusive even when the marker appears in the
        // retained bytes: it may be a citation in a cut-off HTML/log page, not a
        // genuine RSC error. Truncation → None, never a guessed VULNERABLE.
        let mut r = resp(
            500,
            &[("Content-Type", "text/html")],
            br#"<html><body>upstream error: E{"digest":"x"} ... (page cut off"#,
        );
        r.body_truncated = true;
        assert_eq!(evaluate_safe_check(&r).state, State::Unknown);
    }

    #[test]
    fn netlify_vary_excludes_as_unknown_even_with_marker() {
        let r = resp(500, &[("Netlify-Vary", "query")], br#"E{"digest"}"#);
        let d = evaluate_safe_check(&r);
        assert_eq!(d.state, State::Unknown);
        assert!(d.reason.contains("Netlify"));
    }

    #[test]
    fn server_vercel_and_netlify_exclude_as_unknown() {
        for s in ["vercel", "Netlify", "VERCEL"] {
            let r = resp(500, &[("Server", s)], br#"E{"digest"}"#);
            assert_eq!(
                evaluate_safe_check(&r).state,
                State::Unknown,
                "Server: {s} must be excluded as Unknown"
            );
        }
    }

    #[test]
    fn active_hit_on_redirect_marker() {
        let r = resp(
            303,
            &[("X-Action-Redirect", "https://x/login?a=11111&b=2")],
            b"",
        );
        assert_eq!(evaluate_active(&r).state, State::Vulnerable);
    }

    #[test]
    fn absent_and_partial_representations_are_inconclusive() {
        for (status, body) in [
            (200, b"  ".as_slice()),
            (204, b""),
            (205, b""),
            (206, b"0:"),
        ] {
            let r = resp(status, &[RSC], body);
            assert_eq!(evaluate_safe_check(&r).state, State::Unknown);
            assert_eq!(evaluate_active(&r).state, State::Unknown);
        }
        let r = resp(200, &[RSC, ("Content-Range", "bytes 0-1/40")], b"0:");
        assert_eq!(evaluate_safe_check(&r).state, State::Unknown);
        assert_eq!(evaluate_active(&r).state, State::Unknown);
    }

    #[test]
    fn active_miss_on_complete_rsc_2xx_is_negative() {
        // A complete RSC 2xx that reached the component without reflecting the
        // marker is a demonstrated negative.
        let r = resp(200, &[RSC, ("X-Action-Redirect", "/login?a=0")], b"0:null");
        assert_eq!(evaluate_active(&r).state, State::NotVulnerable);
    }

    #[test]
    fn active_generic_200_without_rsc_evidence_is_inconclusive() {
        let r = resp(200, &[("Content-Type", "text/html")], b"<html>ok</html>");
        assert_eq!(evaluate_active(&r).state, State::Unknown);
    }

    #[test]
    fn active_cdn_masked_is_inconclusive_in_both_directions() {
        let neg = resp(200, &[RSC, ("Server", "vercel")], b"0:null");
        assert_eq!(evaluate_active(&neg).state, State::Unknown);
        let pos = resp(
            302,
            &[
                ("Server", "Vercel"),
                ("X-Action-Redirect", ACTIVE_REDIRECT_NEEDLE),
            ],
            b"",
        );
        assert_eq!(evaluate_active(&pos).state, State::Unknown);
        // Netlify-Vary masks it the same way.
        let nl = resp(200, &[RSC, ("Netlify-Vary", "query")], b"0:null");
        assert_eq!(evaluate_active(&nl).state, State::Unknown);
    }

    #[test]
    fn active_non_2xx_without_marker_is_inconclusive() {
        // 302/404/405 (and auth/5xx) never reached the component → Unknown, never
        // a demonstrated negative, even though the marker is absent.
        for status in [302, 303, 404, 405, 401, 403, 429, 500] {
            let r = resp(status, &[], b"");
            assert_eq!(
                evaluate_active(&r).state,
                State::Unknown,
                "active status {status} must be Unknown, never a negative"
            );
        }
    }

    #[test]
    fn contains_edges() {
        assert!(contains(b"abc", b"abc"));
        assert!(contains(b"xEabc", b"E"));
        assert!(!contains(b"ab", b"abc"));
        assert!(contains(b"anything", b""));
    }

    #[test]
    fn safe_check_redirect_and_reject_statuses_are_inconclusive() {
        // A redirect (302 → login), a not-found path (404), or a rejected method
        // (405) never reached the component → Unknown, never a demonstrated negative.
        for status in [301, 302, 303, 307, 308, 400, 404, 405] {
            let r = resp(status, &[], b"irrelevant");
            assert_eq!(
                evaluate_safe_check(&r).state,
                State::Unknown,
                "status {status} did not reach the component; must be Unknown"
            );
        }
    }
}
