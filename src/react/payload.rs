//! Crafted RSC "action" requests.
//!
//! These are *detection* probes, not exploits: the safe-check elicits the
//! digest error-signature on a vulnerable build, and the active probe carries a
//! benign reflected marker; never an attacker-chosen command. All variants are
//! built here from named constants so there is one place to tune them against
//! the validation lab.

use crate::core::http::HttpRequest;

/// A fixed RSC action id used to route the request into the Server Components
/// action path. Benign placeholder value.
pub const NEXT_ACTION_ID: &str = "0000000000000000000000000000000000000001";
/// Request-id header value sent with the crafted request.
pub const NEXT_ROUTER_STATE: &str = "x2shell-probe";

// NOTE: minimal benign flight-format body; tune the exact bytes against the
// react lab target so the vulnerable build emits the digest signature.
const SAFE_CHECK_BODY: &[u8] = b"[{}]";

/// Build the side-channel safe-check request (the default mode).
pub fn safe_check_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        headers: vec![
            ("Next-Action".into(), NEXT_ACTION_ID.into()),
            ("Next-Router-State-Tree".into(), NEXT_ROUTER_STATE.into()),
            ("Content-Type".into(), "text/plain;charset=UTF-8".into()),
            ("Accept".into(), "text/x-component".into()),
        ],
        body: SAFE_CHECK_BODY.to_vec(),
    }
}

#[cfg(feature = "active-confirm")]
pub use active::{active_request, ACTIVE_MARKER};

#[cfg(feature = "active-confirm")]
mod active {
    use super::{HttpRequest, NEXT_ROUTER_STATE};

    /// Fixed RSC action id used to route the active request.
    const ACTIVE_ACTION_ID: &str = "0000000000000000000000000000000000000002";
    /// Marker used to recognize a reflected redirect.
    pub const ACTIVE_MARKER: &str = "/login?a=11111";
    /// Whitespace bytes used for the (deterministic) `--waf-bypass` junk.
    const WS: &[u8] = b" \t\r\n";

    /// Build the active-confirmation request. `seed` makes the `--waf-bypass`
    /// junk deterministic; `waf_bypass` prepends benign whitespace junk that
    /// never touches the marker string, so the reflected value stays intact.
    pub fn active_request(seed: Option<u64>, waf_bypass: bool) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            headers: vec![
                ("Next-Action".into(), ACTIVE_ACTION_ID.into()),
                ("Next-Router-State-Tree".into(), NEXT_ROUTER_STATE.into()),
                ("Content-Type".into(), "text/plain;charset=UTF-8".into()),
                ("Accept".into(), "text/x-component".into()),
            ],
            body: active_body(seed, waf_bypass),
        }
    }

    /// Flight-format body carrying only the benign marker as a redirect field.
    /// With `waf_bypass`, deterministic leading whitespace junk is prepended.
    fn active_body(seed: Option<u64>, waf_bypass: bool) -> Vec<u8> {
        let core = format!(r#"[{{"redirect":"{ACTIVE_MARKER}"}}]"#);
        if !waf_bypass {
            return core.into_bytes();
        }
        let mut rng = seed.unwrap_or(0);
        let mut out = Vec::with_capacity(core.len() + 16);
        for _ in 0..16 {
            // LCG (Knuth MMIX constants) → deterministic benign whitespace.
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.push(WS[(rng >> 33) as usize % WS.len()]);
        }
        out.extend_from_slice(core.as_bytes());
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn active_request_carries_only_the_benign_marker() {
            let r = active_request(None, false);
            assert_eq!(r.method, "POST");
            let body = String::from_utf8(r.body).unwrap();
            assert!(body.contains(ACTIVE_MARKER));
            // Benign: a redirect URL field, never a shell/command token.
            assert!(!body.contains(';') && !body.contains('`') && !body.contains("$("));
        }

        #[test]
        fn waf_bypass_junk_is_deterministic_and_keeps_the_marker() {
            let a = active_request(Some(42), true).body;
            let b = active_request(Some(42), true).body;
            assert_eq!(a, b, "same seed → same bytes");
            let c = active_request(Some(7), true).body;
            assert_ne!(a, c, "different seed → different junk");
            // The marker survives the junk (junk is leading whitespace only).
            assert!(String::from_utf8_lossy(&a).contains(ACTIVE_MARKER));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_check_request_is_a_benign_post() {
        let r = safe_check_request();
        assert_eq!(r.method, "POST");
        assert!(r
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("next-action")));
        // Body must not carry anything that looks like a command payload.
        assert_eq!(r.body, b"[{}]");
    }
}
