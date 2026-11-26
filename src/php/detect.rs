//! PHP crash-signal detection and verdict resolution.
//!
//! Two pure stages, both table-testable:
//! 1. [`probe_signal`] reads one `(control, probe)` pair under a SAPI mode and
//!    returns the raw crash signal.
//! 2. [`resolve`] combines that signal with the advertised version class to a
//!    final verdict; this is where the **false-positive guard** lives: a crash
//!    with no disclosed version is indistinguishable from a patched-but-OOM
//!    build, so it resolves to `INCONCLUSIVE`, never `VULNERABLE`.

use crate::core::http::RawResponse;
use crate::core::report::State;

use super::version::VersionClass;

/// Statuses that mean the request was rejected before the multipart parser ran
///: no parse, so no crash signal is possible → stop, inconclusive.
pub const REJECTION_STATUSES: [u16; 9] = [400, 403, 411, 413, 414, 417, 422, 429, 431];

/// Front-end gateway statuses that, under FPM, indicate the worker died
/// mid-request.
pub const FPM_GATEWAY_STATUSES: [u16; 3] = [502, 503, 504];

// NOTE: tight in-band fatal signature; tune the exact bytes against the php
// lab target. The multipart-parser OOM fatal is what a vulnerable build
// prints when display_errors is on.
pub const FATAL_SIGNATURE: &[u8] = b"Allowed memory size of";

/// Which SAPI rules to apply. `Auto` behaves like `Fpm` (the superset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sapi {
    #[default]
    Auto,
    ModPhp,
    Fpm,
}

impl Sapi {
    /// Whether the FPM-only signals (gateway 5xx, empty-200) are in play.
    fn fpm_rules(self) -> bool {
        matches!(self, Sapi::Auto | Sapi::Fpm)
    }
}

/// Raw crash signal from one probe, before version reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhpSignal {
    /// A crash signal fired (reason names which).
    Crash(&'static str),
    /// No crash signal in this probe.
    NoSignal,
    /// The request never reached the parser (rejection status) → stop.
    Inconclusive(&'static str),
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Read one `(control, probe)` pair and return the raw crash signal under `sapi`.
/// `control` is the benign baseline; a differential signal needs the control to
/// have produced a body.
pub fn probe_signal(control: &RawResponse, probe: &RawResponse, sapi: Sapi) -> PhpSignal {
    if REJECTION_STATUSES.contains(&probe.status) {
        return PhpSignal::Inconclusive("rejection status: parser never ran");
    }

    let control_had_body = !control.body.is_empty();

    // In-band PHP fatal (both SAPI modes).
    if contains(&probe.body, FATAL_SIGNATURE) {
        return PhpSignal::Crash("in-band PHP memory-exhaustion fatal");
    }

    // Differential empty 500 (both SAPI modes).
    if probe.status == 500 && probe.body.is_empty() && control_had_body {
        return PhpSignal::Crash("empty HTTP 500 where control produced a body");
    }

    // FPM-only signals: worker died mid-request.
    if sapi.fpm_rules() {
        if FPM_GATEWAY_STATUSES.contains(&probe.status) {
            return PhpSignal::Crash("front-end 502/503/504 (FPM worker death)");
        }
        if probe.status == 200 && probe.body.is_empty() && control_had_body {
            return PhpSignal::Crash("empty HTTP 200 where control produced a body (FPM)");
        }
    }

    PhpSignal::NoSignal
}

/// Final verdict for one host, resolving the crash signal against the advertised
/// version class (`None` = version not disclosed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpDecision {
    pub state: State,
    pub native: &'static str,
    pub reason: String,
}

const VULNERABLE: &str = "VULNERABLE";
const FIXED: &str = "FIXED";
const NO_SIGNAL: &str = "NO SIGNAL";
const INCONCLUSIVE: &str = "INCONCLUSIVE";

pub fn resolve(signal: &PhpSignal, version: Option<VersionClass>) -> PhpDecision {
    use VersionClass::*;
    match signal {
        PhpSignal::Inconclusive(r) => decision(State::Unknown, INCONCLUSIVE, r),

        // A crash fired. The version decides whether we can trust it.
        PhpSignal::Crash(r) => match version {
            Some(Vulnerable) => decision(State::Vulnerable, VULNERABLE, r),
            // Patched build that OOMs on the probe → the documented false positive.
            Some(Fixed) => decision(
                State::NotVulnerable,
                FIXED,
                "crash signal but version is patched: patched-OOM false positive",
            ),
            Some(Undecided) => decision(
                State::Unknown,
                INCONCLUSIVE,
                "crash signal but version newer than known fixed branch",
            ),
            // The core guard: no version → cannot tell vulnerable from patched-OOM.
            None => decision(
                State::Unknown,
                INCONCLUSIVE,
                "crash signal but version undisclosed: patched-OOM indistinguishable",
            ),
        },

        // No crash: fall back to the advertised version.
        PhpSignal::NoSignal => match version {
            Some(Vulnerable) => decision(
                State::Vulnerable,
                VULNERABLE,
                "no crash signal; advertised version is pre-fix",
            ),
            Some(Fixed) => decision(
                State::NotVulnerable,
                FIXED,
                "no crash signal; version is patched",
            ),
            Some(Undecided) => decision(
                State::Unknown,
                INCONCLUSIVE,
                "no crash signal; version newer than known fixed branch",
            ),
            None => decision(
                State::Unknown,
                NO_SIGNAL,
                "no crash signal; version undisclosed",
            ),
        },
    }
}

fn decision(state: State, native: &'static str, reason: &str) -> PhpDecision {
    PhpDecision {
        state,
        native,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &[u8]) -> RawResponse {
        RawResponse {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
            body_truncated: false,
            headers_truncated: false,
            negotiated_alpn: None,
        }
    }

    fn control() -> RawResponse {
        resp(200, b"baseline body")
    }

    #[test]
    fn empty_500_is_crash_when_control_had_body() {
        let s = probe_signal(&control(), &resp(500, b""), Sapi::ModPhp);
        assert!(matches!(s, PhpSignal::Crash(_)));
    }

    #[test]
    fn empty_500_is_no_signal_when_control_was_also_empty() {
        let empty_control = resp(200, b"");
        let s = probe_signal(&empty_control, &resp(500, b""), Sapi::ModPhp);
        assert_eq!(s, PhpSignal::NoSignal);
    }

    #[test]
    fn nonempty_500_is_no_signal() {
        let s = probe_signal(
            &control(),
            &resp(500, b"Fatal: something else"),
            Sapi::ModPhp,
        );
        assert_eq!(s, PhpSignal::NoSignal);
    }

    #[test]
    fn in_band_fatal_is_crash_both_sapi() {
        let body = b"PHP Fatal error: Allowed memory size of 2097152 bytes exhausted";
        assert!(matches!(
            probe_signal(&control(), &resp(500, body), Sapi::ModPhp),
            PhpSignal::Crash(_)
        ));
        assert!(matches!(
            probe_signal(&control(), &resp(200, body), Sapi::Fpm),
            PhpSignal::Crash(_)
        ));
    }

    #[test]
    fn gateway_5xx_only_counts_under_fpm() {
        for status in FPM_GATEWAY_STATUSES {
            assert!(
                matches!(
                    probe_signal(&control(), &resp(status, b""), Sapi::Fpm),
                    PhpSignal::Crash(_)
                ),
                "status {status} should signal under fpm"
            );
            assert_eq!(
                probe_signal(&control(), &resp(status, b""), Sapi::ModPhp),
                PhpSignal::NoSignal,
                "status {status} must not signal under mod_php"
            );
        }
    }

    #[test]
    fn empty_200_signals_only_under_fpm() {
        assert!(matches!(
            probe_signal(&control(), &resp(200, b""), Sapi::Fpm),
            PhpSignal::Crash(_)
        ));
        assert_eq!(
            probe_signal(&control(), &resp(200, b""), Sapi::ModPhp),
            PhpSignal::NoSignal
        );
    }

    #[test]
    fn every_rejection_status_is_inconclusive() {
        for status in REJECTION_STATUSES {
            assert!(
                matches!(
                    probe_signal(&control(), &resp(status, b""), Sapi::Auto),
                    PhpSignal::Inconclusive(_)
                ),
                "status {status} must be inconclusive"
            );
        }
    }

    // ---- resolve: the false-positive guard ----

    #[test]
    fn crash_without_version_is_inconclusive() {
        // The single most important row: patched-OOM, no version header.
        let d = resolve(&PhpSignal::Crash("x"), None);
        assert_eq!(d.state, State::Unknown);
    }

    #[test]
    fn crash_with_prefix_version_is_vulnerable() {
        let d = resolve(&PhpSignal::Crash("x"), Some(VersionClass::Vulnerable));
        assert_eq!(d.state, State::Vulnerable);
    }

    #[test]
    fn crash_with_patched_version_is_fixed_not_vulnerable() {
        let d = resolve(&PhpSignal::Crash("x"), Some(VersionClass::Fixed));
        assert_eq!(d.state, State::NotVulnerable);
        assert_eq!(d.native, "FIXED");
    }

    #[test]
    fn no_signal_falls_back_to_version() {
        assert_eq!(
            resolve(&PhpSignal::NoSignal, Some(VersionClass::Vulnerable)).state,
            State::Vulnerable
        );
        assert_eq!(
            resolve(&PhpSignal::NoSignal, Some(VersionClass::Fixed)).state,
            State::NotVulnerable
        );
        assert_eq!(resolve(&PhpSignal::NoSignal, None).state, State::Unknown);
    }

    #[test]
    fn rejection_stays_inconclusive_regardless_of_version() {
        let d = resolve(
            &PhpSignal::Inconclusive("rej"),
            Some(VersionClass::Vulnerable),
        );
        assert_eq!(d.state, State::Unknown);
    }
}
