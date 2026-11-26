//! PHP version parsing and the fixed-patch table.
//!
//! Single source of truth for the per-branch fixed patch. Update only from
//! advisories. Verified against the PHP security release of 2026-10-21
//! (PHP2Shell, CVE-2026-109618/109619): 8.2.35, 8.3.36, 8.4.27, 8.5.12.

/// Fixed patch level per `(major, minor)` branch.
pub const FIXED_PATCH: &[((u8, u8), u16)] =
    &[((8, 2), 35), ((8, 3), 36), ((8, 4), 27), ((8, 5), 12)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhpVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u16,
}

/// What the advertised version tells us, independent of any crash probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionClass {
    /// Below the branch's fixed patch, or below 8.2 (never fixed).
    Vulnerable,
    /// At or above the branch's fixed patch.
    Fixed,
    /// Above the newest branch we have data for (> 8.5): cannot decide.
    Undecided,
}

/// Parse a `PHP/x.y.z` token out of an `X-Powered-By` value. Tolerant of
/// surrounding text; returns `None` if no `PHP/<major>.<minor>.<patch>` is found.
pub fn parse_powered_by(powered_by: &str) -> Option<PhpVersion> {
    let idx = powered_by.find("PHP/")?;
    let rest = &powered_by[idx + 4..];
    // The version token runs until the first char that is not a digit or dot;
    // slice it in place instead of collecting into a new String.
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    // A letter or `-`/`+` directly after the numeric version marks a pre-release
    // or build (`8.4.27RC1`, `8.5.0-dev`, `8.4.27+build`): that build is NOT the
    // final release and may lack the fix, so it must never be compared against
    // the fixed-patch table → unknown. A clean delimiter (space, `(`, …) is fine.
    if let Some(&next) = rest.as_bytes().get(end) {
        if next.is_ascii_alphabetic() || next == b'-' || next == b'+' {
            return None;
        }
    }
    let mut parts = rest[..end].splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    // A missing patch is *unknown*, not zero: a partial `PHP/8.4` must not be
    // compared against the fixed table, so refuse to parse it.
    let patch = parts.next()?.parse().ok()?;
    Some(PhpVersion {
        major,
        minor,
        patch,
    })
}

/// Classify a parsed version against the fixed-patch table.
pub fn classify(v: &PhpVersion) -> VersionClass {
    // Below 8.2 is never fixed.
    if (v.major, v.minor) < (8, 2) {
        return VersionClass::Vulnerable;
    }
    if let Some((_, fixed_patch)) = FIXED_PATCH
        .iter()
        .find(|((maj, min), _)| (*maj, *min) == (v.major, v.minor))
    {
        return if v.patch >= *fixed_patch {
            VersionClass::Fixed
        } else {
            VersionClass::Vulnerable
        };
    }
    // (major,minor) not in the table and >= 8.2 means it is above 8.5.
    VersionClass::Undecided
}

/// Convenience: parse + classify in one step.
pub fn classify_powered_by(powered_by: &str) -> Option<VersionClass> {
    parse_powered_by(powered_by).as_ref().map(classify)
}

#[cfg(test)]
mod tests {
    use super::VersionClass::*;
    use super::*;

    fn v(major: u8, minor: u8, patch: u16) -> PhpVersion {
        PhpVersion {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn parses_from_powered_by() {
        assert_eq!(parse_powered_by("PHP/8.4.27"), Some(v(8, 4, 27)));
        assert_eq!(
            parse_powered_by("Apache/2.4 PHP/8.3.36 (Debian)"),
            Some(v(8, 3, 36))
        );
        assert_eq!(parse_powered_by("nginx"), None);
        // Partial version (no patch) is unknown, never assumed `.0`.
        assert_eq!(parse_powered_by("PHP/8.5"), None);
        assert_eq!(parse_powered_by("PHP/8.4"), None);
        assert_eq!(classify_powered_by("PHP/8.4"), None);
        // A clean delimiter after the version is fine.
        assert_eq!(parse_powered_by("PHP/8.4.27 (Debian)"), Some(v(8, 4, 27)));
    }

    #[test]
    fn extra_numeric_components_are_unknown() {
        for header in ["PHP/8.4.27.1", "PHP/8.4.26.1 (vendor)", "PHP/8.4.27."] {
            assert_eq!(classify_powered_by(header), None, "{header}");
        }
    }

    #[test]
    fn prerelease_or_build_suffix_is_unknown_not_the_final_release() {
        // An RC/alpha/beta/dev build of the fixed patch is NOT the fixed release
        // and may still be vulnerable → must not classify as Fixed.
        assert_eq!(parse_powered_by("PHP/8.4.27RC1"), None);
        assert_eq!(classify_powered_by("PHP/8.4.27RC1"), None);
        assert_eq!(parse_powered_by("PHP/8.5.0alpha1"), None);
        assert_eq!(parse_powered_by("PHP/8.4.27-dev"), None);
        assert_eq!(parse_powered_by("PHP/8.4.27+build5"), None);
    }

    #[test]
    fn patch_boundaries_per_branch() {
        // exact fix boundary for each branch
        assert_eq!(classify(&v(8, 4, 26)), Vulnerable);
        assert_eq!(classify(&v(8, 4, 27)), Fixed);
        assert_eq!(classify(&v(8, 3, 35)), Vulnerable);
        assert_eq!(classify(&v(8, 3, 36)), Fixed);
        assert_eq!(classify(&v(8, 2, 34)), Vulnerable);
        assert_eq!(classify(&v(8, 2, 35)), Fixed);
        assert_eq!(classify(&v(8, 5, 11)), Vulnerable);
        assert_eq!(classify(&v(8, 5, 12)), Fixed);
    }

    #[test]
    fn below_8_2_never_fixed() {
        assert_eq!(classify(&v(8, 1, 99)), Vulnerable);
        assert_eq!(classify(&v(7, 4, 33)), Vulnerable);
    }

    #[test]
    fn above_8_5_is_undecided() {
        assert_eq!(classify(&v(8, 6, 0)), Undecided);
        assert_eq!(classify(&v(9, 0, 0)), Undecided);
    }

    #[test]
    fn classify_powered_by_end_to_end() {
        assert_eq!(classify_powered_by("PHP/8.4.27"), Some(Fixed));
        assert_eq!(classify_powered_by("PHP/8.4.26"), Some(Vulnerable));
        assert_eq!(classify_powered_by("no version here"), None);
    }
}
