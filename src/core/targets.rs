//! Target parsing, normalization and dedup.
//!
//! Responsibilities kept here (pure, no I/O, so it is table-testable):
//! - add the default `https://` scheme when none is given;
//! - accept only `http`/`https`;
//! - reject URLs carrying credentials (`user:pass@`);
//! - IDNA-encode hostnames and bracket IPv6 literals (delegated to the `url` crate);
//! - produce a stable dedup key `(scheme, lowercased host, path, query)`.

use thiserror::Error;
use url::Url;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetError {
    #[error("empty target")]
    Empty,
    #[error("invalid URL: {0}")]
    Parse(String),
    #[error("unsupported scheme `{0}` (only http/https)")]
    Scheme(String),
    #[error("URL must not contain credentials (user:pass@)")]
    Credentials,
    #[error("URL has no host")]
    NoHost,
}

/// A parsed, normalized scan target. Construction is the only way to get one,
/// so every `Target` in the system is already validated. Immutable by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    url: Url,
}

impl Target {
    /// Parse one raw line (a bare host, or a full URL). A missing scheme
    /// defaults to `https://`. Returns a validated, normalized target.
    pub fn parse(raw: &str) -> Result<Self, TargetError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(TargetError::Empty);
        }

        // Add the default scheme only when the input carries none. Any explicit
        // `scheme://` is kept as-is so a non-http scheme reaches the check below
        // and is rejected, rather than being mangled into a host.
        let with_scheme = if has_any_scheme(trimmed) {
            trimmed.to_string()
        } else {
            format!("https://{trimmed}")
        };

        let mut url = Url::parse(&with_scheme).map_err(|e| TargetError::Parse(e.to_string()))?;

        match url.scheme() {
            "http" | "https" => {}
            other => return Err(TargetError::Scheme(other.to_string())),
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(TargetError::Credentials);
        }

        if url.host_str().is_none() {
            return Err(TargetError::NoHost);
        }

        // HTTP requests never carry URI fragments. Drop them before reporting or deduplication.
        url.set_fragment(None);
        Ok(Target { url })
    }

    /// Return a copy of this target with its path replaced (used for
    /// `--path` / `default_paths()` expansion). Immutable: the original
    /// is untouched.
    pub fn with_path(&self, path: &str) -> Self {
        let next = {
            let mut u = self.url.clone();
            u.set_path(path);
            u
        };
        Target { url: next }
    }

    /// Stable dedup key: `(scheme, lowercased host, effective port, path,
    /// query)`. Using the *effective* port (implicit 443/80 resolved) folds
    /// `https://h` and `https://h:443` together but keeps `:443` and `:8443`
    /// distinct. The `url` crate already lowercases the host for http/https.
    pub fn dedup_key(&self) -> String {
        let port = self
            .url
            .port_or_known_default()
            .map(|p| p.to_string())
            .unwrap_or_default();
        format!(
            "{}://{}:{}{}{}",
            self.url.scheme(),
            self.url.host_str().unwrap_or(""),
            port,
            self.url.path(),
            self.url
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default(),
        )
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    pub fn url(&self) -> &Url {
        &self.url
    }
}

/// Compare redirect origins by scheme, canonical host and effective port.
pub(crate) fn origin(url: &Url) -> Option<(&str, &str, u16)> {
    Some((url.scheme(), url.host_str()?, url.port_or_known_default()?))
}

/// True if `s` begins with an explicit `scheme://` (RFC-3986 scheme chars),
/// regardless of which scheme. Used to decide whether to prepend the default.
fn has_any_scheme(s: &str) -> bool {
    match s.find("://") {
        None => false,
        Some(idx) => {
            let scheme = &s[..idx];
            !scheme.is_empty()
                && scheme
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
    }
}

/// True if the raw target carries an explicit path (a `/…` after the authority).
/// A bare host (`example.com`, `example.com:8443`, `example.com?q`) has none; a
/// trailing slash (`example.com/`) counts as an explicit path and is preserved.
fn raw_has_explicit_path(raw: &str) -> bool {
    let trimmed = raw.trim();
    // Strip only a *leading* `scheme://`; do not let a `://` inside a query value
    // (e.g. `host/api?next=https://x`) be mistaken for the scheme separator and
    // swallow the real path.
    let after_authority = if has_any_scheme(trimmed) {
        trimmed.split_once("://").map(|(_, r)| r).unwrap_or(trimmed)
    } else {
        trimmed
    };
    match after_authority.find(['/', '?', '#']) {
        Some(i) => after_authority.as_bytes()[i] == b'/',
        None => false,
    }
}

/// Parse a batch of raw target lines, apply the detector's `default_path` to any
/// target with no explicit path, then deduplicate; in that order, so a bare host
/// and the same host spelled with the default path collapse to one scan. An
/// explicit path (including a lone `/`) is preserved. Preserves first-seen order.
///
/// Returns the valid targets plus the per-line errors, each as a `(1-based line
/// number, error)` pair. The offending line text is deliberately **not**
/// returned: a mistyped target can carry credentials (`user:pass@`), and a line
/// number plus reason lets the caller report the skip without logging the secret.
pub fn parse_dedup(
    raw_lines: &[&str],
    default_path: &str,
) -> (Vec<Target>, Vec<(usize, TargetError)>) {
    let mut seen = std::collections::HashSet::new();
    let mut targets = Vec::new();
    let mut errors = Vec::new();

    for (idx, &line) in raw_lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match Target::parse(line) {
            Ok(t) => {
                // Default-path BEFORE dedup so path-less and defaulted spellings
                // of the same resource are one key.
                let t = if raw_has_explicit_path(line) {
                    t
                } else {
                    t.with_path(default_path)
                };
                if seen.insert(t.dedup_key()) {
                    targets.push(t);
                }
            }
            Err(e) => errors.push((idx + 1, e)),
        }
    }

    (targets, errors)
}

/// An allowlist of hosts/domains. A target is in scope when its host equals an
/// entry or is a subdomain of one. An empty scope allows nothing (so a scope
/// file that reads empty refuses every target, by design; fail safe).
#[derive(Debug, Clone, Default)]
pub struct Scope {
    allowed: Vec<String>,
}

/// A malformed `--scope` line: not a bare host/domain. Carries only the 1-based
/// line number; never the line's text, which could hold a credential a user
/// pasted by mistake (e.g. `https://user:pass@host`) and must not reach the logs.
#[derive(Debug, Error)]
#[error(
    "scope line {line} is not a bare host or domain — expected one host or domain \
     per line (no scheme, port, path, or credentials)"
)]
pub struct ScopeError {
    pub line: usize,
}

/// Canonical host form (IDNA/punycode + lowercase for domains, dotted IPv4,
/// bracketed IPv6) matching how `Target` normalizes. `url::Host::parse` rejects
/// anything carrying a port or path, so a scope entry can only ever be a host.
fn canonical_host(host: &str) -> Option<String> {
    match url::Host::parse(host).ok()? {
        url::Host::Domain(mut domain) => {
            if domain.ends_with('.') {
                domain.pop();
            }
            if domain.is_empty() || domain.ends_with('.') {
                return None;
            }
            Some(domain)
        }
        ip => Some(ip.to_string()),
    }
}

impl Scope {
    /// Build from file lines: trim, drop blanks and `#` comments, strip a
    /// leading `*.`/`.` wildcard, then validate each remaining entry as a bare
    /// host (IDNA domain, IPv4, or bracketed IPv6). `example.com` covers
    /// `example.com` and any `*.example.com`. An entry with a port, path, or
    /// scheme (e.g. `example.org:8443`, `example.org/admin`) is a hard error:
    /// a config slip must never silently widen the scope.
    pub fn from_lines<I, S>(lines: I) -> Result<Self, ScopeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowed = Vec::new();
        for (i, l) in lines.into_iter().enumerate() {
            let raw = l.as_ref().trim();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            let host = raw.trim_start_matches("*.").trim_start_matches('.');
            match canonical_host(host) {
                Some(h) => allowed.push(h),
                None => return Err(ScopeError { line: i + 1 }),
            }
        }
        Ok(Scope { allowed })
    }

    /// Whether `host` is allowed (exact match or a subdomain of an entry).
    pub fn allows_host(&self, host: &str) -> bool {
        let Some(h) = canonical_host(host) else {
            return false;
        };
        self.allowed
            .iter()
            .any(|e| h == *e || h.ends_with(&format!(".{e}")))
    }

    /// Whether a target's host is in scope.
    pub fn allows(&self, target: &Target) -> bool {
        target
            .url()
            .host_str()
            .map(|h| self.allows_host(h))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_origin_compares_scheme_host_and_effective_port() {
        let https = Url::parse("https://h/a").unwrap();
        let http = Url::parse("http://h/a").unwrap();
        assert_eq!(
            origin(&https),
            origin(&Url::parse("https://h:443/b").unwrap())
        );
        assert_eq!(origin(&http), origin(&Url::parse("http://h:80/b").unwrap()));
        assert_ne!(origin(&https), origin(&http));
        assert_ne!(
            origin(&https),
            origin(&Url::parse("https://h:8443/a").unwrap())
        );
        assert_ne!(
            origin(&https),
            origin(&Url::parse("https://other/a").unwrap())
        );
    }

    #[test]
    fn fragments_are_removed_before_reporting_and_deduplication() {
        let (targets, errors) = parse_dedup(
            &[
                "https://example.org?q=1#local-note",
                "https://example.org/index.php?q=1#other",
            ],
            "/index.php",
        );
        assert!(errors.is_empty());
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].as_str(), "https://example.org/index.php?q=1");
        assert_eq!(
            Target::parse("https://example.org/a%23b#local")
                .unwrap()
                .url()
                .path(),
            "/a%23b"
        );
    }

    #[test]
    fn scope_matches_exact_and_subdomains_only() {
        let scope = Scope::from_lines(["example.com", "# comment", "", "*.wild.net"]).unwrap();
        assert!(scope.allows_host("example.com"));
        assert!(scope.allows_host("api.example.com"));
        assert!(scope.allows_host("a.b.example.com"));
        assert!(scope.allows_host("host.wild.net"));
        // Not a subdomain, just a suffix string → refused.
        assert!(!scope.allows_host("notexample.com"));
        assert!(!scope.allows_host("example.com.evil.com"));
        assert!(!scope.allows_host("other.org"));
    }

    #[test]
    fn scope_ignores_one_final_dns_dot() {
        for entry in ["example.invalid", "example.invalid."] {
            let scope = Scope::from_lines([entry]).unwrap();
            for host in [
                "example.invalid",
                "example.invalid.",
                "api.example.invalid.",
            ] {
                assert!(
                    scope.allows(&Target::parse(host).unwrap()),
                    "{entry}: {host}"
                );
            }
            for host in [
                "notexample.invalid.",
                "example.invalid.other.",
                "example.invalid..",
            ] {
                assert!(!scope.allows_host(host), "{entry}: {host}");
            }
        }
        assert!(Scope::from_lines(["example.invalid.."]).is_err());
    }

    #[test]
    fn scope_matches_internationalized_domain_as_punycode() {
        // Entry is Unicode; a target host is normalized to punycode. Both must
        // resolve to the same ASCII form or the target is wrongly refused.
        let scope = Scope::from_lines(["bücher.example"]).unwrap();
        let target = Target::parse("https://bücher.example/x").unwrap();
        assert!(scope.allows(&target));
        assert!(scope.allows_host("xn--bcher-kva.example"));
        assert!(scope.allows_host("shop.bücher.example")); // subdomain, Unicode
    }

    #[test]
    fn scope_rejects_entry_with_port_or_path() {
        // A port/path/scheme on an entry would otherwise be silently dropped,
        // widening the scope to every port/path of that host. Must hard-error
        // with the offending line number (comments/blanks don't count).
        let err = Scope::from_lines(["# header", "good.com", "bad.org:8443"]).unwrap_err();
        assert_eq!(err.line, 3);
        // The offending text (which may hold a credential) must never appear in
        // the error message; only the line number and expected format.
        assert!(!err.to_string().contains("bad.org"));
        assert!(Scope::from_lines(["example.org/admin"]).is_err());
        assert!(Scope::from_lines(["https://user:pass@example.org"]).is_err());
    }

    #[test]
    fn empty_scope_allows_nothing() {
        let scope = Scope::from_lines(Vec::<String>::new()).unwrap();
        assert!(!scope.allows_host("example.com"));
    }

    #[test]
    fn adds_default_https_scheme() {
        let t = Target::parse("example.com").unwrap();
        assert_eq!(t.url().scheme(), "https");
        assert_eq!(t.url().host_str(), Some("example.com"));
    }

    #[test]
    fn keeps_explicit_http() {
        let t = Target::parse("http://example.com/x").unwrap();
        assert_eq!(t.url().scheme(), "http");
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert_eq!(
            Target::parse("ftp://example.com"),
            Err(TargetError::Scheme("ftp".into()))
        );
    }

    #[test]
    fn rejects_credentials() {
        assert_eq!(
            Target::parse("https://user:pass@example.com"),
            Err(TargetError::Credentials)
        );
        // credentials survive the default-scheme path too
        assert_eq!(
            Target::parse("user:pass@example.com"),
            Err(TargetError::Credentials)
        );
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(Target::parse(" "), Err(TargetError::Empty));
    }

    #[test]
    fn idna_encodes_hostname() {
        // Unicode host → punycode in the normalized URL.
        let t = Target::parse("https://bücher.example").unwrap();
        assert_eq!(t.url().host_str(), Some("xn--bcher-kva.example"));
    }

    #[test]
    fn brackets_ipv6_literal() {
        let t = Target::parse("https://[::1]:8080/p").unwrap();
        assert_eq!(t.url().host_str(), Some("[::1]"));
        assert_eq!(t.url().port(), Some(8080));
    }

    #[test]
    fn dedup_key_folds_host_case_not_path() {
        let a = Target::parse("https://Example.COM/Path").unwrap();
        let b = Target::parse("https://example.com/Path").unwrap();
        // host case folds (same key), path case is preserved (still same here)
        assert_eq!(a.dedup_key(), b.dedup_key());
        let c = Target::parse("https://example.com/other").unwrap();
        assert_ne!(a.dedup_key(), c.dedup_key());
    }

    #[test]
    fn dedup_key_uses_effective_port() {
        // Implicit https == explicit :443.
        let implicit = Target::parse("https://example.com/p").unwrap();
        let explicit = Target::parse("https://example.com:443/p").unwrap();
        assert_eq!(implicit.dedup_key(), explicit.dedup_key());
        // Distinct ports never collapse.
        let a = Target::parse("https://host:8011/").unwrap();
        let b = Target::parse("https://host:8012/").unwrap();
        assert_ne!(a.dedup_key(), b.dedup_key());
    }

    #[test]
    fn parse_dedup_drops_duplicates_keeps_order_and_errors() {
        let lines = [
            "example.com",
            "https://example.com", // dup of line 1 (default scheme → https)
            "ftp://bad",
            "second.example/path",
        ];
        let (targets, errors) = parse_dedup(&lines, "/");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].url().host_str(), Some("example.com"));
        assert_eq!(targets[1].url().host_str(), Some("second.example"));
        assert_eq!(errors.len(), 1);
        // The error reports the 1-based line number, never the raw line (which
        // could carry credentials).
        assert_eq!(errors[0].0, 3);
        assert_eq!(errors[0].1, TargetError::Scheme("ftp".into()));
    }

    #[test]
    fn parse_dedup_error_never_returns_the_raw_line() {
        // A credentialed target is rejected and reported by line number only.
        let (targets, errors) = parse_dedup(&["https://user:pass@example.com"], "/");
        assert!(targets.is_empty());
        assert_eq!(errors, vec![(1, TargetError::Credentials)]);
    }

    #[test]
    fn default_path_applied_before_dedup_collapses_bare_and_spelled() {
        // A bare host and the same host spelled with the default path are one scan.
        let (targets, _) = parse_dedup(&["example.com", "example.com/index.php"], "/index.php");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].url().path(), "/index.php");
    }

    #[test]
    fn explicit_root_path_is_preserved_not_defaulted() {
        // A trailing slash is an explicit path → kept as `/`, never rewritten.
        let (targets, _) = parse_dedup(&["example.com/"], "/index.php");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].url().path(), "/");
        // A bare host (no slash) does get the default.
        let (bare, _) = parse_dedup(&["example.com"], "/index.php");
        assert_eq!(bare[0].url().path(), "/index.php");
    }

    #[test]
    fn raw_explicit_path_detection() {
        assert!(!raw_has_explicit_path("example.com"));
        assert!(!raw_has_explicit_path("example.com:8443"));
        assert!(!raw_has_explicit_path("example.com?q=1"));
        assert!(raw_has_explicit_path("example.com/"));
        assert!(raw_has_explicit_path("https://example.com/api"));
        // A `://` inside a query value must not be mistaken for the scheme sep.
        assert!(raw_has_explicit_path(
            "127.0.0.1:1/api?next=https://example.invalid"
        ));
        assert!(!raw_has_explicit_path("example.com?next=https://x"));
    }

    #[test]
    fn scheme_in_query_does_not_swallow_the_path() {
        // Regression: the real path /api must survive and the default not applied.
        let (targets, _) = parse_dedup(
            &["http://127.0.0.1:1/api?next=https://example.invalid"],
            "/index.php",
        );
        assert_eq!(targets[0].url().path(), "/api");
    }

    #[test]
    fn with_path_is_immutable() {
        let base = Target::parse("https://example.com/orig").unwrap();
        let derived = base.with_path("/index.php");
        assert_eq!(base.url().path(), "/orig"); // original untouched
        assert_eq!(derived.url().path(), "/index.php");
    }
}
