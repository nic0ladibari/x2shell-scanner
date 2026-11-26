//! CLI surface: a subcommand per detector (`php`, `node`, `react`) plus `all`.
//!
//! Every shared flag lives once in [`CommonArgs`] and is flattened into each
//! subcommand. Only `--timeout` is spelled per subcommand, because the default
//! differs (php/node/all 60s, react 10s), and the detector-specific flags
//! (`--active`/`--sapi`, `--safe-check`/`--follow-redirects`) live under their
//! own subcommand.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// An inter-request gap longer than this isn't a rate limit, it's a
/// misconfiguration, and such an interval overflows the limiter's `Instant`
/// arithmetic, so we reject it up front.
const MAX_RATE_INTERVAL: Duration = Duration::from_secs(86_400); // 24h

/// Validate `--rate` at parse time (a clap error here is usage exit code 2,
/// raised before any output file is opened). Rejects non-finite (`NaN`/`inf`),
/// non-positive, and values so low the request interval (`1/rate` seconds) is
/// either not representable as a `Duration` or exceeds [`MAX_RATE_INTERVAL`].
/// Without this a value like `1e-19` parses into a `Duration` but then overflows
/// `Instant + interval` inside a worker, killing it while the process still
/// exits 0; an automation would read that as a clean run.
fn parse_rate(s: &str) -> Result<f64, String> {
    let r: f64 = s.parse().map_err(|_| format!("`{s}` is not a number"))?;
    if !r.is_finite() || r <= 0.0 {
        return Err(format!("rate must be a finite positive number (got `{s}`)"));
    }
    let interval = Duration::try_from_secs_f64(1.0 / r)
        .map_err(|_| format!("rate `{s}` is too small to represent an interval"))?;
    if interval > MAX_RATE_INTERVAL {
        return Err(format!("rate `{s}` is too low (interval exceeds 24h)"));
    }
    Ok(r)
}

/// Validate `--threads` / `--max-heavy` at parse time. `tokio::sync::Semaphore::new`
/// panics above `MAX_PERMITS`, and that panic fires *after* `-o` has been opened
/// (truncating any existing report); exiting 101 and losing the file. Rejecting
/// an out-of-range value here makes it a clean usage error (exit 2) before any
/// file is touched. `0` is allowed (`--threads` floors to 1; `--max-heavy 0`
/// means uncapped).
fn parse_permits(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("`{s}` is not a non-negative integer"))?;
    if n > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(format!(
            "value `{s}` exceeds the maximum ({})",
            tokio::sync::Semaphore::MAX_PERMITS
        ));
    }
    Ok(n)
}

#[derive(Parser, Debug)]
#[command(
    name = "x2shell-scanner",
    version,
    about = "Defensive detection scanner"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// PHP multipart-parser detector (CVE-2026-109618/109619).
    Php(PhpArgs),
    /// Node encoded-body detector (CVE-2026-111497).
    Node(NodeArgs),
    /// React Server Components / Next.js detector (CVE-2025-55182).
    React(ReactArgs),
    /// Run every detector per target (low-impact checks only).
    All(AllArgs),
}

/// Flags shared by every subcommand, flattened into each. `--timeout` is not
/// here: its default differs per detector, so each subcommand spells it.
#[derive(Args, Debug)]
pub struct CommonArgs {
    /// Single target URL.
    #[arg(short = 'u', long, conflicts_with = "list")]
    pub url: Option<String>,

    /// File of hosts, one per line.
    #[arg(short = 'l', long, conflicts_with = "url")]
    pub list: Option<PathBuf>,

    /// Disable TLS verification (default off).
    #[arg(short = 'k', long)]
    pub insecure: bool,

    /// Write results to this file.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Save only vulnerable results (default: save all; positive, negative,
    /// and inconclusive).
    #[arg(long)]
    pub only_vulnerable: bool,

    /// Concurrent scans in flight (min 1).
    #[arg(short = 't', long, default_value_t = 10, value_parser = parse_permits)]
    pub threads: usize,

    /// Hide the progress bar and print only vulnerable hosts.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Custom request header `Key: Value`, repeatable; overrides the built-in
    /// defaults (e.g. User-Agent) on every request.
    #[arg(short = 'H', long = "header", value_name = "KEY: VALUE")]
    pub header: Vec<String>,

    /// Route traffic through a proxy (`http://[user:pass@]host:port` or
    /// `socks5://host:port`). Falls back to HTTPS_PROXY / ALL_PROXY when unset.
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Structured trace to stderr with a redacted dump of each exchange (request
    /// line + headers, response status + headers + a bounded body preview).
    #[arg(long)]
    pub debug: bool,

    /// Output format for the `-o` file. json/sarif are only valid once the run
    /// finishes; use ndjson or csv for a run you may interrupt (each row is flushed).
    #[arg(long, value_enum, default_value_t = FormatArg::Json)]
    pub format: FormatArg,

    /// Allowlist file (one host/domain per line); targets outside it are
    /// refused. A subdomain of a listed domain is in scope.
    #[arg(long)]
    pub scope: Option<PathBuf>,

    /// Global requests/second cap (default off); backs off on HTTP 429.
    #[arg(long, value_parser = parse_rate)]
    pub rate: Option<f64>,

    /// Max concurrent heavy probes, independent of --threads.
    #[arg(long, default_value_t = 4, value_parser = parse_permits)]
    pub max_heavy: usize,
}

#[derive(Parser, Debug)]
pub struct AllArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 60)]
    pub timeout: u64,
}

#[derive(Parser, Debug)]
pub struct NodeArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 60)]
    pub timeout: u64,
}

/// Output format for the `-o` file.
#[derive(ValueEnum, Clone, Copy, Debug, Default)]
pub enum FormatArg {
    #[default]
    Json,
    Ndjson,
    Sarif,
    Csv,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default)]
pub enum SapiArg {
    #[default]
    Auto,
    /// Accept the documented spelling `mod_php` (underscore); `mod-php` is an alias.
    #[value(name = "mod_php", alias = "mod-php")]
    ModPhp,
    Fpm,
}

#[derive(Parser, Debug)]
pub struct PhpArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 60)]
    pub timeout: u64,

    /// Run the heavy crash probes. Off by default: with no flag, `php` performs
    /// only the passive control + version check (safe fleet triage). Active
    /// probes can exhaust memory and kill workers; authorized use only.
    #[arg(long)]
    pub active: bool,

    /// SAPI rules to apply.
    #[arg(long, value_enum, default_value_t = SapiArg::Auto)]
    pub sapi: SapiArg,

    /// Follow redirects (<=10 hops) and re-baseline at the final URL. Cross-origin
    /// hops are followed too, but the operator's -H secrets (Authorization,
    /// Cookie, custom headers) are stripped once a hop leaves the origin.
    #[arg(long)]
    pub follow_redirects: bool,
}

#[derive(Parser, Debug)]
pub struct ReactArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Side-channel safe-check (the default and only mode in the default build).
    #[arg(long, default_value_t = true)]
    pub safe_check: bool,

    /// Follow same-host redirects and retest the final URL once.
    #[arg(long)]
    pub follow_redirects: bool,

    /// Active confirmation mode (sends a crafted RSC action with a benign
    /// reflected marker). Requires `--i-am-authorized`; only in a binary built
    /// with the `active-confirm` feature.
    #[cfg(feature = "active-confirm")]
    #[arg(long, conflicts_with = "safe_check")]
    pub active: bool,

    /// Authorized-use acknowledgement required to run `--active`.
    #[cfg(feature = "active-confirm")]
    #[arg(long)]
    pub i_am_authorized: bool,

    /// Single documented WAF-bypass variant for the active probe (deterministic
    /// junk seeded by `--seed`).
    #[cfg(feature = "active-confirm")]
    #[arg(long)]
    pub waf_bypass: bool,

    /// Seed for deterministic `--waf-bypass` junk.
    #[cfg(feature = "active-confirm")]
    #[arg(long)]
    pub seed: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::{parse_permits, parse_rate};

    #[cfg(feature = "active-confirm")]
    #[test]
    fn react_rejects_conflicting_explicit_modes() {
        use super::Cli;
        use clap::{error::ErrorKind, Parser};

        for (first, second) in [("--safe-check", "--active"), ("--active", "--safe-check")] {
            let error =
                Cli::try_parse_from(["scanner", "react", first, second, "--i-am-authorized"])
                    .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
        assert!(Cli::try_parse_from(["scanner", "react", "--active", "--i-am-authorized"]).is_ok());
        assert!(Cli::try_parse_from(["scanner", "react", "--safe-check"]).is_ok());
    }

    #[test]
    fn rate_accepts_finite_positive() {
        assert_eq!(parse_rate("10").unwrap(), 10.0);
        assert_eq!(parse_rate("0.5").unwrap(), 0.5);
    }

    #[test]
    fn rate_rejects_nan_inf_and_nonpositive() {
        // NaN must not silently disable the limit (it would with a bare `> 0.0`)
        assert!(parse_rate("NaN").is_err());
        assert!(parse_rate("inf").is_err());
        assert!(parse_rate("0").is_err());
        assert!(parse_rate("-1").is_err());
        assert!(parse_rate("x").is_err());
    }

    #[test]
    fn rate_rejects_value_too_small_to_represent() {
        // 1/1e-30 overflows a Duration → would panic (exit 101); must be a usage err
        assert!(parse_rate("1e-30").is_err());
    }

    #[test]
    fn rate_rejects_interval_that_overflows_instant_arithmetic() {
        // 1e-19 parses into a Duration but its interval later overflows
        // `Instant + interval` in a worker (silent exit 0). Must be rejected here.
        assert!(parse_rate("1e-19").is_err());
    }

    #[test]
    fn permits_accepts_in_range_including_zero() {
        assert_eq!(parse_permits("0").unwrap(), 0); // --max-heavy 0 = uncapped
        assert_eq!(parse_permits("10").unwrap(), 10);
        assert_eq!(
            parse_permits(&tokio::sync::Semaphore::MAX_PERMITS.to_string()).unwrap(),
            tokio::sync::Semaphore::MAX_PERMITS
        );
    }

    #[test]
    fn permits_rejects_overflow_before_semaphore_panics() {
        // usize::MAX would panic Semaphore::new *after* -o truncates the report
        // (exit 101). Must be a usage error (exit 2) at parse time.
        assert!(parse_permits(&usize::MAX.to_string()).is_err());
        assert!(parse_permits("-1").is_err());
        assert!(parse_permits("x").is_err());
    }
}
