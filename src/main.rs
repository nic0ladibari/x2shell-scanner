//! CLI entry point for target selection, scan execution and report output.
#![forbid(unsafe_code)]

mod cli;

/// Like `eprintln!`, but a closed stderr reader (BrokenPipe) never panics the
/// process; it drops the line. Every CLI diagnostic goes through this so an
/// early error still exits with its real code (2/3/4) instead of 101.
macro_rules! eprintln_safe {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use serde_json::json;

use x2shell_scanner::core::concurrency::{scan_targets, PoolOpts, RunSummary};
use x2shell_scanner::core::detector::{Detector, ScanOpts};
use x2shell_scanner::core::http::{HttpClient, HttpConfig, Proxy};
use x2shell_scanner::core::output::{Format, ResultSink, RunMeta};
use x2shell_scanner::core::targets::{parse_dedup, Scope, Target};
use x2shell_scanner::node::NodeDetector;
use x2shell_scanner::php::detect::Sapi;
use x2shell_scanner::php::PhpDetector;
use x2shell_scanner::react::ReactDetector;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let (common, timeout) = match &cli.command {
        cli::Command::Php(a) => (&a.common, a.timeout),
        cli::Command::Node(a) => (&a.common, a.timeout),
        cli::Command::React(a) => (&a.common, a.timeout),
        cli::Command::All(a) => (&a.common, a.timeout),
    };
    init_tracing(common.debug);
    let http = match parse_http_config(common, timeout) {
        Ok(config) => config,
        Err(code) => return code,
    };
    match cli.command {
        cli::Command::Php(args) => run_php(args, http).await,
        cli::Command::Node(args) => run_node(args, http).await,
        cli::Command::React(args) => run_react(args, http).await,
        cli::Command::All(args) => run_all(args, http).await,
    }
}

/// Install a stderr tracing subscriber at DEBUG when `--debug` is set. Without it
/// no subscriber is installed, so the `tracing::debug!` dumps in the HTTP layer
/// are no-ops and never evaluate their (redacting) arguments.
fn init_tracing(debug: bool) {
    if debug {
        tracing_subscriber::fmt()
            .with_env_filter("off,x2s::http=debug")
            .with_writer(std::io::stderr)
            .with_target(false)
            .init();
    }
}

/// The detector's primary default path, applied to path-less targets.
fn default_path(detector: &dyn Detector) -> &str {
    detector.default_paths().first().copied().unwrap_or("/")
}

/// Everything the unified driver needs, gathered from one subcommand's args.
struct RunConfig<'a> {
    detector: Arc<dyn Detector>,
    common: &'a cli::CommonArgs,
    http: HttpConfig,
    opts: ScanOpts,
    /// Sanitized, verdict-affecting options for the run metadata (never argv).
    options: serde_json::Value,
}

/// Build the heavy-probe semaphore for `--max-heavy`; `0` means uncapped.
fn heavy_semaphore(max_heavy: usize) -> Option<Arc<tokio::sync::Semaphore>> {
    (max_heavy > 0).then(|| Arc::new(tokio::sync::Semaphore::new(max_heavy)))
}

fn map_format(f: cli::FormatArg) -> Format {
    match f {
        cli::FormatArg::Json => Format::Json,
        cli::FormatArg::Ndjson => Format::Ndjson,
        cli::FormatArg::Sarif => Format::Sarif,
        cli::FormatArg::Csv => Format::Csv,
    }
}

/// Common sanitized option keys recorded in run metadata (never raw argv or
/// header values; only the custom-header *count*).
fn common_options(c: &cli::CommonArgs, http: &HttpConfig) -> serde_json::Value {
    json!({
        "threads": c.threads,
        "timeout": http.timeout.as_secs(),
        "insecure": c.insecure,
        "only_vulnerable": c.only_vulnerable,
        "custom_headers": c.header.len(),
        // Scheme only; host and credentials are never persisted.
        "proxy": http.proxy.as_ref().map(Proxy::scheme),
    })
}

async fn run_node(args: cli::NodeArgs, http: HttpConfig) -> ExitCode {
    let mut options = common_options(&args.common, &http);
    options["detector"] = json!("node");
    run(RunConfig {
        detector: Arc::new(NodeDetector),
        common: &args.common,
        http,
        opts: ScanOpts::default(),
        options,
    })
    .await
}

async fn run_php(args: cli::PhpArgs, http: HttpConfig) -> ExitCode {
    let sapi = match args.sapi {
        cli::SapiArg::Auto => Sapi::Auto,
        cli::SapiArg::ModPhp => Sapi::ModPhp,
        cli::SapiArg::Fpm => Sapi::Fpm,
    };
    let mut options = common_options(&args.common, &http);
    options["detector"] = json!("php");
    options["sapi"] = json!(format!("{sapi:?}").to_lowercase());
    options["active"] = json!(args.active);
    options["follow_redirects"] = json!(args.follow_redirects);
    run(RunConfig {
        detector: Arc::new(PhpDetector {
            sapi,
            active: args.active,
        }),
        common: &args.common,
        http,
        opts: ScanOpts {
            follow_redirects: args.follow_redirects,
            ..ScanOpts::default()
        },
        options,
    })
    .await
}

async fn run_react(args: cli::ReactArgs, http: HttpConfig) -> ExitCode {
    let (detector, mode) = select_react_detector(&args);
    let mut options = common_options(&args.common, &http);
    options["detector"] = json!("react");
    options["mode"] = json!(mode);
    options["follow_redirects"] = json!(args.follow_redirects);
    run(RunConfig {
        detector,
        common: &args.common,
        http,
        opts: ScanOpts {
            follow_redirects: args.follow_redirects,
            ..ScanOpts::default()
        },
        options,
    })
    .await
}

/// Active confirmation requires the build feature and explicit runtime authorization.
#[cfg(feature = "active-confirm")]
fn select_react_detector(args: &cli::ReactArgs) -> (Arc<dyn Detector>, &'static str) {
    if args.active {
        if !args.i_am_authorized {
            eprintln_safe!(
                "error: --active requires --i-am-authorized; falling back to safe-check"
            );
            return (Arc::new(ReactDetector::safe_check()), "safe-check");
        }
        eprintln_safe!(
            "authorized-use: active confirmation sends a crafted RSC action carrying only a \
             benign reflected marker — no command is sent"
        );
        return (
            Arc::new(ReactDetector::active(args.seed, args.waf_bypass)),
            "active",
        );
    }
    (Arc::new(ReactDetector::safe_check()), "safe-check")
}

#[cfg(not(feature = "active-confirm"))]
fn select_react_detector(_args: &cli::ReactArgs) -> (Arc<dyn Detector>, &'static str) {
    (Arc::new(ReactDetector::safe_check()), "safe-check")
}

/// `all`: run php (passive), node, and react (safe-check) over every target,
/// streaming all results into one sink. Heavy/active modes are never started
/// here (`low_impact`), and a note lists what was skipped.
async fn run_all(args: cli::AllArgs, mut http: HttpConfig) -> ExitCode {
    let c = &args.common;
    if let Err(code) = reject_output_clobbering(
        c.output.as_deref(),
        &[("list", c.list.as_deref()), ("scope", c.scope.as_deref())],
    ) {
        return code;
    }
    let raw = match read_raw(c.url.as_deref(), c.list.as_deref()) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let scope = match load_scope(c.scope.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    // A `-H Host:` override must also be inside --scope (see `run`).
    if let Err(code) = validate_host_override(&mut http.extra_headers, scope.as_ref()) {
        return code;
    }

    // Low-impact detectors only: php passive (no --active), node (controls only,
    // heavy probe skipped via `low_impact`), react safe-check.
    let detectors: Vec<Arc<dyn Detector>> = vec![
        Arc::new(PhpDetector {
            sapi: Sapi::Auto,
            active: false,
        }),
        Arc::new(NodeDetector),
        Arc::new(ReactDetector::safe_check()),
    ];

    // Resolve each detector's targets (its own default path) before opening the
    // sink, so an empty run fails fast and the header is never written alone.
    let per_detector: Vec<(Arc<dyn Detector>, Vec<Target>)> = detectors
        .into_iter()
        .enumerate()
        .map(|(i, det)| {
            let dp = default_path(det.as_ref()).to_string();
            let targets = targets_for(&raw, &scope, &dp, i == 0);
            (det, targets)
        })
        .collect();
    // Distinct endpoints scanned. Detectors apply different default paths to
    // path-less targets (php → /index.php, node/react → /), so their normalized
    // target sets differ: the union of dedup keys is the true endpoint count,
    // not the max of per-detector counts (which undercounts a mixed URL set).
    let distinct_targets = per_detector
        .iter()
        .flat_map(|(_, t)| t.iter().map(Target::dedup_key))
        .collect::<std::collections::HashSet<_>>()
        .len();
    if distinct_targets == 0 {
        eprintln_safe!("error: no valid targets");
        return ExitCode::from(4);
    }

    let mut options = common_options(c, &http);
    options["detector"] = json!("all");
    options["detectors"] = json!(["php(passive)", "node(controls-only)", "react(safe-check)"]);
    let mut sink = match open_report(c, options) {
        Ok(sink) => sink,
        Err(code) => return code,
    };

    let client = Arc::new(HttpClient::new(http).with_rate(c.rate));
    let heavy = heavy_semaphore(c.max_heavy);
    let mut agg = RunSummary::default();
    for (det, targets) in per_detector {
        if targets.is_empty() {
            continue;
        }
        let opts = ScanOpts {
            low_impact: true,
            heavy: heavy.clone(),
            ..ScanOpts::default()
        };
        let summary = scan_targets(
            det,
            targets,
            Arc::clone(&client),
            opts,
            PoolOpts {
                threads: c.threads,
                quiet: c.quiet,
                only_vulnerable: c.only_vulnerable,
            },
            sink.as_mut(),
        )
        .await;
        agg.merge(summary);
    }

    if let Err(code) = finish_report(sink, &agg) {
        return code;
    }

    eprintln_safe!("{}", summary_line(distinct_targets, &agg));
    eprintln_safe!(
        "note: `all` ran low-impact checks only — php heavy probes (--active), node's \
         confirmation probe, and react active modes were skipped"
    );

    ExitCode::from(run_exit_code(&agg))
}

fn open_report(
    common: &cli::CommonArgs,
    options: serde_json::Value,
) -> Result<Option<ResultSink>, ExitCode> {
    let Some(path) = common.output.as_deref() else {
        return Ok(None);
    };
    let meta = RunMeta {
        tool_version: env!("CARGO_PKG_VERSION"),
        git_sha: option_env!("X2S_GIT_SHA"),
        started_at: now_rfc3339(),
        options,
    };
    ResultSink::new(path, map_format(common.format), &meta)
        .map(Some)
        .map_err(|e| {
            eprintln_safe!("error: cannot open output file {}: {e}", path.display());
            ExitCode::from(3)
        })
}

/// Flush the report before printing the terminal summary.
fn finish_report(sink: Option<ResultSink>, summary: &RunSummary) -> Result<(), ExitCode> {
    if let Some(sink) = sink {
        sink.finish(summary).map_err(|e| {
            eprintln_safe!("error: cannot write output file: {e}");
            ExitCode::from(3)
        })?;
    }
    Ok(())
}

/// Exit code once the report is finalized: an output write failure (3) outranks
/// the verdict, then a vulnerable host (1), else success (0).
fn run_exit_code(summary: &RunSummary) -> u8 {
    if summary.output_error {
        3
    } else if summary.vulnerable > 0 {
        1
    } else {
        0
    }
}

fn parse_http_config(common: &cli::CommonArgs, timeout: u64) -> Result<HttpConfig, ExitCode> {
    let extra_headers = parse_headers(&common.header)?;
    let proxy = resolve_proxy(common.proxy.as_deref())?;
    Ok(HttpConfig {
        timeout: Duration::from_secs(timeout),
        insecure: common.insecure,
        extra_headers,
        proxy,
        ..HttpConfig::default()
    })
}

/// Resolve the effective proxy: the `--proxy` flag, else the HTTPS_PROXY /
/// ALL_PROXY environment variables (either case). A malformed proxy URL is a
/// usage error (2); never silently a direct, un-proxied scan.
fn resolve_proxy(flag: Option<&str>) -> Result<Option<Proxy>, ExitCode> {
    let from_env = || {
        ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    };
    let Some(spec) = flag.map(str::to_string).or_else(from_env) else {
        return Ok(None);
    };
    match Proxy::parse(&spec) {
        Ok(p) => Ok(Some(p)),
        Err(e) => {
            eprintln_safe!("error: {e}");
            Err(ExitCode::from(2))
        }
    }
}

/// Parse `-H "Key: Value"` strings into header pairs. A line without a `:` is a
/// usage error (2); a silently dropped header could mean an un-authenticated
/// scan the operator believed was authenticated.
fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>, ExitCode> {
    let mut out = Vec::with_capacity(raw.len());
    for (i, h) in raw.iter().enumerate() {
        match h.split_once(':') {
            Some((k, v))
                if !h.contains(['\r', '\n'])
                    && hyper::header::HeaderName::from_bytes(k.trim().as_bytes()).is_ok()
                    && hyper::header::HeaderValue::from_bytes(v.trim().as_bytes()).is_ok() =>
            {
                out.push((k.trim().to_string(), v.trim().to_string()))
            }
            _ => {
                // Never echo the raw header value: a malformed one (e.g. an
                // Authorization line missing its ':') may carry a secret token.
                // Report its position and the expected shape instead.
                eprintln_safe!(
                    "error: malformed --header at position {} (expected \"Key: Value\")",
                    i + 1
                );
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(out)
}

/// Current time as an RFC3339 string for run metadata; `"unknown"` if the clock
/// cannot be formatted.
fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Run a single detector and finalize its report before printing the summary.
async fn run(mut cfg: RunConfig<'_>) -> ExitCode {
    let c = cfg.common;
    // Refuse to overwrite an input file (the `-l` list or the `--scope`
    // allowlist) with the `-o` output; a slip in `-o` must never silently
    // destroy an input, symlinks and hard links included.
    if let Err(code) = reject_output_clobbering(
        c.output.as_deref(),
        &[("list", c.list.as_deref()), ("scope", c.scope.as_deref())],
    ) {
        return code;
    }

    let default_path = default_path(cfg.detector.as_ref());
    let (targets, scope) = match resolve_targets(
        c.url.as_deref(),
        c.list.as_deref(),
        c.scope.as_deref(),
        default_path,
    ) {
        Ok(t) => t,
        Err(code) => return code,
    };

    // A `-H Host:` override selects which virtual host the server actually
    // serves, so --scope must cover it too: on a shared reverse proxy an
    // in-scope IP could otherwise be steered to an out-of-scope application.
    if let Err(code) = validate_host_override(&mut cfg.http.extra_headers, scope.as_ref()) {
        return code;
    }

    let mut sink = match open_report(c, cfg.options) {
        Ok(sink) => sink,
        Err(code) => return code,
    };

    let total = targets.len();
    let client = Arc::new(HttpClient::new(cfg.http).with_rate(c.rate));
    let mut opts = cfg.opts;
    opts.heavy = heavy_semaphore(c.max_heavy);
    opts.scope = scope.map(Arc::new);
    let summary = scan_targets(
        cfg.detector,
        targets,
        client,
        opts,
        PoolOpts {
            threads: c.threads,
            quiet: c.quiet,
            only_vulnerable: c.only_vulnerable,
        },
        sink.as_mut(),
    )
    .await;

    if let Err(code) = finish_report(sink, &summary) {
        return code;
    }

    eprintln_safe!("{}", summary_line(total, &summary));

    ExitCode::from(run_exit_code(&summary))
}

/// Usage error (2) if `-o` points at the same file as any protected input
/// (`-l` list or `--scope` allowlist), so a slip in `-o` can't silently destroy
/// an input file.
fn reject_output_clobbering(
    output: Option<&Path>,
    protected: &[(&str, Option<&Path>)],
) -> Result<(), ExitCode> {
    let Some(output) = output else {
        return Ok(());
    };
    for (label, path) in protected {
        if let Some(path) = path {
            if same_file(path, output) {
                eprintln_safe!("error: --output would overwrite the --{label} file");
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(())
}

/// Whether two paths are the same existing file. Uses `same-file`, which compares
/// `(device, inode)` on Unix and the volume serial + file index on Windows, so
/// hard links to one file are caught as well as symlinks; on every platform and
/// on stable Rust (std's Windows file-index APIs are unstable). An output path
/// that does not exist yet (the common case) opens with an error → not the input.
fn same_file(a: &Path, b: &Path) -> bool {
    // Only regular files can clobber each other. Check the type via metadata
    // (a stat; never blocks) before opening a handle: opening a FIFO blocks
    // until a writer appears, which would hang the run before it even starts
    // when `-o` points at a named pipe.
    if !is_regular_file(a) || !is_regular_file(b) {
        return false;
    }
    match (
        same_file::Handle::from_path(a),
        same_file::Handle::from_path(b),
    ) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Whether `p` is an existing regular file (metadata follows symlinks, so a
/// symlink/hard link to a regular file still counts, but a FIFO, device, or
/// directory does not).
fn is_regular_file(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// One-line summary so an all-inconclusive run is never mistaken for a clean one.
fn summary_line(targets: usize, summary: &RunSummary) -> String {
    // The verdict breakdown counts checks (results), not endpoints. For a single
    // detector that equals the target count; `all` runs several detectors per
    // target, so spell out the check count to keep the two from being conflated.
    let checks = if summary.total != targets as u64 {
        format!(" ({} checks)", summary.total)
    } else {
        String::new()
    };
    format!(
        "{targets} targets{checks} · {} vulnerable · {} not-vulnerable · {} inconclusive",
        summary.vulnerable, summary.not_vulnerable, summary.unknown
    )
}

/// The raw target strings from `-u` or `-l`. Exit codes: a missing/duplicate
/// selector is a usage error (2); a list that can't be read is a list error (4).
fn read_raw(url: Option<&str>, list: Option<&Path>) -> Result<Vec<String>, ExitCode> {
    match (url, list) {
        (Some(u), None) => Ok(vec![u.to_string()]),
        (None, Some(path)) => match std::fs::read_to_string(path) {
            Ok(contents) => Ok(contents.lines().map(|l| l.to_string()).collect()),
            Err(e) => {
                eprintln_safe!("error: cannot read list file {}: {e}", path.display());
                Err(ExitCode::from(4))
            }
        },
        _ => {
            eprintln_safe!("error: exactly one of --url or --list is required");
            Err(ExitCode::from(2))
        }
    }
}

/// Load the `--scope` allowlist up front: an unreadable scope file is a hard
/// stop (4), never a silently unbounded scan.
fn load_scope(scope: Option<&Path>) -> Result<Option<Scope>, ExitCode> {
    match scope {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(contents) => match Scope::from_lines(contents.lines()) {
                Ok(scope) => Ok(Some(scope)),
                Err(e) => {
                    eprintln_safe!("error: invalid scope file {}: {e}", path.display());
                    Err(ExitCode::from(4))
                }
            },
            Err(e) => {
                eprintln_safe!("error: cannot read scope file {}: {e}", path.display());
                Err(ExitCode::from(4))
            }
        },
        None => Ok(None),
    }
}

/// Parse + dedup raw lines against a detector's default path, then drop
/// out-of-scope hosts. `report_errors` prints per-line parse skips (once, so
/// `all` does not repeat them per detector).
fn targets_for(
    raw: &[String],
    scope: &Option<Scope>,
    default_path: &str,
    report_errors: bool,
) -> Vec<Target> {
    let refs: Vec<&str> = raw.iter().map(|s| s.as_str()).collect();
    let (mut targets, errors) = parse_dedup(&refs, default_path);
    if report_errors {
        // Report skips by line number + reason only; never echo the line, which
        // may carry credentials (user:pass@).
        for (lineno, err) in &errors {
            eprintln_safe!("skip: line {lineno}: {err}");
        }
    }
    if let Some(scope) = scope {
        targets.retain(|t| {
            let ok = scope.allows(t);
            if !ok {
                // Host only (targets are validated, no credentials).
                eprintln_safe!("skip: {} out of scope", t.url().host_str().unwrap_or("?"));
            }
            ok
        });
    }
    targets
}

/// Validate the effective Host even in an unscoped run. Use the same canonical
/// host for the allowlist and the outgoing HTTP authority.
fn validate_host_override(
    headers: &mut [(String, String)],
    scope: Option<&Scope>,
) -> Result<(), ExitCode> {
    let Some((_, raw)) = headers
        .iter_mut()
        .rev()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
    else {
        return Ok(());
    };
    let Some((host, port)) = parse_host_authority(raw) else {
        eprintln_safe!("error: invalid -H Host override (expected a host with an optional port)");
        return Err(ExitCode::from(2));
    };
    let host = host.to_string();
    if scope.is_some_and(|s| !s.allows_host(&host)) {
        eprintln_safe!("error: the -H Host override targets a host outside --scope");
        return Err(ExitCode::from(4));
    }
    *raw = match port {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    Ok(())
}

fn parse_host_authority(raw: &str) -> Option<(url::Host, Option<u16>)> {
    let (host, port) = if raw.ends_with(']') {
        (raw, None)
    } else if let Some((host, port)) = raw.rsplit_once(':') {
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        (host, Some(port.parse().ok()?))
    } else {
        (raw, None)
    };
    // Exclude URL delimiters, escapes and whitespace before IDNA normalization.
    if host
        .bytes()
        .any(|b| b.is_ascii() && !(b.is_ascii_alphanumeric() || b".-_[]:".contains(&b)))
    {
        return None;
    }
    let host = url::Host::parse(host).ok()?;
    if let url::Host::Domain(domain) = &host {
        if !domain
            .strip_suffix('.')
            .unwrap_or(domain)
            .split('.')
            .all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            })
        {
            return None;
        }
    }
    Some((host, port))
}

/// Resolve targets for a single detector run. No valid in-scope target is a list error (4).
fn resolve_targets(
    url: Option<&str>,
    list: Option<&Path>,
    scope: Option<&Path>,
    default_path: &str,
) -> Result<(Vec<Target>, Option<Scope>), ExitCode> {
    let raw = read_raw(url, list)?;
    let scope = load_scope(scope)?;
    let targets = targets_for(&raw, &scope, default_path, true);
    if targets.is_empty() {
        eprintln_safe!("error: no valid targets");
        return Err(ExitCode::from(4));
    }
    // Return the scope so the detector can re-apply it to redirect hops; a
    // `--follow-redirects` chain must stay inside the same allowlist.
    Ok((targets, scope))
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        parse_headers, reject_output_clobbering, run_exit_code, same_file, validate_host_override,
        Scope,
    };
    use std::path::Path;
    use std::process::ExitCode;
    use x2shell_scanner::core::concurrency::RunSummary;

    #[test]
    fn validates_the_effective_host_before_scanning() {
        let scope = Scope::from_lines(["example.org", "[::1]", "xn--bcher-kva.example"]).unwrap();
        let check = |raw: &str| {
            let mut headers = vec![("Host".to_string(), raw.to_string())];
            validate_host_override(&mut headers, Some(&scope)).map(|()| headers.remove(0).1)
        };
        assert_eq!(check("EXAMPLE.org:8443").unwrap(), "example.org:8443");
        assert_eq!(check("bücher.example").unwrap(), "xn--bcher-kva.example");
        assert_eq!(check("[::1]:80").unwrap(), "[::1]:80");
        assert_eq!(check("outside.example"), Err(ExitCode::from(4)));
        for raw in [
            "",
            "x y",
            "example.org:bad",
            "example.org:",
            "example.org:65536",
            "example.org/path",
            "x@example.org",
            "example.org#x",
            "::1",
            "[::1",
        ] {
            assert_eq!(check(raw), Err(ExitCode::from(2)), "{raw:?}");
        }
        assert!(validate_host_override(&mut [], Some(&scope)).is_ok());
        let mut two = [
            ("Host".into(), "outside.example".into()),
            ("host".into(), "example.org".into()),
        ];
        assert!(validate_host_override(&mut two, Some(&scope)).is_ok());
    }

    #[test]
    fn output_error_outranks_verdict_in_exit_code() {
        // A stdout write failure must never be masked by the verdict: 3 wins
        // over a vulnerable (1), which wins over a clean run (0).
        let clean = RunSummary::default();
        assert_eq!(run_exit_code(&clean), 0);
        let vuln = RunSummary {
            vulnerable: 1,
            ..RunSummary::default()
        };
        assert_eq!(run_exit_code(&vuln), 1);
        let bad_output = RunSummary {
            vulnerable: 1,
            output_error: true,
            ..RunSummary::default()
        };
        assert_eq!(run_exit_code(&bad_output), 3);
    }

    #[test]
    fn parse_headers_trims_and_rejects_malformed() {
        let ok = parse_headers(&[
            "X-Foo:  bar ".to_string(),
            "Authorization: Bearer x".to_string(),
        ])
        .unwrap();
        assert_eq!(
            ok,
            vec![
                ("X-Foo".to_string(), "bar".to_string()),
                ("Authorization".to_string(), "Bearer x".to_string()),
            ]
        );
        assert!(parse_headers(&["no-colon".to_string()]).is_err());
        assert!(parse_headers(&[":empty-key".to_string()]).is_err());
    }

    // Give each test case its own file names under the scratch dir.
    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("x2s-clobber-{}-{name}", std::process::id()))
    }

    fn clobbers(input_label: &str, input: &Path, output: &Path) -> bool {
        matches!(
            reject_output_clobbering(Some(output), &[(input_label, Some(input))]),
            Err(code) if format!("{code:?}") == format!("{:?}", ExitCode::from(2))
        )
    }

    #[test]
    fn hard_link_to_an_input_is_caught() {
        let list = tmp("list");
        let out = tmp("out-hardlink");
        std::fs::write(&list, "https://example.com\n").unwrap();
        let _ = std::fs::remove_file(&out);
        std::fs::hard_link(&list, &out).unwrap();

        // Distinct paths, one inode: canonicalize would miss it, same-file catches it.
        assert!(same_file(&list, &out));
        assert!(clobbers("list", &list, &out));

        std::fs::remove_file(&list).unwrap();
        std::fs::remove_file(&out).unwrap();
    }

    #[test]
    fn scope_file_is_protected_too() {
        let scope = tmp("scope");
        std::fs::write(&scope, "example.com\n").unwrap();
        // Output pointing at the scope file itself must be refused.
        assert!(clobbers("scope", &scope, &scope));
        std::fs::remove_file(&scope).unwrap();
    }

    #[test]
    fn distinct_files_and_a_nonexistent_output_are_allowed() {
        let list = tmp("list2");
        let other = tmp("other");
        let missing = tmp("missing");
        std::fs::write(&list, "x\n").unwrap();
        std::fs::write(&other, "y\n").unwrap();
        let _ = std::fs::remove_file(&missing);

        assert!(!same_file(&list, &other));
        assert!(
            !same_file(&list, &missing),
            "output not yet created is never an input"
        );

        std::fs::remove_file(&list).unwrap();
        std::fs::remove_file(&other).unwrap();
    }
}
