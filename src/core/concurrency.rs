//! Bounded worker pool: run one detector over many targets with at most
//! `--threads` scans in flight, a progress bar, per-host serialization, and
//! per-host panic capture so one bad host never aborts the run.
//!
//! Results are printed and counted here as each scan completes; only the rows
//! that will actually be written to `-o` are retained, so a terminal-only run
//! over a huge list never holds every result in memory.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

use super::detector::{Detector, ScanOpts};
use super::http::HttpClient;
use super::output::ResultSink;
use super::report::ScanResult;
use super::targets::Target;

/// Per-host lock so a single host is never hit by two paths/stages at once.
type HostLocks = HashMap<String, Arc<Mutex<()>>>;

/// Counts all scan outcomes, including rows excluded from the report.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunSummary {
    pub total: u64,
    pub vulnerable: u64,
    pub not_vulnerable: u64,
    pub unknown: u64,
    /// A non-`BrokenPipe` write to stdout failed (e.g. a full disk on a
    /// redirected file). Results may be incomplete, so the run must not report
    /// success; the caller maps this to exit 3.
    pub output_error: bool,
}

impl RunSummary {
    /// Add a detector's counts and retain any output error from either run.
    pub fn merge(&mut self, other: Self) {
        self.total += other.total;
        self.vulnerable += other.vulnerable;
        self.not_vulnerable += other.not_vulnerable;
        self.unknown += other.unknown;
        self.output_error |= other.output_error;
    }
}

/// Pool knobs for one run.
#[derive(Debug, Clone, Copy)]
pub struct PoolOpts {
    /// Concurrent scans in flight (clamped to >= 1).
    pub threads: usize,
    /// Suppress the progress bar and print only vulnerable hosts.
    pub quiet: bool,
    /// Write only vulnerable rows to the sink.
    pub only_vulnerable: bool,
}

/// Serialization key for a target: its host plus effective port. Distinct ports
/// are distinct services and are not serialized against each other.
fn host_key(target: &Target) -> String {
    let url = target.url();
    let host = url.host_str().unwrap_or("").to_lowercase();
    let port = url.port_or_known_default().unwrap_or(0);
    format!("{host}:{port}")
}

/// Scan every target with at most `threads` concurrent scans. Each result is
/// printed and tallied as it completes, and written to `sink` (flushed
/// immediately) when one is present and the row passes the `only_vulnerable`
/// filter, so a crash mid-list never loses finished work and a terminal-only
/// run holds nothing in memory. A panic in one scan becomes an `ERROR` result
/// rather than aborting the run.
///
/// `quiet` suppresses the progress bar and prints only vulnerable hosts.
///
/// NOTE: a task holds its semaphore permit while it waits on its host lock,
/// so many paths on few hosts serialize throughput below `threads`. Fine for the
/// documented workload (one path per host by default); revisit only if path
/// fan-out per host becomes the norm.
pub async fn scan_targets(
    detector: Arc<dyn Detector>,
    targets: Vec<Target>,
    client: Arc<HttpClient>,
    opts: ScanOpts,
    pool: PoolOpts,
    mut sink: Option<&mut ResultSink>,
) -> RunSummary {
    let PoolOpts {
        threads,
        quiet,
        only_vulnerable,
    } = pool;
    let threads = threads.max(1);
    let total = targets.len();
    let semaphore = Arc::new(Semaphore::new(threads));
    let host_locks: Arc<Mutex<HostLocks>> = Arc::new(Mutex::new(HashMap::new()));

    let progress = (!quiet && total > 0).then(|| {
        let bar = ProgressBar::new(total as u64);
        bar.set_style(
            ProgressStyle::with_template("{bar:40} {pos}/{len} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        bar
    });

    let detector_id = detector.id();
    let mut join_set: JoinSet<ScanResult> = JoinSet::new();

    let mut summary = RunSummary {
        total: total as u64,
        ..Default::default()
    };

    // Record one finished scan: tally it, print it, and flush it to the sink.
    // Called as results complete (during the spawn loop) so nothing piles up in
    // memory and a crash mid-list never loses finished work.
    // Once the stdout reader goes away (BrokenPipe) we stop writing to it; the
    // `-o` sink is the durable record; while the scan runs to completion.
    let mut stdout_broken = false;
    // A panic row is built here, outside the worker task, so it skips the
    // in-task redaction sweep; redact it with the same pass so a secret caught in
    // a panic payload can't reach the sink/terminal unredacted.
    let redaction = Arc::clone(&client.redaction);
    let mut record = |joined: Result<ScanResult, tokio::task::JoinError>| {
        let result = match joined {
            Ok(result) => result,
            Err(join_err) => {
                let mut row = panic_result(detector_id, &join_err);
                redaction.redact_result(&mut row);
                row
            }
        };
        match result.vulnerable {
            Some(true) => summary.vulnerable += 1,
            Some(false) => summary.not_vulnerable += 1,
            None => summary.unknown += 1,
        }
        if (!quiet || result.vulnerable == Some(true)) && !stdout_broken {
            if let Err(e) = print_result(progress.as_ref(), &result) {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    stdout_broken = true; // reader gone: benign, keep scanning
                } else if !summary.output_error {
                    // A real write failure (e.g. full disk). Record it once so
                    // the run exits non-zero, and keep going to finish the -o
                    // report, but never claim success.
                    summary.output_error = true;
                    let _ = writeln!(std::io::stderr(), "error: writing results to stdout: {e}");
                }
            }
        }
        if let Some(sink) = sink.as_deref_mut() {
            if !only_vulnerable || result.vulnerable == Some(true) {
                sink.write(&result);
            }
        }
        if let Some(bar) = &progress {
            bar.inc(1);
        }
    };

    for target in targets {
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        let detector = Arc::clone(&detector);
        let client = Arc::clone(&client);
        let host_locks = Arc::clone(&host_locks);
        let opts = opts.clone();

        join_set.spawn(async move {
            let _permit = permit;
            let lock = {
                let mut map = host_locks.lock().await;
                Arc::clone(
                    map.entry(host_key(&target))
                        .or_insert_with(|| Arc::new(Mutex::new(()))),
                )
            };
            let _host_guard = lock.lock().await;
            let outcome = detector.scan(&target, &client, &opts).await;
            let mut row = ScanResult::from_outcome(&target, detector.id(), outcome);
            client.redaction.redact_result(&mut row);
            row
        });

        // Flush whatever has finished so far without blocking the launch loop.
        while let Some(joined) = join_set.try_join_next() {
            record(joined);
        }
    }

    // Drain the tasks still running after the last launch. `record`'s borrows on
    // `progress`/`summary` end at its last call here (NLL), freeing them below.
    while let Some(joined) = join_set.join_next().await {
        record(joined);
    }

    if let Some(bar) = progress {
        bar.finish_and_clear();
    }

    summary
}

/// Print one result line, routing through the bar so it does not corrupt the
/// progress display when one is active.
/// Write one result line to stdout, returning the I/O result so the caller can
/// tell a benign `BrokenPipe` (reader closed) from a real write failure. Uses
/// `writeln!` rather than `println!` so a closed pipe never panics the worker
/// and aborts the run before the `-o` report is flushed.
fn print_result(bar: Option<&ProgressBar>, result: &ScanResult) -> std::io::Result<()> {
    let line = format_line(result);
    match bar {
        Some(bar) => bar.suspend(|| writeln!(std::io::stdout(), "{line}")),
        None => writeln!(std::io::stdout(), "{line}"),
    }
}

/// `[VERDICT] host; reason/error`.
fn format_line(result: &ScanResult) -> String {
    let verdict = &result.verdict;
    let host = &result.host;
    match (&result.error, &result.reason) {
        (Some(err), _) => format!("[{verdict}] {host} — {err}"),
        (None, Some(reason)) => format!("[{verdict}] {host} — {reason}"),
        (None, None) => format!("[{verdict}] {host}"),
    }
}

/// Build an `ERROR` result for a scan that panicked.
fn panic_result(detector_id: &str, join_err: &tokio::task::JoinError) -> ScanResult {
    ScanResult {
        host: "<unknown>".to_string(),
        detector: detector_id.to_string(),
        vulnerable: None,
        verdict: "ERROR".to_string(),
        status_code: None,
        reason: Some("scan task panicked".to_string()),
        error: Some(format!("panic: {join_err}")),
        tested_url: String::new(),
        extra: serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::{HttpConfig, DEFAULT_USER_AGENT};
    use crate::core::report::State;
    use async_trait::async_trait;

    #[test]
    fn merging_runs_adds_each_count_and_preserves_output_errors() {
        let mut summary = RunSummary::default();
        for output_error in [true, false] {
            summary.merge(RunSummary {
                total: 6,
                vulnerable: 1,
                not_vulnerable: 2,
                unknown: 3,
                output_error,
            });
            assert!(summary.output_error);
        }
        assert_eq!(summary.total, 12);
        assert_eq!(summary.vulnerable, 2);
        assert_eq!(summary.not_vulnerable, 4);
        assert_eq!(summary.unknown, 6);
    }

    /// Verdict by host suffix; `panic.test` panics so we exercise capture.
    struct MockDetector;

    #[async_trait]
    impl Detector for MockDetector {
        fn id(&self) -> &'static str {
            "mock"
        }
        fn default_paths(&self) -> &[&str] {
            &["/"]
        }
        async fn scan(&self, target: &Target, _: &HttpClient, _: &ScanOpts) -> DetectorOutcome {
            let host = target.url().host_str().unwrap_or("");
            if host == "panic.test" {
                panic!("boom");
            }
            let state = match host {
                "vuln.test" => State::Vulnerable,
                "safe.test" => State::NotVulnerable,
                _ => State::Unknown,
            };
            let mut outcome = DetectorOutcome::new(state, "MOCK", target.url().as_str());
            if state == State::Unknown {
                outcome = outcome.with_reason("undecided");
            }
            outcome
        }
    }

    use crate::core::detector::DetectorOutcome;
    use crate::core::output::{Format, ResultSink, RunMeta};

    fn client() -> Arc<HttpClient> {
        Arc::new(HttpClient::new(HttpConfig {
            user_agent: DEFAULT_USER_AGENT.to_string(),
            ..Default::default()
        }))
    }

    fn targets(hosts: &[&str]) -> Vec<Target> {
        hosts
            .iter()
            .map(|h| Target::parse(&format!("https://{h}/")).unwrap())
            .collect()
    }

    fn meta() -> RunMeta {
        RunMeta {
            tool_version: "test",
            git_sha: None,
            started_at: "t".to_string(),
            options: serde_json::Value::Null,
        }
    }

    /// Scan into an ndjson sink and return the written result rows (the
    /// metadata/summary lines are dropped).
    async fn scan_to_ndjson(
        hosts: &[&str],
        pool: PoolOpts,
    ) -> (Vec<serde_json::Value>, RunSummary) {
        // Key the temp file on the host set (not its length) so tests running
        // in parallel never share a path.
        let path = std::env::temp_dir().join(format!(
            "x2s-pool-{}-{}.ndjson",
            hosts.join("_"),
            std::process::id()
        ));
        let mut sink = ResultSink::new(&path, Format::Ndjson, &meta()).unwrap();
        let summary = scan_targets(
            Arc::new(MockDetector),
            targets(hosts),
            client(),
            ScanOpts::default(),
            pool,
            Some(&mut sink),
        )
        .await;
        sink.finish(&summary).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let rows = text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v.get("verdict").is_some()) // results carry a verdict
            .collect();
        (rows, summary)
    }

    #[tokio::test]
    async fn counts_every_outcome_and_writes_nothing_without_a_sink() {
        let summary = scan_targets(
            Arc::new(MockDetector),
            targets(&["vuln.test", "safe.test", "unknown.test"]),
            client(),
            ScanOpts::default(),
            PoolOpts {
                threads: 2,
                quiet: true,
                only_vulnerable: false,
            },
            None, // no -o → no sink, nothing written or held
        )
        .await;
        assert_eq!(summary.total, 3);
        assert_eq!(summary.vulnerable, 1);
        assert_eq!(summary.not_vulnerable, 1);
        assert_eq!(summary.unknown, 1);
    }

    #[tokio::test]
    async fn only_vulnerable_filters_written_rows() {
        let (rows, _) = scan_to_ndjson(
            &["vuln.test", "safe.test"],
            PoolOpts {
                threads: 4,
                quiet: true,
                only_vulnerable: true,
            },
        )
        .await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["vulnerable"], true);
    }

    #[tokio::test]
    async fn a_panicking_host_becomes_error_not_an_abort() {
        let (rows, summary) = scan_to_ndjson(
            &["vuln.test", "panic.test"],
            PoolOpts {
                threads: 2,
                quiet: true,
                only_vulnerable: false,
            },
        )
        .await;
        // The run survives the panic: both hosts accounted for.
        assert_eq!(summary.total, 2);
        assert_eq!(summary.vulnerable, 1);
        assert_eq!(summary.unknown, 1, "panic counted as undecided");
        assert!(rows.iter().any(|r| r["verdict"] == "ERROR"));
    }
}
