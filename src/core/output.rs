//! Output sinks: write results to a file in the chosen format, flushing each row
//! as it completes so a crash mid-list never loses finished work.
//!
//! Formats: `json` (one object, results streamed into an array with the run
//! summary appended at the end), `ndjson` (a metadata line, one result per line,
//! a trailing summary line), `sarif` (SARIF 2.1.0 for SOC / code-scanning
//! ingestion), and `csv` (a flat table). Per-detector evidence already rides in
//! each result's flattened `extra`, redacted by the detector that produced it.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use serde_json::{json, Value};

use super::concurrency::RunSummary;
use super::report::ScanResult;

/// Output format for `-o`, selected by `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Ndjson,
    Sarif,
    Csv,
}

/// Run metadata recorded at the top of the output. `options` is a **sanitized**
/// record of the verdict-affecting flags; never the raw argv, never secrets.
#[derive(Debug, Clone)]
pub struct RunMeta {
    pub tool_version: &'static str,
    pub git_sha: Option<&'static str>,
    pub started_at: String,
    pub options: Value,
}

impl RunMeta {
    /// The metadata as a JSON object (shared by the json/ndjson/sarif headers).
    fn to_value(&self) -> Value {
        json!({
            "tool_version": self.tool_version,
            "git_sha": self.git_sha,
            "started_at": self.started_at,
            "options": self.options,
        })
    }
}

/// A file sink that writes results incrementally. Open with [`ResultSink::new`],
/// feed each row to [`ResultSink::write`], then call [`ResultSink::finish`].
pub enum ResultSink {
    Stream(StreamSink),
    // Boxed: a `csv::Writer` is much larger than `StreamSink`.
    Csv(Box<CsvSink>),
}

impl ResultSink {
    /// Open `path` and write the format header. The first I/O error (open or
    /// header) is returned; later write errors are latched and surfaced by
    /// [`ResultSink::finish`].
    pub fn new(path: &Path, format: Format, meta: &RunMeta) -> io::Result<Self> {
        match format {
            Format::Csv => Ok(ResultSink::Csv(Box::new(CsvSink::new(path)?))),
            other => Ok(ResultSink::Stream(StreamSink::new(path, other, meta)?)),
        }
    }

    /// Write one result and flush it to disk. A latched error makes this a no-op
    /// so one bad write does not spam; the error resurfaces at `finish`.
    pub fn write(&mut self, result: &ScanResult) {
        match self {
            ResultSink::Stream(s) => s.write(result),
            ResultSink::Csv(s) => s.write(result),
        }
    }

    /// Write the footer (totals + summary) and flush. Returns the first error
    /// seen across the whole run, if any (→ exit code 3 at the call site).
    pub fn finish(self, summary: &RunSummary) -> io::Result<()> {
        match self {
            ResultSink::Stream(s) => s.finish(summary),
            ResultSink::Csv(s) => s.finish(),
        }
    }
}

/// Which JSON-family layout a [`StreamSink`] produces.
#[derive(Debug, Clone, Copy)]
enum Style {
    Json,
    Ndjson,
    Sarif,
}

/// Streams the json / ndjson / sarif formats: header, then one element per
/// result flushed as it arrives, then a footer.
pub struct StreamSink {
    w: BufWriter<File>,
    style: Style,
    count: u64,
    wrote_elem: bool,
    err: Option<io::Error>,
}

impl StreamSink {
    fn new(path: &Path, format: Format, meta: &RunMeta) -> io::Result<Self> {
        let style = match format {
            Format::Ndjson => Style::Ndjson,
            Format::Sarif => Style::Sarif,
            _ => Style::Json,
        };
        let mut w = BufWriter::new(File::create(path)?);
        write_header(&mut w, style, meta)?;
        w.flush()?;
        Ok(Self {
            w,
            style,
            count: 0,
            wrote_elem: false,
            err: None,
        })
    }

    fn write(&mut self, result: &ScanResult) {
        if self.err.is_some() {
            return;
        }
        if let Err(e) = self.write_inner(result) {
            self.err = Some(e);
        }
    }

    fn write_inner(&mut self, result: &ScanResult) -> io::Result<()> {
        match self.style {
            Style::Ndjson => {
                serde_json::to_writer(&mut self.w, result)?;
                self.w.write_all(b"\n")?;
            }
            Style::Json => {
                if self.wrote_elem {
                    self.w.write_all(b",")?;
                }
                serde_json::to_writer(&mut self.w, result)?;
            }
            Style::Sarif => {
                if self.wrote_elem {
                    self.w.write_all(b",")?;
                }
                serde_json::to_writer(&mut self.w, &sarif_result(result))?;
            }
        }
        self.wrote_elem = true;
        self.count += 1;
        self.w.flush()
    }

    fn finish(mut self, summary: &RunSummary) -> io::Result<()> {
        if let Some(e) = self.err {
            return Err(e);
        }
        let summary_json = summary_value(summary);
        match self.style {
            Style::Ndjson => {
                let footer = json!({ "summary": summary_json, "total_results": self.count });
                serde_json::to_writer(&mut self.w, &footer)?;
                self.w.write_all(b"\n")?;
            }
            Style::Json => {
                write!(self.w, "],\"total_results\":{},\"summary\":", self.count)?;
                serde_json::to_writer(&mut self.w, &summary_json)?;
                self.w.write_all(b"}")?;
            }
            Style::Sarif => {
                // Close results array, run, runs array, root object.
                self.w.write_all(b"]}]}")?;
            }
        }
        self.w.flush()
    }
}

fn write_header(w: &mut impl Write, style: Style, meta: &RunMeta) -> io::Result<()> {
    match style {
        Style::Ndjson => {
            let line = json!({ "meta": meta.to_value() });
            serde_json::to_writer(&mut *w, &line)?;
            w.write_all(b"\n")
        }
        Style::Json => {
            // Open the root object and the results array; totals/summary close it.
            w.write_all(b"{\"meta\":")?;
            serde_json::to_writer(&mut *w, &meta.to_value())?;
            w.write_all(b",\"results\":[")
        }
        Style::Sarif => {
            // Write the run skeleton by hand and leave the results array open to
            // stream into. Building the whole object with serde and trimming its
            // tail is fragile; serde_json sorts object keys, so `runs` is not
            // guaranteed to be the last key.
            let driver = json!({ "driver": {
                "name": meta.tool_version_driver_name(),
                "version": meta.tool_version,
            }});
            w.write_all(
                b"{\"version\":\"2.1.0\",\
                  \"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\
                  \"runs\":[{\"tool\":",
            )?;
            serde_json::to_writer(&mut *w, &driver)?;
            w.write_all(b",\"properties\":")?;
            serde_json::to_writer(&mut *w, &meta.to_value())?;
            w.write_all(b",\"results\":[")
        }
    }
}

impl RunMeta {
    fn tool_version_driver_name(&self) -> &'static str {
        env!("CARGO_PKG_NAME")
    }
}

/// Map one result into a minimal SARIF `result` object.
fn sarif_result(r: &ScanResult) -> Value {
    // SARIF level: vulnerable → error, demonstrated-safe → note, undecided → warning.
    let level = match r.vulnerable {
        Some(true) => "error",
        Some(false) => "note",
        None => "warning",
    };
    let text = r
        .reason
        .as_deref()
        .or(r.error.as_deref())
        .unwrap_or(&r.verdict);
    json!({
        "ruleId": format!("x2shell/{}", r.detector),
        "level": level,
        "message": { "text": format!("{}: {text}", r.verdict) },
        "locations": [{
            "physicalLocation": { "artifactLocation": { "uri": r.tested_url } }
        }],
        "properties": {
            "host": r.host,
            "vulnerable": r.vulnerable,
            "status_code": r.status_code,
        },
    })
}

fn summary_value(s: &RunSummary) -> Value {
    json!({
        "total": s.total,
        "vulnerable": s.vulnerable,
        "not_vulnerable": s.not_vulnerable,
        "inconclusive": s.unknown,
    })
}

/// Flat CSV table of the common result fields. Run metadata does not fit a flat
/// table, so it is omitted here (it still goes to the stderr summary); the JSON
/// family carries it.
pub struct CsvSink {
    w: csv::Writer<File>,
    err: Option<io::Error>,
}

impl CsvSink {
    fn new(path: &Path) -> io::Result<Self> {
        let mut w = csv::Writer::from_path(path).map_err(csv_io)?;
        w.write_record([
            "host",
            "detector",
            "vulnerable",
            "verdict",
            "status_code",
            "reason",
            "error",
            "tested_url",
        ])
        .map_err(csv_io)?;
        w.flush()?;
        Ok(Self { w, err: None })
    }

    fn write(&mut self, r: &ScanResult) {
        if self.err.is_some() {
            return;
        }
        if let Err(e) = self.write_inner(r) {
            self.err = Some(e);
        }
    }

    fn write_inner(&mut self, r: &ScanResult) -> io::Result<()> {
        let vulnerable = match r.vulnerable {
            Some(true) => "true",
            Some(false) => "false",
            None => "",
        };
        let status = r.status_code.map(|c| c.to_string()).unwrap_or_default();
        // Neutralize spreadsheet formula injection on the free-text / URL fields
        // (reason/error carry detector- and server-influenced text): this CSV is
        // meant for SOC/spreadsheet ingestion, where a leading =/+/-/@ would run.
        let host = csv_safe(&r.host);
        let verdict = csv_safe(&r.verdict);
        let reason = csv_safe(r.reason.as_deref().unwrap_or(""));
        let error = csv_safe(r.error.as_deref().unwrap_or(""));
        let tested = csv_safe(&r.tested_url);
        self.w
            .write_record([
                &*host,
                &r.detector,
                vulnerable,
                &*verdict,
                &status,
                &*reason,
                &*error,
                &*tested,
            ])
            .map_err(csv_io)?;
        // csv buffers internally; flush each row so a crash keeps finished rows.
        self.w.flush()
    }

    fn finish(mut self) -> io::Result<()> {
        if let Some(e) = self.err {
            return Err(e);
        }
        self.w.flush()
    }
}

/// Flatten a `csv::Error` into an `io::Error` so the sink has one error type.
fn csv_io(e: csv::Error) -> io::Error {
    io::Error::other(e)
}

/// Prefix a `'` when a CSV field starts with a spreadsheet formula trigger
/// (`= + - @`, or a leading tab/CR that some apps treat the same), so opening the
/// file in Excel/Sheets renders it as text instead of executing it. CWE-1236.
fn csv_safe(s: &str) -> std::borrow::Cow<'_, str> {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        std::borrow::Cow::Owned(format!("'{s}"))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::report::State;

    #[test]
    fn csv_safe_neutralizes_formula_triggers_only() {
        assert_eq!(csv_safe("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")");
        assert_eq!(csv_safe("+1"), "'+1");
        assert_eq!(csv_safe("-cmd"), "'-cmd");
        assert_eq!(csv_safe("@SUM"), "'@SUM");
        // Ordinary text is left untouched (borrowed, not reallocated).
        assert!(matches!(
            csv_safe("VULNERABLE"),
            std::borrow::Cow::Borrowed(_)
        ));
        assert_eq!(csv_safe("http://h/x"), "http://h/x");
    }

    fn meta() -> RunMeta {
        RunMeta {
            tool_version: "0.0.0-test",
            git_sha: Some("deadbee"),
            started_at: "2026-11-25T00:00:00Z".to_string(),
            options: json!({ "detector": "php", "threads": 10 }),
        }
    }

    fn result(host: &str, state: State) -> ScanResult {
        ScanResult {
            host: host.to_string(),
            detector: "php".to_string(),
            vulnerable: state_vuln(state),
            verdict: "INCONCLUSIVE".to_string(),
            status_code: Some(500),
            reason: Some("no signal".to_string()),
            error: None,
            tested_url: format!("https://{host}/index.php"),
            extra: Value::Null,
        }
    }

    fn state_vuln(s: State) -> Option<bool> {
        match s {
            State::Vulnerable => Some(true),
            State::NotVulnerable => Some(false),
            State::Unknown => None,
        }
    }

    fn summary() -> RunSummary {
        RunSummary {
            total: 2,
            vulnerable: 1,
            not_vulnerable: 0,
            unknown: 1,
            ..Default::default()
        }
    }

    fn write_all(format: Format) -> String {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("x2s-out-{:?}-{}.out", format, std::process::id()));
        {
            let mut sink = ResultSink::new(&path, format, &meta()).unwrap();
            sink.write(&result("a.test", State::Vulnerable));
            sink.write(&result("b.test", State::Unknown));
            sink.finish(&summary()).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        text
    }

    #[test]
    fn json_is_valid_and_carries_meta_and_summary() {
        let text = write_all(Format::Json);
        let v: Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(v["meta"]["git_sha"], "deadbee");
        assert_eq!(v["total_results"], 2);
        assert_eq!(v["summary"]["vulnerable"], 1);
        assert_eq!(v["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn ndjson_has_meta_line_results_and_summary_line() {
        let text = write_all(Format::Ndjson);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "meta + 2 results + summary");
        let meta: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(meta["meta"]["tool_version"], "0.0.0-test");
        let last: Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(last["total_results"], 2);
        // Every line is valid JSON on its own.
        for l in &lines {
            serde_json::from_str::<Value>(l).expect("each ndjson line is json");
        }
    }

    #[test]
    fn sarif_is_valid_201_with_one_result_per_host() {
        let text = write_all(Format::Sarif);
        let v: Value = serde_json::from_str(&text).expect("valid sarif json");
        assert_eq!(v["version"], "2.1.0");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error"); // vulnerable
        assert_eq!(results[1]["level"], "warning"); // undecided
    }

    #[test]
    fn csv_has_header_and_a_row_per_result() {
        let text = write_all(Format::Csv);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 rows");
        assert!(lines[0].starts_with("host,detector,vulnerable"));
        assert!(lines[1].contains("a.test"));
        assert!(lines[1].contains("true"));
    }
}
