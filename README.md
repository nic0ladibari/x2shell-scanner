# x2shell-scanner

> In the spirit of *«La prima cosa bella»* — Nicola Di Bari.

A Rust command-line tool for assessing PHP, Node.js, and React Server Components endpoints during authorized security reviews. Each check records the URL tested, its verdict, and the reason for that verdict. Inconclusive results are included in the report so reviewers can distinguish an unanswered check from a negative finding.

## Quick start

Build from the repository root with Rust 1.88.0, the version pinned in `rust-toolchain.toml`.

```sh
cargo build --release --locked
./target/release/x2shell-scanner --help
```

For an initial assessment, use `all` to run the low-impact checks. Replace the example URL with an endpoint you are authorized to test.

```sh
./target/release/x2shell-scanner all -u https://app.example.org -o report.json
```

A container build is also available.

```sh
docker build -t x2shell-scanner .
docker run --rm x2shell-scanner --help
```

## Choosing a check

| Command | What it checks | Operational impact |
| --- | --- | --- |
| `all` | PHP version, Node.js control responses, and the React default check | Skips the heavy PHP and Node.js probes. Node.js can return inconclusive when its controls alone cannot settle the result. |
| `php` | The advertised PHP version against the project's fixed-version table for CVE-2026-109618 and CVE-2026-109619 | Passive version assessment by default. The optional active mode can exhaust server memory or terminate a worker. |
| `node` | Differences in how an endpoint handles encoded request bodies for CVE-2026-111497 | The standalone command can send a large request after the initial controls. Use a maintenance window for this mode. |
| `react` | React Server Components response evidence for CVE-2025-55182 | The default build uses the non-executing check. Static HTML, empty responses, and partial representations can leave the result inconclusive. |

In active PHP checks, a patched worker under memory pressure can produce an error response resembling a vulnerable one.

## Targets and scope

Use `-u` for one URL or `-l` for a file containing one host or URL per line. A bare host uses HTTPS. Provide an explicit path when the component is served below the site root.

For a batch assessment, `--scope` restricts requests to the hosts or domains listed in a separate file. An entry includes its subdomains. For example, a scope file containing `staging.example.org` covers that host and `api.staging.example.org`.

```sh
./target/release/x2shell-scanner all -l targets.txt --scope scope.txt \
  --threads 4 --rate 2 --format ndjson -o results.ndjson
```

| Option | Purpose |
| --- | --- |
| `--threads`, `--rate`, `--timeout` | Set concurrent scans, the global request rate per second, and the per-request timeout in seconds. |
| `--max-heavy` | Limit simultaneous heavy probes independently of scan concurrency. |
| `-H`, `--header` | Add a request header. An explicit `Host` must be valid and, when a scope is supplied, within scope. |
| `--proxy` | Route requests through an HTTP or SOCKS5 proxy. TLS certificate verification is enabled by default. |
| `-q`, `--quiet` | Hide progress and print only positive findings to standard output. |
| `--debug` | Write an HTTP trace to standard error. Treat traces and reports as operational data, even with header redaction. |

Redirect following is optional for `php` and `react`. React follows same-origin redirects. PHP checks each redirect against the configured scope and drops operator-supplied headers when the origin changes. For detector-specific options, run a command such as `./target/release/x2shell-scanner php --help`.

## Reading a report

Select `json` (default), `ndjson`, `csv`, or `sarif` with `--format` and write the report with `-o`. JSON includes run metadata, individual results, a result count, and a summary. NDJSON writes one result per line between the metadata and summary records. Use `--only-vulnerable` to limit the saved results to positive findings.

The JSON field `vulnerable` has three possible values.

| Value | Interpretation |
| --- | --- |
| `true` | The detector found evidence consistent with the vulnerability. Review the recorded reason. |
| `false` | The detector obtained evidence supporting a negative result for the tested endpoint. |
| `null` | The evidence was insufficient. Check the reason, HTTP status, and any transport error. |

For automation, exit code **0** means the scan recorded no positive findings. A run in which every result was inconclusive also exits **0**. Read the summary when coverage matters. Exit code **1** indicates at least one positive finding, **2** a usage error, **3** an output failure, and **4** a target or scope error.

### Passive PHP results

The default `php` check reads the `X-Powered-By` response header. These examples show how the advertised version affects the report.

| `X-Powered-By` | Verdict | `vulnerable` |
| --- | --- | --- |
| `PHP/8.4.26` | `VULNERABLE` | `true` |
| `PHP/8.4.28` | `FIXED` | `false` |
| Header absent | `NO SIGNAL` | `null` |

A passive positive identifies an advertised version in the affected range. Check the installed package against the distribution's security advisory, since vendors can backport a fix while keeping the same upstream version. Confirming memory disclosure requires separate evidence.

## Development

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --all-features
```

The test suite uses local HTTP fixtures to exercise verdicts, redirects, transport handling, and report output. It verifies behavior against those fixtures. Deployment-specific conclusions still depend on the endpoint, package version, and configuration.

## Acknowledgments

Thanks to the researchers who discovered and responsibly disclosed the
underlying vulnerabilities, and to the wider security-research community whose
public CVE analysis made an independent detector possible.

On a more personal note, thanks to **Mara Maionchi** for the strength to write
this tool, to **Cristiano Malgioglio** for the immense musical-cultural heritage
that accompanied the coding, and to **Calogero** for supplying the bananas
during engineering — *le ho mangiate tutte, nessuna esclusa… mezza parola.*

## License

Distributed under the [MIT License](./LICENSE).
