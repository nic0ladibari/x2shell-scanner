//! End-to-end mock tests for the node detector.
//!
//! A local server emulates a Node route and decides the response class the way
//! the real runtime would: no Content-Type means the body is never decoded (so
//! it is accepted); `application/json` plus `Content-Encoding: br` is
//! brotli-decoded (valid accepted, malformed rejected); an unsupported encoding
//! is rejected. The large probe's fate is the knob — a vulnerable route accepts
//! it into the valid class, a fixed one rejects it. Never points at an external
//! host.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use x2shell_scanner::core::detector::{Detector, ScanOpts};
use x2shell_scanner::core::http::{HttpClient, HttpConfig};
use x2shell_scanner::core::report::State;
use x2shell_scanner::core::targets::Target;
use x2shell_scanner::node::NodeDetector;

const VALID_RESP: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
const MALFORMED_RESP: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nbad";

/// Spawn the mock Node route; `vuln` decides whether the big probe is accepted.
async fn serve(vuln: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    tokio::spawn(handle(sock, vuln));
                }
                Err(_) => return,
            }
        }
    });
    port
}

async fn handle(mut sock: TcpStream, vuln: bool) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    // Read the request head.
    let head_end = loop {
        match sock.read(&mut tmp).await {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return,
        }
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
    let content_length = header_val(&head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let has_json =
        header_val(&head, "content-type").is_some_and(|v| v.contains("application/json"));
    let is_br = header_val(&head, "content-encoding").as_deref() == Some("br");
    let has_other_encoding = header_val(&head, "content-encoding").is_some_and(|v| v != "br");
    let expect_continue = head.contains("expect: 100-continue");

    if expect_continue {
        let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
        let _ = sock.flush().await;
    }

    // Drain the body (exactly Content-Length bytes).
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        match sock.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    body.truncate(content_length);

    let valid_class = if !has_json {
        true // content-type bypass: body never decoded → accepted
    } else if is_br {
        if expect_continue {
            vuln // the probe: only a vulnerable route lets it through
        } else {
            brotli_ok(&body)
        }
    } else if has_other_encoding {
        false // unsupported encoding → rejected
    } else {
        true
    };

    let resp = if valid_class {
        VALID_RESP
    } else {
        MALFORMED_RESP
    };
    let _ = sock.write_all(resp).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn header_val(lowercased_head: &str, name: &str) -> Option<String> {
    for line in lowercased_head.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn brotli_ok(body: &[u8]) -> bool {
    use std::io::Read;
    let mut out = Vec::new();
    brotli::Decompressor::new(body, 4096)
        .read_to_end(&mut out)
        .is_ok()
}

fn client() -> HttpClient {
    HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(15),
        ..Default::default()
    })
}

async fn scan(port: u16) -> x2shell_scanner::core::detector::DetectorOutcome {
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    NodeDetector
        .scan(&target, &client(), &ScanOpts::default())
        .await
}

#[tokio::test]
async fn vulnerable_route_probe_lands_in_valid_class() {
    let port = serve(true).await;
    let outcome = scan(port).await;
    assert_eq!(outcome.state, State::Vulnerable);
    assert_eq!(outcome.extra["comparison"], "status");
    // The probe reported a full send (23,068,764 bytes) — streaming reached the wire.
    assert_eq!(
        outcome.extra["responses"]["cve_probe"]["bytes_sent"],
        23_068_764u64
    );
}

#[tokio::test]
async fn fixed_route_probe_rejected_is_demonstrated_negative() {
    let port = serve(false).await;
    let outcome = scan(port).await;
    assert_eq!(outcome.state, State::NotVulnerable);
}

#[tokio::test]
async fn low_impact_mode_skips_the_heavy_probe() {
    // A route that WOULD be flagged vulnerable (probe accepted) must, under
    // low_impact (used by `all`), stop before the 23 MiB probe → Unknown, never
    // Vulnerable. If it were Vulnerable, the heavy probe had run.
    let port = serve(true).await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let outcome = NodeDetector
        .scan(
            &target,
            &client(),
            &ScanOpts {
                low_impact: true,
                ..ScanOpts::default()
            },
        )
        .await;
    assert_eq!(outcome.state, State::Unknown);
    assert!(outcome.reason.unwrap().contains("low-impact"));
}

#[tokio::test]
async fn connection_refused_is_inconclusive() {
    // Nothing listening on this port → first stage request errors → INCONCLUSIVE.
    let target = Target::parse("http://127.0.0.1:1/").unwrap();
    let outcome = NodeDetector
        .scan(&target, &client(), &ScanOpts::default())
        .await;
    assert_eq!(outcome.state, State::Unknown);
}

/// Mock that establishes exact-response classes then returns a *truncated*
/// unsupported-encoding control, and records whether the heavy probe (the
/// Expect: 100-continue request) is ever attempted.
async fn serve_truncated_unsupported(
    probe_seen: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let seen = probe_seen.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let head_end = loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => return,
                    }
                    if let Some(p) = find(&buf, b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                if head.contains("expect: 100-continue") {
                    seen.store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = sock
                        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
                let cl = header_val(&head, "content-length")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = buf[head_end..].to_vec();
                while body.len() < cl {
                    match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => body.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                body.truncate(cl);

                let has_json = header_val(&head, "content-type")
                    .is_some_and(|v| v.contains("application/json"));
                let is_br = header_val(&head, "content-encoding").as_deref() == Some("br");
                let other_enc = header_val(&head, "content-encoding").is_some_and(|v| v != "br");

                let resp: &[u8] = if other_enc {
                    // Unsupported control: declare 100 bytes, send 4, then close → truncated.
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nSAME"
                } else if has_json && is_br {
                    if brotli_ok(&body) {
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\nSAME"
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\nDIFF"
                    }
                } else {
                    // stage 1 (no content-type) → valid baseline.
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\nSAME"
                };
                let _ = sock.write_all(resp).await;
                let _ = sock.flush().await;
                // Deliberately do NOT shutdown for the truncated case so the short
                // body + close reads as truncated on the client.
            });
        }
    });
    port
}

#[tokio::test]
async fn truncated_unsupported_control_skips_the_heavy_probe() {
    let probe_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let port = serve_truncated_unsupported(probe_seen.clone()).await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let outcome = NodeDetector
        .scan(&target, &client(), &ScanOpts::default())
        .await;

    assert_eq!(outcome.state, State::Unknown);
    assert!(
        !probe_seen.load(std::sync::atomic::Ordering::Relaxed),
        "the 23 MiB probe must not be sent once the unsupported control is truncated"
    );
}
