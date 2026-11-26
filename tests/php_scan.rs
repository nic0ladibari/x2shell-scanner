//! End-to-end mock tests for the php detector's active path. A local
//! listener drains each request body fully (proving the streamed 1 MiB probe
//! reaches the wire) and returns canned responses per connection. The
//! control connection comes first, then one probe connection.
//! Never points at an external host.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use x2shell_scanner::core::detector::{Detector, ScanOpts};
use x2shell_scanner::core::http::{HttpClient, HttpConfig};
use x2shell_scanner::core::report::State;
use x2shell_scanner::core::targets::{Scope, Target};
use x2shell_scanner::php::detect::Sapi;
use x2shell_scanner::php::PhpDetector;

/// Serve `responses[i]` on the i-th accepted connection, after fully draining
/// that request (headers + Content-Length body). Returns the bound port and the
/// total request-body bytes received across all connections.
async fn serve(responses: Vec<&'static [u8]>) -> (u16, Arc<std::sync::atomic::AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let received_task = received.clone();

    tokio::spawn(async move {
        for resp in responses {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let body_len = drain_request(&mut sock).await;
            received_task.fetch_add(body_len, std::sync::atomic::Ordering::Relaxed);
            let _ = sock.write_all(resp).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        }
    });

    (port, received)
}

/// Read one HTTP request: consume headers, then exactly Content-Length body
/// bytes. Returns the body byte count read.
async fn drain_request(sock: &mut tokio::net::TcpStream) -> u64 {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    // Read until end of header section.
    let header_end = loop {
        match sock.read(&mut tmp).await {
            Ok(0) => return 0,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return 0,
        }
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let content_length = parse_content_length(&buf[..header_end]).unwrap_or(0);
    let mut body_read = buf.len().saturating_sub(header_end) as u64;
    while body_read < content_length {
        match sock.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => body_read += n as u64,
            Err(_) => break,
        }
    }
    body_read
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_content_length(headers: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(headers);
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

fn client() -> HttpClient {
    HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(10),
        ..Default::default()
    })
}

async fn run(responses: Vec<&'static [u8]>, sapi: Sapi) -> (State, u64) {
    let (port, received) = serve(responses).await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/index.php")).unwrap();
    let outcome = PhpDetector { sapi, active: true }
        .scan(&target, &client(), &ScanOpts::default())
        .await;
    (
        outcome.state,
        received.load(std::sync::atomic::Ordering::Relaxed),
    )
}

const CONTROL_PREFIX_VER: &[u8] =
    b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.26\r\nContent-Length: 4\r\n\r\nokay";
const CONTROL_FIXED_VER: &[u8] =
    b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.27\r\nContent-Length: 4\r\n\r\nokay";
const CONTROL_NO_VER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nokay";
const EMPTY_500: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";

#[tokio::test]
async fn low_impact_overrides_an_active_php_detector() {
    let (port, _) = serve(vec![CONTROL_NO_VER]).await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/index.php")).unwrap();
    let opts = ScanOpts {
        low_impact: true,
        heavy: Some(Arc::new(tokio::sync::Semaphore::new(0))),
        ..Default::default()
    };
    let detector = PhpDetector {
        sapi: Sapi::Auto,
        active: true,
    };
    let client = client();
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        detector.scan(&target, &client, &opts),
    )
    .await
    .expect("a low-impact scan should never wait for a heavy-probe permit");
    assert_eq!(outcome.state, State::Unknown);
    assert_eq!(outcome.extra["mode"], "passive");
    assert_eq!(outcome.extra["probes"], serde_json::json!([]));
    assert!(outcome.reason.unwrap().contains("low-impact"));
}

#[tokio::test]
async fn prefix_version_is_vulnerable_without_a_heavy_probe() {
    // A pre-fix advertised version already settles the verdict; active mode must
    // SKIP the DoS-risk probe entirely — no ~1 MiB body reaches the wire.
    let (verdict, received) = run(vec![CONTROL_PREFIX_VER], Sapi::ModPhp).await;
    assert_eq!(verdict, State::Vulnerable);
    assert!(
        received < 10_000,
        "probe must be skipped when the version decides, streamed {received} bytes"
    );
}

#[tokio::test]
async fn empty_500_with_patched_version_is_fixed_without_a_probe() {
    // The documented patched-OOM false positive is now avoided up front: a
    // post-fix version decides FIXED and the probe never runs.
    let (verdict, received) = run(vec![CONTROL_FIXED_VER], Sapi::ModPhp).await;
    assert_eq!(verdict, State::NotVulnerable);
    assert!(
        received < 10_000,
        "probe must be skipped, streamed {received} bytes"
    );
}

#[tokio::test]
async fn undisclosed_version_runs_and_streams_the_probe() {
    // No version → the probe is the only signal, so it must stream to the wire;
    // an empty-500 crash with no version stays INCONCLUSIVE (the core guard:
    // indistinguishable from a patched-OOM).
    let (verdict, received) = run(vec![CONTROL_NO_VER, EMPTY_500], Sapi::ModPhp).await;
    assert_eq!(verdict, State::Unknown);
    assert!(
        received > 1_000_000,
        "probe body should have streamed, got {received}"
    );
}

#[tokio::test]
async fn bare_host_targets_the_default_index_php_on_the_wire() {
    // A path-less target must be retargeted to the detector default (/index.php)
    // so the probe lands on the intended resource, not `/`. Assert the path the
    // control request actually carried on the wire.
    use std::sync::Mutex;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_task = captured.clone();

    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // Read the head, capture the request-line path.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let head_end = loop {
                match sock.read(&mut tmp).await {
                    Ok(0) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
                if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
                    break p + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let path = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .map(|s| s.to_string());
            *captured_task.lock().unwrap() = path;
            // Drain the control body, then answer with a disclosed version so the
            // passive scan settles on this one connection.
            let cl = parse_content_length(&buf[..head_end]).unwrap_or(0);
            let mut body = buf[head_end..].len() as u64;
            while body < cl {
                match sock.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => body += n as u64,
                    Err(_) => break,
                }
            }
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.27\r\nContent-Length: 2\r\n\r\nok",
                )
                .await;
            let _ = sock.flush().await;
        }
    });

    // Bare host (no path) → parse_dedup applies the detector default /index.php.
    let host = format!("http://127.0.0.1:{port}");
    let (targets, _) = x2shell_scanner::core::targets::parse_dedup(&[host.as_str()], "/index.php");
    let target = &targets[0];

    let _ = PhpDetector {
        sapi: Sapi::Auto,
        active: false,
    }
    .scan(target, &client(), &ScanOpts::default())
    .await;

    assert_eq!(captured.lock().unwrap().as_deref(), Some("/index.php"));
}

/// Serve canned responses and record each connection's request head (headers).
/// Mirrors `serve` but keeps the heads so a test can assert what was sent.
async fn serve_capturing(
    responses: Vec<&'static [u8]>,
) -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let heads: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let heads_task = heads.clone();

    tokio::spawn(async move {
        for resp in responses {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let head_end = loop {
                match sock.read(&mut tmp).await {
                    Ok(0) => break buf.len(),
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break buf.len(),
                }
                if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
                    break p + 4;
                }
            };
            heads_task
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..head_end]).to_string());
            // Drain any declared body so the socket is consumed.
            let cl = parse_content_length(&buf[..head_end]).unwrap_or(0);
            let mut body = buf[head_end.min(buf.len())..].len() as u64;
            while body < cl {
                match sock.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => body += n as u64,
                    Err(_) => break,
                }
            }
            let _ = sock.write_all(resp).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        }
    });

    (port, heads)
}

#[tokio::test]
async fn follow_redirects_refuses_a_hop_outside_scope() {
    // The control 302s to an out-of-scope host. With a --scope allowlist that
    // does NOT include it, the redirect must not be followed: the out-of-scope
    // host is never contacted, and the verdict falls back to the in-scope
    // control's own version (here a pre-fix version → VULNERABLE).
    let ctrl_302: &'static [u8] =
        b"HTTP/1.1 302 Found\r\nLocation: http://blocked.invalid/x\r\nX-Powered-By: PHP/8.4.26\r\nContent-Length: 0\r\n\r\n";
    // serve: control POST (302), then the HEAD the resolver sends before it
    // checks scope and aborts. `blocked.invalid` gets no listener — proof it is
    // never reached (the test would hang/error if it were).
    let (port, _) = serve(vec![ctrl_302, ctrl_302]).await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/index.php")).unwrap();
    let scope = Scope::from_lines(["127.0.0.1"]).unwrap();
    let outcome = PhpDetector {
        sapi: Sapi::Auto,
        active: false,
    }
    .scan(
        &target,
        &client(),
        &ScanOpts {
            follow_redirects: true,
            scope: Some(Arc::new(scope)),
            ..ScanOpts::default()
        },
    )
    .await;
    assert_eq!(outcome.state, State::Vulnerable);
    assert!(
        outcome.tested_url.contains(&format!("127.0.0.1:{port}")),
        "verdict must stay on the in-scope host, got {}",
        outcome.tested_url
    );
}

#[tokio::test]
async fn follow_redirects_strips_operator_secrets_on_cross_origin_hop() {
    // The different ports represent separate origins. The second server supplies
    // the version used for the verdict and must never receive the first server's credentials.
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_b = listener_b.local_addr().unwrap().port();

    // The final banner contains both a usable version and a synthetic reflected credential.
    let b_head_ok: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let b_control: &'static [u8] =
        b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.27 account=super-secret\r\nContent-Length: 2\r\n\r\nok";

    // B serves: HEAD during resolve (200, ends chain), then the re-baselined
    // control POST. Capture both heads.
    let heads_b: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let heads_task = heads_b.clone();
        tokio::spawn(async move {
            for resp in [b_head_ok, b_control] {
                let (mut sock, _) = match listener_b.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let head_end = loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => break buf.len(),
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => break buf.len(),
                    }
                    if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                heads_task
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..head_end]).to_string());
                let cl = parse_content_length(&buf[..head_end]).unwrap_or(0);
                let mut body = buf[head_end.min(buf.len())..].len() as u64;
                while body < cl {
                    match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => body += n as u64,
                        Err(_) => break,
                    }
                }
                let _ = sock.write_all(resp).await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            }
        });
    }

    // A serves: the control POST (302 → B) and the HEAD during resolve (302 → B).
    let a_302: &'static [u8] = Box::leak(
        format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port_b}/index.php\r\nContent-Length: 0\r\n\r\n")
            .into_bytes()
            .into_boxed_slice(),
    );
    let (port_a, _heads_a) = serve_capturing(vec![a_302, a_302]).await;

    let client = HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(10),
        extra_headers: vec![("authorization".into(), "Bearer super-secret".into())],
        ..Default::default()
    });
    let target = Target::parse(&format!("http://127.0.0.1:{port_a}/index.php")).unwrap();
    let outcome = PhpDetector {
        sapi: Sapi::Auto,
        active: false,
    }
    .scan(
        &target,
        &client,
        &ScanOpts {
            follow_redirects: true,
            ..ScanOpts::default()
        },
    )
    .await;

    // Verdict came from B (patched version) and B never saw the secret.
    assert_eq!(outcome.state, State::NotVulnerable);
    assert_eq!(outcome.extra["powered_by"], "<redacted>");
    let heads = heads_b.lock().unwrap();
    assert_eq!(
        heads.len(),
        2,
        "B should receive the HEAD and the control POST"
    );
    for h in heads.iter() {
        assert!(
            !h.to_ascii_lowercase().contains("authorization"),
            "operator secret leaked cross-origin to B:\n{h}"
        );
    }
}
