//! End-to-end mock test for the react safe-check detector: a local listener
//! returns crafted responses and the full `scan()` path is asserted.
//! Never points at an external host.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use x2shell_scanner::core::detector::{Detector, ScanOpts};
use x2shell_scanner::core::http::{HttpClient, HttpConfig, HttpRequest};
use x2shell_scanner::core::report::State;
use x2shell_scanner::core::targets::Target;
use x2shell_scanner::react::detect::evaluate_safe_check;
use x2shell_scanner::react::payload::NEXT_ACTION_ID;
use x2shell_scanner::react::ReactDetector;

async fn serve_once(response: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 8192];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(response).await;
            let _ = sock.flush().await;
        }
    });
    port
}

#[tokio::test]
async fn redirect_retest_requires_a_confirmed_terminal_url() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut chunk = [0u8; 512];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    return;
                }
                head.extend_from_slice(&chunk[..n]);
            }
            let path = String::from_utf8_lossy(&head);
            let location = match path.split_whitespace().nth(1).unwrap() {
                "/one" => Some("/two"),
                "/two" => Some("/final"),
                "/loop" | "/stuck" => Some("/stuck"),
                "/final" => None,
                other => panic!("unexpected path {other}"),
            };
            let reply = match location {
                Some(loc) => {
                    format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\n\r\n")
                }
                None => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_owned(),
            };
            sock.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    let client = client();
    for (path, limit, expected) in [
        ("/one", 1, None),
        ("/one", 2, Some("/final")),
        ("/loop", 4, None),
    ] {
        let target = Target::parse(&format!("http://127.0.0.1:{port}{path}")).unwrap();
        let result =
            x2shell_scanner::react::redirect::resolve_same_host(&client, &target, limit).await;
        assert_eq!(result.as_ref().map(|t| t.url().path()), expected);
    }
    server.abort();
}

fn client() -> HttpClient {
    HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(5),
        ..Default::default()
    })
}

#[cfg(feature = "active-confirm")]
#[tokio::test]
async fn active_mode_reports_vulnerable_on_reflected_marker() {
    // A vulnerable build reflects the benign marker into X-Action-Redirect.
    let port = serve_once(
        b"HTTP/1.1 303 See Other\r\nX-Action-Redirect: https://x/login?a=11111&b=2\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let outcome = ReactDetector::active(Some(1), false)
        .scan(&target, &client(), &ScanOpts::default())
        .await;

    assert_eq!(outcome.state, State::Vulnerable);
    assert_eq!(outcome.extra["mode"], "active");
}

#[tokio::test]
async fn safe_check_reports_vulnerable_on_500_marker() {
    // Body is exactly 15 bytes: E{"digest":"x"}
    let port = serve_once(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/x-component\r\nContent-Length: 15\r\n\r\nE{\"digest\":\"x\"}",
    )
    .await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let outcome = ReactDetector::safe_check()
        .scan(&target, &client(), &ScanOpts::default())
        .await;

    assert_eq!(outcome.state, State::Vulnerable);
    assert_eq!(outcome.status_code, Some(500));
    assert_eq!(outcome.extra["cve"], "CVE-2025-55182");
}

#[tokio::test]
async fn safe_check_vercel_host_is_unknown_not_negative() {
    // 500 + marker but Server: vercel → CDN-masked → cannot confirm → Unknown.
    let port = serve_once(
        b"HTTP/1.1 500 Internal Server Error\r\nServer: vercel\r\nContent-Length: 11\r\n\r\nE{\"digest\"}",
    )
    .await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let outcome = ReactDetector::safe_check()
        .scan(&target, &client(), &ScanOpts::default())
        .await;

    assert_eq!(outcome.state, State::Unknown);
}

#[tokio::test]
async fn connection_error_is_unknown() {
    // Nothing listening → connect error describes the check, not the asset → Unknown.
    let target = Target::parse("http://127.0.0.1:1/").unwrap();

    let outcome = ReactDetector::safe_check()
        .scan(&target, &client(), &ScanOpts::default())
        .await;

    assert_eq!(outcome.state, State::Unknown);
    assert!(outcome.error.is_some());
}

/// A mock that returns the vulnerable signature **only** for a well-formed
/// safe-check request (POST, the exact `Next-Action` id, the flight body `[{}]`).
/// A broken or placeholder probe gets a benign 200, so a test that still sees
/// VULNERABLE proves the shipped payload is well-formed — not just that the mock
/// says so (the payload-integrity requirement).
async fn serve_validating() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let head_end = loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => return,
                    }
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let lower = head.to_lowercase();
                let cl = lower
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
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

                let well_formed = head.starts_with("POST ")
                    && lower.contains(&format!("next-action: {}", NEXT_ACTION_ID.to_lowercase()))
                    && body == b"[{}]";
                let resp: &[u8] = if well_formed {
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/x-component\r\nContent-Length: 15\r\n\r\nE{\"digest\":\"x\"}"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/x-component\r\nContent-Length: 2\r\n\r\nok"
                };
                let _ = sock.write_all(resp).await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn safe_check_requires_a_well_formed_payload() {
    // The mock only emits the digest signature for a correct probe. Seeing
    // VULNERABLE proves the shipped payload is well-formed; a broken/placeholder
    // probe would get a 200 and flip this to not-vulnerable.
    let port = serve_validating().await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let outcome = ReactDetector::safe_check()
        .scan(&target, &client(), &ScanOpts::default())
        .await;
    assert_eq!(outcome.state, State::Vulnerable);
}

#[tokio::test]
async fn validating_mock_rejects_a_broken_probe() {
    // Guards against the test above being vacuous: a malformed probe must NOT
    // elicit the signature from the same mock.
    let port = serve_validating().await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let broken = HttpRequest {
        method: "POST".into(),
        headers: vec![("Next-Action".into(), "deadbeef".into())],
        body: b"BROKEN".to_vec(),
    };
    let resp = client().send(&target, broken).await.unwrap();
    assert_eq!(evaluate_safe_check(&resp).state, State::NotVulnerable);
}

/// A mock that 302-redirects `/` to `/final`, answers the HEAD chain so the
/// final URL resolves, then drops the connection on the final POST retest —
/// simulating a redirect into an endpoint that fails verification.
async fn serve_redirect_then_drop() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let head_end = loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => return,
                    }
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let mut parts = head.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                // Drain any declared body.
                let cl = head
                    .to_lowercase()
                    .split("\r\n")
                    .find_map(|l| {
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().to_string())
                    })
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut got = buf[head_end..].len();
                while got < cl {
                    match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => got += n,
                        Err(_) => break,
                    }
                }

                if method == "POST" && path == "/final" {
                    // The failing retest: drop without responding.
                    return;
                }
                let resp: &[u8] = if path == "/final" {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                } else {
                    b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n"
                };
                let _ = sock.write_all(resp).await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn redirect_then_failed_retest_is_inconclusive() {
    // Original 302 → /final resolves, but the final POST retest fails. The report
    // must be INCONCLUSIVE with the attempted URL and the error — never the
    // pre-redirect negative.
    let port = serve_redirect_then_drop().await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let opts = ScanOpts {
        follow_redirects: true,
        verbose: false,
        ..ScanOpts::default()
    };
    let outcome = ReactDetector::safe_check()
        .scan(&target, &client(), &opts)
        .await;

    assert_eq!(outcome.state, State::Unknown);
    assert!(outcome.error.is_some(), "the retest error must be recorded");
    assert!(
        outcome.tested_url.ends_with("/final"),
        "tested_url must be the attempted final URL, got {}",
        outcome.tested_url
    );
    // The final URL never produced a response, so its status must be null — not
    // the pre-redirect 302's status.
    assert_eq!(outcome.status_code, None);
}
