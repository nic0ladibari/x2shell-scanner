//! Integration test for the raw HTTP/1.1 client against a local listener that
//! returns crafted responses. Plain HTTP (no TLS) exercises the same hyper read
//! path the detectors rely on: raw status, exact headers, empty-vs-nonempty
//! body, and body-cap truncation. Never points at an external host.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use x2shell_scanner::core::http::{HttpClient, HttpConfig, HttpRequest, ProbeBodySpec, Proxy};
use x2shell_scanner::core::targets::Target;

/// Spawn a one-shot listener that reads the request and writes `response` raw.
/// Returns the bound port.
async fn serve_once(response: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // Drain the request headers so the client's write completes.
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(response).await;
            let _ = sock.flush().await;
        }
    });
    port
}

/// Like `serve_once`, but fully drains the request (headers + Content-Length
/// body) before replying. Needed for `send_counted` tests: a single read then
/// close can RST the client mid-write, which flakes as "connection reset".
async fn serve_once_drain(response: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
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
            let cl = String::from_utf8_lossy(&buf[..head_end])
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
            let _ = sock.write_all(response).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        }
    });
    port
}

fn client() -> HttpClient {
    HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(5),
        ..Default::default()
    })
}

#[test]
fn debug_formatting_omits_configuration_secrets() {
    let config = HttpConfig {
        extra_headers: vec![("X-Private".into(), "header-credential".into())],
        user_agent: "private-agent".into(),
        proxy: Some(Proxy::parse("http://user:proxy-credential@localhost:8080").unwrap()),
        ..Default::default()
    };
    for output in [
        format!("{config:?}"),
        format!("{:#?}", HttpClient::new(config)),
    ] {
        for secret in ["header-credential", "private-agent", "proxy-credential"] {
            assert!(!output.contains(secret));
        }
        assert!(output.contains("extra_header_count"));
    }
}

#[tokio::test]
async fn counted_reports_only_the_final_response_after_early_hints() {
    let reply = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno";
    for expect in [false, true] {
        // If the server returns a final rejection after its hints, the client
        // must leave even this one-byte body unsent while awaiting Continue.
        let body = if expect { vec![b'x'] } else { Vec::new() };
        let port = serve_once(reply).await;
        let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let r = client()
            .send_counted(
                &target,
                "GET",
                &[],
                ProbeBodySpec::Bytes(body),
                expect,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 403);
        assert_eq!(r.body, b"no");
        assert_eq!(r.header("link"), None);
        assert_eq!(r.bytes_sent, 0);
    }
}

/// A mock HTTP proxy: capture the `CONNECT` request, acknowledge the tunnel,
/// then act as the origin and return `origin_response` over it.
async fn serve_http_proxy(origin_response: &'static [u8], seen: Arc<Mutex<String>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match sock.read(&mut tmp).await {
                    Ok(0) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            *seen.lock().unwrap() = String::from_utf8_lossy(&buf).to_string();
            let _ = sock
                .write_all(
                    b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\n",
                )
                .await;
            let _ = sock.flush().await;
            // Read the tunneled request, then reply as the origin would.
            let _ = sock.read(&mut tmp).await;
            let _ = sock.write_all(origin_response).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        }
    });
    port
}

#[tokio::test]
async fn http_proxy_connect_tunnel_reaches_the_origin() {
    let seen = Arc::new(Mutex::new(String::new()));
    let pport = serve_http_proxy(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        seen.clone(),
    )
    .await;
    let proxied = HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(5),
        proxy: Some(Proxy::parse(&format!("http://%75:%70@127.0.0.1:{pport}")).unwrap()),
        ..Default::default()
    });
    // The proxy never really dials this host; it just tunnels to itself.
    let target = Target::parse("http://origin.test:9999/path").unwrap();

    let resp = proxied
        .send(&target, HttpRequest::new("GET"))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"ok");

    let connect = seen.lock().unwrap().clone();
    assert!(
        connect.starts_with("CONNECT origin.test:9999 HTTP/1.1"),
        "CONNECT line wrong: {connect:?}"
    );
    // base64("u:p") == "dTpw" (case-sensitive token).
    assert!(
        connect.contains("Proxy-Authorization: Basic dTpw"),
        "proxy auth header missing: {connect:?}"
    );
}

#[tokio::test]
async fn reads_status_headers_and_body() {
    let port = serve_once(
        b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.27\r\nContent-Length: 5\r\n\r\nhello",
    )
    .await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/index.php")).unwrap();

    let resp = client()
        .send(&target, HttpRequest::new("GET"))
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("x-powered-by"), Some("PHP/8.4.27"));
    assert_eq!(resp.body, b"hello");
    assert!(!resp.body_is_empty());
    assert!(!resp.body_truncated);
}

#[tokio::test]
async fn distinguishes_empty_body_500() {
    // The differential signal php relies on: a 500 with a genuinely empty body.
    let port = serve_once(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n").await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let resp = client()
        .send(&target, HttpRequest::new("POST"))
        .await
        .unwrap();

    assert_eq!(resp.status, 500);
    assert!(resp.body_is_empty());
}

#[tokio::test]
async fn caps_oversized_body_and_flags_truncation() {
    // 10-byte body but a 4-byte cap → truncated to 4, flag set.
    let port = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789").await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let capped = HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(5),
        max_body: 4,
        ..Default::default()
    });
    let resp = capped.send(&target, HttpRequest::new("GET")).await.unwrap();

    assert_eq!(resp.body, b"0123");
    assert!(resp.body_truncated);
}

#[tokio::test]
async fn counted_marks_premature_close_as_truncated() {
    // Declares Content-Length: 100 but sends only 10 bytes then closes. The
    // measured exchange must flag the short body as truncated so exact-response
    // comparison refuses it as evidence.
    let port = serve_once_drain(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789").await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let resp = client()
        .send_counted(
            &target,
            "POST",
            &[],
            ProbeBodySpec::Bytes(b"x".to_vec()),
            false,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    assert!(resp.body_truncated, "a short close must be truncated");
    assert!(resp.body.len() < 100);
}

#[tokio::test]
async fn counted_caps_oversized_content_length_during_read() {
    // Content-Length far above max_body: the client must bound memory at the cap,
    // not accumulate the full declared length first.
    let port =
        serve_once_drain(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nAAAAAAAAAAAAAAAAAAAA")
            .await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let capped = HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(5),
        max_body: 8,
        ..Default::default()
    });
    let resp = capped
        .send_counted(
            &target,
            "POST",
            &[],
            ProbeBodySpec::Bytes(b"x".to_vec()),
            false,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert_eq!(resp.body.len(), 8, "body must be bounded by max_body");
    assert!(resp.body_truncated);
}

#[tokio::test]
async fn counted_errors_on_invalid_chunk_size() {
    // "ZZ" is not a hex chunk size → invalid framing must surface as an error,
    // never be treated as a zero (final) chunk.
    let port =
        serve_once_drain(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\ngarbage\r\n")
            .await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let result = client()
        .send_counted(
            &target,
            "POST",
            &[],
            ProbeBodySpec::Bytes(b"x".to_vec()),
            false,
            Duration::from_secs(1),
        )
        .await;

    assert!(result.is_err(), "invalid chunk framing must be an error");
}

#[tokio::test]
async fn counted_survives_a_huge_chunk_size_without_panic() {
    // A chunk size near usize::MAX must not overflow the position arithmetic
    // (which would panic in debug); it is simply capped as oversized.
    let port = serve_once_drain(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffff0\r\nAAAA",
    )
    .await;
    let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

    let capped = HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(5),
        max_body: 16,
        ..Default::default()
    });
    let resp = capped
        .send_counted(
            &target,
            "POST",
            &[],
            ProbeBodySpec::Bytes(b"x".to_vec()),
            false,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    assert!(
        resp.body_truncated,
        "oversized chunk must be flagged, not panic"
    );
}
