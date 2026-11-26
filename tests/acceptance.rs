//! Acceptance matrix, run hermetically as mock fixtures (no containers).
//!
//! Each test is one row of the validation matrix: a local mock reproduces the
//! *response behavior* of a vulnerable or patched target, the detector runs
//! end-to-end, and the tri-state verdict is asserted. The live docker-compose
//! lab under `lab/` reproduces the same rows against real builds; that suite is
//! kept `#[ignore]` so this one never depends on containers.
//!
//! Where the tri-state model supersedes the original matrix wording it is noted
//! inline (a cleanly-rejected probe is a demonstrated negative, not "no signal";
//! a CDN-masked look-alike is inconclusive, not "not vulnerable").

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use x2shell_scanner::core::detector::{Detector, ScanOpts};
use x2shell_scanner::core::http::{HttpClient, HttpConfig};
use x2shell_scanner::core::report::State;
use x2shell_scanner::core::targets::Target;
use x2shell_scanner::node::NodeDetector;
use x2shell_scanner::php::detect::Sapi;
use x2shell_scanner::php::PhpDetector;
use x2shell_scanner::react::ReactDetector;

fn client() -> HttpClient {
    HttpClient::new(HttpConfig {
        timeout: Duration::from_secs(15),
        ..Default::default()
    })
}

async fn target(port: u16) -> Target {
    Target::parse(&format!("http://127.0.0.1:{port}/index.php")).unwrap()
}

/// Read one request: consume headers then exactly Content-Length body bytes.
async fn drain(sock: &mut TcpStream) {
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
}

// ─────────────────────────── php ───────────────────────────

/// Serve `responses[i]` on the i-th accepted connection (control, then probes),
/// each after draining the request.
async fn php_server(responses: Vec<&'static [u8]>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        for resp in responses {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            drain(&mut sock).await;
            let _ = sock.write_all(resp).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        }
    });
    port
}

const CTRL_8426: &[u8] =
    b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.26\r\nContent-Length: 2\r\n\r\nok";
const CTRL_8427: &[u8] =
    b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.27\r\nContent-Length: 2\r\n\r\nok";
const CTRL_NOVER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
const CTRL_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\n404";
const EMPTY_500: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
const RESP_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
const RESP_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\n404";

async fn php_verdict(responses: Vec<&'static [u8]>, sapi: Sapi) -> State {
    let port = php_server(responses).await;
    PhpDetector { sapi, active: true }
        .scan(&target(port).await, &client(), &ScanOpts::default())
        .await
        .state
}

#[tokio::test]
async fn php_vuln_apache_mod_php_is_vulnerable() {
    // pre-fix version + empty-500 crash signal under mod_php.
    let s = php_verdict(vec![CTRL_8426, EMPTY_500], Sapi::ModPhp).await;
    assert_eq!(s, State::Vulnerable);
}

#[tokio::test]
async fn php_fixed_apache_mod_php_is_not_vulnerable() {
    // Same crash signal, but the disclosed version is at the fix → FIXED.
    let s = php_verdict(vec![CTRL_8427, EMPTY_500], Sapi::ModPhp).await;
    assert_eq!(s, State::NotVulnerable);
}

#[tokio::test]
async fn php_fixed_lowmem_no_version_is_inconclusive() {
    // THE critical row: a patched build that OOMs on the probe returns the same
    // empty-500 as a vulnerable one, and with no version header it is
    // indistinguishable → INCONCLUSIVE, never VULNERABLE.
    let s = php_verdict(vec![CTRL_NOVER, EMPTY_500], Sapi::ModPhp).await;
    assert_eq!(s, State::Unknown);
}

#[tokio::test]
async fn php_vuln_fpm_is_vulnerable() {
    // FPM worker death shows up as a front-end 502.
    let s = php_verdict(vec![CTRL_8426, RESP_502], Sapi::Fpm).await;
    assert_eq!(s, State::Vulnerable);
}

#[tokio::test]
async fn php_fixed_fpm_is_not_vulnerable() {
    let s = php_verdict(vec![CTRL_8427, RESP_502], Sapi::Fpm).await;
    assert_eq!(s, State::NotVulnerable);
}

#[tokio::test]
async fn php_non_app_404_is_inconclusive() {
    // No crash signal and no version → cannot decide. The probes escalate (all
    // three), so supply a response per connection.
    let s = php_verdict(vec![CTRL_404, RESP_404, RESP_404, RESP_404], Sapi::Auto).await;
    assert_eq!(s, State::Unknown);
}

// ─────────────────────────── node ───────────────────────────

/// Mock Node route: no Content-Type → accepted; `application/json` + br →
/// brotli-decoded (valid accepted, malformed rejected); unsupported encoding
/// rejected. `vuln` decides whether the large probe is accepted.
async fn node_server(vuln: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(node_handle(sock, Some(vuln)));
        }
    });
    port
}

/// A non-app server that answers 404 to everything.
async fn node_404_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(node_handle(sock, None));
        }
    });
    port
}

/// `decide = None` → always 404. `Some(vuln)` → the Node class logic.
async fn node_handle(mut sock: TcpStream, decide: Option<bool>) {
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
    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
    let cl = head
        .split("\r\n")
        .find_map(|l| {
            l.strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let has_json = head.contains("content-type: application/json");
    let is_br = head.contains("content-encoding: br");
    let other_enc = head.contains("content-encoding:") && !is_br;
    let expect = head.contains("expect: 100-continue");
    if expect {
        let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
        let _ = sock.flush().await;
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < cl {
        match sock.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    body.truncate(cl);

    let resp: &[u8] = match decide {
        None => {
            b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\n404"
        }
        Some(vuln) => {
            let valid = if !has_json {
                true
            } else if is_br {
                if expect {
                    vuln
                } else {
                    brotli_ok(&body)
                }
            } else {
                // An unsupported encoding is rejected; no encoding → accepted.
                !other_enc
            };
            if valid {
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
            } else {
                b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nbad"
            }
        }
    };
    let _ = sock.write_all(resp).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

fn brotli_ok(body: &[u8]) -> bool {
    use std::io::Read;
    let mut out = Vec::new();
    brotli::Decompressor::new(body, 4096)
        .read_to_end(&mut out)
        .is_ok()
}

async fn node_verdict(port: u16) -> State {
    let t = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    NodeDetector
        .scan(&t, &client(), &ScanOpts::default())
        .await
        .state
}

#[tokio::test]
async fn node_vuln_is_vulnerable() {
    let port = node_server(true).await;
    assert_eq!(node_verdict(port).await, State::Vulnerable);
}

#[tokio::test]
async fn node_fixed_is_not_vulnerable() {
    // The probe lands clearly in the malformed class → demonstrated negative
    // (tri-state model; the original matrix called this "NO SIGNAL").
    let port = node_server(false).await;
    assert_eq!(node_verdict(port).await, State::NotVulnerable);
}

#[tokio::test]
async fn node_non_app_404_is_inconclusive() {
    // Every stage returns the same 404 → no two classes → cannot decide.
    let port = node_404_server().await;
    assert_eq!(node_verdict(port).await, State::Unknown);
}

// ─────────────────────────── react ───────────────────────────

async fn react_server(response: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            drain(&mut sock).await;
            let _ = sock.write_all(response).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        }
    });
    port
}

async fn react_verdict(response: &'static [u8]) -> State {
    let port = react_server(response).await;
    let t = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    ReactDetector::safe_check()
        .scan(&t, &client(), &ScanOpts::default())
        .await
        .state
}

#[tokio::test]
async fn react_vuln_is_vulnerable() {
    let s = react_verdict(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/x-component\r\nContent-Length: 15\r\n\r\nE{\"digest\":\"x\"}",
    )
    .await;
    assert_eq!(s, State::Vulnerable);
}

#[tokio::test]
async fn react_fixed_is_not_vulnerable() {
    let s = react_verdict(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/x-component\r\nContent-Length: 2\r\n\r\nok",
    )
    .await;
    assert_eq!(s, State::NotVulnerable);
}

#[tokio::test]
async fn react_cdn_decoy_is_inconclusive() {
    // A vulnerable-looking body behind a CDN header cannot be confirmed →
    // INCONCLUSIVE (tri-state model; the original matrix called this excluded
    // "NOT VULNERABLE").
    let s = react_verdict(
        b"HTTP/1.1 500 Internal Server Error\r\nServer: netlify\r\nContent-Length: 15\r\n\r\nE{\"digest\":\"x\"}",
    )
    .await;
    assert_eq!(s, State::Unknown);
}
