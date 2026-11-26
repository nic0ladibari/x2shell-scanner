//! Raw HTTP/1.1 client.
//!
//! Low-level on purpose: verdicts depend on distinguishing an *empty* body from
//! a non-empty one, seeing raw `502/503/504`, observing a connection reset as a
//! worker death, and reading exact header values; things a high-level client
//! normalizes away. Built on `hyper` 1.x over a `tokio` TCP (optionally TLS)
//! stream, with manual request build and a capped, truncation-aware body read.
//!
//! Redaction is *not* done here: detectors need the real header values to decide
//! (e.g. react reads `X-Action-Redirect`). Redaction happens where evidence is
//! persisted, not where it is read.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};
use hyper::Request;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use super::report::HeaderRedaction;
use super::targets::Target;

/// Default cap on the response body kept in memory (1 MiB).
pub const DEFAULT_MAX_BODY: usize = 1024 * 1024;
/// Default cap on the total header-section size (10 MiB).
pub const DEFAULT_MAX_HEADERS: usize = 10 * 1024 * 1024;
/// Default User-Agent applied when the caller supplies none.
pub const DEFAULT_USER_AGENT: &str = "x2shell-scanner/0.1";

#[derive(Clone)]
pub struct HttpConfig {
    pub timeout: Duration,
    pub max_body: usize,
    pub max_headers: usize,
    /// Disable TLS certificate verification (`-k/--insecure`). Defaults to off.
    pub insecure: bool,
    pub user_agent: String,
    /// Operator-supplied headers (`-H/--header`) applied to every request. They
    /// override the built-in defaults (Host, User-Agent) but are themselves
    /// overridden by a detector's per-request headers, so a `-H` can never
    /// clobber a verdict-critical header (e.g. node's per-stage Content-Type).
    pub extra_headers: Vec<(String, String)>,
    /// Route every connection through this proxy (`--proxy`); `None` = direct.
    pub proxy: Option<Proxy>,
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConfig")
            .field("timeout", &self.timeout)
            .field("max_body", &self.max_body)
            .field("max_headers", &self.max_headers)
            .field("insecure", &self.insecure)
            .field("extra_header_count", &self.extra_headers.len())
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

/// A configured proxy. Credentials live here only to dial; they are never
/// serialized into evidence (metadata records the scheme only).
#[derive(Clone)]
pub enum Proxy {
    /// HTTP proxy: a `CONNECT host:port` tunnel is opened, then the normal
    /// (optionally TLS) exchange runs over it; uniform for http and https targets.
    Http {
        host: String,
        port: u16,
        auth: Option<(String, String)>,
    },
    /// SOCKS5 proxy: the target is dialed through it (the proxy resolves DNS, so
    /// the target hostname never leaks to the local resolver).
    Socks5 {
        host: String,
        port: u16,
        auth: Option<(String, String)>,
    },
}

impl std::fmt::Debug for Proxy {
    /// Never print host or credentials; only the scheme.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Proxy({})", self.scheme())
    }
}

impl Proxy {
    /// Parse a proxy URL (`http://[user:pass@]host:port` or `socks5://…`).
    pub fn parse(s: &str) -> Result<Proxy, String> {
        let u = url::Url::parse(s).map_err(|e| format!("invalid proxy URL: {e}"))?;
        let host = u
            .host_str()
            .ok_or_else(|| "proxy URL has no host".to_string())?
            .to_string();
        let auth = if u.username().is_empty() {
            None
        } else {
            let decode = |value: &str| {
                percent_encoding::percent_decode_str(value)
                    .decode_utf8()
                    .map(|decoded| decoded.into_owned())
                    .map_err(|_| "proxy credentials must be valid UTF-8".to_owned())
            };
            Some((decode(u.username())?, decode(u.password().unwrap_or(""))?))
        };
        match u.scheme() {
            // `port_or_known_default()` yields 80 for an explicit or implicit
            // standard HTTP port (the url crate normalizes `:80` to None), so
            // `http://proxy:80` dials 80, not the 8080 fallback.
            "http" => Ok(Proxy::Http {
                host,
                port: u.port_or_known_default().unwrap_or(8080),
                auth,
            }),
            "socks5" | "socks5h" => Ok(Proxy::Socks5 {
                host,
                port: u.port().unwrap_or(1080),
                auth,
            }),
            other => Err(format!(
                "unsupported proxy scheme {other:?} (use http:// or socks5://)"
            )),
        }
    }

    pub fn scheme(&self) -> &'static str {
        match self {
            Proxy::Http { .. } => "http",
            Proxy::Socks5 { .. } => "socks5",
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_body: DEFAULT_MAX_BODY,
            max_headers: DEFAULT_MAX_HEADERS,
            insecure: false,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            extra_headers: Vec::new(),
            proxy: None,
        }
    }
}

/// A request to send. `headers` override the defaults (Host, User-Agent)
/// case-insensitively; `body` is sent as-is.
#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: &str) -> Self {
        Self {
            method: method.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

/// A request whose body is produced lazily, chunk by chunk, so a 20 MiB probe
/// is never held whole in RAM per worker. The body's exact length is
/// known up front, so the wire carries a real `Content-Length` (PHP's multipart
/// parser needs it; chunked would be rejected before the parser runs).
pub struct StreamingRequest {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: ChunkedBody,
}

/// A streaming request body backed by a chunk iterator with a known total
/// length. Peak memory is one chunk, not the whole body. Reusable by any
/// detector that must stream a large probe (php, node).
pub struct ChunkedBody {
    chunks: Box<dyn Iterator<Item = Bytes> + Send>,
    remaining: u64,
}

impl ChunkedBody {
    /// `len` is the exact total byte count the chunks will sum to; it drives the
    /// `Content-Length`. The caller must ensure the chunks really sum to `len`.
    pub fn new(len: u64, chunks: impl Iterator<Item = Bytes> + Send + 'static) -> Self {
        Self {
            chunks: Box::new(chunks),
            remaining: len,
        }
    }
}

impl Body for ChunkedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        match this.chunks.next() {
            Some(b) => {
                this.remaining = this.remaining.saturating_sub(b.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(b))))
            }
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

/// Body for a measured ("counted") exchange: either explicit bytes (the small
/// node control stages) or a repeated filler of a given length (the large probe,
/// streamed one buffer at a time so it is never held whole in RAM).
pub enum ProbeBodySpec {
    Bytes(Vec<u8>),
    Filler { len: u64, byte: u8 },
}

impl ProbeBodySpec {
    fn len(&self) -> u64 {
        match self {
            ProbeBodySpec::Bytes(b) => b.len() as u64,
            ProbeBodySpec::Filler { len, .. } => *len,
        }
    }
}

/// The result of a measured exchange: the response plus how many body
/// bytes actually reached the wire, so a probe the server rejected early
/// (`bytes_sent < len`) can be told apart from one it accepted in full.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub body_truncated: bool,
    pub bytes_sent: u64,
    pub negotiated_alpn: Option<String>,
}

impl ProbeResponse {
    /// First value for a header name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The raw response as the detectors see it.
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Body exceeded `max_body` and was cut.
    pub body_truncated: bool,
    /// Header section exceeded `max_headers`.
    pub headers_truncated: bool,
    /// ALPN protocol negotiated on the TLS handshake, if any. A detector turns
    /// `h2` into `INCONCLUSIVE`; we only ever offer `http/1.1`.
    pub negotiated_alpn: Option<String>,
}

impl RawResponse {
    /// First value for a header name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_is_empty(&self) -> bool {
        self.body.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("request timed out")]
    Timeout,
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("server did not accept HTTP/1.1 over TLS (likely HTTP/2-only); an HTTP/1.1 detector cannot decide")]
    Http2Only,
    #[error("connection reset or I/O error: {0}")]
    Io(String),
    #[error("malformed request: {0}")]
    Build(String),
    #[error("target has no host")]
    NoHost,
}

/// A reusable raw HTTP/1.1 client. A fresh connection is opened per request so a
/// reset on one host never affects another, and a worker death is observable.
/// Global token-less rate gate: spaces request *starts* to at most `rps` per
/// second across every task sharing this client. The lock is held only to stamp
/// the next slot, never across the sleep.
#[derive(Debug)]
pub struct RateGate {
    interval: Duration,
    next: tokio::sync::Mutex<Instant>,
}

impl RateGate {
    fn new(rps: f64) -> Self {
        Self {
            interval: Duration::from_secs_f64(1.0 / rps),
            next: tokio::sync::Mutex::new(Instant::now()),
        }
    }

    async fn wait(&self) {
        let now = Instant::now();
        let slot = {
            let mut next = self.next.lock().await;
            let slot = (*next).max(now);
            // Checked: a pathological interval can't be added past `Instant`'s
            // range (parse_rate caps it, but never panic a worker here).
            *next = slot.checked_add(self.interval).unwrap_or(slot);
            slot
        };
        let delay = slot.saturating_duration_since(now);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpClient {
    config: HttpConfig,
    /// Redaction follows the whole scan, including redirects that drop outgoing headers.
    pub(super) redaction: Arc<HeaderRedaction>,
    /// Shared global rate limiter (`--rate`); `None` = unthrottled.
    rate: Option<Arc<RateGate>>,
}

/// How many times a 429 is retried with exponential backoff before the response
/// is returned as-is.
const MAX_429_RETRIES: u32 = 4;

impl HttpClient {
    pub fn new(config: HttpConfig) -> Self {
        Self {
            redaction: Arc::new(HeaderRedaction::new(&config.extra_headers)),
            config,
            rate: None,
        }
    }

    /// Attach a global rate limit of `rps` requests/second (shared across every
    /// request this client makes). `None` leaves the client unthrottled.
    pub fn with_rate(mut self, rps: Option<f64>) -> Self {
        self.rate = rps.filter(|r| *r > 0.0).map(|r| Arc::new(RateGate::new(r)));
        self
    }

    pub fn config(&self) -> &HttpConfig {
        &self.config
    }

    /// A clone of this client that carries none of the operator `-H` headers, so
    /// Authorization, Cookie, and any custom secret header never travel to a
    /// different origin after a redirect. The built-in Host/User-Agent are added
    /// per request (not from `extra_headers`), so they are unaffected; the shared
    /// rate limiter is preserved.
    pub fn without_extra_headers(&self) -> Self {
        let mut config = self.config.clone();
        config.extra_headers = Vec::new();
        Self {
            config,
            rate: self.rate.clone(),
            redaction: Arc::clone(&self.redaction),
        }
    }

    /// Redact headers for a `--debug` trace: the well-known secret names plus
    /// every `-H` name the operator supplied, so a custom secret header never
    /// leaks to stderr. Only evaluated when a DEBUG subscriber is installed.
    fn redact_trace(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        self.redaction.headers(headers)
    }

    pub(crate) fn evidence_header<'a>(&self, name: &str, value: &'a str) -> &'a str {
        self.redaction.header(name, value)
    }

    /// Body preview for a `--debug` trace. Suppressed entirely when the operator
    /// supplied `-H` headers: a server can reflect a custom secret header into
    /// its response body, and the preview would then print it in the clear.
    /// Status and body length still go to the log.
    fn trace_preview(&self, body: &[u8]) -> String {
        if self.redaction.allows_body_preview() {
            body_preview(body)
        } else {
            "<omitted: -H header may be reflected in body>".to_string()
        }
    }

    /// Block until the global rate limiter allows the next request start.
    async fn throttle(&self) {
        if let Some(gate) = &self.rate {
            gate.wait().await;
        }
    }

    /// Send one request with a fully-buffered body and read the raw response,
    /// under the configured per-request timeout. Honors the global rate limit
    /// and retries a `429` with exponential backoff (the body is buffered, so a
    /// resend is safe).
    pub async fn send(&self, target: &Target, req: HttpRequest) -> Result<RawResponse, HttpError> {
        let mut attempt = 0u32;
        loop {
            self.throttle().await;
            let resp = self
                .run(
                    target,
                    &req.method,
                    &req.headers,
                    Full::new(Bytes::from(req.body.clone())),
                )
                .await?;
            if resp.status == 429 && attempt < MAX_429_RETRIES {
                // 0.5s, 1s, 2s, 4s.
                let backoff = Duration::from_millis(500u64 << attempt);
                attempt += 1;
                tokio::time::sleep(backoff).await;
                continue;
            }
            return Ok(resp);
        }
    }

    /// Send one request whose body is streamed chunk by chunk (large probes).
    /// Uses the same timeout, transport and global rate limit as [`Self::send`].
    /// No 429 retry here; the streamed body is consumed once and a heavy probe
    /// that draws a 429 never ran the parser, so the detector treats it as a
    /// rejection (inconclusive), not something to resend.
    pub async fn send_streaming(
        &self,
        target: &Target,
        req: StreamingRequest,
    ) -> Result<RawResponse, HttpError> {
        self.throttle().await;
        self.run(target, &req.method, &req.headers, req.body).await
    }

    /// A manual HTTP/1.1 exchange that reports how many body bytes were sent and,
    /// when `expect_continue` is set, waits up to `continue_wait` for an interim
    /// `100 Continue` before streaming the body. hyper's client does
    /// neither, so the node detector drives the socket directly. All framing is
    /// kept raw and uniform across stages, so exact-response comparison is valid.
    pub async fn send_counted(
        &self,
        target: &Target,
        method: &str,
        headers: &[(String, String)],
        body: ProbeBodySpec,
        expect_continue: bool,
        continue_wait: Duration,
    ) -> Result<ProbeResponse, HttpError> {
        self.throttle().await;
        match tokio::time::timeout(
            self.config.timeout,
            self.counted_inner(
                target,
                method,
                headers,
                body,
                expect_continue,
                continue_wait,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(HttpError::Timeout),
        }
    }

    async fn counted_inner(
        &self,
        target: &Target,
        method: &str,
        headers: &[(String, String)],
        body: ProbeBodySpec,
        expect_continue: bool,
        continue_wait: Duration,
    ) -> Result<ProbeResponse, HttpError> {
        let url = target.url();
        let host = url.host_str().ok_or(HttpError::NoHost)?;
        let is_tls = url.scheme() == "https";
        let port = url
            .port_or_known_default()
            .unwrap_or(if is_tls { 443 } else { 80 });

        let head = self.build_head_bytes(url, method, headers, body.len(), expect_continue);
        let caps = Caps {
            max_body: self.config.max_body,
            max_headers: self.config.max_headers,
        };
        let tcp = self.connect_tcp(host, port).await?;
        let resp = if is_tls {
            let (stream, alpn) = self.tls_wrap(tcp, host).await?;
            counted_exchange(
                stream,
                alpn,
                head,
                body,
                expect_continue,
                continue_wait,
                caps,
            )
            .await
        } else {
            counted_exchange(tcp, None, head, body, expect_continue, continue_wait, caps).await
        };
        if let Ok(r) = &resp {
            tracing::debug!(
                target: "x2s::http",
                status = r.status,
                headers = ?self.redact_trace(&r.headers),
                body_len = r.body.len(),
                bytes_sent = r.bytes_sent,
                truncated = r.body_truncated,
                preview = %self.trace_preview(&r.body),
                "response (counted)"
            );
        }
        resp
    }

    /// Build the raw request head (request-line + headers + blank line). Defaults
    /// (Host, User-Agent, Content-Length) are applied first, then caller headers
    /// override case-insensitively; `Expect: 100-continue` is appended when asked.
    fn build_head_bytes(
        &self,
        url: &url::Url,
        method: &str,
        req_headers: &[(String, String)],
        content_length: u64,
        expect_continue: bool,
    ) -> Vec<u8> {
        let host = url.host_str().unwrap_or("");
        let default_port = if url.scheme() == "https" { 443 } else { 80 };
        let port = url.port_or_known_default().unwrap_or(default_port);
        let path_and_query = match url.query() {
            Some(q) => format!("{}?{}", url.path(), q),
            None => url.path().to_string(),
        };
        let host_header = if port == default_port {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };

        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host_header),
            ("user-agent".into(), self.config.user_agent.clone()),
            ("content-length".into(), content_length.to_string()),
        ];
        // Operator `-H` first (overrides defaults), then detector headers last
        // (override `-H`, so a verdict-critical header is never clobbered).
        apply_overrides(&mut headers, &self.config.extra_headers);
        apply_overrides(&mut headers, req_headers);
        if expect_continue {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("expect"));
            headers.push(("expect".into(), "100-continue".into()));
        }

        tracing::debug!(
            target: "x2s::http",
            method = %method,
            path = %self.redaction.text(&path_and_query),
            headers = ?self.redact_trace(&headers),
            "request (counted)"
        );

        let mut out = format!("{method} {path_and_query} HTTP/1.1\r\n").into_bytes();
        for (k, v) in headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    async fn run<B>(
        &self,
        target: &Target,
        method: &str,
        headers: &[(String, String)],
        body: B,
    ) -> Result<RawResponse, HttpError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        match tokio::time::timeout(
            self.config.timeout,
            self.send_inner(target, method, headers, body),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(HttpError::Timeout),
        }
    }

    async fn send_inner<B>(
        &self,
        target: &Target,
        method: &str,
        headers: &[(String, String)],
        body: B,
    ) -> Result<RawResponse, HttpError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let url = target.url();
        let host = url.host_str().ok_or(HttpError::NoHost)?;
        let is_tls = url.scheme() == "https";
        let port = url
            .port_or_known_default()
            .unwrap_or(if is_tls { 443 } else { 80 });

        let tcp = self.connect_tcp(host, port).await?;
        let hyper_req = self.build_request(url, host, port, method, headers, body)?;

        if is_tls {
            let (stream, alpn) = self.tls_wrap(tcp, host).await?;
            self.exchange(TokioIo::new(stream), hyper_req, alpn).await
        } else {
            self.exchange(TokioIo::new(tcp), hyper_req, None).await
        }
    }

    /// Open a TCP stream to `host:port`, directly or through the configured proxy.
    /// Both proxy paths return a plain `TcpStream` that is a transparent tunnel to
    /// the target, so TLS and the exchange run over it unchanged.
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, HttpError> {
        match &self.config.proxy {
            None => connect_direct(&format!("{host}:{port}")).await,
            Some(Proxy::Http {
                host: phost,
                port: pport,
                auth,
            }) => {
                let mut tcp = connect_direct(&format!("{phost}:{pport}")).await?;
                http_connect_tunnel(&mut tcp, host, port, auth.as_ref()).await?;
                Ok(tcp)
            }
            Some(Proxy::Socks5 {
                host: phost,
                port: pport,
                auth,
            }) => {
                let proxy = format!("{phost}:{pport}");
                let stream = match auth {
                    Some((u, p)) => {
                        tokio_socks::tcp::Socks5Stream::connect_with_password(
                            proxy.as_str(),
                            (host, port),
                            u,
                            p,
                        )
                        .await
                    }
                    None => {
                        tokio_socks::tcp::Socks5Stream::connect(proxy.as_str(), (host, port)).await
                    }
                }
                .map_err(|e| HttpError::Connect(format!("socks5: {e}")))?;
                Ok(stream.into_inner())
            }
        }
    }

    async fn tls_wrap(
        &self,
        tcp: TcpStream,
        host: &str,
    ) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Option<String>), HttpError> {
        let connector = TlsConnector::from(Arc::new(self.tls_config()));
        let sni = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let server_name = rustls::pki_types::ServerName::try_from(sni)
            .map_err(|e| HttpError::Tls(format!("invalid server name: {e}")))?;
        let stream = match connector.connect(server_name, tcp).await {
            Ok(s) => s,
            Err(e) => {
                // We offer only `http/1.1`; an h2-only server aborts ALPN with a
                // `no_application_protocol` alert. Surface that distinctly so the
                // detector's INCONCLUSIVE carries a clear HTTP/2-only reason
                // rather than a generic TLS error.
                return Err(classify_tls_error(e.to_string()));
            }
        };
        let alpn = stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        Ok((stream, alpn))
    }

    fn tls_config(&self) -> ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // NOTE: not a network/parse path. This is a build-time crypto
        // invariant; the ring provider always carries TLS 1.2+1.3, so it can
        // only fail on a misbuilt binary, never at runtime against a host.
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports TLS 1.2+1.3");

        let mut config = if self.config.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(insecure::NoVerify::new()))
                .with_no_client_auth()
        } else {
            let roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        // Offer only HTTP/1.1; an h2-only server is surfaced via negotiated_alpn.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    }

    fn build_request<B>(
        &self,
        url: &url::Url,
        host: &str,
        port: u16,
        method: &str,
        req_headers: &[(String, String)],
        body: B,
    ) -> Result<Request<B>, HttpError> {
        let method = hyper::Method::from_bytes(method.as_bytes())
            .map_err(|e| HttpError::Build(format!("method: {e}")))?;

        let path_and_query = match url.query() {
            Some(q) => format!("{}?{}", url.path(), q),
            None => url.path().to_string(),
        };

        // Default Host includes the port only when non-default for the scheme.
        let default_port = if url.scheme() == "https" { 443 } else { 80 };
        let host_header = if port == default_port {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };

        // Defaults first, then caller headers override case-insensitively.
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host_header),
            ("user-agent".into(), self.config.user_agent.clone()),
        ];
        apply_overrides(&mut headers, &self.config.extra_headers);
        apply_overrides(&mut headers, req_headers);

        tracing::debug!(
            target: "x2s::http",
            method = %method,
            path = %self.redaction.text(&path_and_query),
            headers = ?self.redact_trace(&headers),
            "request"
        );

        let mut builder = Request::builder().method(method).uri(path_and_query);
        for (k, v) in headers {
            builder = builder.header(k, v);
        }

        builder
            .body(body)
            .map_err(|e| HttpError::Build(e.to_string()))
    }

    async fn exchange<S, B>(
        &self,
        io: S,
        req: Request<B>,
        alpn: Option<String>,
    ) -> Result<RawResponse, HttpError>
    where
        S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| HttpError::Io(e.to_string()))?;
        // Drive the connection; a reset shows up as an error on send/read below.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| HttpError::Io(e.to_string()))?;

        let status = resp.status().as_u16();

        let mut header_bytes = 0usize;
        let mut headers_truncated = false;
        let mut headers = Vec::new();
        for (name, value) in resp.headers() {
            header_bytes += name.as_str().len() + value.as_bytes().len();
            if header_bytes > self.config.max_headers {
                headers_truncated = true;
                break;
            }
            headers.push((
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            ));
        }

        let (body, body_truncated) =
            read_body_capped(resp.into_body(), self.config.max_body).await?;

        tracing::debug!(
            target: "x2s::http",
            status,
            headers = ?self.redact_trace(&headers),
            body_len = body.len(),
            truncated = body_truncated,
            preview = %self.trace_preview(&body),
            "response"
        );

        Ok(RawResponse {
            status,
            headers,
            body,
            body_truncated,
            headers_truncated,
            negotiated_alpn: alpn,
        })
    }
}

/// A short, printable preview of a response body for `--debug` dumps; bounded so
/// a 23 MiB probe response is never echoed whole.
fn body_preview(body: &[u8]) -> String {
    const PREVIEW: usize = 256;
    String::from_utf8_lossy(&body[..body.len().min(PREVIEW)]).into_owned()
}

/// Memory caps applied *while reading* a measured exchange, so a hostile
/// endpoint can never make us buffer more than this regardless of what it
/// advertises (Content-Length) or streams (chunked/headers).
#[derive(Debug, Clone, Copy)]
struct Caps {
    max_body: usize,
    max_headers: usize,
}

/// Drive one measured HTTP/1.1 exchange over `stream`: write the head; optionally
/// wait for an interim `100 Continue`; stream the body counting bytes; read the
/// final response. Framing is kept raw (we only parse enough to find the body
/// end), so every stage's bytes are directly comparable. Memory is bounded by
/// `caps` during every read, not after.
async fn counted_exchange<S>(
    mut stream: S,
    alpn: Option<String>,
    head: Vec<u8>,
    body: ProbeBodySpec,
    expect_continue: bool,
    continue_wait: Duration,
    caps: Caps,
) -> Result<ProbeResponse, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    stream
        .write_all(&head)
        .await
        .map_err(|e| HttpError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| HttpError::Io(e.to_string()))?;

    let mut buf: Vec<u8> = Vec::new();

    let mut remaining_headers = caps.max_headers;
    let early_response = if expect_continue {
        match tokio::time::timeout(
            continue_wait,
            read_response_head(&mut stream, &mut buf, &mut remaining_headers, true),
        )
        .await
        {
            Ok(result) => match result? {
                (100, _) => None,
                final_head => Some(final_head),
            },
            // Silence permits the existing Expect fallback. A partially received
            // response is ambiguous: stop rather than send a body after a possible rejection.
            Err(_) if remaining_headers != caps.max_headers || !buf.is_empty() => {
                return Err(HttpError::Timeout)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    let (bytes_sent, (status, headers)) = match early_response {
        Some(head) => (0, head),
        None => {
            let sent = write_body(&mut stream, &body).await;
            let _ = stream.flush().await;
            let head =
                read_response_head(&mut stream, &mut buf, &mut remaining_headers, false).await?;
            (sent, head)
        }
    };
    let (body_bytes, truncated) =
        read_body_framed(&mut stream, &mut buf, &headers, caps.max_body).await?;

    Ok(ProbeResponse {
        status,
        headers,
        body: body_bytes,
        body_truncated: truncated,
        bytes_sent,
        negotiated_alpn: alpn,
    })
}

/// Write the body, returning how many bytes reached the wire. A write error stops
/// the count where it failed (the server likely rejected and reset).
async fn write_body<S>(stream: &mut S, body: &ProbeBodySpec) -> u64
where
    S: AsyncWrite + Unpin,
{
    match body {
        ProbeBodySpec::Bytes(b) => {
            if stream.write_all(b).await.is_ok() {
                b.len() as u64
            } else {
                0
            }
        }
        ProbeBodySpec::Filler { len, byte } => {
            let chunk = vec![*byte; 64 * 1024];
            let mut sent = 0u64;
            while sent < *len {
                let n = ((*len - sent) as usize).min(chunk.len());
                if stream.write_all(&chunk[..n]).await.is_err() {
                    break;
                }
                sent += n as u64;
            }
            sent
        }
    }
}

/// Consume informational heads under one cumulative header budget. A 100 is
/// meaningful to the caller only while waiting for permission to send the body.
async fn read_response_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    remaining: &mut usize,
    awaiting_continue: bool,
) -> Result<(u16, Vec<(String, String)>), HttpError> {
    loop {
        let (status, headers, end) = read_until_head(stream, buf, *remaining).await?;
        *remaining -= end;
        buf.drain(..end);
        match status {
            101 => return Err(HttpError::Io("unexpected 101 upgrade".into())),
            100 if awaiting_continue => return Ok((status, headers)),
            100..=199 => continue,
            200..=599 => return Ok((status, headers)),
            _ => return Err(HttpError::Io("invalid HTTP response status".into())),
        }
    }
}

/// Read into `buf` until the response head is complete (`\r\n\r\n`), then parse
/// its status and headers. Returns the index just past the head.
async fn read_until_head<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    max_headers: usize,
) -> Result<(u16, Vec<(String, String)>, usize), HttpError>
where
    S: AsyncRead + Unpin,
{
    let mut tmp = [0u8; 8192];
    // Bytes already scanned for the terminator. Searching only the unscanned tail
    // (minus 3, so a `\r\n\r\n` split across two reads is still caught) keeps this
    // O(total bytes) instead of O(n^2): a hostile server that withholds the blank
    // line for ~10 MiB of headers can't pin a worker on CPU before the cap errors.
    let mut scanned = 0usize;
    loop {
        let from = scanned.saturating_sub(3);
        if let Some(rel) = find_subslice(&buf[from..], b"\r\n\r\n") {
            let head_end = from + rel + 4;
            // Enforce the cap on the actual header section, so a block that both
            // completes the head and crosses the cap is still rejected.
            if head_end > max_headers {
                return Err(HttpError::Io(
                    "response header section exceeds the configured cap".into(),
                ));
            }
            let (status, headers) = parse_head(&buf[..head_end])?;
            return Ok((status, headers, head_end));
        }
        // Bound growth while still searching for the terminator.
        if buf.len() > max_headers {
            return Err(HttpError::Io(
                "response header section exceeds the configured cap".into(),
            ));
        }
        scanned = buf.len();
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| HttpError::Io(e.to_string()))?;
        if n == 0 {
            return Err(HttpError::Io(
                "connection closed before response head".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Parse a response head: `HTTP/1.x NNN ...` status line plus `Key: Value` lines.
fn parse_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>), HttpError> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| HttpError::Io(format!("malformed status line: {status_line:?}")))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}

/// Read the response body per its framing (Content-Length, chunked, or
/// connection-close), keeping the raw bytes and capping at `max_body`. `buf` holds
/// any bytes already read past the head; its contents are the body prefix.
async fn read_body_framed<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    headers: &[(String, String)],
    max_body: usize,
) -> Result<(Vec<u8>, bool), HttpError>
where
    S: AsyncRead + Unpin,
{
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };

    let mut raw = std::mem::take(buf);

    if let Some(cl) = header("content-length").and_then(|v| v.trim().parse::<usize>().ok()) {
        // Never buffer more than the cap, whatever Content-Length claims.
        let want = cl.min(max_body);
        let reached = read_capped(stream, &mut raw, want).await?;
        if cl > max_body {
            raw.truncate(max_body);
            return Ok((raw, true)); // cut by the cap
        }
        raw.truncate(cl);
        // A close before the declared length is a partial response → mark it
        // truncated so exact-response comparison refuses it as evidence.
        let truncated = !reached || raw.len() < cl;
        return Ok((raw, truncated));
    }

    if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        let completed = read_until_chunk_end(stream, &mut raw, max_body).await?;
        let hit_cap = raw.len() > max_body;
        raw.truncate(max_body);
        // Capped or ended before the zero-chunk → not a complete body.
        return Ok((raw, hit_cap || !completed));
    }

    // No framing: read to EOF, capped.
    let mut tmp = [0u8; 8192];
    loop {
        if raw.len() >= max_body {
            return Ok((raw[..max_body].to_vec(), true));
        }
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| HttpError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&tmp[..n]);
    }
    Ok((raw, false))
}

/// Read until `raw` holds at least `want` bytes. Returns `true` if it reached
/// `want`, `false` on EOF first (a short/partial body).
async fn read_capped<S>(stream: &mut S, raw: &mut Vec<u8>, want: usize) -> Result<bool, HttpError>
where
    S: AsyncRead + Unpin,
{
    let mut tmp = [0u8; 8192];
    while raw.len() < want {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| HttpError::Io(e.to_string()))?;
        if n == 0 {
            return Ok(false);
        }
        raw.extend_from_slice(&tmp[..n]);
    }
    Ok(true)
}

/// Walk a chunked body to its terminating zero-size chunk, keeping raw bytes and
/// never buffering past `max_body`. Does not decode. Returns `true` only when the
/// zero-chunk was reached; `false` on a premature close or on hitting the cap.
async fn read_until_chunk_end<S>(
    stream: &mut S,
    raw: &mut Vec<u8>,
    max_body: usize,
) -> Result<bool, HttpError>
where
    S: AsyncRead + Unpin,
{
    let mut pos = 0usize;
    loop {
        if raw.len() > max_body {
            return Ok(false);
        }
        // Need the chunk-size line terminator.
        let line_end = loop {
            if let Some(rel) = find_subslice(&raw[pos..], b"\r\n") {
                break pos + rel;
            }
            if raw.len() > max_body {
                return Ok(false);
            }
            if !read_more(stream, raw).await? {
                return Ok(false); // EOF mid-framing
            }
        };
        let size_str = String::from_utf8_lossy(&raw[pos..line_end]);
        // Invalid framing is an error, never silently a zero (final) chunk.
        let size =
            usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| HttpError::Io("invalid chunk size in response framing".into()))?;
        let data_start = line_end
            .checked_add(2)
            .ok_or_else(|| HttpError::Io("chunk framing offset overflow".into()))?;
        if size == 0 {
            // Final chunk. The body ends at the blank line that closes the
            // (possibly empty) trailer section: search for `\r\n\r\n` from the
            // start of this `0` line, so an in-progress trailer is not mistaken
            // for completion and a close before it is inconclusive.
            loop {
                if find_subslice(&raw[pos..], b"\r\n\r\n").is_some() {
                    return Ok(true);
                }
                if raw.len() > max_body {
                    return Ok(false);
                }
                if !read_more(stream, raw).await? {
                    return Ok(false); // closed before the trailer terminator
                }
            }
        }
        // A single chunk larger than the cap means the body exceeds max_body;
        // stop here (capped) rather than overflowing the position arithmetic.
        if size > max_body {
            return Ok(false);
        }
        // data + CRLF, checked so a hostile size can never wrap the position.
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| HttpError::Io("chunk framing offset overflow".into()))?;
        let next = data_end
            .checked_add(2)
            .ok_or_else(|| HttpError::Io("chunk framing offset overflow".into()))?;
        while raw.len() < next {
            if raw.len() > max_body {
                return Ok(false);
            }
            if !read_more(stream, raw).await? {
                return Ok(false); // premature close mid-chunk
            }
        }
        // The two bytes after the chunk data must be the CRLF, or the framing is
        // invalid; do not skip them blindly.
        if &raw[data_end..next] != b"\r\n" {
            return Err(HttpError::Io("chunk data not terminated by CRLF".into()));
        }
        pos = next;
    }
}

/// Append one read into `raw`; false on EOF.
async fn read_more<S>(stream: &mut S, raw: &mut Vec<u8>) -> Result<bool, HttpError>
where
    S: AsyncRead + Unpin,
{
    let mut tmp = [0u8; 8192];
    let n = stream
        .read(&mut tmp)
        .await
        .map_err(|e| HttpError::Io(e.to_string()))?;
    if n == 0 {
        return Ok(false);
    }
    raw.extend_from_slice(&tmp[..n]);
    Ok(true)
}

/// Apply `overrides` onto `headers` case-insensitively: each name replaces any
/// existing entry of the same name, preserving later-layer precedence.
fn apply_overrides(headers: &mut Vec<(String, String)>, overrides: &[(String, String)]) {
    for (k, v) in overrides {
        headers.retain(|(ek, _)| !ek.eq_ignore_ascii_case(k));
        headers.push((k.clone(), v.clone()));
    }
}

/// Classify a rustls connect error: an ALPN `no_application_protocol` alert
/// (we offer only `http/1.1`, so this means the server is HTTP/2-only) becomes
/// [`HttpError::Http2Only`]; anything else is a generic TLS error.
fn classify_tls_error(msg: String) -> HttpError {
    if msg
        .to_ascii_lowercase()
        .replace('_', "")
        .contains("noapplicationprotocol")
    {
        HttpError::Http2Only
    } else {
        HttpError::Tls(msg)
    }
}

/// Resolve `authority` and connect, trying each address until one succeeds.
async fn connect_direct(authority: &str) -> Result<TcpStream, HttpError> {
    let addrs = tokio::net::lookup_host(authority)
        .await
        .map_err(|e| HttpError::Connect(format!("DNS: {e}")))?;
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(HttpError::Connect(
        last.map(|e| e.to_string())
            .unwrap_or_else(|| "no addresses resolved".into()),
    ))
}

/// Open an HTTP-proxy `CONNECT host:port` tunnel over an already-connected proxy
/// socket. On success `tcp` is a transparent tunnel to the target.
async fn http_connect_tunnel(
    tcp: &mut TcpStream,
    host: &str,
    port: u16,
    auth: Option<&(String, String)>,
) -> Result<(), HttpError> {
    let target = format!("{host}:{port}");
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((u, p)) = auth {
        let token = base64(format!("{u}:{p}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes())
        .await
        .map_err(|e| HttpError::Connect(format!("proxy CONNECT write: {e}")))?;
    tcp.flush()
        .await
        .map_err(|e| HttpError::Connect(format!("proxy CONNECT flush: {e}")))?;

    let mut buf = Vec::new();
    let mut remaining_headers = DEFAULT_MAX_HEADERS;
    let (status, _) = read_response_head(tcp, &mut buf, &mut remaining_headers, false)
        .await
        .map_err(|e| HttpError::Connect(format!("proxy CONNECT response: {e}")))?;
    if !(200..300).contains(&status) {
        return Err(HttpError::Connect(format!(
            "proxy refused CONNECT with status {status}"
        )));
    }
    Ok(())
}

/// Standard base64 (for the `Proxy-Authorization: Basic` token). A few lines, so
/// no base64 dependency is pulled in for one header.
fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read the response body, stopping at `max_body` bytes and flagging truncation.
async fn read_body_capped(
    mut body: hyper::body::Incoming,
    max_body: usize,
) -> Result<(Vec<u8>, bool), HttpError> {
    let mut buf = Vec::new();
    let mut truncated = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| HttpError::Io(e.to_string()))?;
        if let Some(data) = frame.data_ref() {
            let remaining = max_body.saturating_sub(buf.len());
            if data.len() > remaining {
                buf.extend_from_slice(&data[..remaining]);
                truncated = true;
                break;
            }
            buf.extend_from_slice(data);
        }
    }
    Ok((buf, truncated))
}

/// Accept-any-cert verifier for `-k/--insecure`. Isolated so the dangerous code
/// is in one named place, used only when the operator explicitly opts in.
mod insecure {
    use std::sync::Arc;

    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::{
        ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerify(Arc<CryptoProvider>);

    impl NoVerify {
        pub fn new() -> Self {
            NoVerify(Arc::new(ring::default_provider()))
        }
    }

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

#[cfg(test)]
mod tls_error_tests {
    use super::{classify_tls_error, HttpError};

    #[test]
    fn alpn_mismatch_becomes_http2_only() {
        // The shapes rustls prints for an ALPN `no_application_protocol` abort.
        for msg in [
            "received fatal alert: NoApplicationProtocol",
            "peer is incompatible: NoApplicationProtocol",
            "alert no_application_protocol",
        ] {
            assert!(
                matches!(classify_tls_error(msg.to_string()), HttpError::Http2Only),
                "{msg:?} should map to Http2Only"
            );
        }
    }

    #[test]
    fn other_tls_errors_stay_generic() {
        assert!(matches!(
            classify_tls_error("invalid certificate: expired".to_string()),
            HttpError::Tls(_)
        ));
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::{base64, Proxy};

    #[test]
    fn base64_rfc4648_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want, "base64({input:?})");
        }
    }

    #[test]
    fn parse_http_and_socks5_with_and_without_auth() {
        match Proxy::parse("http://user:pass@proxy.example:3128").unwrap() {
            Proxy::Http { host, port, auth } => {
                assert_eq!(host, "proxy.example");
                assert_eq!(port, 3128);
                assert_eq!(auth, Some(("user".into(), "pass".into())));
            }
            _ => panic!("expected http proxy"),
        }
        match Proxy::parse("socks5://127.0.0.1").unwrap() {
            Proxy::Socks5 { host, port, auth } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 1080, "default socks port");
                assert_eq!(auth, None);
            }
            _ => panic!("expected socks5 proxy"),
        }
    }

    #[test]
    fn proxy_credentials_are_decoded_once() {
        for scheme in ["http", "socks5", "socks5h"] {
            let url = format!("{scheme}://first%40last:p%40ss%2540+%C3%A9@proxy.example");
            let auth = match Proxy::parse(&url).unwrap() {
                Proxy::Http { auth, .. } | Proxy::Socks5 { auth, .. } => auth,
            };
            assert_eq!(auth, Some(("first@last".into(), "p@ss%40+é".into())));
        }
        let error = Proxy::parse("http://fixture:private%FF@proxy.example").unwrap_err();
        assert_eq!(error, "proxy credentials must be valid UTF-8");
    }

    #[test]
    fn parse_rejects_unsupported_scheme() {
        assert!(Proxy::parse("ftp://nope").is_err());
        assert!(Proxy::parse("not a url").is_err());
    }

    #[test]
    fn explicit_standard_http_port_is_80_not_8080() {
        // the url crate normalizes `:80` to None; port_or_known_default() must
        // still yield 80, not the 8080 fallback.
        match Proxy::parse("http://proxy.example:80").unwrap() {
            Proxy::Http { port, .. } => assert_eq!(port, 80),
            _ => panic!("expected http proxy"),
        }
        // no port at all → also the http default 80
        match Proxy::parse("http://proxy.example").unwrap() {
            Proxy::Http { port, .. } => assert_eq!(port, 80),
            _ => panic!("expected http proxy"),
        }
    }

    #[test]
    fn debug_never_leaks_host_or_credentials() {
        let p = Proxy::parse("http://secret:token@internal.host:8080").unwrap();
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("secret") && !dbg.contains("token") && !dbg.contains("internal"));
        assert_eq!(dbg, "Proxy(http)");
    }
}

#[cfg(test)]
mod rate_tests {
    use super::RateGate;
    use std::time::Instant;

    #[tokio::test]
    async fn gate_spaces_request_starts_by_the_interval() {
        // 50 req/s → 20 ms between starts. Three waits cost ~2 intervals (40 ms);
        // assert a tolerant lower bound so scheduling jitter can't make it flaky.
        let gate = RateGate::new(50.0);
        let start = Instant::now();
        gate.wait().await; // first: no wait
        gate.wait().await; // +20 ms
        gate.wait().await; // +20 ms
        let elapsed = start.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(30),
            "three starts should be spaced by ~2 intervals, got {elapsed:?}"
        );
    }
}

#[cfg(test)]
mod preview_tests {
    use super::{HttpClient, HttpConfig};

    #[test]
    fn preview_suppressed_when_custom_headers_present() {
        let body = b"token=sk-live-abc reflected here";

        let plain = HttpClient::new(HttpConfig::default());
        assert!(plain.trace_preview(body).contains("sk-live-abc"));

        let with_h = HttpClient::new(HttpConfig {
            extra_headers: vec![("x-auth-token".into(), "sk-live-abc".into())],
            ..HttpConfig::default()
        });
        let stripped = with_h.without_extra_headers();
        let reflected = vec![("X-Metadata".into(), "account=sk-live-abc".into())];
        assert_eq!(stripped.redact_trace(&reflected)[0].1, "<redacted>");
        assert!(stripped.trace_preview(body).starts_with("<omitted"));
        let preview = with_h.trace_preview(body);
        assert!(!preview.contains("sk-live-abc"), "secret leaked: {preview}");
        assert!(preview.starts_with("<omitted"));
    }

    #[test]
    fn without_extra_headers_drops_operator_headers_only() {
        let client = HttpClient::new(HttpConfig {
            extra_headers: vec![
                ("authorization".into(), "Bearer secret".into()),
                ("x-custom".into(), "v".into()),
            ],
            user_agent: "ua/1".into(),
            ..HttpConfig::default()
        });
        let stripped = client.without_extra_headers();
        // Operator -H headers are gone...
        assert!(stripped.config().extra_headers.is_empty());
        // ...but the built-in config (e.g. User-Agent) is untouched.
        assert_eq!(stripped.config().user_agent, "ua/1");
        // The original is unchanged (immutable).
        assert_eq!(client.config().extra_headers.len(), 2);
    }
}
