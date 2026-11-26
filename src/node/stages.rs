//! Node probe/control request shapes.
//!
//! Six stages, each a small request except the one large probe. The bodies are
//! original, built from the documented parameters (valid vs malformed
//! Brotli-labeled, the probe size), not copied from any tool. The transport
//! quirks (forced `Accept-Encoding: identity`, `Expect: 100-continue`, byte
//! counting) live in [`crate::core::http::HttpClient::send_counted`].

use std::io::Write;

use crate::core::http::ProbeBodySpec;

/// The CVE probe body size in bytes.
pub const PROBE_LEN: u64 = 23_068_764;
/// Filler byte for the probe body (content is irrelevant to the trigger; it is
/// labeled Brotli and is not valid Brotli). Tunable against the lab.
const PROBE_FILLER: u8 = b'A';

/// One stage's request shape. The orchestrator turns each into a measured
/// exchange and a [`super::compare::StageResponse`].
pub struct StageSpec {
    pub name: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: ProbeBodySpec,
    pub expect_continue: bool,
}

fn header(k: &str, v: &str) -> (String, String) {
    (k.to_string(), v.to_string())
}

/// `Accept-Encoding: identity` is forced on every stage so the *response* is
/// never itself encoded; we compare raw response bytes.
fn base_headers() -> Vec<(String, String)> {
    vec![header("Accept-Encoding", "identity")]
}

/// A valid minimal Brotli stream decoding to `{}` (the valid control body).
pub fn valid_brotli() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        // Writing is infallible into a Vec; the stream is flushed on drop.
        let _ = w.write_all(b"{}");
    }
    out
}

/// Bytes that are *not* a valid Brotli stream → the server's decoder rejects them.
pub fn malformed_brotli() -> Vec<u8> {
    b"\x00\x01\x02 not-a-valid-brotli-stream \xff\xfe\xfd".to_vec()
}

/// 1. Malformed Brotli-labeled body, **no** Content-Type (content-type bypass).
pub fn content_type_bypass() -> StageSpec {
    let mut headers = base_headers();
    headers.push(header("Content-Encoding", "br"));
    StageSpec {
        name: "content_type_bypass",
        headers,
        body: ProbeBodySpec::Bytes(malformed_brotli()),
        expect_continue: false,
    }
}

/// 2. Valid minimal Brotli, `application/json` (the valid control).
pub fn valid_empty_brotli() -> StageSpec {
    let mut headers = base_headers();
    headers.push(header("Content-Encoding", "br"));
    headers.push(header("Content-Type", "application/json"));
    StageSpec {
        name: "valid_empty_brotli",
        headers,
        body: ProbeBodySpec::Bytes(valid_brotli()),
        expect_continue: false,
    }
}

/// 3. Malformed Brotli, `application/json`.
pub fn malformed_brotli_stage() -> StageSpec {
    let mut headers = base_headers();
    headers.push(header("Content-Encoding", "br"));
    headers.push(header("Content-Type", "application/json"));
    StageSpec {
        name: "malformed_brotli",
        headers,
        body: ProbeBodySpec::Bytes(malformed_brotli()),
        expect_continue: false,
    }
}

/// 4. A body under an unsupported `Content-Encoding`.
pub fn unsupported_encoding() -> StageSpec {
    let mut headers = base_headers();
    headers.push(header("Content-Encoding", "x"));
    headers.push(header("Content-Type", "application/json"));
    StageSpec {
        name: "unsupported_encoding",
        headers,
        body: ProbeBodySpec::Bytes(b"{}".to_vec()),
        expect_continue: false,
    }
}

/// 5. The large Brotli-labeled probe, `application/json`, `Expect: 100-continue`.
pub fn cve_probe() -> StageSpec {
    let mut headers = base_headers();
    headers.push(header("Content-Encoding", "br"));
    headers.push(header("Content-Type", "application/json"));
    StageSpec {
        name: "cve_probe",
        headers,
        body: ProbeBodySpec::Filler {
            len: PROBE_LEN,
            byte: PROBE_FILLER,
        },
        expect_continue: true,
    }
}

/// 6. The valid control, re-sent, to confirm the route class is stable.
pub fn final_valid_empty_brotli() -> StageSpec {
    StageSpec {
        name: "final_valid_empty_brotli",
        ..valid_empty_brotli()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_brotli_roundtrips_to_json() {
        use std::io::Read;
        let encoded = valid_brotli();
        assert!(!encoded.is_empty());
        let mut decoded = Vec::new();
        brotli::Decompressor::new(encoded.as_slice(), 4096)
            .read_to_end(&mut decoded)
            .expect("valid brotli must decode");
        assert_eq!(decoded, b"{}");
    }

    #[test]
    fn malformed_brotli_does_not_decode() {
        use std::io::Read;
        let mut decoded = Vec::new();
        let r = brotli::Decompressor::new(malformed_brotli().as_slice(), 4096)
            .read_to_end(&mut decoded);
        assert!(r.is_err(), "malformed input must not decode as brotli");
    }

    #[test]
    fn probe_is_the_spec_size_and_expects_continue() {
        let p = cve_probe();
        assert!(p.expect_continue);
        match p.body {
            ProbeBodySpec::Filler { len, .. } => assert_eq!(len, 23_068_764),
            _ => panic!("probe must be a filler body"),
        }
    }

    #[test]
    fn every_stage_forces_identity_accept_encoding() {
        for s in [
            content_type_bypass(),
            valid_empty_brotli(),
            malformed_brotli_stage(),
            unsupported_encoding(),
            cve_probe(),
            final_valid_empty_brotli(),
        ] {
            assert!(
                s.headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("accept-encoding") && v == "identity"),
                "stage {} must force identity",
                s.name
            );
        }
    }
}
