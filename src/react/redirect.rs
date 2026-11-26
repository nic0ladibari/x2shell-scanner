//! Same-origin redirect resolution for the react retest.
//!
//! Resolve the redirect chain with `HEAD`, never auto-following: follow
//! `301/302/303/307/308`, accept relative `Location` and absolute `Location`
//! only on the same **origin** (scheme + host + effective port), and stop the
//! moment the chain would leave it. Restricting to the full origin; not just
//! the host; keeps operator `-H` secrets (Authorization, Cookie) from ever
//! travelling to a different scheme (an https→http downgrade sends them in the
//! clear) or a different port (a distinct service). Errors are swallowed (the
//! retest never changes a verdict on its own error).

use crate::core::http::{HttpClient, HttpRequest};
use crate::core::targets::{origin, Target};

pub(super) const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

/// Walk the redirect chain from `start` and return the final same-origin target
/// if it differs from `start`. Returns `None` if there is no redirect, the
/// chain leaves the origin (different scheme, host, or port), the hop limit is
/// hit, or any request errors.
pub async fn resolve_same_host(
    http: &HttpClient,
    start: &Target,
    max_hops: usize,
) -> Option<Target> {
    if max_hops == 0 {
        return None;
    }
    let start_origin = origin(start.url())?;
    let mut current = start.clone();

    let mut visited = std::collections::HashSet::new();
    for hop in 0..=max_hops {
        if !visited.insert(current.as_str().to_owned()) {
            return None;
        }
        let resp = http.send(&current, HttpRequest::new("HEAD")).await.ok()?;
        if !REDIRECT_STATUSES.contains(&resp.status) {
            return (hop > 0).then_some(current);
        }
        if hop == max_hops {
            return None;
        }
        let location = resp.header("location")?;
        let next_url = current.url().join(location).ok()?;
        if origin(&next_url) != Some(start_origin) {
            return None; // left the origin (scheme/host/port) → stop, no retest
        }
        current = Target::parse(next_url.as_str()).ok()?;
    }

    None
}
