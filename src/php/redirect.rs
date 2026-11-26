//! PHP redirect handling for `--follow-redirects`.
//!
//! After the first cross-origin hop, subsequent requests omit operator-supplied
//! headers. If the chain cannot be resolved, the original verdict stands.

use crate::core::http::{HttpClient, HttpRequest};
use crate::core::targets::{origin, Scope, Target};

/// Redirect statuses php follows under `--follow-redirects`.
pub const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

/// Hop limit for a PHP redirect chain.
pub const MAX_REDIRECT_HOPS: usize = 10;

/// Where a redirect chain settled.
pub struct Resolved {
    /// The final URL after the chain (differs from the start).
    pub target: Target,
    /// `true` once any hop left the original origin: every request to `target`
    /// (and any hop after the crossing) must omit the operator `-H` secrets.
    pub crossed_origin: bool,
}

/// Follow the redirect chain from `start` with `HEAD`, up to `max_hops`.
/// Returns the final target when it differs from `start`, plus whether the chain
/// ever left the origin. Returns `None` when there is no redirect, a request
/// errors, the `Location` is missing/unparseable, a hop would leave `scope`, or
/// the hop limit is reached while the chain is still redirecting (unsettled).
/// Once a hop crosses the origin, the HEAD probes switch to the stripped client
/// so the operator's secrets are not sent onward.
///
/// `scope`, when `Some`, is the `--scope` allowlist: a hop whose host is outside
/// it aborts the whole follow (`None`), so a redirect can never carry the scan,
/// or the next HEAD, to an out-of-scope host. The check runs *before* the
/// out-of-scope URL is ever contacted.
pub async fn resolve(
    http: &HttpClient,
    start: &Target,
    max_hops: usize,
    scope: Option<&Scope>,
) -> Option<Resolved> {
    let start_origin = origin(start.url())?;
    let stripped = http.without_extra_headers();
    let mut current = start.clone();
    let mut crossed = false;
    let mut settled = false;

    for _ in 0..max_hops {
        // Once we've left the origin, never send the operator headers again.
        let client = if crossed { &stripped } else { http };
        let resp = client.send(&current, HttpRequest::new("HEAD")).await.ok()?;
        if !REDIRECT_STATUSES.contains(&resp.status) {
            settled = true; // reached a non-redirect: the chain's real endpoint
            break;
        }
        let location = resp.header("location")?;
        let next_url = current.url().join(location).ok()?;
        // Refuse to follow (or even contact) a host outside the allowlist.
        if let Some(scope) = scope {
            let in_scope = next_url.host_str().is_some_and(|h| scope.allows_host(h));
            if !in_scope {
                return None;
            }
        }
        if origin(&next_url) != Some(start_origin) {
            crossed = true;
        }
        let next = Target::parse(next_url.as_str()).ok()?;
        if next == current {
            break; // self-redirect loop; not a resolved endpoint (settled stays false)
        }
        current = next;
    }

    // A chain that never reached a non-redirect (hop limit hit mid-redirect) is
    // unresolved; never attribute a verdict to a URL that was still redirecting.
    if !settled || current == *start {
        None
    } else {
        Some(Resolved {
            target: current,
            crossed_origin: crossed,
        })
    }
}
