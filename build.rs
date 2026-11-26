//! Capture the short git SHA at build time into `X2S_GIT_SHA` for run metadata.
//! Absent (not a git checkout, or git missing) → the env var is simply unset and
//! `option_env!` yields `None`.

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if let Some(sha) = sha {
        println!("cargo:rustc-env=X2S_GIT_SHA={sha}");
    }
    // Re-run when HEAD moves so the baked SHA stays current. `.git/HEAD` only
    // changes on a branch *switch*; a new commit on the current branch updates
    // that branch's ref file (loose) or `.git/packed-refs` (packed). Watch only
    // the paths that actually exist — Cargo treats a watched-but-missing file as
    // a change and rebuilds every time, so an absent `packed-refs` (loose repo)
    // would thrash the cache.
    let git = std::path::Path::new(".git");
    let mut candidates = vec![git.join("HEAD"), git.join("packed-refs")];
    if let Some(full) = Command::new("git")
        .args(["rev-parse", "--symbolic-full-name", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "HEAD")
    {
        candidates.push(git.join(full)); // e.g. .git/refs/heads/main (loose)
    }
    for p in candidates {
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
}
