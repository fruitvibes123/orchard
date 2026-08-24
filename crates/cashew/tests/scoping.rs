                                                                                                    
//! convention-level locks (the `tree_lock` idiom), NOT a claim of type-level non-bypassability:
//!  1. the bare-path CALL is made by exactly the allowlisted files — a new caller anywhere fails
//!     closed until the list is deliberately extended (Component C Task 4 adds the rust bump);
//!  2. SHA-1 is constructed at exactly ONE site in cashew (the v4 fingerprint in key.rs), so the E-2
//!     property — SHA-1 is never a signature-verify input — survives the bare path (which SKIPS
//!     self-certs; it does not hash them, and references no SHA-1 at all).

use std::path::{Path, PathBuf};

/// Workspace root = two levels above this crate's manifest dir (crates/cashew → crates → root).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root above crates/cashew")
        .to_path_buf()
}

/// All `.rs` files under `dir`, recursively (skipping any `target`).
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Workspace-relative slash paths of `.rs` files under `crates/<rel>` whose text contains `needle`.
fn files_containing(rel: &str, needle: &str) -> Vec<String> {
    let root = workspace_root();
    let mut files = Vec::new();
    rs_files(&root.join(rel), &mut files);
    let mut hits: Vec<String> = files
        .into_iter()
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|s| s.contains(needle))
                .unwrap_or(false)
        })
        .map(|p| {
            p.strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    hits.sort();
    hits
}

                                                                                                 
/// file does not itself match the call pattern.
#[test]
fn load_pinned_bare_call_sites_are_allowlisted() {
    let needle = concat!("load_pinned_bare", "(");
                                                                                                       
                                                                                                        
                        
    let allowed = [
        "crates/cashew/src/pinned.rs",
        "crates/cashew/tests/pinned.rs",
        "crates/orchard/src/deploy/rust_bump.rs",
    ];
    assert_eq!(
        files_containing("crates", needle),
        allowed,
        "load_pinned_bare call-site set drifted from the allowlist (scoping)"
    );
}

/// (E-2) SHA-1 lives at exactly one construction site in cashew — the v4 fingerprint in key.rs. The
/// bare path references no SHA-1 at all (it skips self-certs, never hashing them).
#[test]
fn sha1_is_a_single_construction_site_in_cashew() {
    let type_token = concat!("Sha", "1");                                      
    assert_eq!(
        files_containing("crates/cashew/src", type_token),
        ["crates/cashew/src/key.rs"],
        "SHA-1 usage escaped key.rs (E-2 — SHA-1 must never be a verify input)"
    );

    let pinned =
        std::fs::read_to_string(workspace_root().join("crates/cashew/src/pinned.rs")).unwrap();
    assert!(
        !pinned.to_lowercase().contains("sha1"),
        "pinned.rs must not reference SHA-1 (E-2)"
    );
}
