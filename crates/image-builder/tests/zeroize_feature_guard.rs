//! Fail-closed FEATURE guard for the docker-rung at-rest key zeroization.
//!
//! The docker rung's at-rest wipes rest on two crate FEATURES, not merely on the
//! crates being present — so the name-level `shipped_crate_allowlist` (which asserts
//! the crate SET) does NOT cover them. A `cargo machete` / "unused dep" prune of
//! orchard's direct dep on either crate would COMPILE, keep the name-level allowlist
//! and clippy green, yet SILENTLY drop the wipe. This guard makes each feature a
//! tested invariant in the orchard host graph:
//!
//!   * `poly1305` built WITH `zeroize` — wipes the one-time-MAC `State` (keywrap
//!     intermediate audit R2/R3). It rests SOLELY on orchard's direct
//!     `poly1305 = { features = ["zeroize"] }`: `chacha20poly1305` pulls `poly1305`
//!     WITHOUT `zeroize`, so a pruned direct dep drops the wipe via feature-unification.
//!   * `ed25519-dalek` built WITH `zeroize` — wipes the `SigningKey` SEED on drop
//!     (keygen-wrapping audit F-2). Requested by BOTH orchard's own Cargo.toml AND vendored
//!     dragonfruit's, so — unlike poly1305 — removing either one alone would not regress it
//!     today; this guard catches the COMPOUND removal that would.
//!
//! Mirrors `shipped_crate_allowlist.rs` / `vendor/rambutan/tests/tree_lock.rs`
                                                                                    
//! tested invariant, SELF-TESTED so it provably fires, wired into `make verify`'s
//! always-on `cargo test --workspace` leg (plus the `crypto-sentry` alias) — NEVER
//! `#[ignore]`d. Resolved `--locked` (a stale lock fails loud, never a silent
//! re-resolve) at the operator-host target the sign path builds for.

use std::collections::BTreeSet;
use std::process::Command;

/// The operator-host target the orchard sign path builds for (matches
/// `shipped_crate_allowlist`'s `HOST_TARGET`).
const HOST_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Repo root, relative to this crate (`crates/image-builder`).
fn workspace_root() -> String {
    format!("{}/../..", env!("CARGO_MANIFEST_DIR"))
}

/// The enabled-feature set of EVERY resolved version of `crate_name` in the orchard host
/// graph, read from the ROOT lines of `cargo tree -i <crate> --format "{p}|{f}"` (invert
/// → each resolved version of the crate is an un-indented tree root carrying its UNIFIED
/// feature list; its reverse-dependents are indented beneath it). Returning EVERY root
/// (not just the first) closes the multi-version gap: if a future diamond dependency ever
/// resolves two versions side-by-side, a second, unprotected instance is still inspected.
/// Fails closed: a non-zero cargo exit or ZERO roots panics rather than scanning an empty
/// set and passing vacuously.
fn root_feature_sets(crate_name: &str) -> Vec<BTreeSet<String>> {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-i",
            crate_name,
            "--edges",
            "normal",
            "--target",
            HOST_TARGET,
            "--locked",
            "--format",
            "{p}|{f}",
        ])
        .current_dir(workspace_root())
        .output()
        .unwrap_or_else(|e| panic!("spawn `cargo tree -i {crate_name}`: {e}"));
    assert!(
        out.status.success(),
        "`cargo tree -i {crate_name}` failed (status {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).expect("cargo tree stdout is utf8");
    let roots: Vec<BTreeSet<String>> = stdout
        .lines()
        .filter(|l| is_root_line(l, crate_name))
        .map(parse_features)
        .collect();
    assert!(
        !roots.is_empty(),
        "`cargo tree -i {crate_name}` produced no root line for `{crate_name}` — absent from the graph?"
    );
    roots
}

/// True iff `line` is an un-indented `cargo tree -i` ROOT for `crate_name` (i.e. one of
/// its resolved versions), not an indented reverse-dependent. Dependents begin with a
/// box-drawing glyph or whitespace; a root begins with `<crate_name> ` (name then space
/// before the version), so `foo` never matches a `foo-bar` root.
fn is_root_line(line: &str, crate_name: &str) -> bool {
    let indented = line.starts_with(|c: char| c.is_whitespace() || "│├└─".contains(c));
    !indented
        && line
            .strip_prefix(crate_name)
            .is_some_and(|rest| rest.starts_with(' '))
}

/// Parse a `{p}|{f}` line into its enabled-feature set: the tail after the LAST `|` is the
/// comma-separated feature list. `rsplit_once` (not `split_once`) so a package field that
/// itself contained a `|` — e.g. a path-dependency whose checkout path has one — can't be
/// mistaken for the separator. e.g. `poly1305 v0.8.0|zeroize` → `{"zeroize"}`; an empty
/// tail (`…|`) is no features. Pure, so the comparison is self-testable without shelling out.
fn parse_features(line: &str) -> BTreeSet<String> {
    line.rsplit_once('|')
        .map(|(_, f)| f)
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn assert_feature_enabled(crate_name: &str, feature: &str, why: &str) {
                                                                                        
                                          
    for feats in root_feature_sets(crate_name) {
        assert!(
            feats.contains(feature),
            "SUPPLY-CHAIN REGRESSION: `{crate_name}` is built WITHOUT the `{feature}` feature in the \
             orchard host graph (a resolved version's enabled set: {feats:?}).\n  \
             {why}\n  \
             The wipe rests on this feature staying enabled; a `cargo machete` / unused-dep prune of \
             orchard's direct `{crate_name}` dependency would silently drop it (still compiles; the \
             name-level shipped_crate_allowlist + clippy stay green). If this change is DELIBERATE, \
             re-audit the at-rest zeroization story and update this guard in the SAME commit."
        );
    }
}

#[test]
fn poly1305_is_built_with_zeroize() {
    assert_feature_enabled(
        "poly1305",
        "zeroize",
        "poly1305/zeroize wipes the one-time-MAC State (keywrap audit R2/R3); it rests SOLELY on \
         orchard's direct `poly1305 = { features = [\"zeroize\"] }` — chacha20poly1305 pulls \
         poly1305 WITHOUT zeroize.",
    );
}

#[test]
fn ed25519_dalek_is_built_with_zeroize() {
    assert_feature_enabled(
        "ed25519-dalek",
        "zeroize",
        "ed25519-dalek/zeroize wipes the SigningKey seed on drop (keygen-wrapping audit F-2). \
         Unlike poly1305 (single-sourced), this feature is requested by BOTH orchard's own \
         Cargo.toml AND vendored dragonfruit's — so today it survives removing either one alone; \
         this guard catches the COMPOUND removal (both) that would actually regress the wipe.",
    );
}

/// Self-test: prove the feature comparison fires in BOTH directions (a guard that
                                                                                      
/// the pure `parse_features` so it needs no cargo shell-out, exactly as
/// `shipped_crate_allowlist::diff_self_test` self-tests its pure comparison.
#[test]
fn feature_parse_self_test_fires_on_absent_feature() {
                                                           
    let present = parse_features("ed25519-dalek v2.2.0|alloc,default,fast,std,zeroize");
    assert!(
        present.contains("zeroize"),
        "must detect an enabled feature"
    );

                                                                                     
                                            
    let absent = parse_features("poly1305 v0.8.0|alloc");
    assert!(
        !absent.contains("zeroize"),
        "must fire (feature reported absent) when zeroize is not enabled"
    );

                                                                                          
    assert!(
        parse_features("poly1305 v0.8.0|").is_empty(),
        "empty feature tail = no features"
    );

                                                                                        
                                                                                  
    let pathy = parse_features("foo v1.0.0 (/we|rd/path)|zeroize");
    assert!(
        pathy.contains("zeroize") && pathy.len() == 1,
        "the LAST `|` is the separator, so a `|` in the path is ignored: {pathy:?}"
    );

                                                                                   
                                                                                          
    assert!(is_root_line("poly1305 v0.8.0|zeroize", "poly1305"), "root");
    assert!(
        !is_root_line("├── chacha20poly1305 v0.10.1|alloc", "chacha20poly1305"),
        "an indented reverse-dependent is not a root"
    );
    assert!(
        !is_root_line("poly1305-foo v1.0.0|x", "poly1305"),
        "the name boundary must be exact (poly1305 != poly1305-foo)"
    );
}
