                                                               
//!
//! The 8 in-image BINARIES are sha256-verified at EVERY bake (`fetch_verified`). The vendored SOURCE
//! drops are compiled from the on-disk `vendor/` tree (grape/dragonfruit[the CRUX artifact signer]/
//! fb-manifest into the `orchard` CLI at `cargo build` time; rambutan into the UEFI loader at bake).
//! Without a gate their integrity would rest on operator DISCIPLINE (remembering `make vendor` + diff
//! review), NOT a mechanism — asymmetric with the binaries.
//!
//! `vendor::verify_vendored_tree` re-tars each `vendor/<crate>` with the publish-side deterministic flags
//! and asserts the sha256 == `consume-pins.toml`. It is the EXACT check `orchard build` runs at bake
                                                                                                    
//! point. This test exercises that SAME production function under `cargo test --workspace` (so `make
//! verify` also fails on a tampered/stale `vendor/`). Read-only; needs only the committed `vendor/` +
//! `consume-pins.toml`. It assumes host GNU tar reproduces the publish tar byte-for-byte (the same
//! assumption `repro-check` already relies on; empirically true for all four drops on the pinned host).

use recipes_image_builder::pin_manifest::PinManifest;
use recipes_image_builder::vendor::verify_vendored_tree;
use std::path::Path;

#[test]
fn vendored_source_drops_match_their_consume_pins() {
                                                                                                            
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pins =
        PinManifest::load(&repo_root.join("consume-pins.toml")).expect("load consume-pins.toml");
    let n = verify_vendored_tree(&repo_root.join("vendor"), &pins)
        .expect("vendor/ matches consume-pins (re-run `make vendor` if this fails)");
    assert!(
        n >= 4,
        "expected the 4 vendored source drops (grape/dragonfruit/fb-manifest/rambutan), verified {n}"
    );
}
