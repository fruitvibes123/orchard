//! `orchard vendor`: (re)populate vendor/ from the artifact store, verifying every source-drop tarball's
                                                                                                 
//! missing/mismatched drop aborts. Idempotent — safe to re-run.
//!
//! Only the `*-src` source artifacts (the deterministic crate tarballs: grape/dragonfruit/rambutan/
//! fb-manifest) are vendored-via-tar here. `service-manifest` is also `kind = "source"` in the manifest
//! but is a plain TOML file (the recipes tenant manifest), NOT a tarball — it's fetched+verified at
//! bake-time as the manifest INPUT, so the vendor loop skips it (the `-src` suffix is the tarball marker).
use recipes_image_builder::artifact_store::DirStore;
use recipes_image_builder::pin_manifest::{ArtifactKind, PinManifest};
use recipes_image_builder::vendor::vendor_source_drop;
use std::path::Path;

/// The `vendor/PROVENANCE.md` content — a GENERATED doc, emitted by every [`vendor`] run (its own
/// header always said "GENERATED (do not hand-edit)"; the comfort follow-up made that true). Being
/// derived output, it survives the market-upgrade stage's WHOLESALE `vendor/` dir swap by
/// construction — before this, the committed doc was silently deleted on every `--source`/
/// `--binary` re-pin (drive-surfaced). The `vendor_emits_the_committed_provenance_doc` test locks
/// this const byte-exact against the committed file.
pub const PROVENANCE_DOC: &str = r#"# vendor/ — pinned source, GENERATED (do not hand-edit)

These crate trees are **vendored pinned source** for the pinned supply chain. Each was
fetched from the operator artifact store and **verified against its sha256 in
`../consume-pins.toml`** before unpacking (the verify-at-consumption gate; a mismatch aborts).

| dir | store key | owner repo | used by |
|-----|-----------|------------|---------|
| `grape/` | `grape-src` | seed-vault | image-builder + orchard (rescue host-key seed derive) |
| `dragonfruit/` | `dragonfruit-src` | seed-vault | orchard CLI only (`[sign]` — the artifact signer; CRUX) |
| `fb-manifest/` | `fb-manifest-src` | fruit-basket | image-builder (the typed service-manifest schema) |
| `rambutan/` | `rambutan-src` | fruit-basket | the UEFI loader, compiled per-bake in the `Firmware::Uefi` arm only |

`consume-pins.toml` is the authority. To regenerate after a pin-bump:

```sh
make vendor        # = orchard vendor: fetch + verify each *-src tarball, unpack here
```

**Do not hand-edit** these trees — `make vendor` overwrites them, and the committed bytes must
match the pinned shas (a future audit / `repro-check` re-derives them). The committed copy gives
an offline-buildable, reviewable checkout (the operator chose commit-vendored); the shas in
`consume-pins.toml` remain the integrity authority regardless of what's committed here.
"#;

pub fn vendor(repo_root: &Path, store: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let manifest = PinManifest::load(&repo_root.join("consume-pins.toml"))?;
    let store_be = DirStore::new(store);
    let vendor_root = repo_root.join("vendor");
    let mut n = 0;
    for (key, pin) in &manifest.artifacts {
        if pin.kind != ArtifactKind::Source {
            continue;
        }
                                                                                                         
                                                                              
        if !key.ends_with("-src") {
            continue;
        }
        vendor_source_drop(&store_be, key, &pin.sha256, &vendor_root)?;
        n += 1;
    }
                                                                                                 
                                                                                                        
    std::fs::create_dir_all(&vendor_root)?;
    std::fs::write(vendor_root.join("PROVENANCE.md"), PROVENANCE_DOC)?;
    Ok(format!(
        "vendor: {n} source drops verified + unpacked into {} (+ PROVENANCE.md)",
        vendor_root.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drift lock: the emitted doc IS the committed file, byte-exact. A hand-edit to either
    /// side without the other fails here (the doc's "GENERATED" claim stays true).
    #[test]
    fn vendor_emits_the_committed_provenance_doc() {
        let committed =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/PROVENANCE.md");
        let committed =
            std::fs::read_to_string(&committed).expect("the committed vendor/PROVENANCE.md exists");
        assert_eq!(
            committed, PROVENANCE_DOC,
            "vendor/PROVENANCE.md and vendor_cmd::PROVENANCE_DOC must be byte-identical — \
             edit the const and re-run `make vendor` (or vice versa)"
        );
    }

    /// The doc is written even when the manifest has zero source drops — a re-derived vendor tree
    /// is never missing it (the wholesale-swap survival guarantee).
    #[test]
    fn vendor_writes_provenance_even_with_no_source_drops() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("consume-pins.toml"),
            format!(
                "schema-version = 1\n[artifacts.box-init]\nkind = \"binary\"\nsha256 = \"{}\"\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let summary = vendor(dir.path(), &store).unwrap();
        assert!(summary.contains("PROVENANCE.md"), "{summary}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("vendor/PROVENANCE.md")).unwrap(),
            PROVENANCE_DOC
        );
    }
}
