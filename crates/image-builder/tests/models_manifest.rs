//! make-verify guard for the repo-root `models.toml` (the dha weights pin, Component E). A malformed
//! or typo'd pin must fail the build loudly HERE, not silently drop out of the bake's sha256 integrity
                                                                                                       
//! committed-`pins.toml` drift guard in `pins_drift.rs`.

use recipes_image_builder::models::Models;

/// Repo root from the image-builder crate dir (`crates/image-builder` → `../..`), as in `pins_drift.rs`.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root canonicalizes")
}

#[test]
fn committed_models_toml_loads_and_validates() {
                                                                                                        
                                                                                                   
    Models::load(&repo_root()).expect("repo-root models.toml loads and validates");
}
