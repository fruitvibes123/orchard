//! `market verify` integration self-test (the public `verify` entry, end-to-end). Every check must FIRE
                                                                                                        
//! expected check set. The collect-all / exact-check-set-lock assembly logic is unit-tested white-box in
//! `src/deploy/market.rs` (it reaches the private `CheckReport`); per-check fail-closed cases live in the
//! lib modules (provenance/seed_agree/store_checks/cert_presence). This file covers the fixture-expressible
//! fail-closed verdicts (manifest omission/extra → a collected `ManifestArtifactSet` failure) + the
                                                                                

use std::path::Path;

use orchard::deploy::market::{CheckFailures, CheckId, MarketError, VerifyOpts, verify};

/// Write a `consume-pins.toml` + `repo-manifest.toml` into `root`.
fn write_fixture(root: &Path, consume: &[(&str, &str)], repos: &[(&str, &str, &[&str])]) {
    let mut c = String::from("schema-version = 1\n");
    for (key, kind) in consume {
        c.push_str(&format!(
            "[artifacts.{key}]\nsha256 = \"{}\"\nkind = \"{kind}\"\n",
            "a".repeat(64)
        ));
    }
    std::fs::write(root.join("consume-pins.toml"), c).unwrap();

    let mut m = String::from("schema-version = 1\n");
    for (name, path, arts) in repos {
        let list = arts
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        m.push_str(&format!(
            "[repos.{name}]\npath = \"{path}\"\nartifacts = [{list}]\n"
        ));
    }
    std::fs::write(root.join("repo-manifest.toml"), m).unwrap();
}

fn opts(root: &Path) -> VerifyOpts {
    VerifyOpts {
        repo_root: root.to_path_buf(),
        repo_manifest: root.join("repo-manifest.toml"),
        artifact_store: root.join("../artifact-store"),
        certs: false,
        all: false,
        allow_missing: vec![],
    }
}

/// True iff `err` is a `ChecksFailed` whose `manifest-artifact-set` leg failed with `needle` in its detail.
/// (A bare fixture trips many legs; this isolates the artifact-set lock's specific verdict.)
fn artifact_set_leg_failed(err: &MarketError, needle: &str) -> bool {
    match err {
        MarketError::ChecksFailed(CheckFailures(fs)) => fs
            .iter()
            .any(|c| c.id == CheckId::ManifestArtifactSet && c.detail.contains(needle)),
        _ => false,
    }
}

#[test]
fn manifest_omitting_an_artifact_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
                                                                                                      
                                                                                                    
                                                                                            
    write_fixture(
        dir.path(),
        &[("recipes-app", "binary"), ("grape-src", "source")],
        &[("recipes", "../../recipes", &["recipes-app"])],
    );
    let err = verify(&opts(dir.path())).unwrap_err();
    assert!(
        artifact_set_leg_failed(&err, "grape-src"),
        "an omitted artifact must fail the manifest-artifact-set leg naming it, got {err:?}"
    );
}

#[test]
fn manifest_with_an_extra_artifact_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    write_fixture(
        dir.path(),
        &[("recipes-app", "binary")],
        &[("recipes", "../../recipes", &["recipes-app", "ghost"])],
    );
    let err = verify(&opts(dir.path())).unwrap_err();
    assert!(
        artifact_set_leg_failed(&err, "ghost"),
        "an extra artifact must fail the manifest-artifact-set leg naming it, got {err:?}"
    );
}
