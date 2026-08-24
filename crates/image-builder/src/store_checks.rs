//! `market verify`'s reusable store checks (§3a-4/5/6): config re-derive, format-lock drift, apk
//! closure shape-lock. Each calls the existing image-builder machinery (`Pins::check_drift`,
//! `PinnedApks::from_toml_str`) so the gate and the legacy tests can't disagree.

use std::collections::BTreeSet;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::pin_manifest::{ArtifactKind, PinManifest};
use crate::pins::{Pins, PinsError};
use crate::repo_manifest::RepoManifest;
use crate::PinnedApks;

/// The `kind=config` artifact: a plain TOML hashed like a binary (no tar). Owned by `recipes`.
const CONFIG_KEY: &str = "service-manifest";
const CONFIG_FILE: &str = "service-manifest.toml";
/// The pinned runtime apk closure shape (matches `tests/apk_verify.rs`).
const EXPECTED_APK_PACKAGES: usize = 37;
const EXPECTED_BUILD_INPUTS: [&str; 2] = ["linux-virt", "syslinux"];
                                                                                                       
/// 4 source + 5 config = 23. The 14 = the 8 base (recipes-app/recipes-admin + the 4 `fb-*` + box-init +
/// initramfs-init) + the 3 v1-dha-box bins (creatine + dha-orchestrator + epa; §4.4) + `uds-pipe`
/// (dha's std-only uds byte pump behind the /opt/dha probe scripts — fruit-basket images carry no
/// socat; published 2026-07-10, dha `faac16f`) + the 2 os-update A/B v1 bins (fb-update + fb-mark-good
/// — the box-side update engine + the mark-good health probe, enrolled at the Step-A binary staging).
/// The 5 config = `service-manifest` (recipes) + the 4 dha `/opt/dha` configs (dha-intake-probe /
/// dha-real-job-probe / dha-ac-i-selftest / dha-epa-config; §D8). A legitimate artifact add is a
/// deliberate review event that updates this literal — the same exact-shape discipline as the apk
                                                                                                         
/// repo-manifest.toml at the operator's publish gate (`market upgrade --binary` / grocer), so `market
/// verify` reports this shape RED on a branch until then — the same "reconcile at publish/land" state as
/// `vendor_integrity`.
const EXPECTED_KIND_COUNTS: (usize, usize, usize) = (15, 4, 5);
/// Where the vendored kernel.org signer keyring lives under the orchard repo root — the
/// `market upgrade --kernel` PGP trust anchor (§3a-8; `keyring/kernel.org/README.md`).
pub const KEYRING_SUBDIR: &str = "keyring/kernel.org";
/// Where the vendored Rust release signing key lives — the `market upgrade --rust` trust anchor
/// (§3a-8; `keyring/rust-lang/README.md`). Loaded via cashew's `load_pinned_bare` (SHA-1 exception).
pub const RUST_KEYRING_SUBDIR: &str = "keyring/rust-lang";

                                                                                              
/// pin-map accessor)`. Iterating this const — not `pins` — is the count-lock: a whole keyring
/// section/dir dropped fails closed (a missing `[*-keyring]` fails `Pins::load`'s required field; a
/// missing dir fails `read_dir`), never a vacuous pass. Adding a keyring is a DELIBERATE edit here
/// paired with a new `Pins` field; `expected_keyrings_is_the_locked_set` asserts the literal.
#[allow(clippy::type_complexity)]
const EXPECTED_KEYRINGS: &[(
    &str,
    &str,
    fn(&Pins) -> &std::collections::BTreeMap<String, String>,
)] = &[
    (KEYRING_SUBDIR, "kernel-keyring", |p| &p.kernel_keyring),
    (RUST_KEYRING_SUBDIR, "rust-keyring", |p| &p.rust_keyring),
];

#[derive(Debug, thiserror::Error)]
pub enum StoreCheckError {
    #[error("io {path}: {reason}")]
    Io { path: String, reason: String },
    #[error("config {CONFIG_KEY:?}: sha256({path}) = {actual} != pin {expected} (re-pin or re-run `make publish` in recipes)")]
    ConfigMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("config artifact {CONFIG_KEY:?} has no owning repo / pin")]
    ConfigUnowned,
    #[error(
        "consume-pins shape drift: expected (binary, source, config) = {expected:?}, got {got:?} — a silently added/dropped/retyped artifact (update EXPECTED_KIND_COUNTS only as a deliberate review event)"
    )]
    ConsumeShape {
        expected: (usize, usize, usize),
        got: (usize, usize, usize),
    },
    #[error("format-lock drift (run `orchard sync-pins`): {0}")]
    Drift(String),
    #[error("{script}: {issue}")]
    FetchScript { script: String, issue: String },
    #[error("pins: {0}")]
    Pins(#[from] PinsError),
    #[error("apk closure shape: {0}")]
    ApkShape(String),
    #[error(
        "vendored-keyring {file:?}: sha256 = {actual} != pin {expected} ({dir} drifted from its \
         pins — a keyring refresh is a review event, see {dir}/README.md)"
    )]
    KeyringMismatch {
        dir: String,
        file: String,
        expected: String,
        actual: String,
    },
    #[error(
        "vendored-keyring: unpinned entry {file:?} in {dir}/ (every trust-anchor file must be \
         pinned in its [*-keyring] table; README.md is the only exception)"
    )]
    KeyringUnpinned { dir: String, file: String },
}

/// §3a-1 (absolute): the consume-pins artifact set is EXACTLY the canonical per-kind shape — 8 binary +
/// 4 source + 1 config. Distinct from the manifest↔consume RELATIVE set-lock (a coordinated add to BOTH
/// files passes that; this catches it) and from `provenance` (which checks each listed pin is consistent,
/// not the cardinality). The `match` is exhaustive over `ArtifactKind`, so a future 4th kind forces an
                                                                                                         
pub fn verify_consume_shape(consume: &PinManifest) -> Result<(), StoreCheckError> {
    let (mut binary, mut source, mut config) = (0usize, 0usize, 0usize);
    for pin in consume.artifacts.values() {
        match pin.kind {
            ArtifactKind::Binary => binary += 1,
            ArtifactKind::Source => source += 1,
            ArtifactKind::Config => config += 1,
        }
    }
    let got = (binary, source, config);
    if got != EXPECTED_KIND_COUNTS {
        return Err(StoreCheckError::ConsumeShape {
            expected: EXPECTED_KIND_COUNTS,
            got,
        });
    }
    Ok(())
}

/// §3a-4: hash `recipes/service-manifest.toml` and assert == its consume-pin. `Ok(true)` if checked,
/// `Ok(false)` if the owning repo is absent + explicitly allow-missing'd.
pub fn config_rederive(
    manifest: &RepoManifest,
    consume: &PinManifest,
    repo_root: &Path,
    allow_missing: &[String],
) -> Result<bool, StoreCheckError> {
    let (repo, _) = manifest
        .owner_of(CONFIG_KEY)
        .ok_or(StoreCheckError::ConfigUnowned)?;
    let dir = manifest
        .repo_path(repo, repo_root)
        .ok_or(StoreCheckError::ConfigUnowned)?;
    let pin = consume
        .artifact(CONFIG_KEY)
        .map_err(|_| StoreCheckError::ConfigUnowned)?;
    let p = dir.join(CONFIG_FILE);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(_) => {
            if allow_missing.iter().any(|r| r == repo) {
                return Ok(false);
            }
            return Err(StoreCheckError::Io {
                path: p.display().to_string(),
                reason: "config source absent".into(),
            });
        }
    };
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != pin.sha256 {
        return Err(StoreCheckError::ConfigMismatch {
            path: p.display().to_string(),
            expected: pin.sha256.clone(),
            actual,
        });
    }
    Ok(true)
}

/// §3a-5: `pins.toml` ⟷ the generated `rust-toolchain.toml` + `Containerfile FROM` (`Pins::check_drift`),
                                                                                                    
/// script is smuggled glue).
pub fn verify_format_lock(repo_root: &Path) -> Result<(), StoreCheckError> {
    let pins = Pins::load(repo_root)?;
    let drifted = pins.check_drift(repo_root)?;
    if !drifted.is_empty() {
        return Err(StoreCheckError::Drift(drifted.join("; ")));
    }
                                                                                                         
                                                                                                      
                                                                                                       
                                                                                                  
                                                                               
                                                                        
    for script in ["fetch-kernel-source.sh", "fetch-syslinux-source.sh"] {
        let path = repo_root.join("crates/image-builder").join(script);
        if path.symlink_metadata().is_ok() {
            return Err(StoreCheckError::FetchScript {
                script: script.to_string(),
                issue: "retired fetch script resurrected — source acquisition is Rust-only \
                        (see crates/image-builder/src/sources.rs)"
                    .to_string(),
            });
        }
    }
    Ok(())
}

/// §3a-6: the apk closure is exactly the expected shape — the package count + the exact build-input
/// allowlist `{linux-virt, syslinux}`. A silently added/dropped package or build-input fails.
pub fn verify_apk_shape(repo_root: &Path) -> Result<usize, StoreCheckError> {
    let path = repo_root.join("crates/image-builder/pinned-apks.toml");
    let body = std::fs::read_to_string(&path).map_err(|e| StoreCheckError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    let apks = PinnedApks::from_toml_str(&body)
        .map_err(|e| StoreCheckError::ApkShape(format!("parse {}: {e}", path.display())))?;
    if apks.packages.len() != EXPECTED_APK_PACKAGES {
        return Err(StoreCheckError::ApkShape(format!(
            "expected exactly {EXPECTED_APK_PACKAGES} runtime packages, got {}",
            apks.packages.len()
        )));
    }
    let inputs: BTreeSet<&str> = apks.build_inputs.iter().map(|p| p.name.as_str()).collect();
    let want: BTreeSet<&str> = EXPECTED_BUILD_INPUTS.iter().copied().collect();
    if inputs != want {
        return Err(StoreCheckError::ApkShape(format!(
            "build-input set {inputs:?} != expected {want:?}"
        )));
    }
    Ok(apks.packages.len())
}

/// §3a-8: EVERY vendored keyring in `EXPECTED_KEYRINGS` (kernel.org + rust-lang) is byte-exact
/// against its `pins.toml` table, AND each keyring dir holds nothing unpinned besides `README.md` —
/// an unpinned `.asc` beside the anchors is smuggled trust material and fails closed (the same
/// exact-set allowlist discipline as the apk shape / `HOT_PATH`). Iterating the const (not `pins`) is
                                                                                                     
/// TOTAL pinned-file count across all keyrings. Each bump re-runs its byte check before cashew parses;
/// this leg keeps every anchor honest on every `market verify`.
pub fn verify_vendored_keyrings(repo_root: &Path) -> Result<usize, StoreCheckError> {
    let pins = Pins::load(repo_root)?;
    let mut total = 0;
    for (subdir, _table, accessor) in EXPECTED_KEYRINGS {
        total += verify_one_keyring(repo_root, subdir, accessor(&pins))?;
    }
    Ok(total)
}

/// Byte-check ONE keyring dir against its pin `map`, and assert the dir holds nothing unpinned
                                                                                                     
fn verify_one_keyring(
    repo_root: &Path,
    subdir: &str,
    map: &std::collections::BTreeMap<String, String>,
) -> Result<usize, StoreCheckError> {
    let dir = repo_root.join(subdir);
    for (name, want) in map {
        let p = dir.join(name);
        let bytes = std::fs::read(&p).map_err(|e| StoreCheckError::Io {
            path: p.display().to_string(),
            reason: format!("pinned keyring file unreadable: {e}"),
        })?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if &actual != want {
            return Err(StoreCheckError::KeyringMismatch {
                dir: subdir.to_string(),
                file: name.clone(),
                expected: want.clone(),
                actual,
            });
        }
    }
    let entries = std::fs::read_dir(&dir).map_err(|e| StoreCheckError::Io {
        path: dir.display().to_string(),
        reason: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| StoreCheckError::Io {
            path: dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
                                                                                                  
                                                                                                    
                                                                                               
                                                                            
        let is_regular_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        let allowed = is_regular_file && (name == "README.md" || map.contains_key(&name));
        if !allowed {
            return Err(StoreCheckError::KeyringUnpinned {
                dir: subdir.to_string(),
                file: name,
            });
        }
    }
    Ok(map.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn consume_with_kinds(binary: usize, source: usize, config: usize) -> PinManifest {
        let mut s = String::from("schema-version = 1\n");
        let sha = "a".repeat(64);
        let mut n = 0;
        for (count, kind) in [(binary, "binary"), (source, "source"), (config, "config")] {
            for _ in 0..count {
                s.push_str(&format!(
                    "[artifacts.art{n}]\nsha256 = \"{sha}\"\nkind = \"{kind}\"\n"
                ));
                n += 1;
            }
        }
        PinManifest::from_toml_str(&s).expect("fixture parses")
    }

    #[test]
    fn consume_shape_passes_on_canonical_and_fails_on_drift() {
                                                                                                       
                                                                                                     
                  
        assert!(verify_consume_shape(&consume_with_kinds(15, 4, 5)).is_ok());
                                                                          
        assert!(matches!(
            verify_consume_shape(&consume_with_kinds(14, 4, 5)),
            Err(StoreCheckError::ConsumeShape { .. })
        ));
        assert!(matches!(
            verify_consume_shape(&consume_with_kinds(16, 4, 5)),
            Err(StoreCheckError::ConsumeShape { .. })
        ));
                                                             
        assert!(matches!(
            verify_consume_shape(&consume_with_kinds(16, 4, 4)),
            Err(StoreCheckError::ConsumeShape { .. })
        ));
    }

    fn config_fixture(
        content: &str,
        pin_sha: &str,
    ) -> (tempfile::TempDir, PathBuf, RepoManifest, PinManifest) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let orchard = root.join("orchard");
        std::fs::create_dir_all(&orchard).unwrap();
        std::fs::write(
            orchard.join("consume-pins.toml"),
            format!("schema-version = 1\n[artifacts.service-manifest]\nsha256 = \"{pin_sha}\"\nkind = \"config\"\n"),
        )
        .unwrap();
        std::fs::write(
            orchard.join("repo-manifest.toml"),
            "schema-version = 1\n[repos.recipes]\npath = \"../recipes\"\nartifacts = [\"service-manifest\"]\n",
        )
        .unwrap();
        let recipes = root.join("recipes");
        std::fs::create_dir_all(&recipes).unwrap();
        std::fs::write(recipes.join("service-manifest.toml"), content).unwrap();
        let m = RepoManifest::load(&orchard.join("repo-manifest.toml")).unwrap();
        let c = PinManifest::load(&orchard.join("consume-pins.toml")).unwrap();
        (tmp, orchard, m, c)
    }

    #[test]
    fn config_rederive_matches_the_pin() {
        let content = "name = \"x\"\n";
        let sha = hex::encode(Sha256::digest(content.as_bytes()));
        let (_t, root, m, c) = config_fixture(content, &sha);
        assert!(config_rederive(&m, &c, &root, &[]).unwrap());
    }

    #[test]
    fn config_rederive_fails_on_edited_source() {
                                                                                           
        let pin = hex::encode(Sha256::digest(b"different"));
        let (_t, root, m, c) = config_fixture("name = \"x\"\n", &pin);
        assert!(matches!(
            config_rederive(&m, &c, &root, &[]),
            Err(StoreCheckError::ConfigMismatch { .. })
        ));
    }

    const RUST_KEY_BYTES: &[u8] = b"RUSTKEY";
    fn rust_key_sha() -> String {
        hex::encode(Sha256::digest(RUST_KEY_BYTES))
    }

    /// A minimal repo root: a valid pins.toml + BOTH vendored keyring dirs, each = (dir files, pins).
    fn keyring_fixture_2(
        kernel_files: &[(&str, &[u8])],
        kernel_pins: &[(&str, String)],
        rust_files: &[(&str, &[u8])],
        rust_pins: &[(&str, String)],
    ) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let sha = "a".repeat(64);
        let mut pins = format!(
            "[kernel]\nversion = \"6.18.34\"\nsha256 = \"{sha}\"\n\
             [syslinux]\nversion = \"6.04-pre1\"\nsha256 = \"{sha}\"\n\
             [rust]\nversion = \"1.96.0\"\nalpine_base = \"alpine:3.23\"\n\
             alpine_base_digest = \"sha256:{sha}\"\n\
             toolchain_musl_url = \"https://static.rust-lang.org/dist/d/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz\"\n\
             toolchain_musl_sha256 = \"{sha}\"\n\
             std_uefi_url = \"https://static.rust-lang.org/dist/d/rust-std-1.96.0-x86_64-unknown-uefi.tar.xz\"\n\
             std_uefi_sha256 = \"{sha}\"\ncontainer_digest = \"sha256:{sha}\"\n"
        );
        for (table, entries) in [("kernel-keyring", kernel_pins), ("rust-keyring", rust_pins)] {
            pins.push_str(&format!("[{table}]\n"));
            for (k, v) in entries {
                pins.push_str(&format!("\"{k}\" = \"{v}\"\n"));
            }
        }
        std::fs::write(root.join("pins.toml"), pins).unwrap();
        for (subdir, files) in [
            (KEYRING_SUBDIR, kernel_files),
            (RUST_KEYRING_SUBDIR, rust_files),
        ] {
            let dir = root.join(subdir);
            std::fs::create_dir_all(&dir).unwrap();
            for (name, bytes) in files {
                std::fs::write(dir.join(name), bytes).unwrap();
            }
        }
        (tmp, root)
    }

    /// The common case: vary the KERNEL keyring; the rust keyring is valid-by-default.
    fn keyring_fixture(
        kernel_files: &[(&str, &[u8])],
        kernel_pins: &[(&str, String)],
    ) -> (tempfile::TempDir, PathBuf) {
        keyring_fixture_2(
            kernel_files,
            kernel_pins,
            &[("rust-signing.asc", RUST_KEY_BYTES)],
            &[("rust-signing.asc", rust_key_sha())],
        )
    }

    #[test]
    fn expected_keyrings_is_the_locked_set() {
                                                                                                          
        let set: Vec<(&str, &str)> = EXPECTED_KEYRINGS
            .iter()
            .map(|(sd, tbl, _)| (*sd, *tbl))
            .collect();
        assert_eq!(
            set,
            [
                ("keyring/kernel.org", "kernel-keyring"),
                ("keyring/rust-lang", "rust-keyring"),
            ]
        );
    }

    #[test]
    fn vendored_keyrings_green_counts_both_and_readme_exempt() {
        let sha = hex::encode(Sha256::digest(b"KEY"));
        let (_t, root) = keyring_fixture(
            &[("gregkh.asc", b"KEY"), ("README.md", b"doc")],
            &[("gregkh.asc", sha)],
        );
                                               
        assert_eq!(verify_vendored_keyrings(&root).unwrap(), 2);
    }

    #[test]
    fn vendored_keyrings_fail_on_byte_drift_in_either_dir() {
        let sha = hex::encode(Sha256::digest(b"KEY"));
                                                
        let (_t, root) =
            keyring_fixture(&[("gregkh.asc", b"EVIL")], &[("gregkh.asc", sha.clone())]);
        match verify_vendored_keyrings(&root) {
            Err(StoreCheckError::KeyringMismatch { dir, .. }) => {
                assert_eq!(dir, "keyring/kernel.org")
            }
            other => panic!("kernel drift must fail, got {other:?}"),
        }
                                     
        let (_t, root) = keyring_fixture_2(
            &[("gregkh.asc", b"KEY")],
            &[("gregkh.asc", sha)],
            &[("rust-signing.asc", b"EVIL")],
            &[("rust-signing.asc", rust_key_sha())],
        );
        match verify_vendored_keyrings(&root) {
            Err(StoreCheckError::KeyringMismatch { dir, file, .. }) => {
                assert_eq!(dir, "keyring/rust-lang");
                assert_eq!(file, "rust-signing.asc");
            }
            other => panic!("rust drift must fail, got {other:?}"),
        }
    }

    #[test]
    fn vendored_keyrings_fail_on_absent_pinned_file() {
        let sha = hex::encode(Sha256::digest(b"KEY"));
        let (_t, root) = keyring_fixture(&[], &[("gregkh.asc", sha)]);
        assert!(matches!(
            verify_vendored_keyrings(&root),
            Err(StoreCheckError::Io { .. })
        ));
    }

    #[test]
    fn vendored_keyrings_fail_closed_on_unpinned_trust_material() {
                                                                                                   
        let sha = hex::encode(Sha256::digest(b"KEY"));
        let (_t, root) = keyring_fixture(
            &[("gregkh.asc", b"KEY"), ("rogue.asc", b"MALLORY")],
            &[("gregkh.asc", sha.clone())],
        );
        match verify_vendored_keyrings(&root) {
            Err(StoreCheckError::KeyringUnpinned { dir, file }) => {
                assert_eq!(dir, "keyring/kernel.org");
                assert_eq!(file, "rogue.asc");
            }
            other => panic!("unpinned kernel material must fail closed, got {other:?}"),
        }
                                                     
        let (_t, root) = keyring_fixture_2(
            &[("gregkh.asc", b"KEY")],
            &[("gregkh.asc", sha)],
            &[
                ("rust-signing.asc", RUST_KEY_BYTES),
                ("rogue.asc", b"MALLORY"),
            ],
            &[("rust-signing.asc", rust_key_sha())],
        );
        match verify_vendored_keyrings(&root) {
            Err(StoreCheckError::KeyringUnpinned { dir, file }) => {
                assert_eq!(dir, "keyring/rust-lang");
                assert_eq!(file, "rogue.asc");
            }
            other => panic!("unpinned rust material must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn vendored_keyrings_fail_closed_on_dropped_dir() {
                                                                                                         
        let sha = hex::encode(Sha256::digest(b"KEY"));
        let (_t, root) = keyring_fixture(&[("gregkh.asc", b"KEY")], &[("gregkh.asc", sha)]);
        std::fs::remove_dir_all(root.join(RUST_KEYRING_SUBDIR)).unwrap();
        assert!(
            matches!(
                verify_vendored_keyrings(&root),
                Err(StoreCheckError::Io { .. })
            ),
            "a dropped rust keyring dir must fail closed"
        );
    }

    #[test]
    fn vendored_keyrings_readme_exemption_is_type_checked() {
                                                                                                  
        let sha = hex::encode(Sha256::digest(b"KEY"));
        let (_t, root) = keyring_fixture(&[("gregkh.asc", b"KEY")], &[("gregkh.asc", sha)]);
        let readme_dir = root.join(KEYRING_SUBDIR).join("README.md");
        std::fs::create_dir(&readme_dir).unwrap();
        std::fs::write(readme_dir.join("smuggled.asc"), b"MALLORY").unwrap();
        match verify_vendored_keyrings(&root) {
            Err(StoreCheckError::KeyringUnpinned { file, .. }) => assert_eq!(file, "README.md"),
            other => panic!("a README.md-named directory must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn config_rederive_absent_recipes_hard_fail_unless_allow_missing() {
        let pin = hex::encode(Sha256::digest(b"x"));
        let (_t, root, m, c) = config_fixture("x", &pin);
                                                                                    
        std::fs::remove_dir_all(root.join("../recipes")).unwrap();
        assert!(
            config_rederive(&m, &c, &root, &[]).is_err(),
            "absent config source is a HARD FAIL"
        );
        assert!(
            !config_rederive(&m, &c, &root, &["recipes".to_string()]).unwrap(),
            "allow-missing recipes → skipped (Ok(false))"
        );
    }

                                                                                                                                              

    /// A synced §3a-5 fixture repo-root: the three REAL format-locked files copied from this repo
    /// (guaranteed synced — `make verify` is green on the real tree), so the fixture is high-fidelity
    /// and cannot silently drift from what `check_drift` actually reads.
    fn format_lock_fixture() -> (tempfile::TempDir, PathBuf) {
        let real_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(root.join("crates/image-builder")).unwrap();
        for rel in [
            "pins.toml",
            "rust-toolchain.toml",
            "crates/image-builder/Containerfile",
        ] {
            std::fs::copy(real_root.join(rel), root.join(rel)).unwrap();
        }
        (tmp, root)
    }

    #[test]
    fn format_lock_passes_on_a_clean_synced_fixture() {
        let (_t, root) = format_lock_fixture();
        verify_format_lock(&root).expect("a clean synced fixture (no fetch scripts) passes");
    }

    #[test]
    fn format_lock_still_fails_on_toolchain_or_containerfile_drift() {
                                                                                                      
                                                                    
        let (_t, root) = format_lock_fixture();
        let cf = root.join("crates/image-builder/Containerfile");
        let body = std::fs::read_to_string(&cf).unwrap();
                                                                                                    
                                                                                                  
                                                       
        let mut lines: Vec<String> = body.lines().map(str::to_string).collect();
        let from_idx = lines
            .iter()
            .position(|l| l.starts_with("FROM "))
            .expect("the fixture Containerfile has a FROM directive line");
        lines[from_idx] = "FROM docker.io/library/alpine:3.23@sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        std::fs::write(&cf, lines.join("\n") + "\n").unwrap();
        match verify_format_lock(&root) {
            Err(StoreCheckError::Drift(_)) => {}
            other => {
                panic!("a Containerfile FROM drift must still fail check_drift, got {other:?}")
            }
        }
    }

    #[test]
    fn format_lock_fails_closed_on_a_resurrected_fetch_script() {
                                                                                                        
                                                                      
        for script in ["fetch-kernel-source.sh", "fetch-syslinux-source.sh"] {
            let (_t, root) = format_lock_fixture();
            let path = root.join("crates/image-builder").join(script);
            std::fs::write(&path, "#!/bin/sh\nVERSION=7.0\n").unwrap();
            match verify_format_lock(&root) {
                Err(StoreCheckError::FetchScript { script: s, .. }) => assert_eq!(s, script),
                other => panic!("a resurrected {script} must fail closed, got {other:?}"),
            }
            std::fs::remove_file(&path).unwrap();

                                                                                              
            std::os::unix::fs::symlink("/etc/hostname", &path).unwrap();
            match verify_format_lock(&root) {
                Err(StoreCheckError::FetchScript { script: s, .. }) => assert_eq!(s, script),
                other => panic!("a resurrected {script} SYMLINK must fail closed, got {other:?}"),
            }
        }
    }
}
