//! Integration tests for `market upgrade --rust` — fixture-driven, NON-ignored (they run in
//! `make verify` via `cargo test -p orchard`; the env-armed produced-bytes chain lives in
//! `tests/rust_upgrade_gate.rs`). Every case runs the REAL bump (real staging, real `load_pinned_bare`
//! verify, real toml parse) with ONLY the transport faked (a URL→bytes map). Fixtures are the committed
//! corpus under tests/fixtures/rust_bump/gen/ (see gen.sh; tests bind via MANIFEST.toml).

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orchard::deploy::market_exec::{Stage, StoreLayout, resolve_layout};
use orchard::deploy::rust_bump::{RUST_MANIFEST_BASE, RustBump, bump_rust};
use recipes_image_builder::Fetcher;
use recipes_image_builder::repo_manifest::RepoManifest;
use sha2::{Digest, Sha256};

struct Fx {
    version: String,
    older_version: String,
    now: SystemTime,
    signer_fpr: String,
    signer_asc: Vec<u8>,
    signer_sha: String,
    manifest: Vec<u8>,
    manifest_asc: Vec<u8>,
    tampered: Vec<u8>,
    unpinned_asc: Vec<u8>,
    older: Vec<u8>,
    older_asc: Vec<u8>,
    unavailable: Vec<u8>,
    unavailable_asc: Vec<u8>,
}

fn fx() -> Fx {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rust_bump/gen");
    let man: toml::Value =
        toml::from_str(&fs::read_to_string(d.join("MANIFEST.toml")).expect("manifest")).unwrap();
    let read = |n: &str| fs::read(d.join(n)).unwrap_or_else(|e| panic!("fixture {n}: {e}"));
    let signer_asc = read("signer.asc");
    Fx {
        version: man["version"].as_str().unwrap().to_string(),
        older_version: man["older_version"].as_str().unwrap().to_string(),
        now: UNIX_EPOCH + Duration::from_secs(man["fixture_now"].as_integer().unwrap() as u64),
        signer_fpr: man["keys"]["signer"].as_str().unwrap().to_string(),
        signer_sha: hex::encode(Sha256::digest(&signer_asc)),
        signer_asc,
        manifest: read("manifest.toml"),
        manifest_asc: read("manifest.toml.asc"),
        tampered: read("manifest-tampered.toml"),
        unpinned_asc: read("unpinned.asc"),
        older: read("manifest-older.toml"),
        older_asc: read("manifest-older.toml.asc"),
        unavailable: read("manifest-unavailable.toml"),
        unavailable_asc: read("manifest-unavailable.toml.asc"),
    }
}

struct Eco {
    _tmp: tempfile::TempDir,
    layout: StoreLayout,
    pins_paths: Vec<PathBuf>,
}

/// `<tmp>/eco/orchard` (+ keyring/rust-lang/rust-signing.asc) with three sibling repos, each carrying
/// the SAME pins.toml whose `[rust-keyring]` pins rust-signing.asc at `keyring_sha`. The `[rust]`
/// block has OLD toolchain values a bump replaces; alpine_base*/container_digest are the invariants.
fn eco(fx: &Fx, keyring_sha: &str) -> Eco {
    let tmp = tempfile::tempdir().unwrap();
    let orchard = tmp.path().join("eco/orchard");
    fs::create_dir_all(orchard.join("keyring/rust-lang")).unwrap();
    fs::write(
        orchard.join("keyring/rust-lang/rust-signing.asc"),
        &fx.signer_asc,
    )
    .unwrap();
    fs::create_dir_all(orchard.join("vendor")).unwrap();
    let z = "0".repeat(64);
    let pins = format!(
        "# fixture pins\n[kernel]\nversion = \"6.18.34\"\nsha256 = \"{z}\"\n\n\
         [syslinux]\nversion = \"6.04-pre1\"\nsha256 = \"{z}\"\n\n\
         [rust]\n# the rust pin\nversion = \"1.96.0\"\nalpine_base = \"alpine:3.23\"\n\
         alpine_base_digest = \"sha256:{z}\"\n\
         toolchain_musl_url = \"https://static.rust-lang.org/dist/OLD/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz\"\n\
         toolchain_musl_sha256 = \"{z}\"\n\
         std_uefi_url = \"https://static.rust-lang.org/dist/OLD/rust-std-1.96.0-x86_64-unknown-uefi.tar.xz\"\n\
         std_uefi_sha256 = \"{z}\"\ncontainer_digest = \"sha256:{z}\"\n\n\
         [kernel-keyring]\n\"gregkh.asc\" = \"{z}\"\n\n\
         [rust-keyring]\n\"rust-signing.asc\" = \"{keyring_sha}\"\n"
    );
    fs::write(
        orchard.join("repo-manifest.toml"),
        "schema-version = 1\n\
         [repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n\
         [repos.fruit-basket]\npath = \"../fruit-basket\"\nartifacts = [\"fb-acme\"]\n\
         [repos.recipes]\npath = \"../../recipes\"\nartifacts = [\"recipes-app\"]\n",
    )
    .unwrap();
    fs::write(orchard.join("consume-pins.toml"), "schema-version = 1\n").unwrap();
    let mut pins_paths = vec![orchard.join("pins.toml")];
    fs::write(&pins_paths[0], &pins).unwrap();
    for rel in ["eco/seed-vault", "eco/fruit-basket", "recipes"] {
        let dir = tmp.path().join(rel);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pins.toml");
        fs::write(&p, &pins).unwrap();
        pins_paths.push(p);
    }
    let manifest = RepoManifest::load(&orchard.join("repo-manifest.toml")).unwrap();
    let store = tmp.path().join("eco/artifact-store");
    let layout = resolve_layout(
        &manifest,
        orchard.clone(),
        store,
        orchard.join("repo-manifest.toml"),
    );
    Eco {
        _tmp: tmp,
        layout,
        pins_paths,
    }
}

struct MapFetcher {
    map: BTreeMap<String, Vec<u8>>,
    calls: Cell<usize>,
}
impl Fetcher for MapFetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.calls.set(self.calls.get() + 1);
        self.map
            .get(url)
            .cloned()
            .ok_or_else(|| format!("fixture 404: {url}"))
    }
}

/// Serve `asc` + `manifest` at the channel-rust-<version> URLs.
fn transport(asc: &[u8], manifest: &[u8], version: &str) -> MapFetcher {
    MapFetcher {
        map: BTreeMap::from([
            (
                format!("{RUST_MANIFEST_BASE}/channel-rust-{version}.toml.asc"),
                asc.to_vec(),
            ),
            (
                format!("{RUST_MANIFEST_BASE}/channel-rust-{version}.toml"),
                manifest.to_vec(),
            ),
        ]),
        calls: Cell::new(0),
    }
}

fn snapshot(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| hex::encode(Sha256::digest(fs::read(p).unwrap())))
        .collect()
}

fn bump<'a>(fx: &'a Fx, f: &'a MapFetcher) -> RustBump<'a> {
    RustBump {
        fetch: f,
        now: fx.now,
        signer_fpr: fx.signer_fpr.as_str(),
    }
}

#[test]
fn green_bump_stages_all_four_pins_and_swaps_byte_identically() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx.manifest_asc, &fx.manifest, &fx.version);
    let before = snapshot(&eco.pins_paths);

    let mut stage = Stage::new(&eco.layout).unwrap();
    bump_rust(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).expect("green bump");
    assert_eq!(
        snapshot(&eco.pins_paths),
        before,
        "REAL trees untouched before the swap"
    );

    let swapped = stage.swap().unwrap();
    assert_eq!(swapped.len(), 4, "all four pins.toml copies swapped");
    let texts: Vec<String> = eco
        .pins_paths
        .iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect();
    for t in &texts {
        assert!(
            t.contains(&format!("version = \"{}\"", fx.version)),
            "rust version bumped"
        );
        assert!(
            t.contains(&format!(
                "rust-{}-x86_64-unknown-linux-musl.tar.xz",
                fx.version
            )),
            "musl url re-pinned to the manifest's dated url"
        );
        assert!(
            t.contains(&format!("toolchain_musl_sha256 = \"{}\"", "1".repeat(64))),
            "musl sha re-pinned from the verified manifest"
        );
        assert!(
            t.contains(&format!("std_uefi_sha256 = \"{}\"", "2".repeat(64))),
            "uefi sha re-pinned"
        );
                                                                                                  
        assert!(
            t.contains("alpine_base = \"alpine:3.23\""),
            "alpine_base untouched"
        );
        assert!(
            t.contains(&format!("container_digest = \"sha256:{}\"", "0".repeat(64))),
            "container_digest untouched by a rust bump"
        );
        assert!(t.contains("# the rust pin"), "comments preserved");
        assert!(t.contains("[rust-keyring]"), "keyring section untouched");
    }
    assert!(
        texts.windows(2).all(|w| w[0] == w[1]),
        "the four copies byte-agree (§3a-2)"
    );
}

#[test]
fn tampered_manifest_fails_pgp_with_nothing_pinned() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx.manifest_asc, &fx.tampered, &fx.version);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_rust(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(err.to_string().contains("PGP verify"), "got: {err}");
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn unpinned_signer_fails_pgp_with_nothing_pinned() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx.unpinned_asc, &fx.manifest, &fx.version);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_rust(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(err.to_string().contains("PGP verify"), "got: {err}");
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn keyring_pin_mismatch_fails_before_any_fetch_or_parse() {
                                                                                                  
                                                          
    let fx = fx();
    let eco = eco(&fx, &"c".repeat(64));                     
    let f = transport(&fx.manifest_asc, &fx.manifest, &fx.version);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_rust(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string()
            .contains("keyring pin mismatch BEFORE parse"),
        "got: {err}"
    );
    assert_eq!(
        f.calls.get(),
        0,
        "no fetch may precede the keyring pin check"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn genuine_older_manifest_is_rejected_by_the_version_bind() {
                                                                                                      
                                                                                                        
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
                                                                                                      
    let f = transport(&fx.older_asc, &fx.older, &fx.version);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_rust(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string().contains("version binding") && err.to_string().contains(&fx.older_version),
        "the downgrade must be caught by the version bind, got: {err}"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn unavailable_target_fails_with_nothing_pinned() {
                                                                                                   
                                                                    
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx.unavailable_asc, &fx.unavailable, &fx.version);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_rust(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(err.to_string().contains("not available"), "got: {err}");
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn bad_version_is_refused_before_any_fetch() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx.manifest_asc, &fx.manifest, &fx.version);
    let mut stage = Stage::new(&eco.layout).unwrap();
    for bad in ["1.96", "1.96.x", "1.96.0/../evil"] {
        let err = bump_rust(&bump(&fx, &f), bad, &eco.layout, &mut stage).unwrap_err();
        assert!(err.to_string().contains("must be <major>"), "got: {err}");
    }
    assert_eq!(f.calls.get(), 0, "a refused version never fetches");
}

#[test]
fn missing_sibling_pins_copy_fails_closed() {
                                                                                               
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    fs::remove_file(&eco.pins_paths[3]).unwrap();                    
    let f = transport(&fx.manifest_asc, &fx.manifest, &fx.version);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let _err = bump_rust(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    drop(stage);
    for p in &eco.pins_paths[..3] {
        let t = fs::read_to_string(p).unwrap();
        assert!(
            t.contains("version = \"1.96.0\""),
            "no partial write landed in {}",
            p.display()
        );
    }
}
