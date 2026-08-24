                                                                                                
//! repo-root `pins.toml` must agree with every downstream consumer; this runs under
//! `cargo test --workspace`. On failure, run `orchard sync-pins` (regenerates the
//! format-locked files) and/or `orchard refresh-apk-lock` (if `alpine.version` moved). Shares
//! `Pins::check_drift` with the `orchard sync-pins --check` CLI, so the gate and the CLI can't disagree.

use recipes_image_builder::pins::Pins;

/// Repo root from the image-builder crate dir (`crates/image-builder` → `../..`).
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root canonicalizes")
}

#[test]
fn generated_and_synced_files_match_pins_toml() {
    let root = repo_root();
    let pins = Pins::load(&root).expect("pins.toml loads");
    let drifted = pins.check_drift(&root).expect("check_drift runs");
    assert!(
        drifted.is_empty(),
        "version pins drifted from pins.toml — run `orchard sync-pins` (and \
         `orchard refresh-apk-lock` if alpine moved): {}",
        drifted.join("; ")
    );
}

#[test]
fn fetch_scripts_stay_retired() {
                                                                                                   
                                                                                                      
                                                                                                         
                                                                        
    for s in ["fetch-kernel-source.sh", "fetch-syslinux-source.sh"] {
        let p = repo_root().join("crates/image-builder").join(s);
        assert!(
            p.symlink_metadata().is_err(),
            "{s} must stay retired  — found at {}",
            p.display()
        );
    }
}

#[test]
fn source_acquisition_is_rust_only_and_pins_derived() {
                                                                                                      
                                                                                                
                                                                                                    
                                                                       
    let mut homes = std::collections::BTreeSet::new();
    for entry in walk_rs_files(&repo_root().join("crates")) {
        let body = std::fs::read_to_string(&entry).unwrap();
        let code_hits = body.lines().any(|l| {
            let t = l.trim_start();
            !t.starts_with("//")
                && (t.contains("cdn.kernel.org") || t.contains("utils/boot/syslinux"))
        });
        if code_hits {
            homes.insert(entry.strip_prefix(repo_root()).unwrap().to_path_buf());
        }
    }
    assert_eq!(
        homes.into_iter().collect::<Vec<_>>(),
        vec![std::path::PathBuf::from(
            "crates/image-builder/src/sources.rs"
        )],
        "upstream source URLs must live ONLY in sources.rs (sole-consumer lock)"
    );
}

/// Recursively collect `*.rs` files under `dir`, skipping `target/` and `tests/`. The sole-consumer
/// lock scopes to shipped/production code (`src/`): an acquisition path would live there, and a test
/// (like THIS file, or sources.rs's own URL-builder assertions) legitimately names the URL for the
/// guard itself — so scanning tests would self-match, the same false-positive class the §3a-5 comment
/// mentions of `[kernel-keyring]` created for the kernel gate.
fn walk_rs_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str());
            if matches!(name, Some("target") | Some("tests")) {
                continue;
            }
            out.extend(walk_rs_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    out
}
