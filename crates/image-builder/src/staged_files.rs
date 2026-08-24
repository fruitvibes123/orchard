                                                                                                            
//! files onto the RO rootfs under `/opt/<dir>/…`. Each entry: resolve its `consume-pins` pin, assert the
//! pin KIND coheres with the declared mode's exec bit (V5: a Binary is `execve`'d → exec; a Config is
//! DATA → non-exec; a Source drop is never a stageable rootfs file), `fetch_verified` its bytes (the
//! sha256 consumption gate), and write them ESCAPE-PROOF: strip the leading `/` and join under `staging`
//! (never an absolute-path footgun), `create_dir_all` the parents, then a canonicalize-EQUALITY assert
//! (a symlink pre-planted in the path would make `create_dir_all` land the file OUTSIDE the staging root —
//! caught by comparing the created parent's canonical path to the expected one), a `create_new(true)`
//! write (refuse a pre-existing inode), and a chmod to the declared mode. A `Some(owner)` entry yields an
//! [`OwnerException`] (the symbolic name resolved to a uid via [`fb_manifest::validate::resolve_owner`]);
//! the caller folds these into the sign-time ownership map. The manifest-time grammar (V1/V2/V4/V6/V7/
//! V9/V3/V10) already ran at parse (fb-manifest); this is the BAKE half (V5 + the filesystem checks).

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::artifact_store::ArtifactStore;
use crate::build::BuildError;
use crate::ownership::OwnerException;
use crate::pin_manifest::{ArtifactKind, PinManifest};

                                                                                                
/// [`OwnerException`]s for the owner-declared entries (empty when none / when the manifest declares no
                                                                                                          
/// (the SAME verify-at-consumption seam `build_binaries` uses). Fail-closed at every step: a missing pin,
/// a hash mismatch, a V5 incoherence, a symlink-escaped parent, or a pre-existing target REFUSES the bake.
pub fn stage_manifest_files(
    staging: &Path,
    manifest: &fb_manifest::ValidatedManifest,
    pins: &PinManifest,
    store: &dyn ArtifactStore,
) -> Result<Vec<OwnerException>, BuildError> {
    let m = manifest.manifest();
    let staged = m.staged_files.as_deref().unwrap_or(&[]);
    if staged.is_empty() {
                                                                                             
        return Ok(Vec::new());
    }
                                                                                                         
                                                                                                           
    let staging_canon = staging.canonicalize().map_err(|source| BuildError::Io {
        path: staging.display().to_string(),
        source,
    })?;
    let mut exceptions = Vec::new();
    for sf in staged {
        let pin = pins.artifact(&sf.key)?;
                                                                                                            
                                                                                                     
                                                                                                     
        let exec = sf.mode & 0o111 != 0;
        let coherent = match pin.kind {
            ArtifactKind::Binary => exec,
            ArtifactKind::Config => !exec,
            ArtifactKind::Source => false,
        };
        if !coherent {
            return Err(BuildError::StagedExecKindMismatch {
                key: sf.key.clone(),
                kind: pin.kind,
                mode: sf.mode,
            });
        }
                                                                                                     
        let verified = store.fetch_verified(&sf.key, &pin.sha256)?;
                                                                                               
                                                                                                        
                                                                 
        let rel = sf.target.trim_start_matches('/');
        let dest = staging.join(rel);
                                                                                                       
        let parent = dest.parent().ok_or_else(|| BuildError::Tool {
            tool: "stage_manifest_files",
            reason: format!("staged target {:?} has no parent dir", sf.target),
        })?;
                                                                                                      
                                                                                                         
                                                                                           
        std::fs::create_dir_all(parent).map_err(|source| BuildError::Io {
            path: parent.display().to_string(),
            source,
        })?;
        let parent_canon = parent.canonicalize().map_err(|source| BuildError::Io {
            path: parent.display().to_string(),
            source,
        })?;
        let expected_parent = staging_canon.join(Path::new(rel).parent().unwrap_or(Path::new("")));
        if parent_canon != expected_parent {
            return Err(BuildError::Tool {
                tool: "stage_manifest_files",
                reason: format!(
                    "staged target {:?} parent canonicalizes to {} (expected {}) — a symlink in the \
                     path escaped the staging root",
                    sf.target,
                    parent_canon.display(),
                    expected_parent.display()
                ),
            });
        }
                                                                                               
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
            .map_err(|source| BuildError::Io {
                path: dest.display().to_string(),
                source,
            })?;
        f.write_all(verified.bytes())
            .map_err(|source| BuildError::Io {
                path: dest.display().to_string(),
                source,
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(sf.mode)).map_err(
                |source| BuildError::Io {
                    path: dest.display().to_string(),
                    source,
                },
            )?;
        }
                                                                                                        
                                                                                                         
        if let Some(owner) = &sf.owner {
            let uid = fb_manifest::validate::resolve_owner(owner, &m.identities).map_err(|e| {
                BuildError::Tool {
                    tool: "stage_manifest_files owner",
                    reason: e.to_string(),
                }
            })?;
            exceptions.push(OwnerException {
                rel_path: PathBuf::from(rel),
                uid,
                gid: uid,
            });
        }
    }
    Ok(exceptions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_store::DirStore;
    use sha2::{Digest, Sha256};

    /// A minimal VALID dha manifest (a `dha` identity uid 110 + the required sections) — the staged_files
    /// block is appended per test. No `runtime_config`, so V8 (dangling client config) never fires here.
    const VALID_BASE: &str = r#"
schema_version = 1
[[identities]]
name = "dha"
uid = 110
[env]
envdir = "/etc/recipes/env"
[env.vars]
DATA_DIR = [ { text = { value = "/persist/recipes" } } ]
[[services]]
name = "recipes"
shape = { exec = { binary = "/usr/bin/recipes", argv = [], priv = { root = {} } } }
[[boot_hooks]]
name = "set-hostname"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "set-hostname" } } ]
priv = { root = {} }
order = 10
timeout_secs = 5
on_failure = { rescue = {} }
[edge]
backend = "127.0.0.1:8000"
ca_file = "/persist/recipes/ca.crt"
redacted_paths = []
redacted_query_params = []
mtls_paths = []
throttle_rules = []
[[persist]]
path = "recipes"
uid = 110
mode = 0o700
[backup]
sources = [ "recipes" ]
[probe]
port = 443
path = "/"
[nftables]
tcp_ports = [ 80, 443, 22 ]
"#;

    fn manifest_with_staged(staged_toml: &str) -> fb_manifest::ValidatedManifest {
        let toml = format!("{VALID_BASE}{staged_toml}");
        fb_manifest::parse_and_validate(&toml, &crate::config::os_identities())
            .expect("the base+staged manifest validates")
    }

    /// A store holding each `(key, bytes)` (CAS put) + a PinManifest pinning each `(key, kind)` to
    /// `sha256(bytes)`. The store TempDir is returned to keep it alive for the test's lifetime.
    fn store_and_pins(
        entries: &[(&str, ArtifactKind, &[u8])],
    ) -> (tempfile::TempDir, DirStore, PinManifest) {
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
        let mut pins = String::from("schema-version = 1\n");
        for (key, kind, bytes) in entries {
            store.put(key, bytes).unwrap();
            let sha = hex::encode(Sha256::digest(bytes));
            let k = match kind {
                ArtifactKind::Binary => "binary",
                ArtifactKind::Config => "config",
                ArtifactKind::Source => "source",
            };
            pins.push_str(&format!(
                "[artifacts.{key}]\nsha256 = \"{sha}\"\nkind = \"{k}\"\n"
            ));
        }
        (tmp, store, PinManifest::from_toml_str(&pins).unwrap())
    }

    #[test]
    fn happy_path_stages_bytes_modes_and_one_owner_exception() {
        let staging = tempfile::tempdir().unwrap();
        let (_s, store, pins) = store_and_pins(&[
            ("uds-pipe", ArtifactKind::Binary, b"UDS-PIPE-ELF"),
            ("dha-epa-config", ArtifactKind::Config, b"{\"epa\":true}"),
        ]);
        let m = manifest_with_staged(
            r#"
[[staged_files]]
key = "uds-pipe"
target = "/opt/dha/uds-pipe"
mode = 0o755
[[staged_files]]
key = "dha-epa-config"
target = "/opt/dha/epa.json"
mode = 0o600
owner = "dha"
"#,
        );
        let exceptions = stage_manifest_files(staging.path(), &m, &pins, &store).expect("stages");
                                      
        assert_eq!(
            std::fs::read(staging.path().join("opt/dha/uds-pipe")).unwrap(),
            b"UDS-PIPE-ELF"
        );
        assert_eq!(
            std::fs::read(staging.path().join("opt/dha/epa.json")).unwrap(),
            b"{\"epa\":true}"
        );
                      
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &str| {
            std::fs::metadata(staging.path().join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("opt/dha/uds-pipe"), 0o755);
        assert_eq!(mode("opt/dha/epa.json"), 0o600);
                                                                     
        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].rel_path, PathBuf::from("opt/dha/epa.json"));
        assert_eq!((exceptions[0].uid, exceptions[0].gid), (110, 110));
    }

    #[test]
    fn a_key_absent_from_pins_is_refused() {
        let staging = tempfile::tempdir().unwrap();
                                                      
        let (_s, store, pins) = store_and_pins(&[("other", ArtifactKind::Binary, b"X")]);
        let m = manifest_with_staged(
            r#"
[[staged_files]]
key = "uds-pipe"
target = "/opt/dha/uds-pipe"
mode = 0o755
"#,
        );
        let err = stage_manifest_files(staging.path(), &m, &pins, &store).unwrap_err();
        assert!(matches!(err, BuildError::Pin(_)), "{err:?}");
    }

    #[test]
    fn a_store_hash_mismatch_is_refused() {
        let staging = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
                                                                                                      
        store.put("uds-pipe", b"WRONG-BYTES").unwrap();
        let correct_sha = hex::encode(Sha256::digest(b"CORRECT-BYTES"));
        let pins = PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.uds-pipe]\nsha256 = \"{correct_sha}\"\nkind = \"binary\"\n"
        ))
        .unwrap();
        let m = manifest_with_staged(
            r#"
[[staged_files]]
key = "uds-pipe"
target = "/opt/dha/uds-pipe"
mode = 0o755
"#,
        );
        let err = stage_manifest_files(staging.path(), &m, &pins, &store).unwrap_err();
        assert!(matches!(err, BuildError::Store(_)), "{err:?}");
    }

    #[test]
    fn an_exec_mode_on_a_config_kind_pin_is_refused_v5() {
        let staging = tempfile::tempdir().unwrap();
                                                                                              
        let (_s, store, pins) =
            store_and_pins(&[("dha-epa-config", ArtifactKind::Config, b"DATA")]);
        let m = manifest_with_staged(
            r#"
[[staged_files]]
key = "dha-epa-config"
target = "/opt/dha/epa.json"
mode = 0o755
"#,
        );
        let err = stage_manifest_files(staging.path(), &m, &pins, &store).unwrap_err();
        assert!(
            matches!(err, BuildError::StagedExecKindMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_preexisting_target_inode_is_refused_create_new() {
        let staging = tempfile::tempdir().unwrap();
                                                                                  
        std::fs::create_dir_all(staging.path().join("opt/dha")).unwrap();
        std::fs::write(staging.path().join("opt/dha/uds-pipe"), b"PREEXISTING").unwrap();
        let (_s, store, pins) = store_and_pins(&[("uds-pipe", ArtifactKind::Binary, b"NEW")]);
        let m = manifest_with_staged(
            r#"
[[staged_files]]
key = "uds-pipe"
target = "/opt/dha/uds-pipe"
mode = 0o755
"#,
        );
        let err = stage_manifest_files(staging.path(), &m, &pins, &store).unwrap_err();
        assert!(matches!(err, BuildError::Io { .. }), "{err:?}");
                                                            
        assert_eq!(
            std::fs::read(staging.path().join("opt/dha/uds-pipe")).unwrap(),
            b"PREEXISTING"
        );
    }

    #[test]
    fn a_symlinked_parent_component_is_refused_by_canonicalize_equality() {
        let staging = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
                                                                      
        std::os::unix::fs::symlink(elsewhere.path(), staging.path().join("opt")).unwrap();
        let (_s, store, pins) = store_and_pins(&[("uds-pipe", ArtifactKind::Binary, b"ELF")]);
        let m = manifest_with_staged(
            r#"
[[staged_files]]
key = "uds-pipe"
target = "/opt/dha/uds-pipe"
mode = 0o755
"#,
        );
        let err = stage_manifest_files(staging.path(), &m, &pins, &store).unwrap_err();
        assert!(matches!(err, BuildError::Tool { .. }), "{err:?}");
                                                                         
        assert!(!elsewhere.path().join("dha/uds-pipe").exists());
    }

    #[test]
    fn a_leading_slash_target_lands_inside_staging() {
        let staging = tempfile::tempdir().unwrap();
        let (_s, store, pins) = store_and_pins(&[("uds-pipe", ArtifactKind::Binary, b"ELF")]);
        let m = manifest_with_staged(
            r#"
[[staged_files]]
key = "uds-pipe"
target = "/opt/dha/uds-pipe"
mode = 0o755
"#,
        );
        stage_manifest_files(staging.path(), &m, &pins, &store).expect("stages");
                                                                                                          
        assert!(staging.path().join("opt/dha/uds-pipe").is_file());
    }

    #[test]
    fn ac4_no_staged_files_is_a_no_op() {
        let staging = tempfile::tempdir().unwrap();
        let (_s, store, pins) = store_and_pins(&[("uds-pipe", ArtifactKind::Binary, b"ELF")]);
                                                     
        let m = manifest_with_staged("");
        let exceptions = stage_manifest_files(staging.path(), &m, &pins, &store).expect("no-op");
        assert!(exceptions.is_empty());
                                                                          
        assert!(!staging.path().join("opt").exists());
    }
}
