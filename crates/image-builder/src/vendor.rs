                                                                                                   
//! Seed-Vault crates (grape, dragonfruit), rambutan, and fb-manifest are delivered as deterministic
//! source tarballs (FB/Seed-Vault publish them); Orchard fetches+verifies (the SAME gate as binaries)
//! then unpacks into vendor/, which Orchard's Cargo.toml path-points at. Verify BEFORE unpack — never
//! unpack an unverified archive.

use std::path::Path;

use crate::artifact_store::{ArtifactStore, ArtifactStoreError};
use crate::pin_manifest::{ArtifactKind, PinManifest};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum VendorError {
    #[error(transparent)]
    Store(#[from] ArtifactStoreError),
    #[error("unpack {key:?} into {dest}: {msg}")]
    Unpack {
        key: String,
        dest: String,
        msg: String,
    },
    #[error(
        "vendored source {key:?}: vendor/ is tampered or stale — re-run `make vendor` (expected {expected}, got {actual})"
    )]
    TreeMismatch {
        key: String,
        expected: String,
        actual: String,
    },
}

fn unpack_err(key: &str, dest: impl AsRef<Path>, msg: impl Into<String>) -> VendorError {
    VendorError::Unpack {
        key: key.to_string(),
        dest: dest.as_ref().display().to_string(),
        msg: msg.into(),
    }
}

/// Tar `<c_dir>/<entry>` with the FROZEN deterministic flags and return the raw tar BYTES — the ONE tar
/// recipe shared by publish (the `grocer` tool) and verify (`retar_vendored_sha` below, hence the bake's
/// `verify_vendored_tree`), so the published sha and the re-derived sha CANNOT drift on flags or format
                                                                                                        
                                                                                                               
/// which would prefix members `crates/grape/` and diverge from the pin). The temp tar lives in the SYSTEM
/// temp dir (never under `c_dir`, so it cannot pollute the archive of `c_dir`'s contents).
///
                                                                                                             
/// makes `tar` archive the wrong/outside member. The CALLER guarantees it: verify passes a flat,
/// parser-validated `*-src` pin key; grocer splits its `source` and passes the basename after
/// `crosscheck::sanitize_source`.
///
                                                                                                           
/// source tree may carry a `target/`, which is excluded); VERIFY passes `false` (a clean `vendor/<crate>` has
/// NO `target/` at any depth, so the sha still matches, AND an INJECTED `target/` is INCLUDED → sha mismatch
/// → refused; exclude-on-both would re-open that injected-`target/` blind spot).
pub fn deterministic_source_tar(
    c_dir: &Path,
    entry: &str,
    exclude_target: bool,
) -> Result<Vec<u8>, VendorError> {
    let out = tempfile::Builder::new()
        .prefix("source-tar-")
        .suffix(".tar")
        .tempfile()
        .map_err(|e| unpack_err(entry, c_dir, e.to_string()))?;
    let mut cmd = std::process::Command::new("tar");
    cmd.arg("--sort=name")
        .arg("--mtime=UTC 1970-01-01")
        .arg("--owner=0")
        .arg("--group=0")
        .arg("--numeric-owner")
                                                                                                          
                                                                                                        
                                                                                                       
                            
        .arg("--format=gnu");
    if exclude_target {
        cmd.arg("--exclude=target");
    }
    let result = cmd
        .arg("-C")
        .arg(c_dir)
        .arg("-cf")
        .arg(out.path())
        .arg(entry)
        .output()
        .map_err(|e| unpack_err(entry, c_dir, e.to_string()))?;
    if !result.status.success() {
                                                                                                       
                                                                                                            
                                                                                     
        return Err(unpack_err(
            entry,
            c_dir,
            format!(
                "deterministic source tar failed (`<c_dir>/<entry>` missing, or this `tar` lacks `--format=gnu` — needs GNU tar; check `tar --version`): {}",
                String::from_utf8_lossy(&result.stderr).trim()
            ),
        ));
    }
    std::fs::read(out.path()).map_err(|e| unpack_err(entry, out.path(), e.to_string()))
}

/// Re-tar `vendor/<crate>` (the VERIFY recipe — `exclude_target=false`) and return its sha256, the inverse of
/// the publish source drop. The committed vendor/ tree, re-tarred, reproduces the pinned tarball
/// byte-for-byte (proven for all drops on the pinned build host; the same assumption `repro-check` relies on).
fn retar_vendored_sha(vendor_root: &Path, crate_dir: &str) -> Result<String, VendorError> {
    let bytes = deterministic_source_tar(vendor_root, crate_dir, false)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

                                                                                                  
/// `*-src` source drop, re-tar `vendor/<crate>` and assert sha256 == consume-pins. Returns the count of
/// drops verified. Called at the START of `build_image` so `orchard build` REFUSES a tampered/stale
/// vendor/ at the produce-the-`.img` consumption point (the rambutan loader is compiled from
/// vendor/rambutan AT bake) — the binary↔source symmetry the `make verify`-level `vendor_integrity` test
/// alone does not give. Fail-closed: any mismatch (or a missing drop, via the re-tar) is an error.
pub fn verify_vendored_tree(vendor_root: &Path, pins: &PinManifest) -> Result<usize, VendorError> {
    let mut verified = 0;
    for (key, pin) in &pins.artifacts {
        if pin.kind != ArtifactKind::Source {
            continue;
        }
                                                                                                        
                                                                                             
        let Some(crate_dir) = key.strip_suffix("-src") else {
            continue;
        };
        let actual = retar_vendored_sha(vendor_root, crate_dir)?;
        if actual != pin.sha256 {
            return Err(VendorError::TreeMismatch {
                key: key.clone(),
                expected: pin.sha256.clone(),
                actual,
            });
        }
        verified += 1;
    }
    Ok(verified)
}

/// Fetch+verify the source-drop tarball `key` (expected `sha256`), then unpack it into `vendor_root`.
///
                                                                                                      
/// `vendor_root` (NOT the shared root), then ONLY the single top-level crate dir is moved into place.
/// This ISOLATES every extraction so a hostile member in one drop cannot plant a symlink that a LATER
/// drop's extraction follows out of the tree — the GNU-tar multi-archive symlink escape (CVE-2025-45582),
/// whose precondition `orchard vendor` otherwise meets (4 drops extracted sequentially into ONE root).
/// (GNU tar's default already strips a leading `/` and refuses `..` members; an absolute/`..` member is
/// thus relative-ized into the isolated temp dir and then dropped, never moved out.) This is
/// defense-in-depth BEHIND the sha-pin (`fetch_verified` already refuses a tampered tar); it protects the
/// build host on the hypothetical of a pinned-but-hostile publisher tar.
pub fn vendor_source_drop(
    store: &dyn ArtifactStore,
    key: &str,
    sha256: &str,
    vendor_root: &Path,
) -> Result<(), VendorError> {
    let verified = store.fetch_verified(key, sha256)?;                               
    std::fs::create_dir_all(vendor_root)
        .map_err(|e| unpack_err(key, vendor_root, e.to_string()))?;
                                                                                                       
                                   
    let crate_dir = key.strip_suffix("-src").unwrap_or(key);

                                                                                                          
                                                                                                        
    let extract = tempfile::Builder::new()
        .prefix(".vendor-extract-")
        .tempdir_in(vendor_root)
        .map_err(|e| unpack_err(key, vendor_root, e.to_string()))?;
    let tmp_tar = extract.path().join("drop.tar");
    verified
        .write_to(&tmp_tar)
        .map_err(|e| unpack_err(key, &tmp_tar, e.to_string()))?;
    let status = std::process::Command::new("tar")
        .arg("-xf")
        .arg(&tmp_tar)
        .arg("-C")
        .arg(extract.path())
        .status()
        .map_err(|e| unpack_err(key, extract.path(), e.to_string()))?;
    if !status.success() {
        return Err(unpack_err(key, extract.path(), "tar -xf failed"));
    }
                                                                                                        
                                                                                                          
                                                                                          
    let extracted = extract.path().join(crate_dir);
                                                                                              
                                                                                                       
                                                                                                         
                               
    if !extracted
        .symlink_metadata()
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return Err(unpack_err(
            key,
            &extracted,
            format!("tarball top-level {crate_dir:?} is not a real directory"),
        ));
    }
    let dest = vendor_root.join(crate_dir);
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|e| unpack_err(key, &dest, e.to_string()))?;
    }
    std::fs::rename(&extracted, &dest).map_err(|e| unpack_err(key, &dest, e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn vendors_a_source_drop_after_verifying_its_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        let vendor = tmp.path().join("vendor");
        std::fs::create_dir_all(&store).unwrap();
                                                                           
        let crate_src = tmp.path().join("src/grape");
        std::fs::create_dir_all(&crate_src).unwrap();
        std::fs::write(crate_src.join("Cargo.toml"), b"[package]\nname=\"grape\"\n").unwrap();
        let tar_path = store.join("grape-src");
        let status = std::process::Command::new("tar")
            .args([
                "--sort=name",
                "--mtime=UTC 1970-01-01",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                "-C",
            ])
            .arg(tmp.path().join("src"))
            .args(["-cf"])
            .arg(&tar_path)
            .arg("grape")
            .status()
            .unwrap();
        assert!(status.success());
        let sha = hex::encode(Sha256::digest(std::fs::read(&tar_path).unwrap()));

        let store_be = crate::artifact_store::DirStore::new(&store);
        vendor_source_drop(&store_be, "grape-src", &sha, &vendor).expect("vendor ok");
        assert!(
            vendor.join("grape/Cargo.toml").exists(),
            "drop unpacked into vendor/"
        );
    }

                                                                                                      
                                                                                                       
                                                                                                          
    #[cfg(unix)]
    #[test]
    fn extraction_is_isolated_only_the_crate_dir_is_placed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        let vendor = tmp.path().join("vendor");
        std::fs::create_dir_all(&store).unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("grape")).unwrap();
        std::fs::write(src.join("grape/Cargo.toml"), b"[package]\nname=\"grape\"\n").unwrap();
                                                                                              
        std::os::unix::fs::symlink("../../escape-target", src.join("escape")).unwrap();
        let tar_path = store.join("grape-src");
        let status = std::process::Command::new("tar")
            .args([
                "--sort=name",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                "-C",
            ])
            .arg(&src)
            .args(["-cf"])
            .arg(&tar_path)
            .arg("grape")
            .arg("escape")
            .status()
            .unwrap();
        assert!(status.success());
        let sha = hex::encode(Sha256::digest(std::fs::read(&tar_path).unwrap()));

        let store_be = crate::artifact_store::DirStore::new(&store);
        vendor_source_drop(&store_be, "grape-src", &sha, &vendor).expect("vendor ok");
        assert!(vendor.join("grape/Cargo.toml").exists(), "crate dir placed");
        assert!(
            vendor.join("escape").symlink_metadata().is_err(),
            "the sibling symlink must NOT reach vendor/ (isolated in the temp extract)"
        );
        let strays: Vec<_> = std::fs::read_dir(&vendor)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".vendor-extract-")
            })
            .collect();
        assert!(
            strays.is_empty(),
            "temp extract dir cleaned, no stray left in vendor/"
        );
    }

    #[test]
    fn deterministic_source_tar_excludes_target_and_is_reproducible() {
                                                                                                             
                                                                                                              
                                                                                                         
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("c");
        std::fs::create_dir_all(c.join("target")).unwrap();
        std::fs::write(c.join("lib.rs"), b"fn it() {}").unwrap();
        std::fs::write(c.join("target/junk"), b"BUILD ARTIFACT").unwrap();

        let with = deterministic_source_tar(d.path(), "c", false).unwrap();
        let without = deterministic_source_tar(d.path(), "c", true).unwrap();
        assert_ne!(
            with, without,
            "exclude_target=true must drop target/ from the bytes"
        );

        std::fs::remove_dir_all(c.join("target")).unwrap();
        let clean = deterministic_source_tar(d.path(), "c", false).unwrap();
        assert_eq!(
            without, clean,
            "exclude_target=true must equal a tree with no target/ (exact exclude + deterministic re-tar)"
        );
    }
}
