                                                                                                   
                                                                                                      
//! an artifact's bytes, and it is constructible ONLY through `verify`, which hashes the fetched bytes
//! and compares to the expected pin — a mismatch or absence is a hard error, never best-effort
                                                                                                      
//! backend now; a `ReleaseAssetsStore` (fetch-by-URL + the SAME verify) is a future drop-in (the
                                                                                                         

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ArtifactStoreError {
    #[error("artifact {key:?} not found in the store at {path}")]
    NotFound { key: String, path: String },
    #[error(
        "artifact {key:?} hash mismatch: expected {expected}, got {actual} — REFUSING (tampered/stale pin)"
    )]
    HashMismatch {
        key: String,
        expected: String,
        actual: String,
    },
    #[error("io reading artifact {key:?} at {path}: {source}")]
    Io {
        key: String,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "artifact key {key:?} is unsafe — a store key must be a single in-store filename ([A-Za-z0-9._-], no leading dot) naming a regular file, not a path / `..` / absolute / symlink — REFUSING (F-3b-P1-R1-1)"
    )]
    UnsafeKey { key: String },
    #[error(
        "artifact {key:?} pin {expected:?} is not a 64-char lowercase-hex sha256 — REFUSING (F-3b-P1-R1-6)"
    )]
    MalformedPin { key: String, expected: String },
}

/// A fetched-and-verified artifact. The private fields make the ONLY constructor `verify` (below),
/// so a handle's existence proves the sha256 matched — the type IS the consumption gate.
///
                                                                                                
/// structurally (private fields + the `pub(crate)` `verify` gate). The `compile_fail` doctest below is a
/// permanent test — if a future refactor adds a `pub` constructor or widens field visibility, the gate
/// re-opens and this doctest starts COMPILING, which fails the suite (a `compile_fail` block that
/// compiles is a test failure). It replaces the Phase-1 audit's intentionally-throwaway mint probe.
///
/// ```compile_fail
/// // From OUTSIDE the crate: the fields are private (E0451) and there is no public constructor, so a
/// // `Verified` cannot be forged. This block MUST NOT compile.
/// let _forged = recipes_image_builder::artifact_store::Verified {
///     bytes: vec![1, 2, 3],
///     sha256: "00".repeat(32),
/// };
/// ```
                                                                                                      
                                                                                                      
                                                        
#[derive(Debug)]
pub struct Verified {
    bytes: Vec<u8>,
    sha256: String,
}

impl Verified {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> String {
        self.sha256.clone()
    }
    /// Stage the verified bytes to a path (the bake staging step).
    pub fn write_to(&self, dest: &Path) -> std::io::Result<()> {
        std::fs::write(dest, &self.bytes)
    }
}

/// Hash + compare; the gate. `pub(crate)` so any in-crate `ArtifactStore` impl (incl. a future
/// `ReleaseAssetsStore` in its OWN module) can mint a `Verified`, while it stays un-mintable from
/// OUTSIDE the crate — the security property (bytes unreachable without a passing hash check) holds,
/// and the "drop-in store" claim is no longer blocked by a module-private fn (F-3b-R1-3).
pub(crate) fn verify(
    key: &str,
    bytes: Vec<u8>,
    expected: &str,
) -> Result<Verified, ArtifactStoreError> {
                                                                                                        
                                                                                                         
                                                                                                         
                                                                                                           
    if !crate::pin_manifest::is_sha256_hex(expected) {
        return Err(ArtifactStoreError::MalformedPin {
            key: key.to_string(),
            expected: expected.to_string(),
        });
    }
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != expected {
        return Err(ArtifactStoreError::HashMismatch {
            key: key.to_string(),
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(Verified {
        bytes,
        sha256: actual,
    })
}

pub trait ArtifactStore {
    /// Fetch `key` and verify its bytes hash to `expected_sha256`; refuse on absence or mismatch.
    fn fetch_verified(
        &self,
        key: &str,
        expected_sha256: &str,
    ) -> Result<Verified, ArtifactStoreError>;
}

/// A store key must be a single, flat in-store filename — a secure-by-construction WHITELIST
                                                                                                    
/// leading dot. This structurally blocks every traversal vector F-3b-P1-R1-1 confirmed: `/` and `\`
/// are not in the set (no separators → no `../`, no absolute path, no nested path), and the leading-dot
/// ban kills `.`/`..`/hidden. Store keys in practice are flat names (`recipes-app`, `fb-acme`, …).
fn is_safe_key(key: &str) -> bool {
    !key.is_empty()
        && !key.starts_with('.')
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

                                                                                                 
/// worktree binaries keep today's exact behavior. Retired by a one-line follow-up after the
/// dha/bench streams rebase (flip to false + delete the alias branch + the prune alias guard).
const DUAL_WRITE_FLAT_ALIAS: bool = true;

/// `<key>@<sha>` — called only with a validated key + validated 64-hex sha. `is_safe_key` does not
                                                                                                 
fn revision_name(key: &str, sha: &str) -> String {
    format!("{key}@{sha}")
}

                                                                                            
/// classifies each filename through this; the fetch path never parses (it constructs its candidate
/// names from validated inputs). A `Foreign` name is reported and skipped by maintenance surfaces —
/// never followed, never deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreName {
    /// `<is_safe_key>@<64 lowercase hex>` — a content-addressed revision blob.
    Revision { key: String, sha: String },
    /// An exact `is_safe_key` name — a legacy/dual-write flat blob.
    Alias { key: String },
    /// Anything else (dotfiles, staging temps, malformed sha sides, unsafe keys).
    Foreign,
}

/// Classify one store-dir filename (see [`StoreName`]). Split at the LAST `@` (`is_safe_key` bans
/// `@` from keys, so the split is unambiguous); the key side must pass `is_safe_key` and the sha
/// side must be exactly 64 lowercase hex for a `Revision`.
pub fn parse_store_name(name: &str) -> StoreName {
    if let Some((key, sha)) = name.rsplit_once('@') {
        if is_safe_key(key) && crate::pin_manifest::is_sha256_hex(sha) {
            return StoreName::Revision {
                key: key.to_string(),
                sha: sha.to_string(),
            };
        }
        return StoreName::Foreign;
    }
    if is_safe_key(name) {
        return StoreName::Alias {
            key: name.to_string(),
        };
    }
    StoreName::Foreign
}

/// The operator-managed directory backend. An artifact is stored content-addressed as
/// `<key>@<sha256(bytes)>` (a REVISION — additive by construction: parallel streams cannot clobber
                                                                                                 
/// for pre-CAS binaries. Reads resolve the revision for the requested pin first and fall back to
/// the flat name only on absence; the pin stays the ONLY integrity root either way.
pub struct DirStore {
    root: PathBuf,
}

impl DirStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Write `bytes` to `<root>/<key>@<sha256(bytes)>` (the additive revision blob) and — while
                                                                                                    
    /// same `put_at` machinery: symlink-refusing, atomic temp+rename. Re-publishing identical
    /// bytes is a no-op-equivalent (same names, same content). `grocer` routes every artifact
    /// write through this.
    pub fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ArtifactStoreError> {
        if !is_safe_key(key) {
            return Err(ArtifactStoreError::UnsafeKey {
                key: key.to_string(),
            });
        }
        let sha = hex::encode(Sha256::digest(bytes));
        self.put_at(&revision_name(key, &sha), bytes, key)?;
        if DUAL_WRITE_FLAT_ALIAS {
            self.put_at(key, bytes, key)?;
        }
        Ok(())
    }

    /// The one write primitive — the WRITE-side counterpart of the read gate, with the SAME
                                                                                                  
    /// is either that validated key or `revision_name` built from it + a computed sha), and
    /// `symlink_metadata` (NO-follow) REFUSES an existing symlink at the target, so a pre-planted
    /// symlink can never make the write follow OUT of the store (the write-through escape the
    /// executor's `symlink_free_store` was needed to prevent for the old shell `cp`). The write is
    /// ATOMIC — a temp file in the SAME dir, then `rename` over the target (same filesystem) — so
    /// a crash leaves either the old bytes or the new, never a half-written blob, and the final
    /// `rename` itself never follows a symlink. `key` is error context only.
    fn put_at(&self, name: &str, bytes: &[u8], key: &str) -> Result<(), ArtifactStoreError> {
        let path = self.root.join(name);
                                                                                                             
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(ArtifactStoreError::UnsafeKey {
                    key: key.to_string(),
                });
            }
            Ok(_) => {}                                             
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}              
            Err(source) => {
                return Err(ArtifactStoreError::Io {
                    key: key.to_string(),
                    path: path.display().to_string(),
                    source,
                });
            }
        }
        let io_err = |source: std::io::Error, at: &Path| ArtifactStoreError::Io {
            key: key.to_string(),
            path: at.display().to_string(),
            source,
        };
        std::fs::create_dir_all(&self.root).map_err(|e| io_err(e, &self.root))?;
                                                                                                             
                                                                                                           
        let tmp = tempfile::Builder::new()
            .prefix(".put-")
            .suffix(".tmp")
            .tempfile_in(&self.root)
            .map_err(|e| io_err(e, &self.root))?;
        std::fs::write(tmp.path(), bytes).map_err(|e| io_err(e, tmp.path()))?;
        tmp.persist(&path).map_err(|e| io_err(e.error, &path))?;
        Ok(())
    }

    /// The one read primitive: no-follow stat + read + `verify` (re-hash against the pin) at ONE
    /// store name. `symlink_metadata` does NOT follow symlinks (unlike `exists`/`metadata`/`read`):
    /// a store entry that is a symlink is REFUSED here rather than silently followed OUT of the
    /// store (the third F-3b-P1-R1-1 vector). It also surfaces a real IO error instead of masking,
    /// say, a permission failure as `NotFound` the way `exists()` would. `key` is the pin/error
    /// context; `name` is the on-disk candidate (revision or flat).
    fn read_verified_at(
        &self,
        name: &str,
        key: &str,
        expected: &str,
    ) -> Result<Verified, ArtifactStoreError> {
        let path = self.root.join(name);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ArtifactStoreError::NotFound {
                    key: key.to_string(),
                    path: path.display().to_string(),
                });
            }
            Err(source) => {
                return Err(ArtifactStoreError::Io {
                    key: key.to_string(),
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        if meta.file_type().is_symlink() {
            return Err(ArtifactStoreError::UnsafeKey {
                key: key.to_string(),
            });
        }
        let bytes = std::fs::read(&path).map_err(|source| ArtifactStoreError::Io {
            key: key.to_string(),
            path: path.display().to_string(),
            source,
        })?;
        verify(key, bytes, expected)
    }
}

impl ArtifactStore for DirStore {
    fn fetch_verified(
        &self,
        key: &str,
        expected_sha256: &str,
    ) -> Result<Verified, ArtifactStoreError> {
                                                                                                      
                                                                                                     
                                                                        
        if !is_safe_key(key) {
            return Err(ArtifactStoreError::UnsafeKey {
                key: key.to_string(),
            });
        }
                                                                                                     
                                                                                                      
                                                                                           
        if !crate::pin_manifest::is_sha256_hex(expected_sha256) {
            return Err(ArtifactStoreError::MalformedPin {
                key: key.to_string(),
                expected: expected_sha256.to_string(),
            });
        }
                                                                                                
                                                                                                   
                        
        match self.read_verified_at(&revision_name(key, expected_sha256), key, expected_sha256) {
            Err(ArtifactStoreError::NotFound { .. }) => {
                match self.read_verified_at(key, key, expected_sha256) {
                    Err(ArtifactStoreError::HashMismatch {
                        key,
                        expected,
                        actual,
                    }) => {
                                                                                                      
                                                                                                   
                                                                              
                        let actual = format!(
                            "{actual} — no {key}@{expected} revision exists and the flat alias hashes elsewhere; likely a pre-CAS writer or another branch's publish; see `market store status` / `market store migrate`"
                        );
                        Err(ArtifactStoreError::HashMismatch {
                            key,
                            expected,
                            actual,
                        })
                    }
                    other => other,
                }
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn write_blob(dir: &std::path::Path, name: &str, bytes: &[u8]) -> String {
        let sha = hex::encode(Sha256::digest(bytes));
        std::fs::write(dir.join(name), bytes).unwrap();
        sha
    }

    #[test]
    fn fetch_verifies_and_returns_bytes_on_match() {
        let tmp = tempfile::tempdir().unwrap();
        let sha = write_blob(tmp.path(), "recipes-app", b"ELFDATA");
        let store = DirStore::new(tmp.path());
        let v = store
            .fetch_verified("recipes-app", &sha)
            .expect("verified fetch");
        assert_eq!(v.bytes(), b"ELFDATA");
        assert_eq!(v.sha256(), sha);
    }

    #[test]
    fn fetch_refuses_on_hash_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        write_blob(tmp.path(), "recipes-app", b"ELFDATA");
        let store = DirStore::new(tmp.path());
        let wrong = "0".repeat(64);
        let err = store.fetch_verified("recipes-app", &wrong).unwrap_err();
        assert!(
            matches!(err, ArtifactStoreError::HashMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn fetch_refuses_on_absent_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
        let err = store.fetch_verified("nope", &"a".repeat(64)).unwrap_err();
        assert!(
            matches!(err, ArtifactStoreError::NotFound { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn fetch_refuses_unsafe_keys() {
                                                                                                     
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
        let any = "a".repeat(64);
        for bad in [
            "../secret",
            "/etc/hostname",
            "a/b",
            "..",
            ".",
            "",
            ".hidden",
            "a\\b",
        ] {
            let err = store.fetch_verified(bad, &any).unwrap_err();
            assert!(
                matches!(err, ArtifactStoreError::UnsafeKey { .. }),
                "key {bad:?} must be refused as unsafe, got {err:?}"
            );
        }
    }

    #[test]
    fn fetch_refuses_a_symlink_store_entry() {
                                                                                                      
                                     
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside-secret");
        std::fs::write(&outside, b"OUTSIDE").unwrap();
        let store_dir = tmp.path().join("store");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::os::unix::fs::symlink(&outside, store_dir.join("evil")).unwrap();
        let store = DirStore::new(&store_dir);
        let sha = hex::encode(Sha256::digest(b"OUTSIDE"));
        let err = store.fetch_verified("evil", &sha).unwrap_err();
        assert!(
            matches!(err, ArtifactStoreError::UnsafeKey { .. }),
            "a symlink store entry must be refused, got {err:?}"
        );
    }

    #[test]
    fn verify_refuses_a_malformed_pin() {
                                                                                                 
                                  
        let tmp = tempfile::tempdir().unwrap();
        write_blob(tmp.path(), "recipes-app", b"ELFDATA");
        let store = DirStore::new(tmp.path());
        let upper = "A".repeat(64);
        for bad in ["NOT-A-SHA", "", "deadbeef", upper.as_str()] {
            let err = store.fetch_verified("recipes-app", bad).unwrap_err();
            assert!(
                matches!(err, ArtifactStoreError::MalformedPin { .. }),
                "malformed pin {bad:?} must be refused as MalformedPin, got {err:?}"
            );
        }
    }

    #[test]
    fn put_writes_bytes_to_the_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join("store");
        let store = DirStore::new(&store_dir);
        store.put("grape-src", b"TARBYTES").expect("put ok");
        assert_eq!(
            std::fs::read(store_dir.join("grape-src")).unwrap(),
            b"TARBYTES"
        );
    }

    #[test]
    fn put_refuses_unsafe_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
        for bad in ["../escape", "/etc/passwd", "a/b", "..", ".", "", ".hidden"] {
            let err = store.put(bad, b"X").unwrap_err();
            assert!(
                matches!(err, ArtifactStoreError::UnsafeKey { .. }),
                "put key {bad:?} must be refused, got {err:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn put_refuses_a_symlink_target_and_does_not_write_through() {
                                                                                                              
                                                                                            
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside-real");
        std::fs::write(&outside, b"ORIGINAL").unwrap();
        let store_dir = tmp.path().join("store");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::os::unix::fs::symlink(&outside, store_dir.join("grape-src")).unwrap();
        let store = DirStore::new(&store_dir);
        let err = store.put("grape-src", b"ATTACKER").unwrap_err();
        assert!(
            matches!(err, ArtifactStoreError::UnsafeKey { .. }),
            "a symlink target must be refused, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"ORIGINAL",
            "the file behind the symlink must be untouched (no write-through)"
        );
    }

    #[test]
    fn put_atomically_overwrites_and_leaves_no_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join("store");
        let store = DirStore::new(&store_dir);
        store.put("k", b"OLD").unwrap();
        store.put("k", b"NEW").unwrap();
        assert_eq!(std::fs::read(store_dir.join("k")).unwrap(), b"NEW");
                                                                          
        let strays: Vec<_> = std::fs::read_dir(&store_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".put-"))
            .collect();
        assert!(strays.is_empty(), "no staging temp left in the store dir");
    }

    #[test]
    fn parse_store_name_edge_matrix() {
        use StoreName::*;
        let sha = "a".repeat(64);
        assert_eq!(
            parse_store_name(&format!("grape-src@{sha}")),
            Revision {
                key: "grape-src".into(),
                sha: sha.clone()
            }
        );
        assert_eq!(
            parse_store_name("grape-src"),
            Alias {
                key: "grape-src".into()
            }
        );
                                                                                  
        assert_eq!(parse_store_name(".store-policy.toml"), Foreign);
        assert_eq!(parse_store_name(".put-xyz.tmp"), Foreign);
        assert_eq!(parse_store_name(&format!("k@{}", "a".repeat(63))), Foreign);
        assert_eq!(parse_store_name(&format!("k@{}", "a".repeat(65))), Foreign);
        assert_eq!(parse_store_name(&format!("k@{}", "A".repeat(64))), Foreign);
        assert_eq!(parse_store_name(&format!("a@b@{sha}")), Foreign);                                 
        assert_eq!(parse_store_name(""), Foreign);
        assert_eq!(parse_store_name(&format!("../esc@{sha}")), Foreign);
                                                                             
        assert_eq!(
            parse_store_name(&"b".repeat(64)),
            Alias {
                key: "b".repeat(64)
            }
        );
    }

    #[test]
    fn put_writes_revision_and_alias_additively() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
        let sha_a = hex::encode(Sha256::digest(b"REV-A"));
        store.put("grape-src", b"REV-A").unwrap();
                                              
        assert_eq!(
            std::fs::read(tmp.path().join(format!("grape-src@{sha_a}"))).unwrap(),
            b"REV-A"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("grape-src")).unwrap(),
            b"REV-A"
        );
                                                                                    
        let sha_b = hex::encode(Sha256::digest(b"REV-B"));
        store.put("grape-src", b"REV-B").unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join(format!("grape-src@{sha_a}"))).unwrap(),
            b"REV-A"
        );
        assert_eq!(
            std::fs::read(tmp.path().join(format!("grape-src@{sha_b}"))).unwrap(),
            b"REV-B"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("grape-src")).unwrap(),
            b"REV-B"
        );
    }

    #[test]
    fn fetch_resolves_revision_first_then_flat_on_notfound_only() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
                                                                                               
        let sha_a = hex::encode(Sha256::digest(b"REV-A"));
        std::fs::write(tmp.path().join(format!("grape-src@{sha_a}")), b"REV-A").unwrap();
        std::fs::write(tmp.path().join("grape-src"), b"REV-B").unwrap();
        let v = store
            .fetch_verified("grape-src", &sha_a)
            .expect("A's pin resolves A's revision");
        assert_eq!(v.bytes(), b"REV-A");
                                                                                  
        let sha_b = hex::encode(Sha256::digest(b"REV-B"));
        std::fs::remove_file(tmp.path().join(format!("grape-src@{sha_a}"))).unwrap();
        let v = store
            .fetch_verified("grape-src", &sha_b)
            .expect("flat fallback");
        assert_eq!(v.bytes(), b"REV-B");
    }

    #[test]
    fn lying_revision_filename_is_refused_by_rehash() {
                                                                                                      
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
        let pin = hex::encode(Sha256::digest(b"CLAIMED"));
        std::fs::write(tmp.path().join(format!("grape-src@{pin}")), b"ACTUAL").unwrap();
        let err = store.fetch_verified("grape-src", &pin).unwrap_err();
        assert!(
            matches!(err, ArtifactStoreError::HashMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn fallback_hashmismatch_names_the_layout() {
                                                                                                 
        let tmp = tempfile::tempdir().unwrap();
        let store = DirStore::new(tmp.path());
        std::fs::write(tmp.path().join("grape-src"), b"OTHER-BRANCH").unwrap();
        let pin = hex::encode(Sha256::digest(b"MINE"));
        let err = store.fetch_verified("grape-src", &pin).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("grape-src@"),
            "names the missing revision shape: {msg}"
        );
        assert!(
            msg.contains("market store"),
            "points at the store verbs: {msg}"
        );
    }

    #[test]
    fn symlink_refused_on_both_candidate_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, b"X").unwrap();
        let store_dir = tmp.path().join("store");
        std::fs::create_dir_all(&store_dir).unwrap();
        let store = DirStore::new(&store_dir);
        let pin = hex::encode(Sha256::digest(b"X"));
                                        
        std::os::unix::fs::symlink(&outside, store_dir.join(format!("k@{pin}"))).unwrap();
        assert!(matches!(
            store.fetch_verified("k", &pin).unwrap_err(),
            ArtifactStoreError::UnsafeKey { .. }
        ));
                                                                   
        std::fs::remove_file(store_dir.join(format!("k@{pin}"))).unwrap();
        std::os::unix::fs::symlink(&outside, store_dir.join("k")).unwrap();
        assert!(matches!(
            store.fetch_verified("k", &pin).unwrap_err(),
            ArtifactStoreError::UnsafeKey { .. }
        ));
    }
}
