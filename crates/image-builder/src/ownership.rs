//! The per-inode ownership map for the rootfs pack (per-uid rootfs baking; retire `mksquashfs -all-root`).
//!
//! `-all-root` forced every squashfs inode to `0:0`; retiring it (spec
//! `2026-07-02-per-uid-rootfs-baking-design.md`) means ownership must come from an EXPLICIT map. The map's
//! default owner is a **hardcoded `(0,0)`** for every inode — the staging inode's OWNER is never read
//! (box-init is host-`chown`'d to the build user in staging, so a staging-derived owner would sign PID-1 for
                                                                                                          
//! non-`0:0`. The map is the single source of truth for both the mksquashfs `m` pseudo-lines and the EVM
                                                                               

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The baked owner + mode of one staged inode. `mode` is the FULL `st_mode`; the `m`-line emitter masks
                                                   
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeOwner {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

                                                                                                       
/// numeric uid upstream in fb-manifest). `rel_path` is staging-relative (no leading `/`).
#[derive(Debug, Clone)]
pub struct OwnerException {
    pub rel_path: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum OwnershipError {
    #[error(
        "staging inode {path:?} is not a regular file, directory, or symlink — the ownership walk is \
         fail-closed on unexpected inode types (spec F-4)"
    )]
    UnexpectedInodeType { path: String },
    #[error("staging path {path:?} contains whitespace/control chars — unsafe for the mksquashfs pseudo-file")]
    WhitespacePath { path: String },
    #[error(
        "staging path {path:?} is not valid UTF-8 — the pseudo-file emit cannot faithfully name it \
         (a lossy path would silently miss its inode; fail-closed)"
    )]
    NonUtf8Path { path: String },
    #[error(
        "declared owner exception {path:?} is absent from the staged tree (spec R2-4, fail-closed)"
    )]
    ExceptionPathAbsent { path: String },
    #[error(
        "declared owner exception {path:?} is a hardlink (nlink={nlink}) — the other arm(s) share \
         the inode but keep their own owner lines, so the declarations would conflict on one inode \
         (fail-closed)"
    )]
    ExceptionHardlink { path: String, nlink: u64 },
    #[error(
        "declared owner exception {path:?} (mode {mode:#o}) is executable — a non-0:0 exec escapes IMA \
         appraisal under the fowner=0 policy (fail-closed)"
    )]
    ExceptionExecBit { path: String, mode: u32 },
    #[error(
        "declared owner exception {path:?} is not a regular file (S_IFMT != S_IFREG) — an owner \
         exception is for a config DATA file, never a directory or symlink (fail-closed)"
    )]
    ExceptionNotRegularFile { path: String },
    #[error("read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

/// The staged tree's per-inode ownership. Default `(0,0)`; declared exceptions applied. Backed by a
/// `BTreeMap` so the emitted pseudo-manifest is sorted + reproducible.
pub struct OwnershipMap {
    entries: BTreeMap<PathBuf, InodeOwner>,
}

impl OwnershipMap {
    /// Walk `staging` (allowlist `{file, dir, symlink}`, hard-error on any other inode type or a
    /// whitespace/control/non-UTF-8 path), default every inode to `(0,0)` + its staged mode, then
    /// apply `exceptions` (each: path must exist in the tree, must NOT be executable, and must NOT
    /// be a hardlink — the other arm(s) would keep their own owner lines and conflict on the shared
                                                                                            
    /// `(0,0)` + the shared inode's mode, and the Map bake was probed byte-identical to `-all-root`
    /// for that shape (R1 audit).
    pub fn build(staging: &Path, exceptions: &[OwnerException]) -> Result<Self, OwnershipError> {
        let mut entries = BTreeMap::new();
        walk(staging, staging, &mut entries)?;
        for exc in exceptions {
            let owner = entries.get_mut(&exc.rel_path).ok_or_else(|| {
                OwnershipError::ExceptionPathAbsent {
                    path: exc.rel_path.display().to_string(),
                }
            })?;
                                                                                                            
                                                                                                           
                                                                                                     
            if owner.mode & 0o170000 != 0o100000 {
                return Err(OwnershipError::ExceptionNotRegularFile {
                    path: exc.rel_path.display().to_string(),
                });
            }
            if owner.mode & 0o111 != 0 {
                return Err(OwnershipError::ExceptionExecBit {
                    path: exc.rel_path.display().to_string(),
                    mode: owner.mode,
                });
            }
            let nlink = std::fs::symlink_metadata(staging.join(&exc.rel_path))
                .map_err(|source| OwnershipError::Io {
                    path: exc.rel_path.display().to_string(),
                    source,
                })?
                .nlink();
            if nlink > 1 {
                return Err(OwnershipError::ExceptionHardlink {
                    path: exc.rel_path.display().to_string(),
                    nlink,
                });
            }
            owner.uid = exc.uid;
            owner.gid = exc.gid;
        }
        Ok(Self { entries })
    }

    /// The `(uid, gid)` for a staging-relative path; default `(0,0)` if unmapped.
    pub fn owner(&self, rel: &Path) -> (u32, u32) {
        self.entries.get(rel).map_or((0, 0), |o| (o.uid, o.gid))
    }

    /// Sorted iterator over `(rel_path, owner)` — the `m`-line emission order.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, &InodeOwner)> {
        self.entries.iter().map(|(p, o)| (p.as_path(), o))
    }
}

/// Recursive fail-closed walk. `DirEntry::metadata()` does NOT follow symlinks (lstat), so a symlink's
/// own mode is recorded and it is never traversed.
fn walk(
    root: &Path,
    dir: &Path,
    out: &mut BTreeMap<PathBuf, InodeOwner>,
) -> Result<(), OwnershipError> {
    let read_io = |source| OwnershipError::Io {
        path: dir.display().to_string(),
        source,
    };
    for entry in std::fs::read_dir(dir).map_err(read_io)? {
        let entry = entry.map_err(read_io)?;
        let path = entry.path();
        let ent_io = |source| OwnershipError::Io {
            path: path.display().to_string(),
            source,
        };
        let ft = entry.file_type().map_err(ent_io)?;
        let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                                                                                               
                                                                      
        if rel
            .as_os_str()
            .as_bytes()
            .iter()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(OwnershipError::WhitespacePath {
                path: rel.to_string_lossy().into_owned(),
            });
        }
                                                                                                  
                                                                                                     
                                                                                         
        if rel.to_str().is_none() {
            return Err(OwnershipError::NonUtf8Path {
                path: rel.to_string_lossy().into_owned(),
            });
        }
                                                                                                            
        let mode = entry.metadata().map_err(ent_io)?.mode();
        let owner = InodeOwner {
            uid: 0,
            gid: 0,
            mode,
        };
        if ft.is_dir() {
            out.insert(rel, owner);
            walk(root, &path, out)?;
        } else if ft.is_symlink() || ft.is_file() {
            out.insert(rel, owner);
        } else {
            return Err(OwnershipError::UnexpectedInodeType {
                path: rel.to_string_lossy().into_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn default_owner_is_root_regardless_of_staging_owner() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("d")).unwrap();
        let map = OwnershipMap::build(dir.path(), &[]).unwrap();
        assert_eq!(map.owner(Path::new("a")), (0, 0));
        assert_eq!(map.owner(Path::new("d")), (0, 0));
    }

    #[test]
    fn declared_exception_sets_owner() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("etc/box.json");
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::fs::write(&cfg, b"{}").unwrap();
        chmod(&cfg, 0o600);
        let exc = OwnerException {
            rel_path: PathBuf::from("etc/box.json"),
            uid: 5000,
            gid: 5000,
        };
        let map = OwnershipMap::build(dir.path(), &[exc]).unwrap();
        assert_eq!(map.owner(Path::new("etc/box.json")), (5000, 5000));
                                             
        assert_eq!(map.owner(Path::new("etc")), (0, 0));
    }

    #[test]
    fn multiple_exceptions_from_merged_sources_each_set_their_owner() {
                                                                                                       
                                                                                       
                                                                                                        
                                                                                                   
                                                                                                         
                                                             
        let dir = tempfile::tempdir().unwrap();
        let rels = [
            "etc/dha/box.json",
            "etc/dha/runtime.json",
            "opt/dha/epa.json",
        ];
        for rel in rels {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"{}").unwrap();
            chmod(&p, 0o600);
        }
        let exceptions: Vec<OwnerException> = rels
            .iter()
            .map(|rel| OwnerException {
                rel_path: PathBuf::from(rel),
                uid: 110,
                gid: 110,
            })
            .collect();
        let map = OwnershipMap::build(dir.path(), &exceptions).unwrap();
        assert_eq!(map.owner(Path::new("etc/dha/box.json")), (110, 110));
        assert_eq!(map.owner(Path::new("etc/dha/runtime.json")), (110, 110));
        assert_eq!(map.owner(Path::new("opt/dha/epa.json")), (110, 110));
                                                                                                   
        assert_eq!(map.owner(Path::new("etc/dha")), (0, 0));
        assert_eq!(map.owner(Path::new("opt/dha")), (0, 0));
    }

    #[test]
    fn exception_on_absent_path_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let exc = OwnerException {
            rel_path: PathBuf::from("etc/nope.json"),
            uid: 5000,
            gid: 5000,
        };
        assert!(matches!(
            OwnershipMap::build(dir.path(), &[exc]),
            Err(OwnershipError::ExceptionPathAbsent { .. })
        ));
    }

    #[test]
    fn exception_on_executable_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("bin/tool");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b"x").unwrap();
        chmod(&f, 0o755);
        let exc = OwnerException {
            rel_path: PathBuf::from("bin/tool"),
            uid: 5000,
            gid: 5000,
        };
        assert!(matches!(
            OwnershipMap::build(dir.path(), &[exc]),
            Err(OwnershipError::ExceptionExecBit { .. })
        ));
    }

    #[test]
    fn unexpected_inode_type_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
                                                                                                
        let _sock = std::os::unix::net::UnixListener::bind(dir.path().join("s")).unwrap();
        assert!(matches!(
            OwnershipMap::build(dir.path(), &[]),
            Err(OwnershipError::UnexpectedInodeType { .. })
        ));
    }

    #[test]
    fn whitespace_path_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a b"), b"x").unwrap();
        assert!(matches!(
            OwnershipMap::build(dir.path(), &[]),
            Err(OwnershipError::WhitespacePath { .. })
        ));
    }

    #[test]
    fn non_utf8_path_fails_closed() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
                                                                                             
                                                                                                   
        let name = OsString::from_vec(vec![b'a', 0xFF, b'b']);
        std::fs::write(dir.path().join(&name), b"x").unwrap();
        assert!(matches!(
            OwnershipMap::build(dir.path(), &[]),
            Err(OwnershipError::NonUtf8Path { .. })
        ));
    }

    #[test]
    fn hardlinks_are_allowed_on_the_default_path() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        std::fs::write(&a, b"x").unwrap();
        std::fs::hard_link(&a, dir.path().join("b")).unwrap();
                                                                                           
                                                                              
        let map = OwnershipMap::build(dir.path(), &[]).unwrap();
        assert_eq!(map.owner(Path::new("a")), (0, 0));
        assert_eq!(map.owner(Path::new("b")), (0, 0));
    }

    #[test]
    fn exception_on_hardlink_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("gate.json");
        std::fs::write(&a, b"{}").unwrap();
        chmod(&a, 0o600);
        std::fs::hard_link(&a, dir.path().join("other.json")).unwrap();
        let exc = OwnerException {
            rel_path: PathBuf::from("gate.json"),
            uid: 5000,
            gid: 5000,
        };
        assert!(matches!(
            OwnershipMap::build(dir.path(), &[exc]),
            Err(OwnershipError::ExceptionHardlink { .. })
        ));
    }

    #[test]
    fn map_records_full_st_mode_for_the_m_line_and_h_misc() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        chmod(&f, 0o600);
        let map = OwnershipMap::build(dir.path(), &[]).unwrap();
        let (_, owner) = map.iter().find(|(p, _)| *p == Path::new("f")).unwrap();
                                                          
        assert_eq!(
            owner.mode & 0o170000,
            0o100000,
            "S_IFMT preserved for h_misc"
        );
        assert_eq!(owner.mode & 0o7777, 0o600, "perm bits for the m-line mask");
    }

    #[test]
    fn exception_on_a_directory_fails_closed() {
                                                                                                      
                                                                                                  
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc/conf.d")).unwrap();
        let exc = OwnerException {
            rel_path: PathBuf::from("etc/conf.d"),
            uid: 5000,
            gid: 5000,
        };
        assert!(matches!(
            OwnershipMap::build(dir.path(), &[exc]),
            Err(OwnershipError::ExceptionNotRegularFile { .. })
        ));
    }

    #[test]
    fn exception_on_a_symlink_fails_closed() {
                                                                                                          
                                                                                   
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/target", dir.path().join("link")).unwrap();
        let exc = OwnerException {
            rel_path: PathBuf::from("link"),
            uid: 5000,
            gid: 5000,
        };
        assert!(matches!(
            OwnershipMap::build(dir.path(), &[exc]),
            Err(OwnershipError::ExceptionNotRegularFile { .. })
        ));
    }
}
