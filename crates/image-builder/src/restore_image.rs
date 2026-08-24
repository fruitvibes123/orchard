                                                                                                 
//! pair (data tar + db sidecar) into a persist-shaped tree, size it two-dimensionally (bytes AND
//! inodes), and self-check the baked identity facts the box depends on.
//!
                                 
//! - **ONE parser** — the std `tar` crate makes every staging decision operator-side; the container
//!   only applies ownership from a NUL-delimited spec derived from that same parse. There is never a
//!   second in-container tar extraction (validate-with-A/extract-with-B is a validation-bypass seam).
//! - **Deterministic** — the image is a pure function of (tar bytes, db bytes, pubkey, flags):
//!   fixed label/UUID/hash-seed, fixed [`crate::build::RESTORE_BAKE_EPOCH`] on both normalization
//!   legs, explicit `-N` from the staged file count, no wall clock anywhere. Iteration order is
//!   archive order (no map iteration).
//! - **Fail-loud** — hostile tar paths, non-uniform owners without `--db-owner`, inode/byte
//!   exhaustion (killed by construction via explicit sizing), and any identity drift abort the
//!   assembly with operator-facing messages. The checks catch OPERATOR ERROR; an attacker with the
//!   signing key already owns restore content (spec C1 §6e) — nothing here oversells.
//!
//! The container bake leg ([`crate::build_tools_host::HostBuildTools::bake_restore_image`]) is the
//! audited `bake_persist_skeleton` shape parameterized (+ the owner legs and the explicit `-N`),
//! double-baked internally and byte-compared before any bytes leave the builder.

use std::os::unix::fs::PermissionsExt as _;

/// What the operator hands the assembler (the `orchard restore-image` verb's parsed args).
#[derive(Debug)]
pub struct RestoreImageSpec<'a> {
    /// The daily `data-<ts>.tar.gz` bytes (the fb-backup data leg).
    pub data_tar_gz: &'a [u8],
    /// The daily `db-<ts>.sqlite` bytes (the fb-backup db leg).
    pub db: &'a [u8],
    /// The operator login pubkey staged at the shared skeleton path (may be empty ⇒ no key file).
    pub operator_pubkey: &'a [u8],
    /// Tenant root directory on persist (default `recipes`) — ONE safe path component.
    pub root: &'a str,
    /// The db's target path under `root` (default `recipes.db`) — validated relative components.
    pub db_target: &'a str,
    /// Explicit tenant owner; `None` ⇒ derive from uniform tar entry owners or fail loud.
    pub db_owner: Option<(u32, u32)>,
}

/// One staged entry (tar entries + the injected db), for the CLI's operator-facing manifest print.
#[derive(Debug)]
pub struct StagedManifestEntry {
    /// Path relative to the persist filesystem root (includes the tenant `root` prefix).
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub size: u64,
}

/// The staged tree + everything the container bake leg needs. Owners are deliberately NOT applied
/// host-side (unprivileged) — they ride `owners_nul` into the container's `xargs -0 chown` leg.
#[derive(Debug)]
pub struct StagedRestore {
    /// The staging tree (contents + modes applied; owners host-side unapplied).
    pub stage: tempfile::TempDir,
    /// `"uid:gid\0relpath\0"…` — the container chown spec, in archive order (deterministic).
    pub owners_nul: Vec<u8>,
    /// Archive-ordered entry list (+ the injected db last), for the CLI manifest print.
    pub manifest: Vec<StagedManifestEntry>,
    /// The tenant owner actually resolved (explicit `--db-owner`, or the uniform tar owner).
    pub resolved_db_owner: (u32, u32),
    /// The validated tenant root component (carried to the bake script's chown-floor leg).
    pub root: String,
    /// Inode demand: staged tar entries + db + tenant root dir + the skeleton subtree.
    pub file_count: u64,
    /// BLOCK-GRANULAR content demand: every entry rounded up to whole 4096-byte blocks (a 1-byte
    /// file consumes a full block on disk — raw byte sums under-size small-file-dense content;
    /// the inode-dense bake gate caught exactly that).
    pub content_bytes: u64,
}

                                                                                   
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizePlan {
    /// 4096-byte blocks passed to `mke2fs` as the fs size.
    pub blocks: u64,
    /// Explicit `-N` inode count — NEVER ratio-derived (the <512 MiB `small` class flips
    /// `inode_ratio` 16384→4096 at the boundary; pinning `-N` kills the class).
    pub inodes: u64,
}

/// Assembly errors — every message is operator-facing (the CLI exits non-zero printing these).
#[derive(Debug, thiserror::Error)]
pub enum RestoreImageError {
    #[error(
        "hostile path in the data tar: {path:?} — every component must be non-empty and not \
         `.`/`..`; no absolute paths, no `//` (the tar is parsed ONCE, here, and nothing that \
         fails this rule reaches the image)"
    )]
    HostilePath { path: String },
    #[error(
        "--root {root:?} must be a single path component of [A-Za-z0-9._-] (and not `.`/`..`) — \
         it is substituted into the container bake script's chown-floor leg"
    )]
    BadRoot { root: String },
    #[error(
        "--db-target {target:?} must be relative with components that are non-empty and not \
         `.`/`..`"
    )]
    BadDbTarget { target: String },
    #[error(
        "unsupported tar entry type for {path:?} — the assembler stages regular files, \
         directories and symlinks only (fail-closed allowlist; a device/fifo/hardlink in a daily \
         data tar is not the fb-backup shape)"
    )]
    UnsupportedEntryType { path: String },
    #[error(
        "tar entry {path:?} carries owner {uid}:{gid} outside the u32 range — refusing (the \
         owner spec is applied numerically in-container)"
    )]
    OwnerOutOfRange { path: String, uid: u64, gid: u64 },
    #[error(
        "data tar owners are not uniform ({found}) and no --db-owner was given — pass \
         --db-owner uid:gid to pick the tenant owner explicitly (I-R3-2: the reference tenant's \
         daily tar is expected-uniform; a stray differently-owned entry is worth investigating \
         before restoring)"
    )]
    AmbiguousOwner { found: String },
    #[error(
        "the data tar staged no entries and no --db-owner was given — cannot derive the tenant \
         owner (pass --db-owner uid:gid)"
    )]
    NoOwnerSource,
    #[error(
        "staged path collision: {path:?} already exists in the staging tree — the db --db-target \
         collides with a tar entry (the daily pair should carry the db ONLY as the sidecar)"
    )]
    Collision { path: String },
    #[error(
        "tar entry {path:?} escaped the staging root (unpack_in skip) — the path validator \
         should have rejected it; refusing fail-closed"
    )]
    Escape { path: String },
    #[error(
        "assembled restore image would be {computed} bytes — past the installer's \
         {cap}-byte restore cap (MAX_RESTORE_IMAGE_BYTES): never bake an image the box is \
         guaranteed to refuse (ceiling). Shrink the backup or split the restore"
    )]
    TooLarge { computed: u64, cap: u64 },
    #[error("restore image too short for an ext4 superblock ({len} bytes)")]
    IdentityTooShort { len: usize },
    #[error("restore image is not ext4 (superblock magic {found:#06x}, want 0xef53)")]
    IdentityNotExt4 { found: u16 },
    #[error(
        "restore image has an ext4 journal (COMPAT has_journal bit set) — it must be baked \
         `-O ^has_journal`: box-init gates the first-boot grow on journal-ABSENCE, so a journaled \
         image strands the restore at its baked size (identity)"
    )]
    IdentityJournalPresent,
    #[error(
        "restore image volume label is {found:?}, want exactly \"persist\" — the box locates \
         persist BY LABEL (findfs LABEL=persist); a mislabeled image is rescue-on-every-restore \
         (identity, the R2 High class)"
    )]
    IdentityWrongLabel { found: String },
    #[error("skeleton staging failed: {0}")]
    Skeleton(String),
    #[error("staging io at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("data tar read: {0}")]
    TarRead(#[from] std::io::Error),
}

                                                                                                  
/// TWIN of fruit-basket's `initramfs-init` `MAX_RESTORE_IMAGE_BYTES` (AC6 keeps the box side at
/// zero new deps, so the constant is reimplemented there, not shared) — keep the two in lockstep.
pub const RESTORE_ASSEMBLY_CEILING_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Fixed fs overhead headroom in the byte dimension: superblock/GDT/bitmaps/root+lost+found slack.
/// Deliberately generous (4 MiB) — assembly fails LOUD if short (`mke2fs -d` aborts under `set -e`)
/// and first boot grows to the partition regardless; the §4b cap bounds the top.
const FIXED_FS_OVERHEAD_BLOCKS: u64 = 1024;

/// The 16 MiB floor (in 4096-byte blocks) — never bake below the skeleton-class size.
const FLOOR_BLOCKS: u64 = 4096;

/// The inode floor for `-N` (mke2fs needs room for the skeleton + slack even on a tiny restore).
const INODE_FLOOR: u64 = 1024;

/// Parse + validate + re-root the daily pair into a bake-ready staging tree (ONE parser: the std
                                                                                                   
/// owners are RECORDED into `owners_nul` for the container's `xargs -0 chown -h` leg.
pub fn stage_restore(spec: &RestoreImageSpec) -> Result<StagedRestore, RestoreImageError> {
                                                                                                   
                                                                                              
    if !is_safe_root_component(spec.root) {
        return Err(RestoreImageError::BadRoot {
            root: spec.root.to_string(),
        });
    }
    if spec.db_target.is_empty()
        || spec
            .db_target
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(RestoreImageError::BadDbTarget {
            target: spec.db_target.to_string(),
        });
    }

    let stage = tempfile::tempdir().map_err(|e| RestoreImageError::Io {
        path: "stage_restore tempdir".into(),
        source: e,
    })?;
    let root_dir = stage.path().join(spec.root);
    std::fs::create_dir_all(&root_dir).map_err(|e| RestoreImageError::Io {
        path: root_dir.display().to_string(),
        source: e,
    })?;

    let mut owners_nul: Vec<u8> = Vec::new();
    let mut manifest: Vec<StagedManifestEntry> = Vec::new();
                                                                                                
    let mut owner_set: Vec<(u32, u32)> = Vec::new();
                                                                                                 
                                                                                                    
                                                                                                          
                                                                                        
    let block_demand = |size: u64| size.div_ceil(4096).saturating_mul(4096);
    let mut content_bytes =
        block_demand(spec.db.len() as u64) + block_demand(spec.operator_pubkey.len() as u64);

    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(spec.data_tar_gz));
                                                                                           
                                                                                            
    archive.set_preserve_permissions(true);
                                                                                                 
                                                                                      
    archive.set_unpack_xattrs(false);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        let raw = entry.path_bytes().into_owned();
        let rel = validate_tar_path(&raw, kind.is_dir())?;
                                                                                              
        if !matches!(
            kind,
            tar::EntryType::Regular | tar::EntryType::Directory | tar::EntryType::Symlink
        ) {
            return Err(RestoreImageError::UnsupportedEntryType { path: rel });
        }
        let uid_raw = entry.header().uid()?;
        let gid_raw = entry.header().gid()?;
        let (Ok(uid), Ok(gid)) = (u32::try_from(uid_raw), u32::try_from(gid_raw)) else {
            return Err(RestoreImageError::OwnerOutOfRange {
                path: rel,
                uid: uid_raw,
                gid: gid_raw,
            });
        };
        let mode = entry.header().mode()?;
        let size = entry.header().size()?;
                                                                                             
                                                                                                   
        if !entry.unpack_in(&root_dir)? {
            return Err(RestoreImageError::Escape { path: rel });
        }
        let staged_path = format!("{}/{}", spec.root, rel);
        owners_nul.extend_from_slice(format!("{uid}:{gid}\0{staged_path}\0").as_bytes());
        if !owner_set.contains(&(uid, gid)) {
            owner_set.push((uid, gid));
        }
        manifest.push(StagedManifestEntry {
            path: staged_path,
            uid,
            gid,
            mode,
            size,
        });
        content_bytes = content_bytes.saturating_add(block_demand(size));
    }

                                                                                                     
    crate::build_tools_host::stage_persist_skeleton(stage.path(), spec.operator_pubkey)
        .map_err(|e| RestoreImageError::Skeleton(e.to_string()))?;

                                                                                               
    let resolved_db_owner = match spec.db_owner {
        Some(o) => o,
        None => match owner_set.as_slice() {
            [] => return Err(RestoreImageError::NoOwnerSource),
            [one] => *one,
            many => {
                return Err(RestoreImageError::AmbiguousOwner {
                    found: many
                        .iter()
                        .map(|(u, g)| format!("{u}:{g}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
        },
    };

                                                                                                  
    let db_rel = format!("{}/{}", spec.root, spec.db_target);
    let db_path = stage.path().join(&db_rel);
    if db_path.symlink_metadata().is_ok() {
        return Err(RestoreImageError::Collision { path: db_rel });
    }
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| RestoreImageError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    std::fs::write(&db_path, spec.db).map_err(|e| RestoreImageError::Io {
        path: db_path.display().to_string(),
        source: e,
    })?;
    std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        RestoreImageError::Io {
            path: db_path.display().to_string(),
            source: e,
        }
    })?;
    let (du, dg) = resolved_db_owner;
    owners_nul.extend_from_slice(format!("{du}:{dg}\0{db_rel}\0").as_bytes());
    manifest.push(StagedManifestEntry {
        path: db_rel,
        uid: du,
        gid: dg,
        mode: 0o600,
        size: spec.db.len() as u64,
    });
                                                                                                    
                                                                  
    owners_nul.extend_from_slice(format!("{du}:{dg}\0{}\0", spec.root).as_bytes());

                                                                                             
                                                                                                  
                                                                                                    
    let file_count = manifest.len() as u64 + 1 + 4;

    Ok(StagedRestore {
        stage,
        owners_nul,
        manifest,
        resolved_db_owner,
        root: spec.root.to_string(),
        file_count,
        content_bytes,
    })
}

/// The skeleton's top-level directory (`etc`, from `PERSIST_AUTHORIZED_KEYS_DIR`) — a `--root` that
                                                                                                     
/// then chowns `/work/{root}` to the tenant owner, so `{root} == "etc"` silently re-owns the operator
/// SSH key to the tenant uid → a box dropbear locks out, WHILE the ceremony's content-only staged-key
/// cross-check still passes (the false-assurance sting). Derived from the const so a future skeleton
/// dir addition keeps the reservation honest.
fn skeleton_top_level() -> &'static str {
    crate::build_tools_host::PERSIST_AUTHORIZED_KEYS_DIR
        .split('/')
        .next()
        .expect("PERSIST_AUTHORIZED_KEYS_DIR is a non-empty relative path")
}

/// `--root` rule: ONE path component, charset `[A-Za-z0-9._-]`, not `.`/`..`, and not the skeleton's
/// reserved top-level dir — strict because the value is substituted into the container bake script
/// (`chown -R {owner} /work/{root}`); the charset has no whitespace/quote/glob surface.
fn is_safe_root_component(root: &str) -> bool {
    !root.is_empty()
        && root != "."
        && root != ".."
        && root != skeleton_top_level()
        && root
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// The ONE tar path rule (every staging decision flows from this parse): UTF-8, relative, every
/// component non-empty and not `.`/`..`. Directory entries may carry ONE trailing `/` (the
/// `append_dir_all` shape) — stripped before validation. Returns the normalized relative path.
fn validate_tar_path(raw: &[u8], is_dir: bool) -> Result<String, RestoreImageError> {
    let lossy = || String::from_utf8_lossy(raw).into_owned();
    let mut bytes = raw;
    if is_dir && bytes.last() == Some(&b'/') {
        bytes = &bytes[..bytes.len() - 1];
    }
    if bytes.is_empty() {
        return Err(RestoreImageError::HostilePath { path: lossy() });
    }
    let s =
        std::str::from_utf8(bytes).map_err(|_| RestoreImageError::HostilePath { path: lossy() })?;
    if s.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(RestoreImageError::HostilePath {
            path: s.to_string(),
        });
    }
    Ok(s.to_string())
}

                                                                                
/// `inodes = max(file_count*2, 1024)` explicit (never ratio-derived);
/// `blocks = max(ceil(bytes*1.15/4096) + ceil(inodes*256/4096) + overhead, 16 MiB floor)`;
/// refuses past the 2 GiB installer cap — never bake what the box must refuse.
pub fn plan_size(content_bytes: u64, file_count: u64) -> Result<SizePlan, RestoreImageError> {
    let inodes = (file_count.saturating_mul(2)).max(INODE_FLOOR);
                                                                                                   
    let data_blocks = content_bytes
        .saturating_mul(115)
        .div_ceil(100)
        .div_ceil(4096);
                                                                      
    let itable_blocks = inodes.saturating_mul(256).div_ceil(4096);
    let blocks = (data_blocks + itable_blocks + FIXED_FS_OVERHEAD_BLOCKS).max(FLOOR_BLOCKS);
    let computed = blocks * 4096;
    if computed > RESTORE_ASSEMBLY_CEILING_BYTES {
        return Err(RestoreImageError::TooLarge {
            computed,
            cap: RESTORE_ASSEMBLY_CEILING_BYTES,
        });
    }
    Ok(SizePlan { blocks, inodes })
}

                                                                                                    
/// pure byte reads of the three superblock facts the box depends on — ext4 magic `0xEF53` at
/// 1024+56, journal COMPAT bit (1024+0x5C & 0x4) CLEAR, `s_volume_name` at 1024+0x78 exactly
/// `"persist"` (NUL-padded 16 bytes).
///
/// The offsets are deliberately REIMPLEMENTED (~10 lines) in fruit-basket's `initramfs-init`
/// `prepare()` pre-checks (AC6 keeps the box installer at zero new deps) — the twin is named
                                                             
pub fn check_restore_identity(image: &[u8]) -> Result<(), RestoreImageError> {
                                                                    
    let sb = image
        .get(SB_OFFSET..SB_OFFSET + SB_VOLUME_NAME_OFFSET + 16)
        .ok_or(RestoreImageError::IdentityTooShort { len: image.len() })?;
    let magic = u16::from_le_bytes([sb[SB_MAGIC_OFFSET], sb[SB_MAGIC_OFFSET + 1]]);
    if magic != 0xEF53 {
        return Err(RestoreImageError::IdentityNotExt4 { found: magic });
    }
    let compat = u32::from_le_bytes([
        sb[SB_FEATURE_COMPAT_OFFSET],
        sb[SB_FEATURE_COMPAT_OFFSET + 1],
        sb[SB_FEATURE_COMPAT_OFFSET + 2],
        sb[SB_FEATURE_COMPAT_OFFSET + 3],
    ]);
    if compat & COMPAT_HAS_JOURNAL != 0 {
        return Err(RestoreImageError::IdentityJournalPresent);
    }
    let label = &sb[SB_VOLUME_NAME_OFFSET..SB_VOLUME_NAME_OFFSET + 16];
    if label != PERSIST_LABEL {
        let found = label
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect::<String>();
        return Err(RestoreImageError::IdentityWrongLabel { found });
    }
    Ok(())
}

/// ext4 superblock byte offset in the image.
const SB_OFFSET: usize = 1024;
/// `s_magic` offset within the superblock (LE u16, `0xEF53`).
const SB_MAGIC_OFFSET: usize = 56;
/// `s_feature_compat` offset within the superblock (LE u32).
const SB_FEATURE_COMPAT_OFFSET: usize = 0x5C;
                                                                                          
const COMPAT_HAS_JOURNAL: u32 = 0x4;
/// `s_volume_name` offset within the superblock (16 bytes, NUL-padded).
const SB_VOLUME_NAME_OFFSET: usize = 0x78;
/// The exact 16-byte label field the box's `findfs LABEL=persist` resolves.
const PERSIST_LABEL: &[u8; 16] = b"persist\0\0\0\0\0\0\0\0\0";

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a gz tar whose entries carry RAW names (bypassing `set_path` validation) so hostile
    /// shapes ride into the archive exactly as an attacker-crafted/corrupt tar would carry them.
    /// `(path, bytes, mode, uid, gid)` — the fb-backup pair shape (paths relative to the data root).
    fn tiny_tar(entries: &[(&str, &[u8], u32, u32, u32)]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        for (path, bytes, mode, uid, gid) in entries {
            let mut h = tar::Header::new_gnu();
            {
                let name = &mut h.as_old_mut().name;
                assert!(path.len() <= name.len(), "test path too long: {path}");
                name[..path.len()].copy_from_slice(path.as_bytes());
            }
            h.set_size(bytes.len() as u64);
            h.set_mode(*mode);
            h.set_uid(*uid as u64);
            h.set_gid(*gid as u64);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append(&h, *bytes).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn stage_rejects_hostile_paths() {
        for bad in ["../x", "/abs", "a//b", "a/./b", "a/../b", ""] {
            let tar = tiny_tar(&[(bad, b"x", 0o644, 100, 100)]);
            let spec = RestoreImageSpec {
                data_tar_gz: &tar,
                db: b"",
                operator_pubkey: b"K\n",
                root: "recipes",
                db_target: "recipes.db",
                db_owner: Some((100, 100)),
            };
            assert!(
                stage_restore(&spec).is_err(),
                "accepted hostile path {bad:?}"
            );
        }
                                                                                                 
                                                                        
                                                                                                      
                                                                                                    
                                                            
        let tar = tiny_tar(&[("images/a", b"x", 0o644, 100, 100)]);
        for (root, db_target) in [
            ("../up", "recipes.db"),
            ("a/b", "recipes.db"),
            ("recipes", "../../etc/shadow"),
            ("", "recipes.db"),
            ("etc", "recipes.db"),
        ] {
            let spec = RestoreImageSpec {
                data_tar_gz: &tar,
                db: b"D",
                operator_pubkey: b"K\n",
                root,
                db_target,
                db_owner: Some((100, 100)),
            };
            assert!(
                stage_restore(&spec).is_err(),
                "accepted root={root:?} db_target={db_target:?}"
            );
        }
    }

    #[test]
    fn stage_reroots_applies_metadata_and_injects_db() {
        let tar = tiny_tar(&[
            ("images/a.webp", b"IMG", 0o644, 100, 100),
            ("ca.crt", b"CERT", 0o644, 100, 100),
        ]);
        let spec = RestoreImageSpec {
            data_tar_gz: &tar,
            db: b"SQLITE",
            operator_pubkey: b"K\n",
            root: "recipes",
            db_target: "recipes.db",
            db_owner: None,
        };
        let s = stage_restore(&spec).unwrap();
        assert_eq!(
            std::fs::read(s.stage.path().join("recipes/images/a.webp")).unwrap(),
            b"IMG"
        );
        assert_eq!(
            std::fs::read(s.stage.path().join("recipes/recipes.db")).unwrap(),
            b"SQLITE"
        );
        assert_eq!(s.resolved_db_owner, (100, 100), "uniform default derived");
                                                                         
        assert!(s
            .stage
            .path()
            .join(crate::build_tools_host::PERSIST_AUTHORIZED_KEYS_PATH)
            .exists());
                                                                                     
        let spec_str = String::from_utf8_lossy(&s.owners_nul).into_owned();
        assert!(
            spec_str.contains("100:100\0recipes/recipes.db\0"),
            "{spec_str:?}"
        );
        assert!(
            spec_str.contains("100:100\0recipes/images/a.webp\0"),
            "{spec_str:?}"
        );
        assert!(spec_str.contains("100:100\0recipes\0"), "{spec_str:?}");
                        
        let m = std::fs::metadata(s.stage.path().join("recipes/recipes.db")).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o600);
                                                                                           
        let m = std::fs::metadata(s.stage.path().join("recipes/images/a.webp")).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o644);
    }

    #[test]
    fn stage_fail_louds_on_ambiguous_owner() {
                                                                                                
                                           
        let tar = tiny_tar(&[
            ("images/a", b"x", 0o644, 100, 100),
            ("ca.crt", b"c", 0o644, 0, 0),
        ]);
        let spec = RestoreImageSpec {
            data_tar_gz: &tar,
            db: b"D",
            operator_pubkey: b"K\n",
            root: "recipes",
            db_target: "recipes.db",
            db_owner: None,
        };
        let err = stage_restore(&spec).unwrap_err().to_string();
        assert!(
            err.contains("100") && err.contains('0') && err.contains("--db-owner"),
            "{err}"
        );
    }

    #[test]
    fn stage_fail_louds_on_db_target_collision() {
                                                                                          
                                                                                               
        let tar = tiny_tar(&[("recipes.db", b"STRAY", 0o644, 100, 100)]);
        let spec = RestoreImageSpec {
            data_tar_gz: &tar,
            db: b"REAL",
            operator_pubkey: b"K\n",
            root: "recipes",
            db_target: "recipes.db",
            db_owner: Some((100, 100)),
        };
        let err = stage_restore(&spec).unwrap_err().to_string();
        assert!(err.contains("collision"), "{err}");
    }

    #[test]
    fn plan_size_is_two_dimensional_floored_and_ceilinged() {
                                                                         
        let p = plan_size(100 * 1024 * 1024, 50).unwrap();
        assert!(p.blocks * 4096 > 100 * 1024 * 1024);
        assert_eq!(p.inodes, 1024, "inode floor");
                                                                                                   
        let p = plan_size(10_000 * 1024, 10_000).unwrap();
        assert_eq!(p.inodes, 20_000);
                                                                                 
        let p = plan_size(10, 3).unwrap();
        assert_eq!(p.blocks, 4096);
                                                                                                   
                                                                                                
        let err = plan_size(3 * 1024 * 1024 * 1024, 100)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&RESTORE_ASSEMBLY_CEILING_BYTES.to_string()),
            "{err}"
        );
    }

    #[test]
    fn check_restore_identity_pins_the_three_superblock_facts() {
                                                                                              
                            
        let mut sb = vec![0u8; 8192];
        sb[1024 + 56] = 0x53;
        sb[1024 + 57] = 0xEF;
        sb[1024 + 0x78..1024 + 0x78 + 7].copy_from_slice(b"persist");
        check_restore_identity(&sb).unwrap();
        let mut nolabel = sb.clone();
        nolabel[1024 + 0x78] = 0;                                  
        assert!(check_restore_identity(&nolabel).is_err());
        let mut journal = sb.clone();
        journal[1024 + 0x5C] |= 0x04;                   
        assert!(check_restore_identity(&journal).is_err());
        let mut notext4 = sb.clone();
        notext4[1024 + 56] = 0;            
        assert!(check_restore_identity(&notext4).is_err());
                                                                                               
        let mut suffixed = sb.clone();
        suffixed[1024 + 0x78 + 7] = b'X';              
        assert!(check_restore_identity(&suffixed).is_err());
                                                   
        assert!(check_restore_identity(&[0u8; 512]).is_err());
    }
}
