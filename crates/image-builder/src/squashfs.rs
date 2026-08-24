                                                                                           
//!
//! `mksquashfs` as bounded build-glue (spec line 1035): `-comp xz -xattrs -no-fragments
//! -mkfs-time/-fstime $SOURCE_DATE_EPOCH` + a per-caller ownership flag ([`Ownership`]). `-xattrs`
//! is REQUIRED — it preserves the `security.ima` + `security.evm` xattrs that IMA appraisal depends
//! on — computed by [`crate::ima_evm_signer`] (RFC-6979) and injected at pack via the `-pf`
//! pseudo-file (no live setxattr). Ownership is either `-all-root` (`AllRoot`, every inode `0:0`) or
                                                                                                   
//!
//! REPRODUCIBILITY (R.4): `-mkfs-time`/`-fstime` fix ONLY the superblock timestamps — NOT the
//! per-inode or root-inode mtimes (R.4 proved those escape the argv flags). squashfs byte-determinism
//! actually comes from the `find /staging -depth -exec touch -h -d @SOURCE_DATE_EPOCH` clamp in
//! [`crate::build_tools_host`]'s `pack_squashfs` — which includes the staging ROOT (do NOT re-add
//! `-mindepth 1`; it leaves the root inode at wall-clock time). With that clamp + the fixed superblock
//! time + deterministic content the image is byte-reproducible; `build_twice_is_byte_identical` confirms it.

use std::path::Path;

                                                                                                       
/// today's behavior, kept by every pack with no non-`0:0` file (the weights pack). `Map` DROPS
/// `-all-root` so the per-inode `m` pseudo-lines (from the [`crate::ownership::OwnershipMap`], injected
/// via `-pf`) set ownership instead — required to bake a non-`0:0` owner. `-all-root` (and
/// `-force-uid`/`-force-gid`) OVERRIDE per-file `m` ownership (verified empirically), so the two are
/// mutually exclusive: only the rootfs pack (`pack_squashfs`) uses `Map`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// `-all-root`: every inode `0:0`.
    AllRoot,
    /// No `-all-root`: ownership comes from the per-inode `m` pseudo-lines.
    Map,
}

/// The validated `mksquashfs` argv for a deterministic, xattr-preserving rootfs image.
/// `source_date_epoch` is the fixed build timestamp (e.g. the recipes git commit time); `ownership`
/// selects `-all-root` vs the per-inode `m`-pseudo path (D1/F-1).
pub fn mksquashfs_argv(
    staging: &Path,
    out: &Path,
    source_date_epoch: u64,
    ownership: Ownership,
) -> Vec<String> {
    let epoch = source_date_epoch.to_string();
    let mut argv = vec![
        staging.to_string_lossy().into_owned(),
        out.to_string_lossy().into_owned(),
        "-comp".into(),
        "xz".into(),
        "-xattrs".into(),                                                  
        "-no-fragments".into(),
    ];
                                                                                                        
                                                                                      
    if matches!(ownership, Ownership::AllRoot) {
        argv.push("-all-root".into());                         
    }
    argv.push("-mkfs-time".into());
    argv.push(epoch.clone());
    argv.push("-fstime".into());
    argv.push(epoch);
    argv
}

/// The full in-container `sh -c` pack command: mtime-clamp, `mksquashfs` ([`mksquashfs_argv`] +
/// `-pf <pf>` when signing), output chmod'd host-readable. SINGLE-SOURCED here so the production
/// pack (`build_tools_host::pack_squashfs`/`pack_weights_squashfs`) and the byte-level boot-gate
                                                        
///
/// The clamp `find <staging> -depth -exec touch -h -d @EPOCH` includes the staging ROOT — do NOT
/// re-add `-mindepth 1` (the root inode's mtime otherwise stays wall-clock and breaks `.img`
/// byte-reproducibility, R.4); `-depth` touches children before their parent (touching a child
/// bumps the parent's mtime).
///
/// The `Map` variant additionally forces the staging ROOT inode to `0:0` in-container (`-pf`
/// cannot set the root — probed on mksquashfs 4.7.4; every other inode has an `m` line) and
/// restores the captured owner UNCONDITIONALLY — also when the clamp or `mksquashfs` fails — so a
                                                                                                 
/// RAII cleanup must work on EVERY exit path). The pack's own exit status is preserved via `rc`; a
/// failed restore itself fails the command (fail-closed). Numeric `stat -c '%u:%g'` avoids passwd
/// lookups in the minimal container. All argv/paths are build-time-controlled (no attacker input),
/// so the shell-join is safe.
pub fn pack_shell_cmd(
    staging: &Path,
    out: &Path,
    source_date_epoch: u64,
    ownership: Ownership,
    pf: Option<&Path>,
) -> String {
    let argv = mksquashfs_argv(staging, out, source_date_epoch, ownership).join(" ");
    let pf = pf.map_or_else(String::new, |p| format!(" -pf {}", p.display()));
    let s = staging.display();
    let o = out.display();
    let clamp = format!("find {s} -depth -exec touch -h -d @{source_date_epoch} {{}} +");
    match ownership {
        Ownership::Map => format!(
            "orig=$(stat -c '%u:%g' {s}) && chown 0:0 {s} || exit 1; \
             {clamp} && mksquashfs {argv}{pf}; rc=$?; \
             chown \"$orig\" {s} || exit 1; [ \"$rc\" -eq 0 ] || exit \"$rc\"; chmod a+r {o}"
        ),
        Ownership::AllRoot => format!("{clamp} && mksquashfs {argv}{pf} && chmod a+r {o}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn argv_carries_the_load_bearing_flags() {
        let argv = mksquashfs_argv(
            &PathBuf::from("/staging"),
            &PathBuf::from("/out.sqfs"),
            1_700_000_000,
            Ownership::AllRoot,
        );
        assert_eq!(argv[0], "/staging");
        assert_eq!(argv[1], "/out.sqfs");
        assert!(
            argv.contains(&"-xattrs".to_string()),
            "xattrs REQUIRED for IMA"
        );
        assert!(argv.contains(&"-all-root".to_string()));
        assert!(argv.contains(&"-no-fragments".to_string()));
                                                                  
        let n = argv.iter().filter(|a| *a == "1700000000").count();
        assert_eq!(
            n, 2,
            "-mkfs-time + -fstime both pinned to SOURCE_DATE_EPOCH"
        );
    }

    #[test]
    fn all_root_variant_emits_all_root() {
        let argv = mksquashfs_argv(
            Path::new("/s"),
            Path::new("/o.sqfs"),
            1_700_000_000,
            Ownership::AllRoot,
        );
        assert!(argv.contains(&"-all-root".to_string()));
    }

    #[test]
    fn map_variant_omits_all_root() {
        let argv = mksquashfs_argv(
            Path::new("/s"),
            Path::new("/o.sqfs"),
            1_700_000_000,
            Ownership::Map,
        );
        assert!(
            !argv.contains(&"-all-root".to_string()),
            "Map ownership must NOT force -all-root — it OVERRIDES the per-inode m pseudo-lines"
        );
                                                     
        assert!(argv.contains(&"-xattrs".to_string()));
        assert!(argv.contains(&"-no-fragments".to_string()));
        let n = argv.iter().filter(|a| *a == "1700000000").count();
        assert_eq!(n, 2, "-mkfs-time + -fstime still pinned under Map");
    }

    #[test]
    fn map_pack_cmd_restores_the_owner_unconditionally() {
        let cmd = pack_shell_cmd(
            Path::new("/staging"),
            Path::new("/out/rootfs.sqfs"),
            1_700_000_000,
            Ownership::Map,
            Some(Path::new("/xattr.pseudo")),
        );
                                                                                                      
                                                                                           
        let rc_pos = cmd.find("rc=$?").expect("captures the pack status");
        let restore_pos = cmd.find("chown \"$orig\"").expect("restores the owner");
        assert!(
            restore_pos > rc_pos,
            "restore after status capture, unconditional: {cmd}"
        );
        assert!(
            !cmd.contains("&& chown \"$orig\""),
            "restore NOT gated on pack success: {cmd}"
        );
                                                                       
        assert!(
            cmd.contains("|| exit \"$rc\""),
            "pack status preserved: {cmd}"
        );
        assert!(cmd.contains("chown 0:0 /staging"), "root forced 0:0: {cmd}");
        assert!(cmd.contains("-pf /xattr.pseudo"), "pseudo injected: {cmd}");
        assert!(!cmd.contains("-all-root"), "Map drops -all-root: {cmd}");
        assert!(
            cmd.contains("find /staging -depth"),
            "mtime clamp present, root included: {cmd}"
        );
    }

    #[test]
    fn all_root_pack_cmd_never_chowns() {
        let cmd = pack_shell_cmd(
            Path::new("/staging"),
            Path::new("/out/weights.sqfs"),
            1_700_000_000,
            Ownership::AllRoot,
            None,
        );
        assert!(!cmd.contains("chown"), "AllRoot never chowns: {cmd}");
        assert!(!cmd.contains("-pf"), "no pseudo flag when pf=None: {cmd}");
        assert!(cmd.contains("-all-root"));
        assert!(cmd.contains("chmod a+r /out/weights.sqfs"));
    }
}
