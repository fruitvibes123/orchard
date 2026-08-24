//! Pure-Rust, no-privilege, deterministic syslinux (extlinux) installer — the **B1 mechanism** of the
                                                                                                    
//! firmware-agnostic; findings `installer-b1-spike-findings.md`).
//!
//! Real `extlinux --install` loop-mounts the target filesystem and `FIBMAP`s `ldlinux.sys` to learn
//! its physical sector map — which needs `CAP_SYS_ADMIN`. This crate replaces that one privileged
//! step by reading the ext4 extent tree directly out of the baked boot-fs bytes ([`ext4`]), then
//! porting syslinux 6.04-pre1's `syslxmod.c::syslinux_patch` ([`patch`]) to patch `ldlinux.sys`'s
//! patch-area + the VBR for that placement. The result is **deterministic by construction** (given a
//! reproducible `mke2fs -d` placement) and needs **no mount, no capability, no exec** — so the build
//! container keeps its no-`CAP_SYS_ADMIN` property (the I-3 invariant), and the box installer never
//! runs syslinux at all (the image is pre-baked).
//!
//! Two public steps, both called by `recipes-image-builder`'s `bake_boot_fs`:
//! 1. [`prepare_ldlinux_sys`] — turn the `make bios` core into the on-disk form `mke2fs -d` stages.
//! 2. [`install_into_bootfs`] — after `mke2fs -d`, patch the staged `ldlinux.sys` + VBR in place.
//!
//! A third entry point, [`read_file`], exposes the same ext4 reader for its second consumer class:
//! generic no-privilege file reads out of a baked ext4 image (the `orchard prod --restore-from`
//! staged-key cross-check reads `etc/ssh/authorized_keys.d/root` out of a restore persist image).
//! Same fail-closed scope as the installer path — depth-0 extents, linear dirs, bounds-checked.

#![cfg_attr(not(test), deny(clippy::unwrap_used))]

mod error;
mod ext4;
mod patch;

pub use error::Error;

use ext4::Ext4;

/// The 2-sector ADV (Auxiliary Data Vector) syslinux appends after the core image.
const ADV_SIZE: usize = 2 * 512;

/// Disk geometry baked into the VBR (`patch_file_and_bootblock`). For the pre-baked boot-fs these are
/// FIXED, not probed from a real disk: `hidden` is the boot partition's start LBA (1 MiB-aligned =
/// 2048), `total_sectors` is the boot-fs size in sectors, and `heads`/`sectors` are syslinux's
/// loop-device defaults (64/32) — the values a real `extlinux --install` would bake.
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    pub heads: u16,
    pub sectors: u16,
    /// `bsHiddenSecs`: the boot partition's start LBA on the eventual disk.
    pub hidden: u32,
    /// Total sectors of the boot-fs partition.
    pub total_sectors: u64,
}

/// What [`install_into_bootfs`] did — for the build's sanity log (mirrors the spike's stdout line).
#[derive(Debug, Clone, Copy)]
pub struct InstallReport {
    pub ldlinux_inode: u32,
    pub sector_count: usize,
    pub extent_runs: usize,
    pub first_sector: u64,
}

/// Build the on-disk `ldlinux.sys` from the raw source-built core (`bios/core/ldlinux.sys` from the
/// pinned `make bios`): zero-pad to a 512-byte multiple (= `boot_image_len`, matching `bin2c.pl`'s
/// pad) then append the 2-sector reset ADV. This is exactly what `extlinux --install` writes to disk;
/// doing it in Rust is the privilege-free B1 install-prep. The result is what gets staged into the
/// boot-fs tree (so `mke2fs -d` lays it down) and later patched in place by [`install_into_bootfs`].
pub fn prepare_ldlinux_sys(core: &[u8]) -> Vec<u8> {
    let boot_image_len = core.len().div_ceil(512) * 512;
    let mut ondisk = Vec::with_capacity(boot_image_len + ADV_SIZE);
    ondisk.extend_from_slice(core);
    ondisk.resize(boot_image_len, 0);                                       
    ondisk.extend_from_slice(&reset_adv());                                        
    ondisk
}

/// The reset ADV (`syslinux_reset_adv`/`cleanup_adv`, `setadv.c`): an EMPTY 2×512 ADV. Byte-verified
/// against a real `extlinux` install's tail (`a5 2f 2d 5a | 67 17 04 a3 | 00.. | 64 bf 28 dd`).
fn reset_adv() -> [u8; ADV_SIZE] {
    let mut sector = [0u8; 512];
    sector[0..4].copy_from_slice(&0x5a2d_2fa5u32.to_le_bytes());                     
    sector[4..8].copy_from_slice(&0xa304_1767u32.to_le_bytes());                                                   
    sector[508..512].copy_from_slice(&0xdd28_bf64u32.to_le_bytes());                     
    let mut out = [0u8; ADV_SIZE];
    out[..512].copy_from_slice(&sector);
    out[512..].copy_from_slice(&sector);                                  
    out
}

/// Read a regular file at `path` (e.g. `etc/ssh/authorized_keys.d/root`) out of an ext4 image held
/// in memory. Path components are resolved from the root inode; no mount, no privilege, no exec.
/// Errors are the crate's existing fail-closed [`Error`] (bad superblock, unsupported extent
/// depth/htree dir, missing entry, bounds). The image must be the WHOLE filesystem bytes.
pub fn read_file(image: &[u8], path: &str) -> Result<Vec<u8>, Error> {
    let fs = Ext4::open(image)?;
    let ino = fs.resolve(path)?;
    let (size, extents) = fs.read_inode(ino)?;
    fs.read_extent_data(&extents, size)
}

/// Install the syslinux stage-2 into a baked ext4 boot-fs image, IN PLACE. Resolves
/// `<install_dir>/ldlinux.sys` (already placed by `mke2fs -d` in the form [`prepare_ldlinux_sys`]
/// produced), reads its physical extents from the ext4 metadata, patches the core's patch-area + the
/// VBR for that exact placement, and writes both back: the patched VBR to the boot sector (offset 0,
/// the area ext4 reserves for a bootloader) and the patched `ldlinux.sys` over its own extents.
/// `vbr_template` is the source-built `ldlinux.bss` (exactly 512 bytes). No mount, no CAP, no exec.
pub fn install_into_bootfs(
    image: &mut [u8],
    vbr_template: &[u8],
    install_dir: &str,
    geo: &Geometry,
) -> Result<InstallReport, Error> {
    if vbr_template.len() != 512 {
        return Err(Error::VbrLength {
            found: vbr_template.len(),
        });
    }
    let path = format!("{}/ldlinux.sys", install_dir.trim_end_matches('/'));

                                                                                                     
    let (i_size, extents, block_size, inode, mut ldlinux) = {
        let fs = Ext4::open(image)?;
        let inode = fs.resolve(&path)?;
        let (i_size, extents) = fs.read_inode(inode)?;
        let ldlinux = fs.read_extent_data(&extents, i_size)?;
        (i_size, extents, fs.block_size(), inode, ldlinux)
    };
    if i_size < ADV_SIZE as u64 {
        return Err(Error::OnDiskTooSmallForAdv { size: i_size });
    }

                                                                                                  
                                                                                                    
                                                                                                  
                                                                                                
    let spb = block_size / 512;
    let mut sectp = Vec::new();
    for &(phys, len) in &extents {
        for b in 0..len as u64 {
            for s in 0..spb {
                sectp.push((phys + b) * spb + s);
            }
        }
    }
    sectp.truncate((i_size as usize).div_ceil(512));

                                                                                  
    let mut vbr = vbr_template.to_vec();
    let boot_image_len = (i_size as usize) - ADV_SIZE;
    let subdir = if install_dir.starts_with('/') {
        install_dir.to_string()
    } else {
        format!("/{install_dir}")
    };
    let extent_runs =
        patch::syslinux_patch(&mut ldlinux, &mut vbr, &sectp, &subdir, geo, boot_image_len)?;

                                                                                         
    let image_len = image.len();
    write_at(image, 0, &vbr, "vbr_writeback", image_len)?;
    write_extents(image, &extents, &ldlinux, block_size)?;

    Ok(InstallReport {
        ldlinux_inode: inode,
        sector_count: sectp.len(),
        extent_runs,
        first_sector: sectp.first().copied().unwrap_or(0),
    })
}

/// Overwrite `[off, off+data.len())` of `image`, fail-closed if it would run past the end.
fn write_at(
    image: &mut [u8],
    off: usize,
    data: &[u8],
    what: &'static str,
    image_len: usize,
) -> Result<(), Error> {
    image
        .get_mut(off..off + data.len())
        .ok_or(Error::OutOfBounds {
            what,
            offset: off as u64,
            len: data.len(),
            image_len,
        })?
        .copy_from_slice(data);
    Ok(())
}

/// Write `file`'s bytes back over its physical `extents` (the inverse of `read_extent_data`).
fn write_extents(
    image: &mut [u8],
    extents: &[(u64, u16)],
    file: &[u8],
    block_size: u64,
) -> Result<(), Error> {
    let image_len = image.len();
    let mut off = 0usize;
    for &(phys, len) in extents {
        if off >= file.len() {
            break;
        }
        let span = (len as usize * block_size as usize).min(file.len() - off);
        let dst_start = (phys * block_size) as usize;
        write_at(
            image,
            dst_start,
            &file[off..off + span],
            "ldlinux_writeback",
            image_len,
        )?;
        off += span;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_file_rejects_garbage_and_truncated_images() {
                                                                            
        let err = read_file(&[0u8; 4096], "etc/passwd").unwrap_err();
        assert!(matches!(err, Error::NotExt4 { found: 0 }), "got {err:?}");
                                                                             
        let err = read_file(&[0u8; 512], "etc/passwd").unwrap_err();
        assert!(
            matches!(
                err,
                Error::OutOfBounds {
                    what: "superblock",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn read_file_reads_the_staged_pubkey_from_a_real_bake() {
        use std::io::Read as _;
                                                                                              
                                                                                                   
                                                                                                 
                                                                                                  
        let gz = include_bytes!("../tests/fixtures/persist-skeleton-16m.img.gz");
        let mut img = Vec::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_end(&mut img)
            .expect("fixture gunzips");
        let key = read_file(&img, "etc/ssh/authorized_keys.d/root").expect("staged key reads");
        assert_eq!(key, b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8lxt94RGN2sG/6ECF1NEO49z1nsPu61qOPl0dQ4HGJ restore-fixture@test\n");
                                                      
        assert!(read_file(&img, "etc/ssh/authorized_keys.d/nope").is_err());
    }

    #[test]
    fn prepare_pads_to_512_multiple_and_appends_adv() {
        let core = vec![0xAAu8; 1000];
        let ondisk = prepare_ldlinux_sys(&core);
        assert_eq!(
            ondisk.len(),
            1024 + ADV_SIZE,
            "pad 1000→1024 + 2-sector ADV"
        );
        assert_eq!(&ondisk[..1000], &core[..], "core bytes preserved");
        assert!(
            ondisk[1000..1024].iter().all(|&b| b == 0),
            "zero-padded to the 512 boundary"
        );
                                                                 
        assert_eq!(
            u32::from_le_bytes(ondisk[1024..1028].try_into().unwrap()),
            0x5a2d_2fa5
        );
        assert_eq!(
            u32::from_le_bytes(ondisk[1536..1540].try_into().unwrap()),
            0x5a2d_2fa5
        );
                                                     
        assert_eq!(
            u32::from_le_bytes(ondisk[1532..1536].try_into().unwrap()),
            0xdd28_bf64
        );
    }

    #[test]
    fn prepare_does_not_overpad_an_exact_multiple() {
        let core = vec![0u8; 1024];
        let ondisk = prepare_ldlinux_sys(&core);
        assert_eq!(
            ondisk.len(),
            1024 + ADV_SIZE,
            "already 512-aligned ⇒ no extra pad"
        );
    }

    #[test]
    fn install_rejects_a_wrong_length_vbr() {
        let mut image = vec![0u8; 4096];
        let geo = Geometry {
            heads: 64,
            sectors: 32,
            hidden: 2048,
            total_sectors: 8,
        };
        assert!(matches!(
            install_into_bootfs(&mut image, &[0u8; 511], "/slot-a", &geo),
            Err(Error::VbrLength { found: 511 })
        ));
    }

    #[test]
    fn install_rejects_a_non_ext4_image() {
        let mut image = vec![0u8; 4096];                              
        let geo = Geometry {
            heads: 64,
            sectors: 32,
            hidden: 2048,
            total_sectors: 8,
        };
        assert!(matches!(
            install_into_bootfs(&mut image, &[0u8; 512], "/slot-a", &geo),
            Err(Error::NotExt4 { .. })
        ));
    }
}
