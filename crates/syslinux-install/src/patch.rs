//! Port of syslinux 6.04-pre1 `libinstaller/syslxmod.c::syslinux_patch` + `generate_extents`
//! (+ the geometry poke from `extlinux/main.c::patch_file_and_bootblock`). Pure logic: given the
//! on-disk `ldlinux.sys` (boot_image) + the VBR (boot_sector) + the physical sector map `sectp[]`,
//! produce the patched bytes. No mount, no privilege. Offsets per `libinstaller/syslxint.h`.
//!
//! Authoritative against the PINNED `syslinux=6.04_pre1-r19` (Containerfile); the format is frozen for
//! that version (M-3). Every external-offset access is bounds-checked and fails closed — a malformed
//! template aborts the bake rather than panicking or writing garbage.

use crate::error::Error;
use crate::Geometry;

pub(crate) const LDLINUX_MAGIC: u32 = 0x3eb2_02fe;
const SECTOR_SIZE: u32 = 512;

                                                                                                    
const BS_BYTES_PER_SEC: usize = 11;
const BS_SECTORS: usize = 19;
const BS_SEC_PER_TRACK: usize = 24;
const BS_HEADS: usize = 26;
const BS_HIDDEN_SECS: usize = 28;
const BS_HUGE_SECTORS: usize = 32;

                                                              
const PA_DATA_SECTORS: usize = 8;
const PA_ADV_SECTORS: usize = 10;
const PA_DWORDS: usize = 12;
const PA_CHECKSUM: usize = 16;
const PA_EPAOFFSET: usize = 22;
                                                                            
const EPA_ADVPTROFFSET: usize = 0;
const EPA_DIROFFSET: usize = 2;
const EPA_DIRLEN: usize = 4;
const EPA_SECPTROFFSET: usize = 10;
const EPA_SECPTRCNT: usize = 12;
const EPA_SECT1PTR0: usize = 14;
const EPA_SECT1PTR1: usize = 16;

/// Checked little-endian reads/writes — a bad patch-area offset fails closed.
fn g16(b: &[u8], o: usize, what: &'static str) -> Result<u16, Error> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(Error::PatchAreaOutOfRange { what })
}
fn g32(b: &[u8], o: usize, what: &'static str) -> Result<u32, Error> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(Error::PatchAreaOutOfRange { what })
}
fn s16(b: &mut [u8], o: usize, v: u16, what: &'static str) -> Result<(), Error> {
    let s = b
        .get_mut(o..o + 2)
        .ok_or(Error::PatchAreaOutOfRange { what })?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn s32(b: &mut [u8], o: usize, v: u32, what: &'static str) -> Result<(), Error> {
    let s = b
        .get_mut(o..o + 4)
        .ok_or(Error::PatchAreaOutOfRange { what })?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn s64(b: &mut [u8], o: usize, v: u64, what: &'static str) -> Result<(), Error> {
    let s = b
        .get_mut(o..o + 8)
        .ok_or(Error::PatchAreaOutOfRange { what })?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// `generate_extents` (syslxmod.c): RLE-compress the sector list into `{lba:u64, len:u16}` runs,
/// breaking a run when the disk sector is non-contiguous, the run would exceed 64 KiB, or the load
/// address would cross a 64 KiB real-mode segment window. Returns the packed 10-byte-per-entry bytes.
fn generate_extents(sectp: &[u64]) -> Vec<u8> {
    let mut runs: Vec<(u64, u16)> = Vec::new();
    let mut addr: u32 = 0x8000;                            
    let mut base: u32 = addr;
    let mut lba: u64 = 0;
    let mut len: u32 = 0;
    for &sect in sectp {
        if len > 0 {
            let xbytes = (len + 1) * SECTOR_SIZE;
            if sect == lba + len as u64
                && xbytes < 65536
                && ((addr ^ (base + xbytes - 1)) & 0xffff_0000) == 0
            {
                len += 1;
                addr += SECTOR_SIZE;
                continue;
            }
            runs.push((lba, len as u16));
        }
        base = addr;
        lba = sect;
        len = 1;
        addr += SECTOR_SIZE;
    }
    if len > 0 {
        runs.push((lba, len as u16));
    }
    let mut out = Vec::with_capacity(runs.len() * 10);
    for (l, n) in runs {
        out.extend_from_slice(&l.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
    }
    out
}

/// Patch `boot_image` (ldlinux.sys) + `boot_sector` (VBR) in place for the given sector map.
/// `sectp` is the full physical-sector list of ldlinux.sys (length nsect, last 2 = ADV).
/// `boot_image_len` is the core length (excluding the 2-sector ADV). Returns the number of extent
/// runs written (for sanity logging). Fails closed on a malformed template or over-fragmentation.
pub(crate) fn syslinux_patch(
    boot_image: &mut [u8],
    boot_sector: &mut [u8],
    sectp: &[u64],
    subdir: &str,
    geo: &Geometry,
    boot_image_len: usize,
) -> Result<usize, Error> {
    let nsect = sectp.len();
    if nsect < 3 {
                                                             
        return Err(Error::OnDiskTooSmallForAdv {
            size: (nsect as u64) * 512,
        });
    }

                                                      
    s16(
        boot_sector,
        BS_BYTES_PER_SEC,
        SECTOR_SIZE as u16,
        "vbr.bytes_per_sec",
    )?;
    if geo.total_sectors >= 65536 {
        s16(boot_sector, BS_SECTORS, 0, "vbr.sectors")?;
    } else {
        s16(
            boot_sector,
            BS_SECTORS,
            geo.total_sectors as u16,
            "vbr.sectors",
        )?;
    }
    s32(
        boot_sector,
        BS_HUGE_SECTORS,
        geo.total_sectors as u32,
        "vbr.huge_sectors",
    )?;
    s16(
        boot_sector,
        BS_SEC_PER_TRACK,
        geo.sectors,
        "vbr.sec_per_track",
    )?;
    s16(boot_sector, BS_HEADS, geo.heads, "vbr.heads")?;
    s32(boot_sector, BS_HIDDEN_SECS, geo.hidden, "vbr.hidden_secs")?;

                                                               
    let pa = boot_image
        .windows(4)
        .position(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == LDLINUX_MAGIC)
        .ok_or(Error::LdlinuxMagicNotFound)?;
    let epa = g16(boot_image, pa + PA_EPAOFFSET, "epaoffset")? as usize;
    let advptroffset = g16(boot_image, epa + EPA_ADVPTROFFSET, "advptroffset")? as usize;
    let diroffset = g16(boot_image, epa + EPA_DIROFFSET, "diroffset")? as usize;
    let dirlen = g16(boot_image, epa + EPA_DIRLEN, "dirlen")? as usize;
    let secptroffset = g16(boot_image, epa + EPA_SECPTROFFSET, "secptroffset")? as usize;
    let secptrcnt = g16(boot_image, epa + EPA_SECPTRCNT, "secptrcnt")? as usize;
    let sect1ptr0 = g16(boot_image, epa + EPA_SECT1PTR0, "sect1ptr0")? as usize;
    let sect1ptr1 = g16(boot_image, epa + EPA_SECT1PTR1, "sect1ptr1")? as usize;

                                                                                                    
                                                                                                
    let dwords = (boot_image_len / 4) as u32;
    s32(boot_image, pa + PA_DWORDS, dwords, "pa.dwords")?;

                                              
    s32(boot_sector, sect1ptr0, sectp[0] as u32, "vbr.sect1ptr0")?;
    s32(
        boot_sector,
        sect1ptr1,
        (sectp[0] >> 32) as u32,
        "vbr.sect1ptr1",
    )?;

                     
    s16(
        boot_image,
        pa + PA_DATA_SECTORS,
        (nsect - 2) as u16,
        "pa.data_sectors",
    )?;
    s16(boot_image, pa + PA_ADV_SECTORS, 2, "pa.adv_sectors")?;

                                                                                                
    let slot_table_len = secptrcnt
        .checked_mul(10)
        .ok_or(Error::PatchAreaOutOfRange {
            what: "secptr_table",
        })?;
    let slot_table = boot_image
        .get_mut(secptroffset..secptroffset + slot_table_len)
        .ok_or(Error::PatchAreaOutOfRange {
            what: "secptr_table",
        })?;
    slot_table.iter_mut().for_each(|b| *b = 0);
    let ext_bytes = generate_extents(&sectp[1..nsect - 2]);
    if ext_bytes.len() > slot_table_len {
        return Err(Error::TooManyExtents {
            runs: ext_bytes.len() / 10,
            slots: secptrcnt,
        });
    }
    slot_table[..ext_bytes.len()].copy_from_slice(&ext_bytes);

                                                
    s64(boot_image, advptroffset, sectp[nsect - 2], "adv.ptr0")?;
    s64(boot_image, advptroffset + 8, sectp[nsect - 1], "adv.ptr1")?;

                                                                                                     
                                                                                                      
                                                                                                         
    let sub = subdir.as_bytes();
    if sub.len() >= dirlen {
        return Err(Error::SubdirTooLong {
            len: sub.len(),
            max: dirlen,
        });
    }
    let dst = boot_image
        .get_mut(diroffset..diroffset + sub.len() + 1)
        .ok_or(Error::PatchAreaOutOfRange { what: "subdir" })?;
    dst[..sub.len()].copy_from_slice(sub);
    dst[sub.len()] = 0;

                                                                                  
    s32(boot_image, pa + PA_CHECKSUM, 0, "pa.checksum")?;
    let checksum_region =
        boot_image
            .get(..(dwords as usize) * 4)
            .ok_or(Error::PatchAreaOutOfRange {
                what: "checksum_region",
            })?;
    let mut csum: u32 = LDLINUX_MAGIC;
    for chunk in checksum_region.chunks_exact(4) {
        csum = csum.wrapping_sub(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    s32(boot_image, pa + PA_CHECKSUM, csum, "pa.checksum")?;

                                                                                                  
                                                                                                     
    if !verify_checksum(boot_image) {
        return Err(Error::ChecksumSelfCheckFailed);
    }

    Ok(ext_bytes.len() / 10)
}

/// The bootloader's self-check: after patching, the sum of the first `dwords` 32-bit words of
/// ldlinux.sys must equal `LDLINUX_MAGIC` (the negative-checksum invariant). Returns true if it holds.
pub(crate) fn verify_checksum(boot_image: &[u8]) -> bool {
    let pa = match boot_image
        .windows(4)
        .position(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == LDLINUX_MAGIC)
    {
        Some(p) => p,
        None => return false,
    };
    let dwords = match g32(boot_image, pa + PA_DWORDS, "pa.dwords") {
        Ok(d) => d as usize,
        Err(_) => return false,
    };
    let region = match boot_image.get(..dwords * 4) {
        Some(r) => r,
        None => return false,
    };
    let mut sum: u32 = 0;
    for chunk in region.chunks_exact(4) {
        sum = sum.wrapping_add(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    sum == LDLINUX_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `generate_extents` RLE-compresses a contiguous run into a single `{lba,len}` entry.
    #[test]
    fn contiguous_sectors_compress_to_one_run() {
        let sectp: Vec<u64> = (1000..1010).collect();
        let out = generate_extents(&sectp);
        assert_eq!(out.len(), 10, "one run = 10 bytes");
        assert_eq!(u64::from_le_bytes(out[0..8].try_into().unwrap()), 1000);
        assert_eq!(u16::from_le_bytes(out[8..10].try_into().unwrap()), 10);
    }

    /// A discontinuity forces a new run.
    #[test]
    fn discontinuity_splits_runs() {
        let sectp = [10u64, 11, 12, 50, 51];
        let out = generate_extents(&sectp);
        assert_eq!(out.len(), 20, "two runs");
        assert_eq!(u64::from_le_bytes(out[0..8].try_into().unwrap()), 10);
        assert_eq!(u16::from_le_bytes(out[8..10].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(out[10..18].try_into().unwrap()), 50);
        assert_eq!(u16::from_le_bytes(out[18..20].try_into().unwrap()), 2);
    }

    /// Minimal synthetic patch inputs: an on-disk ldlinux.sys (4 core sectors + 2 ADV) with a
    /// `patch_area` @64 + `ext_patch_area` @512 (the given `dirlen`), a 512-byte VBR, geometry, and a
    /// 6-sector map (sectp[0]=VBR ptr, [1..4] data, [4..6] ADV). Returns `(core, vbr, geo, sectp,
    /// boot_image_len)`.
    fn synthetic_inputs(dirlen: u16) -> (Vec<u8>, Vec<u8>, Geometry, Vec<u64>, usize) {
        let boot_image_len = 2048usize;
        let mut core = vec![0u8; boot_image_len + 2 * 512];
        let (pa, epa) = (64usize, 512usize);
        core[pa..pa + 4].copy_from_slice(&LDLINUX_MAGIC.to_le_bytes());
        core[pa + PA_EPAOFFSET..pa + PA_EPAOFFSET + 2].copy_from_slice(&(epa as u16).to_le_bytes());
        let put16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        put16(&mut core, epa + EPA_ADVPTROFFSET, 800);
        put16(&mut core, epa + EPA_DIROFFSET, 900);
        put16(&mut core, epa + EPA_DIRLEN, dirlen);
        put16(&mut core, epa + EPA_SECPTROFFSET, 1024);
        put16(&mut core, epa + EPA_SECPTRCNT, 64);
        put16(&mut core, epa + EPA_SECT1PTR0, 0);                                             
        put16(&mut core, epa + EPA_SECT1PTR1, 4);
        let geo = Geometry {
            heads: 64,
            sectors: 32,
            hidden: 2048,
            total_sectors: 262144,
        };
                                                                                 
        let sectp = vec![5000u64, 5001, 5002, 5003, 5004, 5005];
        (core, vec![0u8; 512], geo, sectp, boot_image_len)
    }

    /// `verify_checksum` is true exactly when the dword-sum equals the magic — and `syslinux_patch`
    /// establishes that invariant.
    #[test]
    fn patch_then_checksum_self_check_holds() {
        let (mut core, mut vbr, geo, sectp, boot_image_len) = synthetic_inputs(64);
        let runs = syslinux_patch(&mut core, &mut vbr, &sectp, "/slot-a", &geo, boot_image_len)
            .expect("patch succeeds");
        assert_eq!(runs, 1, "the 3 contiguous data sectors compress to one run");
        assert!(
            verify_checksum(&core),
            "the negative-checksum invariant must hold after patching"
        );
                                                                   
        assert_eq!(
            u32::from_le_bytes(core[64 + PA_DWORDS..64 + PA_DWORDS + 4].try_into().unwrap()),
            512
        );
        assert_eq!(
            u16::from_le_bytes(vbr[BS_HEADS..BS_HEADS + 2].try_into().unwrap()),
            64
        );
        assert_eq!(
            u32::from_le_bytes(vbr[0..4].try_into().unwrap()),
            5000,
            "sect1ptr0 = sectp[0]"
        );
    }

    /// INFO-1 regression: a subdir longer than the core's dir field FAILS CLOSED (mirrors the C
    /// `exit(1)`), rather than silently skipping the poke → a stale/empty subdir → a wrong-path boot.
    #[test]
    fn subdir_too_long_fails_closed() {
        let (mut core, mut vbr, geo, sectp, boot_image_len) = synthetic_inputs(8);                  
        let err = syslinux_patch(
            &mut core,
            &mut vbr,
            &sectp,
            "/a-very-long-install-subdir",
            &geo,
            boot_image_len,
        )
        .expect_err("a subdir longer than the dir field must fail closed");
        assert!(matches!(err, Error::SubdirTooLong { .. }), "got {err:?}");
    }

    /// A buffer without the magic fails closed rather than panicking.
    #[test]
    fn missing_magic_is_an_error() {
        let mut core = vec![0u8; 4096];
        let mut vbr = vec![0u8; 512];
        let geo = Geometry {
            heads: 64,
            sectors: 32,
            hidden: 2048,
            total_sectors: 1024,
        };
        let sectp = vec![1u64, 2, 3, 4, 5];
        assert!(matches!(
            syslinux_patch(&mut core, &mut vbr, &sectp, "/slot-a", &geo, 1536),
            Err(Error::LdlinuxMagicNotFound)
        ));
    }
}
