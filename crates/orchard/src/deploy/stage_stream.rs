                                                                                                  
//! `deploy prod` ceremony uses to put the (sentinel-patched) `.img` onto a raw byte region at the
//! target-disk tail with O(chunk) operator RAM — the sentinel PRE-SCAN over the local file's boot
//! region, the chunk-boundary-safe patch substitution, and the chunked local file hash. The remote
//! `dd oflag=seek_bytes` spawn itself lives in `prod_process_ops` (the FFI half); these parts are
//! pure/host-tested.

use std::io::Read;
use std::path::Path;

use crate::deploy::prod::{INSTALL_COPY_CHUNK_BYTES, partition_device_name};
use crate::deploy::prod_orchestrate::LayoutInfo;
use recipes_image_builder::firmware::Firmware;

/// A fixed-width byte replacement at an absolute `.img` offset — the sentinel patch, computed
/// ONCE by [`sentinel_patch_spec`] and applied on the fly to each streamed chunk (the stream is
                                      
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchSpec {
    pub abs_offset: u64,
    pub bytes: Vec<u8>,
}

/// Locate the rootfs-dev sentinel in the LOCAL `.img`'s boot region (a bounded read of
/// `[boot_offset, boot_offset + boot_size)` — never the whole image) and return the absolute
/// patch: the slot-A device path (`partition_device_name(disk, 2)`) space-padded to the fixed
/// field width, exactly the bytes `prod::patch_rootfs_dev` would write. Semantics match that
/// sibling fail-closed: plain `Seabios` REQUIRES exactly one occurrence (absent or duplicated ⇒
/// `Err`); `SeabiosGpt` images are staged VERBATIM (no sentinel by construction) ⇒ `Ok(None)`.
pub fn sentinel_patch_spec(
    img: &Path,
    layout: &LayoutInfo,
    disk: &str,
) -> Result<Option<PatchSpec>, String> {
    use recipes_image_builder::boot_fs::{ROOTFS_DEV_FIELD_WIDTH, ROOTFS_DEV_SENTINEL};
    match layout.firmware {
        Firmware::SeabiosGpt => return Ok(None),
        Firmware::Seabios => {}
                                                                                     
        Firmware::Uefi => {
            return Err("sentinel pre-scan: uefi never reaches the kexec ceremony".into());
        }
    }
    let value = partition_device_name(disk, 2);
    if value.len() > ROOTFS_DEV_FIELD_WIDTH {
        return Err(format!(
            "rootfs-dev {value:?} is {} bytes, wider than the {ROOTFS_DEV_FIELD_WIDTH}-byte field",
            value.len()
        ));
    }
                                                                                         
    let mut f = std::fs::File::open(img).map_err(|e| format!("open {}: {e}", img.display()))?;
    use std::io::Seek;
    f.seek(std::io::SeekFrom::Start(layout.boot_offset))
        .map_err(|e| format!("seek boot region: {e}"))?;
    let boot_size = usize::try_from(layout.boot_size)
        .map_err(|_| "boot_size exceeds addressable memory".to_string())?;
    let mut boot = vec![0u8; boot_size];
    f.read_exact(&mut boot)
        .map_err(|e| format!("read boot region ({boot_size} bytes): {e}"))?;
    let sentinel = ROOTFS_DEV_SENTINEL.as_bytes();
    let positions: Vec<usize> = boot
        .windows(sentinel.len())
        .enumerate()
        .filter_map(|(i, w)| (w == sentinel).then_some(i))
        .collect();
    if positions.len() > 1 {
        return Err(format!(
            "rootfs-dev sentinel occurs {} times in the boot-fs (expected exactly one)",
            positions.len()
        ));
    }
    let start = *positions
        .first()
        .ok_or("rootfs-dev sentinel not found in the boot-fs")?;
    let mut bytes = vec![b' '; ROOTFS_DEV_FIELD_WIDTH];
    bytes[..value.len()].copy_from_slice(value.as_bytes());
    Ok(Some(PatchSpec {
        abs_offset: layout.boot_offset + start as u64,
        bytes,
    }))
}

/// Apply `patch` to the chunk covering `[chunk_abs_pos, chunk_abs_pos + chunk.len())` — pure
/// interval substitution that handles the fixed-width field STRADDLING two chunks (spec R1 I10:
/// each chunk applies only its intersection with the patch window; a straddled patch lands half
/// in each).
pub fn apply_patch_window(chunk: &mut [u8], chunk_abs_pos: u64, patch: &PatchSpec) {
    let p0 = patch.abs_offset;
    let p1 = p0 + patch.bytes.len() as u64;
    let c0 = chunk_abs_pos;
    let c1 = c0 + chunk.len() as u64;
    let lo = p0.max(c0);
    let hi = p1.min(c1);
    if lo >= hi {
        return;
    }
    chunk[(lo - c0) as usize..(hi - c0) as usize]
        .copy_from_slice(&patch.bytes[(lo - p0) as usize..(hi - p0) as usize]);
}

/// Chunked SHA-256 of a local file (replaces the Vec-based sidecar preflight hash — same
/// guarantee, O(chunk) RAM). Returns the raw 32-byte digest.
pub fn hash_file_chunked(path: &Path) -> Result<[u8; 32], String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; INSTALL_COPY_CHUNK_BYTES as usize];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use recipes_image_builder::boot_fs::{ROOTFS_DEV_FIELD_WIDTH, ROOTFS_DEV_SENTINEL};

    fn layout(firmware: Firmware, boot_offset: u64, boot_size: u64) -> LayoutInfo {
        LayoutInfo {
            boot_offset,
            boot_size,
            persist_skeleton_offset: boot_offset + boot_size,
            persist_skeleton_size: 512,
            rootfs_offset: boot_offset + boot_size + 512,
            rootfs_size: 1024,
            rootfs_verity_hash_offset: 512,
            firmware,
            weights_offset: None,
            weights_size: None,
        }
    }

    fn temp_img(bytes: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn sentinel_patch_spec_finds_the_planted_sentinel_absolutely() {
                                                                                            
                                                                                  
        let mut img = vec![0u8; 8192];
        img[4096 + 100..4096 + 100 + ROOTFS_DEV_SENTINEL.len()]
            .copy_from_slice(ROOTFS_DEV_SENTINEL.as_bytes());
        let f = temp_img(&img);
        let spec = sentinel_patch_spec(f.path(), &layout(Firmware::Seabios, 4096, 2048), "vda")
            .unwrap()
            .expect("seabios yields a patch");
        assert_eq!(spec.abs_offset, 4096 + 100);
        let mut expected = vec![b' '; ROOTFS_DEV_FIELD_WIDTH];
        expected[.."/dev/vda2".len()].copy_from_slice(b"/dev/vda2");
        assert_eq!(spec.bytes, expected);
                                                           
        let nvme = sentinel_patch_spec(f.path(), &layout(Firmware::Seabios, 4096, 2048), "nvme0n1")
            .unwrap()
            .unwrap();
        assert!(nvme.bytes.starts_with(b"/dev/nvme0n1p2"));
    }

    #[test]
    fn sentinel_patch_spec_fails_closed_on_absent_or_duplicate() {
                                                                        
        let img = vec![0u8; 8192];
        let f = temp_img(&img);
        assert!(
            sentinel_patch_spec(f.path(), &layout(Firmware::Seabios, 0, 4096), "vda")
                .unwrap_err()
                .contains("not found")
        );
                     
        let mut dup = vec![0u8; 8192];
        for at in [0usize, 512] {
            dup[at..at + ROOTFS_DEV_SENTINEL.len()].copy_from_slice(ROOTFS_DEV_SENTINEL.as_bytes());
        }
        let f2 = temp_img(&dup);
        assert!(
            sentinel_patch_spec(f2.path(), &layout(Firmware::Seabios, 0, 4096), "vda")
                .unwrap_err()
                .contains("2 times")
        );
    }

    #[test]
    fn sentinel_patch_spec_gpt_is_verbatim_none() {
                                                                                                   
        let f = temp_img(&[0u8; 512]);
        assert_eq!(
            sentinel_patch_spec(f.path(), &layout(Firmware::SeabiosGpt, 0, 512), "vda").unwrap(),
            None
        );
    }

    #[test]
    fn apply_patch_window_handles_inside_straddle_and_outside() {
        let patch = PatchSpec {
            abs_offset: 1000,
            bytes: b"REPLACEMENT!".to_vec(),                             
        };
                                  
        let mut chunk = vec![0u8; 100];
        apply_patch_window(&mut chunk, 950, &patch);
        assert_eq!(&chunk[50..62], b"REPLACEMENT!");
                                                                                     
        let mut a = vec![0u8; 8];
        let mut b = vec![0u8; 100];
        apply_patch_window(&mut a, 996, &patch);
        apply_patch_window(&mut b, 1004, &patch);
        assert_eq!(&a[4..8], b"REPL");
        assert_eq!(&b[0..8], b"ACEMENT!");
                              
        let mut c = vec![0xEEu8; 64];
        apply_patch_window(&mut c, 5000, &patch);
        assert!(c.iter().all(|&x| x == 0xEE));
    }

    #[test]
    fn hash_file_chunked_equals_whole_file_sha() {
        use sha2::{Digest, Sha256};
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let f = temp_img(&data);
        let chunked = hash_file_chunked(f.path()).unwrap();
        let whole: [u8; 32] = Sha256::digest(&data).into();
        assert_eq!(chunked, whole);
    }
}
