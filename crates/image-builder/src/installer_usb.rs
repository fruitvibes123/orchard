//! §9.5 UEFI signed-USB installer: assemble the installer USB `.img` (Task 5.1).
//!
//! Two-stage by concern:
//! - [`assemble_usb_image`] (this commit, pure + host-tested) — given the two BAKED partition images
//!   (the FAT16 ESP from `bake_esp`, the ext4 data partition holding `box.img`+layout), lay them out on a
//!   GPT disk: p1 ESP at the 1 MiB boundary, p2 ext4 1 MiB-aligned after it, the [`crate::gpt`] serializer
//!   stamping the two fixed installer PARTUUIDs, and the protective MBR + primary/backup GPT spliced in.
//! - `build_installer_usb` (Task 5.1b, follows) — the orchestrator that PRODUCES those two images:
//!   `installer_image_sha256_hex` → recompute the box.img root hash from the verified rootfs slice →
//!   `render_installer_cmdline` → a 2nd `build_efi_loader` (installer cmdline baked) → `bake_esp` (p1) →
//!   `bake_installer_data` (p2 ext4) → `assemble_usb_image`. The container ops ride the `BuildTools` seam.
//!
//! The whole USB `.img` is NOT byte-reproducible (the signed installer-loader PE inside the ESP carries a
//! per-sign `signingTime`), so there is no repro gate over it — the digest seam is `fb.image-sha256` over
//! the box.img, checked install-side (M-2).

use crate::boot_fs::{
    installer_image_sha256_hex, render_installer_cmdline, INSTALLER_DATA_PARTUUID,
    INSTALLER_ESP_PARTUUID,
};
use crate::build::{BuildError, BuildTools};
use crate::gpt::{
    build_usb_gpt, GptError, GptPartition, ESP_TYPE_GUID, GPT_BACKUP_SECTORS, LINUX_FS_TYPE_GUID,
    USB_DISK_GUID,
};

const SECTOR: usize = 512;
/// 1 MiB partition alignment in 512-byte sectors (LBA 2048) — the modern-disk default the existing USB
/// path uses (`dryrun.rs::assemble_manual_usb_disk`).
const ALIGN_LBA: u64 = 2048;

/// The byte offset of the p1 ESP within the assembled USB image — p1 always begins at LBA
/// [`ALIGN_LBA`] (the 1 MiB boundary). `deploy sign-installer-usb` (Task 5.3) splices the db-signed
/// installer loader into the ESP at this fixed offset; it is the single source shared with
/// [`assemble_usb_image`]'s p1 placement so the splice target can never drift from the layout.
pub const ESP_PARTITION_OFFSET: u64 = ALIGN_LBA * SECTOR as u64;

/// The assembled installer USB disk image, ready to `dd` onto a stick (and to sign — the installer loader
/// PE inside p1's ESP is db-signed + re-spliced by `sign-installer-usb`, Task 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerUsbImage {
    pub img: Vec<u8>,
}

/// Fail-closed assembly errors.
#[derive(Debug, thiserror::Error)]
pub enum InstallerUsbError {
    #[error("the {part} image is {len} bytes, not a multiple of the {SECTOR}-byte sector size")]
    NotSectorAligned { part: &'static str, len: usize },
    #[error("USB GPT: {0}")]
    Gpt(#[from] GptError),
}

/// Lay the two baked partition images onto a GPT disk: p1 = the FAT16 ESP at LBA 2048, p2 = the ext4 data
/// partition 1 MiB-aligned after p1; a protective MBR + primary GPT at the front and the mirrored backup
/// GPT at the tail (sized to leave exactly [`GPT_BACKUP_SECTORS`]). The two fixed installer PARTUUIDs are
/// stamped onto the entries (ESP→`INSTALLER_ESP_PARTUUID`, data→`INSTALLER_DATA_PARTUUID`) so the init
/// resolves the data partition by GUID. Both inputs MUST be 512-byte-sector multiples (the bakes always
/// are; a non-multiple fails closed). Pure — host-tested; the byte-write to the stick is the caller's.
pub fn assemble_usb_image(esp: &[u8], data: &[u8]) -> Result<InstallerUsbImage, InstallerUsbError> {
    if !esp.len().is_multiple_of(SECTOR) {
        return Err(InstallerUsbError::NotSectorAligned {
            part: "esp",
            len: esp.len(),
        });
    }
    if !data.len().is_multiple_of(SECTOR) {
        return Err(InstallerUsbError::NotSectorAligned {
            part: "data",
            len: data.len(),
        });
    }
    let esp_sectors = (esp.len() / SECTOR) as u64;
    let data_sectors = (data.len() / SECTOR) as u64;

    let p1_start = ALIGN_LBA;                                           
    let p2_start = align_up(p1_start + esp_sectors, ALIGN_LBA);                                   
                                                                                                                                                                 
                                                                                                                                                                  
    let disk_sectors = align_up(p2_start + data_sectors + GPT_BACKUP_SECTORS, ALIGN_LBA);

    let parts = [
        GptPartition {
            type_guid: ESP_TYPE_GUID,
            unique_guid: INSTALLER_ESP_PARTUUID,
            start_lba: p1_start,
            sector_count: esp_sectors,
        },
        GptPartition {
            type_guid: LINUX_FS_TYPE_GUID,
            unique_guid: INSTALLER_DATA_PARTUUID,
            start_lba: p2_start,
            sector_count: data_sectors,
        },
    ];
    let gpt = build_usb_gpt(&parts, disk_sectors, USB_DISK_GUID)?;

    let mut img = vec![0u8; disk_sectors as usize * SECTOR];
    img[0..gpt.primary.len()].copy_from_slice(&gpt.primary);
    let p1_off = p1_start as usize * SECTOR;
    img[p1_off..p1_off + esp.len()].copy_from_slice(esp);
    let p2_off = p2_start as usize * SECTOR;
    img[p2_off..p2_off + data.len()].copy_from_slice(data);
    let backup_off = gpt.backup_lba as usize * SECTOR;
    img[backup_off..backup_off + gpt.backup.len()].copy_from_slice(&gpt.backup);

    Ok(InstallerUsbImage { img })
}

/// Round `lba` UP to the next multiple of `align` (both in 512-byte sectors).
fn align_up(lba: u64, align: u64) -> u64 {
    lba.div_ceil(align) * align
}

/// The inputs to [`build_installer_usb`] — grouped so the orchestrator stays a 2-arg call (a flat list
/// trips `clippy::too_many_arguments`). The CLI (`deploy build-installer-usb`, Task 5.2) fills these from
/// the `--from` signed runtime `.img` + its sibling sidecars.
pub struct InstallerUsbInputs<'a> {
    /// The signed runtime `box.img` — the p2 payload AND the `fb.image-sha256` digest source.
    pub signed_img: &'a [u8],
    /// The `box.layout.toml` sibling, staged verbatim into p2 at `/box.layout.toml`.
    pub box_layout_toml: &'a [u8],
    /// The shared signed kernel + initramfs (the p1 ESP's `\vmlinuz` + `\initrd`) — the SAME bytes the
    /// runtime build emitted, so the installer boots the identical pair the loader's digest gates.
    pub vmlinuz: &'a [u8],
    pub initramfs: &'a [u8],
    /// The box.img's OWN verity root hash (recomputed by the CLI from the verified rootfs slice) — the
    /// installer cmdline's DEAD-WEIGHT verity pair (the installer never consumes it; baked for
    /// forward-safety per spec, never a placeholder/zero).
    pub root_hash: &'a str,
    pub verity_offset: u64,
    /// Optional `fb.install-to` whole-disk override; `None` ⇒ the init auto-selects the single eligible
    /// internal disk (fail-closed on 0/>1).
    pub install_to: Option<&'a str>,
    /// Bake `SB_REQUIRED` into the installer loader (the SB-on rung).
    pub sb_required: bool,
    pub source_date_epoch: u64,
}

/// Orchestrate the installer USB build: compute the `box.img` digest, render the installer cmdline, bake
/// it into a SECOND rambutan loader, bake the ESP (p1) + ext4 data (p2), then [`assemble_usb_image`] the
/// USB `.img`. The 2nd `build_efi_loader` call lives HERE (re-sequenced from plan Task 4.3 — it has no
/// home until there is a USB to put the loader in). Pure orchestration over the [`BuildTools`] seam
/// (fake-tested); the loader build + the two bakes are the gate-proven container ops.
pub fn build_installer_usb(
    tools: &impl BuildTools,
    inputs: &InstallerUsbInputs,
) -> Result<InstallerUsbImage, BuildError> {
                                                                                                        
                                                              
    let image_sha256 = installer_image_sha256_hex(inputs.signed_img);
    let cmdline = render_installer_cmdline(
        &image_sha256,
        inputs.root_hash,
        inputs.verity_offset,
        inputs.install_to,
    );
                                                                                                         
                                                                                                
    let initrd_sha256 = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(inputs.initramfs))
    };
                                                                                                      
                                                                                                      
    let loader = tools.build_efi_loader(
        &cmdline,
        &initrd_sha256,
        inputs.sb_required,
        inputs.source_date_epoch,
    )?;
                                                                                                     
                                                
    let esp = tools.bake_esp(
        &loader,
        inputs.vmlinuz,
        inputs.initramfs,
        inputs.source_date_epoch,
    )?;
                                                                                    
    let data = tools.bake_installer_data(
        inputs.signed_img,
        inputs.box_layout_toml,
        inputs.source_date_epoch,
    )?;
    assemble_usb_image(&esp, &data).map_err(|e| BuildError::Tool {
        tool: "assemble_usb_image",
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpt::guid_to_mixed_endian;

    fn le64(s: &[u8]) -> u64 {
        u64::from_le_bytes(s.try_into().unwrap())
    }

    #[test]
    fn assemble_usb_image_lays_out_gpt_esp_and_data() {
                                                                                                   
        let esp = vec![0xEEu8; 4096 * SECTOR];
        let data = vec![0xDDu8; 8192 * SECTOR];
        let usb = assemble_usb_image(&esp, &data).unwrap();

        let p1_start = ALIGN_LBA as usize;                  
        let p2_start = 6144usize;                                                        

                                                                                                 
        assert_eq!(usb.img.len() % (1024 * 1024), 0, "disk is 1 MiB-aligned");
        assert!(usb.img.len() >= (p2_start + 8192 + GPT_BACKUP_SECTORS as usize) * SECTOR);

                                                                             
        assert_eq!(
            &usb.img[p1_start * SECTOR..p1_start * SECTOR + esp.len()],
            &esp[..]
        );
        assert_eq!(
            &usb.img[p2_start * SECTOR..p2_start * SECTOR + data.len()],
            &data[..]
        );

                                               
        assert_eq!(usb.img[450], 0xEE, "pMBR GPT-protective type");
        assert_eq!(&usb.img[510..512], &[0x55, 0xAA]);
        assert_eq!(
            &usb.img[SECTOR..SECTOR + 8],
            b"EFI PART",
            "primary GPT header magic"
        );

                                                                                                                        
        let entries = &usb.img[2 * SECTOR..2 * SECTOR + 128 * 128];
        assert_eq!(
            &entries[0..16],
            &guid_to_mixed_endian(ESP_TYPE_GUID).unwrap()
        );
        assert_eq!(
            &entries[16..32],
            &guid_to_mixed_endian(INSTALLER_ESP_PARTUUID).unwrap()
        );
        assert_eq!(le64(&entries[32..40]), p1_start as u64);
        assert_eq!(le64(&entries[40..48]), (p1_start + 4096 - 1) as u64);
        assert_eq!(
            &entries[128..144],
            &guid_to_mixed_endian(LINUX_FS_TYPE_GUID).unwrap()
        );
        assert_eq!(
            &entries[144..160],
            &guid_to_mixed_endian(INSTALLER_DATA_PARTUUID).unwrap()
        );
        assert_eq!(le64(&entries[160..168]), p2_start as u64);
        assert_eq!(le64(&entries[168..176]), (p2_start + 8192 - 1) as u64);

                                                                                                      
        let backup_hdr_off = (usb.img.len() / SECTOR - 1) * SECTOR;
        assert_eq!(
            &usb.img[backup_hdr_off..backup_hdr_off + 8],
            b"EFI PART",
            "backup GPT header magic"
        );
    }

    #[test]
    fn assemble_usb_image_aligns_p2_when_esp_is_not_a_megabyte_multiple() {
                                                                                                           
        let esp = vec![0xEEu8; 3000 * SECTOR];                                     
        let data = vec![0xDDu8; 100 * SECTOR];
        let usb = assemble_usb_image(&esp, &data).unwrap();
                                                                               
        let entries = &usb.img[2 * SECTOR..2 * SECTOR + 128 * 128];
        assert_eq!(
            le64(&entries[160..168]),
            6144,
            "p2 is 1 MiB-aligned after a non-aligned ESP"
        );
                                                                                             
        assert_eq!(&usb.img[2048 * SECTOR..2048 * SECTOR + esp.len()], &esp[..]);
    }

    #[test]
    fn assemble_usb_image_rejects_unaligned_inputs() {
        let bad = vec![0u8; 4096 * SECTOR + 1];                         
        let ok = vec![0u8; 512 * SECTOR];
        assert!(matches!(
            assemble_usb_image(&bad, &ok),
            Err(InstallerUsbError::NotSectorAligned { part: "esp", .. })
        ));
        assert!(matches!(
            assemble_usb_image(&ok, &bad),
            Err(InstallerUsbError::NotSectorAligned { part: "data", .. })
        ));
    }

    #[test]
    fn esp_partition_offset_is_the_one_mib_p1_boundary() {
                                                                                                
                                                                                                     
        assert_eq!(ESP_PARTITION_OFFSET, 1024 * 1024);
        assert_eq!(ESP_PARTITION_OFFSET, ALIGN_LBA * SECTOR as u64);
    }
}
