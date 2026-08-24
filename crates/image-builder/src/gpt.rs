//! Pure-Rust GPT serializer for the §9.5 UEFI signed-USB installer (Task 4.1).
//!
//! The box's on-disk GPT is serialized init-side by `initramfs_init::installer::build_gpt` (a fixed
//! 4-partition *target-disk* layout: boot + slot A + slot B + persist). The installer **USB** needs a
//! DIFFERENT 2-partition layout — a FAT16 ESP (the installer rambutan loader + the shared signed kernel
//! + the shared initramfs) followed by an ext4 data partition (`box.img` + its `.layout.toml`) — so this
//! is a SIBLING serializer, not shared code. Only the on-disk ENCODING convention is shared: mixed-endian
//! GUIDs, reflected CRC-32, the 92-byte header, the protective MBR, and the mirrored backup. That
//! convention is ported here byte-for-byte so a future audit can diff the two against the reference.
//!
//! **Why a 2nd serializer (the Phase-4 fork → Option A):** the plan's "serializes mixed-endian GUID
//! bytes" golden needs HOST-TESTABLE bytes — `sgdisk` (the existing USB-GPT path in `install-usb.sh` /
//! `dryrun.rs`) can't be unit-golden'd and already carries a "no automated guard" gap. The USB layout
//! differs from the target-disk layout, so the two serializers share no code, only the convention.
//! image-builder can't cleanly depend on the `panic = "abort"` `initramfs-init` workspace (it's vendored
//! as a binary, not source). The whole USB `.img` isn't byte-reproducible anyway (the signed loader PE
//! carries a per-sign `signingTime`), so `sgdisk` gains nothing. Reversible to `sgdisk` if a future
//! audit prefers it.
//!
//! image-builder is host-side (it may use `std`), but the encoding is kept allocation-light + table-free
//! to mirror the audited reference exactly.

/// EFI System Partition type GUID (UEFI 2.10 Table 5-7) — the USB ESP's PARTITION TYPE. DUPLICATED from
/// `initramfs_init::installer::ESP_TYPE_GUID`; a 2-line type-GUID literal does not justify a shared
/// crate across the `panic = "abort"` workspace boundary.
pub const ESP_TYPE_GUID: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
/// Linux filesystem-data type GUID — the USB ext4 data partition's PARTITION TYPE. DUPLICATED from
/// `initramfs_init::installer::LINUX_FS_TYPE_GUID`.
pub const LINUX_FS_TYPE_GUID: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
/// The installer USB disk's GUID (the GPT header `disk_guid` field). A fixed constant so the table is
/// byte-reproducible; distinct from `initramfs_init::installer::DISK_GUID` (the target-disk's GUID) and
/// from every PARTUUID. Generated once as a random v4 UUID; carries no operator secret.
pub const USB_DISK_GUID: &str = "7d3b1e9a-2c4f-4a6b-9e8d-1f5a3c7b2d04";

const SECTOR_SIZE: usize = 512;
/// GPT geometry (UEFI 2.10 §5.3): 128 entries × 128 bytes, a 92-byte header, first usable LBA at 34
/// (LBA0 protective MBR + LBA1 header + 32 entry-array sectors).
const GPT_NUM_ENTRIES: u32 = 128;
const GPT_ENTRY_SIZE: usize = 128;
const GPT_HEADER_BYTES: usize = 92;
const GPT_FIRST_USABLE_LBA: u64 = 34;
/// The tail reserved region: 32 entry sectors + 1 backup-header sector. `pub` so the USB assembler
/// ([`crate::installer_usb`]) can size the disk to leave exactly this room for the backup GPT.
pub const GPT_BACKUP_SECTORS: u64 = 33;

/// One GPT partition in the USB layout: its on-disk type + unique GUIDs (canonical `8-4-4-4-12` strings)
/// and its extent in 512-byte sectors. The serialized `last_lba` is computed inclusive
/// (`start_lba + sector_count - 1`).
#[derive(Debug, Clone)]
pub struct GptPartition {
    pub type_guid: &'static str,
    pub unique_guid: &'static str,
    pub start_lba: u64,
    pub sector_count: u64,
}

/// A serialized GPT, split into the two regions that land at different disk offsets. `primary` is the
/// front region (LBA0 protective MBR + LBA1 header + the 32-sector entry array = 34 sectors, written at
/// LBA0); `backup` is the tail region (the 32-sector entry array + the backup header = 33 sectors),
/// written at `backup_lba`. The caller (`build_installer_usb`, Task 5.1) splices both into the USB `.img`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptImage {
    pub primary: Vec<u8>,
    pub backup: Vec<u8>,
    pub backup_lba: u64,
}

/// Fail-closed: never emit a corrupt or geometry-invalid partition table.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GptError {
    #[error("malformed GUID {0:?}")]
    MalformedGuid(String),
    #[error("too many partitions: {0} (the GPT entry array holds 128)")]
    TooManyPartitions(usize),
    #[error("disk too small for a GPT: {0} sectors (need >= 68)")]
    DiskTooSmall(u64),
    #[error("partition {index} out of bounds: last_lba {last_lba} > last_usable {last_usable}")]
    PartitionOutOfBounds {
        index: usize,
        last_lba: u64,
        last_usable: u64,
    },
}

/// Encode a canonical `8-4-4-4-12` GUID string to its 16-byte GPT on-disk (mixed-endian) form: the first
/// three fields are little-endian, the trailing 2+6 bytes big-endian (UEFI 2.10 §5.3.1). Hex digits may
/// be upper- or lower-case. Whitelist the shape; any malformed input — wrong group count/lengths or a
/// non-hex digit — returns `None` (fail closed: never write a garbage GUID into a partition table).
pub fn guid_to_mixed_endian(s: &str) -> Option<[u8; 16]> {
    let groups: Vec<&str> = s.split('-').collect();
    if groups.len() != 5
        || [8, 4, 4, 4, 12]
            != [
                groups[0].len(),
                groups[1].len(),
                groups[2].len(),
                groups[3].len(),
                groups[4].len(),
            ]
    {
        return None;
    }
                                                                                                         
    let joined: String = groups.concat();
    let mut raw = [0u8; 16];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = u8::from_str_radix(&joined[i * 2..i * 2 + 2], 16).ok()?;
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);                       
    out[4..6].copy_from_slice(&[raw[5], raw[4]]);                       
    out[6..8].copy_from_slice(&[raw[7], raw[6]]);                       
    out[8..16].copy_from_slice(&raw[8..16]);                                            
    Some(out)
}

/// Reflected CRC-32 (IEEE 802.3 polynomial `0xEDB88320`) — the checksum GPT headers + entry arrays carry
/// (UEFI 2.10 §5.3.1/§5.3.2). Bitwise / table-free, mirroring the audited reference exactly.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();                                            
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Validate a GPT header's `header_crc32` (the field at offset 16): recompute over the 92-byte header
/// with that field zeroed and compare. `false` for a short slice (fail closed).
pub fn gpt_header_crc_valid(header: &[u8]) -> bool {
    if header.len() < GPT_HEADER_BYTES {
        return false;
    }
    let stored = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let mut h = header[..GPT_HEADER_BYTES].to_vec();
    h[16..20].copy_from_slice(&[0, 0, 0, 0]);
    crc32(&h) == stored
}

/// Serialize the GPT (protective MBR + primary header + 128-entry array + the mirrored backup) for the
/// `partitions` on a `disk_sectors`-sector USB disk. Pure + host-tested; the raw block writes are the
/// caller's. With all-constant GUIDs the output is byte-reproducible. Fails closed on a malformed GUID,
/// too many partitions, a too-small disk, or a partition that runs past the last usable LBA.
pub fn build_usb_gpt(
    partitions: &[GptPartition],
    disk_sectors: u64,
    disk_guid: &str,
) -> Result<GptImage, GptError> {
    if partitions.len() > GPT_NUM_ENTRIES as usize {
        return Err(GptError::TooManyPartitions(partitions.len()));
    }
                                                                                                    
                                                                                                  
    if disk_sectors < GPT_FIRST_USABLE_LBA + GPT_BACKUP_SECTORS + 1 {
        return Err(GptError::DiskTooSmall(disk_sectors));
    }
    let last_usable = disk_sectors - GPT_FIRST_USABLE_LBA;                       
    let backup_header_lba = disk_sectors - 1;
    let backup_entries_lba = disk_sectors - GPT_BACKUP_SECTORS;                                             

    let mixed =
        |g: &str| guid_to_mixed_endian(g).ok_or_else(|| GptError::MalformedGuid(g.to_string()));

                                                                                             
    let mut entries = vec![0u8; GPT_NUM_ENTRIES as usize * GPT_ENTRY_SIZE];
    for (idx, p) in partitions.iter().enumerate() {
        if p.sector_count == 0 {
            return Err(GptError::PartitionOutOfBounds {
                index: idx,
                last_lba: p.start_lba,
                last_usable,
            });
        }
        let last_lba = p.start_lba + p.sector_count - 1;             
        if p.start_lba < GPT_FIRST_USABLE_LBA || last_lba > last_usable {
            return Err(GptError::PartitionOutOfBounds {
                index: idx,
                last_lba,
                last_usable,
            });
        }
        let off = idx * GPT_ENTRY_SIZE;
        entries[off..off + 16].copy_from_slice(&mixed(p.type_guid)?);
        entries[off + 16..off + 32].copy_from_slice(&mixed(p.unique_guid)?);
        entries[off + 32..off + 40].copy_from_slice(&p.start_lba.to_le_bytes());
        entries[off + 40..off + 48].copy_from_slice(&last_lba.to_le_bytes());
                                                                                                            
    }
    let entries_crc = crc32(&entries);
    let disk_guid_bytes = mixed(disk_guid)?;

                                                                                                 
    let header = |my_lba: u64, alt_lba: u64, entry_lba: u64| -> [u8; GPT_HEADER_BYTES] {
        let mut h = [0u8; GPT_HEADER_BYTES];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);                
        h[12..16].copy_from_slice(&(GPT_HEADER_BYTES as u32).to_le_bytes());
                                                                        
        h[24..32].copy_from_slice(&my_lba.to_le_bytes());
        h[32..40].copy_from_slice(&alt_lba.to_le_bytes());
        h[40..48].copy_from_slice(&GPT_FIRST_USABLE_LBA.to_le_bytes());
        h[48..56].copy_from_slice(&last_usable.to_le_bytes());
        h[56..72].copy_from_slice(&disk_guid_bytes);
        h[72..80].copy_from_slice(&entry_lba.to_le_bytes());
        h[80..84].copy_from_slice(&GPT_NUM_ENTRIES.to_le_bytes());
        h[84..88].copy_from_slice(&(GPT_ENTRY_SIZE as u32).to_le_bytes());
        h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let crc = crc32(&h);                                                                      
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    let primary_header = header(1, backup_header_lba, 2);
    let backup_header = header(backup_header_lba, 1, backup_entries_lba);

                                                                                            
    let mut pmbr = [0u8; SECTOR_SIZE];
    pmbr[447..450].copy_from_slice(&[0x00, 0x02, 0x00]);                        
    pmbr[450] = 0xEE;                       
    pmbr[451..454].copy_from_slice(&[0xFF, 0xFF, 0xFF]);                    
    pmbr[454..458].copy_from_slice(&1u32.to_le_bytes());                    
                                                                                                                                                           
    let pmbr_size = u32::try_from(disk_sectors - 1).unwrap_or(u32::MAX);
    pmbr[458..462].copy_from_slice(&pmbr_size.to_le_bytes());
    pmbr[510] = 0x55;
    pmbr[511] = 0xAA;

                                     
    let mut primary = vec![0u8; 34 * SECTOR_SIZE];                                             
    primary[0..SECTOR_SIZE].copy_from_slice(&pmbr);
    primary[SECTOR_SIZE..SECTOR_SIZE + GPT_HEADER_BYTES].copy_from_slice(&primary_header);
    primary[2 * SECTOR_SIZE..2 * SECTOR_SIZE + entries.len()].copy_from_slice(&entries);

    let mut backup = vec![0u8; GPT_BACKUP_SECTORS as usize * SECTOR_SIZE];                              
    backup[0..entries.len()].copy_from_slice(&entries);
    backup[32 * SECTOR_SIZE..32 * SECTOR_SIZE + GPT_HEADER_BYTES].copy_from_slice(&backup_header);

    Ok(GptImage {
        primary,
        backup,
        backup_lba: backup_entries_lba,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_fs::{INSTALLER_DATA_PARTUUID, INSTALLER_ESP_PARTUUID};

                                                                                                         
                                                                                
    const DISK_SECTORS: u64 = 100_000;
    const ESP_START: u64 = 2048;
    const ESP_SECTORS: u64 = 40_960;          
    const DATA_START: u64 = 43_008;                           
    const DATA_SECTORS: u64 = 51_200;          

    fn usb_fixture() -> Vec<GptPartition> {
        vec![
            GptPartition {
                type_guid: ESP_TYPE_GUID,
                unique_guid: INSTALLER_ESP_PARTUUID,
                start_lba: ESP_START,
                sector_count: ESP_SECTORS,
            },
            GptPartition {
                type_guid: LINUX_FS_TYPE_GUID,
                unique_guid: INSTALLER_DATA_PARTUUID,
                start_lba: DATA_START,
                sector_count: DATA_SECTORS,
            },
        ]
    }

    fn le64(s: &[u8]) -> u64 {
        u64::from_le_bytes(s.try_into().unwrap())
    }
    fn le32(s: &[u8]) -> u32 {
        u32::from_le_bytes(s.try_into().unwrap())
    }

    #[test]
    fn guid_to_mixed_endian_matches_known_esp_vector() {
                                                                                                
        let expected = [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B,
        ];
        assert_eq!(guid_to_mixed_endian(ESP_TYPE_GUID).unwrap(), expected);
    }

    #[test]
    fn guid_to_mixed_endian_rejects_malformed() {
        assert_eq!(guid_to_mixed_endian("not-a-guid"), None);
        assert_eq!(
            guid_to_mixed_endian("C12A7328F81F11D2BA4B00A0C93EC93B"),
            None
        );             
        assert_eq!(
            guid_to_mixed_endian("C12A7328-F81F-11D2-BA4B-00A0C93EC93"),
            None
        );              
        assert_eq!(
            guid_to_mixed_endian("g12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
            None
        );           
    }

    #[test]
    fn crc32_matches_iso_hdlc_check_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn build_usb_gpt_golden() {
        let g = build_usb_gpt(&usb_fixture(), DISK_SECTORS, USB_DISK_GUID).unwrap();
        let sec = SECTOR_SIZE;
        assert_eq!(g.primary.len(), 34 * sec);
        assert_eq!(g.backup.len(), 33 * sec);
        assert_eq!(g.backup_lba, DISK_SECTORS - 33);

                                      
        assert_eq!(g.primary[450], 0xEE, "pMBR partition type = GPT protective");
        assert_eq!(&g.primary[510..512], &[0x55, 0xAA], "pMBR boot signature");
        assert_eq!(le32(&g.primary[454..458]), 1, "pMBR start LBA = 1");
        assert_eq!(
            le32(&g.primary[458..462]),
            (DISK_SECTORS - 1) as u32,
            "pMBR size LBA"
        );

                                      
        let h = &g.primary[sec..sec + 92];
        assert_eq!(&h[0..8], b"EFI PART");
        assert_eq!(le64(&h[24..32]), 1, "my_lba");
        assert_eq!(
            le64(&h[32..40]),
            DISK_SECTORS - 1,
            "alt (backup header) lba"
        );
        assert_eq!(le64(&h[40..48]), 34, "first usable lba");
        assert_eq!(le64(&h[48..56]), DISK_SECTORS - 34, "last usable lba");
        assert_eq!(le64(&h[72..80]), 2, "entry array lba");
        assert_eq!(le32(&h[80..84]), 128, "num entries");
        assert_eq!(le32(&h[84..88]), 128, "entry size");
        assert!(
            gpt_header_crc_valid(h),
            "primary header CRC self-consistent"
        );

                                                                                                
        let entries = &g.primary[2 * sec..2 * sec + 128 * 128];
        assert_eq!(
            le32(&h[88..92]),
            crc32(entries),
            "header's partition-entries CRC"
        );

                        
        assert_eq!(
            &entries[0..16],
            &guid_to_mixed_endian(ESP_TYPE_GUID).unwrap()
        );
        assert_eq!(
            &entries[16..32],
            &guid_to_mixed_endian(INSTALLER_ESP_PARTUUID).unwrap()
        );
        assert_eq!(le64(&entries[32..40]), ESP_START);
        assert_eq!(le64(&entries[40..48]), ESP_START + ESP_SECTORS - 1);

                              
        assert_eq!(
            &entries[128..144],
            &guid_to_mixed_endian(LINUX_FS_TYPE_GUID).unwrap()
        );
        assert_eq!(
            &entries[144..160],
            &guid_to_mixed_endian(INSTALLER_DATA_PARTUUID).unwrap()
        );
        assert_eq!(le64(&entries[160..168]), DATA_START);
        assert_eq!(le64(&entries[168..176]), DATA_START + DATA_SECTORS - 1);

                                    
        assert!(
            entries[256..384].iter().all(|&b| b == 0),
            "unused entry is zeroed"
        );

                                                                                     
        assert_eq!(
            &g.backup[0..16],
            &entries[0..16],
            "backup mirrors the entry array"
        );
        let bh = &g.backup[32 * sec..32 * sec + 92];
        assert_eq!(&bh[0..8], b"EFI PART");
        assert_eq!(
            le64(&bh[24..32]),
            DISK_SECTORS - 1,
            "backup my_lba = backup header lba"
        );
        assert_eq!(le64(&bh[32..40]), 1, "backup alt = primary header lba");
        assert_eq!(
            le64(&bh[72..80]),
            DISK_SECTORS - 33,
            "backup entry array lba"
        );
        assert!(
            gpt_header_crc_valid(bh),
            "backup header CRC self-consistent"
        );
    }

    #[test]
    fn build_usb_gpt_rejects_malformed_guid() {
        let parts = vec![GptPartition {
            type_guid: "nope",
            unique_guid: INSTALLER_ESP_PARTUUID,
            start_lba: 2048,
            sector_count: 4096,
        }];
        assert!(matches!(
            build_usb_gpt(&parts, DISK_SECTORS, USB_DISK_GUID),
            Err(GptError::MalformedGuid(_))
        ));
    }

    #[test]
    fn build_usb_gpt_rejects_partition_past_last_usable() {
        let parts = vec![GptPartition {
            type_guid: ESP_TYPE_GUID,
            unique_guid: INSTALLER_ESP_PARTUUID,
            start_lba: 2048,
            sector_count: DISK_SECTORS,                                 
        }];
        assert!(matches!(
            build_usb_gpt(&parts, DISK_SECTORS, USB_DISK_GUID),
            Err(GptError::PartitionOutOfBounds { .. })
        ));
    }

    #[test]
    fn build_usb_gpt_rejects_tiny_disk() {
        assert!(matches!(
            build_usb_gpt(&usb_fixture(), 10, USB_DISK_GUID),
            Err(GptError::DiskTooSmall(10))
        ));
    }

    #[test]
    fn build_usb_gpt_rejects_malformed_disk_guid() {
        assert!(matches!(
            build_usb_gpt(&usb_fixture(), DISK_SECTORS, "nope"),
            Err(GptError::MalformedGuid(_))
        ));
    }
}
