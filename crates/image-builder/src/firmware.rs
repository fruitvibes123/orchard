                                                                                                   
//! `firmware` string is the wire contract between this builder and the on-box installer;
//! `initramfs_init::installer::Firmware` is the DUPLICATED reader half (a 2-variant enum does not
//! justify a shared crate, and initramfs-init is a standalone `panic=abort` workspace).
//!
//! SCOPE: the firmware-parameterized seam is implemented for BOTH branches. SeaBIOS is the production
//! default (Infomaniak is BIOS-only); UEFI builds a real GPT + FAT ESP + the hand-rolled rambutan
//! Secure Boot loader (the 2026-06-10 loader pivot — NOT a kernel-EFI-stub/UKI), OVMF-boot-proven. Only
//! the PRODUCTION SUBSTRATE (real UEFI hardware + PK/KEK/db enrollment) is deferred until one is adopted
                                                   

/// Which boot firmware the `.img` targets — selects the partition-table serializer (MBR vs GPT) and
/// the boot-partition type (ext4 boot-fs vs FAT ESP). Default is SeaBIOS (the production substrate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Firmware {
    /// Legacy BIOS / SeaBIOS — MBR + ext4 boot-fs + extlinux + the 440-byte `mbr.bin` stage-1.
    #[default]
    Seabios,
    /// Legacy BIOS booting from a GPT disk (the dha-hosting box; the BIOS+GPT installer arm). Reuses the
    /// SeaBIOS boot-fs bake (ext4 + extlinux) and the UEFI GPT partition table (`build_gpt`), with the
    /// boot partition's `legacy_boot` attribute + Linux-fs type GUID and `gptmbr.bin` as the stage-1.
    SeabiosGpt,
    /// UEFI — GPT + FAT ESP + the hand-rolled rambutan Secure Boot loader (OVMF-boot-proven). Only the
                                                                                                      
    Uefi,
}

impl Firmware {
    /// The `.layout.toml` wire token. Stable — `initramfs_init::installer::Firmware` parses it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seabios => "seabios",
            Self::SeabiosGpt => "seabios-gpt",
            Self::Uefi => "uefi",
        }
    }
}

impl std::str::FromStr for Firmware {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "seabios" => Ok(Self::Seabios),
            "seabios-gpt" => Ok(Self::SeabiosGpt),
            "uefi" => Ok(Self::Uefi),
            other => Err(format!(
                "unknown firmware {other:?} (expected seabios|seabios-gpt|uefi)"
            )),
        }
    }
}

/// C3: the DEPLOY SUBSTRATE — derived from [`Firmware`], selects the kernel-config substrate block
/// (`kernel-config-pins-{vpskvm,baremetal}.toml`) + the substrate hardening fragment. A KVM guest
/// (both BIOS firmwares) never boots off USB media, so it FORBIDS the USB host/storage stack; real
/// UEFI bare-metal boots off USB media, so it ASSERTS that stack. Deliberately USB-ONLY: the DISK
/// transports (SCSI/ATA/NVMe/virtio-scsi) stay on BOTH substrates so the box boots on any KVM
/// hypervisor's disk. Also the `.layout.toml` `substrate` line + the `--substrate` cross-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Substrate {
    /// KVM guest (Infomaniak + any hypervisor VPS) — the production substrate. Boots off its virtual
    /// disk (virtio-blk/scsi, NVMe, or emulated SATA — all kept); the USB host/storage drivers are
    /// forbidden as unused attack surface (a VPS has no USB boot media).
    VpsKvm,
    /// Real UEFI bare-metal — boots off USB media, so the USB host/storage stack is required (the disk
    /// transports it rides on are shared base config, present here too).
    BareMetalUefi,
}

impl Substrate {
    /// The one derivation: BIOS (SeaBIOS/SeaBIOS-GPT) ⇒ vps-kvm; UEFI ⇒ bare-metal-uefi.
    pub fn from_firmware(fw: Firmware) -> Self {
        match fw {
            Firmware::Seabios | Firmware::SeabiosGpt => Self::VpsKvm,
            Firmware::Uefi => Self::BareMetalUefi,
        }
    }

    /// The `.layout.toml` `substrate` wire token + the `--substrate` flag value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VpsKvm => "vps-kvm",
            Self::BareMetalUefi => "bare-metal-uefi",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_the_wire_token() {
        for f in [Firmware::Seabios, Firmware::SeabiosGpt, Firmware::Uefi] {
            assert_eq!(f.as_str().parse::<Firmware>().unwrap(), f);
        }
    }

    #[test]
    fn unknown_token_fails_closed() {
        assert!("bios".parse::<Firmware>().is_err());
        assert!("".parse::<Firmware>().is_err());
    }

    #[test]
    fn default_is_seabios() {
                                                                                                  
                                          
        assert_eq!(Firmware::default(), Firmware::Seabios);
    }

    #[test]
    fn substrate_derives_from_firmware() {
                                                                                         
        assert_eq!(
            Substrate::from_firmware(Firmware::Seabios),
            Substrate::VpsKvm
        );
        assert_eq!(
            Substrate::from_firmware(Firmware::SeabiosGpt),
            Substrate::VpsKvm
        );
        assert_eq!(
            Substrate::from_firmware(Firmware::Uefi),
            Substrate::BareMetalUefi
        );
        assert_eq!(Substrate::VpsKvm.as_str(), "vps-kvm");
        assert_eq!(Substrate::BareMetalUefi.as_str(), "bare-metal-uefi");
    }
}
