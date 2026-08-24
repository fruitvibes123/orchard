                                                                                      
//!
//! The shell control this replaces (`readelf -l | grep -q INTERP`) asserted **dynamic** positively but
//! never asserted **static** at all. grocer adds the missing positive static assert, an architecture check,
//! and a typed parse (the vetted, single-format `elf` crate — small-surface DNA, not `object`). The input is
//! TRUSTED build-dir output (§5), so hostile-input robustness is not load-bearing here; the value is the
//! integrity control: a static (or static-PIE) binary silently swapped for a dynamic-musl service — which
//! would change the IMA-signed `.so` set the dm-verity/IMA design depends on — is refused **before any
//! store write**.
//!
//! Classification keys on the **PT_INTERP program-header count**, NOT `e_type`: the box's `box-init` /
//! `initramfs-init` are static-PIE (`ET_DYN` with **zero** PT_INTERP), so a naive `static == ET_EXEC` test
//! misclassifies them. `dynamic` = ≥1 PT_INTERP; `static` = a valid ELF with exactly 0.

use elf::abi::{EM_X86_64, ET_DYN, ET_EXEC, PT_INTERP};
use elf::endian::AnyEndian;
use elf::file::Class;
use elf::ElfBytes;

/// The link shape a `kind=binary` manifest entry declares — asserted against the real ELF at publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linkage {
    /// A dynamically-linked binary — carries ≥1 `PT_INTERP` program header (the musl loader).
    Dynamic,
    /// A statically-linked binary (incl. static-PIE) — a valid ELF with **zero** `PT_INTERP`.
    Static,
}

/// Every distinct way a candidate binary fails the fail-closed ELF/linkage gate. Each maps to a hard
                                                             
#[derive(Debug, thiserror::Error)]
pub enum ElfError {
    #[error("not a parseable ELF object")]
    NotElf,
    #[error("not ELFCLASS64 (grocer publishes only 64-bit box binaries)")]
    NotElf64,
    #[error("not little-endian (grocer publishes only x86-64 box binaries)")]
    NotLittleEndian,
    #[error("wrong architecture: e_machine={got:#06x} (expected EM_X86_64 = 0x003e)")]
    WrongArch { got: u16 },
    #[error("wrong ELF type: e_type={got:#06x} (expected ET_EXEC or ET_DYN)")]
    WrongType { got: u16 },
    #[error(
        "linkage mismatch: manifest declares {want:?} but the ELF carries {interp_count} PT_INTERP \
         program header(s)"
    )]
    LinkageMismatch { want: Linkage, interp_count: usize },
}

/// Validate ELF-ness FIRST (magic + `ELFCLASS64` + little-endian + `e_type ∈ {ET_EXEC, ET_DYN}` +
/// `e_machine == EM_X86_64`), THEN assert the declared `want` linkage against the actual `PT_INTERP` count.
/// A non-ELF / wrong-class / wrong-endianness / wrong-arch / wrong-type / linkage-mismatch is a hard error —
/// never a silent "static OK".
pub fn assert_elf(bytes: &[u8], want: Linkage) -> Result<(), ElfError> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(bytes).map_err(|_| ElfError::NotElf)?;

    if elf.ehdr.class != Class::ELF64 {
        return Err(ElfError::NotElf64);
    }
    if elf.ehdr.endianness != AnyEndian::Little {
        return Err(ElfError::NotLittleEndian);
    }
    if elf.ehdr.e_machine != EM_X86_64 {
        return Err(ElfError::WrongArch {
            got: elf.ehdr.e_machine,
        });
    }
    if elf.ehdr.e_type != ET_EXEC && elf.ehdr.e_type != ET_DYN {
        return Err(ElfError::WrongType {
            got: elf.ehdr.e_type,
        });
    }

    let interp_count = elf
        .segments()
        .map(|segs| segs.iter().filter(|ph| ph.p_type == PT_INTERP).count())
        .unwrap_or(0);

    match (want, interp_count) {
        (Linkage::Dynamic, n) if n >= 1 => Ok(()),
        (Linkage::Static, 0) => Ok(()),
        (want, interp_count) => Err(ElfError::LinkageMismatch { want, interp_count }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

                                                                                                   
                                                                                                 
                                                                                                       
                                                                                                            
    const DYNAMIC: &[u8] = include_bytes!("../tests/fixtures/fb-cert-check");
    const STATIC_PIE: &[u8] = include_bytes!("../tests/fixtures/box-init");

    #[test]
    fn dynamic_service_asserts_dynamic_ok() {
        assert!(assert_elf(DYNAMIC, Linkage::Dynamic).is_ok());
    }

    #[test]
    fn static_pie_asserts_static_ok() {
        assert!(assert_elf(STATIC_PIE, Linkage::Static).is_ok());
    }

    #[test]
    fn dynamic_service_asserted_static_is_linkage_mismatch() {
        assert!(matches!(
            assert_elf(DYNAMIC, Linkage::Static),
            Err(ElfError::LinkageMismatch { .. })
        ));
    }

    #[test]
    fn static_pie_asserted_dynamic_is_linkage_mismatch() {
        assert!(matches!(
            assert_elf(STATIC_PIE, Linkage::Dynamic),
            Err(ElfError::LinkageMismatch { .. })
        ));
    }

    #[test]
    fn truncated_header_is_not_elf() {
                                                                                                       
        assert!(matches!(
            assert_elf(&DYNAMIC[..16], Linkage::Static),
            Err(ElfError::NotElf)
        ));
    }

    #[test]
    fn non_elf_bytes_are_not_elf() {
        assert!(matches!(
            assert_elf(b"this is not an ELF file, not even close", Linkage::Static),
            Err(ElfError::NotElf)
        ));
    }

    #[test]
    fn wrong_arch_is_rejected() {
                                                                                                    
                                                   
        let mut bytes = DYNAMIC.to_vec();
        bytes[18] = 0xB7;                    
        bytes[19] = 0x00;
        assert!(matches!(
            assert_elf(&bytes, Linkage::Dynamic),
            Err(ElfError::WrongArch { .. })
        ));
    }

    #[test]
    fn et_rel_is_rejected() {
                                                                                                     
        let mut bytes = DYNAMIC.to_vec();
        bytes[16] = 0x01;
        bytes[17] = 0x00;
        assert!(matches!(
            assert_elf(&bytes, Linkage::Dynamic),
            Err(ElfError::WrongType { .. })
        ));
    }

    #[test]
    fn et_core_is_rejected() {
                                       
        let mut bytes = DYNAMIC.to_vec();
        bytes[16] = 0x04;
        bytes[17] = 0x00;
        assert!(matches!(
            assert_elf(&bytes, Linkage::Dynamic),
            Err(ElfError::WrongType { .. })
        ));
    }
}
