                                                                                                   
//!
//! The deterministic, tool-free tail of the build pipeline: build the rootfs component (pad the
//! squashfs to a 4096 boundary + append the dm-verity hash tree), then concatenate the three
//! PRE-BAKED partition components into the single-blob `.img` and emit the `.layout.toml` sidecar of
//! byte offsets. Pure (no external tools, no randomness) so the layer-8 determinism contract + the
                                                                                           
//! `bake_persist_skeleton` / `pack_squashfs` / `build_verity` / kernel) carry their determinism via
//! their pinned argv + an empirical double-build (see [`crate::build_tools_host`]).
//!
//! `.img` byte structure (O3): raw concatenation of three pre-baked partition images, NOT a tarball
//! or a partitioned disk image — the on-box installer `dd`s each component to its partition:
//!   `boot-component || persist-skeleton || (squashfs padded to 4096 || verity hash tree)`.
//! The kernel + initramfs are NOT in the `.img` (they live inside the boot-component's ext4 + are also
                                                                                                     
//! are firmware-NEUTRAL (`boot_offset`/`boot_size` — the boot component is an opaque blob, ext4+syslinux
//! under SeaBIOS or a FAT ESP holding the rambutan SB loader under UEFI) plus a `firmware` field.
//!
//! **Output is the UNSIGNED triple** `.img` + `.layout.toml` + `.sha256` (+ the local `.vmlinuz` /
//! `.initramfs` kexec artifacts) — the operator-sovereign ed25519 `.sig` is forward-debt (covers the
                                                                                    

use std::path::{Path, PathBuf};

use crate::firmware::{Firmware, Substrate};

/// dm-verity / squashfs data-block size. The squashfs portion is zero-padded up to
/// a multiple of this so the verity hash tree (and `fb.verity-hash-offset`)
                                          
pub const BLOCK_SIZE: usize = 4096;

/// Byte offsets/sizes of the three `.img` components, written to `<img>.layout.toml` so the on-box
/// installer (and `deploy verify`) can slice the exact byte ranges back out. Firmware-neutral keys:
/// the boot component is an opaque pre-baked partition image, so it is `boot_*`, not `bootfs_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub boot_offset: u64,
    pub boot_size: u64,
    pub persist_skeleton_offset: u64,
    pub persist_skeleton_size: u64,
    pub rootfs_offset: u64,
    pub rootfs_size: u64,
    /// Where the verity hash tree begins WITHIN the rootfs partition (= the padded
    /// squashfs size). Carried into the slot-A extlinux APPEND as `fb.verity-hash-offset`
                                                                             
                                                                             
    pub rootfs_verity_hash_offset: u64,
    /// dha Component E (O4=GPT): the weights component's byte range within the `.img` blob (appended
    /// after rootfs) + where its verity hash tree begins within it. `Some` only for a dha box; the
    /// installer dd's `[weights_offset .. +weights_size]` into the 5th GPT partition. `None` ⇒ no
                                                                                                  
    pub weights_offset: Option<u64>,
    pub weights_size: Option<u64>,
    pub weights_verity_hash_offset: Option<u64>,
                                                                                             
    /// production; the installer reads it back to branch the partition-table/boot logic.
    pub firmware: Firmware,
    /// os-update A/B v1 (§4i): the per-stream monotonic image serial + the operator's active
    /// `UpdateImage` delegation `monotonic_ctr`, stamped into BOTH this sidecar (the ceremony's
    /// authoritative text read) AND the rootfs `/etc/recipes/{image-version,min-delegation-ctr}`
    /// (the running box's read; per-slot + verity-protected). A golden cross-checks the two. Stamped
    /// firmware-UNCONDITIONALLY (R5-2): `box-init`'s `seed-update-floors` oneshot is one universal
    /// binary and must find the baked values on any image that ships it — MBR, seabios-gpt, and UEFI.
    pub image_version: u64,
    pub min_delegation_ctr: u64,
}

/// The rootfs partition image (squashfs padded to a block boundary + the appended
/// dm-verity hash tree) and the verity-hash offset within it.
pub struct RootfsComponent {
    pub bytes: Vec<u8>,
    pub verity_hash_offset: u64,
}

/// Build the rootfs partition component: zero-pad the squashfs up to a [`BLOCK_SIZE`]
/// multiple, then append the verity hash tree. The pad makes the verity tree start
/// on a block boundary so `fb.verity-hash-offset` (= padded size =
                                                                                  
pub fn build_rootfs_component(squashfs: &[u8], verity_hash_tree: &[u8]) -> RootfsComponent {
    let padded_len = squashfs.len().next_multiple_of(BLOCK_SIZE);
    debug_assert_eq!(padded_len % BLOCK_SIZE, 0);
    let mut bytes = Vec::with_capacity(padded_len + verity_hash_tree.len());
    bytes.extend_from_slice(squashfs);
    bytes.resize(padded_len, 0);                                                    
    let verity_hash_offset = padded_len as u64;
    bytes.extend_from_slice(verity_hash_tree);
    RootfsComponent {
        bytes,
        verity_hash_offset,
    }
}

/// Concatenate `boot || persist_skeleton || rootfs` into the `.img` blob + compute the layout.
/// Deterministic: a pure function of its inputs (no clock, no randomness). The three inputs are the
/// pre-baked partition images (`bake_boot_fs`, `bake_persist_skeleton`, [`build_rootfs_component`]).
pub fn assemble_img(
    boot: &[u8],
    persist_skeleton: &[u8],
    rootfs: &RootfsComponent,
    weights: Option<&RootfsComponent>,
    firmware: Firmware,
    image_version: u64,
    min_delegation_ctr: u64,
) -> (Vec<u8>, Layout) {
    let boot_size = boot.len() as u64;
    let persist_skeleton_size = persist_skeleton.len() as u64;
    let rootfs_size = rootfs.bytes.len() as u64;
    let rootfs_offset = boot_size + persist_skeleton_size;

    let mut capacity = boot.len() + persist_skeleton.len() + rootfs.bytes.len();
    if let Some(w) = weights {
        capacity += w.bytes.len();
    }
    let mut img = Vec::with_capacity(capacity);
    img.extend_from_slice(boot);
    img.extend_from_slice(persist_skeleton);
    img.extend_from_slice(&rootfs.bytes);

                                                                                                    
                                                                                                        
                                                                                                       
    let (weights_offset, weights_size, weights_verity_hash_offset) = match weights {
        None => (None, None, None),
        Some(w) => {
            let off = rootfs_offset + rootfs_size;
            img.extend_from_slice(&w.bytes);
            (
                Some(off),
                Some(w.bytes.len() as u64),
                Some(w.verity_hash_offset),
            )
        }
    };

    let layout = Layout {
        boot_offset: 0,
        boot_size,
        persist_skeleton_offset: boot_size,
        persist_skeleton_size,
        rootfs_offset,
        rootfs_size,
        rootfs_verity_hash_offset: rootfs.verity_hash_offset,
        weights_offset,
        weights_size,
        weights_verity_hash_offset,
        firmware,
        image_version,
        min_delegation_ctr,
    };
                                                                                                 
                                                                                                   
                                                                                              
                                                                                                
                                                                                                 
                                                                                                  
                                                  
    assert!(
        img.len() % 512 == 0,
        "assembled .img is {} bytes — not 512-aligned; a component broke its block-multiple \
         contract (streaming-installer)",
        img.len()
    );
    (img, layout)
}

                                                                           
                                                                                  
/// covers the `.img` bytes only, so tampering with the layout makes `verify` fail
/// (wrong byte-range → wrong hash → sig mismatch), it does not bypass.
pub fn render_layout_toml(layout: &Layout) -> String {
    use std::fmt::Write as _;
    let mut s = format!(
        "[layout]\n\
         boot_offset = {}\n\
         boot_size = {}\n\
         persist_skeleton_offset = {}\n\
         persist_skeleton_size = {}\n\
         rootfs_offset = {}\n\
         rootfs_size = {}\n\
         rootfs_verity_hash_offset = {}\n",
        layout.boot_offset,
        layout.boot_size,
        layout.persist_skeleton_offset,
        layout.persist_skeleton_size,
        layout.rootfs_offset,
        layout.rootfs_size,
        layout.rootfs_verity_hash_offset,
    );
                                                                                                      
                                                                                                    
    if let (Some(off), Some(size), Some(vho)) = (
        layout.weights_offset,
        layout.weights_size,
        layout.weights_verity_hash_offset,
    ) {
        let _ = writeln!(s, "weights_offset = {off}");
        let _ = writeln!(s, "weights_size = {size}");
        let _ = writeln!(s, "weights_verity_hash_offset = {vho}");
    }
                                                                                                      
                                                                                                        
                                                                          
    let _ = writeln!(s, "image_version = {}", layout.image_version);
    let _ = writeln!(s, "min_delegation_ctr = {}", layout.min_delegation_ctr);
    let _ = writeln!(s, "firmware = \"{}\"", layout.firmware.as_str());
                                                                                                      
                                                                                                     
                                                                                    
    let _ = writeln!(
        s,
        "substrate = \"{}\"",
        Substrate::from_firmware(layout.firmware).as_str()
    );
    s
}

/// SHA-256 hex over the `.img` bytes (the `.sha256` sidecar; a transfer-corruption
/// convenience hash, NOT the crypto trust anchor — that's the `.sig`).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The unsigned build outputs (Task 2.3 + O3). The `.sig` (operator-sovereign ed25519) is forward-debt.
/// `vmlinuz` + `initramfs` are LOCAL kexec artifacts (NOT in the `.img`): the deploy CLI `kexec -l`s
                                                                                        
#[derive(Debug, Clone)]
pub struct ImageOutputs {
    pub img: PathBuf,
    pub layout: PathBuf,
    pub sha256: PathBuf,
    pub vmlinuz: PathBuf,
    pub initramfs: PathBuf,
    pub vmlinuz_sha256: PathBuf,
    pub initramfs_sha256: PathBuf,
}

/// Write the assembled image + sidecars + the local kexec artifacts to `out_dir` as
/// `recipes-image-<image_label>.{img,layout.toml,sha256,vmlinuz,initramfs}`. Deterministic: identical
/// inputs → byte-identical files (the `.img` carries the layer-8 reproducibility contract). The
/// `.sha256` sidecars use `sha256sum` format (`<hex>  <name>\n`) — one per scp'd artifact
                                                                                              
/// on-target before kexec.
pub fn write_image_outputs(
    out_dir: &Path,
    image_label: &str,
    img: &[u8],
    layout: &Layout,
    vmlinuz: &[u8],
    initramfs: &[u8],
) -> std::io::Result<ImageOutputs> {
    std::fs::create_dir_all(out_dir)?;
    let base = format!("recipes-image-{image_label}");
    let img_path = out_dir.join(format!("{base}.img"));
    let layout_path = out_dir.join(format!("{base}.layout.toml"));
    let sha_path = out_dir.join(format!("{base}.sha256"));
    let vmlinuz_path = out_dir.join(format!("{base}.vmlinuz"));
    let initramfs_path = out_dir.join(format!("{base}.initramfs"));
    let vmlinuz_sha_path = out_dir.join(format!("{base}.vmlinuz.sha256"));
    let initramfs_sha_path = out_dir.join(format!("{base}.initramfs.sha256"));
    std::fs::write(&img_path, img)?;
    std::fs::write(&layout_path, render_layout_toml(layout))?;
    std::fs::write(&sha_path, format!("{}  {base}.img\n", sha256_hex(img)))?;
    std::fs::write(&vmlinuz_path, vmlinuz)?;
    std::fs::write(&initramfs_path, initramfs)?;
    std::fs::write(
        &vmlinuz_sha_path,
        format!("{}  {base}.vmlinuz\n", sha256_hex(vmlinuz)),
    )?;
    std::fs::write(
        &initramfs_sha_path,
        format!("{}  {base}.initramfs\n", sha256_hex(initramfs)),
    )?;
    Ok(ImageOutputs {
        img: img_path,
        layout: layout_path,
        sha256: sha_path,
        vmlinuz: vmlinuz_path,
        initramfs: initramfs_path,
        vmlinuz_sha256: vmlinuz_sha_path,
        initramfs_sha256: initramfs_sha_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

                                                                                     
                                                                                       
    fn squashfs() -> Vec<u8> {
        vec![0xABu8; BLOCK_SIZE + 100]                                  
    }
    fn verity_tree() -> Vec<u8> {
        vec![0xCDu8; 512]
    }
    fn boot() -> Vec<u8> {
        vec![0x01u8; 2048]                                                    
    }
    fn persist_skeleton() -> Vec<u8> {
        vec![0x02u8; 3072]
    }

    #[test]
    fn rootfs_component_pads_squashfs_to_block_boundary() {
        let sq = squashfs();
        let rc = build_rootfs_component(&sq, &verity_tree());
                                  
        assert_eq!(rc.verity_hash_offset, 8192);
        assert_eq!(
            rc.verity_hash_offset % BLOCK_SIZE as u64,
            0,
            "verity offset is block-aligned"
        );
        assert_eq!(rc.bytes.len(), 8192 + 512, "padded squashfs + verity tree");
                                                                        
        assert!(
            rc.bytes[sq.len()..8192].iter().all(|&b| b == 0),
            "pad is zeroed"
        );
        assert_eq!(
            &rc.bytes[8192..],
            &verity_tree()[..],
            "verity tree appended at the offset"
        );
    }

    #[test]
    fn already_aligned_squashfs_is_not_repadded() {
        let sq = vec![0xABu8; BLOCK_SIZE * 2];                   
        let rc = build_rootfs_component(&sq, &verity_tree());
        assert_eq!(
            rc.verity_hash_offset,
            (BLOCK_SIZE * 2) as u64,
            "no extra pad block added"
        );
    }

    #[test]
    fn img_is_concatenation_in_order_with_correct_layout() {
        let (b, p) = (boot(), persist_skeleton());
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let rootfs_len = rc.bytes.len() as u64;
        let (img, layout) = assemble_img(&b, &p, &rc, None, Firmware::Seabios, 1, 100);

        assert_eq!(
            img.len() as u64,
            b.len() as u64 + p.len() as u64 + rootfs_len
        );
                                                                      
        assert_eq!(&img[..b.len()], &b[..]);
        assert_eq!(&img[b.len()..b.len() + p.len()], &p[..]);
        assert_eq!(&img[b.len() + p.len()..], &rc.bytes[..]);

        assert_eq!(layout.boot_offset, 0);
        assert_eq!(layout.boot_size, b.len() as u64);
        assert_eq!(layout.persist_skeleton_offset, b.len() as u64);
        assert_eq!(layout.persist_skeleton_size, p.len() as u64);
        assert_eq!(layout.rootfs_offset, b.len() as u64 + p.len() as u64);
        assert_eq!(layout.rootfs_size, rootfs_len);
        assert_eq!(layout.rootfs_verity_hash_offset, 8192);
        assert_eq!(layout.firmware, Firmware::Seabios);
    }

    #[test]
    fn weights_component_appended_after_rootfs_with_layout() {
                                                                                                   
                                                                                                        
                                                                                           
        let (b, p) = (boot(), persist_skeleton());
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let weights = build_rootfs_component(&vec![0xEEu8; BLOCK_SIZE + 50], &vec![0xDDu8; 512]);
        let weights_len = weights.bytes.len() as u64;
        let (img, layout) = assemble_img(&b, &p, &rc, Some(&weights), Firmware::SeabiosGpt, 1, 100);
        let weights_off = b.len() as u64 + p.len() as u64 + rc.bytes.len() as u64;
        assert_eq!(layout.weights_offset, Some(weights_off));
        assert_eq!(layout.weights_size, Some(weights_len));
        assert_eq!(
            layout.weights_verity_hash_offset,
            Some(weights.verity_hash_offset)
        );
        assert_eq!(
            &img[weights_off as usize..],
            &weights.bytes[..],
            "weights bytes at offset"
        );
        assert_eq!(img.len() as u64, weights_off + weights_len);
    }

    #[test]
    fn no_weights_leaves_layout_none_and_three_component_blob() {
                                                                                                            
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let (img, layout) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc,
            None,
            Firmware::Seabios,
            1,
            100,
        );
        assert_eq!(layout.weights_offset, None);
        assert_eq!(layout.weights_size, None);
        assert_eq!(layout.weights_verity_hash_offset, None);
        assert_eq!(
            img.len(),
            boot().len() + persist_skeleton().len() + rc.bytes.len()
        );
    }

    #[test]
    fn render_layout_toml_weights_keys_present_only_when_some() {
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let weights = build_rootfs_component(&vec![0xEEu8; 4096], &vec![0xDDu8; 512]);
        let (_img, with) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc,
            Some(&weights),
            Firmware::SeabiosGpt,
            1,
            100,
        );
        let toml = render_layout_toml(&with);
        assert!(toml.contains(&format!(
            "weights_offset = {}",
            with.weights_offset.unwrap()
        )));
        assert!(toml.contains(&format!("weights_size = {}", with.weights_size.unwrap())));
        assert!(toml.contains("weights_verity_hash_offset ="));
        let (_i2, without) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc,
            None,
            Firmware::Seabios,
            1,
            100,
        );
        assert!(!render_layout_toml(&without).contains("weights_offset"));
    }

    #[test]
    fn assembled_img_length_is_512_aligned() {
                                                                                              
                                                                                                    
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let weights = build_rootfs_component(&vec![0xEEu8; BLOCK_SIZE + 50], &vec![0xDDu8; 512]);
        let (img, _) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc,
            Some(&weights),
            Firmware::SeabiosGpt,
            1,
            100,
        );
        assert_eq!(img.len() % 512, 0);
    }

    #[test]
    #[should_panic(expected = "not 512-aligned")]
    fn misaligned_assembly_trips_the_emit_assert() {
                                                                                                 
                                                                                            
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let misaligned_boot = vec![0x01u8; 511];
        let _ = assemble_img(
            &misaligned_boot,
            &persist_skeleton(),
            &rc,
            None,
            Firmware::Seabios,
            1,
            100,
        );
    }

    #[test]
    fn assembly_is_byte_reproducible() {
                                                                                   
                                                                                   
        let rc1 = build_rootfs_component(&squashfs(), &verity_tree());
        let rc2 = build_rootfs_component(&squashfs(), &verity_tree());
        let (img1, l1) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc1,
            None,
            Firmware::Seabios,
            1,
            100,
        );
        let (img2, l2) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc2,
            None,
            Firmware::Seabios,
            1,
            100,
        );
        assert_eq!(
            img1, img2,
            "two assemblies over identical inputs are byte-identical"
        );
        assert_eq!(l1, l2);
        assert_eq!(sha256_hex(&img1), sha256_hex(&img2));
    }

    #[test]
    fn layout_toml_roundtrips_the_offsets_and_firmware() {
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let (_img, layout) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc,
            None,
            Firmware::Seabios,
            1,
            100,
        );
        let toml = render_layout_toml(&layout);
        assert!(toml.contains("rootfs_verity_hash_offset = 8192"));
        assert!(toml.contains("boot_offset = 0"));
        assert!(toml.contains("firmware = \"seabios\""), "{toml}");
                                                                             
        let v: toml::Value = toml::from_str(&toml).unwrap();
        assert_eq!(
            v["layout"]["rootfs_size"].as_integer().unwrap() as u64,
            layout.rootfs_size
        );
        assert_eq!(
            v["layout"]["persist_skeleton_offset"].as_integer().unwrap() as u64,
            layout.persist_skeleton_offset
        );
        assert_eq!(v["layout"]["firmware"].as_str().unwrap(), "seabios");
    }

                                                                                                        
    /// for UEFI, vps-kvm for both BIOS firmwares.
    #[test]
    fn layout_carries_the_substrate_line() {
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let (_i, uefi) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc,
            None,
            Firmware::Uefi,
            1,
            100,
        );
        let ut = render_layout_toml(&uefi);
        assert!(ut.contains("substrate = \"bare-metal-uefi\""), "{ut}");
        let (_i, bios) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc,
            None,
            Firmware::SeabiosGpt,
            1,
            100,
        );
        let bt = render_layout_toml(&bios);
        assert!(bt.contains("substrate = \"vps-kvm\""), "{bt}");
                                     
        assert_eq!(
            toml::from_str::<toml::Value>(&ut).unwrap()["layout"]["substrate"]
                .as_str()
                .unwrap(),
            "bare-metal-uefi"
        );
    }

    #[test]
    fn build_reproducible_outputs_are_byte_identical() {
                                                                                 
                                                                              
                                                              
        let vm = vec![0x07u8; 2048];
        let ir = vec![0x08u8; 1500];
        let rc1 = build_rootfs_component(&squashfs(), &verity_tree());
        let (img1, l1) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc1,
            None,
            Firmware::Seabios,
            1,
            100,
        );
        let rc2 = build_rootfs_component(&squashfs(), &verity_tree());
        let (img2, l2) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc2,
            None,
            Firmware::Seabios,
            1,
            100,
        );

        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let o1 = write_image_outputs(d1.path(), "abc123de", &img1, &l1, &vm, &ir).unwrap();
        let o2 = write_image_outputs(d2.path(), "abc123de", &img2, &l2, &vm, &ir).unwrap();

        assert_eq!(
            std::fs::read(&o1.img).unwrap(),
            std::fs::read(&o2.img).unwrap(),
            ".img is byte-identical across builds"
        );
        assert_eq!(
            std::fs::read_to_string(&o1.sha256).unwrap(),
            std::fs::read_to_string(&o2.sha256).unwrap(),
            ".sha256 sidecar identical"
        );
        assert_eq!(
            std::fs::read_to_string(&o1.layout).unwrap(),
            std::fs::read_to_string(&o2.layout).unwrap(),
            ".layout.toml identical"
        );
                                                                      
        assert_eq!(
            std::fs::read(&o1.vmlinuz).unwrap(),
            vm,
            "<base>.vmlinuz = the kernel bytes"
        );
        assert_eq!(
            std::fs::read(&o1.initramfs).unwrap(),
            ir,
            "<base>.initramfs = the initramfs bytes"
        );
                                                                                        
        let img_hash = sha256_hex(&std::fs::read(&o1.img).unwrap());
        let sha_line = std::fs::read_to_string(&o1.sha256).unwrap();
        assert_eq!(
            sha_line,
            format!("{img_hash}  recipes-image-abc123de.img\n")
        );
                                             
        assert!(
            !d1.path().join("recipes-image-abc123de.img.sig").exists(),
            ".sig is forward-debt — must NOT be emitted by the foundation build"
        );
    }

    #[test]
    fn write_image_outputs_emits_kernel_initramfs_sha256() {
                                                                                                   
                                                                                                   
                                                           
        let vm = vec![0x07u8; 2048];
        let ir = vec![0x08u8; 1500];
        let rc = build_rootfs_component(&squashfs(), &verity_tree());
        let (img, layout) = assemble_img(
            &boot(),
            &persist_skeleton(),
            &rc,
            None,
            Firmware::Seabios,
            1,
            100,
        );

        let d = tempfile::tempdir().unwrap();
        let out = write_image_outputs(d.path(), "abc123de", &img, &layout, &vm, &ir).unwrap();

        let base = "recipes-image-abc123de";
        assert_eq!(
            out.vmlinuz_sha256,
            d.path().join(format!("{base}.vmlinuz.sha256"))
        );
        assert_eq!(
            out.initramfs_sha256,
            d.path().join(format!("{base}.initramfs.sha256"))
        );
        let v = std::fs::read_to_string(&out.vmlinuz_sha256).unwrap();
        assert_eq!(
            v,
            format!(
                "{}  {base}.vmlinuz\n",
                sha256_hex(&std::fs::read(&out.vmlinuz).unwrap())
            )
        );
        let i = std::fs::read_to_string(&out.initramfs_sha256).unwrap();
        assert_eq!(
            i,
            format!(
                "{}  {base}.initramfs\n",
                sha256_hex(&std::fs::read(&out.initramfs).unwrap())
            )
        );
    }
}
