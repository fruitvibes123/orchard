                                                                                           
//! ADVISORY twin of the box's partition arithmetic — the weights-INCLUSIVE persist start and the
//! tail-window placement + fit check, run pre-staging so a doomed ceremony aborts before any byte
//! moves. **The installer's check against the real disk is authoritative**; this one exists to
//! fail FAST (and to close the R1-1 weights-blind brick: the old `min_install` sum dropped the
//! weights partition entirely).
//!
//! The arithmetic necessarily RE-IMPLEMENTS `initramfs-init`'s `compute_partition_layout`
//! cross-crate (the box is a standalone panic=abort workspace — no shared crate), which is the
                                                                                              
                                                                             

use crate::deploy::prod::{INSTALL_COPY_CHUNK_BYTES, RawWindowSpec};
use crate::deploy::prod_orchestrate::LayoutInfo;
use recipes_image_builder::firmware::Firmware;

                                                                                        
                                                                                                   
                                          
const BOOT_SIZE_BYTES: u64 = 128 * 1024 * 1024;
const SLOT_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const ALIGN_BYTES: u64 = 1024 * 1024;
const GPT_BACKUP_BYTES: u64 = 33 * 512;

/// Round up to the box's 1 MiB partition alignment — SATURATING (code-audit R1 L1). Plain
/// `div_ceil(..) * ALIGN_BYTES` on BYTE quantities overflows for a `weights_size` within ~1 MiB of
/// `u64::MAX` and silently WRAPS `orchard_persist_start` back to the weights-BLIND value (defeating
/// this cycle's R1-1 fix for that input class). Saturating mirrors the box's fail-closed behavior:
/// an absurd size drives `persist_start` toward `u64::MAX`, which `place_and_check_window`'s floor
/// check then refuses (the box's sector-based twin never wraps and refuses via `DiskTooSmall`).
fn align_up(bytes: u64) -> u64 {
    bytes.div_ceil(ALIGN_BYTES).saturating_mul(ALIGN_BYTES)
}

                                                                               
fn chunk_align_down(bytes: u64) -> u64 {
    bytes - (bytes % INSTALL_COPY_CHUNK_BYTES)
}

/// The persist partition's byte start under the box's layout arithmetic — WEIGHTS-INCLUSIVE
/// (plan R1-1): boot at 1 MiB + 128 MiB boot + two 64 MiB slots + (when the image carries a
/// weights component) the 1 MiB-aligned weights partition sized from `weights_size`.
pub fn orchard_persist_start(layout: &LayoutInfo, _disk_bytes: u64) -> u64 {
                                                                                            
                                                                                            
                                                                                          
    let boot_start = ALIGN_BYTES;
    let slot_a = align_up(boot_start + BOOT_SIZE_BYTES);
    let slot_b = align_up(slot_a + SLOT_SIZE_BYTES);
    let after_slots = align_up(slot_b + SLOT_SIZE_BYTES);
    match layout.weights_size {
                                                                                                 
                                                                      
        Some(ws) => align_up(after_slots.saturating_add(align_up(ws))),
        None => after_slots,
    }
}

/// Place the staging window at the extreme allowed tail (`chunk_align_down(disk − tail_reserve −
/// img_len)`) and CHECK the whole weights-inclusive fit: the layout floor (persist start + one
/// alignment unit + the tail reserve — the box's `DiskTooSmall` twin) and the window-vs-written
/// prefix disjointness (`window ≥ persist_start + max(skeleton, restore)`) — the fit GATES the
/// subtraction so it can never underflow (R1-1). Every refusal is a pre-staging abort with the
/// disk untouched everywhere.
pub fn place_and_check_window(
    layout: &LayoutInfo,
    disk: &str,
    disk_bytes: u64,
    img_len: u64,
    restore_len: u64,
) -> Result<RawWindowSpec, String> {
    let tail_reserve = match layout.firmware {
        Firmware::Seabios => 0,
        Firmware::SeabiosGpt | Firmware::Uefi => GPT_BACKUP_BYTES,
    };
    let persist_start = orchard_persist_start(layout, disk_bytes);
                                                                                            
                                                                                      
                                                                                                 
                                                                                                    
    let layout_floor = persist_start
        .saturating_add(ALIGN_BYTES)
        .saturating_add(tail_reserve);
    if disk_bytes < layout_floor {
                                                                                       
                                                                                                 
                                                                                                   
                                                                                     
        return Err(format!(
            "/dev/{disk} is {disk_bytes} bytes but the weights-inclusive layout needs ≥ \
             {layout_floor} (boot + 2 slots{} + persist floor); the box would refuse DiskTooSmall \
             post-kexec (row R-GEOMETRY). --reclaim-tail is not its remedy: the reclaim frees the \
             disk tail by shrinking the doomed root, but this floor is the total size the \
             weights-inclusive layout needs and the reclaim enlarges neither the disk nor the \
             persist prefix (AC-R5, §5a); aborting BEFORE any action",
            if layout.weights_size.is_some() {
                " + weights"
            } else {
                ""
            },
        ));
    }
    let top = disk_bytes - tail_reserve;
                                                                                                 
                                                                                             
                                                                      
    let floor = persist_start.saturating_add(layout.persist_skeleton_size.max(restore_len));
    let offset = top
        .checked_sub(img_len)
        .map(chunk_align_down)
        .filter(|&off| off >= floor)
        .ok_or_else(|| {
            format!(
                "staging window unplaceable on /dev/{disk} (row R-GEOMETRY): the {img_len}-byte \
                 image's tail window would reach below byte {floor} (persist start {persist_start} \
                 + the written persist prefix) — bigger disk, smaller image, or smaller restore. \
                 --reclaim-tail is not its remedy: the reclaim frees the disk tail by shrinking the \
                 doomed root, but this floor is the persist prefix the window must sit above, which \
                 the reclaim does not move (AC-R5, §5a); aborting BEFORE any action"
            )
        })?;
    Ok(RawWindowSpec {
        disk: disk.to_string(),
        offset,
        len: img_len,
    })
}

                                                                                    
///
/// [`place_and_check_window`] places the window by arithmetic on disk SIZE alone; it knows the box's
/// future layout but nothing about what is on the disk RIGHT NOW. The only existing guard is the D8
/// free-space advisory, whose own comment concedes *"amount is checkable; placement is not"*.
///
/// That gap is not theoretical. `growpart` filling the disk is the DEFAULT on Debian/Ubuntu
/// genericcloud images, so on a normally-provisioned VPS the tail window lands INSIDE the live,
/// mounted root filesystem. The installer then digests a window that the running system is still
/// writing back into, the mandatory `fb.image-sha256` check fails closed, and the machine reboots
                                                                                                       
/// the window inside vda1's block group 80 of 94 and the digest happened to PASS — and it gets MORE
/// likely the better-provisioned the target. One green sample of a race is not safety.
///
/// So: the ceremony already has the partition table in hand (it runs `lsblk` to walk root → disk),
/// and this turns that into the placement check the advisory could not make. Pre-staging, disk
/// untouched, like every other refusal on this path.
///
/// Note this deliberately does NOT try to make room. Shrinking the doomed root fs to free the tail
                                                                                                   
/// half and is what keeps a real operator's box bootable.
/// The first partition the staging window intersects, as DATA — `(win_start, win_end, extent)` —
/// or None. Half-open intersection: [a,b) ∩ [c,d) ≠ ∅  ⟺  a < d ∧ c < b. The pre-flight refusal
/// below renders its advice over this; `arbitrate`'s post-reboot D-1 re-run renders its own
/// slot-scoped line from the same data, never this file's rendered message, whose
/// "aborting BEFORE any action" / re-provision advice is true only at the pre-flight slot
                 
pub fn window_partition_intersection<'p>(
    window: &RawWindowSpec,
    parts: &'p [crate::deploy::prod::PartitionExtent],
) -> Option<(u64, u64, &'p crate::deploy::prod::PartitionExtent)> {
    let win_start = window.offset;
    let win_end = window.offset.saturating_add(window.len);
    parts
        .iter()
        .find(|p| win_start < p.end && p.start < win_end)
        .map(|p| (win_start, win_end, p))
}

pub fn refuse_if_window_intersects_partition(
    window: &RawWindowSpec,
    parts: &[crate::deploy::prod::PartitionExtent],
) -> Result<(), String> {
    match window_partition_intersection(window, parts) {
        None => Ok(()),
        Some((win_start, win_end, p)) => Err(format!(
            "the staging window [{win_start}, {win_end}) on /dev/{} INTERSECTS partition \
                 /dev/{} at [{}, {}) — streaming the image there would scribble a LIVE filesystem \
                 (and, if it is the mounted root, race its writeback until the installer's digest \
                 fails closed and the box reboots into the old OS). This is what a cloud-init \
                 `growpart` looks like: the partition was grown to fill the disk, so there is no \
                 free tail. Use a larger disk, a smaller image, or re-provision the target without \
                 growing the root partition to the end of the disk (D-1) — or, on a \
                 default-provisioned VPS, run `orchard reclaim-tail` (or `orchard prod \
                 --reclaim-tail`) to shrink the doomed root so the tail becomes free (D-2); \
                 aborting BEFORE any action",
            window.disk, p.name, p.start, p.end
        )),
    }
}

/// One golden-vector row — see [`GOLDEN_VECTORS`]; column semantics are defined by the fb twin
/// (`initramfs-init/src/installer_stream.rs`) and MUST stay byte-identical here.
pub type GoldenVector = (
    u64,
    &'static str,
    u64,
    u64,
    u64,
    u64,
    u64,
    u64,
    &'static str,
);

                                                                                               
/// Row: `(disk_bytes, fw_wire, weights_size, skel_len, restore_len, img_len, persist_start,
/// window_offset, verdict)`. This side asserts `orchard_persist_start` + `place_and_check_window`
/// over the `ok`/`refuse=`/`disk-too-small` rows; `given-refuse=` rows are box-side-only (a
/// hostile GIVEN window this placement never produces) and are hash-locked here without a
/// placement assert. Update BOTH crates together, never one.
pub const GOLDEN_VECTORS: &[GoldenVector] = &[
                                                                
    (
        10_737_418_240,
        "seabios",
        0,
        33_554_432,
        0,
        167_772_160,
        269_484_032,
        10_569_646_080,
        "ok",
    ),
                                                                             
    (
        10_737_418_240,
        "seabios-gpt",
        0,
        33_554_432,
        0,
        167_772_160,
        269_484_032,
        10_561_257_472,
        "ok",
    ),
                                                                                                   
                                                    
    (
        32_212_254_720,
        "seabios-gpt",
        1_714_917_376,
        33_554_432,
        0,
        2_276_954_112,
        1_984_954_368,
        29_930_553_344,
        "ok",
    ),
                                                                                          
    (
        536_870_912,
        "seabios",
        0,
        33_554_432,
        209_715_200,
        167_772_160,
        269_484_032,
        369_098_752,
        "refuse=persist-prefix",
    ),
                                                                                                
                                                                             
    (
        10_737_418_240,
        "seabios-gpt",
        0,
        33_554_432,
        0,
        8_388_608,
        269_484_032,
        10_729_029_632,
        "given-refuse=tail-bounds",
    ),
                                                                         
    (
        10_737_418_240,
        "seabios",
        0,
        33_554_432,
        0,
        10_569_646_080,
        269_484_032,
        167_772_160,
        "refuse=slot-a",
    ),
                                                                                                
                                                                   
    (
        4_294_967_296,
        "seabios",
        0,
        7_340_032,
        0,
        4_018_143_232,
        269_484_032,
        276_824_064,
        "ok",
    ),
                                                                                        
    (
        209_715_200,
        "seabios",
        0,
        33_554_432,
        0,
        8_388_608,
        0,
        0,
        "disk-too-small",
    ),
];

/// SHA-256 (lowercase hex) over `format!("{GOLDEN_VECTORS:?}")` — MUST equal the fb pin
/// (`installer_stream::GOLDEN_VECTORS_SHA256`); a one-sided table edit breaks this crate's pin
/// test (fail-closed drift guard).
pub const GOLDEN_VECTORS_SHA256: &str =
    "8687624aec50ad11aa4463bab96fa69f3431774abe6b103ec57547ffed60ff10";

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_layout(fw: &str, weights: u64, skel: u64) -> LayoutInfo {
        LayoutInfo {
            boot_offset: 0,
            boot_size: 1024,
            persist_skeleton_offset: 1024,
            persist_skeleton_size: skel,
            rootfs_offset: 2048,
            rootfs_size: 1024,
            rootfs_verity_hash_offset: 512,
            firmware: match fw {
                "seabios" => Firmware::Seabios,
                "seabios-gpt" => Firmware::SeabiosGpt,
                other => panic!("vector firmware {other:?}"),
            },
            weights_offset: (weights != 0).then_some(4096),
            weights_size: (weights != 0).then_some(weights),
        }
    }

    #[test]
    fn golden_vectors_hash_matches_the_fb_pin() {
        use sha2::{Digest, Sha256};
        let hex: String = Sha256::digest(format!("{GOLDEN_VECTORS:?}").as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex, GOLDEN_VECTORS_SHA256,
            "GOLDEN_VECTORS drifted — update BOTH crates' tables + pins together (4b)"
        );
    }

    #[test]
    fn golden_vectors_drive_persist_start_and_placement() {
        for &(disk_bytes, fw, weights, skel, restore, img, persist_col, window_col, verdict) in
            GOLDEN_VECTORS
        {
            if verdict.starts_with("given-refuse=") {
                continue;                                                                 
            }
            let layout = vector_layout(fw, weights, skel);
            if verdict == "disk-too-small" {
                assert!(
                    place_and_check_window(&layout, "vda", disk_bytes, img, restore).is_err(),
                    "vector disk={disk_bytes}: expected the layout-floor refusal"
                );
                continue;
            }
            assert_eq!(
                orchard_persist_start(&layout, disk_bytes),
                persist_col,
                "vector disk={disk_bytes} fw={fw} weights={weights}: persist_start drift"
            );
            let placed = place_and_check_window(&layout, "vda", disk_bytes, img, restore);
            match verdict {
                "ok" => {
                    let w = placed.unwrap_or_else(|e| {
                        panic!("vector disk={disk_bytes} img={img}: expected placement, got {e}")
                    });
                    assert_eq!(
                        w.offset, window_col,
                        "vector disk={disk_bytes}: window drift"
                    );
                    assert_eq!(w.len, img);
                    assert_eq!(w.disk, "vda");
                }
                v if v.starts_with("refuse=") => {
                    assert!(
                        placed.is_err(),
                        "vector disk={disk_bytes} img={img}: expected refusal"
                    );
                }
                other => panic!("unknown verdict {other:?}"),
            }
        }
    }

    #[test]
    fn absurd_weights_size_fails_closed_not_wraps_to_weights_blind() {
                                                                                              
                                                                                             
        let layout = vector_layout("seabios-gpt", u64::MAX - 1024, 33_554_432);
                                                                  
        assert!(orchard_persist_start(&layout, 0) >= u64::MAX - ALIGN_BYTES);
                                                                                              
        assert!(
            place_and_check_window(&layout, "vda", 64 << 30, 2_276_954_112, 0).is_err(),
            "an absurd weights_size must refuse pre-staging, not wrap to weights-blind"
        );
    }

    #[test]
    fn restore_length_tightens_the_fit_gate() {
                                                                                                
                                                    
        let layout = vector_layout("seabios", 0, 33_554_432);
        let disk = 536_870_912;
        assert!(place_and_check_window(&layout, "vda", disk, 167_772_160, 0).is_ok());
        assert!(place_and_check_window(&layout, "vda", disk, 167_772_160, 209_715_200).is_err());
    }

    #[test]
    fn floor_refusal_names_r_geometry_and_says_reclaim_is_not_its_remedy() {
                                                                                                
                                                                                                  
                                                                                                   
                                                                                          
        let layout = vector_layout("seabios", 0, 33_554_432);
        let e = place_and_check_window(&layout, "vda", 536_870_912, 167_772_160, 209_715_200)
            .unwrap_err();
        assert!(e.contains("R-GEOMETRY"), "{e}");
        assert!(e.contains("--reclaim-tail is not its remedy"), "{e}");
    }

    #[test]
    fn layout_floor_refusal_names_r_geometry_and_says_reclaim_is_not_its_remedy() {
                                                                                                 
                                                                                                       
                                                                                                  
                                                                                                 
                                                                                                   
                                                                                     
        let layout = vector_layout("seabios", 0, 33_554_432);
        let e = place_and_check_window(&layout, "vda", 1_048_576, 4096, 0).unwrap_err();
        assert!(
            e.contains("R-GEOMETRY"),
            "layout-floor arm names the row: {e}"
        );
        assert!(
            e.contains("--reclaim-tail is not its remedy"),
            "layout-floor arm disambiguates the reclaim: {e}"
        );
        assert!(
            e.contains("DiskTooSmall"),
            "the layout-floor arm still names the box-side twin: {e}"
        );
    }

                                                                         
    ///
                                                                                                 
    /// 11.87 GiB, and a window at byte 10,989,076,480 that therefore landed inside the mounted root
    /// fs. Under the old size-only placement that ceremony proceeded and the digest passed by luck.
                                                                                                    
    /// pre-fold `PROD_IMG_LEN` — an illustrative pair, not a transcript of one run (both prod lengths
    /// align to the same offset, and the window START already sits inside the partition, so the
    /// refusal is independent of `len`).
    #[test]
    fn a_window_inside_a_grown_root_partition_is_refused() {
        use crate::deploy::prod::PartitionExtent;

        let window = RawWindowSpec {
            disk: "vda".to_string(),
            offset: 10_989_076_480,
            len: 1_892_032_512,
        };
        let grown = vec![PartitionExtent {
            name: "vda1".to_string(),
            start: 1_048_576,
            end: 12_750_684_160,                          
        }];
        let err = refuse_if_window_intersects_partition(&window, &grown)
            .expect_err("a window inside the live root partition must refuse");
        assert!(err.contains("INTERSECTS"), "{err}");
        assert!(
            err.contains("vda1"),
            "the refusal must name the partition: {err}"
        );
        assert!(
            err.contains("growpart"),
            "the refusal must name the cause: {err}"
        );
                                                                                              
                                                
        assert!(
            err.contains("orchard reclaim-tail"),
            "the refusal must name the reclaim-tail remedy: {err}"
        );

                                                                                                  
                                                                                               
        let ungrown = vec![PartitionExtent {
            name: "vda1".to_string(),
            start: 1_048_576,
            end: 3_221_225_472,                                      
        }];
        assert!(refuse_if_window_intersects_partition(&window, &ungrown).is_ok());
    }

    /// Adjacency is NOT intersection: a partition ending exactly where the window starts (and one
    /// starting exactly where it ends) must pass. Half-open ranges make this exact, and getting it
    /// wrong by one would refuse every correctly-placed window on an aligned disk.
    #[test]
    fn partition_boundaries_touching_the_window_are_not_an_intersection() {
        use crate::deploy::prod::PartitionExtent;

        let window = RawWindowSpec {
            disk: "vda".to_string(),
            offset: 1_000_000,
            len: 1_000_000,
        };
        let touching = vec![
            PartitionExtent {
                name: "vda1".to_string(),
                start: 0,
                end: 1_000_000,                                    
            },
            PartitionExtent {
                name: "vda2".to_string(),
                start: 2_000_000,                                    
                end: 3_000_000,
            },
        ];
        assert!(refuse_if_window_intersects_partition(&window, &touching).is_ok());

                                                                  
        let over_left = vec![PartitionExtent {
            name: "vda1".to_string(),
            start: 0,
            end: 1_000_001,
        }];
        assert!(refuse_if_window_intersects_partition(&window, &over_left).is_err());
        let over_right = vec![PartitionExtent {
            name: "vda2".to_string(),
            start: 1_999_999,
            end: 3_000_000,
        }];
        assert!(refuse_if_window_intersects_partition(&window, &over_right).is_err());
    }
}
