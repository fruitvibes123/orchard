//! Reclaim-tail (D-2): consent-gated offline shrink of the doomed root filesystem + partition on a
//! default-provisioned target, run in the target's own Debian initramfs across one reboot, so the
//! streaming staging window lands in unpartitioned space and D-1 passes.
//!
                                                                                         
//! Anchors measured at orchard `si-land` `a2ecde8`
                                                            
//!
                                                                                          
//! orchestrated half (eligibility, neutralization, consent, splice hooks). Nothing in
                                                                              

use std::fmt;

/// A closed enum whose full variant set and per-variant value are maintained by the COMPILER, not
/// a hand list: one table declares the variants, the generated `ALL` slice is built from the same
/// list (a new variant is in `ALL` by construction), and the generated fn is a total match (a new
/// variant does not compile without a value). This is the anti-treadmill floor for the two
/// enumeration classes that kept losing (the hand-written consequence census and the source-text
                                                                                              
/// case fails a test until it is driven, and a case cannot be declared without its row/fact.
macro_rules! closed_enum_table {
    (
        $(#[$meta:meta])*
        enum $name:ident -> $ty:ty {
            $( $(#[$vmeta:meta])* $variant:ident => $val:expr ),+ $(,)?
        }
        fn = $fnname:ident
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub(crate) enum $name { $( $(#[$vmeta])* $variant ),+ }
        impl $name {
            /// Every variant, macro-generated from the SAME list that defines the enum. Consumed
            /// by the set-equality coverage floors (test cfg), hence the scoped allow.
            #[cfg_attr(not(test), allow(dead_code))]
            pub(crate) const ALL: &'static [$name] = &[ $( $name::$variant ),+ ];
            pub(crate) fn $fnname(self) -> $ty {
                match self { $( $name::$variant => $val ),+ }
            }
        }
    };
}
pub(crate) use closed_enum_table;

pub mod ceremony;
pub mod consent;
pub mod eligibility;
mod fstab_model;
pub mod neutralize;
pub mod post;

/// The target-read seam for the read-only half. One method: run a remote command on the
/// provisioning leg and return its stdout. The blanket adapter [`OpsReader`] routes through
/// `OrchestrationOps::ssh_capture`, so every reclaim read lands in the `FakeOps` `target_calls`
/// recorder exactly like the rest of the ceremony; unit tests drive a scripted fake instead.
/// Remote commands are structured to exit 0 and carry their own `RC:`/marker tokens, so a
/// non-zero tool exit is data, never a transport error.
pub trait TargetReader {
    fn capture(&mut self, cmd: &str) -> Result<String, String>;
}

/// Adapter: a `TargetReader` over the ceremony's `OrchestrationOps` (provisioning leg).
pub struct OpsReader<'a>(pub &'a mut dyn crate::deploy::prod_orchestrate::OrchestrationOps);

impl TargetReader for OpsReader<'_> {
    fn capture(&mut self, cmd: &str) -> Result<String, String> {
        self.0
            .ssh_capture(crate::deploy::prod_orchestrate::Leg::Provisioning, cmd)
    }
}

                                                                                            
/// generator level on the class.
pub const CLOUD_INIT_DISABLED_MARKER: &str = "/etc/cloud/cloud-init.disabled";

                                                                                                   

                                                                                        
pub const RECLAIM_MARGIN_BYTES: u64 = 1024 * 1024;
/// §5.8: bound on the reboot poll. Operator-overridable at the entry points.
pub const RECLAIM_REBOOT_TIMEOUT_SECS: u64 = 1800;

                                                                                            
/// arithmetic and compares the DECIMAL RENDERING as a string against [`ARITH_SELFTEST_PRODUCT`]
/// (never `test -eq`, so a shell whose arithmetic and whose `test` disagree about width cannot
/// pass). The product exceeds 2^32.
pub const ARITH_SELFTEST_A: u64 = 1048576;
pub const ARITH_SELFTEST_B: u64 = 1048583;
pub const ARITH_SELFTEST_PRODUCT: &str = "1099518967808";

                                                                                                    

/// §7 row ids. A refusal names the outcome-matrix row it lands on, so operator text and the
/// gate assertions key on the same vocabulary.
pub mod rows {
    pub const ELIG: &str = "R-ELIG";
    pub const FIT: &str = "R-FIT";
    pub const WOULD_GROW: &str = "R-WOULD-GROW";
    pub const GEOMETRY: &str = "R-GEOMETRY";
    pub const NEUTRALIZE: &str = "R-NEUTRALIZE";
    pub const INITRAMFS: &str = "R-INITRAMFS";
    pub const IDENTITY: &str = "R-IDENTITY";
    pub const POST_FIT: &str = "R-POST-FIT";
    pub const DISARM: &str = "R-DISARM";
    pub const NO_CRUMB: &str = "R-NO-CRUMB";
    pub const INTERSECTS: &str = "R-INTERSECTS";
    pub const REGROWN: &str = "R-REGROWN";
    pub const STALE_KERNEL: &str = "R-STALE-KERNEL";
    pub const NO_ANSWER: &str = "R-NO-ANSWER";
    pub const LOST_PRE_REBOOT: &str = "R-LOST-PRE-REBOOT";
}

/// A reclaim refusal: fail-closed, named by its §7 outcome row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimRefusal {
    /// The §7 outcome-matrix row this refusal lands on.
    pub row: &'static str,
    pub reason: String,
}

impl ReclaimRefusal {
    pub fn new(row: &'static str, reason: impl Into<String>) -> Self {
        Self {
            row,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ReclaimRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reclaim refuses ({}): {}", self.row, self.reason)
    }
}

impl std::error::Error for ReclaimRefusal {}

                                                                                                   

                                                                                                 
                                                                      
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub part_start: u64,
    pub planned_end: u64,
    pub planned_size: u64,
                                                   
    pub target_blocks: u64,
}

                                                                                 
                                                                  
pub fn plan_geometry(
    window_offset: u64,
    part_start: u64,
    block_size: u64,
) -> Result<Geometry, ReclaimRefusal> {
    if block_size == 0 {
        return Err(ReclaimRefusal::new(
            rows::GEOMETRY,
            "block_size is 0 — refusing before a division by zero (fail-closed; \
             the eligibility reads refuse a non-numeric or empty dumpe2fs read upstream)",
        ));
    }
    let margined = window_offset
        .checked_sub(RECLAIM_MARGIN_BYTES)
        .ok_or_else(|| {
            ReclaimRefusal::new(
                rows::GEOMETRY,
                format!(
                    "window offset {window_offset} is below the {RECLAIM_MARGIN_BYTES}-byte \
                     margin — planned_end underflows"
                ),
            )
        })?;
    let planned_end = margined - margined % RECLAIM_MARGIN_BYTES;
    let planned_size = planned_end.checked_sub(part_start).ok_or_else(|| {
        ReclaimRefusal::new(
            rows::GEOMETRY,
            format!(
                "planned end {planned_end} is below the partition start {part_start} — \
                 planned_size underflows"
            ),
        )
    })?;
    Ok(Geometry {
        part_start,
        planned_end,
        planned_size,
        target_blocks: planned_size / block_size,
    })
}

                                                                                              
/// holds §8's partition-never-below-filesystem invariant.
pub fn final_part_end(planned_end: u64, part_start: u64, fs_bytes: u64) -> u64 {
    planned_end.max(part_start.saturating_add(fs_bytes))
}

                                                                                          
                                                                                                 
/// the floor is exact.
pub fn sfdisk_size_sectors(final_part_end: u64, part_start: u64) -> u64 {
    final_part_end.saturating_sub(part_start) / 512
}

/// The §6.5 readback as data: either the measured `fs_bytes` or the defect the read produced
                                                                              
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadbackValue {
    Value(u64),
    Absent,
    NonNumeric,
    Ambiguous,
}

                                                                                             
/// exit 0, boot; R8 then refuses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadbackVerdict {
    Edit {
        final_part_end: u64,
        size_sectors: u64,
    },
    Skip {
        why: String,
    },
}

                                                                                       
/// strictly-positive sector count. `planned_size` is derived as `planned_end − part_start`
                                                                                              
/// decisions in shell; this function is the reference the `make verify` vectors pin (§9).
pub fn classify_readback(
    readback: ReadbackValue,
    part_start: u64,
    part_end_original: u64,
    planned_end: u64,
) -> ReadbackVerdict {
    let fs_bytes = match readback {
        ReadbackValue::Value(v) => v,
        ReadbackValue::Absent => {
            return ReadbackVerdict::Skip {
                why: "readback absent".into(),
            };
        }
        ReadbackValue::NonNumeric => {
            return ReadbackVerdict::Skip {
                why: "readback non-numeric".into(),
            };
        }
        ReadbackValue::Ambiguous => {
            return ReadbackVerdict::Skip {
                why: "readback matched other than exactly one line".into(),
            };
        }
    };
    let planned_size = planned_end.saturating_sub(part_start);
    if fs_bytes < planned_size / 2 {
        return ReadbackVerdict::Skip {
            why: format!(
                "readback {fs_bytes} is below half the planned size {planned_size} — \
                 sanity floor"
            ),
        };
    }
    let end = final_part_end(planned_end, part_start, fs_bytes);
    if !(part_start < end && end <= part_end_original) {
        return ReadbackVerdict::Skip {
            why: format!(
                "final end {end} violates part_start {part_start} < end <= original \
                 {part_end_original}"
            ),
        };
    }
    let size_sectors = sfdisk_size_sectors(end, part_start);
    if size_sectors == 0 {
        return ReadbackVerdict::Skip {
            why: "derived sector count is not strictly positive".into(),
        };
    }
    ReadbackVerdict::Edit {
        final_part_end: end,
        size_sectors,
    }
}

                                                                                           
/// against the threaded `planned_end` and never against `part_start + fs_bytes` (the v5/v6
                                                                                                 
pub fn should_short_circuit(
    fs_bytes: u64,
    part_end: u64,
    planned_end: u64,
    part_start: u64,
) -> bool {
    let planned_size = planned_end.saturating_sub(part_start);
    fs_bytes <= planned_size && part_end <= planned_end
}

                                                                                             
/// the partition edit without invoking `resize2fs` (initramfs backstop, §6.4).
pub fn would_grow(target_blocks: u64, block_size: u64, fs_bytes: u64) -> bool {
    target_blocks.saturating_mul(block_size) > fs_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reclaim_module_compiles() {}

    #[test]
    fn arith_selftest_product_matches_the_pinned_literal() {
        let product = (ARITH_SELFTEST_A as u128) * (ARITH_SELFTEST_B as u128);
        assert!(product > (1u128 << 32));
        assert_eq!(product.to_string(), ARITH_SELFTEST_PRODUCT);
    }

                                           

    #[test]
    fn geometry_matches_spec_worked_example() {
                                                                                                   
        let g = plan_geometry(41053847552, 134217728, 4096).unwrap();
        assert_eq!(g.planned_end, 41052798976);
        assert_eq!(g.planned_size, 40918581248);
        assert_eq!(g.target_blocks, 9989888);
    }

    #[test]
    fn geometry_underflow_refuses_not_wraps() {
                                                                   
        let e = plan_geometry(500_000, 134217728, 4096).unwrap_err();
        assert_eq!(e.row, rows::GEOMETRY);
                                                                  
        let e = plan_geometry(2 * 1024 * 1024, 134217728, 4096).unwrap_err();
        assert_eq!(e.row, rows::GEOMETRY);
        assert!(e.reason.contains("underflow"), "{e}");
                                                               
        let e = plan_geometry(41053847552, 134217728, 0).unwrap_err();
        assert_eq!(e.row, rows::GEOMETRY);
    }

                                                                             

    const S: u64 = 134217728;                  
    const E_ORIG: u64 = 42948624384;                                  
    const P_END: u64 = 41052798976;                   
    const P_SIZE: u64 = 40918581248;                    

    #[test]
    fn readback_smaller_lands_at_planned_end() {
        let fs = P_SIZE - 40960;
        match classify_readback(ReadbackValue::Value(fs), S, E_ORIG, P_END) {
            ReadbackVerdict::Edit {
                final_part_end: end,
                size_sectors,
            } => {
                assert_eq!(end, P_END);
                assert_eq!(size_sectors, (P_END - S) / 512);
                assert_eq!(size_sectors * 512, P_END - S, " floor is exact");
            }
            other => panic!("expected Edit, got {other:?}"),
        }
    }

    #[test]
    fn readback_raise_band_writes_part_start_plus_fs_not_planned_end() {
                                                                                      
        let fs = P_SIZE + 3 * 1024 * 1024;
        match classify_readback(ReadbackValue::Value(fs), S, E_ORIG, P_END) {
            ReadbackVerdict::Edit {
                final_part_end: end,
                size_sectors,
            } => {
                assert_eq!(end, S + fs, "raise band writes part_start + fs_bytes (max)");
                assert_ne!(end, P_END);
                assert!(size_sectors > 0);
            }
            other => panic!("expected Edit, got {other:?}"),
        }
    }

    #[test]
    fn readback_larger_than_original_end_skips() {
                                                                                                
        let fs = (E_ORIG - S) + 4096;
        let v = classify_readback(ReadbackValue::Value(fs), S, E_ORIG, P_END);
        assert!(matches!(v, ReadbackVerdict::Skip { .. }), "{v:?}");
    }

    #[test]
    fn readback_absent_nonnumeric_ambiguous_each_skip() {
        for r in [
            ReadbackValue::Absent,
            ReadbackValue::NonNumeric,
            ReadbackValue::Ambiguous,
        ] {
            let v = classify_readback(r, S, E_ORIG, P_END);
            assert!(matches!(v, ReadbackVerdict::Skip { .. }), "{r:?} must SKIP");
        }
    }

    #[test]
    fn readback_sanity_floor_skips_below_half_planned_size() {
        let v = classify_readback(ReadbackValue::Value(P_SIZE / 2 - 1), S, E_ORIG, P_END);
        assert!(matches!(v, ReadbackVerdict::Skip { .. }), "{v:?}");
                                                      
        let v = classify_readback(ReadbackValue::Value(P_SIZE / 2), S, E_ORIG, P_END);
        assert!(matches!(v, ReadbackVerdict::Edit { .. }), "{v:?}");
    }

    #[test]
    fn readback_sub_sector_span_skips_on_nonpositive_sector_count() {
                                                                                          
                                                    
        let s = 1048576;
        let planned_end = s + 256;
        let v = classify_readback(ReadbackValue::Value(200), s, s + 4096, planned_end);
        assert!(matches!(v, ReadbackVerdict::Skip { .. }), "{v:?}");
    }

                                                                                           

    /// The seven shapes R5's `probe_growpart`/`probe_growpart_mbr` recorded
                                                                                                 
    /// `growpart` + `resize2fs`): (part_start, grown part_end, gpt_remainder).
    /// `gpt_remainder` is the measured `end − (start + fs)` leftover: 0 on every MBR shape and the
    /// block-aligned GPT shape, 3584 on the growpart GPT shapes.
    const GEOMETRIES: [(u64, u64, u64); 7] = [
        (1048576, 8589934592, 0),                         
        (1048576, 21474836480, 0),                         
        (1048576, 42949672960, 0),                         
        (1048576, 44023414784, 0),                         
        (134217728, 8589917696, 3584),                                           
        (134217728, 42949656064, 3584),                    
        (134217728, 42947575808, 0),                                      
    ];

    #[test]
    fn conjunction_true_only_at_exact_landing_across_measured_geometries() {
        for (s, grown_end, rem) in GEOMETRIES {
                                                                                             
                                                                              
            let margined = grown_end - 1892036608 - RECLAIM_MARGIN_BYTES;
            let planned_end = margined - margined % (1024 * 1024);
            let planned_size = planned_end - s;
            let shrunk_fs = planned_size - planned_size % 4096;

                                                                                          
                                                                                                
            let grown_fs = (grown_end - s) - rem;
            assert!(!should_short_circuit(grown_fs, grown_end, planned_end, s));

                                                                                             
                                                                                                 
                                 
            assert!(!should_short_circuit(
                planned_size / 3,
                grown_end,
                planned_end,
                s
            ));

                                                                      
            assert!(!should_short_circuit(shrunk_fs, grown_end, planned_end, s));

                                                     
            assert!(should_short_circuit(shrunk_fs, planned_end, planned_end, s));

                                                                                                    
            let raise_fs = planned_size + 8192;
            assert!(!should_short_circuit(
                raise_fs,
                s + raise_fs,
                planned_end,
                s
            ));

                                                                                           
                                                               
            assert!(!should_short_circuit(raise_fs, planned_end, planned_end, s));
        }
    }

                                

    #[test]
    fn would_grow_refuses_growth_and_admits_shrink_or_equal() {
                                                                                        
        assert!(would_grow(9989888, 4096, 40918581247));
        assert!(
            !would_grow(9989888, 4096, 40918581248),
            "equal is not a grow"
        );
        assert!(!would_grow(9989888, 4096, 40918581249));
                                                
        assert!(would_grow(u64::MAX, 4096, 1));
    }
}

                                                                                                    

                                                                                                
/// the script re-reads it, which makes `fs_bytes = block_count × block_size` unsplittable.
#[derive(Debug, Clone)]
pub struct PremountInputs {
    pub disk: String,
    pub part_num: u32,
    pub part_node: String,
    pub part_sysfs: String,
    pub part_start: u64,
    pub part_end_original: u64,
    pub planned_end: u64,
    pub target_blocks: u64,
}

const PREMOUNT_TEMPLATE: &str = include_str!("reclaim/premount.sh.tmpl");

                                                                                 
pub const PREMOUNT_SCRIPT_NAME: &str = "orchard-reclaim";

fn require_shell_safe(label: &str, value: &str) -> Result<(), ReclaimRefusal> {
    let ok = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'));
    if ok {
        Ok(())
    } else {
        Err(ReclaimRefusal::new(
                                                                                             
                                                                                                 
                                                                                             
                                                                                                 
                                           
            rows::ELIG,
            format!(
                "{label} {value:?} carries characters outside [A-Za-z0-9._/-] — refusing to \
                 render a root-executed script around it (fail-closed; the value came from the \
                 target over SSH). Refused in the read-only half so no permanent write precedes \
                 it"
            ),
        ))
    }
}

/// Render the §6 premount script. Fail-closed on device names that could corrupt the rendered
/// shell and on any unrendered token.
pub fn render_premount(i: &PremountInputs) -> Result<String, ReclaimRefusal> {
    require_shell_safe("disk", &i.disk)?;
    require_shell_safe("part_node", &i.part_node)?;
    require_shell_safe("part_sysfs", &i.part_sysfs)?;
    let out = PREMOUNT_TEMPLATE
        .replace("@DISK@", &i.disk)
        .replace("@PART_NUM@", &i.part_num.to_string())
        .replace("@PART_NODE@", &i.part_node)
        .replace("@PART_SYSFS@", &i.part_sysfs)
        .replace("@PART_START@", &i.part_start.to_string())
        .replace("@PART_END_ORIGINAL@", &i.part_end_original.to_string())
        .replace("@PLANNED_END@", &i.planned_end.to_string())
        .replace("@TARGET_BLOCKS@", &i.target_blocks.to_string())
        .replace("@ARITH_A@", &ARITH_SELFTEST_A.to_string())
        .replace("@ARITH_B@", &ARITH_SELFTEST_B.to_string())
        .replace("@ARITH_PRODUCT@", ARITH_SELFTEST_PRODUCT);
    if out.contains('@') {
        return Err(ReclaimRefusal::new(
                                                                                                    
                                                                         
            rows::ELIG,
            "an unrendered template token remains in the premount script — refused in the \
             read-only half so no permanent write precedes it",
        ));
    }
    Ok(out)
}

                                                                                            
/// file silently: a `0644` script lists in `lsinitramfs` but never enters ORDER and never runs.
pub fn write_rendered_0755(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, content)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

#[cfg(test)]
mod premount_tests {
    use super::*;
    use std::process::Command;

    fn sample_inputs() -> PremountInputs {
        PremountInputs {
            disk: "vda".into(),
            part_num: 1,
            part_node: "/dev/vda1".into(),
            part_sysfs: "vda1".into(),
            part_start: 134217728,
            part_end_original: 42948624384,
            planned_end: 41052798976,
            target_blocks: 9989888,
        }
    }

    fn rendered() -> String {
        render_premount(&sample_inputs()).unwrap()
    }

    fn run_sh(script: &str, arg: &str) -> (std::process::Output, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PREMOUNT_SCRIPT_NAME);
        write_rendered_0755(&path, script).unwrap();
        let out = Command::new("sh")
            .arg(&path)
            .arg(arg)
            .current_dir(dir.path())
            .output()
            .unwrap();
        (out, dir)
    }

    #[test]
    fn premount_prereqs_preamble_emits_no_tokens() {
        let s = rendered();
        assert!(s.contains("case $1 in"));
        assert!(s.contains("prereqs)"));
        let (out, dir) = run_sh(&s, "prereqs");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "");
        assert_eq!(out.status.code(), Some(0));
                                                                                                
                                           
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn premount_mode_is_0755() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PREMOUNT_SCRIPT_NAME);
        write_rendered_0755(&path, &rendered()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn premount_sh_syntax_clean() {
                                                                                                    
                                                                                                 
                                                                                                        
                                                                                               
                                                                                                    
                                                                                                  
          
                                                                                               
                                                                                                      
                                                                                                    
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PREMOUNT_SCRIPT_NAME);
        write_rendered_0755(&path, &rendered()).unwrap();

        let avail = |prog: &str, arg: &str| {
            Command::new(prog)
                .args([arg, "-c", ":"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        let (prog, pre): (&str, &[&str]) = if avail("dash", "-n") {
            ("dash", &[])
        } else if Command::new("busybox")
            .args(["ash", "-n", "-c", ":"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            ("busybox", &["ash"])
        } else {
                                                                                                    
                                                                     
            ("sh", &[])
        };
        let out = Command::new(prog)
            .args(pre)
            .arg("-n")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{prog} {pre:?} -n: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn premount_breadcrumbs_one_redirect_per_line_with_level_prefix() {
        let s = rendered();
        let mut crumb_lines = 0;
        for line in s.lines() {
            if line.contains("/dev/kmsg") {
                let t = line.trim();
                assert!(
                    t.starts_with("echo \"<3>orchard-reclaim: "),
                    "breadcrumb prefix: {t}"
                );
                assert!(t.ends_with("> /dev/kmsg"), "own kmsg redirect: {t}");
                crumb_lines += 1;
            }
            assert!(
                !(line.contains("exec") && line.contains("kmsg")),
                "a held kmsg descriptor is forbidden: {line}"
            );
        }
        assert!(
            crumb_lines >= 12,
            "expected the §6 crumbs, got {crumb_lines}"
        );
    }

    #[test]
    fn premount_reads_back_via_dumpe2fs_never_resize2fs_output() {
        let s = rendered();
        assert!(s.contains("dumpe2fs -h"), "anchored dumpe2fs read");
        assert!(!s.contains("blocks long"), "never parse resize2fs output");
        assert!(s.contains("--lock=nonblock"), "sfdisk lock flag");
        assert!(s.contains("e2fsck -fp"), "§6.3: -p never -y, -f required");
        assert!(s.contains("rc & 252"), "§6.3 bitmask (0xFC)");
                                                                                               
        assert!(
            s.contains("dump_rc=$?") && s.contains("dumpe2fs-rc="),
            "a non-zero dumpe2fs exit is a SKIP"
        );
    }

    #[test]
    fn premount_read_fs_skips_on_a_nonzero_dumpe2fs_exit() {
                                                                                                    
                                                                                                  
                                                                                                
                                                                                                    
                                         
        use std::os::unix::fs::PermissionsExt;
        let s = rendered();
        let start = s.find("lstrip() {").expect("lstrip present");
        let end = s.find("# step 1").expect("step 1 marker present");
        let funcs = &s[start..end];                                   

        let run_with_dumpe2fs = |exit: i32| -> String {
            let dir = tempfile::tempdir().unwrap();
            let shim = dir.path().join("dumpe2fs");
            std::fs::write(
                &shim,
                format!(
                    "#!/bin/sh\nprintf 'Block count:              100\\nBlock size:               4096\\n'\nexit {exit}\n"
                ),
            )
            .unwrap();
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            let harness = format!(
                "PART_NODE=/dev/does-not-matter\n{funcs}\nread_fs\nprintf 'FS_OK=%s FS_WHY=%s\\n' \"$FS_OK\" \"$FS_WHY\"\n"
            );
            let path = format!(
                "{}:{}",
                dir.path().display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let out = Command::new("sh")
                .arg("-c")
                .arg(&harness)
                .env("PATH", path)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

                                                                                             
        let skip = run_with_dumpe2fs(3);
        assert!(
            skip.contains("FS_OK=0"),
            "a non-zero dumpe2fs exit must not succeed: {skip:?}"
        );
        assert!(
            skip.contains("FS_WHY=dumpe2fs-rc=3"),
            "the SKIP names the dumpe2fs exit code: {skip:?}"
        );
                                                                               
        let ok = run_with_dumpe2fs(0);
        assert!(
            ok.contains("FS_OK=1"),
            "a clean dumpe2fs read must succeed: {ok:?}"
        );
    }

    #[test]
    fn premount_threads_the_r43_set_and_not_block_size() {
        let s = rendered();
        for needle in [
            "PART_START=134217728",
            "PART_END_ORIGINAL=42948624384",
            "PLANNED_END=41052798976",
            "TARGET_BLOCKS=9989888",
            "PART_NODE=/dev/vda1",
            "PART_SYSFS=vda1",
        ] {
            assert!(s.contains(needle), "missing {needle}");
        }
        assert!(!s.contains('@'), "no unrendered token may remain");
    }

    #[test]
    fn premount_shells_out_to_nothing_but_the_required_set() {
                                                                                                 
                                                                                                  
                                                                                                 
                                                                                                 
                                                                                        
                                                                                                  
                                                                                               
                                                                                                
                                                                                           
        let s = rendered();
        let allowed = [
            "dumpe2fs",
            "e2fsck",
            "resize2fs",
            "sfdisk",        
            "command",
            "sleep",
            "cat",
            "echo",
            "printf",
            "break",
            "return",
            "exit",
            "case",
            "while",
            "for",
            "if",
            "then",
            "else",
            "elif",
            "fi",
            "do",
            "done",
            "esac",
            "set",
            "read_fs",
            "lstrip",
            "local",
            "prereqs",
        ];
        for line in s.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
                                                                                   
            let first = t
                .trim_start_matches("if ! ")
                .trim_start_matches("if ")
                .trim_start_matches("! ")
                .split_whitespace()
                .next()
                .unwrap_or("");
            let bare = first.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
            if bare.is_empty()
                || bare
                    .chars()
                    .next()
                    .is_some_and(|c| !c.is_ascii_alphabetic())
            {
                continue;
            }
                                                                                          
            if first.contains('=')
                || first.starts_with('$')
                || first.starts_with('"')
                || t.contains("() {")
                || t.ends_with(')')                                            
                || t.starts_with('\'')                          
                || t == "}"
            {
                continue;
            }
            assert!(
                allowed.contains(&bare),
                "the premount script invokes {bare:?} — outside the allowlisted set + the builtins the \
                 initramfs provides; the phase has no grep/sed/awk (measured). Line: {t}"
            );
        }
                                                                                
        for banned in [
            " grep ", "| grep", " sed ", "| sed", " awk ", "| awk", "| cut", "| tr ",
        ] {
            assert!(
                !s.contains(banned),
                "the premount script uses {banned:?}, which the initramfs does not provide"
            );
        }

                                                                                                  
                                                                                                        
                                                                                                       
                                                                                                      
                                                                                                  
                                                                              
        let subst_cmd = |frag: &str| -> Option<String> {
            if frag.starts_with('(') {
                return None;                       
            }
            let first = frag.split_whitespace().next()?;
            let bare = first.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
            (!bare.is_empty() && bare.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
                .then(|| bare.to_string())
        };
        let mut subst_cmds: Vec<String> = s.split("$(").skip(1).filter_map(subst_cmd).collect();
        subst_cmds.sort();
        subst_cmds.dedup();
        assert!(
            subst_cmds.iter().any(|c| c == "dumpe2fs"),
            "expected the dumpe2fs/cat/sfdisk substitutions to be inspected, got {subst_cmds:?}"
        );
        for cmd in &subst_cmds {
            assert!(
                allowed.contains(&cmd.as_str()),
                "the premount script invokes {cmd:?} inside a command substitution — outside the \
                 premount allowlist"
            );
        }
                                                                                                       
        let synthetic = "BC=\"$(grep -c '^Block count:' \"$PART_NODE\")\"";
        let caught: Vec<String> = synthetic
            .split("$(")
            .skip(1)
            .filter_map(subst_cmd)
            .collect();
        assert!(
            caught.iter().any(|c| c == "grep") && !allowed.contains(&"grep"),
            "the substitution scan must reject a grep inside $(…): {caught:?}"
        );
    }

    #[test]
    fn premount_render_refuses_shell_metacharacters_in_each_field() {
                                                                                                 
                                                                                                 
                                                                                                        
        let sets: [fn(&mut PremountInputs); 3] = [
            |i| i.disk = "vda; reboot".into(),
            |i| i.part_node = "/dev/vda1; reboot".into(),
            |i| i.part_sysfs = "vda1; reboot".into(),
        ];
        for set in sets {
            let mut i = sample_inputs();
            set(&mut i);
            let e = render_premount(&i).unwrap_err();
            assert_eq!(
                e.row,
                rows::ELIG,
                "a shell metacharacter in each rendered field must refuse at R-ELIG (\
                 render_premount runs in the read-only half, so the refusal precedes any write)"
            );
        }
    }
}

                                                                                                   

                                                                                               
/// and the landing check both derive from it.
pub const REQUIRED_BINARIES: [&str; 4] = ["e2fsck", "resize2fs", "sfdisk", "dumpe2fs"];

                                                                         
pub const HOOK_NAME: &str = "orchard-reclaim";

const HOOK_TEMPLATE: &str = include_str!("reclaim/hook.sh.tmpl");

                                                                                        
pub fn render_hook() -> String {
    let lines: Vec<String> = REQUIRED_BINARIES
        .iter()
        .map(|b| format!("copy_exec /sbin/{b}"))
        .collect();
    HOOK_TEMPLATE.replace("@COPY_EXEC_LINES@", &lines.join("\n"))
}

                                                                                              
/// listing. The match is by basename, never an exact `/sbin/…` path: `copy_exec` targets land at
/// their usr-merged canonical paths (`/sbin/sfdisk` lists as `usr/sbin/sfdisk`). A missing
/// binary REFUSES naming it (row `R-INITRAMFS`, "a required binary did not land").
pub fn verify_required_set(lsinitramfs_output: &str) -> Result<(), ReclaimRefusal> {
    let basenames: std::collections::HashSet<&str> = lsinitramfs_output
        .lines()
        .filter_map(|l| l.trim().rsplit('/').next())
        .collect();
    for required in REQUIRED_BINARIES {
        if !basenames.contains(required) {
            return Err(ReclaimRefusal::new(
                rows::INITRAMFS,
                format!(
                    "required binary {required} did not land in the rebuilt initrd \
                     (lsinitramfs listing has no entry with that basename)"
                ),
            ));
        }
    }
    Ok(())
}

/// Split a per-initrd framed probe reply into `(initrd_path, body)` sections on `marker` lines
/// (`INITRD:` / `ORDER-INITRD:`). Lines before the first marker, and trailing bookkeeping
/// (`INITRD-COUNT:` / `RC:` / `ORDER-DONE`), fall outside any section or into the last one
/// harmlessly — they carry no required basename and no premount name.
fn frame_initrds(output: &str, marker: &str) -> Vec<(String, String)> {
    let mut sections: Vec<(String, String)> = vec![];
    for line in output.lines() {
        if let Some(path) = line.trim().strip_prefix(marker) {
            sections.push((path.trim().to_string(), String::new()));
        } else if let Some((_, body)) = sections.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    sections
}

                                                                                                 
/// the landing check's scope must match the rebuild's, so the kernel the target next boots is
/// covered even when a second, not-yet-booted kernel is installed). `LSINITRAMFS_CMD` frames only
/// the initrds paired with an installed `/boot/vmlinu[xz]-<v>` — the exact set `-k all` rebuilds
                                                                                                      
/// least one paired initrd must have been enumerated — an empty `/boot/initrd.img-*` glob REFUSES
/// (row `R-INITRAMFS`), never admits.
pub fn verify_required_set_all_initrds(listing: &str) -> Result<(), ReclaimRefusal> {
    let sections = frame_initrds(listing, "INITRD:");
    if sections.is_empty() {
        return Err(ReclaimRefusal::new(
            rows::INITRAMFS,
            "the landing check enumerated no kernel-paired initrd (/boot/initrd.img-* matched \
             nothing, or none had a matching /boot/vmlinu[xz]-<v>) — the required set cannot be \
             confirmed to have landed (row R-INITRAMFS)",
        ));
    }
    for (path, body) in &sections {
        verify_required_set(body).map_err(|e| {
            ReclaimRefusal::new(
                rows::INITRAMFS,
                format!(
                    "{} — in {path} (this initrd is paired with an installed kernel, so the \
                     -k all rebuild wrote it)",
                    e.reason
                ),
            )
        })?;
    }
    Ok(())
}

                                                                                            
                                                                                           
                                                                                                      
/// an empty glob REFUSES.
pub fn verify_order_membership_all_initrds(
    order_output: &str,
    premount_name: &str,
) -> Result<(), ReclaimRefusal> {
    let sections = frame_initrds(order_output, "ORDER-INITRD:");
    if sections.is_empty() {
        return Err(ReclaimRefusal::new(
            rows::INITRAMFS,
            "the ORDER check enumerated no kernel-paired initrd (/boot/initrd.img-* matched \
             nothing, or none had a matching /boot/vmlinu[xz]-<v>) — the premount script cannot be \
             confirmed to run (row R-INITRAMFS)",
        ));
    }
    for (path, body) in &sections {
        if !body.lines().any(|l| l.contains(premount_name)) {
            return Err(ReclaimRefusal::new(
                rows::INITRAMFS,
                format!(
                    "the premount script is ABSENT from {path}'s scripts/local-premount/ORDER — \
                     it would never run there (the installer's set_initlist contracts; the -k all rebuild scope, \
                     this initrd paired with an installed kernel)"
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod hook_tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn required_set_missing_binary_refuses_usr_merged_passes() {
                                                                                     
        let full = "usr/sbin/e2fsck\nusr/sbin/resize2fs\nusr/sbin/sfdisk\nusr/sbin/dumpe2fs\n";
        assert!(verify_required_set(full).is_ok());
        let missing = "usr/sbin/e2fsck\nusr/sbin/resize2fs\nusr/sbin/dumpe2fs\n";
        let err = verify_required_set(missing).unwrap_err();
        assert_eq!(err.row, rows::INITRAMFS);
        assert!(err.reason.contains("sfdisk"), "{err}");
    }

    #[test]
    fn required_set_refuses_each_member_absent_in_turn() {
        for absent in REQUIRED_BINARIES {
            let listing: String = REQUIRED_BINARIES
                .iter()
                .filter(|b| **b != absent)
                .map(|b| format!("usr/sbin/{b}\n"))
                .collect();
            let err = verify_required_set(&listing).unwrap_err();
            assert!(err.reason.contains(absent), "{err}");
        }
    }

    #[test]
    fn all_initrds_helpers_check_each_and_refuse_an_empty_glob() {
                                                                                                
                                                                                                    
        let full = "usr/sbin/e2fsck\nusr/sbin/resize2fs\nusr/sbin/sfdisk\nusr/sbin/dumpe2fs\n";
        let two_ok = format!(
            "INITRD:/boot/initrd.img-a\n{full}INITRD:/boot/initrd.img-b\n{full}INITRD-COUNT:2"
        );
        assert!(verify_required_set_all_initrds(&two_ok).is_ok());
                                                                              
        let one_bad = format!(
            "INITRD:/boot/initrd.img-a\n{full}\
             INITRD:/boot/initrd.img-b\nusr/sbin/e2fsck\nusr/sbin/resize2fs\nusr/sbin/dumpe2fs\n"
        );
        let e = verify_required_set_all_initrds(&one_bad).unwrap_err();
        assert!(
            e.row == rows::INITRAMFS
                && e.reason.contains("initrd.img-b")
                && e.reason.contains("sfdisk"),
            "{e}"
        );
                                                       
        let e = verify_required_set_all_initrds("INITRD-COUNT:0").unwrap_err();
        assert!(
            e.reason.contains("enumerated no kernel-paired initrd"),
            "{e}"
        );

                                        
        let order_ok = "ORDER-INITRD:/boot/initrd.img-a\nscripts/local-premount/orchard-reclaim\n\
             ORDER-INITRD:/boot/initrd.img-b\nscripts/local-premount/orchard-reclaim\nORDER-DONE";
        assert!(verify_order_membership_all_initrds(order_ok, PREMOUNT_SCRIPT_NAME).is_ok());
        let order_bad = "ORDER-INITRD:/boot/initrd.img-a\nscripts/local-premount/orchard-reclaim\n\
             ORDER-INITRD:/boot/initrd.img-b\nscripts/local-premount/resume\nORDER-DONE";
        let e = verify_order_membership_all_initrds(order_bad, PREMOUNT_SCRIPT_NAME).unwrap_err();
        assert!(
            e.reason.contains("initrd.img-b") && e.reason.contains("ABSENT"),
            "{e}"
        );
        let e =
            verify_order_membership_all_initrds("ORDER-DONE", PREMOUNT_SCRIPT_NAME).unwrap_err();
        assert!(
            e.reason.contains("enumerated no kernel-paired initrd"),
            "{e}"
        );
    }

    /// Run one of the three initrd-enumeration constants against a fake `/boot`, returning the
    /// BASENAMES it framed (`INITRD:` / `ORDER-INITRD:` / `LS-OK:`/`LS-FAIL:`). Test-only: the
    /// hardcoded `/boot/` is repointed at the fixture dir so the pairing filter under audit runs on
    /// real files; `lsinitramfs`/`unmkinitramfs` are absent in the test env, but every frame line is
    /// emitted BEFORE those calls, so the enumerated SET is faithful.
    fn framed_initrds(cmd_const: &str, boot: &std::path::Path) -> Vec<String> {
        let script = cmd_const.replace("/boot/", &format!("{}/", boot.display()));
        let out = Command::new("sh").arg("-c").arg(&script).output().unwrap();
        let mut names: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                l.strip_prefix("INITRD:")
                    .or_else(|| l.strip_prefix("ORDER-INITRD:"))
                    .or_else(|| l.strip_prefix("LS-OK:"))
                    .or_else(|| l.strip_prefix("LS-FAIL:"))
            })
            .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn landing_and_disarm_enumerate_only_kernel_paired_initrds() {
                                                                                      
                                                                                                     
                                                                                               
                                                                                                       
                                                                                                 
                                                 
        let boot = tempfile::tempdir().unwrap();
        let touch = |name: &str| std::fs::write(boot.path().join(name), b"x").unwrap();
                                                                                          
        touch("initrd.img-6.1.0-0-amd64");
        touch("vmlinuz-6.1.0-0-amd64");
        touch("initrd.img-6.1.0-1-amd64");
        touch("vmlinuz-6.1.0-1-amd64");
                                                                                                    
        touch("initrd.img-6.1.0-0-amd64.bak");
                                                                                                        
        touch("initrd.img-6.1.0-0-amd64.dpkg-bak");
                                                                                                
        touch("initrd.img-5.10.0-orphan");

        let paired = vec![
            "initrd.img-6.1.0-0-amd64".to_string(),
            "initrd.img-6.1.0-1-amd64".to_string(),
        ];
        assert_eq!(
            framed_initrds(super::ceremony::LSINITRAMFS_CMD, boot.path()),
            paired,
            "LSINITRAMFS_CMD must frame only kernel-paired initrds (cases B/D excluded)"
        );
        assert_eq!(
            framed_initrds(super::ceremony::ORDER_CMD, boot.path()),
            paired,
            "ORDER_CMD must frame only kernel-paired initrds (cases B/D excluded)"
        );
        assert_eq!(
            framed_initrds(super::post::DISARM_VERIFY_CMD, boot.path()),
            paired,
            "DISARM_VERIFY_CMD must enumerate only kernel-paired initrds — a stale armed .bak/.dpkg-bak \
             copy (case C) cannot report a disarmed target as still armed"
        );
    }

    #[test]
    fn the_three_initrd_constants_carry_the_kernel_pairing_filter() {
                                                                                              
                                                                                                   
                                                       
        for c in [
            super::ceremony::LSINITRAMFS_CMD,
            super::ceremony::ORDER_CMD,
            super::post::DISARM_VERIFY_CMD,
        ] {
            assert!(
                c.contains("v=${f#/boot/initrd.img-}")
                    && c.contains(
                        "[ -e \"/boot/vmlinuz-$v\" ] || [ -e \"/boot/vmlinux-$v\" ] || continue"
                    ),
                "the kernel-pairing filter is missing from: {c}"
            );
        }
    }

    #[test]
    fn hook_carries_prereqs_preamble_and_derived_copy_exec_lines() {
        let s = render_hook();
        assert!(s.contains("case $1 in"));
        assert!(s.contains("prereqs)"));
        for b in REQUIRED_BINARIES {
            assert!(s.contains(&format!("copy_exec /sbin/{b}")), "missing {b}");
        }
        assert!(!s.contains('@'), "no unrendered token may remain");
    }

    #[test]
    fn hook_prereqs_invocation_emits_no_tokens_and_touches_nothing() {
                                                                                   
                                                                      
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HOOK_NAME);
        write_rendered_0755(&path, &render_hook()).unwrap();
        let out = Command::new("sh")
            .arg(&path)
            .arg("prereqs")
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "");
        assert_eq!(out.status.code(), Some(0));
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn hook_sh_syntax_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HOOK_NAME);
        write_rendered_0755(&path, &render_hook()).unwrap();
        let out = Command::new("sh").arg("-n").arg(&path).output().unwrap();
        assert!(
            out.status.success(),
            "sh -n: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
