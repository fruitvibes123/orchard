                                                                                               
                                                                                                
//! existing `render_pre_wipe_summary` output and `DESTRUCTIVE_ADVISORY` const; with no flag both
//! compositions are `None`, so the no-flag output is byte-identical to today's by construction
//! (AC-R31's first arm).

use super::Geometry;
use super::eligibility::DoomedPartition;

                                                                                  
/// `--wipe-confirmed` does not imply it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReclaimConfirmed(());

impl ReclaimConfirmed {
    pub fn from_flag(reclaim_tail_flag: bool) -> Option<Self> {
        if reclaim_tail_flag {
            Some(Self(()))
        } else {
            None
        }
    }
}

                                                                                     
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimDecision {
    /// D-1 refused and every read-only check admitted the target: the writing half will run.
    WillRun,
    /// D-1 passed; §5.2 short-circuited. Nothing will be shrunk.
    ShortCircuit,
}

                                                                                        
/// destructive summary when the reclaim will run; the stated no-op when §5.2 short-circuited.
pub fn summary_row(decision: Option<ReclaimDecision>) -> Option<String> {
    match decision {
        None => None,
        Some(ReclaimDecision::WillRun) => Some(
            "\n  reclaim-tail    WILL RUN: shrink the root filesystem and its partition, purge \
             cloud-initramfs-growroot, disable cloud-init, strip x-systemd.growfs from every \
             /etc/fstab entry, reboot the target once"
                .to_string(),
        ),
        Some(ReclaimDecision::ShortCircuit) => Some(
            "\n  reclaim-tail    no-op: the staging window already intersects nothing (D-1 \
             passes); nothing will be shrunk, purged, disabled or edited"
                .to_string(),
        ),
    }
}

                                                                                             
/// the short-circuit branch none of the six actions happens and the clause is omitted.
pub fn advisory_clause(decision: Option<ReclaimDecision>) -> Option<String> {
    match decision {
        Some(ReclaimDecision::WillRun) => Some(
            "\n  * RECLAIM-TAIL RUNS BEFORE STAGING. Before any image byte moves, this ceremony \
             SHRINKS the root filesystem, REWRITES its partition-table entry, PURGES \
             cloud-initramfs-growroot, DISABLES cloud-init, STRIPS x-systemd.growfs from every \
             /etc/fstab entry carrying it, and REBOOTS the target once. The neutralizations are \
             permanent (nothing restores them, on any path)."
                .to_string(),
        ),
        _ => None,
    }
}

                                                                                                     
                                                                                         
pub const RECLAIM_STANDALONE_PRECONFIRM: &str = "reclaim-tail permanently modifies the target (filesystem+partition shrink, growroot purge, \
     cloud-init disable, every-entry fstab edit, one reboot); pass --confirmed to proceed";

                                                                      
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPoint {
    /// `orchard prod --reclaim-tail`: the wipe gate has already authorized erasing the disk.
    Prod,
                                                                          
    Standalone,
}

/// Inputs to the §4 plan block. All byte quantities; formatting converts at the render boundary.
#[derive(Debug, Clone)]
pub struct PlanInputs {
    pub ip: String,
    pub disk: String,
    pub disk_bytes: u64,
    /// The non-doomed sibling partitions, as (name, start, end).
    pub siblings: Vec<(String, u64, u64)>,
    pub part: DoomedPartition,
    pub fs_bytes: u64,
    pub fs_used_bytes: u64,
    pub block_size: u64,
    pub window_offset: u64,
    pub img_len: u64,
    pub geometry: Geometry,
    pub timeout_secs: u64,
}

fn gib(bytes: u64) -> String {
    format!("{:.2} GiB", bytes as f64 / (1u64 << 30) as f64)
}

                                                                                            
                                                                                                
pub fn render_plan(i: &PlanInputs, path: EntryPoint) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "reclaim-tail plan for {}  (/dev/{}, {} bytes)\n\n",
        i.ip, i.disk, i.disk_bytes
    ));
    for (idx, (name, start, end)) in i.siblings.iter().enumerate() {
        let label = if idx == 0 {
            "  siblings   "
        } else {
            "             "
        };
        s.push_str(&format!("{label} /dev/{name}  [{start}, {end})\n"));
    }
    s.push_str(&format!(
        "  partition   {}   ext4, mounted at /   [{}, {})   <- last by end offset\n",
        i.part.node, i.part.start, i.part.end
    ));
    s.push_str(&format!(
        "  filesystem  used {} of {}   (block size {})\n",
        gib(i.fs_used_bytes),
        gib(i.fs_bytes),
        i.block_size
    ));
    s.push_str(&format!(
        "  window      needs                [{}, {})\n              for a {}-byte image\n\n",
        i.window_offset,
        i.window_offset.saturating_add(i.img_len),
        i.img_len
    ));
    s.push_str(&format!(
        "  proposed    shrink filesystem to {}   ({} blocks)\n",
        gib(i.geometry.planned_size),
        i.geometry.target_blocks
    ));
    s.push_str(&format!(
        "              shrink {} to  [{}, {})\n",
        i.part.node, i.part.start, i.geometry.planned_end
    ));
    s.push_str(&format!(
        "              gives up             {} at the disk tail\n\n",
        gib(i.part.end.saturating_sub(i.geometry.planned_end))
    ));
    s.push_str(
        "  method      one-shot script in the target's own initramfs; ONE reboot\n\
         \x20             (a second may be needed if the kernel does not re-read the table)\n\
         \x20 after       the window lands in unpartitioned space and D-1 is re-run\n\n",
    );
    s.push_str("  THIS IS THE POINT WHERE THE TARGET'S PARTITION TABLE STOPS BEING UNTOUCHED.\n");
    match path {
        EntryPoint::Prod => {
            s.push_str("  You have already authorized erasing this disk (wipe gate, above).\n");
        }
        EntryPoint::Standalone => {
            s.push_str(
                "  You have authorized preparing this disk; you have NOT authorized erasing it.\n",
            );
        }
    }
    s.push_str(
        "  TAKE A SNAPSHOT FIRST. This ceremony cannot verify one exists, and a snapshot\n\
         \x20 is the only recovery from the two failures below.\n\
         \x20 The reboot is not optional, and the reclaim cannot be cancelled once it starts.\n\
         \x20 e2fsck repairs the filesystem before the shrink and may alter data.\n\
         \x20 A reset while the filesystem is being shrunk can leave it UNRECOVERABLE.\n\
         \x20 If the target does not come back, recovery is the snapshot or re-provisioning.\n",
    );
    s.push_str(&format!(
        "  Expect up to {}s with no contact.\n",
        i.timeout_secs
    ));
    s.push_str(
        "  This permanently removes cloud-initramfs-growroot, permanently disables\n\
         \x20 cloud-init, and permanently removes the x-systemd.growfs option from every\n\
         \x20 /etc/fstab entry that carries it on this target. None is restored, on any path. Any provider\n\
         \x20 panel features implemented through cloud-init (commonly SSH-key injection,\n\
         \x20 password reset, network reconfiguration) would stop taking effect once it is\n\
         \x20 disabled -- UNVERIFIED which of them this provider routes through cloud-init.\n\
         \x20 Whether the existing network setup survives without cloud-init is likewise\n\
         \x20 UNVERIFIED on this provider; if it does not come back, the recovery above applies.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::prod_orchestrate::DESTRUCTIVE_ADVISORY;

    #[test]
    fn reclaim_confirmed_only_from_its_own_flag() {
        assert!(ReclaimConfirmed::from_flag(false).is_none());
        assert!(ReclaimConfirmed::from_flag(true).is_some());
    }

    #[test]
    fn three_renderings_no_flag_will_run_short_circuit() {
                                                                                        
                                     
        assert!(summary_row(None).is_none());
        assert!(advisory_clause(None).is_none());
        let composed = format!(
            "{DESTRUCTIVE_ADVISORY}{}",
            advisory_clause(None).unwrap_or_default()
        );
        assert_eq!(composed, DESTRUCTIVE_ADVISORY);

                                                                           
        let row = summary_row(Some(ReclaimDecision::WillRun)).unwrap();
        let clause = advisory_clause(Some(ReclaimDecision::WillRun)).unwrap();
        for (token_row, token_clause) in [
            ("shrink", "SHRINKS"),
            ("partition", "partition-table"),
            ("purge", "PURGES"),
            ("cloud-init", "cloud-init"),
            ("fstab", "fstab"),
            ("reboot", "REBOOTS"),
        ] {
            assert!(row.contains(token_row), "row missing {token_row}: {row}");
            assert!(
                clause.contains(token_clause),
                "clause missing {token_clause}: {clause}"
            );
        }

                                                                                             
        let row = summary_row(Some(ReclaimDecision::ShortCircuit)).unwrap();
        assert!(row.contains("no-op"), "{row}");
        assert!(advisory_clause(Some(ReclaimDecision::ShortCircuit)).is_none());
    }

    fn worked_inputs() -> PlanInputs {
                                                                          
        PlanInputs {
            ip: "203.0.113.10".into(),
            disk: "vda".into(),
            disk_bytes: 42949672960,
            siblings: vec![
                ("vda14".into(), 1048576, 4194304),
                ("vda15".into(), 4194304, 134217728),
            ],
            part: DoomedPartition {
                sysfs: "vda1".into(),
                node: "/dev/vda1".into(),
                num: 1,
                start: 134217728,
                end: 42948624384,
            },
            fs_bytes: 42814406656,
            fs_used_bytes: 1943527424,
            block_size: 4096,
            window_offset: 41053847552,
            img_len: 1892036608,
            geometry: Geometry {
                part_start: 134217728,
                planned_end: 41052798976,
                planned_size: 40918581248,
                target_blocks: 9989888,
            },
            timeout_secs: 1800,
        }
    }

    #[test]
    fn plan_block_carries_the_worked_arithmetic_and_disclosures() {
        let s = render_plan(&worked_inputs(), EntryPoint::Prod);
                                        
        for needle in [
            "203.0.113.10",
            "(/dev/vda, 42949672960 bytes)",
            "/dev/vda14",
            "/dev/vda15",
            "[134217728, 42948624384)   <- last by end offset",
            "used 1.81 GiB of 39.87 GiB   (block size 4096)",
            "[41053847552, 42945884160)",
            "for a 1892036608-byte image",
            "shrink filesystem to 38.11 GiB   (9989888 blocks)",
            "shrink /dev/vda1 to  [134217728, 41052798976)",
            "gives up             1.77 GiB at the disk tail",
            "ONE reboot",
            "THIS IS THE POINT WHERE THE TARGET'S PARTITION TABLE STOPS BEING UNTOUCHED.",
            "TAKE A SNAPSHOT FIRST",
            "cannot be cancelled once it starts",
            "e2fsck repairs the filesystem before the shrink and may alter data",
            "UNRECOVERABLE",
            "Expect up to 1800s with no contact.",
            "permanently removes cloud-initramfs-growroot",
            "UNVERIFIED which of them this provider routes through cloud-init",
            "network setup survives without cloud-init is likewise",
        ] {
            assert!(s.contains(needle), "plan block missing {needle:?}:\n{s}");
        }
    }

    #[test]
    fn plan_block_is_path_dependent_r108() {
        let prod = render_plan(&worked_inputs(), EntryPoint::Prod);
        assert!(prod.contains("You have already authorized erasing this disk (wipe gate, above)."));
        assert!(!prod.contains("NOT authorized erasing"));
        let standalone = render_plan(&worked_inputs(), EntryPoint::Standalone);
        assert!(standalone.contains(
            "You have authorized preparing this disk; you have NOT authorized erasing it."
        ));
        assert!(!standalone.contains("wipe gate, above"));
    }

    #[test]
    fn fstab_scope_disclosure_is_every_entry_not_root_only() {
                                                                                                     
                                                                                                    
                                                                                                     
                                                                                                   
                                                                                                     
                                                                                                    
                                                                                                     
                                          
        let collapse = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let row = summary_row(Some(ReclaimDecision::WillRun)).unwrap();
        let clause = advisory_clause(Some(ReclaimDecision::WillRun)).unwrap();
        let prod = render_plan(&worked_inputs(), EntryPoint::Prod);
        let standalone = render_plan(&worked_inputs(), EntryPoint::Standalone);
        let advisory = crate::deploy::reclaim::ceremony::RECLAIM_STANDALONE_ADVISORY.to_string();
        let note = crate::deploy::prod_orchestrate::RECLAIM_STANDING_NOTE.to_string();
        for s in [&row, &clause, &prod, &standalone, &advisory, &note] {
            assert!(
                !collapse(s).contains("root fstab"),
                "narrows the fstab scope to root-only: {s}"
            );
            assert!(
                collapse(s).contains("every /etc/fstab entry"),
                "does not disclose the EVERY-entry scope (a weak proxy admits 'root /etc/fstab entry'): {s}"
            );
        }
                                                                                                     
        assert!(
            !RECLAIM_STANDALONE_PRECONFIRM.contains("root fstab")
                && RECLAIM_STANDALONE_PRECONFIRM.contains("every-entry"),
            "pre-confirm narrows the fstab scope: {RECLAIM_STANDALONE_PRECONFIRM}"
        );
    }
}
