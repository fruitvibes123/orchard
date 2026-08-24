//! The §5/§5a ceremony halves (plan T9): the read-only half run at the D-1 slot, and the writing
//! half run after the wipe gate, both composed into `deploy_prod` by the splice. The standalone
//! verb (T10) reuses both with `EntryPoint::Standalone`.
//!
//! Refusals bubble as `ReclaimRefusal` (§7 rows) and are stringified at the `deploy_prod`
//! boundary. Every read-only refusal fires before the disk-name retype (G-5).

use super::consent::{EntryPoint, PlanInputs, ReclaimDecision, render_plan};
use super::eligibility::{
    DPKG_LOCK_PATHS, EligibilityOk, ReclaimCtx, check_eligibility_readonly, dumpe2fs_cmd,
    lock_precheck, parse_dumpe2fs_h, split_rc,
};
use super::post::{BOOT_ID_CMD, PollOutcome, PreReclaimState, arbitrate, disarm, poll_refusal};
use super::{
    Geometry, HOOK_NAME, OpsReader, PREMOUNT_SCRIPT_NAME, PremountInputs,
    RECLAIM_REBOOT_TIMEOUT_SECS, ReclaimRefusal, TargetReader, plan_geometry, render_hook,
    render_premount, rows, would_grow,
};
use crate::deploy::prod::{self, PartitionExtent, RawWindowSpec};
use crate::deploy::prod_orchestrate::{ArmedFailure, Leg, OrchestrationOps, ReclaimAbort};

/// Everything the splice hands the read-only half; every value already exists in `deploy_prod`
/// at the `:1180` slot (§5.1: the reclaim consumes, it re-derives nothing).
pub struct SpliceInputs<'a> {
    pub ip: &'a str,
    /// Bare names, the ceremony's convention.
    pub disk: &'a str,
    pub root_dev: &'a str,
    pub disk_bytes: u64,
    pub window: &'a RawWindowSpec,
    pub img_len: u64,
    /// The `:1120-1145` staged-bytes quantity (kexec pair + restore pair + headroom).
    pub staging_reserve: u64,
    pub extents: &'a [PartitionExtent],
    /// The recorded (not fatal) first D-1 outcome.
    pub d1: Result<(), String>,
    pub timeout_secs: u64,
}

/// The read-only half's product.
pub struct ReadOnlyOutcome {
    pub decision: ReclaimDecision,
    /// Present iff the reclaim will run.
    pub prepared: Option<Prepared>,
    /// Decision 16: on the §5.2 short-circuit branch, whether D8's abort is recorded-not-fatal
    /// (partition end <= planned_end AND the overhang read established fs <= part). On the
    /// will-run branch this is always true (superseded by the post-reclaim re-run).
    pub d8_recorded_not_fatal: bool,
}

/// What the writing half needs, all captured read-only.
pub struct Prepared {
    pub elig: EligibilityOk,
    pub geometry: Geometry,
    pub pre: PreReclaimState,
    pub plan_inputs: PlanInputs,
                                                                                             
    /// (`prepare_read_only`), so a metacharacter in a target-supplied field refuses at row
                                                                                            
    /// verbatim.
    pub premount_script: String,
}

/// The read-only half's refusal → operator text. The two `prepare_read_only` egresses (the prod
/// `read_only_half` and the standalone) are its only callers, so appending the standing note here is
/// the ONE point that keeps every read-only refusal — current or future — from being silent about the
                                                                                                      
/// note is identical to the write-half paths.
fn stringify(e: ReclaimRefusal) -> ReclaimAbort {
    crate::deploy::prod_orchestrate::reclaim_abort_text(e.to_string())
}

/// §5.2–§5.4 on the `prod` path: D-1 recorded; on refusal the full read-only battery runs; on a
                                                                                   
pub(crate) fn read_only_half(
    ops: &mut dyn OrchestrationOps,
    i: &SpliceInputs<'_>,
) -> Result<ReadOnlyOutcome, ReclaimAbort> {
                                                                                     
                                                                                                     
                                                                                                  
                                                                                
    let mut reader = OpsReader(ops);
    match &i.d1 {
        Ok(()) => {
                                                                                                  
                                                                                              
            let d8 = short_circuit_d8_conjunction(&mut reader, i).unwrap_or(false);
            Ok(ReadOnlyOutcome {
                decision: ReclaimDecision::ShortCircuit,
                prepared: None,
                d8_recorded_not_fatal: d8,
            })
        }
        Err(_) => {
            let prepared = prepare_read_only(&mut reader, i).map_err(stringify)?;
            Ok(ReadOnlyOutcome {
                decision: ReclaimDecision::WillRun,
                prepared: Some(prepared),
                d8_recorded_not_fatal: true,
            })
        }
    }
}

/// Decision 16's conjunction on the short-circuit branch: root partition end <= `planned_end`
/// AND `fs_bytes <= part_bytes`, with the overhang read taken HERE (read-only; §5.2). Any
/// failure to establish either conjunct yields false (no relaxation).
fn short_circuit_d8_conjunction(
    reader: &mut dyn TargetReader,
    i: &SpliceInputs<'_>,
) -> Option<bool> {
    let root_name = i.root_dev;
    let root = i.extents.iter().find(|e| e.name == root_name)?;
    let out = reader
        .capture(&dumpe2fs_cmd(&format!("/dev/{root_name}")))
        .ok()?;
    let (body, rc) = split_rc(&out, "dumpe2fs -h").ok()?;
    if rc != 0 {
        return Some(false);
    }
    let (count, size) = parse_dumpe2fs_h(&body).ok()?;
    let fs_bytes = count.saturating_mul(size);
    let part_bytes = root.end.saturating_sub(root.start);
    let geometry = plan_geometry(i.window.offset, root.start, size).ok()?;
    Some(root.end <= geometry.planned_end && fs_bytes <= part_bytes)
}

/// §5.3–§5.4: eligibility, lock pre-check, would-grow, feasibility, geometry.
fn prepare_read_only(
    reader: &mut dyn TargetReader,
    i: &SpliceInputs<'_>,
) -> Result<Prepared, ReclaimRefusal> {
    let ctx = ReclaimCtx {
        disk: i.disk.to_string(),
        root_dev: format!("/dev/{}", i.root_dev),
        window_offset: i.window.offset,
        window_len: i.window.len,
    };
                                                                                                    
                                                                                                       
                                                                                                           
    let elig = check_eligibility_readonly(reader, &ctx, i.extents)?;
    lock_precheck(reader, &DPKG_LOCK_PATHS)?;

                                          
    let geometry = plan_geometry(i.window.offset, elig.part.start, elig.block_size)?;
    if would_grow(geometry.target_blocks, elig.block_size, elig.fs_bytes) {
        return Err(ReclaimRefusal::new(
            rows::WOULD_GROW,
            format!(
                "the plan would GROW the filesystem: target_blocks {} x block_size {} > \
                 fs_bytes {}; the reclaim grows nothing",
                geometry.target_blocks, elig.block_size, elig.fs_bytes
            ),
        ));
    }
    let used = read_df_used_bytes(reader)?;
    let projected = used.saturating_add(i.staging_reserve);
    if projected > geometry.planned_size {
        return Err(ReclaimRefusal::new(
            rows::FIT,
            format!(
                "projected size does not fit: used {used} + staging reserve {} = {projected} > \
                 planned size {} (§5.4; df-used is a lower bound — resize2fs's true minimum is \
                 higher)",
                i.staging_reserve, geometry.planned_size
            ),
        ));
    }
    let mut siblings: Vec<(String, u64, u64)> = i
        .extents
        .iter()
        .filter(|e| e.name != elig.part.sysfs)
        .map(|e| (e.name.clone(), e.start, e.end))
        .collect();
    siblings.sort_by_key(|(_, start, _)| *start);
    let plan_inputs = PlanInputs {
        ip: i.ip.to_string(),
        disk: i.disk.to_string(),
        disk_bytes: i.disk_bytes,
        siblings,
        part: elig.part.clone(),
        fs_bytes: elig.fs_bytes,
        fs_used_bytes: used,
        block_size: elig.block_size,
        window_offset: i.window.offset,
        img_len: i.img_len,
        geometry,
        timeout_secs: i.timeout_secs,
    };
                                                                                           
                                                                                                  
                                                                                                 
                                                                                             
    let premount_script = render_premount(&PremountInputs {
        disk: i.disk.to_string(),
        part_num: elig.part.num,
        part_node: elig.part.node.clone(),
        part_sysfs: elig.part.sysfs.clone(),
        part_start: elig.part.start,
        part_end_original: elig.part.end,
        planned_end: geometry.planned_end,
        target_blocks: geometry.target_blocks,
    })?;
    Ok(Prepared {
        pre: PreReclaimState {
            root_dev: i.root_dev.to_string(),
            disk: i.disk.to_string(),
        },
        elig,
        geometry,
        plan_inputs,
        premount_script,
    })
}

/// §5.4's `used` lower bound, from `df -P -k /` (the third column of the root row).
pub const DF_USED_CMD: &str = "df -P -k /";

fn read_df_used_bytes(reader: &mut dyn TargetReader) -> Result<u64, ReclaimRefusal> {
    let out = reader.capture(DF_USED_CMD).map_err(|e| {
        ReclaimRefusal::new(
            rows::FIT,
            format!("df read for the feasibility check failed: {e}"),
        )
    })?;
    for line in out.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 6
            && let Ok(kib) = f[2].parse::<u64>()
        {
            return Ok(kib.saturating_mul(1024));
        }
    }
    Err(ReclaimRefusal::new(
        rows::FIT,
        "unparseable df output for the feasibility check — refusing fail-closed (§5.4)",
    ))
}

                                                                                                   

                                                                                       
/// interactively; on a non-TTY the flag alone authorizes, so gates run unattended. The decline is
/// pre-write; its text carries the unconditional standing note via `reclaim_abort_text`.
pub(crate) fn plan_and_consent(
    ops: &mut dyn OrchestrationOps,
    prepared: &Prepared,
    path: EntryPoint,
) -> Result<(), ReclaimAbort> {
                                                                                                   
                                                                                                    
    let plan = render_plan(&prepared.plan_inputs, path);
    ops.say(&plan);
    if ops.stdin_is_tty() {
        let line = ops
            .read_line("authorize the reclaim? [y/N] ")
            .unwrap_or_default();
        if line.trim() != "y" && line.trim() != "Y" {
            return Err(crate::deploy::prod_orchestrate::reclaim_abort_text(
                "operator declined the reclaim plan (row R-DECLINE); nothing was written",
            ));
        }
    }
    Ok(())
}

pub fn hook_write_cmd(content: &str) -> String {
                                                                                           
                                                                                              
                                                                                                  
                      
    format!(
        "mkdir -p /etc/initramfs-tools/hooks && \
         cat > /etc/initramfs-tools/hooks/{HOOK_NAME} <<'ORCHARD_RECLAIM_HOOK' && \
         chmod 755 /etc/initramfs-tools/hooks/{HOOK_NAME}\n\
         {content}ORCHARD_RECLAIM_HOOK\n\
         echo RC:$?"
    )
}

pub fn premount_write_cmd(content: &str) -> String {
                                                                                         
    format!(
        "mkdir -p /etc/initramfs-tools/scripts/local-premount && \
         cat > /etc/initramfs-tools/scripts/local-premount/{PREMOUNT_SCRIPT_NAME} \
         <<'ORCHARD_RECLAIM_PREMOUNT' && \
         chmod 755 /etc/initramfs-tools/scripts/local-premount/{PREMOUNT_SCRIPT_NAME}\n\
         {content}ORCHARD_RECLAIM_PREMOUNT\n\
         echo RC:$?"
    )
}

                                                                                           
/// conservative form.
pub const REBUILD_CMD: &str = "update-initramfs -u -k all 2>/dev/null 1>&2; echo RC:$?";

                                                                                          
                                                                               
/// `/boot/vmlinu[xz]-<v>` and `/boot/initrd.img-<v>` exist (`get_sorted_versions` over
/// `linux-version list`, `initramfs-tools 0.142+deb12u3`), so each command pairs every
/// `/boot/initrd.img-<v>` with an installed kernel and skips the rest: a `.bak`/`.dpkg-bak`/orphan
/// initrd the rebuild never rewrote is neither read nor reported. Reading only the running kernel's
                                                                                                 
/// kernel — the class enables `unattended-upgrades`, which installs one. Each PAIRED initrd is
/// framed with `INITRD:`/`ORDER-INITRD:` so the host checks the required set and ORDER membership
/// PER initrd. `[ -e "$f" ]` guards the literal glob a no-match leaves in POSIX sh.
pub const LSINITRAMFS_CMD: &str = "rc=0; n=0; for f in /boot/initrd.img-*; do [ -e \"$f\" ] || continue; \
     v=${f#/boot/initrd.img-}; [ -e \"/boot/vmlinuz-$v\" ] || [ -e \"/boot/vmlinux-$v\" ] || continue; \
     n=$((n+1)); echo \"INITRD:$f\"; lsinitramfs \"$f\" 2>/dev/null || rc=1; done; \
     echo \"INITRD-COUNT:$n\"; echo RC:$rc";

pub const ORDER_CMD: &str = "for f in /boot/initrd.img-*; do [ -e \"$f\" ] || continue; \
     v=${f#/boot/initrd.img-}; [ -e \"/boot/vmlinuz-$v\" ] || [ -e \"/boot/vmlinux-$v\" ] || continue; \
     echo \"ORDER-INITRD:$f\"; d=$(mktemp -d) && unmkinitramfs \"$f\" \"$d\" 2>/dev/null; \
     cat \"$d\"/*/scripts/local-premount/ORDER \"$d\"/scripts/local-premount/ORDER 2>/dev/null; \
     rm -rf \"$d\"; done; echo ORDER-DONE";

pub const REBOOT_CMD: &str = "nohup reboot >/dev/null 2>&1 & echo REBOOT-ISSUED";

super::closed_enum_table! {
    /// EVERY Err exit of `install_and_arm` past `neutralize`, one variant per site — the closed set
    /// the consequence census covers by SET-EQUALITY against `ALL` (the same floor as
    /// [`super::neutralize::NeutralizeExit`]). The value is the §7 row: uniformly `R-INITRAMFS`
    /// (the target is modified — marker written, growroot purged, fstab rewritten — and the hook
    /// may be on it), derived at the ONE constructor `armed` so no site names a row by hand and
                                                                                
    enum InstallExit -> &'static str {
        HookWriteTransport => rows::INITRAMFS,
        HookWriteSplitRc => rows::INITRAMFS,
        HookWriteRc => rows::INITRAMFS,
        PremountWriteTransport => rows::INITRAMFS,
        PremountWriteSplitRc => rows::INITRAMFS,
        PremountWriteRc => rows::INITRAMFS,
        RebuildTransport => rows::INITRAMFS,
        RebuildSplitRc => rows::INITRAMFS,
        RebuildRc => rows::INITRAMFS,
        LsinitramfsTransport => rows::INITRAMFS,
        LsinitramfsSplitRc => rows::INITRAMFS,
        LsinitramfsRc => rows::INITRAMFS,
        RequiredSetMissing => rows::INITRAMFS,
        OrderTransport => rows::INITRAMFS,
        OrderIncomplete => rows::INITRAMFS,
        OrderMembershipMissing => rows::INITRAMFS,
    }
    fn = row
}

/// The ONE constructor of a post-neutralize `install_and_arm` failure: the variant is
/// `AfterInstall` and the row comes from the exit's table entry. Adding an Err exit without
/// declaring an `InstallExit` variant does not compile; declaring one grows `InstallExit::ALL` and
/// fails the census set-equality until an arm drives it.
fn armed(exit: InstallExit, reason: impl Into<String>) -> InstallFailure {
    InstallFailure::AfterInstall {
        exit,
        refusal: ReclaimRefusal::new(exit.row(), reason),
    }
}

                                                                                                   
/// refused, so THIS run wrote no reclaim hook: there is no hook file to remove, so no cleanup runs.
/// The caller (`route_install_failure`) routes it to `no_disarm_outcome`, whose text — like every
/// reclaim-region failure — carries the unconditional standing note (`reclaim_abort_text`); the
/// per-arm permanence computation that treadmilled R6→R11 is gone. `AfterInstall` — a
                                                                                                 
/// meaningful, and all three neutralizations landed. The §7 row was a PROXY for the hook fact (three
/// `R-NEUTRALIZE` arms fire with the hook unwritten); the variant threads it, as `reclaim_done` does
/// for the staging wraps. Both variants carry their EXIT id, so the census proves coverage of the
                                                                                        
#[derive(Debug)]
pub(crate) enum InstallFailure {
    BeforeInstall {
        /// Which `neutralize` exit fired — read by the census set-equality floor (test cfg).
        #[cfg_attr(not(test), allow(dead_code))]
        exit: super::neutralize::NeutralizeExit,
        refusal: ReclaimRefusal,
    },
    AfterInstall {
        /// Which post-neutralize exit fired — read by the census set-equality floor (test cfg).
        #[cfg_attr(not(test), allow(dead_code))]
        exit: InstallExit,
        refusal: ReclaimRefusal,
    },
}

/// §5.6–§5.7: neutralize, install the hook + premount script, rebuild, verify both landing
                                                                              
/// `InstallFailure::BeforeInstall` wraps a `neutralize` refusal (rows `R-ELIG`/`R-NEUTRALIZE`) —
/// this run wrote no hook, so the call sites route it to `no_disarm_outcome` with no cleanup;
/// `InstallFailure::AfterInstall` wraps a refusal at or after the hook write (row `R-INITRAMFS`) —
/// the hook may be on the target, so the call sites run `append_disarm_outcome`'s disarm.
pub(crate) fn install_and_arm(
    ops: &mut dyn OrchestrationOps,
    prepared: &Prepared,
) -> Result<(), InstallFailure> {
    let mut reader = OpsReader(ops);
                                                                                           
                                                                                                    
                                                                                                  
                                                                                                    
                                                                                                 
                                          
    super::neutralize::neutralize(&mut reader).map_err(|nr| InstallFailure::BeforeInstall {
        exit: nr.exit,
        refusal: nr.refusal,
    })?;

                                                                                               
                                                                                                 
                                                              
    use InstallExit as X;
    let premount: &str = &prepared.premount_script;
    for (what, cmd, transport, splitrc, rc_exit) in [
        (
            "hook",
            hook_write_cmd(&render_hook()),
            X::HookWriteTransport,
            X::HookWriteSplitRc,
            X::HookWriteRc,
        ),
        (
            "premount script",
            premount_write_cmd(premount),
            X::PremountWriteTransport,
            X::PremountWriteSplitRc,
            X::PremountWriteRc,
        ),
    ] {
        let out = reader
            .capture(&cmd)
            .map_err(|e| armed(transport, format!("writing the {what} failed to run: {e}")))?;
        let (_, rc) = split_rc(&out, what).map_err(|e| armed(splitrc, e.reason))?;
        if rc != 0 {
            return Err(armed(
                rc_exit,
                format!("writing the {what} failed (rc {rc})"),
            ));
        }
    }
    let (_, rc) = split_rc(
        &reader.capture(REBUILD_CMD).map_err(|e| {
            armed(
                X::RebuildTransport,
                format!("initramfs rebuild failed to run: {e}"),
            )
        })?,
        "update-initramfs",
    )
    .map_err(|e| armed(X::RebuildSplitRc, e.reason))?;
    if rc != 0 {
        return Err(armed(
            X::RebuildRc,
            format!(
                "update-initramfs failed (rc {rc}) — the previous initrd is still in place \
                 (atomic build-to-.new + mv)"
            ),
        ));
    }
                                                                                              
                                                                                   
    let (listing, rc) = split_rc(
        &reader.capture(LSINITRAMFS_CMD).map_err(|e| {
            armed(
                X::LsinitramfsTransport,
                format!("lsinitramfs failed to run: {e}"),
            )
        })?,
        "lsinitramfs",
    )
    .map_err(|e| armed(X::LsinitramfsSplitRc, e.reason))?;
    if rc != 0 {
        return Err(armed(
            X::LsinitramfsRc,
            format!("lsinitramfs could not read a rebuilt initrd (rc {rc})"),
        ));
    }
                                                                                                   
                                                                                                 
                                                                                                   
    super::verify_required_set_all_initrds(&listing)
        .map_err(|e| armed(X::RequiredSetMissing, e.reason))?;
    let order = reader.capture(ORDER_CMD).map_err(|e| {
        armed(
            X::OrderTransport,
            format!("ORDER verification failed to run: {e}"),
        )
    })?;
    if !order.contains("ORDER-DONE") {
        return Err(armed(
            X::OrderIncomplete,
            "ORDER verification did not complete",
        ));
    }
    super::verify_order_membership_all_initrds(&order, PREMOUNT_SCRIPT_NAME)
        .map_err(|e| armed(X::OrderMembershipMissing, e.reason))?;
    Ok(())
}

/// §5.8–§5.10: reboot, poll `Leg::Provisioning` with the per-tick cancel, fetch the breadcrumb,
/// arbitrate (R8), then the prod-path re-takes (stage_dev + same-partition, the stage free-space
/// gate — row `R-POST-FIT` — and the clock skew). Returns the breadcrumb for the completion
/// report. Every error is an [`ArmedFailure`] — `install_and_arm` succeeded, so the target is
/// armed and the neutralizations are permanent — which no call site can stringify without passing
                                                                                          
#[allow(clippy::too_many_arguments)]
pub(crate) fn reboot_and_arbitrate(
    ops: &mut dyn OrchestrationOps,
    prepared: &Prepared,
    window: &RawWindowSpec,
    real_stage: &str,
    staged_bytes: u64,
    timeout_secs: u64,
    max_clock_skew_secs: i64,
    prod_retakes: bool,
) -> Result<Vec<String>, ArmedFailure> {
                                                                                               
                                                                                                  
                                                                   
    let boot_id_before = {
        let mut reader = OpsReader(ops);
        let id = reader
            .capture(BOOT_ID_CMD)
            .map_err(|e| {
                ArmedFailure::new(
                    rows::LOST_PRE_REBOOT,
                    format!("could not read the target's boot id before the reboot: {e}"),
                )
            })?
            .trim()
            .to_string();
        if id.is_empty() {
            return Err(ArmedFailure::new(
                rows::LOST_PRE_REBOOT,
                "the target's boot id read back empty — refusing to reboot without the \
                 one signal that distinguishes a completed reboot from the pre-reboot \
                 session (§5.8)",
            ));
        }
        let _ = reader.capture(REBOOT_CMD);                                              
        id
    };
    let outcome = {
        let came_back = |ops: &mut dyn OrchestrationOps, before: &str| match ops
            .ssh_capture(Leg::Provisioning, BOOT_ID_CMD)
        {
            Ok(o) => {
                let now = o.trim();
                !now.is_empty() && now != before
            }
            Err(_) => false,
        };
                                                                                    
        let mut elapsed = 0u64;
        loop {
            if ops.cancel_requested() {
                break PollOutcome::Cancelled;
            }
            if came_back(ops, &boot_id_before) {
                break PollOutcome::Alive;
            }
            if elapsed >= timeout_secs {
                break PollOutcome::TimedOut;
            }
            ops.sleep_secs(15);
            elapsed = elapsed.saturating_add(15);
        }
    };
    if let Some(refusal) = poll_refusal(&outcome, timeout_secs) {
        return Err(ArmedFailure::new(refusal.row, refusal.reason));
    }
    let arb = {
        let mut reader = OpsReader(ops);
        arbitrate(&mut reader, &prepared.pre, window)
            .map_err(|e| ArmedFailure::new(e.row, e.reason))?
    };
                                                                                                   
                                                                                        
                                                                                          
                    
    if prod_retakes {
        prod_retake_checks(
            ops,
            real_stage,
            &prepared.pre.root_dev,
            staged_bytes,
            max_clock_skew_secs,
        )
        .map_err(ArmedFailure::mark_completed)?;
    }
    Ok(arb.breadcrumb)
}

/// The §5.10 prod-only re-take checks, ALL structurally past `arbitrate`-Ok. Split from
/// `reboot_and_arbitrate` so the completed-reclaim fact attaches to EVERY error here at the ONE
                                                                                                  
/// each `ArmedFailure::new` below is marked completed by the caller.
fn prod_retake_checks(
    ops: &mut dyn OrchestrationOps,
    real_stage: &str,
    root_dev: &str,
    staged_bytes: u64,
    max_clock_skew_secs: i64,
) -> Result<(), ArmedFailure> {
    let mut reader = OpsReader(ops);
                                                                  
    let fm = reader
        .capture(&format!(
            "findmnt -n -o SOURCE --target {real_stage} || true"
        ))
        .map_err(|e| ArmedFailure::new(rows::POST_FIT, format!("stage_dev re-take failed: {e}")))?;
    let stage_dev = prod::parse_findmnt_source(&fm).ok_or_else(|| {
        ArmedFailure::new(
            rows::POST_FIT,
            "stage_dev re-take: could not resolve the stage partition; aborting",
        )
    })?;
    prod::check_same_partition(root_dev, &stage_dev)
        .map_err(|e| ArmedFailure::new(rows::POST_FIT, e))?;
    let df = reader
        .capture(&format!("df -P -k {real_stage}"))
        .map_err(|e| {
            ArmedFailure::new(
                rows::POST_FIT,
                format!("stage free-space re-take failed: {e}"),
            )
        })?;
    let avail = prod::parse_df_avail_kib(&df)
        .ok_or_else(|| {
            ArmedFailure::new(
                rows::POST_FIT,
                "unparseable df output at the free-space re-take; aborting",
            )
        })?
        .saturating_mul(1024);
    if avail < staged_bytes {
                                                                                                
                                                                                               
                                                                                                 
                                             
        return Err(ArmedFailure::new(
            rows::POST_FIT,
            format!(
                "post-reclaim stage free space {avail} is below the staged-artifact need \
                 {staged_bytes} — the shrink removed the slack §5.4 projected over; the \
                 reclaim itself is durable, only the staging does not proceed"
            ),
        ));
    }
    let date = reader.capture("date +%s").map_err(|e| {
        ArmedFailure::new(rows::POST_FIT, format!("clock-skew re-take failed: {e}"))
    })?;
    let parsed = prod::parse_u64_line(&date).ok_or_else(|| {
        ArmedFailure::new(
            rows::POST_FIT,
            "unparseable `date +%s` at the clock-skew re-take; aborting",
        )
    })?;
                                                                                              
                                                                                           
                                                                                              
                          
    let remote_epoch = i64::try_from(parsed).map_err(|_| {
        ArmedFailure::new(
            rows::POST_FIT,
            "target clock at the clock-skew re-take reads out of i64 range — the target \
             clock is unreadable; aborting",
        )
    })?;
    let now = ops.now_epoch();
    let skew = remote_epoch
        .checked_sub(now)
        .and_then(i64::checked_abs)
        .ok_or_else(|| {
            ArmedFailure::new(
                rows::POST_FIT,
                "target clock skew at the clock-skew re-take is out of i64 range — the \
                 target clock is unreadable; aborting",
            )
        })?;
    if skew >= max_clock_skew_secs {
        return Err(ArmedFailure::new(
            rows::POST_FIT,
            format!(
                "target clock is {skew}s off after the reclaim reboot (limit \
                 {max_clock_skew_secs}s) — an NTP step at boot is when a clock jumps; fix the \
                 target clock; aborting"
            ),
        ));
    }
    Ok(())
}

                                                                                               
/// leaves an armed target whose neutralizations are permanent, so the boundary must state both —
/// `append_disarm_outcome` embeds it, the §5.11 completion site routes it through
/// `completion_disarm_abort`; a bare `?` into a String context does not compile.
pub(crate) fn disarm_reachable(ops: &mut dyn OrchestrationOps) -> Result<(), ArmedFailure> {
    let mut reader = OpsReader(ops);
    disarm(&mut reader, "all").map_err(|e| ArmedFailure::new(e.row, e.reason))
}

/// The default reboot-poll bound (§5.8), operator-overridable at the entry points.
pub fn effective_timeout(operator_override: Option<u64>) -> u64 {
    operator_override.unwrap_or(RECLAIM_REBOOT_TIMEOUT_SECS)
}

/// §5 Cancellation inside the reclaim region, pre-write: observe the SIGINT flag immediately
/// before step 5 (plan + consent) and immediately before step 6 (§5.6's first write) — the prod
                                                                                                  
/// reclaim has written nothing, and neither entry point has staged files here, so the check is the
/// flag read alone. `reclaim_abort_text` appends the standing note: the reclaim region is active,
/// so a PRIOR run's permanence can exist on the target and the note's conditional clause covers it
                                                                                
                                                                                            
/// functions, not a runtime flag.
pub(crate) fn reclaim_cancel_check(ops: &mut dyn OrchestrationOps) -> Result<(), ReclaimAbort> {
    if ops.cancel_requested() {
        return Err(crate::deploy::prod_orchestrate::reclaim_abort_text(
            "cancelled by operator signal before the reclaim's first write — nothing was \
             written to the target by the reclaim (§5 Cancellation)",
        ));
    }
    Ok(())
}

                                                                                                   

                                                                                             
/// consent. "Prepare this disk" is not the consent "erase this disk", so it carries its own
                                                            
pub const RECLAIM_STANDALONE_ADVISORY: &str = "\
ADVISORY — reclaim-tail prepares this disk for a later `orchard prod`:
  * It SHRINKS the live root filesystem and its partition across ONE reboot of the target.
  * e2fsck runs first and repairs the filesystem AUTOMATICALLY; a repair may alter data (§6.3).
  * A reset while the filesystem is being shrunk can leave it UNRECOVERABLE; the only
    recovery is your snapshot or re-provisioning. TAKE A SNAPSHOT FIRST.
  * It PERMANENTLY removes cloud-initramfs-growroot, disables cloud-init, and removes the
    x-systemd.growfs option from every /etc/fstab entry carrying it. Nothing restores them, on any path.
  * This does NOT erase the disk; preparing is a narrower consent than `deploy prod`'s wipe.";

pub struct StandaloneOpts {
    pub ip: String,
    pub image: std::path::PathBuf,
    pub host_fingerprint: Option<String>,
    pub timeout_secs: Option<u64>,
}

                                                                                             
                                                                                             
pub fn reclaim_tail_standalone(
    ops: &mut dyn OrchestrationOps,
    o: &StandaloneOpts,
) -> Result<(), String> {
    let art = ops.read_image_artifacts(&o.image)?;
    let layout = art.layout;
    let img_len = art.img_len;

                                                                                               
    let (line, presented) = ops.scan_host_key()?;
    match &o.host_fingerprint {
        Some(f) if f.trim() == presented.trim() => {
            ops.pin_host_key(Leg::Provisioning, &line)?;
        }
        Some(f) => {
            return Err(format!(
                "--host-fingerprint {f} does not match the scanned {presented}; aborting"
            ));
        }
        None if ops.stdin_is_tty() => {
            let answer = ops
                .read_line(&format!(
                    "target host key {presented} — type yes to trust: "
                ))
                .unwrap_or_default();
            if answer.trim() != "yes" {
                return Err("host key not confirmed; aborting".into());
            }
            ops.pin_host_key(Leg::Provisioning, &line)?;
        }
        None => {
            return Err(
                "no --host-fingerprint and stdin is not a TTY — failing closed (never \
                 accept-new)"
                    .into(),
            );
        }
    }
    ops.ssh_capture(Leg::Provisioning, "echo recipes-deploy-connected")?;

                                                                                                
                                       
    let fm = ops
        .ssh_capture(Leg::Provisioning, "findmnt -n -o SOURCE / || true")
        .unwrap_or_default();
    let root_dev = prod::parse_findmnt_source(&fm)
        .ok_or("could not discover the target's root partition; aborting")?;
    let walk = ops.ssh_capture(Leg::Provisioning, "lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME")?;
    let disk = prod::parse_lsblk_parent_walk(&walk, &root_dev)?;
    let sectors = prod::parse_u64_line(&ops.ssh_capture(
        Leg::Provisioning,
        &format!("cat /sys/class/block/{disk}/size"),
    )?)
    .ok_or_else(|| format!("unparseable /sys/class/block/{disk}/size; aborting"))?;
    let disk_bytes = sectors.saturating_mul(512);
    let window = crate::deploy::staging_geometry::place_and_check_window(
        &layout, &disk, disk_bytes, img_len, 0,
    )?;
    let extents = prod::parse_lsblk_partition_extents(
        &ops.ssh_capture(
            Leg::Provisioning,
            &format!("lsblk -nbro NAME,TYPE,START,SIZE /dev/{disk}"),
        )?,
        &disk,
    )?;
    let d1 =
        crate::deploy::staging_geometry::refuse_if_window_intersects_partition(&window, &extents);
    if d1.is_ok() {
                                                                                        
        ops.say(
            "reclaim-tail: the staging window already intersects nothing (D-1 passes) — no-op; \
             the partition table and the window are untouched (row S-NOOP)",
        );
        return Ok(());
    }
    let staging_reserve = (art.vmlinuz.len() + art.initramfs.len()) as u64
        + crate::deploy::prod_orchestrate::STAGE_HEADROOM_BYTES;
    let timeout_secs = effective_timeout(o.timeout_secs);
    let inputs = SpliceInputs {
        ip: &o.ip,
        disk: &disk,
        root_dev: &root_dev,
        disk_bytes,
        window: &window,
        img_len,
        staging_reserve,
        extents: &extents,
        d1: d1.clone(),
        timeout_secs,
    };
    let prepared = {
        let mut reader = OpsReader(ops);
        prepare_read_only(&mut reader, &inputs)
            .map_err(stringify)
            .map_err(ReclaimAbort::into_message)?
    };

                                                                                               
                                     
    ops.say(RECLAIM_STANDALONE_ADVISORY);
    if ops.stdin_is_tty() {
        let retyped = ops
            .read_line(&format!(
                "Retype the target ip (or /dev/{disk}) to confirm PREPARING this disk: "
            ))
            .unwrap_or_default();
        let r = retyped.trim();
        if r != o.ip && r != disk && r != format!("/dev/{disk}") {
            return Err(crate::deploy::prod_orchestrate::reclaim_abort_text(
                "reclaim-tail: retype mismatch — aborting before any write",
            )
            .into_message());
        }
    }
                                                       
    reclaim_cancel_check(ops).map_err(ReclaimAbort::into_message)?;
    plan_and_consent(ops, &prepared, EntryPoint::Standalone).map_err(ReclaimAbort::into_message)?;
                                                 
    reclaim_cancel_check(ops).map_err(ReclaimAbort::into_message)?;
    if let Err(e) = install_and_arm(ops, &prepared) {
                                                                                                
                                                                        
        return Err(crate::deploy::prod_orchestrate::route_install_failure(ops, e).into_message());
    }
    let crumbs = match reboot_and_arbitrate(
        ops,
        &prepared,
        &window,
        "",
        0,
        timeout_secs,
        i64::MAX,
        false,
    ) {
        Ok(c) => c,
        Err(e) => {
            return Err(crate::deploy::prod_orchestrate::armed_abort(ops, e).into_message());
        }
    };
                                                                                        
                                                                                                 
                                                                                                    
                                                                                                    
                                                                                                        
                                                                                                     
                                                                                             
    disarm_reachable(ops)
        .map_err(ArmedFailure::mark_completed)
        .map_err(crate::deploy::prod_orchestrate::completion_disarm_abort)
        .map_err(ReclaimAbort::into_message)?;
    ops.say(&format!(
        "reclaim-tail COMPLETE: prepared /dev/{disk} on {} — the staging window sits in \
         unpartitioned space and D-1 passes ({} breadcrumb line(s)). cloud-init REMAINS \
         DISABLED and cloud-initramfs-growroot REMAINS REMOVED (permanent: restoring \
         either would re-grow the root on the next boot and undo the reclaim). A prepared disk \
         is not a restored one; the way back is your snapshot.",
        o.ip,
        crumbs.len()
    ));
    Ok(())
}

#[cfg(test)]
#[path = "ceremony_census_tests.rs"]
mod census_tests;

#[cfg(test)]
mod tests {
    //! ceremony.rs had no test module (R1 Sonnet F1 / class-hunt C-1); these pin the row ids the
    //! §7 matrix keys on (C-1), the D8 short-circuit disposition (S-F1 / AC-R29), and the shipped
    //! reboot-poll's cancel (C-2). A scripted `TargetReader` drives the read-only half; a minimal
    //! `OrchestrationOps` double (`CeremonyOps`) drives the write half and the reboot.
    use super::*;

                                                                                                   

    struct ScriptReader {
        replies: Vec<(&'static str, String)>,
    }
    impl TargetReader for ScriptReader {
        fn capture(&mut self, cmd: &str) -> Result<String, String> {
            for (needle, reply) in &self.replies {
                if cmd.contains(needle) {
                    return Ok(reply.clone());
                }
            }
            Err(format!("unscripted (reader): {cmd}"))
        }
    }

                                                                                                  

    pub(super) struct CeremonyOps {
        replies: Vec<(&'static str, String)>,
        /// One-shot replies consumed BEFORE the static table (front-of-queue, needle-contains) —
        /// the census uses these to serve an early read of a command and fail (or change) a LATER
        /// read of the SAME command, which a needle table alone cannot express.
        once: std::collections::VecDeque<(&'static str, String)>,
        pub(super) calls: Vec<String>,
        cancel: bool,
        boot_id_reads: u32,
    }
    impl CeremonyOps {
        pub(super) fn new(replies: Vec<(&'static str, String)>) -> Self {
            Self {
                replies,
                once: Default::default(),
                calls: vec![],
                cancel: false,
                boot_id_reads: 0,
            }
        }
        pub(super) fn with_once(
            replies: Vec<(&'static str, String)>,
            once: &[(&'static str, &str)],
        ) -> Self {
            let mut ops = Self::new(replies);
            ops.once = once.iter().map(|(n, r)| (*n, r.to_string())).collect();
            ops
        }
    }
    impl OrchestrationOps for CeremonyOps {
        fn stdin_is_tty(&self) -> bool {
            false
        }
        fn say(&mut self, _msg: &str) {}
        fn read_line(&mut self, _prompt: &str) -> Option<String> {
            None
        }
        fn cancel_requested(&self) -> bool {
            self.cancel
        }
        fn sleep_secs(&mut self, _secs: u64) {}
        fn now_epoch(&self) -> i64 {
            0
        }
        fn ssh_port(&self) -> u16 {
            22
        }
        fn ssh_capture(&mut self, _leg: Leg, cmd: &str) -> Result<String, String> {
            self.calls.push(cmd.to_string());
                                                                                                  
                                                                               
            if cmd.contains("/proc/sys/kernel/random/boot_id") {
                self.boot_id_reads += 1;
                return Ok(if self.boot_id_reads == 1 {
                    "before-boot-id\n".into()
                } else {
                    "after-boot-id\n".into()
                });
            }
            if let Some((needle, _)) = self.once.front()
                && cmd.contains(needle)
            {
                let (_, reply) = self.once.pop_front().expect("front exists");
                return Ok(reply);
            }
            for (needle, reply) in &self.replies {
                if cmd.contains(needle) {
                    return Ok(reply.clone());
                }
            }
            Err(format!("unscripted (ops): {cmd}"))
        }
        fn read_image_artifacts(
            &mut self,
            _image: &std::path::Path,
        ) -> Result<crate::deploy::prod_orchestrate::ImageArtifacts, String> {
            unimplemented!()
        }
        fn local_pubkey_fingerprint(
            &mut self,
            _pubkey: &std::path::Path,
        ) -> Result<String, String> {
            unimplemented!()
        }
        fn derive_runtime_hostkey(
            &mut self,
            _image: &std::path::Path,
        ) -> Result<(String, String), String> {
            unimplemented!()
        }
        fn recompute_root_hash(
            &mut self,
            _img: &std::path::Path,
            _off: u64,
            _len: u64,
        ) -> Result<String, String> {
            unimplemented!()
        }
        fn known_hosts_host(&self) -> String {
            unimplemented!()
        }
        fn scan_host_key(&mut self) -> Result<(String, String), String> {
            unimplemented!()
        }
        fn pin_host_key(&mut self, _leg: Leg, _line: &str) -> Result<(), String> {
            unimplemented!()
        }
        fn scp_stage(&mut self, _local: &std::path::Path, _remote: &str) -> Result<(), String> {
            unimplemented!()
        }
        fn scp_image_bytes(&mut self, _bytes: &[u8], _remote: &str) -> Result<(), String> {
            unimplemented!()
        }
        fn stage_raw_window(
            &mut self,
            _img: &std::path::Path,
            _patch: Option<&crate::deploy::stage_stream::PatchSpec>,
            _disk: &str,
            _offset: u64,
        ) -> Result<[u8; 32], String> {
            unimplemented!()
        }
        fn fire_kexec(&mut self, _token: crate::deploy::prod::WipeConfirmed) -> Result<(), String> {
            unimplemented!()
        }
    }

                                                                                                   

    fn window() -> RawWindowSpec {
        RawWindowSpec {
            disk: "vda".into(),
            offset: 41053847552,
            len: 1892036608,
        }
    }
    fn extents() -> Vec<PartitionExtent> {
        vec![
            PartitionExtent {
                name: "vda1".into(),
                start: 134217728,
                end: 42948624384,
            },
            PartitionExtent {
                name: "vda14".into(),
                start: 1048576,
                end: 4194304,
            },
            PartitionExtent {
                name: "vda15".into(),
                start: 4194304,
                end: 134217728,
            },
        ]
    }
    fn splice<'a>(window: &'a RawWindowSpec, extents: &'a [PartitionExtent]) -> SpliceInputs<'a> {
        SpliceInputs {
            ip: "203.0.113.5",
            disk: "vda",
            root_dev: "vda1",
            disk_bytes: 42949672960,
            window,
            img_len: 1892036608,
            staging_reserve: 0,
            extents,
            d1: Err("the window intersects the root partition".into()),
            timeout_secs: 1800,
        }
    }

    /// The read-only battery: a pristine class target that passes eligibility + lock. The
    /// dumpe2fs count lands `fs_bytes` at `planned_size` (no would-grow), the df row projects well
    /// under it (no R-FIT). Overridable at the front for the two refusal legs.
    fn readonly_battery() -> Vec<(&'static str, String)> {
        vec![
            ("for c in", "CAP-PROBE-DONE\n".into()),
            ("dpkg-query", "install installed RC:0".into()),
                                                                                                     
                                                                                             
            ("cloud-init.disabled", "marker-absent\n".into()),
            ("FSTYPE", "ext4\nRC:0".into()),
            ("--target /boot", "/dev/vda1\nRC:0".into()),
            (
                "dumpe2fs -h",
                "Block count:              9989888\nBlock size:               4096\nRC:0".into(),
            ),
                                                                                          
                                                                                               
                                                                                                    
                                   
            (
                "python3 - /var/lib/dpkg",
                "/var/lib/dpkg/lock-frontend FREE\n/var/lib/dpkg/lock FREE\n".into(),
            ),
            (
                "df -P -k /",
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 41943040 1897068 40045972 5% /\n".into(),
            ),
        ]
    }

    pub(super) fn front(
        mut base: Vec<(&'static str, String)>,
        needle: &'static str,
        reply: &str,
    ) -> Vec<(&'static str, String)> {
        base.insert(0, (needle, reply.to_string()));
        base
    }

    pub(super) fn sample_prepared() -> Prepared {
        let window = window();
        let extents = extents();
        let mut r = ScriptReader {
            replies: readonly_battery(),
        };
        prepare_read_only(&mut r, &splice(&window, &extents)).expect("the happy read-only half")
    }

    /// install_and_arm's happy replies: the neutralize Already-Absent path (growroot gone, fstab
    /// already clean — no purge, no fstab write, so no state flip is needed) plus a clean install.
    pub(super) fn install_battery() -> Vec<(&'static str, String)> {
        vec![
            ("touch /etc/cloud/cloud-init.disabled", "RC:0".into()),
            ("test -e /etc/cloud/cloud-init.disabled", "marker-present".into()),
            (
                "python3 - /var/lib/dpkg",
                "/var/lib/dpkg/lock-frontend FREE\n/var/lib/dpkg/lock FREE\n".into(),
            ),
            ("dpkg-query", " RC:1".into()),                                                     
            ("cat /etc/fstab", "PARTUUID=abcd-01 / ext4 rw,discard 0 1\nFSTAB-DONE\nRC:0".into()),                         
            ("cat > /etc/initramfs-tools/hooks/", "RC:0".into()),
            ("cat > /etc/initramfs-tools/scripts/local-premount/", "RC:0".into()),
            ("update-initramfs -u -k all", "RC:0".into()),
            (
                "INITRD-COUNT",
                "INITRD:/boot/initrd.img-x\nusr/sbin/e2fsck\nusr/sbin/resize2fs\n\
                 usr/sbin/sfdisk\nusr/sbin/dumpe2fs\nINITRD-COUNT:1\nRC:0".into(),
            ),
            (
                "unmkinitramfs",
                "ORDER-INITRD:/boot/initrd.img-x\nscripts/local-premount/orchard-reclaim\nORDER-DONE\n".into(),
            ),
        ]
    }

                                                                                                  

    fn d8(root_end: u64, dumpe2fs_reply: &str) -> Option<bool> {
        let window = window();
        let extents = vec![PartitionExtent {
            name: "vda1".into(),
            start: 134217728,
            end: root_end,
        }];
        let mut r = ScriptReader {
            replies: vec![("dumpe2fs -h", dumpe2fs_reply.to_string())],
        };
                                                                                             
        short_circuit_d8_conjunction(&mut r, &splice(&window, &extents))
    }

    #[test]
    fn d8_short_circuit_disposition_over_the_five_states() {
                                                                                                    
                                                                                           
        let clean_low = "Block count: 9000000\nBlock size: 4096\nRC:0";                   
        let overhang = "Block count: 10000000\nBlock size: 4096\nRC:0";                   
                                                              
        assert_eq!(d8(41052798976, clean_low), Some(true));
                                                         
        assert_eq!(d8(41052798976, overhang), Some(false));
                                                    
        assert_eq!(d8(42000000000, clean_low), Some(false));
                                                   
        assert_eq!(
            d8(42000000000, "Block count: 11000000\nBlock size: 4096\nRC:0"),
            Some(false)
        );
                                                                                                
        assert_eq!(d8(41052798976, "RC:1"), Some(false));
        assert_eq!(
            d8(41052798976, "Block count: x\nBlock size: 4096\nRC:0"),
            None
        );
    }

    #[test]
    fn read_only_half_short_circuit_threads_the_d8_disposition() {
                                                                                                 
                                                                                          
                                                                                      
        let extents = vec![PartitionExtent {
            name: "vda1".into(),
            start: 134217728,
            end: 41052798976,                             
        }];
        let window = window();
        let mut i = splice(&window, &extents);
        i.d1 = Ok(());
        let mut ops = CeremonyOps::new(vec![(
            "dumpe2fs -h",
            "Block count: 9000000\nBlock size: 4096\nRC:0".into(),
        )]);
        let out = read_only_half(&mut ops, &i).unwrap();
        assert!(matches!(out.decision, ReclaimDecision::ShortCircuit));
        assert!(
            out.d8_recorded_not_fatal,
            "in-bounds low-space is recorded-not-fatal"
        );

        let mut ops = CeremonyOps::new(vec![("dumpe2fs -h", "RC:1".into())]);
        let out = read_only_half(&mut ops, &i).unwrap();
        assert!(
            !out.d8_recorded_not_fatal,
            "a failed overhang read is FATAL (unwrap_or(false))"
        );
    }

                                                                                                   

    #[test]
    fn prepare_read_only_refuses_r_would_grow_and_r_fit_by_row() {
                                                                                  
        let window = window();
        let extents = extents();
        let mut r = ScriptReader {
            replies: front(
                readonly_battery(),
                "dumpe2fs -h",
                "Block count: 100000\nBlock size: 4096\nRC:0",
            ),
        };
        let e = prepare_read_only(&mut r, &splice(&window, &extents))
            .err()
            .unwrap();
        assert_eq!(e.row, rows::WOULD_GROW);

                                                                              
        let mut r = ScriptReader {
            replies: front(
                readonly_battery(),
                "df -P -k /",
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                 /dev/vda1 41943040 40000000 1943040 96% /\n",
            ),
        };
        let e = prepare_read_only(&mut r, &splice(&window, &extents))
            .err()
            .unwrap();
        assert_eq!(e.row, rows::FIT);
    }

    #[test]
    fn append_disarm_outcome_discloses_permanence_on_both_arms() {
                                                                                              
                                                                                                    
                                                                                              
                                                                
        let mut ops = CeremonyOps::new(vec![]);
        let out = crate::deploy::prod_orchestrate::append_disarm_outcome(
            &mut ops,
            ReclaimRefusal::new(rows::INITRAMFS, "a post-install refusal"),
            false,                                                                    
        )
        .into_message();
        assert!(
            out.contains("R-ARMED"),
            "the disarm-failed arm names R-ARMED: {out}"
        );
        assert!(
            out.contains("PERMANENT"),
            "the disarm-failed arm still discloses the permanence: {out}"
        );

                                                                                                        
                                                                          
        let mut ok_ops = CeremonyOps::new(vec![
            (
                "rm -f /etc/initramfs-tools/hooks/orchard-reclaim",
                "RC:0".into(),
            ),
            ("update-initramfs -u -k all", "RC:0".into()),
            (
                "echo LS-DONE",
                "usr/sbin/e2fsck\nscripts/local-premount/resume\n\
                 LS-OK:/boot/initrd.img-x\nLS-COUNT:1\nLS-DONE"
                    .into(),
            ),
        ]);
        let ok_out = crate::deploy::prod_orchestrate::append_disarm_outcome(
            &mut ok_ops,
            ReclaimRefusal::new(rows::INITRAMFS, "a post-install refusal"),
            false,                                         
        )
        .into_message();
        assert!(
            ok_out.contains("disarmed") && ok_out.contains("PERMANENT"),
            "the disarm-OK arm discloses the permanence: {ok_out}"
        );
    }

    #[test]
    fn install_and_arm_transport_error_at_the_hook_write_is_after_install() {
                                                                                                      
                                                                                                    
                                                                                                  
                                                                                                    
                                                                                                       
                      
        let prepared = sample_prepared();
        let battery: Vec<(&'static str, String)> = install_battery()
            .into_iter()
            .filter(|(needle, _)| *needle != "cat > /etc/initramfs-tools/hooks/")
            .collect();
        let mut ops = CeremonyOps::new(battery);
        match install_and_arm(&mut ops, &prepared) {
            Ok(()) => panic!("a lost hook-write reply must refuse"),
            Err(InstallFailure::BeforeInstall { refusal, .. }) => panic!(
                "a transport error at the hook write may have written the file — must be \
                 AfterInstall, got BeforeInstall: {refusal}"
            ),
            Err(InstallFailure::AfterInstall { .. }) => {}
        }
    }

    #[test]
    fn a_metacharacter_in_a_target_partition_field_refuses_in_the_read_only_half() {
                                                                                               
                                                                                                
                                                                                             
                                                                                                  
                                                                                             
                                                                                               
                                                                                                  
                                                                                            
                                                                                                 
                                                       
        let window = window();
        let extents = extents();                                                  
                                                                                             
        let inputs = SpliceInputs {
            ip: "203.0.113.5",
            disk: "vda;reboot",
            root_dev: "vda1",
            disk_bytes: 42949672960,
            window: &window,
            img_len: 1892036608,
            staging_reserve: 0,
            extents: &extents,
            d1: Err("the window intersects the root partition".into()),
            timeout_secs: 1800,
        };
        let mut r = ScriptReader {
            replies: readonly_battery(),
        };
        let e = match prepare_read_only(&mut r, &inputs) {
            Ok(_) => panic!("a metacharacter in a target field must refuse in the read-only half"),
            Err(e) => e,
        };
        assert_eq!(
            e.row,
            rows::ELIG,
            "a metacharacter in the doomed partition's node must refuse at R-ELIG in the \
             read-only half: {e:?}"
        );
    }

    #[test]
    fn reboot_and_arbitrate_refuses_r_post_fit_by_row() {
                                                                                                    
                                                                                                   
                                                                                                
                                                                                                   
                              
        let prepared = sample_prepared();
        let window = window();
        let shrunk = "vda disk 0 42949672960\nvda1 part 262144 40918581248\nvda14 part 2048 3145728\nvda15 part 8192 130023424\n";
        let replies = vec![
            ("nohup reboot", "REBOOT-ISSUED\n".to_string()),
            ("findmnt -n -o SOURCE / ||", "/dev/vda1\n".to_string()),
            ("NAME,TYPE,MOUNTPOINT,PKNAME", "vda disk  \nvda1 part / vda\n".to_string()),
            (
                "grep -F 'orchard-reclaim:'",
                "<3>orchard-reclaim: step10 done part=[134217728,41052798976) sectors=79919104\nCRUMB-DONE".to_string(),
            ),
            ("NAME,TYPE,START,SIZE", shrunk.to_string()),
            ("findmnt -n -o SOURCE --target", "/dev/vda1\n".to_string()),
            (
                "df -P -k /stage",
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 41943040 40000000 1943040 96% /stage\n".to_string(),
            ),
        ];
        let mut ops = CeremonyOps::new(replies);
        let e = reboot_and_arbitrate(
            &mut ops,
            &prepared,
            &window,
            "/stage",
            10_000_000_000_000,                                                           
            1800,
            i64::MAX,
            true,
        )
        .unwrap_err();
        assert_eq!(
            e.row(),
            rows::POST_FIT,
            "the free-space re-take refuses at R-POST-FIT: {}",
            e.text()
        );
        assert!(e.text().contains("stage free space"), "{}", e.text());
    }

                                                                                                  

    #[test]
    fn reboot_and_arbitrate_observes_a_cancel_in_the_poll() {
                                                                                       
                                                                                           
        let prepared = sample_prepared();
        let window = window();
        let mut ops = CeremonyOps::new(vec![("nohup reboot", "REBOOT-ISSUED\n".into())]);
        ops.cancel = true;
        let e = reboot_and_arbitrate(&mut ops, &prepared, &window, "", 0, 1800, i64::MAX, false)
            .unwrap_err();
        assert!(
            e.text().contains("cancelled") && e.text().contains("UNKNOWN"),
            "the inline poll must observe the cancel: {}",
            e.text()
        );
                                                                   
        assert!(
            !ops.calls
                .iter()
                .any(|c| c.contains("NAME,TYPE,MOUNTPOINT,PKNAME")),
            "no arbitration may run after a poll cancel: {:?}",
            ops.calls
        );
    }
}
