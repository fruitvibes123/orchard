//! The post-reboot half (plan T8): success arbitration (R8), the breadcrumb fetch (R9), the
                                                                                      
//!
                                                                                        
                                                                                             
//! own commands and compared byte-for-byte.

use super::eligibility::split_rc;
use super::{HOOK_NAME, PREMOUNT_SCRIPT_NAME, ReclaimRefusal, TargetReader, rows};
use crate::deploy::prod;
use crate::deploy::prod::RawWindowSpec;
use crate::deploy::staging_geometry::window_partition_intersection;

                                                                                              
/// ceremony's convention: BARE device names (`vda1`, `vda`), as `parse_findmnt_source` and
/// `parse_lsblk_parent_walk` produce them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreReclaimState {
    pub root_dev: String,
    pub disk: String,
}

/// A successful arbitration: D-1 passed on the re-read extents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimOutcome {
    pub breadcrumb: Vec<String>,
}

                                                                                                   

                                                                                  
pub const ROOT_DEV_CMD: &str = "findmnt -n -o SOURCE / || true";
pub const PARENT_WALK_CMD: &str = "lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME";

pub fn extents_cmd(disk: &str) -> String {
    format!("lsblk -nbro NAME,TYPE,START,SIZE /dev/{disk}")
}

                                                                                         
/// before any further reboot. The grep's rc is irrelevant (zero lines is a legal outcome with
                                                                        
pub const BREADCRUMB_CMD: &str = "dmesg 2>/dev/null | grep -F 'orchard-reclaim:'; echo CRUMB-DONE";

pub fn disarm_rm_cmd() -> String {
    format!(
        "rm -f /etc/initramfs-tools/hooks/{HOOK_NAME} \
         /etc/initramfs-tools/scripts/local-premount/{PREMOUNT_SCRIPT_NAME} 2>/dev/null; \
         echo RC:$?"
    )
}

                                                                                             
/// covering every kernel a `-k all` install wrote).
pub fn disarm_rebuild_cmd(kscope: &str) -> String {
    format!("update-initramfs -u -k {kscope} 2>/dev/null 1>&2; echo RC:$?")
}

/// The boot identity §5.8's poll waits on. `/proc/sys/kernel/random/boot_id` is regenerated on
/// every boot, so comparing it against the value read BEFORE the reboot is what distinguishes
/// "the target came back" from "the target has not gone down yet".
///
/// This is not decoration. A plain liveness probe issued right after `reboot` answers over the
/// STILL-RUNNING pre-reboot session — measured on the grown fixture: the first RT-1 run polled
/// alive immediately, arbitrated against the unshrunk state, and refused at row `R-NO-CRUMB`
/// with the script blameless (it had not run yet, because the reboot had not happened yet).
pub const BOOT_ID_CMD: &str = "cat /proc/sys/kernel/random/boot_id";

                                                                                           
/// stronger than ORDER-absence — a 0644 script is ORDER-absent while still installed). Each initrd
/// is paired with an installed kernel — `/boot/vmlinu[xz]-<v>` present, the `-k all` rebuild's own
                                                                                                
/// checked and cannot report a correctly-disarmed target as still armed. Each paired initrd is
/// enumerated with a per-file `LS-OK:`/`LS-FAIL:` marker and a trailing `LS-COUNT:` so the disarm
/// can tell "listed and absent" apart from "nothing was listed" — an empty glob or an unreadable
                                                                                             
/// no-match leaves in POSIX sh.
pub const DISARM_VERIFY_CMD: &str = "n=0; for f in /boot/initrd.img-*; do [ -e \"$f\" ] || continue; \
     v=${f#/boot/initrd.img-}; [ -e \"/boot/vmlinuz-$v\" ] || [ -e \"/boot/vmlinux-$v\" ] || continue; \
     n=$((n+1)); if lsinitramfs \"$f\" 2>/dev/null; then echo \"LS-OK:$f\"; else echo \"LS-FAIL:$f\"; fi; \
     done; echo \"LS-COUNT:$n\"; echo LS-DONE";

                                                                                                   

                                                                                         
/// `R-NO-CRUMB`'s input, never silently dropped.
pub fn fetch_breadcrumb(reader: &mut dyn TargetReader) -> Result<Vec<String>, ReclaimRefusal> {
    let out = reader.capture(BREADCRUMB_CMD).map_err(|e| {
        ReclaimRefusal::new(
            rows::NO_CRUMB,
            format!("breadcrumb fetch failed to run: {e}"),
        )
    })?;
    if !out.contains("CRUMB-DONE") {
        return Err(ReclaimRefusal::new(
            rows::NO_CRUMB,
            "breadcrumb fetch did not complete (no CRUMB-DONE token)",
        ));
    }
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("orchard-reclaim:"))
        .map(|l| l.to_string())
        .collect())
}

fn crumb_text(breadcrumb: &[String]) -> String {
    if breadcrumb.is_empty() {
        String::new()
    } else {
        format!("\nbreadcrumb:\n  {}", breadcrumb.join("\n  "))
    }
}

                                                                                                   

                                                                                             
                                                                                               
                                                                                               
/// and structurally cannot carry a crumb — a transport-failed arm has no readable crumb, and the
/// identity-changed arm forbids further target calls; the standing permanence note still covers
                                                                        
/// `R-STALE-KERNEL` (script landed the edit on disk, kernel view stale — second reboot),
/// `R-REGROWN` (script completed, view matched, yet the window intersects again),
/// `R-NO-CRUMB` (D-1 refused and the script never executed), `R-INTERSECTS` (everything else).
pub fn arbitrate(
    reader: &mut dyn TargetReader,
    pre: &PreReclaimState,
    window: &RawWindowSpec,
) -> Result<ReclaimOutcome, ReclaimRefusal> {
                                                                                    
    let fm = reader.capture(ROOT_DEV_CMD).map_err(|e| {
        ReclaimRefusal::new(
            rows::IDENTITY,
            format!("root_dev re-derivation failed: {e}"),
        )
    })?;
    let root_dev = prod::parse_findmnt_source(&fm).unwrap_or_default();
    let walk = reader.capture(PARENT_WALK_CMD).map_err(|e| {
        ReclaimRefusal::new(
            rows::IDENTITY,
            format!("parent walk re-derivation failed: {e}"),
        )
    })?;
    let disk = prod::parse_lsblk_parent_walk(&walk, &root_dev).unwrap_or_default();
    if root_dev != pre.root_dev || disk != pre.disk {
        return Err(ReclaimRefusal::new(
            rows::IDENTITY,
            format!(
                "target identity changed across the reboot: root_dev {:?} -> {root_dev:?}, \
                 disk {:?} -> {disk:?}; no further ceremony-advancing target call — \
                 the disarm still runs (path-addressed, host-key-verified)",
                pre.root_dev, pre.disk
            ),
        ));
    }

                                                                                    
    let breadcrumb = fetch_breadcrumb(reader)?;

                                                                                                
                                                                                              
                                                                                                 
                                                                                                     
                                                                             
    let lsblk = reader.capture(&extents_cmd(&pre.disk)).map_err(|e| {
        ReclaimRefusal::new(
            rows::INTERSECTS,
            format!("extent re-read failed: {e}{}", crumb_text(&breadcrumb)),
        )
    })?;
    let extents = prod::parse_lsblk_partition_extents(&lsblk, &pre.disk).map_err(|e| {
        ReclaimRefusal::new(
            rows::INTERSECTS,
            format!(
                "extent re-read did not parse: {e}{}",
                crumb_text(&breadcrumb)
            ),
        )
    })?;
    match window_partition_intersection(window, &extents) {
        None => Ok(ReclaimOutcome { breadcrumb }),
        Some((win_start, win_end, part)) => {
                                                                                                
                                                                                                   
                                                                                                   
                                                                                               
                                                                                
            let d1 = format!(
                "the re-read staging window [{win_start}, {win_end}) on /dev/{} still INTERSECTS \
                 partition /dev/{} at [{}, {})",
                window.disk, part.name, part.start, part.end
            );
            let crumbs = crumb_text(&breadcrumb);
            if breadcrumb.is_empty() {
                                                                                            
                                                                                               
                                 
                return Err(ReclaimRefusal::new(
                    rows::NO_CRUMB,
                    format!(
                        "the window still intersects and the breadcrumb is EMPTY after a \
                         successful reconnect — the premount script never executed; check the \
                         initramfs rebuild's kernel scope. D-1: {d1}"
                    ),
                ));
            }
            let stale = breadcrumb.iter().any(|l| l.contains("kernel view STALE"));
            let completed = breadcrumb.iter().any(|l| l.contains("step10 done"));
            if stale && completed {
                return Err(ReclaimRefusal::new(
                    rows::STALE_KERNEL,
                    format!(
                        "the shrink landed on disk but the kernel view is stale — REBOOT the \
                         target once more and re-run; the on-disk table is already correct. \
                         D-1: {d1}{crumbs}"
                    ),
                ));
            }
            if completed {
                return Err(ReclaimRefusal::new(
                    rows::REGROWN,
                    format!(
                        "the script completed a shrink yet the window intersects again — a \
                         re-grow mechanism was missed (holds this). D-1: {d1}{crumbs}"
                    ),
                ));
            }
            Err(ReclaimRefusal::new(
                rows::INTERSECTS,
                format!("the window still intersects. D-1: {d1}{crumbs}"),
            ))
        }
    }
}

                                                                                                   

                                                                                            
/// `lsinitramfs`. A disarm that cannot be verified REFUSES naming the target as still armed
                                                
pub fn disarm(reader: &mut dyn TargetReader, kscope: &str) -> Result<(), ReclaimRefusal> {
    let refuse = |reason: String| ReclaimRefusal::new(rows::DISARM, reason);
    let (_, rc) = split_rc(
        &reader
            .capture(&disarm_rm_cmd())
            .map_err(|e| refuse(format!("disarm file removal failed to run: {e}")))?,
        "disarm rm",
    )
    .map_err(|e| refuse(e.reason))?;
    if rc != 0 {
        return Err(refuse(format!(
            "removing the ceremony's two files failed (rc {rc}) — the target is still armed; \
             manual removal per orchard_guide.md §9.1"
        )));
    }
    let (_, rc) = split_rc(
        &reader
            .capture(&disarm_rebuild_cmd(kscope))
            .map_err(|e| refuse(format!("disarm rebuild failed to run: {e}")))?,
        "disarm rebuild",
    )
    .map_err(|e| refuse(e.reason))?;
    if rc != 0 {
        return Err(refuse(format!(
            "update-initramfs failed during the disarm (rc {rc}) — the previous initrd, and \
             its copy of the premount script, is still in place; the target is still \
             armed"
        )));
    }
    let listing = reader
        .capture(DISARM_VERIFY_CMD)
        .map_err(|e| refuse(format!("disarm verification failed to run: {e}")))?;
    if !listing.contains("LS-DONE") {
        return Err(refuse("disarm verification did not complete".into()));
    }
                                                                                                    
                                                                                                
                                                                                             
                                 
    let enumerated = listing
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("LS-COUNT:"))
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
    if enumerated == 0 {
        return Err(refuse(
            "disarm verification enumerated NO initrd (empty /boot/initrd.img-* or lsinitramfs \
             absent) — the script's absence cannot be confirmed; the target is treated as still \
             armed (row R-DISARM); manual removal per orchard_guide.md §9.1"
                .into(),
        ));
    }
    if listing
        .lines()
        .map(str::trim)
        .any(|l| l.starts_with("LS-FAIL:"))
    {
        return Err(refuse(
            "disarm verification could not read at least one initrd (lsinitramfs failed) — the \
             script's absence cannot be confirmed; the target is treated as still armed \
             (row R-DISARM); manual removal per orchard_guide.md §9.1"
                .into(),
        ));
    }
    let premount_suffix = format!("scripts/local-premount/{PREMOUNT_SCRIPT_NAME}");
    if listing
        .lines()
        .map(str::trim)
        .any(|l| l.ends_with(&premount_suffix))
    {
        return Err(refuse(format!(
            "the premount script is STILL PRESENT in a rebuilt initrd \
             ({premount_suffix}) — the target is still armed (row R-DISARM); \
             manual removal per orchard_guide.md §9.1"
        )));
    }
    Ok(())
}

                                                                                                   

/// §5.8's poll as pure logic: `alive` is one liveness probe of the target's own sshd
/// (`Leg::Provisioning`, never `Leg::Reconnect`), `cancel` is the SIGINT flag, `sleep_tick` is
/// one 15-second cadence tick. The cancel is observed within one tick (AC-R19).
pub enum PollOutcome {
    Alive,
    Cancelled,
    TimedOut,
}

pub fn poll_loop(
    mut alive: impl FnMut() -> bool,
    cancel: impl Fn() -> bool,
    mut sleep_tick: impl FnMut(),
    timeout_secs: u64,
    tick_secs: u64,
) -> PollOutcome {
    let mut elapsed = 0u64;
    loop {
        if cancel() {
            return PollOutcome::Cancelled;
        }
        if alive() {
            return PollOutcome::Alive;
        }
        if elapsed >= timeout_secs {
            return PollOutcome::TimedOut;
        }
        sleep_tick();
        elapsed = elapsed.saturating_add(tick_secs);
    }
}

/// Map a poll outcome to the §5.8 refusals: a cancel refuses naming the target's state as
/// unknown (it does not stop the shrink and does not claim to); a timeout is row `R-NO-ANSWER`
/// (the shrink may still be running or the target may be gone — indistinguishable from the
/// host; the provider's VNC console shows the `<3>` breadcrumb on tty0).
pub fn poll_refusal(outcome: &PollOutcome, timeout_secs: u64) -> Option<ReclaimRefusal> {
    match outcome {
        PollOutcome::Alive => None,
        PollOutcome::Cancelled => Some(ReclaimRefusal::new(
            rows::NO_ANSWER,
            "cancelled during the reboot poll — polling stopped; the reclaim on the target is \
             NOT stopped by this and its state is UNKNOWN until the target is re-reached",
        )),
        PollOutcome::TimedOut => Some(ReclaimRefusal::new(
            rows::NO_ANSWER,
            format!(
                "no answer within {timeout_secs}s — the shrink may still be running, or the \
                 target may be gone; the two are indistinguishable from here. Read the \
                 orchard-reclaim breadcrumb on the provider's VNC console (kernel printk \
                 reaches tty0); recovery is the snapshot or re-provisioning"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct ScriptReader {
        replies: Vec<(String, String)>,
        issued: Vec<String>,
    }

    impl ScriptReader {
        fn new(replies: &[(&str, &str)]) -> Self {
            Self {
                replies: replies
                    .iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
                issued: vec![],
            }
        }
    }

    impl TargetReader for ScriptReader {
        fn capture(&mut self, cmd: &str) -> Result<String, String> {
            self.issued.push(cmd.to_string());
            for (needle, reply) in &self.replies {
                if cmd.contains(needle.as_str()) {
                    return Ok(reply.clone());
                }
            }
            panic!("unscripted command: {cmd}");
        }
    }

    fn pre() -> PreReclaimState {
        PreReclaimState {
            root_dev: "vda1".into(),
            disk: "vda".into(),
        }
    }

    fn window() -> RawWindowSpec {
        RawWindowSpec {
            disk: "vda".into(),
            offset: 41053847552,
            len: 1892036608,
        }
    }

                                                                                           
                                                  
    const WALK: &str = "vda disk  \nvda1 part / vda\n";

    fn shrunk_extents() -> &'static str {
                                                                                        
                                                                                                
        "vda disk 0 42949672960\nvda1 part 262144 40918581248\nvda14 part 2048 3145728\nvda15 part 8192 130023424\n"
    }

    fn grown_extents() -> &'static str {
                                                                             
        "vda disk 0 42949672960\nvda1 part 262144 42814406656\nvda14 part 2048 3145728\nvda15 part 8192 130023424\n"
    }

    const CRUMB_OK: &str = "[  3.1] <3>orchard-reclaim: step1 arithmetic self-test ok\n\
        [  9.9] <3>orchard-reclaim: step9 kernel view matches on-disk end 41052798976\n\
        [ 10.0] <3>orchard-reclaim: step10 done part=[134217728,41052798976) sectors=79919104\n\
        CRUMB-DONE";

    #[test]
    fn arbitrate_success_is_d1_passing_on_reread_extents() {
        let replies = [
            ("findmnt -n -o SOURCE /", "/dev/vda1\n"),
            ("NAME,TYPE,MOUNTPOINT,PKNAME", WALK),
            ("grep -F 'orchard-reclaim:'", CRUMB_OK),
            ("NAME,TYPE,START,SIZE", shrunk_extents()),
        ];
        let mut r = ScriptReader::new(&replies);
        let out = arbitrate(&mut r, &pre(), &window()).unwrap();
        assert!(out.breadcrumb.iter().any(|l| l.contains("step10 done")));
    }

    #[test]
    fn arbitrate_identity_change_refuses_naming_both_values() {
        let replies = [
            ("findmnt -n -o SOURCE /", "/dev/vdb1\n"),
            (
                "NAME,TYPE,MOUNTPOINT,PKNAME",
                "vdb disk  \nvdb1 part / vdb\n",
            ),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = arbitrate(&mut r, &pre(), &window()).unwrap_err();
        assert_eq!(e.row, rows::IDENTITY);
        assert!(
            e.reason.contains("vda1") && e.reason.contains("vdb1"),
            "{e}"
        );
                                                                           
        assert!(!r.issued.iter().any(|c| c.contains("START,SIZE")));
    }

    #[test]
    fn arbitrate_stale_kernel_names_the_second_reboot() {
        let crumb_stale = "<3>orchard-reclaim: step8 on-disk table confirms size=79919104\n\
            <3>orchard-reclaim: step9 kernel view STALE, a second reboot re-reads the table (R-STALE-KERNEL)\n\
            <3>orchard-reclaim: step10 done part=[134217728,41052798976) sectors=79919104\n\
            CRUMB-DONE";
        let replies = [
            ("findmnt -n -o SOURCE /", "/dev/vda1\n"),
            ("NAME,TYPE,MOUNTPOINT,PKNAME", WALK),
            ("grep -F 'orchard-reclaim:'", crumb_stale),
            ("NAME,TYPE,START,SIZE", grown_extents()),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = arbitrate(&mut r, &pre(), &window()).unwrap_err();
        assert_eq!(e.row, rows::STALE_KERNEL);
        assert!(e.reason.contains("REBOOT"), "{e}");
        assert!(e.reason.contains("breadcrumb"), "carries the crumb: {e}");
    }

    #[test]
    fn arbitrate_regrown_when_script_completed_but_window_intersects() {
        let replies = [
            ("findmnt -n -o SOURCE /", "/dev/vda1\n"),
            ("NAME,TYPE,MOUNTPOINT,PKNAME", WALK),
            ("grep -F 'orchard-reclaim:'", CRUMB_OK),
            ("NAME,TYPE,START,SIZE", grown_extents()),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = arbitrate(&mut r, &pre(), &window()).unwrap_err();
        assert_eq!(e.row, rows::REGROWN);
        assert!(e.reason.contains("re-grow mechanism was missed"), "{e}");
    }

    #[test]
    fn arbitrate_empty_breadcrumb_diagnoses_r34() {
        let replies = [
            ("findmnt -n -o SOURCE /", "/dev/vda1\n"),
            ("NAME,TYPE,MOUNTPOINT,PKNAME", WALK),
            ("grep -F 'orchard-reclaim:'", "CRUMB-DONE"),
            ("NAME,TYPE,START,SIZE", grown_extents()),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = arbitrate(&mut r, &pre(), &window()).unwrap_err();
        assert_eq!(e.row, rows::NO_CRUMB);
        assert!(e.reason.contains("kernel scope"), "{e}");
    }

    #[test]
    fn arbitrate_skip_shaped_crumb_lands_on_intersects_with_the_crumb() {
        let crumb_skip = "<3>orchard-reclaim: step4 SKIP resize2fs rc=1, only rc 0 is success (§6.4)\nCRUMB-DONE";
        let replies = [
            ("findmnt -n -o SOURCE /", "/dev/vda1\n"),
            ("NAME,TYPE,MOUNTPOINT,PKNAME", WALK),
            ("grep -F 'orchard-reclaim:'", crumb_skip),
            ("NAME,TYPE,START,SIZE", grown_extents()),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = arbitrate(&mut r, &pre(), &window()).unwrap_err();
        assert_eq!(e.row, rows::INTERSECTS);
        assert!(e.reason.contains("SKIP resize2fs"), "{e}");
    }

    #[test]
    fn disarm_removes_rebuilds_and_verifies_path_absence() {
                                                                                 
        let clean = "usr/sbin/e2fsck\nscripts/local-premount/resume\n\
                     LS-OK:/boot/initrd.img-6.1.0-0-amd64\nLS-COUNT:1\nLS-DONE";
        let replies = [
            ("rm -f /etc/initramfs-tools/hooks/orchard-reclaim", "RC:0"),
            ("update-initramfs -u -k all", "RC:0"),
            ("lsinitramfs", clean),
        ];
        let mut r = ScriptReader::new(&replies);
        disarm(&mut r, "all").unwrap();

                                                                                         
        let armed = "scripts/local-premount/orchard-reclaim\n\
                     LS-OK:/boot/initrd.img-6.1.0-0-amd64\nLS-COUNT:1\nLS-DONE";
        let replies = [
            ("rm -f /etc/initramfs-tools/hooks/orchard-reclaim", "RC:0"),
            ("update-initramfs -u -k all", "RC:0"),
            ("lsinitramfs", armed),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = disarm(&mut r, "all").unwrap_err();
        assert_eq!(e.row, rows::DISARM);
        assert!(e.reason.contains("still armed"), "{e}");

                                                                                                   
                                                                
        let empty = "LS-COUNT:0\nLS-DONE";
        let replies = [
            ("rm -f /etc/initramfs-tools/hooks/orchard-reclaim", "RC:0"),
            ("update-initramfs -u -k all", "RC:0"),
            ("lsinitramfs", empty),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = disarm(&mut r, "all").unwrap_err();
        assert_eq!(e.row, rows::DISARM);
        assert!(e.reason.contains("enumerated NO initrd"), "{e}");

                                                                                                   
                            
        let unreadable = "LS-FAIL:/boot/initrd.img-6.1.0-0-amd64\nLS-COUNT:1\nLS-DONE";
        let replies = [
            ("rm -f /etc/initramfs-tools/hooks/orchard-reclaim", "RC:0"),
            ("update-initramfs -u -k all", "RC:0"),
            ("lsinitramfs", unreadable),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = disarm(&mut r, "all").unwrap_err();
        assert_eq!(e.row, rows::DISARM);
        assert!(e.reason.contains("could not read"), "{e}");

                                                                                             
        let replies = [
            ("rm -f /etc/initramfs-tools/hooks/orchard-reclaim", "RC:0"),
            ("update-initramfs -u -k all", "RC:1"),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = disarm(&mut r, "all").unwrap_err();
        assert!(e.reason.contains("previous initrd"), "{e}");
    }

    #[test]
    fn poll_cancel_is_observed_within_one_tick() {
                                                                           
        let ticks = Cell::new(0u32);
        let out = poll_loop(|| false, || true, || ticks.set(ticks.get() + 1), 1800, 15);
        assert!(matches!(out, PollOutcome::Cancelled));
        assert_eq!(ticks.get(), 0, "no sleep before the cancel is observed");
        let refusal = poll_refusal(&out, 1800).unwrap();
        assert!(refusal.reason.contains("UNKNOWN"), "{refusal}");
    }

    #[test]
    fn poll_times_out_bounded_and_alive_wins() {
        let ticks = Cell::new(0u32);
        let out = poll_loop(|| false, || false, || ticks.set(ticks.get() + 1), 60, 15);
        assert!(matches!(out, PollOutcome::TimedOut));
        assert_eq!(ticks.get(), 4, "60s bound at 15s cadence");
        let refusal = poll_refusal(&out, 60).unwrap();
        assert!(refusal.reason.contains("VNC"), "{refusal}");

        let mut n = 0;
        let out = poll_loop(
            move || {
                n += 1;
                n >= 3
            },
            || false,
            || {},
            1800,
            15,
        );
        assert!(matches!(out, PollOutcome::Alive));
        assert!(poll_refusal(&out, 1800).is_none());
    }
}
