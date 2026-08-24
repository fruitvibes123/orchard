                                                                                                  
                                                                                              
//! refusal here fires with the target untouched (§7 rows `R-ELIG`); every remote command is a
//! read structured to exit 0 with its own `RC:`/marker tokens.
//!
//! Grounding: the dpkg status/selection states are `probes-r17-pre/p17pre_dpkg_status.sh` and
//! `probes-r17/p17_fold_hold.sh`; the F_GETLK reader is `probes-r12/p_getlk.sh`; the
//! `findmnt --target` semantics were re-measured at util-linux 2.42.2 for this task (plain
//! `findmnt -n -o SOURCE <path>` returns rc 1/empty for a path that is not its own mountpoint,
//! so the class's desired /boot-on-root state needs `--target`, whose output may carry a
//! `[subdir]` suffix that is stripped before comparison).

use super::{CLOUD_INIT_DISABLED_MARKER, REQUIRED_BINARIES, ReclaimRefusal, TargetReader, rows};
use crate::deploy::prod::PartitionExtent;

/// What the reclaim needs to know about the ceremony it rides in (T9 fills it from
/// `deploy_prod`'s existing values; the standalone verb re-derives them the same way).
#[derive(Debug, Clone)]
pub struct ReclaimCtx {
    /// Parent-walk disk name, e.g. `vda`.
    pub disk: String,
    /// The root filesystem's device node, e.g. `/dev/vda1`.
    pub root_dev: String,
    /// The staging window (from `place_and_check_window`).
    pub window_offset: u64,
    pub window_len: u64,
}

/// The doomed partition, identified from the D-1 extents (all byte quantities).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoomedPartition {
    /// `vda1` — the lsblk NAME / sysfs name.
    pub sysfs: String,
    /// `/dev/vda1`.
    pub node: String,
    /// The partition number `sfdisk -N` takes (trailing digits of the name).
    pub num: u32,
    pub start: u64,
    /// The original (pre-shrink) end.
    pub end: u64,
}

/// The read-only half's product: the doomed partition plus the one-call `dumpe2fs -h` factors
                                   
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibilityOk {
    pub part: DoomedPartition,
    pub block_size: u64,
    pub fs_bytes: u64,
                                                                         
    pub growroot_installed: bool,
    /// True if the cloud-init.disabled marker is on the target BEFORE this run — a prior run's
                                                                                               
    /// refusal disclosure carries the target-scoped fact even when growroot is still installed.
    pub marker_present: bool,
}

                                                                                                   

                                                                                           
/// echoed as `MISSING:<name>` / `MISSING-DIR:<path>`. The command always exits 0.
pub fn capability_probe_cmd() -> String {
    let mut tools: Vec<&str> = vec![
        "update-initramfs",
        "lsinitramfs",
        "unmkinitramfs",
        "apt-get",
        "cloud-init",
        "python3",
    ];
    tools.extend(REQUIRED_BINARIES);
    let tool_loop = format!(
        "for c in {}; do command -v \"$c\" >/dev/null 2>&1 || echo \"MISSING:$c\"; done",
        tools.join(" ")
    );
    let dirs = [
        "/etc/initramfs-tools/hooks",
        "/etc/initramfs-tools/scripts/local-premount",
        "/etc/cloud",
    ];
    let dir_probes: Vec<String> = dirs
        .iter()
        .map(|d| format!("test -d {d} || echo \"MISSING-DIR:{d}\""))
        .collect();
    format!(
        "{tool_loop}; {}; echo CAP-PROBE-DONE",
        dir_probes.join("; ")
    )
}

                                                                                                  
/// (`dpkg-query -W -f` prints no trailing newline, so ` RC:n` lands on the same line; rc 1 = no
/// record — `p17pre_dpkg_status.sh`).
pub const GROWROOT_STATUS_CMD: &str = "dpkg-query -W -f='${db:Status-Want} ${db:Status-Status}' cloud-initramfs-growroot 2>/dev/null; echo \" RC:$?\"";

                        
pub fn marker_probe_cmd() -> String {
    format!("test -e {CLOUD_INIT_DISABLED_MARKER} && echo marker-present || echo marker-absent")
}

                                    
pub const ROOT_FSTYPE_CMD: &str = "findmnt -n -o FSTYPE / 2>/dev/null; echo RC:$?";

                                                                                           
/// non-mountpoint (measured; the plain form returns rc 1/empty on the class's desired state).
pub const BOOT_SOURCE_CMD: &str = "findmnt -n -o SOURCE --target /boot 2>/dev/null; echo RC:$?";

                                                                            
pub fn dumpe2fs_cmd(node: &str) -> String {
    format!("dumpe2fs -h \"{node}\" 2>/dev/null; echo RC:$?")
}

                                                                                                   

fn refuse(reason: String) -> ReclaimRefusal {
    ReclaimRefusal::new(rows::ELIG, reason)
}

/// Split a probe output into (body, rc) on the trailing `RC:n` token. A missing or non-numeric
/// rc token refuses (fail-closed: the probe contract was not met).
pub(crate) fn split_rc(out: &str, what: &str) -> Result<(String, u32), ReclaimRefusal> {
    let trimmed = out.trim_end();
    let (body, rc_tok) = match trimmed.rsplit_once("RC:") {
        Some(x) => x,
        None => return Err(refuse(format!("{what}: probe output carries no RC token"))),
    };
    let rc: u32 = rc_tok
        .trim()
        .parse()
        .map_err(|_| refuse(format!("{what}: non-numeric RC token {rc_tok:?}")))?;
    Ok((body.trim_end().to_string(), rc))
}

                                                                                        
fn anchored_u64(body: &str, anchor: &str, what: &str) -> Result<u64, ReclaimRefusal> {
    let mut hits = body.lines().filter(|l| l.starts_with(anchor));
    let line = match (hits.next(), hits.next()) {
        (Some(l), None) => l,
        (None, _) => {
            return Err(refuse(format!(
                "{what}: anchored pattern {anchor:?} matched 0 lines, need exactly one"
            )));
        }
        (Some(_), Some(_)) => {
            return Err(refuse(format!(
                "{what}: anchored pattern {anchor:?} matched more than one line, need exactly \
                 one"
            )));
        }
    };
    let value = line[anchor.len()..].trim();
    if value.is_empty() {
        return Err(refuse(format!("{what}: {anchor:?} value is empty")));
    }
    value
        .parse()
        .map_err(|_| refuse(format!("{what}: {anchor:?} value {value:?} is non-numeric")))
}

                                                                                       
pub fn parse_dumpe2fs_h(body: &str) -> Result<(u64, u64), ReclaimRefusal> {
    let count = anchored_u64(body, "Block count:", "dumpe2fs -h")?;
    let size = anchored_u64(body, "Block size:", "dumpe2fs -h")?;
    Ok((count, size))
}

fn basename(dev: &str) -> &str {
    dev.rsplit('/').next().unwrap_or(dev)
}

fn trailing_number(name: &str) -> Option<u32> {
    let digits: String = name
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

                                                                                                   

                                                                                           
pub fn identify_doomed(
    ctx: &ReclaimCtx,
    extents: &[PartitionExtent],
) -> Result<DoomedPartition, ReclaimRefusal> {
    let wend = ctx.window_offset.saturating_add(ctx.window_len);
    let intersecting: Vec<&PartitionExtent> = extents
        .iter()
        .filter(|e| e.start < wend && e.end > ctx.window_offset)
        .collect();
                                                                                                   
                                                       
    if intersecting.len() != 1 {
        return Err(refuse(format!(
            "{} partitions intersect the staging window, need exactly one: [{}]",
            intersecting.len(),
            intersecting
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let doomed = intersecting[0];
                                                      
    if doomed.name != basename(&ctx.root_dev) {
        return Err(refuse(format!(
            "the intersecting partition {} is not the root partition {}",
            doomed.name, ctx.root_dev
        )));
    }
                                                                                                
                                          
    if let Some(higher) = extents.iter().find(|e| e.end > doomed.end) {
        return Err(refuse(format!(
            "partition {} ends at {} beyond the root's {} — the root is not the last partition \
             by end offset",
            higher.name, higher.end, doomed.end
        )));
    }
    let num = trailing_number(&doomed.name).ok_or_else(|| {
        refuse(format!(
            "cannot derive a partition number from {:?} (sfdisk -N needs one)",
            doomed.name
        ))
    })?;
                                                                                                 
                                                                                             
                                                                                      
    if doomed.name.is_empty()
        || !doomed
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(refuse(format!(
            "doomed partition name {:?} carries a character outside [A-Za-z0-9_-] — refusing to \
             interpolate it into a root-run shell command (fail-closed)",
            doomed.name
        )));
    }
    Ok(DoomedPartition {
        sysfs: doomed.name.clone(),
        node: format!("/dev/{}", doomed.name),
        num,
        start: doomed.start,
        end: doomed.end,
    })
}

                                                                                                
                                                                                              
                                                                                               
                                                                                                       
/// a gate (decision record 2026-08-05).
pub fn check_eligibility_readonly(
    reader: &mut dyn TargetReader,
    ctx: &ReclaimCtx,
    extents: &[PartitionExtent],
) -> Result<EligibilityOk, ReclaimRefusal> {
                                             
    let cap = reader
        .capture(&capability_probe_cmd())
        .map_err(|e| refuse(format!("capability probe failed: {e}")))?;
    if !cap.contains("CAP-PROBE-DONE") {
        return Err(refuse(
            "capability probe did not complete (no CAP-PROBE-DONE token)".into(),
        ));
    }
    let missing: Vec<&str> = cap
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("MISSING:") || l.starts_with("MISSING-DIR:"))
        .collect();
    if !missing.is_empty() {
        return Err(refuse(format!(
            "capability set not met: {}",
            missing.join(", ")
        )));
    }

                                                                                                    
                                                                                                 
    let (growroot_installed, marker_present) = growroot_conjunct(reader)?;

                                               
    let part = identify_doomed(ctx, extents)?;

                     
    let (fstype, rc) = split_rc(
        &reader
            .capture(ROOT_FSTYPE_CMD)
            .map_err(|e| refuse(format!("fstype probe failed: {e}")))?,
        "root fstype",
    )?;
    if rc != 0 || fstype.trim() != "ext4" {
        return Err(refuse(format!(
            "root filesystem type is {:?} (rc {rc}), need ext4",
            fstype.trim()
        )));
    }

                                                      
    let (boot_src_raw, rc) = split_rc(
        &reader
            .capture(BOOT_SOURCE_CMD)
            .map_err(|e| refuse(format!("/boot source probe failed: {e}")))?,
        "/boot source",
    )?;
    let boot_src = boot_src_raw.trim().split('[').next().unwrap_or("").trim();
    if rc != 0 || boot_src != ctx.root_dev {
        return Err(refuse(format!(
            "/boot resolves to {boot_src:?} (rc {rc}), not the root filesystem {} — \
             update-initramfs would write outside the ceremony's write set",
            ctx.root_dev
        )));
    }

                                                                                                 
    let (dump_body, rc) = split_rc(
        &reader
            .capture(&dumpe2fs_cmd(&part.node))
            .map_err(|e| refuse(format!("dumpe2fs probe failed: {e}")))?,
        "dumpe2fs -h",
    )?;
    if rc != 0 {
        return Err(refuse(format!(
            "dumpe2fs -h {} exited rc {rc} (failed read)",
            part.node
        )));
    }
    let (block_count, block_size) = parse_dumpe2fs_h(&dump_body)?;
    let fs_bytes = block_count.saturating_mul(block_size);

                                                                   
    let part_bytes = part.end.saturating_sub(part.start);
    if fs_bytes > part_bytes {
        return Err(refuse(format!(
            "filesystem {fs_bytes} bytes overhangs its partition {part_bytes} bytes on arrival \
; R4 holds this invariant only for partitions this component writes"
        )));
    }

    Ok(EligibilityOk {
        part,
        block_size,
        fs_bytes,
        growroot_installed,
        marker_present,
    })
}

                                                                                          
                                                                                              
/// status refuses; a `hold` selection refuses naming `apt-mark unhold` — its real purge fails
/// rc 100 with the package left installed, `p17_fold_hold.sh`).
fn growroot_conjunct(reader: &mut dyn TargetReader) -> Result<(bool, bool), ReclaimRefusal> {
    let raw = reader
        .capture(GROWROOT_STATUS_CMD)
        .map_err(|e| refuse(format!("growroot status probe failed: {e}")))?;
    let (body, rc) = split_rc(&raw, "growroot status")?;
                                                                                                     
                                                                                               
                                                                                                 
                                                                                            
    let m = reader
        .capture(&marker_probe_cmd())
        .map_err(|e| refuse(format!("marker probe failed: {e}")))?;
    let marker_present = m.contains("marker-present");
    let growroot_installed = match rc {
        0 => {
            let mut fields = body.split_whitespace();
            let want = fields.next().unwrap_or("");
            let status = fields.next().unwrap_or("");
            match status {
                "installed" if want == "hold" => {
                    return Err(refuse(
                        "cloud-initramfs-growroot is on dpkg selection `hold` — its purge would \
                         fail rc 100 with the package left installed; run `apt-mark unhold \
                         cloud-initramfs-growroot` first"
                            .into(),
                    ));
                }
                "installed" => true,
                "not-installed" if marker_present => false,
                "not-installed" => {
                    return Err(refuse(
                        "cloud-initramfs-growroot has a not-installed record and the \
                         cloud-init.disabled marker is absent — this target is not the class \
                         and was not neutralized by this component"
                            .into(),
                    ));
                }
                other => {
                    return Err(refuse(format!(
                        "cloud-initramfs-growroot dpkg status is {other:?} (selection {want:?}) — \
                         neither `installed` nor the gone-with-marker disjunct (`config-files` \
                         is the remove-not-purge state)"
                    )));
                }
            }
        }
        1 if marker_present => false,
        1 => {
            return Err(refuse(
                "cloud-initramfs-growroot has no dpkg record and the cloud-init.disabled \
                 marker is absent — this target is not the class"
                    .into(),
            ));
        }
        other => {
            return Err(refuse(format!(
                "growroot status read failed rc {other} — refusing fail-closed, never the \
                 already-absent branch ('s rc >= 2 arm)"
            )));
        }
    };
    Ok((growroot_installed, marker_present))
}

                                                                                                    

/// The reader script, grounded in `probes-r12/p_getlk.sh`: queries `F_GETLK` per path, reports
/// `FREE` or `HELD type=<n> pid=<n>`, acquires nothing, always exits 0.
pub const GETLK_READER_PY: &str = r#"import fcntl, struct, sys, os
FMT = 'hhqqi'
for p in sys.argv[1:]:
    try:
        fd = os.open(p, os.O_RDONLY)
    except OSError as e:
        print("%s OPEN-FAIL %s" % (p, e))
        continue
    try:
        buf = struct.pack(FMT, fcntl.F_WRLCK, 0, 0, 0, 0)
        t, wh, st, ln, pid = struct.unpack(FMT, fcntl.fcntl(fd, fcntl.F_GETLK, buf))
        if t == fcntl.F_UNLCK:
            print("%s FREE" % p)
        else:
            print("%s HELD type=%d pid=%d" % (p, t, pid))
    except OSError as e:
        print("%s GETLK-ERR %s" % (p, e))
    finally:
        os.close(fd)
"#;

/// The two production lock paths (dpkg and apt hold POSIX fcntl record locks on these).
pub const DPKG_LOCK_PATHS: [&str; 2] = ["/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"];

                                                                                             
/// passes a test-held path; production passes [`DPKG_LOCK_PATHS`]).
pub fn getlk_probe_cmd(lock_paths: &[&str]) -> String {
    format!(
        "python3 - {} <<'ORCHARD_RECLAIM_PY'\n{}ORCHARD_RECLAIM_PY",
        lock_paths.join(" "),
        GETLK_READER_PY
    )
}

                                                                                               
/// target untouched, naming the holder's pid and the retry — distinguishable from the §5.6
/// backstop's `R-NEUTRALIZE`.
pub fn lock_precheck(
    reader: &mut dyn TargetReader,
    lock_paths: &[&str],
) -> Result<(), ReclaimRefusal> {
    let out = reader
        .capture(&getlk_probe_cmd(lock_paths))
        .map_err(|e| refuse(format!("lock pre-check failed to run: {e}")))?;
    let mut seen = 0usize;
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.ends_with(" FREE") || line.ends_with("FREE") && line.contains(' ') {
            seen += 1;
            continue;
        }
        if line.contains("HELD") {
            return Err(refuse(format!(
                "a dpkg/apt lock is held ({line}) — the expected transient on this class \
                 (apt-daily / unattended-upgrades); wait for the holder to finish and re-run \
"
            )));
        }
        return Err(refuse(format!(
            "lock pre-check could not read a lock path ({line}) — refusing fail-closed"
        )));
    }
    if seen != lock_paths.len() {
        return Err(refuse(format!(
            "lock pre-check reported {seen} of {} paths — refusing fail-closed",
            lock_paths.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scripted reader: replies keyed on a command substring; records every issued command.
    struct ScriptReader {
        replies: Vec<(&'static str, String)>,
        issued: Vec<String>,
    }

    impl ScriptReader {
        fn new(replies: Vec<(&'static str, String)>) -> Self {
            Self {
                replies,
                issued: vec![],
            }
        }
    }

    impl TargetReader for ScriptReader {
        fn capture(&mut self, cmd: &str) -> Result<String, String> {
            self.issued.push(cmd.to_string());
            for (needle, reply) in &self.replies {
                if cmd.contains(needle) {
                    return Ok(reply.clone());
                }
            }
            panic!("unscripted command: {cmd}");
        }
    }

    fn ctx() -> ReclaimCtx {
                                                                                             
        ReclaimCtx {
            disk: "vda".into(),
            root_dev: "/dev/vda1".into(),
            window_offset: 41053847552,
            window_len: 1892036608,
        }
    }

    fn class_extents() -> Vec<PartitionExtent> {
                                                                                               
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

    fn happy_replies() -> Vec<(&'static str, String)> {
        vec![
            ("CAP-PROBE-DONE", "CAP-PROBE-DONE\n".into()),
            ("dpkg-query", "install installed RC:0".into()),
            ("cloud-init.disabled", "marker-absent\n".into()),
            ("FSTYPE", "ext4\nRC:0".into()),
            ("SOURCE --target /boot", "/dev/vda1\nRC:0".into()),
            (
                "dumpe2fs -h",
                "Block count:              9989888\nBlock size:               4096\nRC:0".into(),
            ),
        ]
    }

    fn run_ok() -> EligibilityOk {
        let mut r = ScriptReader::new(happy_replies());
        check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap()
    }

    #[test]
    fn happy_path_yields_the_doomed_partition_and_the_one_read_factors() {
        let ok = run_ok();
        assert_eq!(ok.part.sysfs, "vda1");
        assert_eq!(ok.part.node, "/dev/vda1");
        assert_eq!(ok.part.num, 1);
        assert_eq!(ok.part.start, 134217728);
        assert_eq!(ok.part.end, 42948624384);
        assert_eq!(ok.block_size, 4096);
        assert_eq!(ok.fs_bytes, 9989888 * 4096);
        assert!(ok.growroot_installed);
    }

    #[test]
    fn doomed_partition_name_with_metacharacter_refuses() {
                                                                                               
                                                                                                 
                                                                                                 
                                                                                                  
        let ctx = ReclaimCtx {
            root_dev: "/dev/vda$(id)1".into(),
            ..ctx()
        };
        let extents = vec![PartitionExtent {
            name: "vda$(id)1".into(),
            start: 0,
            end: u64::MAX,
        }];
        let e = identify_doomed(&ctx, &extents).unwrap_err();
        assert!(e.reason.contains("root-run shell command"), "{e}");
    }

    #[test]
    fn every_probe_command_is_read_only_by_allowlist() {
                                                                                                  
                                                                                            
        let mut r = ScriptReader::new(happy_replies());
        check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap();
        let allow = [
            "for c in ",
            "dpkg-query -W",
            "test -e /etc/cloud/cloud-init.disabled",
            "findmnt -n -o",
            "dumpe2fs -h",
        ];
        for cmd in &r.issued {
            assert!(
                allow.iter().any(|p| cmd.starts_with(p)),
                "command outside the read-only allowlist: {cmd}"
            );
        }
        assert!(r.issued.len() >= 5, "expected the full probe sequence");
    }

    #[test]
    fn capability_members_absent_in_turn_refuse_naming_them() {
        let mut members = vec![
            "update-initramfs",
            "lsinitramfs",
            "unmkinitramfs",
            "apt-get",
            "cloud-init",
            "python3",
        ];
        members.extend(REQUIRED_BINARIES);
        for m in members {
            let mut replies = happy_replies();
            replies[0] = ("CAP-PROBE-DONE", format!("MISSING:{m}\nCAP-PROBE-DONE\n"));
            let mut r = ScriptReader::new(replies);
            let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
            assert_eq!(e.row, rows::ELIG);
            assert!(e.reason.contains(m), "{e}");
        }
        for d in [
            "/etc/initramfs-tools/hooks",
            "/etc/initramfs-tools/scripts/local-premount",
            "/etc/cloud",
        ] {
            let mut replies = happy_replies();
            replies[0] = (
                "CAP-PROBE-DONE",
                format!("MISSING-DIR:{d}\nCAP-PROBE-DONE\n"),
            );
            let mut r = ScriptReader::new(replies);
            let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
            assert!(e.reason.contains(d), "{e}");
        }
    }

    #[test]
    fn growroot_predicate_all_arms() {
                                                                                 
        let mut replies = happy_replies();
        replies[1] = ("dpkg-query", "hold installed RC:0".into());
        let mut r = ScriptReader::new(replies);
        let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
        assert!(e.reason.contains("apt-mark unhold"), "{e}");

                                                                                            
        let mut replies = happy_replies();
        replies[1] = ("dpkg-query", "deinstall not-installed RC:0".into());
        replies[2] = ("cloud-init.disabled", "marker-present\n".into());
        let mut r = ScriptReader::new(replies);
        let ok = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap();
        assert!(!ok.growroot_installed);

                                                    
        let mut replies = happy_replies();
        replies[1] = ("dpkg-query", " RC:1".into());
        replies[2] = ("cloud-init.disabled", "marker-present\n".into());
        let mut r = ScriptReader::new(replies);
        assert!(
            !check_eligibility_readonly(&mut r, &ctx(), &class_extents())
                .unwrap()
                .growroot_installed
        );

                                                              
        let mut replies = happy_replies();
        replies[1] = ("dpkg-query", " RC:1".into());
        let mut r = ScriptReader::new(replies);
        let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
        assert!(e.reason.contains("not the class"), "{e}");

                                                                                    
                                    
        for marker in ["marker-present", "marker-absent"] {
            let mut replies = happy_replies();
            replies[1] = ("dpkg-query", "deinstall config-files RC:0".into());
            replies[2] = ("cloud-init.disabled", format!("{marker}\n"));
            let mut r = ScriptReader::new(replies);
            let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
            assert!(e.reason.contains("config-files"), "{e}");
        }

                                                                           
        let mut replies = happy_replies();
        replies[1] = ("dpkg-query", "garbage RC:2".into());
        let mut r = ScriptReader::new(replies);
        let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
        assert!(e.reason.contains("fail-closed"), "{e}");
    }

    #[test]
    fn partition_identity_refusals() {
                                                                   
        let mut c = ctx();
        c.window_offset = 5000000;
        c.window_len = 1000000;
        let mut r = ScriptReader::new(happy_replies());
        let e = check_eligibility_readonly(&mut r, &c, &class_extents()).unwrap_err();
        assert!(e.reason.contains("not the root partition"), "{e}");

                                                                  
        let mut ex = class_extents();
        ex.push(PartitionExtent {
            name: "vda2".into(),
            start: 42948624384,
            end: 42949000000,
        });
                                                                                       
                                                                                        
                                                                                   
        let mut r = ScriptReader::new(happy_replies());
        let e = check_eligibility_readonly(&mut r, &ctx(), &ex).unwrap_err();
        assert!(e.reason.contains("by end offset"), "{e}");

                                   
        let mut ex = class_extents();
        ex.push(PartitionExtent {
            name: "vda2".into(),
            start: 41060000000,
            end: 41070000000,
        });
        let mut r = ScriptReader::new(happy_replies());
        let e = check_eligibility_readonly(&mut r, &ctx(), &ex).unwrap_err();
        assert!(e.reason.contains("need exactly one"), "{e}");

                                                                
        let mut c = ctx();
        c.window_offset = 42949000000;
        c.window_len = 1000;
        let mut r = ScriptReader::new(happy_replies());
        assert!(check_eligibility_readonly(&mut r, &c, &class_extents()).is_err());
    }

    #[test]
    fn fstype_and_boot_refusals() {
                           
        let mut replies = happy_replies();
        replies[3] = ("FSTYPE", "btrfs\nRC:0".into());
        let mut r = ScriptReader::new(replies);
        let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
        assert!(e.reason.contains("ext4"), "{e}");

                                          
        let mut replies = happy_replies();
        replies[4] = ("SOURCE --target /boot", "/dev/vda15\nRC:0".into());
        let mut r = ScriptReader::new(replies);
        let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
        assert!(e.reason.contains("write set"), "{e}");

                                                                                         
        let mut replies = happy_replies();
        replies[4] = ("SOURCE --target /boot", "/dev/vda1[/@]\nRC:0".into());
        let mut r = ScriptReader::new(replies);
        assert!(check_eligibility_readonly(&mut r, &ctx(), &class_extents()).is_ok());
    }

    #[test]
    fn dumpe2fs_defects_and_overhang_refuse() {
                                                             
        let mut replies = happy_replies();
        replies[5] = (
            "dumpe2fs -h",
            "Block count: 1\nBlock count: 2\nBlock size: 4096\nRC:0".into(),
        );
        let mut r = ScriptReader::new(replies);
        let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
        assert!(e.reason.contains("exactly one"), "{e}");

                       
        let mut replies = happy_replies();
        replies[5] = (
            "dumpe2fs -h",
            "Block count: x\nBlock size: 4096\nRC:0".into(),
        );
        let mut r = ScriptReader::new(replies);
        assert!(check_eligibility_readonly(&mut r, &ctx(), &class_extents()).is_err());

                                 
        let mut replies = happy_replies();
        replies[5] = ("dumpe2fs -h", "RC:1".into());
        let mut r = ScriptReader::new(replies);
        assert!(check_eligibility_readonly(&mut r, &ctx(), &class_extents()).is_err());

                                                             
        let mut replies = happy_replies();
        replies[5] = (
            "dumpe2fs -h",
            "Block count:              10486000\nBlock size:               4096\nRC:0".into(),
        );
        let mut r = ScriptReader::new(replies);
        let e = check_eligibility_readonly(&mut r, &ctx(), &class_extents()).unwrap_err();
        assert!(e.reason.contains("overhang"), "{e}");
    }

    #[test]
    fn lock_precheck_refuses_held_and_unreadable_passes_free() {
        struct One(String);
        impl TargetReader for One {
            fn capture(&mut self, _cmd: &str) -> Result<String, String> {
                Ok(self.0.clone())
            }
        }
                            
        let mut r = One("/var/lib/dpkg/lock-frontend FREE\n/var/lib/dpkg/lock FREE\n".into());
        assert!(lock_precheck(&mut r, &DPKG_LOCK_PATHS).is_ok());
                                                                                        
        let mut r = One(
            "/var/lib/dpkg/lock-frontend HELD type=1 pid=4242\n/var/lib/dpkg/lock FREE\n".into(),
        );
        let e = lock_precheck(&mut r, &DPKG_LOCK_PATHS).unwrap_err();
        assert_eq!(e.row, rows::ELIG);
        assert!(e.reason.contains("4242"), "{e}");
                                             
        let mut r =
            One("/var/lib/dpkg/lock-frontend OPEN-FAIL x\n/var/lib/dpkg/lock FREE\n".into());
        assert!(lock_precheck(&mut r, &DPKG_LOCK_PATHS).is_err());
                                                                  
        let mut r = One("/var/lib/dpkg/lock-frontend FREE\n".into());
        assert!(lock_precheck(&mut r, &DPKG_LOCK_PATHS).is_err());
    }

    #[test]
    fn lock_precheck_against_a_really_held_fcntl_lock() {
                                                                                                
                                                                                               
                                                                                               
                       
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("test.lock");
        std::fs::write(&lock_path, b"x").unwrap();
        let mut holder = std::process::Command::new("python3")
            .arg("-c")
            .arg(
                "import fcntl,sys,time\nf=open(sys.argv[1],'w')\nfcntl.lockf(f, fcntl.LOCK_EX)\nprint('LOCKED', flush=True)\ntime.sleep(30)",
            )
            .arg(&lock_path)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("python3 is a make-verify host dependency (§9)");
                                                   
        let mut buf = [0u8; 6];
        holder
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut buf)
            .unwrap();
        assert_eq!(&buf, b"LOCKED");

        struct LocalSh;
        impl TargetReader for LocalSh {
            fn capture(&mut self, cmd: &str) -> Result<String, String> {
                let out = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .output()
                    .map_err(|e| e.to_string())?;
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            }
        }
        let lp = lock_path.to_str().unwrap().to_string();
        let paths = [lp.as_str()];
        let mut r = LocalSh;
        let e = lock_precheck(&mut r, &paths).unwrap_err();
        assert_eq!(e.row, rows::ELIG);
        assert!(
            e.reason.contains(&format!("pid={}", holder.id())),
            "reader must report the real holder's pid: {e}"
        );
                                                                                       
        let e2 = lock_precheck(&mut r, &paths).unwrap_err();
        assert!(e2.reason.contains(&format!("pid={}", holder.id())), "{e2}");
        holder.kill().ok();
        holder.wait().ok();
    }
}
