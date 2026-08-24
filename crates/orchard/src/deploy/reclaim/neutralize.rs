//! Neutralization, the write half (plan T6): the three permanent re-grow neutralizations in
                                                                                             
                                                                                               
//! marker is that signature's second disjunct, so it goes first). Every Err exit is a
//! [`NeutralizeExit`] variant whose table entry declares the §7 row and the run-wrote fact: the
//! read-only feasibility prefix (the fstab read + `edit_fstab`, before the marker) is row `R-ELIG`
                                                                                               
                                                                                          
//!
//! Grounding: the dpkg states and the rc-100 absent-package apt behaviour are
                                                                                          
//! failure is `probes-r17/p17_fold_hold.sh`; the multi-occurrence fstab vectors are
//! `probes-r17/p17_r1211.sh` (e2_minus_one stays ARMED, e3/e5 disarm).

use super::eligibility::{GROWROOT_STATUS_CMD, marker_probe_cmd, split_rc};
use super::fstab_model::{FSTAB_HEREDOC_MARKER, edit_fstab, verify_fstab_edit};
use super::{CLOUD_INIT_DISABLED_MARKER, ReclaimRefusal, TargetReader, rows};

super::closed_enum_table! {
    /// EVERY Err exit of [`neutralize`], one variant per site — the closed set the consequence
    /// census (`ceremony.rs`) covers by SET-EQUALITY against `ALL`, replacing the beatable
                                                                             
    ///
    /// `R-ELIG` only for the read-only feasibility prefix (the fstab read + `edit_fstab`, both
                                                                                                   
                                                                                                   
                                                                                                 
    /// row is DERIVED from this table at the one constructor `nrefuse`, so no site can name a row by
                                                                   
    ///
    /// The disclosure is no longer per-arm: the operator note is a constant appended on every
    /// reclaim-region failure (`prod_orchestrate::reclaim_abort_text`), so this table carries only
    /// the row, not a per-exit permanence bool (the old `run_wrote` column, dead after the R11→R12
    /// disclosure simplification).
    enum NeutralizeExit -> &'static str {
                                                                                 
        FeasReadTransport => rows::ELIG,
        FeasParse => rows::ELIG,
        FeasEdit => rows::ELIG,
                                                     
        MarkerWriteTransport => rows::NEUTRALIZE,
        MarkerWriteSplitRc => rows::NEUTRALIZE,
        MarkerWriteRc => rows::NEUTRALIZE,
        MarkerVerifyTransport => rows::NEUTRALIZE,
        MarkerVerifyAbsent => rows::NEUTRALIZE,
                                              
        LockPrecheck => rows::NEUTRALIZE,
                                                  
        GrowrootStatusTransport => rows::NEUTRALIZE,
        GrowrootStatusSplitRc => rows::NEUTRALIZE,
        PurgeRouteRefuse => rows::NEUTRALIZE,
        PurgeDryrunTransport => rows::NEUTRALIZE,
        PurgeDryrunSplitRc => rows::NEUTRALIZE,
        PurgeSetWrong => rows::NEUTRALIZE,
        PurgeTransport => rows::NEUTRALIZE,
        PurgeSplitRc => rows::NEUTRALIZE,
        PurgeVerifyTransport => rows::NEUTRALIZE,
        PurgeVerifySplitRc => rows::NEUTRALIZE,
        PurgeDidNotTake => rows::NEUTRALIZE,
                                                                           
        FstabReadTransport => rows::NEUTRALIZE,
        FstabParse => rows::NEUTRALIZE,
        FstabEdit => rows::NEUTRALIZE,
        FstabWriteTransport => rows::NEUTRALIZE,
        FstabWriteSplitRc => rows::NEUTRALIZE,
        FstabWriteRc => rows::NEUTRALIZE,
        FstabRereadTransport => rows::NEUTRALIZE,
        FstabRereadParse => rows::NEUTRALIZE,
        FstabVerify => rows::NEUTRALIZE,
    }
    fn = row
}

/// The ONE constructor of a `neutralize` refusal: the §7 row comes from the exit's table entry,
/// never a call site. Adding an Err exit without declaring a variant (its row) does not compile;
/// declaring one grows `NeutralizeExit::ALL` and fails the census set-equality until an arm drives
/// it.
fn nrefuse(exit: NeutralizeExit, reason: impl Into<String>) -> NeutralizeRefusal {
    NeutralizeRefusal {
        exit,
        refusal: ReclaimRefusal::new(exit.row(), reason),
    }
}

                                                                                                   

pub fn marker_write_cmd() -> String {
    format!("touch {CLOUD_INIT_DISABLED_MARKER} 2>/dev/null; echo RC:$?")
}

pub const PURGE_DRYRUN_CMD: &str =
    "apt-get purge --dry-run cloud-initramfs-growroot 2>/dev/null; echo RC:$?";

pub const PURGE_CMD: &str = "DEBIAN_FRONTEND=noninteractive apt-get purge -y cloud-initramfs-growroot 2>/dev/null 1>&2; echo RC:$?";

pub const FSTAB_READ_CMD: &str = "cat /etc/fstab 2>/dev/null; rc=$?; echo FSTAB-DONE; echo RC:$rc";

pub fn fstab_write_cmd(content: &str) -> String {
    format!(
        "cat > /etc/fstab <<'{FSTAB_HEREDOC_MARKER}'\n{content}{FSTAB_HEREDOC_MARKER}\necho RC:$?"
    )
}

                                                                                                   

                                                                                               
/// code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeRoute {
    /// Status `installed`: compute the removal set with apt, purge, then re-verify.
    Apt,
    /// A `not-installed` record (rc 0, empty version) or no record at all (rc 1): the re-run
    /// case; no apt call is made.
    AlreadyAbsent,
    /// Everything else refuses at row `R-NEUTRALIZE` naming the query result.
    Refuse(String),
}

                                                                                            
pub fn purge_predicate(rc: u32, want: &str, status: &str) -> PurgeRoute {
    match rc {
        0 => match status {
            "installed" => PurgeRoute::Apt,
            "not-installed" => PurgeRoute::AlreadyAbsent,
            other => PurgeRoute::Refuse(format!(
                "cloud-initramfs-growroot dpkg status is {other:?} (selection {want:?}) — an \
                 rc-0 status neither `installed` nor `not-installed` refuses (\
                 `config-files` is the remove-not-purge state)"
            )),
        },
        1 => PurgeRoute::AlreadyAbsent,
        other => PurgeRoute::Refuse(format!(
            "growroot status query failed rc {other} — refusing, never the already-absent \
             branch ('s rc >= 2 arm)"
        )),
    }
}

/// Parse a `FSTAB_READ_CMD` reply (`cat /etc/fstab 2>/dev/null; rc=$?; echo FSTAB-DONE; echo RC:$rc`)
                                                                                              
                                                                                                    
/// an `FSTAB-DONE` occurring INSIDE the fstab body (a comment is the realistic carrier) is preserved —
                                                                                                       
/// the caller sets its own §7 row.
fn parse_fstab_reply(out: &str) -> Result<String, String> {
    let trimmed = out.trim_end();
    let (before_rc, rc_tok) = trimmed.rsplit_once("RC:").ok_or_else(|| {
        "fstab reply carries no RC token — a truncated read; refusing fail-closed".to_string()
    })?;
    let rc: i64 = rc_tok
        .trim()
        .parse()
        .map_err(|_| format!("fstab reply has a non-numeric RC token {rc_tok:?}"))?;
    if rc != 0 {
        return Err(format!(
            "reading /etc/fstab failed (cat rc {rc}) — a partial read on the filesystem being \
             shrunk could hide an armed entry; refusing fail-closed"
        ));
    }
    let before = before_rc.trim_end();
                                                                                                       
                                                                                                        
                                                                                                     
                                                                      
    let Some(body) = before.strip_suffix("FSTAB-DONE") else {
        return Err(
            "fstab reply's last content line is not the FSTAB-DONE marker — a truncated read; \
             refusing fail-closed (7)"
                .to_string(),
        );
    };
    if !body.is_empty() && !body.ends_with('\n') {
        return Err(
            "the FSTAB-DONE marker is glued to a non-terminated last line — a truncated read; \
             refusing fail-closed"
                .to_string(),
        );
    }
                                                                                                      
                                                                                                      
                                                                                 
    if body.contains('\u{FFFD}') {
        return Err(
            "fstab carries a byte the read cannot represent (U+FFFD after a lossy UTF-8 decode) — \
             refusing to rewrite a file that cannot be read exactly, fail-closed"
                .to_string(),
        );
    }
                                                                                                     
                                                                                                      
                                                                                                         
                                                                                                        
                                                                  
    if body.contains('\0') {
        return Err(
            "fstab carries a NUL byte, which ends glibc getmntent's view of the line but not the \
             tool's — an arming token behind it would under-strip; refusing to rewrite a file the real \
             parser reads differently, fail-closed"
                .to_string(),
        );
    }
    Ok(body.to_string())
}

                                                                                                   

/// A `neutralize` failure: the refusal plus WHICH exit produced it. The exit names its §7 row (the
/// table above). The operator disclosure is not carried here: every reclaim-region failure appends
                                                                                                  
/// permanence unconditionally rather than reading a per-exit fact.
#[derive(Debug)]
pub(crate) struct NeutralizeRefusal {
    pub exit: NeutralizeExit,
    pub refusal: ReclaimRefusal,
}

                                                                                              
/// re-check runs immediately before the purge (a lock taken between §5.3 and here surfaces as
/// `R-NEUTRALIZE`, distinguishable from the read-only half's `R-ELIG`). Every Err exit is a
/// `NeutralizeExit` variant built through `nrefuse`, so the caller names the §7 row and the census
                                                                                                  
/// on every path, not per exit.
pub(crate) fn neutralize(reader: &mut dyn TargetReader) -> Result<(), NeutralizeRefusal> {
    use NeutralizeExit as E;
                                                                                                      
                                                                                                      
                                                                                                 
                                                                                                          
                                                                                                     
                                                                                               
                                                                                            
    {
        let probe = parse_fstab_reply(
            &reader
                .capture(FSTAB_READ_CMD)
                .map_err(|e| nrefuse(E::FeasReadTransport, format!("fstab read failed: {e}")))?,
        )
        .map_err(|e| nrefuse(E::FeasParse, e))?;
        edit_fstab(&probe).map_err(|e| nrefuse(E::FeasEdit, format!("fstab edit refused: {e}")))?;
    }

                                                                                                
                                                                                                 
                                                                                                   
                                                                                                     
                                                                                                
                                                                                                  
                                                                                                  
                                                                                                   
                                           
    let (_, rc) = split_rc(
        &reader.capture(&marker_write_cmd()).map_err(|e| {
            nrefuse(
                E::MarkerWriteTransport,
                format!("marker write failed to run: {e}"),
            )
        })?,
        "marker write",
    )
    .map_err(|e| nrefuse(E::MarkerWriteSplitRc, e.reason))?;
    if rc != 0 {
        return Err(nrefuse(
            E::MarkerWriteRc,
            format!(
                "writing {CLOUD_INIT_DISABLED_MARKER} reported rc {rc} — this run's touch failed \
; whether the file was created is unknown (touch opens before it sets \
                 times)"
            ),
        ));
    }
    let verify = reader.capture(&marker_probe_cmd()).map_err(|e| {
        nrefuse(
            E::MarkerVerifyTransport,
            format!("marker verify failed to run: {e}"),
        )
    })?;
    if !verify.contains("marker-present") {
        return Err(nrefuse(
            E::MarkerVerifyAbsent,
            "the cloud-init.disabled marker does not verify after the write",
        ));
    }

                                                           
    if let Err(e) = super::eligibility::lock_precheck(reader, &super::eligibility::DPKG_LOCK_PATHS)
    {
        return Err(nrefuse(
            E::LockPrecheck,
            format!(
                "dpkg lock held at the write half ({}) — the §5.6 backstop",
                e.reason
            ),
        ));
    }

                                                          
    let raw = reader.capture(GROWROOT_STATUS_CMD).map_err(|e| {
        nrefuse(
            E::GrowrootStatusTransport,
            format!("growroot status read failed: {e}"),
        )
    })?;
    let (body, rc) = split_rc(&raw, "growroot status")
        .map_err(|e| nrefuse(E::GrowrootStatusSplitRc, e.reason))?;
    let mut fields = body.split_whitespace();
    let want = fields.next().unwrap_or("");
    let status = fields.next().unwrap_or("");
    match purge_predicate(rc, want, status) {
        PurgeRoute::Refuse(r) => return Err(nrefuse(E::PurgeRouteRefuse, r)),
        PurgeRoute::AlreadyAbsent => {}
        PurgeRoute::Apt => {
            let (dry_body, dry_rc) = split_rc(
                &reader.capture(PURGE_DRYRUN_CMD).map_err(|e| {
                    nrefuse(
                        E::PurgeDryrunTransport,
                        format!("purge dry-run failed to run: {e}"),
                    )
                })?,
                "purge dry-run",
            )
            .map_err(|e| nrefuse(E::PurgeDryrunSplitRc, e.reason))?;
            let removals: Vec<&str> = dry_body
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with("Purg ") || l.starts_with("Remv "))
                .collect();
            let one_purg =
                removals.len() == 1 && removals[0].starts_with("Purg cloud-initramfs-growroot");
            if dry_rc != 0 || !one_purg {
                return Err(nrefuse(
                    E::PurgeSetWrong,
                    format!(
                        "the purge removal set is not exactly cloud-initramfs-growroot \
                         (rc {dry_rc}, set {removals:?}) — refusing"
                    ),
                ));
            }
            let (_, purge_rc) = split_rc(
                &reader
                    .capture(PURGE_CMD)
                    .map_err(|e| nrefuse(E::PurgeTransport, format!("purge failed to run: {e}")))?,
                "purge",
            )
            .map_err(|e| nrefuse(E::PurgeSplitRc, e.reason))?;
                                                                                            
                                                                                            
                                                                                          
            let (vbody, vrc) = split_rc(
                &reader.capture(GROWROOT_STATUS_CMD).map_err(|e| {
                    nrefuse(
                        E::PurgeVerifyTransport,
                        format!("post-purge status read failed: {e}"),
                    )
                })?,
                "post-purge status",
            )
            .map_err(|e| nrefuse(E::PurgeVerifySplitRc, e.reason))?;
            let vstatus = vbody.split_whitespace().nth(1).unwrap_or("");
            let gone = vrc == 1 || (vrc == 0 && vstatus == "not-installed");
            if !gone {
                return Err(nrefuse(
                    E::PurgeDidNotTake,
                    format!(
                        "the purge did not take: post-purge status is rc {vrc} {vstatus:?} \
                         (apt rc was {purge_rc}) — the verify half"
                    ),
                ));
            }
        }
    }

                                                                                                        
                                                                                                    
                                                                                                     
                                                                                                      
                                                                                                     
                                                                                                  
                 
    let orig = parse_fstab_reply(
        &reader
            .capture(FSTAB_READ_CMD)
            .map_err(|e| nrefuse(E::FstabReadTransport, format!("fstab read at failed: {e}")))?,
    )
    .map_err(|e| nrefuse(E::FstabParse, e))?;
    match edit_fstab(&orig)
        .map_err(|e| nrefuse(E::FstabEdit, format!("fstab edit refused at: {e}")))?
    {
        None => {}                                                                          
        Some(edited) => {
            let (_, wrc) = split_rc(
                &reader.capture(&fstab_write_cmd(&edited)).map_err(|e| {
                    nrefuse(
                        E::FstabWriteTransport,
                        format!("fstab write failed to run: {e}"),
                    )
                })?,
                "fstab write",
            )
            .map_err(|e| nrefuse(E::FstabWriteSplitRc, e.reason))?;
            if wrc != 0 {
                return Err(nrefuse(
                    E::FstabWriteRc,
                    format!("fstab write failed (rc {wrc})"),
                ));
            }
            let reread = parse_fstab_reply(&reader.capture(FSTAB_READ_CMD).map_err(|e| {
                nrefuse(
                    E::FstabRereadTransport,
                    format!("fstab re-read failed: {e}"),
                )
            })?)
            .map_err(|e| nrefuse(E::FstabRereadParse, e))?;
            if let Err(e) = verify_fstab_edit(&orig, &reread) {
                return Err(nrefuse(
                    E::FstabVerify,
                    format!("fstab edit did not verify: {e}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::reclaim::fstab_model::options_carry_no_token;

    #[test]
    fn trailing_blank_line_round_trips_via_parse_then_edit() {
                                                                                                  
                                                                              
        let reply = "# c\nPARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n\nFSTAB-DONE\nRC:0";
        let orig = parse_fstab_reply(reply).unwrap();
        assert_eq!(orig, "# c\nPARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n\n");
        let edited = edit_fstab(&orig).unwrap().unwrap();
        assert_eq!(edited, "# c\nPARTUUID=aa / ext4 rw 0 1\n\n");
        verify_fstab_edit(&orig, &edited).unwrap();
    }

    #[test]
    fn parse_fstab_reply_refuses_a_non_utf8_lossy_byte() {
                                                                                                   
                                                  
        let reply =
            "PARTUUID=aa / ext4 rw 0 1\nLABEL=Dat\u{FFFD} /d ext4 defaults 0 2\nFSTAB-DONE\nRC:0";
        let e = parse_fstab_reply(reply).unwrap_err();
        assert!(e.contains("U+FFFD"), "{e}");
    }

    #[test]
    fn purge_predicate_routes_per_the_probe_states() {
        assert_eq!(purge_predicate(0, "install", "installed"), PurgeRoute::Apt);
        assert_eq!(
            purge_predicate(0, "deinstall", "not-installed"),
            PurgeRoute::AlreadyAbsent
        );
        assert_eq!(purge_predicate(1, "", ""), PurgeRoute::AlreadyAbsent);
        assert!(matches!(
            purge_predicate(0, "deinstall", "config-files"),
            PurgeRoute::Refuse(_)
        ));
        assert!(matches!(purge_predicate(2, "", ""), PurgeRoute::Refuse(_)));
    }

                                                                   

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

    fn happy(fstab_state: &str) -> Vec<(&'static str, String)> {
        vec![
            ("touch /etc/cloud/cloud-init.disabled", "RC:0".into()),
            (
                "test -e /etc/cloud/cloud-init.disabled",
                "marker-present".into(),
            ),
            (
                "python3 - /var/lib/dpkg/lock-frontend",
                "/var/lib/dpkg/lock-frontend FREE\n/var/lib/dpkg/lock FREE\n".into(),
            ),
            (
                "--dry-run",
                "Purg cloud-initramfs-growroot [0.18.deb12.3]\nRC:0".into(),
            ),
            ("purge -y", "RC:0".into()),
            ("cat > /etc/fstab", "RC:0".into()),
            ("cat /etc/fstab", format!("{fstab_state}FSTAB-DONE\nRC:0")),
        ]
    }

    /// A reader whose dpkg status flips to gone after the purge command runs, and whose fstab
    /// read returns the edited content after the write.
    struct StatefulReader {
        purged: bool,
        fstab: String,
        issued: Vec<String>,
        purge_takes: bool,
    }

    impl TargetReader for StatefulReader {
        fn capture(&mut self, cmd: &str) -> Result<String, String> {
            self.issued.push(cmd.to_string());
            if cmd.contains("touch /etc/cloud") {
                return Ok("RC:0".into());
            }
            if cmd.contains("test -e /etc/cloud/cloud-init.disabled") {
                return Ok("marker-present".into());
            }
            if cmd.contains("python3 - /var/lib/dpkg") {
                return Ok("/var/lib/dpkg/lock-frontend FREE\n/var/lib/dpkg/lock FREE\n".into());
            }
            if cmd.contains("--dry-run") {
                return Ok("Purg cloud-initramfs-growroot [0.18.deb12.3]\nRC:0".into());
            }
            if cmd.contains("purge -y") {
                if self.purge_takes {
                    self.purged = true;
                }
                return Ok("RC:0".into());
            }
            if cmd.contains("dpkg-query -W") {
                return Ok(if self.purged {
                    " RC:1".into()
                } else {
                    "install installed RC:0".into()
                });
            }
            if cmd.starts_with("cat > /etc/fstab") {
                                                                                                
                                  
                let body = cmd
                    .split_once("ORCHARD_RECLAIM_FSTAB'\n")
                    .map(|x| x.1)
                    .and_then(|s| s.split("ORCHARD_RECLAIM_FSTAB").next())
                    .unwrap_or("");
                self.fstab = body.to_string();
                return Ok("RC:0".into());
            }
            if cmd.contains("cat /etc/fstab") {
                return Ok(format!("{}FSTAB-DONE\nRC:0", self.fstab));
            }
            panic!("unscripted command: {cmd}");
        }
    }

    fn class_fstab() -> String {
        "# cloud image\nPARTUUID=b69af6fb-08dd-4525-acb0-1f870e0f0221 / ext4 rw,discard,errors=remount-ro,x-systemd.growfs 0 1\n".to_string()
    }

    #[test]
    fn neutralize_happy_path_applies_marker_purge_fstab_in_r1212_order() {
        let mut r = StatefulReader {
            purged: false,
            fstab: class_fstab(),
            issued: vec![],
            purge_takes: true,
        };
        neutralize(&mut r).unwrap();
        assert!(
            options_carry_no_token(&r.fstab),
            "token removed: {}",
            r.fstab
        );
                                                                                           
                       
        let idx = |needle: &str| {
            r.issued
                .iter()
                .position(|c| c.contains(needle))
                .unwrap_or(usize::MAX)
        };
        assert!(idx("touch /etc/cloud") < idx("--dry-run"));
        assert!(idx("--dry-run") < idx("purge -y"));
        assert!(idx("purge -y") < idx("cat > /etc/fstab"));
    }

    #[test]
    fn neutralize_refuses_when_the_purge_does_not_take() {
                                                                                              
                                                                                                
                                
        let mut r = StatefulReader {
            purged: false,
            fstab: class_fstab(),
            issued: vec![],
            purge_takes: false,
        };
        let e = neutralize(&mut r).unwrap_err().refusal;
        assert_eq!(e.row, rows::NEUTRALIZE);
        assert!(e.reason.contains("did not take"), "{e}");
                                                                                   
        assert!(!r.issued.iter().any(|c| c.starts_with("cat > /etc/fstab")));
    }

    #[test]
    fn neutralize_refuses_oversized_removal_set_and_held_lock() {
                                           
        let mut replies = happy(&class_fstab());
        replies[3] = (
            "--dry-run",
            "Purg cloud-initramfs-growroot\nPurg cloud-guest-utils\nRC:0".into(),
        );
        replies.push(("dpkg-query -W", "install installed RC:0".into()));
        let pairs: Vec<(&str, &str)> = replies.iter().map(|(a, b)| (*a, b.as_str())).collect();
        let mut r = ScriptReader::new(&pairs);
        let e = neutralize(&mut r).unwrap_err().refusal;
        assert!(e.reason.contains("not exactly"), "{e}");

                                                                                              
        let mut replies = happy(&class_fstab());
        replies[2] = (
            "python3 - /var/lib/dpkg/lock-frontend",
            "/var/lib/dpkg/lock-frontend HELD type=1 pid=777\n/var/lib/dpkg/lock FREE\n".into(),
        );
        replies.push(("dpkg-query -W", "install installed RC:0".into()));
        let pairs: Vec<(&str, &str)> = replies.iter().map(|(a, b)| (*a, b.as_str())).collect();
        let mut r = ScriptReader::new(&pairs);
        let e = neutralize(&mut r).unwrap_err().refusal;
        assert_eq!(e.row, rows::NEUTRALIZE);
        assert!(e.reason.contains("777"), "{e}");
    }

    #[test]
    fn neutralize_marker_failure_runs_no_purge_or_fstab() {
                                                                                                   
        let fstab = format!("{}FSTAB-DONE\nRC:0", class_fstab());
        let replies = vec![
            ("cat /etc/fstab", fstab.as_str()),
            ("touch /etc/cloud/cloud-init.disabled", "RC:1"),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = neutralize(&mut r).unwrap_err().refusal;
                                                                                                
                                                                                                      
                                                                   
        assert!(e.reason.contains("this run's touch failed"), "{e}");
                                                                                            
        assert_eq!(
            r.issued.len(),
            2,
            "only the fstab read + marker write may have run: {:?}",
            r.issued
        );
        assert!(
            !r.issued
                .iter()
                .any(|c| c.contains("purge") || c.starts_with("cat > /etc/fstab")),
            "{:?}",
            r.issued
        );
    }

    #[test]
    fn neutralize_marker_verify_failure_refuses_before_the_purge() {
                                                                                              
                                                                                              
                                                                                                         
        let fstab = format!("{}FSTAB-DONE\nRC:0", class_fstab());
        let replies = vec![
            ("cat /etc/fstab", fstab.as_str()),
            ("touch /etc/cloud/cloud-init.disabled", "RC:0"),
            ("test -e /etc/cloud/cloud-init.disabled", "marker-absent"),
        ];
        let mut r = ScriptReader::new(&replies);
        let e = neutralize(&mut r).unwrap_err().refusal;
        assert_eq!(e.row, rows::NEUTRALIZE);
        assert!(e.reason.contains("does not verify"), "{e}");
        assert!(
            !r.issued
                .iter()
                .any(|c| c.contains("--dry-run") || c.contains("purge -y")),
            "nothing irreversible may run after the failed marker verify: {:?}",
            r.issued
        );
    }

    #[test]
    fn neutralize_refuses_an_infeasible_fstab_before_any_write() {
                                                                                                      
                                                                                                        
        let bad = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n\
                   PARTUUID=bb /data ext4 x-systemd.growfs 0 2\n";
        let reply = format!("{bad}FSTAB-DONE\nRC:0");
        let replies = vec![("cat /etc/fstab", reply.as_str())];
        let mut r = ScriptReader::new(&replies);
        let e = neutralize(&mut r).unwrap_err().refusal;
        assert!(e.reason.contains("empty options field"), "{e}");
                                                                           
        assert_eq!(
            r.issued.len(),
            1,
            "no write before the feasibility refusal: {:?}",
            r.issued
        );
        assert!(
            !r.issued.iter().any(|c| c.contains("touch /etc/cloud")),
            "{:?}",
            r.issued
        );
    }

    #[test]
    fn r1212_order_leaves_eligibility_passing_after_each_failure_prefix() {
        use crate::deploy::prod::PartitionExtent;
        use crate::deploy::reclaim::eligibility::{ReclaimCtx, check_eligibility_readonly};
                                                                                           
                                                                                         
                                                                                
        let ctx = ReclaimCtx {
            disk: "vda".into(),
            root_dev: "/dev/vda1".into(),
            window_offset: 41053847552,
            window_len: 1892036608,
        };
        let extents = vec![PartitionExtent {
            name: "vda1".into(),
            start: 134217728,
            end: 42948624384,
        }];
        for growroot_reply in ["install installed RC:0", " RC:1"] {
            let replies = [
                ("CAP-PROBE-DONE", "CAP-PROBE-DONE".to_string()),
                ("dpkg-query", growroot_reply.to_string()),
                ("cloud-init.disabled", "marker-present".to_string()),
                ("FSTYPE", "ext4\nRC:0".to_string()),
                ("SOURCE --target /boot", "/dev/vda1\nRC:0".to_string()),
                (
                    "dumpe2fs -h",
                    "Block count: 9989888\nBlock size: 4096\nRC:0".to_string(),
                ),
            ];
            let pairs: Vec<(&str, &str)> = replies.iter().map(|(a, b)| (*a, b.as_str())).collect();
            let mut r = ScriptReader::new(&pairs);
            assert!(
                check_eligibility_readonly(&mut r, &ctx, &extents).is_ok(),
                "eligibility must pass after a failure with growroot state {growroot_reply:?}"
            );
        }
    }

                                                                                                    

    #[test]
    fn pre_write_feasibility_refusals_are_rowed_r_elig() {
                                                                                                     
                                                                                                         
                                                                                                       
        let edit_shapes: &[(&str, &str)] = &[
            ("PARTUUID=x /data ext4 rw 0 2\n", "0 root"),
            (
                "PARTUUID=a / ext4 rw 0 1\nPARTUUID=b / ext4 rw 0 1\n",
                "2 root",
            ),
            ("PARTUUID=aa / ext4 x-systemd.growfs 0 1\n", "empty options"),
            (
                "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\nORCHARD_RECLAIM_FSTAB\n",
                "heredoc terminator",
            ),
        ];
                                                                                                      
        let parse_shapes: &[(&str, &str)] = &[
            ("PARTUUID=aa / ext4 rw 0 1\nFSTAB-DONE\nRC:1", "cat rc 1"),
            ("PARTUUID=aa / ext4 rw 0 1\nRC:0", "FSTAB-DONE marker"),
            (
                "PARTUUID=aa / ext4 rw 0 1\nLABEL=x\u{FFFD} /d ext4 rw 0 2\nFSTAB-DONE\nRC:0",
                "U+FFFD",
            ),
        ];
        for (body, needle) in edit_shapes {
            let reply = format!("{body}FSTAB-DONE\nRC:0");
            let mut r = ScriptReader::new(&[("cat /etc/fstab", reply.as_str())]);
            let e = neutralize(&mut r).unwrap_err().refusal;
            assert_eq!(e.row, rows::ELIG, "shape {body:?} must be R-ELIG: {e}");
            assert!(e.reason.contains(needle), "shape {body:?}: {e}");
            assert_eq!(
                r.issued.len(),
                1,
                "only the read-only fstab read ran: {:?}",
                r.issued
            );
        }
        for (reply, needle) in parse_shapes {
            let mut r = ScriptReader::new(&[("cat /etc/fstab", reply)]);
            let e = neutralize(&mut r).unwrap_err().refusal;
            assert_eq!(e.row, rows::ELIG, "reply {reply:?} must be R-ELIG: {e}");
            assert!(e.reason.contains(needle), "reply {reply:?}: {e}");
            assert_eq!(
                r.issued.len(),
                1,
                "only the read-only fstab read ran: {:?}",
                r.issued
            );
        }
    }

    /// A reader that serves a scripted SEQUENCE of fstab-read bodies (the probe read, then the
                                                                                                       
    /// script. Marker/lock/purge answer happily (the purge takes). For the fix-(b) read-ordering
                                                                                                  
    struct StagedReader {
        reads: std::collections::VecDeque<String>,
        wrote: Option<String>,
        issued: Vec<String>,
        purged: bool,
    }

    impl StagedReader {
        fn new(bodies: &[&str]) -> Self {
            Self {
                reads: bodies.iter().map(|s| s.to_string()).collect(),
                wrote: None,
                issued: vec![],
                purged: false,
            }
        }
    }

    impl TargetReader for StagedReader {
        fn capture(&mut self, cmd: &str) -> Result<String, String> {
            self.issued.push(cmd.to_string());
            if cmd.contains("touch /etc/cloud") {
                return Ok("RC:0".into());
            }
            if cmd.contains("test -e /etc/cloud/cloud-init.disabled") {
                return Ok("marker-present".into());
            }
            if cmd.contains("python3 - /var/lib/dpkg") {
                return Ok("/var/lib/dpkg/lock-frontend FREE\n/var/lib/dpkg/lock FREE\n".into());
            }
            if cmd.contains("--dry-run") {
                return Ok("Purg cloud-initramfs-growroot [0.18.deb12.3]\nRC:0".into());
            }
            if cmd.contains("purge -y") {
                self.purged = true;
                return Ok("RC:0".into());
            }
            if cmd.contains("dpkg-query -W") {
                return Ok(if self.purged {
                    " RC:1".into()
                } else {
                    "install installed RC:0".into()
                });
            }
            if cmd.starts_with("cat > /etc/fstab") {
                let body = cmd
                    .split_once("ORCHARD_RECLAIM_FSTAB'\n")
                    .map(|x| x.1)
                    .and_then(|s| s.split("ORCHARD_RECLAIM_FSTAB").next())
                    .unwrap_or("");
                self.wrote = Some(body.to_string());
                return Ok("RC:0".into());
            }
            if cmd.contains("cat /etc/fstab") {
                let body = self
                    .reads
                    .pop_front()
                    .or_else(|| self.wrote.clone())
                    .unwrap_or_default();
                return Ok(format!("{body}FSTAB-DONE\nRC:0"));
            }
            panic!("unscripted command: {cmd}");
        }
    }

    #[test]
    fn neutralize_strips_a_token_that_appears_after_the_probe() {
                                                                                                       
                                                                                                       
                                                                                                        
                                                                        
        let absent = "PARTUUID=aa / ext4 rw 0 1\n";
        let armed = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n";
        let mut r = StagedReader::new(&[absent, armed]);
        neutralize(&mut r).unwrap();
        let wrote = r.wrote.expect(
            "the token that appeared after the probe must be written-stripped, not skipped",
        );
        assert!(
            !wrote.contains("x-systemd.growfs"),
            "the authoritative read's token was stripped: {wrote:?}"
        );
    }

    #[test]
    fn neutralize_acts_on_the_authoritative_read_preserving_a_concurrent_line() {
                                                                                                        
                                                                                                    
                                                                        
        let probe = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n";
        let concurrent = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n\
                          LABEL=data /data ext4 defaults,nofail 0 2\n";
        let mut r = StagedReader::new(&[probe, concurrent]);
        neutralize(&mut r).unwrap();
        let wrote = r.wrote.expect("a write must run");
        assert!(
            !wrote.contains("x-systemd.growfs"),
            "the token is stripped: {wrote:?}"
        );
        assert!(
            wrote.contains("LABEL=data /data"),
            "the concurrent line survives, not clobbered: {wrote:?}"
        );
    }

                                                                                                    

    /// The commands `neutralize` issues, in order, as EXACT-SET equality against the production
    /// command constants. Set equality (not containment) so both directions redden: an inserted
    /// call — an apt invocation under any spelling included — and a dropped one. The constants
    /// supply command IDENTITY only; their wire text is pinned independently by the AC-R13 vectors
    /// in `prod_orchestrate_reclaim_tests.rs`. The property asserted here is WHICH commands run and
    /// in WHAT ORDER.
    fn issued_prefix() -> Vec<String> {
        use crate::deploy::reclaim::eligibility::{DPKG_LOCK_PATHS, getlk_probe_cmd};
        vec![
            FSTAB_READ_CMD.to_string(),                                    
            marker_write_cmd(),                 
            marker_probe_cmd(),
            getlk_probe_cmd(&DPKG_LOCK_PATHS),                          
            GROWROOT_STATUS_CMD.to_string(),                            
        ]
    }

    /// Compare the issued sequence against `expected` by FULL-STRING equality, position by
    /// position, reporting a truncated head so the failure stays readable (the lock probe embeds a
    /// 20-line python heredoc). An extra or missing call shows as `None` on one side.
    fn assert_issued(label: &str, issued: &[String], expected: &[String]) {
        let head = |s: &String| s.chars().take(56).collect::<String>();
        for i in 0..issued.len().max(expected.len()) {
            let (got, exp) = (issued.get(i), expected.get(i));
            assert!(
                got == exp,
                "{label}: call #{i} is {:?}, expected {:?}",
                got.map(head),
                exp.map(head)
            );
        }
    }

    #[test]
    fn r121_decides_the_purge_route_from_dpkg_query_never_from_apt() {
                                                                                           
                                                                                                    
                                                                                        
                                                                                              
                                                                                                  
                                                                                                  
                                                                                                    
                                    
          
                                                                                                    
                                                                                           
                                                                          
          
                                                                                                   
                                                                                                 
                                                                                                       
                                                                                                 
                                                                                                   
                                                                                              
                                                                                                   
                                                                                              
                                                                                     
                                                                                                    
                                                                                
        let empty_lists_dryrun = "Reading package lists...\n\
             E: Unable to locate package cloud-initramfs-growroot\nRC:100";
        let clean_fstab_reply = "PARTUUID=aa / ext4 rw,discard 0 1\nFSTAB-DONE\nRC:0";
        let absent = |status: &'static str| -> Vec<(&'static str, String)> {
            vec![
                ("touch /etc/cloud/cloud-init.disabled", "RC:0".into()),
                (
                    "test -e /etc/cloud/cloud-init.disabled",
                    "marker-present".into(),
                ),
                (
                    "python3 - /var/lib/dpkg/lock-frontend",
                    "/var/lib/dpkg/lock-frontend FREE\n/var/lib/dpkg/lock FREE\n".into(),
                ),
                ("dpkg-query -W", status.into()),
                ("--dry-run", empty_lists_dryrun.into()),
                ("purge -y", empty_lists_dryrun.into()),
                ("cat /etc/fstab", clean_fstab_reply.into()),
            ]
        };

                                                                                                    
                                                                                                  
        for status in [" RC:1", "deinstall not-installed RC:0"] {
            let replies = absent(status);
            let pairs: Vec<(&str, &str)> = replies.iter().map(|(a, b)| (*a, b.as_str())).collect();
            let mut r = ScriptReader::new(&pairs);
            neutralize(&mut r)
                .unwrap_or_else(|e| panic!("status {status:?} is the re-run case: {}", e.refusal));
            let mut expected = issued_prefix();
            expected.push(FSTAB_READ_CMD.to_string());                                                
            assert_issued(
                &format!(
                    "status {status:?} — the route is decided from dpkg-query and NO apt call runs"
                ),
                &r.issued,
                &expected,
            );
        }

                                                                                                   
                                                                                                  
                                                                                              
                                                                                                   
                                                                                                    
                                                   
        let mut r = StatefulReader {
            purged: false,
            fstab: "PARTUUID=aa / ext4 rw,discard 0 1\n".to_string(),
            issued: vec![],
            purge_takes: true,
        };
        neutralize(&mut r).expect("the installed route purges and verifies");
        let mut expected = issued_prefix();
        expected.push(PURGE_DRYRUN_CMD.to_string());
        expected.push(PURGE_CMD.to_string());
        expected.push(GROWROOT_STATUS_CMD.to_string());                       
        expected.push(FSTAB_READ_CMD.to_string());
        assert_issued(
            "installed — the apt dry-run runs, and only AFTER the dpkg-query predicate read",
            &r.issued,
            &expected,
        );
                                                                                                  
                                                                                                        
                                                                                                    
                                                   
    }

    #[test]
    fn parse_fstab_reply_refuses_a_nul_byte() {
                                                                                                   
                                                                                      
        let reply = "PARTUUID=aa / ext4 rw,x-systemd.growfs\0ZZZ 0 1\nFSTAB-DONE\nRC:0";
        let e = parse_fstab_reply(reply).unwrap_err();
        assert!(e.contains("NUL") && e.contains("getmntent"), "{e}");
                                                                                        
        let mut r = ScriptReader::new(&[("cat /etc/fstab", reply)]);
        let ne = neutralize(&mut r).unwrap_err().refusal;
        assert_eq!(ne.row, rows::ELIG, "{ne}");
        assert_eq!(r.issued.len(), 1, "only the probe read ran: {:?}", r.issued);
    }
}
