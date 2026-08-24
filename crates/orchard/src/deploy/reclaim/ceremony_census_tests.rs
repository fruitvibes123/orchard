//! Half A: the consequence census over the CLOSED exit enums — split from `ceremony.rs`'s tests
//! module for file length (the prod twin is `prod_orchestrate_reclaim_tests.rs`). A CHILD of the
//! `ceremony` module, so `super::tests`'s pub(super) harness (CeremonyOps + batteries) is in reach.

use super::super::neutralize::NeutralizeExit;
use super::tests::{CeremonyOps, front, install_battery, sample_prepared};
use super::*;

                                                                                                
                                                                                       
                                                                                             
                                                                                              
                                                                                                   
                                                                                               
                                                                                                       
  
                                                                                     
                                                                                             
                                                                                      
                                                                                               
                                                                                              
                                                                                             
                                                                                               
                                                   

/// Drop every reply whose needle equals `needle`, so `CeremonyOps` returns its unscripted error
/// for that command — the transport-failure driver.
fn drop_reply(
    base: Vec<(&'static str, String)>,
    needle: &'static str,
) -> Vec<(&'static str, String)> {
    base.into_iter().filter(|(n, _)| *n != needle).collect()
}

/// Which exit an arm expects: the enum branch IS the expected InstallFailure variant
/// (NeutralizeExit ⇒ BeforeInstall, InstallExit ⇒ AfterInstall).
#[derive(Debug, Clone, Copy, PartialEq)]
enum ExpExit {
    N(NeutralizeExit),
    I(InstallExit),
}

/// One census arm: (label, one-shot replies consumed before the static table, the static reply
/// table, expected exit, expected §7 row as an independent literal).
type CensusArm = (
    &'static str,
    Vec<(&'static str, &'static str)>,
    Vec<(&'static str, String)>,
    ExpExit,
    &'static str,
);

#[test]
fn consequence_census_asserts_exit_row_and_disclosure_for_every_exit() {
    use ExpExit::{I, N};
    let prepared = sample_prepared();
                                                                                               
                                              
    let mut ops = CeremonyOps::new(install_battery());
    install_and_arm(&mut ops, &prepared).expect("the happy install battery arms cleanly");

    let armed_fstab = "PARTUUID=abcd-01 / ext4 rw,x-systemd.growfs 0 1\nFSTAB-DONE\nRC:0";
    let clean_fstab = "PARTUUID=abcd-01 / ext4 rw,discard 0 1\nFSTAB-DONE\nRC:0";
    let two_root = "PARTUUID=a / ext4 rw 0 1\nPARTUUID=b / ext4 rw 0 1\nFSTAB-DONE\nRC:0";
    let installed = || vec![("dpkg-query", "install installed RC:0")];
    let armed_twice = || {
        vec![
            ("cat /etc/fstab", armed_fstab),
            ("cat /etc/fstab", armed_fstab),
        ]
    };
    let cases: Vec<CensusArm> = vec![
                                                                                            
        (
            "feas-read-transport",
            vec![],
            drop_reply(install_battery(), "cat /etc/fstab"),
            N(NeutralizeExit::FeasReadTransport),
            rows::ELIG,
        ),
        (
            "feas-parse-norc",
            vec![],
            front(install_battery(), "cat /etc/fstab", "nothing here"),
            N(NeutralizeExit::FeasParse),
            rows::ELIG,
        ),
        (
            "feas-parse-nul",
            vec![],
            front(
                install_battery(),
                "cat /etc/fstab",
                "PARTUUID=a / ext4 rw\0,x-systemd.growfs 0 1\nFSTAB-DONE\nRC:0",
            ),
            N(NeutralizeExit::FeasParse),
            rows::ELIG,
        ),
        (
            "feas-edit-two-root",
            vec![],
            front(install_battery(), "cat /etc/fstab", two_root),
            N(NeutralizeExit::FeasEdit),
            rows::ELIG,
        ),
        (
            "feas-edit-zero-root",
            vec![],
            front(
                install_battery(),
                "cat /etc/fstab",
                "PARTUUID=a /home ext4 rw,x-systemd.growfs 0 1\nFSTAB-DONE\nRC:0",
            ),
            N(NeutralizeExit::FeasEdit),
            rows::ELIG,
        ),
                                              
        (
            "marker-write-transport",
            vec![],
            drop_reply(install_battery(), "touch /etc/cloud/cloud-init.disabled"),
            N(NeutralizeExit::MarkerWriteTransport),
            rows::NEUTRALIZE,
        ),
        (
            "marker-write-splitrc",
            vec![],
            front(
                install_battery(),
                "touch /etc/cloud/cloud-init.disabled",
                "no rc token here",
            ),
            N(NeutralizeExit::MarkerWriteSplitRc),
            rows::NEUTRALIZE,
        ),
        (
            "marker-write-rc1",
            vec![],
            front(
                install_battery(),
                "touch /etc/cloud/cloud-init.disabled",
                "RC:1",
            ),
            N(NeutralizeExit::MarkerWriteRc),
            rows::NEUTRALIZE,
        ),
        (
            "marker-verify-transport",
            vec![],
            drop_reply(install_battery(), "test -e /etc/cloud/cloud-init.disabled"),
            N(NeutralizeExit::MarkerVerifyTransport),
            rows::NEUTRALIZE,
        ),
        (
            "marker-verify-absent",
            vec![],
            front(
                install_battery(),
                "test -e /etc/cloud/cloud-init.disabled",
                "marker-absent",
            ),
            N(NeutralizeExit::MarkerVerifyAbsent),
            rows::NEUTRALIZE,
        ),
                                                                                           
        (
            "lock-transport",
            vec![],
            drop_reply(install_battery(), "python3 - /var/lib/dpkg"),
            N(NeutralizeExit::LockPrecheck),
            rows::NEUTRALIZE,
        ),
        (
            "lock-held",
            vec![],
            front(
                install_battery(),
                "python3 - /var/lib/dpkg",
                "/var/lib/dpkg/lock-frontend HELD type=1 pid=4242\n/var/lib/dpkg/lock FREE\n",
            ),
            N(NeutralizeExit::LockPrecheck),
            rows::NEUTRALIZE,
        ),
                                                             
        (
            "growroot-status-transport",
            vec![],
            drop_reply(install_battery(), "dpkg-query"),
            N(NeutralizeExit::GrowrootStatusTransport),
            rows::NEUTRALIZE,
        ),
        (
            "growroot-status-splitrc",
            vec![],
            front(install_battery(), "dpkg-query", "install installed"),
            N(NeutralizeExit::GrowrootStatusSplitRc),
            rows::NEUTRALIZE,
        ),
        (
            "purge-route-config-files",
            vec![],
            front(install_battery(), "dpkg-query", "install config-files RC:0"),
            N(NeutralizeExit::PurgeRouteRefuse),
            rows::NEUTRALIZE,
        ),
        (
            "purge-route-rc2",
            vec![],
            front(install_battery(), "dpkg-query", "  RC:2"),
            N(NeutralizeExit::PurgeRouteRefuse),
            rows::NEUTRALIZE,
        ),
        (
            "purge-dryrun-transport",
            vec![],
            front(
                drop_reply(install_battery(), "--dry-run"),
                "dpkg-query",
                "install installed RC:0",
            ),
            N(NeutralizeExit::PurgeDryrunTransport),
            rows::NEUTRALIZE,
        ),
        (
            "purge-dryrun-splitrc",
            vec![],
            front(
                front(
                    install_battery(),
                    "--dry-run",
                    "Purg cloud-initramfs-growroot [1.0]",
                ),
                "dpkg-query",
                "install installed RC:0",
            ),
            N(NeutralizeExit::PurgeDryrunSplitRc),
            rows::NEUTRALIZE,
        ),
        (
            "purge-dryrun-set-wrong",
            vec![],
            front(
                front(
                    install_battery(),
                    "--dry-run",
                    "Purg cloud-initramfs-growroot [1.0]\nRemv something-else [2]\nRC:0",
                ),
                "dpkg-query",
                "install installed RC:0",
            ),
            N(NeutralizeExit::PurgeSetWrong),
            rows::NEUTRALIZE,
        ),
        (
            "purge-transport",
            vec![],
            front(
                front(
                    drop_reply(install_battery(), "purge -y"),
                    "--dry-run",
                    "Purg cloud-initramfs-growroot [1.0]\nRC:0",
                ),
                "dpkg-query",
                "install installed RC:0",
            ),
            N(NeutralizeExit::PurgeTransport),
            rows::NEUTRALIZE,
        ),
        (
            "purge-splitrc",
            vec![],
            front(
                front(
                    front(install_battery(), "purge -y", "done without a token"),
                    "--dry-run",
                    "Purg cloud-initramfs-growroot [1.0]\nRC:0",
                ),
                "dpkg-query",
                "install installed RC:0",
            ),
            N(NeutralizeExit::PurgeSplitRc),
            rows::NEUTRALIZE,
        ),
                                                                                               
                                                                                          
                                                                                               
        (
            "purge-verify-transport",
            installed(),
            front(
                front(
                    drop_reply(install_battery(), "dpkg-query"),
                    "--dry-run",
                    "Purg cloud-initramfs-growroot [1.0]\nRC:0",
                ),
                "purge -y",
                "RC:0",
            ),
            N(NeutralizeExit::PurgeVerifyTransport),
            rows::NEUTRALIZE,
        ),
        (
            "purge-verify-splitrc",
            installed(),
            front(
                front(
                    front(install_battery(), "dpkg-query", "garbage without a token"),
                    "--dry-run",
                    "Purg cloud-initramfs-growroot [1.0]\nRC:0",
                ),
                "purge -y",
                "RC:0",
            ),
            N(NeutralizeExit::PurgeVerifySplitRc),
            rows::NEUTRALIZE,
        ),
        (
            "purge-did-not-take",
            vec![],
            front(
                front(
                    front(install_battery(), "dpkg-query", "install installed RC:0"),
                    "--dry-run",
                    "Purg cloud-initramfs-growroot [1.0]\nRC:0",
                ),
                "purge -y",
                "RC:0",
            ),
            N(NeutralizeExit::PurgeDidNotTake),
            rows::NEUTRALIZE,
        ),
                                                                                               
                                                                                             
        (
            "r1211-read-transport",
            vec![("cat /etc/fstab", clean_fstab)],
            drop_reply(install_battery(), "cat /etc/fstab"),
            N(NeutralizeExit::FstabReadTransport),
            rows::NEUTRALIZE,
        ),
        (
            "r1211-parse",
            vec![("cat /etc/fstab", clean_fstab)],
            front(install_battery(), "cat /etc/fstab", "garbage no token"),
            N(NeutralizeExit::FstabParse),
            rows::NEUTRALIZE,
        ),
        (
            "r1211-edit-refuse",
            vec![("cat /etc/fstab", armed_fstab)],
            front(install_battery(), "cat /etc/fstab", two_root),
            N(NeutralizeExit::FstabEdit),
            rows::NEUTRALIZE,
        ),
        (
            "r1211-write-transport",
            vec![],
            front(
                drop_reply(install_battery(), "cat > /etc/fstab"),
                "cat /etc/fstab",
                armed_fstab,
            ),
            N(NeutralizeExit::FstabWriteTransport),
            rows::NEUTRALIZE,
        ),
        (
            "r1211-write-splitrc",
            vec![],
            front(
                front(install_battery(), "cat > /etc/fstab", "done no token"),
                "cat /etc/fstab",
                armed_fstab,
            ),
            N(NeutralizeExit::FstabWriteSplitRc),
            rows::NEUTRALIZE,
        ),
        (
            "r1211-write-rc1",
            vec![],
            front(
                front(install_battery(), "cat > /etc/fstab", "RC:1"),
                "cat /etc/fstab",
                armed_fstab,
            ),
            N(NeutralizeExit::FstabWriteRc),
            rows::NEUTRALIZE,
        ),
                                                                                           
                                                                                             
                                                              
        (
            "r1211-reread-transport",
            armed_twice(),
            front(
                drop_reply(install_battery(), "cat /etc/fstab"),
                "cat > /etc/fstab",
                "RC:0",
            ),
            N(NeutralizeExit::FstabRereadTransport),
            rows::NEUTRALIZE,
        ),
        (
            "r1211-reread-parse",
            armed_twice(),
            front(
                front(install_battery(), "cat /etc/fstab", "garbage no token"),
                "cat > /etc/fstab",
                "RC:0",
            ),
            N(NeutralizeExit::FstabRereadParse),
            rows::NEUTRALIZE,
        ),
        (
            "r1211-verify-fail",
            vec![],
            front(
                front(install_battery(), "cat /etc/fstab", armed_fstab),
                "cat > /etc/fstab",
                "RC:0",
            ),
            N(NeutralizeExit::FstabVerify),
            rows::NEUTRALIZE,
        ),
                                                                               
        (
            "hook-write-transport",
            vec![],
            drop_reply(install_battery(), "cat > /etc/initramfs-tools/hooks/"),
            I(InstallExit::HookWriteTransport),
            rows::INITRAMFS,
        ),
        (
            "hook-write-splitrc",
            vec![],
            front(
                install_battery(),
                "cat > /etc/initramfs-tools/hooks/",
                "no-rc-token",
            ),
            I(InstallExit::HookWriteSplitRc),
            rows::INITRAMFS,
        ),
        (
            "hook-write-rc2",
            vec![],
            front(
                install_battery(),
                "cat > /etc/initramfs-tools/hooks/",
                "RC:2",
            ),
            I(InstallExit::HookWriteRc),
            rows::INITRAMFS,
        ),
        (
            "premount-write-transport",
            vec![],
            drop_reply(
                install_battery(),
                "cat > /etc/initramfs-tools/scripts/local-premount/",
            ),
            I(InstallExit::PremountWriteTransport),
            rows::INITRAMFS,
        ),
        (
            "premount-write-splitrc",
            vec![],
            front(
                install_battery(),
                "cat > /etc/initramfs-tools/scripts/local-premount/",
                "no-rc-token",
            ),
            I(InstallExit::PremountWriteSplitRc),
            rows::INITRAMFS,
        ),
        (
            "premount-write-rc2",
            vec![],
            front(
                install_battery(),
                "cat > /etc/initramfs-tools/scripts/local-premount/",
                "RC:2",
            ),
            I(InstallExit::PremountWriteRc),
            rows::INITRAMFS,
        ),
        (
            "rebuild-transport",
            vec![],
            drop_reply(install_battery(), "update-initramfs -u -k all"),
            I(InstallExit::RebuildTransport),
            rows::INITRAMFS,
        ),
        (
            "rebuild-splitrc",
            vec![],
            front(
                install_battery(),
                "update-initramfs -u -k all",
                "no-rc-token",
            ),
            I(InstallExit::RebuildSplitRc),
            rows::INITRAMFS,
        ),
        (
            "rebuild-rc1",
            vec![],
            front(install_battery(), "update-initramfs -u -k all", "RC:1"),
            I(InstallExit::RebuildRc),
            rows::INITRAMFS,
        ),
        (
            "lsinitramfs-transport",
            vec![],
            drop_reply(install_battery(), "INITRD-COUNT"),
            I(InstallExit::LsinitramfsTransport),
            rows::INITRAMFS,
        ),
        (
            "lsinitramfs-splitrc",
            vec![],
            front(install_battery(), "INITRD-COUNT", "no-rc-token"),
            I(InstallExit::LsinitramfsSplitRc),
            rows::INITRAMFS,
        ),
        (
            "lsinitramfs-rc1",
            vec![],
            front(
                install_battery(),
                "INITRD-COUNT",
                "INITRD:/boot/initrd.img-x\nusr/sbin/e2fsck\nusr/sbin/resize2fs\n\
                 usr/sbin/sfdisk\nusr/sbin/dumpe2fs\nINITRD-COUNT:1\nRC:1",
            ),
            I(InstallExit::LsinitramfsRc),
            rows::INITRAMFS,
        ),
        (
            "required-set-missing",
            vec![],
            front(
                install_battery(),
                "INITRD-COUNT",
                "INITRD:/boot/initrd.img-x\nusr/sbin/e2fsck\nusr/sbin/resize2fs\n\
                 usr/sbin/dumpe2fs\nINITRD-COUNT:1\nRC:0",
            ),
            I(InstallExit::RequiredSetMissing),
            rows::INITRAMFS,
        ),
        (
            "order-transport",
            vec![],
            drop_reply(install_battery(), "unmkinitramfs"),
            I(InstallExit::OrderTransport),
            rows::INITRAMFS,
        ),
        (
            "order-incomplete",
            vec![],
            front(
                install_battery(),
                "unmkinitramfs",
                "ORDER-INITRD:/boot/initrd.img-x\nscripts/local-premount/orchard-reclaim\n",
            ),
            I(InstallExit::OrderIncomplete),
            rows::INITRAMFS,
        ),
        (
            "order-membership-missing",
            vec![],
            front(
                install_battery(),
                "unmkinitramfs",
                "ORDER-INITRD:/boot/initrd.img-x\nscripts/local-premount/resume\nORDER-DONE\n",
            ),
            I(InstallExit::OrderMembershipMissing),
            rows::INITRAMFS,
        ),
    ];

    let mut violations: Vec<String> = vec![];
    let mut driven_n: std::collections::BTreeSet<NeutralizeExit> = Default::default();
    let mut driven_i: std::collections::BTreeSet<InstallExit> = Default::default();
    for (label, once, replies, exp_exit, exp_row) in cases {
        let mut ops = CeremonyOps::with_once(replies, &once);
        let res = install_and_arm(&mut ops, &prepared);
        let (exit, row) = match res {
            Ok(()) => panic!("{label}: expected a refusal, install_and_arm returned Ok"),
            Err(InstallFailure::BeforeInstall { exit, refusal }) => (ExpExit::N(exit), refusal.row),
            Err(InstallFailure::AfterInstall { exit, refusal }) => (ExpExit::I(exit), refusal.row),
        };
                                                                                                   
                                                                                                    
                                            
        if exit != exp_exit {
            violations.push(format!("{label}: exit {exit:?}, expected {exp_exit:?}"));
        }
        if row != exp_row {
            violations.push(format!("{label}: row {row:?}, expected {exp_row}"));
        }
        match exit {
            ExpExit::N(x) => {
                driven_n.insert(x);
            }
            ExpExit::I(x) => {
                driven_i.insert(x);
            }
        }
    }
    assert!(
        violations.is_empty(),
        "consequence census violations:\n{violations:#?}"
    );
                                                                                               
                                                                                             
                                                                                    
    let all_n: std::collections::BTreeSet<NeutralizeExit> =
        NeutralizeExit::ALL.iter().copied().collect();
    let all_i: std::collections::BTreeSet<InstallExit> = InstallExit::ALL.iter().copied().collect();
    assert_eq!(
        driven_n, all_n,
        "every NeutralizeExit must be driven by a census arm (missing = ALL − driven)"
    );
    assert_eq!(
        driven_i, all_i,
        "every InstallExit must be driven by a census arm (missing = ALL − driven)"
    );
}
