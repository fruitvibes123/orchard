//! Reclaim-tail D-2 (plan T9) tests: the two flagged fixtures and the AC-R13 exact-vector
//! snapshots. Split out of prod_orchestrate_tests.rs (operator file-length directive). Declared as
//! a CHILD of the `tests` module in that file, so it shares the private `FakeOps` harness by
//! descendant privacy — `FakeOps`, `FakeOps::happy` and `FakeOps::opts` are all reachable here.
                                                                                               
                                                                         
use super::*;
use std::path::Path;

                                                                                                  

impl FakeOps {
    /// The will-run shape: the D-1 extents read sees a growpart-grown root ONCE (the pre-reboot
    /// state); the static clear-tail reply then serves the post-reclaim re-read. The dpkg status
    /// and the fstab content flip the same way (installed→gone; token→edited).
    fn happy_reclaim_will_run(dir: &Path) -> FakeOps {
        let mut ops = FakeOps::happy(dir);
        ops.remote_once.push_back((
            "lsblk -nbro NAME,TYPE,START,SIZE",
            "vda disk  42949672960\nvda1 part 2048 42948607488\n".to_string(),
        ));
        ops.remote_once
            .push_back(("dpkg-query -W", "install installed RC:0".to_string()));
        ops.remote_once
            .push_back(("dpkg-query -W", "install installed RC:0".to_string()));
                                                                                                      
                                                                                                       
                                                            
        ops.remote_once
            .push_back(("cloud-init.disabled", "marker-absent\n".to_string()));
        let armed_fstab = "PARTUUID=abcd-01 / ext4 rw,discard,errors=remount-ro,x-systemd.growfs 0 1\nFSTAB-DONE\nRC:0";
                                                                                             
                                                                                                      
                                                                                                     
                                                      
        ops.remote_once
            .push_back(("cat /etc/fstab", armed_fstab.to_string()));
        ops.remote_once
            .push_back(("cat /etc/fstab", armed_fstab.to_string()));
                                                                                                 
                                                                                                 
                                                                                                 
                               
        ops.remote_once.push_back((
            "/proc/sys/kernel/random/boot_id",
            "11111111-1111-1111-1111-111111111111\n".to_string(),
        ));
        let reclaim_static: Vec<(&'static str, String)> = vec![
            ("for c in update-initramfs", "CAP-PROBE-DONE\n".into()),
            ("dpkg-query -W", " RC:1".into()),
            ("test -e /etc/cloud/cloud-init.disabled", "marker-present\n".into()),
            ("findmnt -n -o FSTYPE /", "ext4\nRC:0".into()),
            ("--target /boot", "/dev/vda1\nRC:0".into()),
            (
                "dumpe2fs -h",
                "Block count:              10485499\nBlock size:               4096\nRC:0".into(),
            ),
                                                                                               
                                                                                                
            (
                "cat /etc/fstab",
                "PARTUUID=abcd-01 / ext4 rw,discard,errors=remount-ro 0 1\nFSTAB-DONE\nRC:0".into(),
            ),
            (
                "python3 - /var/lib/dpkg",
                "/var/lib/dpkg/lock-frontend FREE\n/var/lib/dpkg/lock FREE\n".into(),
            ),
                                                                                                       
                                                                                                   
                                                                                                  
                                                                                                       
                                                                                                  
                                                                                                   
            (
                "df -P -k /var/tmp/recipes-deploy",
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 41934272 20971520 20962752 51% /var/tmp/recipes-deploy\n".into(),
            ),
            (
                "df -P -k /",
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 41943040 1897068 40045972 5% /\n".into(),
            ),
            ("touch /etc/cloud/cloud-init.disabled", "RC:0".into()),
            (
                "--dry-run",
                "Purg cloud-initramfs-growroot [0.18.deb12.3]\nRC:0".into(),
            ),
            ("purge -y", "RC:0".into()),
            ("cat > /etc/fstab", "RC:0".into()),
            ("cat > /etc/initramfs-tools/hooks/", "RC:0".into()),
            ("cat > /etc/initramfs-tools/scripts/local-premount/", "RC:0".into()),
            ("update-initramfs -u -k all", "RC:0".into()),
            (
                                                                                            
                                                                                                 
                                                                                          
                "INITRD-COUNT",
                "INITRD:/boot/initrd.img-6.1.0-0-amd64\nusr/sbin/e2fsck\nusr/sbin/resize2fs\n\
                 usr/sbin/sfdisk\nusr/sbin/dumpe2fs\nINITRD-COUNT:1\nRC:0"
                    .into(),
            ),
            (
                "unmkinitramfs",
                "ORDER-INITRD:/boot/initrd.img-6.1.0-0-amd64\n\
                 scripts/local-premount/orchard-reclaim\nORDER-DONE\n"
                    .into(),
            ),
            ("nohup reboot", "REBOOT-ISSUED\n".into()),
            (
                "/proc/sys/kernel/random/boot_id",
                "22222222-2222-2222-2222-222222222222\n".into(),
            ),
            (
                "grep -F 'orchard-reclaim:'",
                "<3>orchard-reclaim: step10 done part=[1048576,42940235776) sectors=83865600\nCRUMB-DONE\n".into(),
            ),
        ];
        for (i, entry) in reclaim_static.into_iter().enumerate() {
            ops.remote.insert(i, entry);
        }
        ops
    }

    /// The short-circuit shape: happy()'s clear tail means D-1 passes; the only addition is the
    /// §5.2 overhang read for the D8 disposition (Decision 16).
    fn happy_reclaim_short_circuit(dir: &Path) -> FakeOps {
        let mut ops = FakeOps::happy(dir);
        ops.remote.insert(
            0,
            (
                "dumpe2fs -h",
                "Block count:              786432\nBlock size:               4096\nRC:0"
                    .to_string(),
            ),
        );
        ops
    }

    fn opts_reclaim(dir: &Path) -> DeployProdOpts {
        let mut o = FakeOps::opts(dir);
        o.reclaim_tail = true;
        o
    }
}

                                                                                          
                                                                                        
                                                                                         
                                                                                 
fn expected_no_flag_calls() -> Vec<String> {
    [
        "scan_host_key",
        "pin:Provisioning:203.0.113.5 ssh-ed25519 AAAAscan",
        "ssh:Provisioning:echo recipes-deploy-connected",
        "ssh:Provisioning:findmnt -n -o SOURCE / || true",
        "ssh:Provisioning:mkdir -p /var/tmp/recipes-deploy && realpath /var/tmp/recipes-deploy",
        "ssh:Provisioning:findmnt -n -o SOURCE --target /var/tmp/recipes-deploy || true",
        "ssh:Provisioning:lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME",
        "ssh:Provisioning:df -P -k /var/tmp/recipes-deploy",
        "ssh:Provisioning:cat /sys/class/block/vda/size",
        "ssh:Provisioning:lsblk -nbro NAME,TYPE,START,SIZE /dev/vda",
        "ssh:Provisioning:df -P -k /",
        "ssh:Provisioning:cat /proc/meminfo",
        "ssh:Provisioning:command -v kexec || echo MISSING",
        "ssh:Provisioning:date +%s",
        "say:\n── deploy summary — what you are author",
        "say:ADVISORY — read before confirming:\n  * S",
        "scp:<DIR>/r.vmlinuz:/var/tmp/recipes-deploy/r.vmlinuz",
        "scp:<DIR>/r.initramfs:/var/tmp/recipes-deploy/r.initramfs",
        "say:streaming the 1536-byte image onto the r",
        "stage_raw_window:vda:42941284352",
        "ssh:Provisioning:dd if=/var/tmp/recipes-deploy/r.vmlinuz iflag=direct bs=1M status=none | sha256sum",
        "ssh:Provisioning:dd if=/var/tmp/recipes-deploy/r.initramfs iflag=direct bs=1M status=none | sha256sum",
        "ssh:Provisioning:dd if=/dev/vda iflag=direct,skip_bytes,count_bytes skip=42941284352 count=1536 bs=1M status=none | sha256sum",
        "ssh:Provisioning:kexec -l /var/tmp/recipes-deploy/r.vmlinuz --initrd=/var/tmp/recipes-deploy/r.initramfs --append='fb.mode=installer fb.firmware=seabios fb.root-hash=abababababababababababababababababababababababababababababababab fb.verity-hash-offset=256 fb.image-raw=vda:42941284352:1536 fb.image-sha256=e5a2026ccc5590ac8806bb18e93fab4e684b48e80978d6827a1a2c909c64d587 fb.image-layout=fw:seabios,boot:0:512,skel:512:512,rootfs:1024:512 lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2 console=tty0 console=ttyS0'",
        "say:kexec loaded on 203.0.113.5; executing —",
        "fire_kexec",
        "pin:Reconnect:203.0.113.5 ssh-ed25519 AAAAfake",
        "say:waiting for the installed box at 203.0.1",
        "ssh:Reconnect:echo recipes-box-up",
        "ssh:Reconnect:cat /proc/mounts",
        "ssh:Reconnect:cat /proc/cmdline",
        "ssh:Reconnect:head -c 512 /dev/vda1 | sha256sum",
        "ssh:Reconnect:wget -q -S -O /dev/null --no-check-certificate https://127.0.0.1:443/ 2>&1 || true",
        "say:deploy prod COMPLETE: 203.0.113.5 runs y",
        "say:the installed box's runtime host key is ",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn expected_reclaim_short_circuit_calls() -> Vec<String> {
    [
        "scan_host_key",
        "pin:Provisioning:203.0.113.5 ssh-ed25519 AAAAscan",
        "ssh:Provisioning:echo recipes-deploy-connected",
        "ssh:Provisioning:findmnt -n -o SOURCE / || true",
        "ssh:Provisioning:mkdir -p /var/tmp/recipes-deploy && realpath /var/tmp/recipes-deploy",
        "ssh:Provisioning:findmnt -n -o SOURCE --target /var/tmp/recipes-deploy || true",
        "ssh:Provisioning:lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME",
        "ssh:Provisioning:df -P -k /var/tmp/recipes-deploy",
        "ssh:Provisioning:cat /sys/class/block/vda/size",
        "ssh:Provisioning:lsblk -nbro NAME,TYPE,START,SIZE /dev/vda",
        "ssh:Provisioning:dumpe2fs -h \"/dev/vda1\" 2>/dev/null; echo RC:$?",
        "ssh:Provisioning:df -P -k /",
        "ssh:Provisioning:cat /proc/meminfo",
        "ssh:Provisioning:command -v kexec || echo MISSING",
        "ssh:Provisioning:date +%s",
        "say:\n── deploy summary — what you are author",
        "say:ADVISORY — read before confirming:\n  * S",
        "scp:<DIR>/r.vmlinuz:/var/tmp/recipes-deploy/r.vmlinuz",
        "scp:<DIR>/r.initramfs:/var/tmp/recipes-deploy/r.initramfs",
        "say:streaming the 1536-byte image onto the r",
        "stage_raw_window:vda:42941284352",
        "ssh:Provisioning:dd if=/var/tmp/recipes-deploy/r.vmlinuz iflag=direct bs=1M status=none | sha256sum",
        "ssh:Provisioning:dd if=/var/tmp/recipes-deploy/r.initramfs iflag=direct bs=1M status=none | sha256sum",
        "ssh:Provisioning:dd if=/dev/vda iflag=direct,skip_bytes,count_bytes skip=42941284352 count=1536 bs=1M status=none | sha256sum",
        "ssh:Provisioning:kexec -l /var/tmp/recipes-deploy/r.vmlinuz --initrd=/var/tmp/recipes-deploy/r.initramfs --append='fb.mode=installer fb.firmware=seabios fb.root-hash=abababababababababababababababababababababababababababababababab fb.verity-hash-offset=256 fb.image-raw=vda:42941284352:1536 fb.image-sha256=e5a2026ccc5590ac8806bb18e93fab4e684b48e80978d6827a1a2c909c64d587 fb.image-layout=fw:seabios,boot:0:512,skel:512:512,rootfs:1024:512 lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2 console=tty0 console=ttyS0'",
        "say:kexec loaded on 203.0.113.5; executing —",
        "fire_kexec",
        "pin:Reconnect:203.0.113.5 ssh-ed25519 AAAAfake",
        "say:waiting for the installed box at 203.0.1",
        "ssh:Reconnect:echo recipes-box-up",
        "ssh:Reconnect:cat /proc/mounts",
        "ssh:Reconnect:cat /proc/cmdline",
        "ssh:Reconnect:head -c 512 /dev/vda1 | sha256sum",
        "ssh:Reconnect:wget -q -S -O /dev/null --no-check-certificate https://127.0.0.1:443/ 2>&1 || true",
        "say:deploy prod COMPLETE: 203.0.113.5 runs y",
        "say:the installed box's runtime host key is ",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn expected_reclaim_will_run_calls() -> Vec<String> {
    [
        "scan_host_key",
        "pin:Provisioning:203.0.113.5 ssh-ed25519 AAAAscan",
        "ssh:Provisioning:echo recipes-deploy-connected",
        "ssh:Provisioning:findmnt -n -o SOURCE / || true",
        "ssh:Provisioning:mkdir -p /var/tmp/recipes-deploy && realpath /var/tmp/recipes-deploy",
        "ssh:Provisioning:findmnt -n -o SOURCE --target /var/tmp/recipes-deploy || true",
        "ssh:Provisioning:lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME",
        "ssh:Provisioning:df -P -k /var/tmp/recipes-deploy",
        "ssh:Provisioning:cat /sys/class/block/vda/size",
        "ssh:Provisioning:lsblk -nbro NAME,TYPE,START,SIZE /dev/vda",
        "say:D-1 refused (RECORDED, --reclaim-tail): ",
        "ssh:Provisioning:for c in update-initramfs lsinitramfs unmkinitramfs apt-get cloud-init python3 e2fsck resize2fs sfdisk dumpe2fs; do command -v \"$c\" >/dev/null 2>&1 || echo \"MISSING:$c\"; done; test -d /etc/initramfs-tools/hooks || echo \"MISSING-DIR:/etc/initramfs-tools/hooks\"; test -d /etc/initramfs-tools/scripts/local-premount || echo \"MISSING-DIR:/etc/initramfs-tools/scripts/local-premount\"; test -d /etc/cloud || echo \"MISSING-DIR:/etc/cloud\"; echo CAP-PROBE-DONE",
        "ssh:Provisioning:dpkg-query -W -f='${db:Status-Want} ${db:Status-Status}' cloud-initramfs-growroot 2>/dev/null; echo \" RC:$?\"",
        "ssh:Provisioning:test -e /etc/cloud/cloud-init.disabled && echo marker-present || echo marker-absent",
        "ssh:Provisioning:findmnt -n -o FSTYPE / 2>/dev/null; echo RC:$?",
        "ssh:Provisioning:findmnt -n -o SOURCE --target /boot 2>/dev/null; echo RC:$?",
        "ssh:Provisioning:dumpe2fs -h \"/dev/vda1\" 2>/dev/null; echo RC:$?",
        "ssh:Provisioning:python3 - /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock <<'ORCHARD_RECLAIM_PY'\n<<BODY>>",
        "ssh:Provisioning:df -P -k /",
        "ssh:Provisioning:df -P -k /",
        "ssh:Provisioning:cat /proc/meminfo",
        "ssh:Provisioning:command -v kexec || echo MISSING",
        "ssh:Provisioning:date +%s",
        "say:\n── deploy summary — what you are author",
        "say:ADVISORY — read before confirming:\n  * S",
        "say:reclaim-tail plan for 203.0.113.5  (/dev",
        "ssh:Provisioning:cat /etc/fstab 2>/dev/null; rc=$?; echo FSTAB-DONE; echo RC:$rc",
        "ssh:Provisioning:touch /etc/cloud/cloud-init.disabled 2>/dev/null; echo RC:$?",
        "ssh:Provisioning:test -e /etc/cloud/cloud-init.disabled && echo marker-present || echo marker-absent",
        "ssh:Provisioning:python3 - /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock <<'ORCHARD_RECLAIM_PY'\n<<BODY>>",
        "ssh:Provisioning:dpkg-query -W -f='${db:Status-Want} ${db:Status-Status}' cloud-initramfs-growroot 2>/dev/null; echo \" RC:$?\"",
        "ssh:Provisioning:apt-get purge --dry-run cloud-initramfs-growroot 2>/dev/null; echo RC:$?",
        "ssh:Provisioning:DEBIAN_FRONTEND=noninteractive apt-get purge -y cloud-initramfs-growroot 2>/dev/null 1>&2; echo RC:$?",
        "ssh:Provisioning:dpkg-query -W -f='${db:Status-Want} ${db:Status-Status}' cloud-initramfs-growroot 2>/dev/null; echo \" RC:$?\"",
                                                                                                      
                                                                                    
        "ssh:Provisioning:cat /etc/fstab 2>/dev/null; rc=$?; echo FSTAB-DONE; echo RC:$rc",
        "ssh:Provisioning:cat > /etc/fstab <<'ORCHARD_RECLAIM_FSTAB'\n<<BODY>>\necho RC:$?",
        "ssh:Provisioning:cat /etc/fstab 2>/dev/null; rc=$?; echo FSTAB-DONE; echo RC:$rc",
        "ssh:Provisioning:mkdir -p /etc/initramfs-tools/hooks && cat > /etc/initramfs-tools/hooks/orchard-reclaim <<'ORCHARD_RECLAIM_HOOK' && chmod 755 /etc/initramfs-tools/hooks/orchard-reclaim\n<<BODY>>\necho RC:$?",
        "ssh:Provisioning:mkdir -p /etc/initramfs-tools/scripts/local-premount && cat > /etc/initramfs-tools/scripts/local-premount/orchard-reclaim <<'ORCHARD_RECLAIM_PREMOUNT' && chmod 755 /etc/initramfs-tools/scripts/local-premount/orchard-reclaim\n<<BODY>>\necho RC:$?",
        "ssh:Provisioning:update-initramfs -u -k all 2>/dev/null 1>&2; echo RC:$?",
        "ssh:Provisioning:rc=0; n=0; for f in /boot/initrd.img-*; do [ -e \"$f\" ] || continue; v=${f#/boot/initrd.img-}; [ -e \"/boot/vmlinuz-$v\" ] || [ -e \"/boot/vmlinux-$v\" ] || continue; n=$((n+1)); echo \"INITRD:$f\"; lsinitramfs \"$f\" 2>/dev/null || rc=1; done; echo \"INITRD-COUNT:$n\"; echo RC:$rc",
        "ssh:Provisioning:for f in /boot/initrd.img-*; do [ -e \"$f\" ] || continue; v=${f#/boot/initrd.img-}; [ -e \"/boot/vmlinuz-$v\" ] || [ -e \"/boot/vmlinux-$v\" ] || continue; echo \"ORDER-INITRD:$f\"; d=$(mktemp -d) && unmkinitramfs \"$f\" \"$d\" 2>/dev/null; cat \"$d\"/*/scripts/local-premount/ORDER \"$d\"/scripts/local-premount/ORDER 2>/dev/null; rm -rf \"$d\"; done; echo ORDER-DONE",
        "ssh:Provisioning:cat /proc/sys/kernel/random/boot_id",
        "ssh:Provisioning:nohup reboot >/dev/null 2>&1 & echo REBOOT-ISSUED",
        "ssh:Provisioning:cat /proc/sys/kernel/random/boot_id",
        "ssh:Provisioning:findmnt -n -o SOURCE / || true",
        "ssh:Provisioning:lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME",
        "ssh:Provisioning:dmesg 2>/dev/null | grep -F 'orchard-reclaim:'; echo CRUMB-DONE",
        "ssh:Provisioning:lsblk -nbro NAME,TYPE,START,SIZE /dev/vda",
        "ssh:Provisioning:findmnt -n -o SOURCE --target /var/tmp/recipes-deploy || true",
        "ssh:Provisioning:df -P -k /var/tmp/recipes-deploy",
        "ssh:Provisioning:date +%s",
        "say:reclaim-tail COMPLETE: the window sits i",
        "scp:<DIR>/r.vmlinuz:/var/tmp/recipes-deploy/r.vmlinuz",
        "scp:<DIR>/r.initramfs:/var/tmp/recipes-deploy/r.initramfs",
        "say:streaming the 1536-byte image onto the r",
        "stage_raw_window:vda:42941284352",
        "ssh:Provisioning:dd if=/var/tmp/recipes-deploy/r.vmlinuz iflag=direct bs=1M status=none | sha256sum",
        "ssh:Provisioning:dd if=/var/tmp/recipes-deploy/r.initramfs iflag=direct bs=1M status=none | sha256sum",
        "ssh:Provisioning:dd if=/dev/vda iflag=direct,skip_bytes,count_bytes skip=42941284352 count=1536 bs=1M status=none | sha256sum",
        "ssh:Provisioning:kexec -l /var/tmp/recipes-deploy/r.vmlinuz --initrd=/var/tmp/recipes-deploy/r.initramfs --append='fb.mode=installer fb.firmware=seabios fb.root-hash=abababababababababababababababababababababababababababababababab fb.verity-hash-offset=256 fb.image-raw=vda:42941284352:1536 fb.image-sha256=e5a2026ccc5590ac8806bb18e93fab4e684b48e80978d6827a1a2c909c64d587 fb.image-layout=fw:seabios,boot:0:512,skel:512:512,rootfs:1024:512 lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2 console=tty0 console=ttyS0'",
        "say:kexec loaded on 203.0.113.5; executing —",
        "fire_kexec",
        "pin:Reconnect:203.0.113.5 ssh-ed25519 AAAAfake",
        "say:waiting for the installed box at 203.0.1",
        "ssh:Reconnect:echo recipes-box-up",
        "ssh:Reconnect:cat /proc/mounts",
        "ssh:Reconnect:cat /proc/cmdline",
        "ssh:Reconnect:head -c 512 /dev/vda1 | sha256sum",
        "ssh:Reconnect:wget -q -S -O /dev/null --no-check-certificate https://127.0.0.1:443/ 2>&1 || true",
        "say:deploy prod COMPLETE: 203.0.113.5 runs y",
        "say:the installed box's runtime host key is ",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Normalize the recorded calls for the AC-R13 snapshots: the per-run tempdir becomes `<DIR>`,
/// and only the heredoc BODY (the lines between the opening `<<'MARKER'` and the terminator line)
/// collapses to `<<BODY>>`. The bodies (the rendered premount script, the hook, the edited fstab,
/// the F_GETLK reader) are pinned by their own seam tests; embedding them here would make the
/// vector fail on every comment edit while proving nothing about the call SEQUENCE, which is the
/// property AC-R13 needs. The rest of the command LINE stays: the `&& chmod …` on the redirect line
/// and the trailing `echo RC:$?` remain visible, so a B-2-style reorder that moves the chmod out of
                                                                                                
                                      
fn normalized_calls(ops: &FakeOps, dir: &Path) -> Vec<String> {
    let d = dir.display().to_string();
    ops.target_calls
        .iter()
        .map(|c| {
            let c = c.replace(&d, "<DIR>");
            match c.split_once("<<'") {
                Some((head, rest)) => {
                    let marker = rest.split('\'').next().unwrap_or("");
                                                                                                   
                                                                                          
                    let after = &rest[marker.len() + 1..];
                    let line0_tail = after.split('\n').next().unwrap_or("");
                                                                                                  
                    let tail = after
                        .split_once(&format!("\n{marker}"))
                        .map(|(_, t)| t)
                        .unwrap_or("");
                    format!("{head}<<'{marker}'{line0_tail}\n<<BODY>>{tail}")
                }
                None => c,
            }
        })
        .collect()
}

#[test]
fn no_flag_deploy_prod_call_sequence_is_pinned_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    deploy_prod(&mut ops, FakeOps::opts(dir.path())).expect("happy ceremony succeeds");
    assert_eq!(normalized_calls(&ops, dir.path()), expected_no_flag_calls());
}

#[test]
fn reclaim_short_circuit_call_sequence_is_pinned_exactly() {
                                                                                             
                                                                         
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_short_circuit(dir.path());
    deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).expect("short-circuit succeeds");
    assert_eq!(
        normalized_calls(&ops, dir.path()),
        expected_reclaim_short_circuit_calls()
    );
}

                                                                            
                                                                                                    
                                                                                                      
                                                                                                           
                              

#[test]
fn reclaim_will_run_call_sequence_is_pinned_exactly() {
                                                                                             
                                                                                           
                                                                                              
                                                                               
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).expect("will-run succeeds");
    assert_eq!(
        normalized_calls(&ops, dir.path()),
        expected_reclaim_will_run_calls()
    );
}

#[test]
fn a_post_reclaim_staging_failure_disarms_the_reachable_target() {
                                                                                               
                                                                                                   
                                                                                                  
                                                                                               
                                                                         
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
                                                                                 
    ops.remote.insert(
        0,
        (
            "rm -f /etc/initramfs-tools/hooks/orchard-reclaim",
            "RC:0".to_string(),
        ),
    );
    ops.remote.insert(
        0,
        (
            "echo LS-DONE",
            "usr/sbin/e2fsck\nscripts/local-premount/resume\n\
             LS-OK:/boot/initrd.img-6.1.0-0-amd64\nLS-COUNT:1\nLS-DONE"
                .to_string(),
        ),
    );
                                                                                                   
                                                                                             
    let mut injected = false;
    for (needle, resp) in &mut ops.remote {
        if needle.contains("iflag=direct,skip_bytes") {
            *resp =
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  -".to_string();
            injected = true;
        }
    }
    assert!(
        injected,
        "the window-readback reply must exist to be failed"
    );
    let err = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert!(
        err.contains("readback"),
        "the abort is the window-readback contention: {err}"
    );
    assert!(
        err.contains("disarm"),
        "the abort must report the disarm outcome: {err}"
    );
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("rm -f /etc/initramfs-tools/hooks/orchard-reclaim")),
        "the disarm must remove the reclaim hook on a post-reclaim staging failure: {:?}",
        ops.target_calls
    );
    assert!(
        !ops.target_calls.iter().any(|c| c.contains("fire_kexec")),
        "no kexec fires on a pre-kexec abort: {:?}",
        ops.target_calls
    );
}

#[test]
fn a_refused_kexec_after_reclaim_disarms_the_reachable_target() {
                                                                                                 
                                                                                                 
                                                                                                 
                                                                                                    
                                                                                                  
                                                                                       
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
                                                                                               
                                                                                  
    ops.fire_kexec_err = Some(
        "kexec -e was refused on the target (exit status: 1): kexec_load failed: Operation not \
         permitted — nothing was written"
            .to_string(),
    );
                                                                                          
    ops.remote.insert(
        0,
        (
            "rm -f /etc/initramfs-tools/hooks/orchard-reclaim",
            "RC:0".to_string(),
        ),
    );
    ops.remote.insert(
        0,
        (
            "echo LS-DONE",
            "usr/sbin/e2fsck\nscripts/local-premount/resume\n\
             LS-OK:/boot/initrd.img-6.1.0-0-amd64\nLS-COUNT:1\nLS-DONE"
                .to_string(),
        ),
    );
    let err = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert!(
        err.contains("kexec -e was refused") && err.contains("nothing was written"),
        "the abort carries the kexec-refusal witness: {err}"
    );
    assert!(
        err.contains("disarm"),
        "the abort must report the disarm outcome: {err}"
    );
                                                                                                      
                                                                       
    let fire_pos = ops.target_calls.iter().position(|c| c == "fire_kexec");
    let disarm_pos = ops
        .target_calls
        .iter()
        .position(|c| c.contains("rm -f /etc/initramfs-tools/hooks/orchard-reclaim"));
    assert!(
        matches!((fire_pos, disarm_pos), (Some(f), Some(d)) if f < d),
        "the disarm must run AFTER the refused fire_kexec: fire={fire_pos:?} disarm={disarm_pos:?} in {:?}",
        ops.target_calls
    );
}

#[test]
fn no_flag_against_a_grown_target_refuses_naming_the_remedy_with_no_write() {
                                                                                                  
                                                                                    
                                               
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());                               
    let err = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(err.contains("INTERSECTS"), "{err}");
    assert!(err.contains("orchard reclaim-tail"), "{err}");
                                                                                                     
                                                                                               
                                                                                                     
                                                                                             
                                                                                                 
                                                                                                   
                                                                         
    assert!(
        err.contains(PREFLIGHT_D1_MESSAGE),
        "the unflagged D-1 slot must carry the WHOLE rendered refusal: {err}"
    );
    for clause in PREFLIGHT_ONLY_CLAUSES {
        assert!(
            err.contains(clause),
            "the unflagged D-1 refusal must keep {clause:?}: {err}"
        );
    }
    for c in &ops.target_calls {
        assert!(
            !(c.contains("cat > ")
                || c.contains("touch ")
                || c.contains("purge")
                || c.contains("sfdisk")
                || c.contains("update-initramfs")
                || c.contains("reboot")
                || c.contains("stage_raw_window")
                || c.contains("kexec")),
            "no write-shaped call may run on the no-flag refusal: {c}"
        );
    }
}

#[test]
fn standalone_reclaim_noop_when_d1_passes() {
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    reclaim_tail_standalone(
        &mut ops,
        &StandaloneOpts {
            ip: "203.0.113.5".into(),
            image: dir.path().join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            timeout_secs: None,
        },
    )
    .expect("S-NOOP path succeeds");
    assert!(
        ops.said.iter().any(|m| m.contains("S-NOOP")),
        "the no-op is said: {:?}",
        ops.said
    );
}

#[test]
fn standalone_reclaim_runs_end_to_end_and_disarms() {
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
                                              
    ops.remote.insert(
        0,
        (
            "rm -f /etc/initramfs-tools/hooks/orchard-reclaim",
            "RC:0".to_string(),
        ),
    );
    ops.remote.insert(
        0,
        (
                                                                                         
                                                                                               
            "echo LS-DONE",
            "usr/sbin/e2fsck\nscripts/local-premount/resume\n\
             LS-OK:/boot/initrd.img-6.1.0-0-amd64\nLS-COUNT:1\nLS-DONE"
                .to_string(),
        ),
    );
    reclaim_tail_standalone(
        &mut ops,
        &StandaloneOpts {
            ip: "203.0.113.5".into(),
            image: dir.path().join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            timeout_secs: None,
        },
    )
    .expect("the standalone will-run path completes");
    let done = ops
        .said
        .iter()
        .any(|m| m.contains("A prepared disk") && m.contains("REMAINS DISABLED"));
    assert!(done, "the report is said: {:?}", ops.said);
                                                                                         
    let adv = ops
        .target_calls
        .iter()
        .position(|c| c.contains("reclaim-tail prepares this"));
    let plan = ops
        .target_calls
        .iter()
        .position(|c| c.contains("reclaim-tail plan for"));
    assert!(
        adv.is_some() && plan.is_some() && adv < plan,
        "advisory before plan"
    );
}

#[test]
fn standalone_cancel_before_consent_writes_nothing() {
                                                                                                
                                                                                                
                                                                     
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    ops.cancel = true;
    let e = reclaim_tail_standalone(
        &mut ops,
        &StandaloneOpts {
            ip: "203.0.113.5".into(),
            image: dir.path().join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            timeout_secs: None,
        },
    )
    .unwrap_err();
    assert!(
        e.contains("cancelled") && e.contains("nothing was written"),
        "{e}"
    );
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("touch /etc/cloud/cloud-init.disabled")
                || c.contains("cat > /etc/fstab")
                || c.contains("purge -y")),
        "a write ran despite the pre-consent cancel: {:?}",
        ops.target_calls
    );
}

#[test]
fn standalone_cancel_between_the_two_checks_writes_nothing() {
                                                                                              
                                                                                                     
                                                                                                   
                                                                                                    
                                                                                                    
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    ops.cancel_on_say = Some("reclaim-tail plan for");                                           
    let e = reclaim_tail_standalone(
        &mut ops,
        &StandaloneOpts {
            ip: "203.0.113.5".into(),
            image: dir.path().join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            timeout_secs: None,
        },
    )
    .unwrap_err();
    assert!(
        e.contains("cancelled") && e.contains("nothing was written"),
        "{e}"
    );
                                                                                       
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("reclaim-tail plan for")),
        "the plan say must have run (proving the first check passed): {:?}",
        ops.target_calls
    );
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("touch /etc/cloud/cloud-init.disabled")
                || c.contains("cat > /etc/fstab")
                || c.contains("purge -y")),
        "a write ran despite the consent-window cancel: {:?}",
        ops.target_calls
    );
}

#[test]
fn write_commands_report_the_write_rc_not_chmods() {
                                                                                                  
                                                                                               
                                                                                           
    use crate::deploy::reclaim::ceremony::{hook_write_cmd, premount_write_cmd};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

                                                                                               
                                                                                                  
    for cmd in [hook_write_cmd("HOOKBODY\n"), premount_write_cmd("PMBODY\n")] {
        let redirect_line = cmd.lines().next().unwrap();
        assert!(
            redirect_line.contains("&& \\") || redirect_line.contains("&& chmod 755"),
            "chmod must be chained into the write with &&: {cmd}"
        );
        assert!(
            cmd.trim_end().ends_with("echo RC:$?"),
            "echo RC:$? must be the final line: {cmd}"
        );
    }

                                                                                                  
                                                                                                  
                                                                                                     
                                               
    let dir = tempfile::tempdir().unwrap();
    let hooks = dir.path().join("hooks");
    let run = |cmd: String| -> String {
        let script = cmd.replace("/etc/initramfs-tools/hooks", hooks.to_str().unwrap());
        let out = Command::new("sh").arg("-c").arg(&script).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let target = hooks.join("orchard-reclaim");

    let ok = run(hook_write_cmd("hello\n"));
    assert!(ok.ends_with("RC:0"), "a good write reports RC:0: {ok:?}");
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "the good write left the file 0755");

    std::fs::remove_file(&target).unwrap();
    std::fs::create_dir(&target).unwrap();                                   
    let bad = run(hook_write_cmd("hello\n"));
    let rc = bad.rsplit_once("RC:").expect("an RC token").1;
    assert_ne!(
        rc, "0",
        "a failed write must NOT report RC:0 (B-2): {bad:?}"
    );
}

#[test]
fn probe_p2_post_reclaim_clock_skew_overflow() {
                                                                                                 
                                                                                                
                                                                                                     
                                                                                             
                                                                                                   
                                                                                                    
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    let honest = ops.now_epoch();
    ops.remote_once
        .push_back(("date +%s", format!("{honest}\n")));
    ops.remote_once
        .push_back(("date +%s", "9223372036854775808\n".to_string()));
    let err = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("an out-of-range post-reclaim clock must refuse, not overflow");
    assert!(
        err.contains("clock-skew re-take") && err.contains("out of i64 range"),
        "F-1 refusal names the re-take and the out-of-range clock: {err}"
    );
}

                                                                                                     
                                                                                                
                                                                                                     
                                                                                                     
                                                                                                  
         

#[test]
fn deploy_prod_before_install_refusal_issues_no_cleanup() {
                                                                                                  
                                                                                                        
                                                                                                  
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    for (needle, resp) in &mut ops.remote {
        if *needle == "touch /etc/cloud/cloud-init.disabled" {
            *resp = "RC:1".to_string();
        }
    }
    let err = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("a failing marker write must refuse");
    assert!(
        err.contains("R-NEUTRALIZE") && err.contains("cloud-init.disabled"),
        "the refusal is the marker arm: {err}"
    );
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("rm -f /etc/initramfs-tools/hooks/")
                || c.contains("update-initramfs -u -k all")),
        "a BeforeInstall refusal issues no cleanup at the shipped call site: {:?}",
        ops.target_calls
    );
                                                                                                     
                                                                                                  
    assert!(
        err.contains("if any reclaim step reached"),
        "a touch rc≠0 may have landed the marker — the refusal hedges the permanence: {err}"
    );
}

#[test]
fn deploy_prod_marker_applied_refusal_discloses_permanence() {
                                                                                                 
                                                                                                        
                                                                                                       
                                                                                                    
                                                                                            
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    for (needle, resp) in &mut ops.remote {
        if *needle == "cat > /etc/fstab" {
            *resp = "RC:1".to_string();
        }
    }
    let err = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("an fstab-write failure must refuse");
    assert!(
        err.contains("R-NEUTRALIZE") && err.contains("fstab write failed"),
        "the refusal is the fstab write arm, past the marker: {err}"
    );
    assert!(
        err.contains("PERMANENT") && err.contains("none of them restored"),
        "the permanence is disclosed by the standing note: {err}"
    );
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("rm -f /etc/initramfs-tools/hooks/")
                || c.contains("update-initramfs -u -k all")),
        "a BeforeInstall refusal issues no cleanup, even when the marker landed: {:?}",
        ops.target_calls
    );
}

#[test]
fn standalone_before_install_refusal_issues_no_cleanup() {
                                                                                                       
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    for (needle, resp) in &mut ops.remote {
        if *needle == "touch /etc/cloud/cloud-init.disabled" {
            *resp = "RC:1".to_string();
        }
    }
    let err = reclaim_tail_standalone(
        &mut ops,
        &StandaloneOpts {
            ip: "203.0.113.5".into(),
            image: dir.path().join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            timeout_secs: None,
        },
    )
    .expect_err("a failing marker write must refuse");
    assert!(
        err.contains("R-NEUTRALIZE"),
        "the refusal is the marker arm: {err}"
    );
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("rm -f /etc/initramfs-tools/hooks/")
                || c.contains("update-initramfs -u -k all")),
        "the standalone BeforeInstall refusal issues no cleanup: {:?}",
        ops.target_calls
    );
                                                                                                     
    assert!(
        err.contains("if any reclaim step reached"),
        "a touch rc≠0 may have landed the marker — the refusal hedges the permanence: {err}"
    );
}

                                                                                                          
                                                                                                        
                                                                                                        
                                                                                  
                                                                                                       
                                                                                                        
                                                                                                     
                                                                                                       
                          
                                                                                              
                                                                                                                  
                                                                                                               
                                                                                                                 
                                                                                                        
                                                                                                     
                                                          

/// The disarm's own replies, so an AfterInstall route can proceed past the `rm` (same shape as the
/// inline replies in `a_post_reclaim_staging_failure_disarms_the_reachable_target`).
fn with_disarm_replies(ops: &mut FakeOps) {
    ops.remote.insert(
        0,
        (
            "rm -f /etc/initramfs-tools/hooks/orchard-reclaim",
            "RC:0".to_string(),
        ),
    );
    ops.remote.insert(
        0,
        (
            "echo LS-DONE",
            "usr/sbin/e2fsck\nscripts/local-premount/resume\n\
             LS-OK:/boot/initrd.img-6.1.0-0-amd64\nLS-COUNT:1\nLS-DONE"
                .to_string(),
        ),
    );
}

#[test]
fn deploy_prod_after_install_refusal_runs_the_disarm() {
                                                                                                     
                                                                                                   
                                                                                              
                                                                                                 
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    let mut injected = false;
    for (needle, resp) in &mut ops.remote {
        if *needle == "cat > /etc/initramfs-tools/hooks/" {
            *resp = "RC:2".to_string();
            injected = true;
        }
    }
    assert!(injected, "the hook-write reply must exist to be failed");
    let err = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("a failing hook write must refuse");
    assert!(
        err.contains("R-INITRAMFS") && err.contains("writing the hook failed"),
        "the refusal is the hook-write arm: {err}"
    );
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("rm -f /etc/initramfs-tools/hooks/orchard-reclaim")),
        "an AfterInstall refusal MUST disarm at the shipped call site: {:?}",
        ops.target_calls
    );
    assert!(
        err.contains("disarm"),
        "the abort must report the disarm outcome: {err}"
    );
}

#[test]
fn standalone_after_install_refusal_runs_the_disarm() {
                                                                                                       
                                                                                             
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    let mut injected = false;
    for (needle, resp) in &mut ops.remote {
        if *needle == "cat > /etc/initramfs-tools/hooks/" {
            *resp = "RC:2".to_string();
            injected = true;
        }
    }
    assert!(injected, "the hook-write reply must exist to be failed");
    let err = reclaim_tail_standalone(
        &mut ops,
        &StandaloneOpts {
            ip: "203.0.113.5".into(),
            image: dir.path().join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            timeout_secs: None,
        },
    )
    .expect_err("a failing hook write must refuse");
    assert!(
        err.contains("R-INITRAMFS"),
        "the refusal is the hook-write arm: {err}"
    );
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("rm -f /etc/initramfs-tools/hooks/orchard-reclaim")),
        "the standalone AfterInstall refusal MUST disarm: {:?}",
        ops.target_calls
    );
}

                                                                                                        
                                                                                                     
                                                                                                       
                                                                                                   
                                                                               

#[test]
fn deploy_prod_reboot_arbitrate_failure_disarms_the_reachable_target() {
                                                                                                       
                                                                                                     
                                                                                                       
                  
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    let honest = ops.now_epoch();
    ops.remote_once
        .push_back(("date +%s", format!("{honest}\n")));
    ops.remote_once
        .push_back(("date +%s", "9223372036854775808\n".to_string()));
    let err = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("an out-of-range post-reclaim clock must refuse");
    assert!(
        err.contains("clock-skew re-take"),
        "the abort is the reboot/arbitrate wrap: {err}"
    );
    assert!(
        err.contains("disarm"),
        "the reboot-wrap abort must report the disarm outcome: {err}"
    );
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("rm -f /etc/initramfs-tools/hooks/orchard-reclaim")),
        "the reboot-wrap abort MUST disarm at the shipped call site: {:?}",
        ops.target_calls
    );
}

#[test]
fn standalone_reboot_arbitrate_failure_disarms_the_reachable_target() {
                                                                                              
                                                                                                       
                                                                                        
                                                                                                        
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    for (needle, resp) in &mut ops.remote {
        if needle.contains("/proc/sys/kernel/random/boot_id") {
            *resp = "11111111-1111-1111-1111-111111111111\n".to_string();
        }
    }
    let err = reclaim_tail_standalone(
        &mut ops,
        &StandaloneOpts {
            ip: "203.0.113.5".into(),
            image: dir.path().join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            timeout_secs: Some(1),
        },
    )
    .expect_err("a poll timeout must refuse");
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("rm -f /etc/initramfs-tools/hooks/orchard-reclaim")),
        "the standalone reboot-wrap abort MUST disarm: {err}\n{:?}",
        ops.target_calls
    );
}

                                                                                               
                                                                                            
                                                                                                   
                                                                                                
                                                                                                    
                                                                                                                   
                                               

#[test]
fn every_reclaim_region_failure_states_the_permanence_fact() {
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
                                                                                              
                                                                                                   
                                                                                                  
                                                                                                  
                                                                                                 
                                                                                          
                                                          
    let marker = "if any reclaim step reached";
    let notes = |e: &str| e.matches(marker).count();

                                                                                         
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    ops.cancel = true;
    let standalone = |dir: &Path| StandaloneOpts {
        ip: "203.0.113.5".into(),
        image: dir.join("r.img"),
        host_fingerprint: Some("SHA256:legA".into()),
        timeout_secs: None,
    };
    let e = reclaim_tail_standalone(&mut ops, &standalone(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "standalone pre-write cancel: {e}");
    assert!(
        e.contains("nothing was written to the target by the reclaim"),
        "{e}"
    );

                                                                                                
                                                                                        
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    ops.cancel_on_say = Some("ADVISORY — read before confirming:");
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "prod pre-consent cancel: {e}");
    assert!(
        e.contains("cancelled") && e.contains("by the reclaim"),
        "{e}"
    );
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("reclaim-tail plan for")),
        "the abort must fire BEFORE plan_and_consent: {:?}",
        ops.target_calls
    );

                                                                                                 
                                                                           
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    ops.cancel_on_say = Some("reclaim-tail plan for");
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "prod pre-write cancel: {e}");
    assert!(
        ops.target_calls
            .iter()
            .any(|c| c.contains("reclaim-tail plan for")),
        "the plan say must have run (the FIRST check passed): {:?}",
        ops.target_calls
    );
    assert!(
        !ops.target_calls
            .iter()
            .any(|c| c.contains("touch /etc/cloud/cloud-init.disabled")),
        "no write may run after the pre-write cancel: {:?}",
        ops.target_calls
    );

                                                                                      
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    for (needle, resp) in &mut ops.remote {
        if *needle == "touch /etc/cloud/cloud-init.disabled" {
            *resp = "RC:1".to_string();
        }
    }
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "BeforeInstall: {e}");
    assert!(
        e.contains("this run wrote no reclaim hook") && e.contains("§9.1"),
        "the per-arm hook fact + the manual-removal pointer: {e}"
    );
                                                                                                   
                                                                                                  
                                                                                                    
                                        
    assert!(
        e.contains("may carry PERMANENT changes (any of"),
        "(c) the note is the conservative set form on a partial-neutralize arm: {e}"
    );

                                                                                                  
                                                                                                 
                                                
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    for (needle, resp) in &mut ops.remote {
        if *needle == "cat > /etc/initramfs-tools/hooks/" {
            *resp = "RC:2".to_string();
        }
    }
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "AfterInstall: {e}");
    assert!(e.contains("disarmed:"), "{e}");
    assert!(
        !e.contains("may still be"),
        "a verified disarm must not be contradicted by an armed clause: {e}"
    );

                                                                                                   
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    for (needle, resp) in &mut ops.remote {
        if needle.contains("iflag=direct,skip_bytes") {
            *resp =
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  -".to_string();
        }
    }
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "staging wrap: {e}");
    assert!(
        e.contains("RECLAIM HAS RUN") && e.contains("shrunk"),
        "a post-reclaim staging failure states the resize: {e}"
    );

                                                                
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    ops.fire_kexec_err = Some("kexec -e was refused on the target".to_string());
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "refused fire_kexec: {e}");
    assert!(e.contains("RECLAIM HAS RUN"), "{e}");

                                                                                             
                                                                                             
                                                                                             
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    ops.cancel_on_say = Some("reclaim-tail COMPLETE");
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "post-reclaim cancel: {e}");
    assert!(
        e.contains("cancelled") && e.contains("RECLAIM HAS RUN") && e.contains("shrunk"),
        "a post-reclaim cancel states the resize: {e}"
    );

                                                                                           
                                                                                                    
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    let e = reclaim_tail_standalone(&mut ops, &standalone(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "completion disarm: {e}");
    assert!(
        e.contains("RECLAIM HAS RUN") && e.contains("manual removal per"),
        "the completion-disarm arm states the resize + the manual-removal pointer: {e}"
    );

                                                                                                   
                                                                                                  
                                                                                        
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    for (needle, resp) in &mut ops.remote {
        if needle.contains("FSTYPE") {
            *resp = "xfs\nRC:0".to_string();
        }
    }
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "read-only refusal: {e}");
    assert!(e.contains("R-ELIG"), "{e}");
    assert!(
        !e.contains("hook") && !e.contains("armed"),
        "a read-only refusal wrote nothing and carries no armed clause: {e}"
    );

                                                                                             
                                          
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    ops.tty = true;
    ops.lines = ["203.0.113.5".to_string(), "n".to_string()]
        .into_iter()
        .collect();
    let e = reclaim_tail_standalone(&mut ops, &standalone(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "consent decline: {e}");
    assert!(e.contains("R-DECLINE"), "{e}");

                                                                                
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    ops.tty = true;
    ops.lines = ["not-the-target".to_string()].into_iter().collect();
    let e = reclaim_tail_standalone(&mut ops, &standalone(dir.path())).unwrap_err();
    assert_eq!(notes(&e), 1, "retype mismatch: {e}");
    assert!(e.contains("retype mismatch"), "{e}");
}

#[test]
fn deploy_prod_marks_post_arbitrate_retake_failures_completed_at_the_boundary() {
                                                                                                 
                                                                                                    
                                                                 
                                                                                                   
                                                                                                
                                                                                                  
                                                                                                    
                                                                                                
                                                                                                    
                                                                                              
    let clause = "RECLAIM HAS RUN";

                                                                                                       
                                                                                                   
                                                                                        
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    let now = ops.now_epoch();
    ops.remote_once.push_back(("date +%s", format!("{now}\n")));
    ops.remote_once
        .push_back(("date +%s", format!("{}\n", now + 9999)));
    let skew = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert!(
        skew.contains("clock is") && skew.contains("after the reclaim reboot"),
        "arm sanity: this drives the post-reclaim clock-skew re-take: {skew}"
    );
    assert!(
        skew.contains(clause) && skew.contains("shrunk"),
        "a post-arbitrate re-take failure carries the completed-reclaim fact: {skew}"
    );

                                                                                                  
                                                                                                    
                                                                               
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    for (needle, resp) in &mut ops.remote {
        if needle.contains("/proc/sys/kernel/random/boot_id") {
            *resp = "11111111-1111-1111-1111-111111111111\n".to_string();
        }
    }
    let mut o = FakeOps::opts_reclaim(dir.path());
    o.reclaim_reboot_timeout_secs = Some(1);
    let timeout = deploy_prod(&mut ops, o).unwrap_err();
                                                                                                   
                                                                                                
                                                                                                    
                                                                                      
    assert!(
        timeout.contains("R-NO-ANSWER"),
        "arm sanity — this drives the reboot-poll-timeout arm (row R-NO-ANSWER): {timeout}"
    );
    assert!(
        !timeout.contains(clause),
        "a pre-arbitrate (reboot-timeout) failure must not claim the shrink ran: {timeout}"
    );
}

#[test]
fn completion_disarm_abort_renders_the_shrink_clause_from_the_flag_not_unconditionally() {
                                                                                       
                                                                                                   
                                                                                                      
                                                                                                      
                                                                                                  
                                                                                          
                                                                                                   
                                                                                                    
                   
    use crate::deploy::prod_orchestrate::{ArmedFailure, completion_disarm_abort};

    let unmarked = completion_disarm_abort(ArmedFailure::new(
        crate::deploy::reclaim::rows::DISARM,
        "a completion disarm failure",
    ))
    .into_message();
    assert!(
        unmarked.contains("manual removal per"),
        "arm sanity — completion_disarm_abort rendered its text: {unmarked}"
    );
    assert!(
        !unmarked.contains("RECLAIM HAS RUN"),
        "an un-marked (not-past-boundary) failure must not assert the shrink completed: {unmarked}"
    );

    let marked = completion_disarm_abort(
        ArmedFailure::new(
            crate::deploy::reclaim::rows::DISARM,
            "a completion disarm failure",
        )
        .mark_completed(),
    )
    .into_message();
    assert!(
        marked.contains("RECLAIM HAS RUN") && marked.contains("shrunk"),
        "a marked (past-boundary) failure renders the completed-reclaim clause: {marked}"
    );
}

#[test]
fn non_reclaim_failures_carry_no_reclaim_note() {
                                                                                                 
                                                                                                  
                                                                                                 
                                                                                               
                                                                                                  
    let marker = "if any reclaim step reached";

                                                                                         
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    ops.cancel = true;
    let e = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(
        e.contains("cancelled by operator signal BEFORE kexec"),
        "{e}"
    );
    assert!(!e.contains(marker), "no reclaim ran — no note: {e}");

                                                                                   
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    ops.cancel_on_say = Some("streaming the");
    let e = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(e.contains("cancelled"), "{e}");
    assert!(!e.contains(marker), "{e}");

                                                                                                 
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy(dir.path());
    for (needle, resp) in &mut ops.remote {
        if needle.contains("iflag=direct,skip_bytes") {
            *resp =
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  -".to_string();
        }
    }
    let e = deploy_prod(&mut ops, FakeOps::opts(dir.path())).unwrap_err();
    assert!(e.contains("direct-readback mismatch"), "{e}");
    assert!(!e.contains(marker), "{e}");

                                                                                                  
                                                                                                       
                                                                                               
                                                                                       
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_short_circuit(dir.path());
    ops.cancel_on_say = Some("streaming the");
    let e = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert!(e.contains("cancelled"), "{e}");
    assert!(
        e.contains(marker) && e.contains("short-circuited") && e.contains("§9.1"),
        "the short-circuit discloses prior permanence + the manual-removal pointer: {e}"
    );
    assert!(
        !e.contains("RECLAIM HAS RUN"),
        "no completed-this-run clause on a short-circuit (nothing ran this run): {e}"
    );
}

#[test]
fn standalone_completion_disarm_failure_surfaces_as_an_error_not_complete() {
                                                                                                      
                                                                                                    
                                                                                                         
                                                                        
    use crate::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
                                                                                             
    reclaim_tail_standalone(
        &mut ops,
        &StandaloneOpts {
            ip: "203.0.113.5".into(),
            image: dir.path().join("r.img"),
            host_fingerprint: Some("SHA256:legA".into()),
            timeout_secs: None,
        },
    )
    .expect_err("a completion-disarm failure must surface as an error");
    assert!(
        !ops.said.iter().any(|m| m.contains("reclaim-tail COMPLETE")),
        "the COMPLETE banner must NOT print over a failed completion disarm: {:?}",
        ops.said
    );
}

#[test]
fn debug_on_reclaim_error_types_does_not_leak_the_operator_text() {
                                                                                                
                                                                                                       
                                                                                                      
                                                                                                    
                                                                                                   
    use crate::deploy::prod_orchestrate::{ArmedFailure, reclaim_abort_text};
    let secret = "SECRET-OPERATOR-TEXT-DO-NOT-LEAK";
    let ra = reclaim_abort_text(secret);
    assert!(
        !format!("{ra:?}").contains(secret),
        "ReclaimAbort Debug must not leak the operator text: {ra:?}"
    );
    let af = ArmedFailure::new(crate::deploy::reclaim::rows::DISARM, secret);
    assert!(
        !format!("{af:?}").contains(secret),
        "ArmedFailure Debug must not leak the refusal text: {af:?}"
    );
}

#[test]
fn arbitrate_extent_reread_failure_discloses_the_completed_shrink_breadcrumb() {
                                                                                                 
                                                                                                  
                                                                                                 
                               
                                                                                                
                                                                                                     
                                                                                                 
                                                                                                    
                                                                                      
                                                        
    let crumb = "step10 done";

                                                                                                       
                                                                                                  
                                                                                            
                                                                              
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    for (needle, _) in &mut ops.remote {
        if *needle == "lsblk -nbro NAME,TYPE,START,SIZE" {
            *needle = "lsblk -nbro NAME,TYPE,START,SIZE,ZZZNOMATCH";
        }
        if *needle == "lsblk" {
            *needle = "lsblk -nro NAME,TYPE,MOUNTPOINT,PKNAME";
        }
    }
    let e1 = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert!(
        e1.contains("extent re-read failed"),
        "the transport-failure arm is the subject of this test: {e1}"
    );
    assert!(
        e1.contains(crumb) && e1.contains("breadcrumb:"),
        "the transport-failure arm must disclose the completed-shrink breadcrumb: {e1}"
    );

                                                                                                  
                                                                                             
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    ops.remote_once.push_back((
        "lsblk -nbro NAME,TYPE,START,SIZE",
        "vda1 part notanumber 42\n".to_string(),
    ));
    let e2 = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path())).unwrap_err();
    assert!(
        e2.contains("extent re-read did not parse") && e2.contains(crumb),
        "the parse-failure sibling still discloses the crumb: {e2}"
    );
}

                                                                                                  
                                                                                                
                                                                                                   
                                                                              
                                                                                             
                                                                                                   
                                                                                           
                                   

/// The post-reboot `lsblk -nbro NAME,TYPE,START,SIZE` reply: the root still fills the disk, so the
/// D-1 re-run refuses. Byte-identical to the pre-reboot grown reply `happy_reclaim_will_run` pushes.
const REREAD_GROWN_EXTENTS: &str = "vda disk  42949672960\nvda1 part 2048 42948607488\n";

/// The geometry the post-reboot D-1 line must disclose, as a HAND literal derived from the
/// fixture's own inputs, never from the SUT:
///   window — `stage_raw_window:vda:42941284352` and the 1536-byte image, both pinned independently
///            in `expected_reclaim_will_run_calls` above → `[42941284352, 42941284352 + 1536)`.
///   vda1   — `REREAD_GROWN_EXTENTS`' `2048 42948607488`, where lsblk's START is SECTORS and SIZE is
///            BYTES (`prod::parse_lsblk_partition_extents`) → `[2048*512, 2048*512 + 42948607488)`.
const REREAD_D1_LINE: &str = "the re-read staging window [42941284352, 42941285888) on /dev/vda \
     still INTERSECTS partition /dev/vda1 at [1048576, 42949656064)";

/// Clauses that are true ONLY at the pre-flight slot: this run stopped before touching the target,
/// and the remedy is the reclaim ceremony. A post-reboot arm carrying any of them contradicts its
/// own prose. The set is six of the pre-flight renderer's distinctive fragments; a paraphrase that
/// copies none of them is a NAMED BLIND SPOT of this literal set in the NEGATIVE direction (the
/// arms), where no whole-message form is possible. In the POSITIVE direction (the two pre-flight
/// slots) the whole message is pinned by [`PREFLIGHT_D1_MESSAGE`], so this set is a diagnostic
                                                                                             
/// mutations deleted with the suite green (M-P4b the consequence, M-P3b two of the four remedies).
const PREFLIGHT_ONLY_CLAUSES: [&str; 6] = [
    "aborting BEFORE any action",
    "scribble a LIVE filesystem",
    "to shrink the doomed root",
    "re-provision the target without",
    "race its writeback until the installer's digest fails closed",
    "Use a larger disk, a smaller image, or ",
];

/// FREEZE (writing-floors Principle 2, form 1) of the pre-flight D-1 refusal for the fixture's
/// geometry: a HAND literal, so it is an oracle INDEPENDENT of the renderer under test. Every
/// mechanical input is pinned elsewhere and re-derivable from the fixture — window
/// `stage_raw_window:vda:42941284352` + the 1536-byte image → `[42941284352, 42941285888)`;
/// vda1's `2048 42948607488` (sectors, bytes) → `[1048576, 42949656064)`; both also spelled out at
/// [`REREAD_D1_LINE`].
///
                                                                                             
/// expected value and asserted `err.contains(&that)`, i.e. it compared the production renderer to
/// itself. That floors the SLOT (a call site that truncates or re-words the message fails it) and
/// says nothing about the CONTENT — two thinning mutations against the renderer's own literal
/// shipped 573/0 green. Exact equality against a hand literal closes that: ANY edit to the message,
/// honest or evasive, reds `the_preflight_d1_refusal_is_frozen_verbatim` and forces a conscious
/// re-freeze here. The trade is the freeze's standing cost — an intentional re-word must be typed
/// twice, once in `staging_geometry.rs` and once here.
const PREFLIGHT_D1_MESSAGE: &str = "the staging window [42941284352, 42941285888) on /dev/vda \
     INTERSECTS partition /dev/vda1 at [1048576, 42949656064) — streaming the image there would \
     scribble a LIVE filesystem (and, if it is the mounted root, race its writeback until the \
     installer's digest fails closed and the box reboots into the old OS). This is what a \
     cloud-init `growpart` looks like: the partition was grown to fill the disk, so there is no \
     free tail. Use a larger disk, a smaller image, or re-provision the target without growing the \
     root partition to the end of the disk (D-1) — or, on a default-provisioned VPS, run \
     `orchard reclaim-tail` (or `orchard prod --reclaim-tail`) to shrink the doomed root so the \
     tail becomes free (D-2); aborting BEFORE any action";

#[test]
fn the_preflight_d1_refusal_is_frozen_verbatim() {
                                                                                      
                                                                                 
                                                                                               
                                                                                                    
                                                                                                 
                                               
    let window = crate::deploy::prod::RawWindowSpec {
        disk: "vda".into(),
        offset: 42_941_284_352,
        len: 1536,
    };
    let grown = vec![crate::deploy::prod::PartitionExtent {
        name: "vda1".into(),
        start: 1_048_576,
        end: 42_949_656_064,
    }];
    let rendered =
        crate::deploy::staging_geometry::refuse_if_window_intersects_partition(&window, &grown)
            .expect_err("the fixture's window intersects vda1, so the pre-flight renderer refuses");
    assert_eq!(
        rendered, PREFLIGHT_D1_MESSAGE,
        "the pre-flight D-1 refusal changed; re-read it as an operator would, then re-freeze the \
         literal deliberately"
    );
                                                                                                 
                                                                                          
                                                           
    for clause in PREFLIGHT_ONLY_CLAUSES {
        assert!(
            PREFLIGHT_D1_MESSAGE.contains(clause),
            "the pre-flight-only clause {clause:?} is not in the frozen message"
        );
    }
}

/// Drive the flagged will-run path to a post-reboot D-1 REFUSAL and return `deploy_prod`'s operator
/// text. The post-reboot extent re-read is served grown by a second one-shot for the same needle
/// (the fixture's own one-shot answers the pre-reboot read first); `crumb` overrides the breadcrumb
/// the fixture would otherwise serve, which is what selects the classification arm.
fn arbitrate_refusal_text(crumb: Option<&str>) -> String {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    ops.remote_once.push_back((
        "lsblk -nbro NAME,TYPE,START,SIZE",
        REREAD_GROWN_EXTENTS.to_string(),
    ));
    if let Some(c) = crumb {
        ops.remote_once
            .push_back(("grep -F 'orchard-reclaim:'", c.to_string()));
    }
    deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("a post-reboot D-1 refusal must abort the ceremony")
}

#[test]
fn arbitrate_arms_render_the_reread_geometry_the_crumb_and_no_preflight_clause() {
                                                                             
                                                                                                   
                                                                                                   
                                                                                                
                                                                                                 
                                                                                                 
                                                                                                    
      
                                                                                                   
                                                                                                    
                                                                                                  
                                                                                                    
                                                                                                   
                                                                  
      
                                                                                                 
                                                                                                   
                                                           
    let arms: [(&str, Option<&str>, Option<&str>); 4] = [
                                                                                                        
        (
            "(R-REGROWN)",
            None,
            Some("step10 done part=[1048576,42940235776) sectors=83865600"),
        ),
        (
            "(R-STALE-KERNEL)",
            Some(
                "<3>orchard-reclaim: step9 kernel view STALE, a second reboot re-reads the table\n\
                 <3>orchard-reclaim: step10 done part=[1048576,42940235776) sectors=83865600\n\
                 CRUMB-DONE\n",
            ),
            Some("step9 kernel view STALE, a second reboot re-reads the table"),
        ),
                                                                                                 
        ("(R-NO-CRUMB)", Some("CRUMB-DONE\n"), None),
                                                        
        (
            "(R-INTERSECTS)",
            Some(
                "<3>orchard-reclaim: step4 SKIP resize2fs rc=1, only rc 0 is success\nCRUMB-DONE\n",
            ),
            Some("step4 SKIP resize2fs rc=1, only rc 0 is success"),
        ),
    ];
    for (row, crumb, expected_crumb) in arms {
        let e = arbitrate_refusal_text(crumb);
        assert!(e.contains(row), "arm sanity — this drives {row}: {e}");
        assert!(
            e.contains(REREAD_D1_LINE),
            "{row} must disclose the re-read intersection geometry: {e}"
        );
        match expected_crumb {
            Some(line) => assert!(
                e.contains("breadcrumb:\n") && e.contains(line),
                "{row} must disclose the breadcrumb evidence {line:?}: {e}"
            ),
            None => assert!(
                !e.contains("breadcrumb:\n"),
                "{row} is the empty-breadcrumb arm and must render no breadcrumb block: {e}"
            ),
        }
        assert!(
            !e.contains(PREFLIGHT_D1_MESSAGE),
            "{row} must not embed the pre-flight rendered refusal: {e}"
        );
        for clause in PREFLIGHT_ONLY_CLAUSES {
            assert!(
                !e.contains(clause),
                "{row} must not carry the pre-flight-only clause {clause:?}: {e}"
            );
        }
    }
}

#[test]
fn the_flagged_preflight_d1_say_carries_the_whole_rendered_refusal() {
                                                                                                
                                                                                                   
                                                                                                 
                                                                                      
                                                                                     
                                                                                               
                                  
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect("the will-run fixture succeeds");
    let said = ops
        .said
        .iter()
        .find(|m| m.starts_with("D-1 refused (RECORDED, --reclaim-tail): "))
        .unwrap_or_else(|| {
            panic!(
                "arm sanity — the flagged pre-flight slot must say the recorded D-1 refusal: {:?}",
                ops.said
            )
        });
    assert!(
        said.contains(PREFLIGHT_D1_MESSAGE),
        "the flagged pre-flight slot must say the WHOLE rendered refusal: {said}"
    );
    for clause in PREFLIGHT_ONLY_CLAUSES {
        assert!(
            said.contains(clause),
            "the pre-flight disclosure must keep {clause:?}: {said}"
        );
    }
}

                                                                                                    
                                                                                                     
                                                                                                      
                                                                                                      
                                                                                                      
                                                                                                
                                                                                                
                                                                                              

/// Drive the flagged will-run path to the post-reboot `R-STALE-KERNEL` arm (crumb = kernel-view
/// STALE + `step10 done`) with the disarm's `rm` answering `rm_rc`, and return `deploy_prod`'s
/// composed operator text. `rm_rc = "RC:1"` is the failing-disarm branch of `disarm_reachable`.
fn stale_kernel_refusal_with_disarm_rc(rm_rc: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    let mut injected = false;
    for (needle, resp) in &mut ops.remote {
        if needle.contains("rm -f /etc/initramfs-tools/hooks/orchard-reclaim") {
            *resp = rm_rc.to_string();
            injected = true;
        }
    }
    assert!(injected, "the disarm rm reply must exist to be driven");
    ops.remote_once.push_back((
        "lsblk -nbro NAME,TYPE,START,SIZE",
        REREAD_GROWN_EXTENTS.to_string(),
    ));
    ops.remote_once.push_back((
        "grep -F 'orchard-reclaim:'",
        "<3>orchard-reclaim: step9 kernel view STALE, a second reboot re-reads the table\n\
         <3>orchard-reclaim: step10 done part=[1048576,42940235776) sectors=83865600\n\
         CRUMB-DONE\n"
            .to_string(),
    ));
    deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("a post-reboot D-1 refusal must abort the ceremony")
}

#[test]
fn the_stale_kernel_arm_leaves_the_hook_state_to_the_disarm_outcome() {
                                                                                               
                                                                                                   
                                                                                                   
                                                                                                   
                                                                                                
                                                                                                 
                                                                                                 
                                                                                                  
                                                                                 
      
                                                                                                     
                                                                                                  
                                                                                                  
                                                                                               
              
    for (rm_rc, decided, contradiction) in [
                                                                                       
        (
            "RC:0",
            "(disarmed: the hook and premount script are removed and the initrd rebuilt",
            "may still be armed",
        ),
                                                                                     
        (
            "RC:1",
            "the target may still be armed; row R-ARMED, manual removal per orchard_guide.md §9.1",
            "(disarmed:",
        ),
    ] {
        let e = stale_kernel_refusal_with_disarm_rc(rm_rc);
                                                                                              
                                                                                      
        assert!(
            e.contains("reclaim refuses (R-STALE-KERNEL):")
                && e.contains("REBOOT the target once more and re-run"),
            "arm sanity ({rm_rc}) — this drives the R-STALE-KERNEL arm: {e}"
        );
        assert!(
            e.contains("disarm"),
            "arm sanity ({rm_rc}) — the disarm outcome is rendered into this message: {e}"
        );
                                                                  
        assert!(
            e.contains(decided),
            "the {rm_rc} disarm must state {decided:?}: {e}"
        );
                                                                              
        assert!(
            !e.contains(contradiction),
            "the {rm_rc} disarm outcome is contradicted by {contradiction:?}: {e}"
        );
                                                                                               
                                                                                              
        assert!(
            !e.contains("the premount script is disarmed"),
            "the arm must not state the hook state it does not decide: {e}"
        );
    }
}

#[test]
fn armed_abort_renders_the_failures_own_row_once_and_never_r_initramfs() {
                                                                                         
                                                                                                       
                                                                                                          
                                                                                               
                                                                                
                                                                                   
                                                                                                      
                                                                         
      
                                                                                                 
                                                                                                     
                                                                                                   
                                                                                      
      
                                                                                 
                                                                                                
                                                  
                                                                                               
                                                        
    let stale = "<3>orchard-reclaim: step9 kernel view STALE, a second reboot re-reads the table\n\
                 <3>orchard-reclaim: step10 done part=[1048576,42940235776) sectors=83865600\n\
                 CRUMB-DONE\n";
    let mut arms: Vec<(&str, &str, bool)> = Vec::new();
    let texts: Vec<String> = [
        None,
        Some(stale),
        Some("CRUMB-DONE\n"),
        Some("<3>orchard-reclaim: step4 SKIP resize2fs rc=1, only rc 0 is success\nCRUMB-DONE\n"),
    ]
    .into_iter()
    .map(arbitrate_refusal_text)
    .collect();
                                                                                               
                                                                                              
                                                                               
    for (i, row) in [
        crate::deploy::reclaim::rows::REGROWN,
        crate::deploy::reclaim::rows::STALE_KERNEL,
        crate::deploy::reclaim::rows::NO_CRUMB,
        crate::deploy::reclaim::rows::INTERSECTS,
    ]
    .into_iter()
    .enumerate()
    {
        arms.push((row, &texts[i], false));
    }

                                                                                                   
                                                                                                    
                                                                                   
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    let now = ops.now_epoch();
    ops.remote_once.push_back(("date +%s", format!("{now}\n")));
    ops.remote_once
        .push_back(("date +%s", format!("{}\n", now + 9999)));
    let skew = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("a post-reclaim clock 9999s off must refuse");
    assert!(
        skew.contains("target clock is 9999s off after the reclaim reboot"),
        "arm sanity — this drives the §5.10 clock-skew re-take: {skew}"
    );
    arms.push((crate::deploy::reclaim::rows::POST_FIT, &skew, true));

                                                                                                
                                                                
    let dir = tempfile::tempdir().unwrap();
    let mut ops = FakeOps::happy_reclaim_will_run(dir.path());
    with_disarm_replies(&mut ops);
    let mut injected = false;
    for (needle, resp) in &mut ops.remote_once {
        if needle.contains("/proc/sys/kernel/random/boot_id") {
            *resp = "\n".to_string();
            injected = true;
        }
    }
    assert!(
        injected,
        "the PRE-reboot boot-id reply must exist to be emptied"
    );
    let lost = deploy_prod(&mut ops, FakeOps::opts_reclaim(dir.path()))
        .expect_err("an empty pre-reboot boot id must refuse");
    assert!(
        lost.contains("the target's boot id read back empty"),
        "arm sanity — this drives the pre-reboot boot-id arm: {lost}"
    );
    arms.push((crate::deploy::reclaim::rows::LOST_PRE_REBOOT, &lost, false));

    for (row, e, completed) in arms {
        assert!(
            e.starts_with(&format!("reclaim refuses ({row}): ")),
            "the composed message must OPEN with its own §7 row {row}: {e}"
        );
        assert_eq!(
            e.matches("reclaim refuses (").count(),
            1,
            "the row prefix is added exactly once, at the render: {e}"
        );
        assert!(
            !e.contains(crate::deploy::reclaim::rows::INITRAMFS),
            "a post-install armed failure must not be classified as a pre-reboot initramfs \
             failure: {e}"
        );
        assert_eq!(
            e.contains("RECLAIM HAS RUN"),
            completed,
            "the row {row} and the completed-reclaim clause must agree: {e}"
        );
    }
}

#[test]
fn no_from_impl_opens_a_note_free_channel_into_reclaim_abort() {
                                                                                            
                                                                                          
                                                                                                     
                                                                                                    
                                                                                                     
                                                                                                     
                                                                                               
                                                              
      
                                                                                             
                                                                                                 
                                                                                                     
                                                                                                   
                                                                                                
            
      
                                                                                                      
                                                                                              
                                                                                                   
                                                                                                  
                                                                                                    
                                                                                                    
                                                                                           
                                                                                            
                                                                                                    
                                                                                             
                                                         
    use crate::deploy::prod_orchestrate::ReclaimAbort;
    use std::marker::PhantomData;

    struct Probe<T>(PhantomData<T>);
    trait NoImpl {
        fn has_impl(&self) -> bool {
            false
        }
    }
    impl<T> NoImpl for &Probe<T> {}
    impl<T: Into<ReclaimAbort>> Probe<T> {
        fn has_impl(&self) -> bool {
            true
        }
    }

                                                                                                
                                                                                                      
                                                                                                
                                                                                                  
                                                                                                    
                                                                                              
                                                                                
    assert!(
        Probe::<ReclaimAbort>(PhantomData).has_impl(),
        "self-test — the probe must report TRUE when the impl exists, or the guard is vacuous"
    );

    assert!(
        !(&Probe::<String>(PhantomData)).has_impl(),
        "no `impl From<String> for ReclaimAbort` may exist: it would make every `?` on a \
         String-error channel in the reclaim region a silent note-free refusal, dropping \
         RECLAIM_STANDING_NOTE, and would retire the E0277 the census deletion rests on"
    );
}
