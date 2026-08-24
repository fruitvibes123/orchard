use super::*;
use crate::deploy::build_image::Firmware;
use crate::deploy::prod_orchestrate::LayoutInfo;

                                                                                        
fn dha_layout() -> LayoutInfo {
    LayoutInfo {
        boot_offset: 0,
        boot_size: 209_715_200,
        persist_skeleton_offset: 209_715_200,
        persist_skeleton_size: 33_554_432,
        rootfs_offset: 243_269_632,
        rootfs_size: 318_767_104,
        rootfs_verity_hash_offset: 268_435_456,
        firmware: Firmware::SeabiosGpt,
        weights_offset: Some(562_036_736),
        weights_size: Some(1_714_917_376),
    }
}

fn dha_window() -> RawWindowSpec {
    RawWindowSpec {
        disk: "nvme0n1".to_string(),
        offset: 24_461_180_928,
        len: 2_276_954_112,
    }
}

#[test]
fn v2_cmdline_composes_the_worst_case_exactly_and_under_budget() {
                                                                                              
                                                                                                
                                                                                                   
                    
    let root = "ab".repeat(32);
    let sha = "cd".repeat(32);
    let c = build_installer_cmdline(
        &root,
        268_435_456,
        &dha_window(),
        &sha,
        &dha_layout(),
        Some(("nvme0n1p2", "/a/restore.persist.img")),
        Some(42),
    )
    .expect("worst case composes");
    let expected = format!(
        "fb.mode=installer fb.firmware=seabios-gpt fb.root-hash={root} \
         fb.verity-hash-offset=268435456 \
         fb.image-raw=nvme0n1:24461180928:2276954112 fb.image-sha256={sha} \
         fb.image-layout=fw:seabios-gpt,boot:0:209715200,skel:209715200:33554432,\
         rootfs:243269632:318767104,weights:562036736:1714917376 \
         fb.restore-from=disk:nvme0n1p2:/a/restore.persist.img fb.min-ctr=42 {DEFENSE_TRIPLE} \
         console=tty0 console=ttyS0"
    );
    assert_eq!(c, expected);
    assert!(
        c.len() < 1800,
        "worst-case append must stay under the 1800-char budget: {} chars",
        c.len()
    );
                                                                                                     
    let sha_idx = c.find("fb.image-sha256=").expect("sha token");
    let triple_idx = c.find("lockdown=integrity").expect("defense triple");
    assert!(
        sha_idx < triple_idx,
        "fb.image-sha256 must come before the defense triple"
    );
                                                                                            
                                                                                                  
                                                                                                   
                                                                      
    let tty0_idx = c.find("console=tty0").expect("tty0 token");
    let ttys0_idx = c.find("console=ttyS0").expect("ttyS0 token");
    assert!(
        triple_idx < tty0_idx,
        "the consoles must come AFTER the defense triple (defense-in-depth ordering)"
    );
                                                                                   
    assert!(
        tty0_idx < ttys0_idx,
        "console=ttyS0 must be last so it wins /dev/console"
    );
                                                                    
    let mut plain = dha_layout();
    plain.firmware = Firmware::Seabios;
    plain.weights_offset = None;
    plain.weights_size = None;
    let plain_c = build_installer_cmdline(
        &root,
        4096,
        &RawWindowSpec {
            disk: "vda".to_string(),
            offset: 8_388_608,
            len: 512,
        },
        &sha,
        &plain,
        None,
        None,
    )
    .expect("plain seabios composes");
    assert!(plain_c.contains("fb.firmware=seabios "));
    assert!(plain_c.contains("fb.image-layout=fw:seabios,"));
    assert!(!plain_c.contains("weights:"));
}

                                                                                    
///
/// The audit found no length check anywhere in `build_installer_cmdline`, while its docstring
/// promised "a composition bug refuses HERE". The amplifier is the `--restore-from` stage path: it
/// is operator-supplied, validated only for whitespace, and sits immediately ahead of the tail
/// tokens — so it, not a composer bug, is what realistically pushes the string over.
#[test]
fn v2_cmdline_refuses_an_over_budget_append() {
    let root = "ab".repeat(32);
    let sha = "cd".repeat(32);

                                                                                              
                                                                                                    
                                                                                               
    let long_path = format!("/{}", "d".repeat(1900));
    let err = build_installer_cmdline(
        &root,
        268_435_456,
        &dha_window(),
        &sha,
        &dha_layout(),
        Some(("nvme0n1p2", &long_path)),
        Some(42),
    )
    .expect_err("an over-budget append must refuse, not compose");
                                                                                                   
                                                                                                
                                                                                     
    assert!(
        matches!(
            err,
            CmdlineError::Length {
                restore_requested: true,
                ..
            }
        ),
        "an over-budget restore append must be the Length variant with a restore request: {err:?}"
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("COMMAND_LINE_SIZE"),
        "the refusal must name the budget it broke: {rendered}"
    );
    assert!(
        rendered.contains("--restore-from"),
        "with a restore path supplied, the refusal must point at the unbounded input: {rendered}"
    );

                                                                                                 
                                                                                                      
                                                                                                       
                                                                                                       
                                                                                                  
    let compose_len = |pad: usize| -> Result<usize, CmdlineError> {
        let p = format!("/{}", "d".repeat(pad));
        build_installer_cmdline(
            &root,
            268_435_456,
            &dha_window(),
            &sha,
            &dha_layout(),
            Some(("nvme0n1p2", &p)),
            Some(42),
        )
        .map(|c| c.len())
    };
    let mut largest_ok = None;
    for pad in 1..2000 {
        match compose_len(pad) {
            Ok(len) => largest_ok = Some((pad, len)),
            Err(_) => break,
        }
    }
    let (pad, len) = largest_ok.expect("some stage-path length must compose");
    assert_eq!(
        len,
        COMMAND_LINE_SIZE - 2,
        "the largest accepted append must be exactly COMMAND_LINE_SIZE-2 bytes (kexec-tools accepts \
         strlen + 1 <= the kernel's cmdline_size of COMMAND_LINE_SIZE-1), got {len}"
    );
    assert!(
        compose_len(pad + 1).is_err(),
        "one byte past the budget must refuse"
    );
}

                                                                                                   
/// `build_installer_cmdline` is `>= COMMAND_LINE_SIZE - 1`, so the whole guard rides on this value.
/// The image-builder twin has its own freeze (`the_guard_ceilings_are_frozen_to_their_consumers_limits`);
/// this is the kexec side of that cross-crate duplication. The literal 2048 is `arch/x86/include/asm/setup.h`
/// `#define COMMAND_LINE_SIZE 2048`; a re-pin to a kernel with a different value re-derives it here.
/// Claim (the constant), not coverage: a mutation of `COMMAND_LINE_SIZE` reds this alone.
#[test]
fn command_line_size_is_the_x86_64_kernel_constant() {
    assert_eq!(
        COMMAND_LINE_SIZE, 2048,
        "x86-64 COMMAND_LINE_SIZE is 2048 (arch/x86/include/asm/setup.h); the kexec cmdline guard \
         boundary is derived from it"
    );
}

                                                                                 
///
/// `lsblk -b` prints SIZE in bytes but START in 512-byte sectors. The rows below are REAL observed
/// output. If START were read as bytes, every partition would appear to start 512× lower, the
/// extents would collapse toward zero, and the intersection check would pass precisely when it
/// ought to fail — a guard strictly worse than no guard, because it reads as coverage.
#[test]
fn lsblk_partition_extents_convert_start_from_sectors_and_size_from_bytes() {
    let out = "nvme0n1 disk  2000398934016\n\
               nvme0n1p1 part 4096 2147483648\n\
               nvme0n1p2 part 4198400 1998249164800\n";
    let parts = parse_lsblk_partition_extents(out, "nvme0n1").expect("parses");
    assert_eq!(
        parts.len(),
        2,
        "the `disk` row must not be counted as a partition"
    );

                                                   
    assert_eq!(parts[0].name, "nvme0n1p1");
    assert_eq!(parts[0].start, 2_097_152);
    assert_eq!(parts[0].end, 2_097_152 + 2_147_483_648);

    assert_eq!(parts[1].start, 4_198_400 * 512);
    assert_eq!(parts[1].end, 4_198_400 * 512 + 1_998_249_164_800);

                                                                                                
    assert!(parse_lsblk_partition_extents("vda disk  3221225472\n", "vda").is_err());
                                                                              
    assert!(parse_lsblk_partition_extents("vda1 part XXX 512\n", "vda").is_err());
}

#[test]
fn v2_cmdline_refuses_malformed_inputs() {
    let root = "ab".repeat(32);
    let sha = "cd".repeat(32);
    let ok_window = || RawWindowSpec {
        disk: "vda".to_string(),
        offset: 8_388_608,
        len: 512,
    };
                     
    assert!(
        build_installer_cmdline("zz", 4096, &ok_window(), &sha, &dha_layout(), None, None).is_err()
    );
                     
    assert!(
        build_installer_cmdline(&root, 4096, &ok_window(), "beef", &dha_layout(), None, None)
            .is_err()
    );
                                      
    let part = RawWindowSpec {
        disk: "vda1".to_string(),
        ..ok_window()
    };
    assert!(build_installer_cmdline(&root, 4096, &part, &sha, &dha_layout(), None, None).is_err());
                                       
    let unaligned = RawWindowSpec {
        offset: 512,
        ..ok_window()
    };
    assert!(
        build_installer_cmdline(&root, 4096, &unaligned, &sha, &dha_layout(), None, None).is_err()
    );
                          
    let zero = RawWindowSpec {
        len: 0,
        ..ok_window()
    };
    assert!(build_installer_cmdline(&root, 4096, &zero, &sha, &dha_layout(), None, None).is_err());
                                                                      
    assert!(
        build_installer_cmdline(
            &root,
            4096,
            &ok_window(),
            &sha,
            &dha_layout(),
            Some(("vda1", "/a/has space.img")),
            None,
        )
        .is_err()
    );
                                              
    assert!(
        build_installer_cmdline(
            &root,
            4096,
            &ok_window(),
            &sha,
            &dha_layout(),
            None,
            Some(1)
        )
        .is_err()
    );
                                                      
    let mut uefi = dha_layout();
    uefi.firmware = Firmware::Uefi;
    assert!(build_installer_cmdline(&root, 4096, &ok_window(), &sha, &uefi, None, None).is_err());
}

#[test]
fn whole_disk_name_twin_matches_the_box_grammar() {
                                                                                                 
                                                                                 
                                                                                               
    for ok in [
        "sda", "vdb", "nvme0n1", "nvme10n2", "mmcblk0", "xvda", "hda",
    ] {
        assert!(is_whole_disk_name(ok), "{ok:?} is a whole disk");
    }
    for bad in [
        "sda1",                              
        "vda2",        
        "nvme0n1p1",                  
        "mmcblk0p2",                    
        "loop0",                                                                   
        "loop0p1",     
        "nvme0",                                     
        "nvme",                          
        "sd",          
        "foo",                       
        "x",           
        "SDA",                   
        "",            
        "/dev/vda",          
    ] {
        assert!(!is_whole_disk_name(bad), "{bad:?} is not a whole disk");
    }
}

#[test]
fn partition_device_name_matches_the_installer_convention() {
                                                                                             
                                                                                        
                                                                               
    assert_eq!(partition_device_name("vda", 2), "/dev/vda2");
    assert_eq!(partition_device_name("sda", 1), "/dev/sda1");
    assert_eq!(partition_device_name("xvdf", 2), "/dev/xvdf2");
    assert_eq!(partition_device_name("nvme0n1", 2), "/dev/nvme0n1p2");
    assert_eq!(partition_device_name("nvme0n1", 1), "/dev/nvme0n1p1");
    assert_eq!(partition_device_name("mmcblk0", 2), "/dev/mmcblk0p2");
    assert_eq!(partition_device_name("loop0", 2), "/dev/loop0p2");
}

#[test]
fn kexec_refused_classifies_outcomes() {
                                                                                                 
                                                                                                      
                                                                                               
                                                                                                     
      
                                                                                                  
                                                                                              
    assert!(kexec_refused(
        false,
        "kexec failed: Operation not permitted"
    ));
                                                                                       
    assert!(kexec_refused(false, "kexec: Operation not permitted"));
    assert!(kexec_refused(false, "KEXEC failed"));
                                                                                                    
                                                                     
    assert!(!kexec_refused(false, "Connection closed"));
    assert!(!kexec_refused(
        false,
        "ssh: connect to host 10.0.0.1 port 22: Connection refused"
    ));
                                                                                                  
    assert!(!kexec_refused(
        false,
        "kex_exchange_identification: read: Connection reset by peer"
    ));
                                                                                    
    assert!(!kexec_refused(true, ""));
                                                                                                      
    assert!(!kexec_refused(false, "some other error"));
}

#[test]
fn artifact_filename_guard_whitelists_one_clean_segment() {
                                                         
    assert_eq!(
        validate_artifact_filename("recipes-image-3f13470.img").unwrap(),
        "recipes-image-3f13470.img"
    );
    assert_eq!(
        validate_artifact_filename("recipes-image-abc.layout.toml").unwrap(),
        "recipes-image-abc.layout.toml"
    );
                                                                                           
    for bad in [
        "a b.img", "a\tb", "a/b.img", "..", ".", "-rf", "a;b.img", "ä.img", "", "a\nb",
    ] {
        assert!(
            validate_artifact_filename(bad).is_err(),
            "{bad:?} must fail closed"
        );
    }
}

#[test]
fn findmnt_strips_dev_prefix() {
                                                                   
    assert_eq!(parse_findmnt_source("/dev/vda1\n").as_deref(), Some("vda1"));
    assert_eq!(
        parse_findmnt_source("/dev/nvme0n1p1").as_deref(),
        Some("nvme0n1p1")
    );
}

#[test]
fn findmnt_rejects_non_plain_partition_sources() {
                                                                                               
                                                                                         
    for bad in [
        "/dev/mapper/vg-root\n",
        "/dev/disk/by-uuid/1234\n",           
        "UUID=1234\n",
        "tmpfs\n",
        "/dev/\n",
        "",
    ] {
        assert_eq!(parse_findmnt_source(bad), None, "{bad:?} must fail closed");
    }
}

#[test]
fn proc_mounts_fallback_finds_the_root_device() {
    let mounts = "sysfs /sys sysfs rw 0 0\n\
                      /dev/sda1 / ext4 rw,relatime 0 0\n\
                      /dev/sda2 /home ext4 rw 0 0\n";
    assert_eq!(parse_proc_mounts_root(mounts).as_deref(), Some("sda1"));
                            
    assert_eq!(parse_proc_mounts_root("tmpfs /run tmpfs rw 0 0\n"), None);
                                                                  
    assert_eq!(
        parse_proc_mounts_root("/dev/mapper/root / ext4 rw 0 0\n"),
        None
    );
}

#[test]
fn wipe_confirmed_only_constructs_from_the_flag() {
                                                                                               
    assert!(WipeConfirmed::from_flag(false).is_none());
    assert!(WipeConfirmed::from_flag(true).is_some());
                                                                                          
                                                                                       
}

#[test]
fn wipe_gate_tty_requires_retype_and_names_whole_disk() {
                                                                                            
    assert!(wipe_gate(false, None, "vda", "203.0.113.5").is_ok());
                                                                              
    assert!(wipe_gate(true, Some("203.0.113.5"), "vda", "203.0.113.5").is_ok());
    assert!(wipe_gate(true, Some("/dev/vda"), "vda", "203.0.113.5").is_ok());
    assert!(wipe_gate(true, Some("vda\n"), "vda", "203.0.113.5").is_ok());
                                           
    assert!(wipe_gate(true, Some("203.0.113.6"), "vda", "203.0.113.5").is_err());
    assert!(wipe_gate(true, Some(""), "vda", "203.0.113.5").is_err());
    assert!(wipe_gate(true, None, "vda", "203.0.113.5").is_err());
                                                                                       
    let echo = whole_disk_echo("vda", "203.0.113.5");
    assert!(echo.contains("ALL partitions on /dev/vda"), "{echo}");
    assert!(echo.contains("not just /"), "{echo}");
    assert!(echo.contains("203.0.113.5"), "{echo}");
    assert!(echo.contains("ERASED"), "{echo}");
}

#[test]
fn host_key_decision_pin_confirm_fail_closed() {
    use HostKeyDecision::*;
    let fp = "SHA256:uNixzcyDR8RmCSWXjMW5BC2hJsHIQGTId2ZsXLALww0";
                                                                               
    assert_eq!(host_key_decision(Some(fp), true, fp), Accept);
    assert_eq!(host_key_decision(Some(fp), false, fp), Accept);
                                                                                           
                                                                                
    assert_eq!(host_key_decision(Some(fp), true, "SHA256:evil"), Abort);
    assert_eq!(host_key_decision(Some(fp), false, "SHA256:evil"), Abort);
                                                                                          
    assert_eq!(
        host_key_decision(None, true, fp),
        ConfirmInteractively(fp.to_string())
    );
                                                                 
    assert_eq!(host_key_decision(None, false, fp), FailClosed);
}

#[test]
fn stage_dir_guard_whitelists_clean_absolute_paths() {
                                                    
    assert_eq!(validate_stage_dir("/root").unwrap(), "/root");
    assert_eq!(
        validate_stage_dir("/var/tmp/recipes-stage_1.d").unwrap(),
        "/var/tmp/recipes-stage_1.d"
    );
                                                                                        
                                                               
    for bad in ["/root/a b", "/root/a\tb", "/root/a\nb", " /root", "/root "] {
        assert!(validate_stage_dir(bad).is_err(), "{bad:?} must fail closed");
    }
                                                                                          
    for bad in [
        "/root/a\0b",
        "/root/../etc",
        "root/stage",
        "",
        "/",
        "/root/",
        "/root;rm",
        "/root$(x)",
        "/r\u{f6}ot",
    ] {
        assert!(validate_stage_dir(bad).is_err(), "{bad:?} must fail closed");
    }
                                                                                           
                                                                                   
    for bad in ["/a/-rf", "/-x", "/var/tmp/-recipes"] {
        assert!(validate_stage_dir(bad).is_err(), "{bad:?} must fail closed");
    }
                                                                         
    assert!(validate_stage_dir("/var/tmp/recipes-deploy").is_ok());
}

#[test]
fn identity_comparisons_match_only_full_equal_hashes() {
    let h = "a".repeat(64);
    let other = format!("{}b", "a".repeat(63));
                                                                                          
                                                                                 
    assert!(verity_identity_ok(&h, &h));
    assert!(verity_identity_ok(&format!(" {h}\n"), &h.to_uppercase()));
    assert!(boot_fs_identity_ok(&h, &h));
    assert!(boot_fs_identity_ok(&format!("{h}\n"), &h));
                                            
    assert!(!verity_identity_ok(&h, &other));
    assert!(!boot_fs_identity_ok(&h, &other));
                                                                                           
                                                                                                
    assert!(!verity_identity_ok("", ""));
    assert!(!boot_fs_identity_ok("", ""));
    assert!(!verity_identity_ok("zz", "zz"));
    let short = "a".repeat(32);
    assert!(!verity_identity_ok(&short, &short));
    assert!(!boot_fs_identity_ok(&short, &short));
}

#[test]
fn stage_on_root_partition_check() {
    assert!(check_same_partition("sda1", "sda1").is_ok());
    let err = check_same_partition("sda1", "sdb1").unwrap_err();
    assert!(err.contains("stage-on-root-partition") && err.contains("sdb1"));
                                                                                            
                                                                                             
                                            
    assert!(err.contains("whole disk"), "{err}");
}

#[test]
fn lsblk_parent_walk_whitelists_part_on_disk_only() {
                                                                                    
    let out = "vda disk  \nvda1 part / vda\nvda2 part  vda\n";
    assert_eq!(parse_lsblk_parent_walk(out, "vda1").unwrap(), "vda");
                                                               
    let nvme = "nvme0n1 disk  \nnvme0n1p1 part / nvme0n1\n";
    assert_eq!(
        parse_lsblk_parent_walk(nvme, "nvme0n1p1").unwrap(),
        "nvme0n1"
    );
                                                                                           
                                                            
    let luks = "vda disk  \nvda1 part  vda\ndm-0 crypt / vda1\n";
    let e = parse_lsblk_parent_walk(luks, "dm-0").unwrap_err();
    assert!(e.contains("crypt"), "{e}");
                                                          
    let lvm = "vda disk  \nvda1 part  vda\nvg-root lvm / vda1\n";
    assert!(parse_lsblk_parent_walk(lvm, "vg-root").is_err());
                                                                
    let raid = "md0 raid0  \nmd0p1 part / md0\n";
    assert!(parse_lsblk_parent_walk(raid, "md0p1").is_err());
                                                                                            
    let wholedisk = "vda disk / \n";
    let e = parse_lsblk_parent_walk(wholedisk, "vda").unwrap_err();
    assert!(e.contains("whole-disk") || e.contains("partition"), "{e}");
                                                        
    assert!(parse_lsblk_parent_walk(out, "sdb1").is_err());
                                                                                                       
                                                                                                  
                                                                                                         
    let inj = "vda$(id) disk  \nvda1 part / vda$(id)\n";
    let e = parse_lsblk_parent_walk(inj, "vda1").unwrap_err();
    assert!(e.contains("root-run shell command"), "{e}");
}

#[test]
fn sha256sum_output_parses_hex_path_pairs() {
    let out = "ab".repeat(32) + "  /var/tmp/recipes-deploy/r.img\n";                 
    let pairs = parse_sha256sum_output(&out);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "ab".repeat(32));
    assert_eq!(pairs[0].1, "/var/tmp/recipes-deploy/r.img");
                                                                                         
    let multi = format!(
        "{}  /a\nnot a sha line\n{}  /b\n",
        "0".repeat(64),
        "f".repeat(64)
    );
    let pairs = parse_sha256sum_output(&multi);
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[1].1, "/b");
                                                     
    assert!(parse_sha256sum_output("zz  /a\n").is_empty());
}

#[test]
fn df_source_fallback_and_target_host_guard() {
    let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                  /dev/vda1 41152812 1336764 38087492 4% /\n";
    assert_eq!(parse_df_source(df).as_deref(), Some("vda1"));
    assert_eq!(parse_df_source("/dev/mapper/x / \n"), None);
    assert_eq!(parse_df_source(""), None);

    assert_eq!(validate_target_host("203.0.113.5").unwrap(), "203.0.113.5");
    assert_eq!(
        validate_target_host(" 2001:db8::1 ").unwrap(),
        "2001:db8::1"
    );
    assert_eq!(
        validate_target_host("box.example.ch").unwrap(),
        "box.example.ch"
    );
    for bad in [
        "-oProxyCommand=x",
        "",
        "Box Example",
        "a;b",
        ".lead",
        "Höst",
    ] {
        assert!(validate_target_host(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn df_avail_parses_posix_kib_output() {
    let out = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                   /dev/vda1 41152812 1336764 38087492 4% /\n";
    assert_eq!(parse_df_avail_kib(out), Some(38_087_492));
    assert_eq!(parse_df_avail_kib(""), None);
    assert_eq!(parse_df_avail_kib("garbage\n"), None);
}

#[test]
fn sysfs_sectors_and_epoch_parse() {
    assert_eq!(parse_u64_line("83886080\n"), Some(83_886_080));
    assert_eq!(parse_u64_line("  \n"), None);
    assert_eq!(parse_u64_line("12 extra\n"), None);
}

#[test]
fn cmdline_root_hash_extracts_the_token() {
    let cmdline = "console=ttyS0 fb.root-hash=ABCDEF rootfs-dev=/dev/vda2 ro";
    assert_eq!(
        extract_cmdline_root_hash(cmdline).as_deref(),
        Some("ABCDEF")
    );
    assert_eq!(extract_cmdline_root_hash("console=ttyS0 ro"), None);
                                                  
    assert_eq!(extract_cmdline_root_hash("xroot-hash=AB"), None);
}

#[test]
fn rootfs_verity_ro_check_requires_all_three() {
                                                                                           
                                                                  
    let ok = "devtmpfs /dev devtmpfs rw 0 0\n/dev/dm-0 / squashfs ro,relatime 0 0\n";
    assert!(rootfs_verity_ro_ok(ok));
    assert!(rootfs_verity_ro_ok("/dev/mapper/vroot / squashfs ro 0 0\n"));
                                                                                    
                                                                                                
    assert!(rootfs_verity_ro_ok(
        "/dev/recipes-root / squashfs ro,relatime 0 0\n"
    ));
                                                     
    assert!(!rootfs_verity_ro_ok("/dev/vda2 / squashfs ro 0 0\n"));
                                   
    assert!(!rootfs_verity_ro_ok(
        "/dev/dm-0 / squashfs rw,relatime 0 0\n"
    ));
    assert!(!rootfs_verity_ro_ok("/dev/dm-0 / ext4 ro 0 0\n"));
                                                                         
    assert!(!rootfs_verity_ro_ok("/dev/dm-0 /mnt squashfs ro 0 0\n"));
    assert!(!rootfs_verity_ro_ok(""));
}

#[test]
fn byte_patch_overwrites_sentinel_length_preserving() {
    use recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL;
    let mut buf =
        format!("  APPEND fb.root-hash=ab fb.rootfs-dev={ROOTFS_DEV_SENTINEL} ro lockdown\n")
            .into_bytes();
    let before = buf.len();
    patch_rootfs_dev(&mut buf, "/dev/vda2").unwrap();
    assert_eq!(buf.len(), before, "the patch must be length-preserving");
    let s = String::from_utf8_lossy(&buf);
    assert!(
        s.contains("fb.rootfs-dev=/dev/vda2 "),
        "device + space padding: {s:?}"
    );
    assert!(!s.contains(ROOTFS_DEV_SENTINEL), "sentinel consumed: {s:?}");
                                                                                     
    assert!(
        s.split_whitespace().any(|t| t == "fb.rootfs-dev=/dev/vda2"),
        "must tokenize to the bare device: {s:?}"
    );
}

#[test]
fn byte_patch_rejects_missing_nonunique_and_overlong() {
    use recipes_image_builder::boot_fs::ROOTFS_DEV_SENTINEL;
                                   
    assert!(patch_rootfs_dev(&mut b"no sentinel here".to_vec(), "/dev/vda2").is_err());
                                                                           
    let mut two = format!("{ROOTFS_DEV_SENTINEL} x {ROOTFS_DEV_SENTINEL}").into_bytes();
    assert!(patch_rootfs_dev(&mut two, "/dev/vda2").is_err());
                                                                                          
    let long = format!("/dev/{}", "x".repeat(64));
    let mut buf = format!("fb.rootfs-dev={ROOTFS_DEV_SENTINEL}").into_bytes();
    assert!(patch_rootfs_dev(&mut buf, &long).is_err());
                                                                             
    let mut buf2 = format!("fb.rootfs-dev={ROOTFS_DEV_SENTINEL}").into_bytes();
    assert!(patch_rootfs_dev(&mut buf2, "/dev/mapper/root").is_err());
}

#[test]
fn parse_meminfo_memtotal_reads_kb_as_bytes_or_fails_closed() {
    let m = "MemTotal:        2048000 kB\nMemFree:          100 kB\n";
    assert_eq!(parse_meminfo_memtotal_bytes(m), Some(2_048_000 * 1024));
                                                                
    assert_eq!(parse_meminfo_memtotal_bytes("MemFree: 1 kB\n"), None);
    assert_eq!(parse_meminfo_memtotal_bytes("garbage"), None);
    assert_eq!(
        parse_meminfo_memtotal_bytes("MemTotal: notanumber kB\n"),
        None
    );
}

#[test]
fn ram_floor_is_image_size_independent() {
                                                                                             
                                                                                                 
                                                                
    assert!(refuse_if_ram_below_floor(INSTALL_MIN_RAM_BYTES).is_ok());
    assert!(refuse_if_ram_below_floor(2048 * 1024 * 1024).is_ok());                          
    let err = refuse_if_ram_below_floor(INSTALL_MIN_RAM_BYTES - 1).unwrap_err();
    assert!(err.contains("installer floor"), "{err}");
    assert!(refuse_if_ram_below_floor(0).is_err());
}
