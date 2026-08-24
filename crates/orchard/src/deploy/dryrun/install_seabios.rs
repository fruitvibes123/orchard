                                                                                                                            

use super::assertions::*;
use super::qemu::*;
use super::*;

                                                                               
                                                                                 
                                                                               
  
                                                                                                       
                                                                                                               
                                                                                          
                                                                                                     
                                                                                              
                                                                                                    
                                                                                        
                                                                                          
                                                                                       
  
                                                                                                   
                                                                                                     
                                                                                                  
                                                                                                      
                                                                                                      
                                                               

/// The installer reads the source `.img` from this partition of the single install disk; the
/// installer's `disk_from_partition("vda1")` → `vda` is therefore the repartitioned target. Booted
/// standalone afterwards the disk is the sole virtio disk → `/dev/vda`, so slot A is `/dev/vda2`.
const GATE_SOURCE_PARTITION: &str = "vda1";
/// The slot-A device the byte-patch writes into the boot-fs APPEND (partition 2 of the booted disk).
pub(super) const GATE_ROOTFS_DEV: &str = "/dev/vda2";
/// The source ext4 partition starts at the 1 MiB alignment (LBA 2048), the modern-disk default.
const GATE_SOURCE_FS_START_LBA: u64 = 2048;
/// The install disk size — generous so the installer's persist partition (the remainder after
/// boot+A+B) far exceeds the 16 MiB pre-baked persist-skeleton, making the first-boot resize2fs-grow
/// assertion meaningful. 1.5 GiB ≫ the ~257 MiB layout minimum, and /512 < u32::MAX (MBR-addressable).
const GATE_INSTALL_DISK_BYTES: u64 = 1536 * 1024 * 1024;
/// The negative-boot window for the bootable-last assertion: a healthy box reaches SSH well within it,
/// so no-SSH-within-this ⇒ genuinely not booting (not merely slow).
pub(super) const GATE_NO_BOOT_WINDOW: Duration = Duration::from_secs(90);

/// The restore payload staged onto the source partition (vda1) beside the `.img` for the restore-from
/// gate. `GATE_RESTORE_IMAGE_PATH` is the `fb.restore-from` cmdline path the installer reads it from
/// (on the old-root partition vda1; the on-box `parse_install_sources` mounts ONE old-root for the
/// restore pair, on the same disk the `fb.image-raw` window names). The src-tree BASENAME is derived from
/// this path (`trim_start_matches('/')`) so the cmdline path and the on-disk name cannot drift (audit
/// I-3); the installer reads the detached signature from the sibling `<path>.sig`.
const GATE_RESTORE_IMAGE_PATH: &str = "/restore.persist.img";

                                                                                                     
/// SeabiosGpt (GPT) firmwares — both boot the INSTALLED disk through SeaBIOS. Takes a PRE-built `.img`
/// (its sibling `.layout.toml` + the LOCAL `<stem>.vmlinuz`/`.initramfs` beside it) built with
/// `--operator-pubkey <pubkey>` AND `--net <the QEMU user-net static config>`; `operator_privkey` is the
/// matching private key. `firmware` selects the two SeaBIOS-family deltas: SeaBIOS byte-patches the
/// boot-fs `/dev` sentinel + asserts it on the runtime cmdline; SeabiosGpt skips the patch (it bakes a
/// fixed PARTUUID, like UEFI) + asserts `fb.firmware=seabios-gpt` + that PARTUUID. RAII-tears-down every
/// QEMU child. See the section header for the single-disk model.
pub fn install_disk_and_verify(
    img: &Path,
    operator_privkey: &Path,
    firmware: crate::deploy::build_image::Firmware,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    preflight()?;
    let layout = parse_layout(&layout_sidecar(img))?;
    let vmlinuz = local_artifact(img, "vmlinuz")?;
    let initramfs = local_artifact(img, "initramfs")?;

    let workdir = tempfile::Builder::new()
        .prefix("recipes-prod-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating prod-gate workdir"))?;
    let wd = workdir.path();

                                                                                                        
                                                                                                     
                                                                          
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| wd.to_path_buf());
    if log_dir != wd {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }

                                                                                                         
                                                                                                      
                                                                            
    let rootfs_data = wd.join("rootfs-data");
    slice(
        img,
        layout.rootfs_offset,
        layout.rootfs_verity_hash_offset,
        &rootfs_data,
    )?;
    let root_hash = recompute_verity_root_hash(&rootfs_data, &wd.join("verity.hash"))?;

                                                                                                    
                                                                                                           
                                                                                                              
    let mut image =
        std::fs::read(img).map_err(DryrunError::io(format!("read {}", img.display())))?;
    if firmware == crate::deploy::build_image::Firmware::Seabios {
        patch_boot_fs_rootfs_dev(&mut image, &layout)?;
    }

                                                                                            
                                                                                     
    let disk = wd.join("install-disk.img");
    let layout_info = gate_layout_info(&layout, firmware);
    let window = stage_install_disk(&image, &layout_info, wd, &disk)?;
    let staged_sha = recipes_image_builder::image::sha256_hex(&image);

                                                                                          
                               
    run_installer_phase(
        &vmlinuz,
        &initramfs,
        &disk,
        &root_hash,
        layout.rootfs_verity_hash_offset,
        &layout_info,
        &window,
        &staged_sha,
        None,                                        
        None,                       
        opts,
        &log_dir.join("install-console.log"),
    )?;

                                                                                                       
    {
        let console = log_dir.join("boot-console.log");
        let mut guard = boot_installed_disk(&disk, opts, &console, true)?;
                                                                                                
                                                                                                      
        wait_for_ssh(
            operator_privkey,
            opts.ssh_port,
            opts.boot_timeout,
            &mut guard,
            &console,
        )?;
        assert_recipes_http(opts, &mut guard)?;                  
        assert_rootfs_ro(operator_privkey, opts.ssh_port)?;                           
                                                                                                  
                                                                      
        match firmware {
            crate::deploy::build_image::Firmware::SeabiosGpt => {
                assert_cmdline_partuuid(operator_privkey, opts.ssh_port)?
            }
            crate::deploy::build_image::Firmware::Seabios => {
                assert_cmdline_rootfs_dev(operator_privkey, opts.ssh_port)?
            }
                                                                                                       
                                                                                 
                                                                                                        
                                                                                        
            crate::deploy::build_image::Firmware::Uefi => unreachable!(
                "install_disk_and_verify is the legacy-BIOS (SeaBIOS/SeabiosGpt) gate; \
                 UEFI uses install_uefi_disk_and_verify"
            ),
        }
        assert_persist_grown(operator_privkey, opts.ssh_port)?;                                          
                                                                                                      
                                                                                                           
                                                                                                  
                                                                                           
        sync_persist_over_ssh(operator_privkey, opts.ssh_port)?;
    }

                                                                                                          
                                                                                                       
                                                                                                        
                                                                                     
    let aborted = wd.join("aborted-disk.img");
    std::fs::copy(&disk, &aborted)
        .map_err(DryrunError::io("copying disk for the bootable-last test"))?;
    zero_mbr_bootcode(&aborted)?;
    assert_disk_does_not_boot(
        &aborted,
        operator_privkey,
        opts,
        &log_dir.join("aborted-console.log"),
    )?;

                                                                                                         
                                                                                                         
                                                                                               
                                                                                                          
                                                                                                         
                                                                                                           
                                                                            
    {
        let console = log_dir.join("crash-recovery-console.log");
        let mut guard = boot_installed_disk(&disk, opts, &console, true)?;
                                                                                                     
        wait_for_ssh(
            operator_privkey,
            opts.ssh_port,
            opts.boot_timeout,
            &mut guard,
            &console,
        )?;
        assert_recipes_http(opts, &mut guard)?;
                                                                                                         
        assert_persist_grown(operator_privkey, opts.ssh_port)?;
    }

                                                                                               
                                                                                                                 
                                                                                                            
                                                                                                              
                                                                                                           
    clean_reboot_and_verify(
        &disk,
        operator_privkey,
        opts,
        &log_dir.join("clean-reboot-console.log"),
    )?;

    Ok(())
}

/// MUST equal `initramfs_init::installer::MAX_RESTORE_TARBALL_BYTES` (2 GiB). The installer is a
/// standalone `panic=abort` workspace — NOT an orchard dependency — so the over-cap threshold is
/// HAND-MIRRORED here (the cross-crate convention-duplication class, cf. [`crate::deploy::prod`]'s
/// `DEFENSE_TRIPLE` / the `SB_*` PARTUUID mirrors). The over-cap fixture stages a sparse tarball ONE
/// byte over this.
///
/// **Since the streaming redesign this constant no longer selects which refusal fires.** A
/// `restore_len` this size raises the staging-window floor
/// (`persist_start + max(skeleton, restore_len)`) above the placed window, so the ceremony-side
/// window refusal fires upstream of the box's size cap regardless of where the cap sits — which is
/// why the leg now asserts the window-overlap reason (operator decision 2026-07-30, see the
/// `over-cap` case below). The value is retained because it still picks a `logical_size` large
/// enough to trip that floor, and because it documents the box-side threshold this gate used to
/// prove. Drift in either direction is now caught by the box-side seam suite, not here.
const GATE_MAX_RESTORE_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// SHA-256 of the ENTIRE disk file — the PRE/POST "byte-untouched" probe for the restore-from gate's
/// abort cases. A verify / size-cap failure must leave the target disk bit-identical (NO write from an
/// unverified tarball); the source ext4 is mounted `MS_RDONLY` by the installer, so a clean
/// pre-`commit` abort cannot perturb even the superblock. Streams in 1 MiB chunks.
pub(super) fn whole_disk_sha256(disk: &Path) -> Result<[u8; 32], DryrunError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = File::open(disk).map_err(DryrunError::io("open disk for hashing"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(DryrunError::io("read disk for hashing"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// The restore-from gate's per-case expectation (see [`install_restore_from_and_verify`]).
enum RestoreExpect<'a> {
    /// A validly-signed restore image: the installer's verify + §4b pre-checks PASS, so the install
    /// PROCEEDS — the dd-only commit runs and the installed disk boots to a working runtime. The §6
    /// content asserts (sentinel/manifest/grown/label) ride along for the realistic assembled case.
    Proceeds {
        asserts: Option<RestoreContentAsserts<'a>>,
    },
    /// A rejected tarball (wrong-key / tampered / over-cap): the installer FATAL-aborts in 7.pre
    /// (BEFORE any destructive write), with `reason_substr` on the console, and the target disk is
    /// byte-identical PRE/POST — the load-bearing "never write a disk from an unverified tarball".
    AbortsUntouched { reason_substr: &'static str },
}

/// C1 / AC7 — the PRODUCED-BYTES restore-from verify gate. Proves, on the REAL `.img` + the REAL
/// on-box installer over real block devices, that the restore-image signature verify + §4b pre-checks are
/// before-any-write: a validly-signed tarball lets the install proceed (the box boots + serves),
/// while a wrong-key / tampered / over-cap tarball aborts the installer with the target disk
                                                                                                      
/// on paper; the host-unit tests STUB the verify, so this is its only end-to-end proof.)
///
/// `img` / `operator_privkey` are the built SeaBIOS `.img` (built with `--operator-pubkey` + `--net`,
/// so the signed case can SSH-assert the installed runtime) and the matching SSH private key.
/// `keys_dir` is the ARTIFACT-SIGNING key set the `.img` was baked with — its `artifact-root.pub` is
/// the on-box trust anchor baked at `/etc/recipes/artifact-root.pub`, so the harness can mint a tarball
/// that verifies against the baked anchor. A fresh second key set (a throwaway dir under the workdir)
/// provides the wrong-key fixture. RAII-tears-down every QEMU child.
pub fn install_restore_from_and_verify(
    img: &Path,
    operator_privkey: &Path,
    keys_dir: &Path,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    use crate::deploy::artifact_keys::{Custody, generate_artifact_keys, read_root_pub};
    use crate::deploy::artifact_sign::{SignPlan, plan_signing, sign_bytes};
    use dragonfruit::Purpose;

    preflight()?;
    let layout = parse_layout(&layout_sidecar(img))?;
    let vmlinuz = local_artifact(img, "vmlinuz")?;
    let initramfs = local_artifact(img, "initramfs")?;

    let workdir = tempfile::Builder::new()
        .prefix("recipes-restore-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating restore-gate workdir"))?;
    let wd = workdir.path();
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| wd.to_path_buf());
    if log_dir != wd {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }

                                                                                                     
                                                                                       
    let rootfs_data = wd.join("rootfs-data");
    slice(
        img,
        layout.rootfs_offset,
        layout.rootfs_verity_hash_offset,
        &rootfs_data,
    )?;
    let root_hash = recompute_verity_root_hash(&rootfs_data, &wd.join("verity.hash"))?;

                                                                                                      
                                                                                                   
    let mut image =
        std::fs::read(img).map_err(DryrunError::io(format!("read {}", img.display())))?;
    patch_boot_fs_rootfs_dev(&mut image, &layout)?;

                                                                                                    
                                                                                              
                                                                                           
                                                                                                  
                                                                                                  
                                                                                       
                                                                                              
                                                                                                  
                                                                                                
                                                                                               
                                                                                                
                                                                           
    let operator_pubkey_line =
        crate::deploy::build_image::read_validated_pubkey("operator", operator_privkey).map_err(
            |e| DryrunError::InstallDiskStage(format!("restore gate: derive operator pubkey: {e}")),
        )?;
    let assembled = assemble_realistic_restore(wd, &operator_pubkey_line)?;
                                                                                             
                                                                                        
    let tarball: &[u8] = b"recipes-restore-from-gate: a small operator backup tarball";
                                                                                              
                                                                                               
                                                                                     
                                                                  
    let valid_set = match plan_signing(keys_dir, &wd.join("no-pin")).map_err(|e| {
        DryrunError::InstallDiskStage(format!(
            "restore gate: plan the signing from {} (the keys-dir the .img was baked with — \
             RECIPES_RESTORE_KEYS_DIR): {e}",
            keys_dir.display()
        ))
    })? {
        SignPlan::Host(set) => set,
        other => {
            return Err(DryrunError::InstallDiskStage(format!(
                "restore gate: keys at {} must be a RAW (Host-rung) set, got {}",
                keys_dir.display(),
                match other {
                    SignPlan::Docker => "Docker",
                    _ => "UnsignedFloor",
                }
            )));
        }
    };
    let valid_sig = sign_bytes(&valid_set, Purpose::Backup, tarball).map_err(|e| {
        DryrunError::InstallDiskStage(format!("restore gate: sign the valid tarball: {e}"))
    })?;
                                                                                                      
                                                                               
    let wrong_dir = wd.join("wrong-artifact-keys");
    generate_artifact_keys(&wrong_dir, 365, false, Custody::Raw).map_err(|e| {
        DryrunError::InstallDiskStage(format!("restore gate: mint the wrong-key set: {e}"))
    })?;
    let wrong_set = match plan_signing(&wrong_dir, &wd.join("no-pin")).map_err(|e| {
        DryrunError::InstallDiskStage(format!("restore gate: plan the wrong-key signing: {e}"))
    })? {
        SignPlan::Host(set) => set,
        _ => {
            return Err(DryrunError::InstallDiskStage(
                "restore gate: the freshly-minted wrong-key set must be a RAW (Host-rung) set"
                    .to_string(),
            ));
        }
    };
    let wrong_sig = sign_bytes(&wrong_set, Purpose::Backup, tarball).map_err(|e| {
        DryrunError::InstallDiskStage(format!("restore gate: sign with the wrong key: {e}"))
    })?;
                                                                                                     
                                                                                       
    let mut tampered_sig = valid_sig.clone();
    tampered_sig[0] ^= 0xFF;
                                                                                                
                                                                                              
    let assembled_sig = sign_bytes(&valid_set, Purpose::Backup, &assembled.image).map_err(|e| {
        DryrunError::InstallDiskStage(format!("restore gate: sign the assembled image: {e}"))
    })?;
    let assembled_ctr = {
        use sha2::Digest as _;
        let bf = dragonfruit::BundleFile::from_bytes(&assembled_sig).map_err(|e| {
            DryrunError::InstallDiskStage(format!("restore gate: parse the assembled sig: {e:?}"))
        })?;
        let hash: [u8; 32] = sha2::Sha256::digest(&assembled.image).into();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
                                                                                           
                                                                                
        let baked_root_pub = read_root_pub(keys_dir).map_err(|e| {
            DryrunError::InstallDiskStage(format!("restore gate: read the public root pin: {e}"))
        })?;
        dragonfruit::verify_bundle(
            &bf.as_bundle(),
            &baked_root_pub,
            now,
            &hash,
            Purpose::Backup,
        )
        .map_err(|e| {
            DryrunError::InstallDiskStage(format!(
                "restore gate: the freshly-signed assembled image must verify: {e:?}"
            ))
        })?
        .monotonic_ctr()
    };
                                                                                               
                                                                                                   
                                                                        
    let mut journal_image = assembled.image.clone();
    journal_image[1024 + 0x5C] |= 0x04;
    let journal_sig = sign_bytes(&valid_set, Purpose::Backup, &journal_image).map_err(|e| {
        DryrunError::InstallDiskStage(format!("restore gate: sign the journal fixture: {e}"))
    })?;

    let ctx = || RestoreCaseCtx {
        image: &image,
        img,
        vmlinuz: &vmlinuz,
        initramfs: &initramfs,
        root_hash: &root_hash,
        verity_hash_offset: layout.rootfs_verity_hash_offset,
        wd,
        log_dir: &log_dir,
        operator_privkey,
        opts,
    };
                                                                                                    
                                                                                                  
                                                                                           
    run_restore_case(
        ctx(),
        "assembled",
        &RestoreStaging::Bytes {
            payload: &assembled.image,
            sig: &assembled_sig,
        },
        Some(assembled_ctr),                                                          
        RestoreExpect::Proceeds {
            asserts: Some(RestoreContentAsserts {
                sentinel_rel: &assembled.sentinel_rel,
                sentinel: &assembled.sentinel,
                samples: &assembled.samples,
                file_count: assembled.file_count,
                baked_bytes: assembled.image.len() as u64,
            }),
        },
    )?;
                                                                            
    run_restore_case(
        ctx(),
        "wrong-key",
        &RestoreStaging::Bytes {
            payload: tarball,
            sig: &wrong_sig,
        },
        None,
        RestoreExpect::AbortsUntouched {
            reason_substr: "verification failed",
        },
    )?;
                                                                           
    run_restore_case(
        ctx(),
        "tampered",
        &RestoreStaging::Bytes {
            payload: tarball,
            sig: &tampered_sig,
        },
        None,
        RestoreExpect::AbortsUntouched {
            reason_substr: "verification failed",
        },
    )?;
                                                                                                   
                                                                                              
                                                                                   
                                                                                              
                                                                                              
                                                                                          
                                                                                              
                                                        
      
                                                                                                   
                                                                                             
                                                           
                                                                                                      
                                                                                                 
                                                                                                  
    run_restore_case(
        ctx(),
        "over-cap",
        &RestoreStaging::SparseOverCap {
            logical_size: GATE_MAX_RESTORE_IMAGE_BYTES + 1,
            sig: &valid_sig,
        },
        None,
        RestoreExpect::AbortsUntouched {
            reason_substr: "overlaps the install's",
        },
    )?;
                                                                                                     
                                                                  
    run_restore_case(
        ctx(),
        "not-ext4",
        &RestoreStaging::Bytes {
            payload: tarball,
            sig: &valid_sig,
        },
        None,
        RestoreExpect::AbortsUntouched {
            reason_substr: "restore-ext4-magic",
        },
    )?;
                                                                                                     
                                                                          
    run_restore_case(
        ctx(),
        "journal-present",
        &RestoreStaging::Bytes {
            payload: &journal_image,
            sig: &journal_sig,
        },
        None,
        RestoreExpect::AbortsUntouched {
            reason_substr: "restore-journal-present",
        },
    )?;
                                                                                                  
                                                                                                    
                                          
    run_restore_case(
        ctx(),
        "min-ctr-below-floor",
        &RestoreStaging::Bytes {
            payload: &assembled.image,
            sig: &assembled_sig,
        },
        Some(assembled_ctr + 1),
        RestoreExpect::AbortsUntouched {
            reason_substr: "CounterRollback",
        },
    )?;
                                                                                         
                                                                                                  
                                                                                              
                                                                                                    
                                                                                                  
                                                                       
                                                                                                
    Ok(())
}

/// The §6 realistic-restore fixture the harness assembles through the REAL library path.
struct AssembledRestore {
    /// The baked persist image bytes (`orchard restore-image`'s exact output for this content).
    image: Vec<u8>,
    /// The sentinel's path relative to /persist (e.g. `recipes/images/gate-sentinel-<nonce>.txt`).
    sentinel_rel: String,
    /// The sentinel's exact bytes (nonce-carrying — a stale disk cannot alias a pass).
    sentinel: Vec<u8>,
    /// Five sampled (rel_path, size, uid) triples from the staging manifest for the on-box stat.
    samples: Vec<(String, u64, u32)>,
    /// Total staged tenant entries (tar entries + db) for the on-box file count.
    file_count: u64,
}

/// The §6 (a)-(c)+(e) post-boot content asserts for the assembled case.
struct RestoreContentAsserts<'a> {
    sentinel_rel: &'a str,
    sentinel: &'a [u8],
    samples: &'a [(String, u64, u32)],
    file_count: u64,
    baked_bytes: u64,
}

/// Build ≥64 MiB of tenant content, tar it in the fb-backup shape (system `tar` — the gate already
/// shells mke2fs/qemu/ssh), and assemble it through the REAL `orchard restore-image` library path:
/// `stage_restore` (one-parser staging) → `plan_size` (two-dimensional) → `bake_restore_image`
/// (pinned container, double-baked, identity-self-checked). The returned image is EXACTLY what the
/// operator ceremony stages.
fn assemble_realistic_restore(
    wd: &Path,
    operator_pubkey_line: &str,
) -> Result<AssembledRestore, DryrunError> {
    use recipes_image_builder::build_tools_host::HostBuildTools;
    use recipes_image_builder::restore_image::{RestoreImageSpec, plan_size, stage_restore};
    let stage = |m: String| DryrunError::InstallDiskStage(m);

    let content = wd.join("restore-content");
    let images = content.join("images");
    std::fs::create_dir_all(&images).map_err(DryrunError::io("create restore content dirs"))?;
                                                                                                     
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for i in 0..4u64 {
        let mut blob = vec![0u8; 16 << 20];
        x ^= i.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1;
        for chunk in blob.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
        }
        std::fs::write(images.join(format!("blob{i}.bin")), &blob)
            .map_err(DryrunError::io("write blob"))?;
    }
                                 
    for i in 0..400u64 {
        let size = 4096 + ((i * 31) % 12288) as usize;
        std::fs::write(
            images.join(format!("f{i}.dat")),
            vec![(i % 251) as u8; size],
        )
        .map_err(DryrunError::io("write small file"))?;
    }
                                                                                                  
                                               
    let sentinel_name = format!(
        "gate-sentinel-{:x}.txt",
        recipes_image_builder::image::sha256_hex(wd.as_os_str().as_encoded_bytes())
            .as_bytes()
            .iter()
            .take(8)
            .fold(0u64, |a, &b| (a << 8) | b as u64)
    );
    let sentinel_bytes = format!("restore-gate sentinel {}\n", wd.display()).into_bytes();
    std::fs::write(images.join(&sentinel_name), &sentinel_bytes)
        .map_err(DryrunError::io("write sentinel"))?;

                                                                               
    let tar_path = wd.join("data-gate.tar.gz");
    let status = Command::new("tar")
        .args(["--owner=100", "--group=100", "-czf"])
        .arg(&tar_path)
        .arg("-C")
        .arg(&content)
        .arg("images")
        .status()
        .map_err(|e| stage(format!("spawn tar: {e}")))?;
    if !status.success() {
        return Err(stage(format!("tar exited {status}")));
    }
    let data_tar_gz = std::fs::read(&tar_path).map_err(DryrunError::io("read gate tar"))?;

                                                                                        
    let spec = RestoreImageSpec {
        data_tar_gz: &data_tar_gz,
        db: b"",                                                                                
                                                                                                
                                                                                              
        operator_pubkey: operator_pubkey_line.as_bytes(),
        root: "recipes",
        db_target: "recipes.db",
        db_owner: Some((100, 100)),
    };
    let staged = stage_restore(&spec).map_err(|e| stage(format!("gate stage_restore: {e}")))?;
    let plan = plan_size(staged.content_bytes, staged.file_count)
        .map_err(|e| stage(format!("gate plan_size: {e}")))?;
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let samples: Vec<(String, u64, u32)> = staged
        .manifest
        .iter()
        .filter(|e| e.size > 0)
        .step_by(staged.manifest.len().max(5) / 5)
        .take(5)
        .map(|e| (e.path.clone(), e.size, e.uid))
        .collect();
    let file_count = staged.manifest.len() as u64;
    let image = HostBuildTools::new("recipes-imgbuild:dev", repo_root)
        .bake_restore_image(&staged, plan)
        .map_err(|e| stage(format!("gate bake_restore_image (needs docker): {e}")))?;
    Ok(AssembledRestore {
        image,
        sentinel_rel: format!("recipes/images/{sentinel_name}"),
        sentinel: sentinel_bytes,
        samples,
        file_count,
    })
}

/// The §6 asserts (a)-(c)+(e) over SSH on the BOOTED restored box: sentinel bytes exact, manifest
/// spot-check (count + sampled size/owner), the first-boot grow, and `findfs LABEL=persist`.
fn assert_restored_content(
    case: &str,
    privkey: &Path,
    port: u16,
    a: RestoreContentAsserts<'_>,
    guard: &mut QemuGuard,
) -> Result<(), DryrunError> {
    let _ = guard;                                                          
    let ssh = |cmd: &str| -> Result<String, DryrunError> {
        let out = Command::new("ssh")
            .args(super::qemu::ssh_base_args(privkey, port))
            .arg(cmd)
            .output()
            .map_err(DryrunError::io("spawn ssh for content assert"))?;
        if !out.status.success() {
            return Err(DryrunError::UnexpectedBoot(format!(
                "restore[{case}]: on-box `{cmd}` failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
                                                                             
    let dev = ssh("findfs LABEL=persist")?;
    if !dev.trim().starts_with("/dev/") {
        return Err(DryrunError::UnexpectedBoot(format!(
            "restore[{case}]: findfs LABEL=persist resolved {dev:?}, want a /dev node"
        )));
    }
                                      
    let got = ssh(&format!("cat /persist/{}", a.sentinel_rel))?;
    if got.as_bytes() != a.sentinel {
        return Err(DryrunError::UnexpectedBoot(format!(
            "restore[{case}]: sentinel mismatch: got {got:?}"
        )));
    }
                                                                                        
    let count = ssh("find /persist/recipes -type f | wc -l")?;
    let on_box: u64 = count.trim().parse().unwrap_or(0);
                                                                                                  
                                                                                                 
    if on_box < 400 {
        return Err(DryrunError::UnexpectedBoot(format!(
            "restore[{case}]: only {on_box} tenant files on the box (manifest staged {})",
            a.file_count
        )));
    }
    for (rel, size, uid) in a.samples {
        let stat = ssh(&format!("stat -c '%s %u' /persist/{rel}"))?;
        let want = format!("{size} {uid}");
        if stat.trim() != want {
            return Err(DryrunError::UnexpectedBoot(format!(
                "restore[{case}]: stat /persist/{rel} = {stat:?}, want {want:?} (size uid)"
            )));
        }
    }
                                                                                      
    let df = ssh("df -P -k /persist | tail -1")?;
    let total_kib: u64 = df
        .split_whitespace()
        .nth(1)
        .and_then(|f| f.parse().ok())
        .unwrap_or(0);
    if total_kib * 1024 < a.baked_bytes * 4 {
        return Err(DryrunError::UnexpectedBoot(format!(
            "restore[{case}]: persist fs is {total_kib} KiB — the first-boot grow did not run \
             (baked image {} bytes)",
            a.baked_bytes
        )));
    }
    Ok(())
}

/// The shared, per-case inputs threaded into [`run_restore_case`] (grouped to dodge the
/// too-many-arguments lint without an `#[allow]` on every call).
struct RestoreCaseCtx<'a> {
    image: &'a [u8],
    img: &'a Path,
    vmlinuz: &'a Path,
    initramfs: &'a Path,
    root_hash: &'a str,
    verity_hash_offset: u64,
    wd: &'a Path,
    log_dir: &'a Path,
    operator_privkey: &'a Path,
    opts: &'a DryrunOpts,
}

/// Run ONE restore-from case: stage a fresh install disk carrying the `.img` + the case's restore
/// bundle, run the dd-only installer with `fb.restore-from`, and assert `expect`. For the abort cases
/// the target disk is whole-disk-hashed PRE and re-hashed POST: equality is the proof that the
/// installer aborted BEFORE any destructive write.
fn run_restore_case(
    ctx: RestoreCaseCtx<'_>,
    case: &str,
    staging: &RestoreStaging<'_>,
    min_ctr: Option<u64>,
    expect: RestoreExpect<'_>,
) -> Result<(), DryrunError> {
    let RestoreCaseCtx {
        image,
        img,
        vmlinuz,
        initramfs,
        root_hash,
        verity_hash_offset,
        wd,
        log_dir,
        operator_privkey,
        opts,
    } = ctx;

    let disk = wd.join(format!("restore-{case}-disk.img"));
    let layout = parse_layout(&layout_sidecar(img))?;
    let layout_info = gate_layout_info(&layout, crate::deploy::build_image::Firmware::Seabios);
    let window = stage_install_disk_with_restore(image, &layout_info, Some(staging), wd, &disk)?;
    let staged_sha = recipes_image_builder::image::sha256_hex(image);
    let pre = whole_disk_sha256(&disk)?;

    let install_console = log_dir.join(format!("restore-{case}-install-console.log"));
    let install = run_installer_phase(
        vmlinuz,
        initramfs,
        &disk,
        root_hash,
        verity_hash_offset,
        &layout_info,
        &window,
        &staged_sha,
        Some(GATE_RESTORE_IMAGE_PATH),
        min_ctr,
        opts,
        &install_console,
    );

    match expect {
        RestoreExpect::Proceeds { asserts } => {
                                                                                                     
                                                                                                        
            install.map_err(|e| match e {
                DryrunError::InstallFailed(m) => DryrunError::InstallFailed(format!(
                    "restore[{case}]: a VALIDLY-signed, identity-clean restore payload was REJECTED — the verify must \
                     pass and the install proceed: {m}"
                )),
                other => other,
            })?;
                                                                                                        
                                                                                                  
            let boot_console = log_dir.join(format!("restore-{case}-boot-console.log"));
            let mut guard = boot_installed_disk(&disk, opts, &boot_console, true)?;
            wait_for_ssh(
                operator_privkey,
                opts.ssh_port,
                opts.boot_timeout,
                &mut guard,
                &boot_console,
            )?;
            assert_recipes_http(opts, &mut guard)?;                      
            if let Some(a) = asserts {
                assert_restored_content(case, operator_privkey, opts.ssh_port, a, &mut guard)?;
            }
        }
        RestoreExpect::AbortsUntouched { reason_substr } => {
                                                                                                      
                                                                                                       
                                                                                                    
            match install {
                Ok(()) => {
                    return Err(DryrunError::UnexpectedBoot(format!(
                        "restore[{case}]: the installer did NOT abort on a rejected restore payload — \
                         it proceeded past the verify-before-write gate. console tail:\n{}",
                        console_tail(&install_console)
                    )));
                }
                Err(DryrunError::InstallFailed(msg)) => {
                                                                                                     
                                                                                                    
                                                                                                          
                                                                                                        
                                                                                                       
                                                                                          
                                          
                    let log = std::fs::read_to_string(&install_console).unwrap_or_default();
                    let fatal_matches = log
                        .lines()
                        .any(|l| l.contains("fb-init FATAL") && l.contains(reason_substr));
                    if !fatal_matches {
                        return Err(DryrunError::InstallFailed(format!(
                            "restore[{case}]: aborted, but its `fb-init FATAL` line is not the expected \
                             {reason_substr:?} reason: {msg}\nconsole tail:\n{}",
                            console_tail(&install_console)
                        )));
                    }
                }
                Err(other) => return Err(other),                                            
            }
                                                                                                    
            let post = whole_disk_sha256(&disk)?;
            if post != pre {
                return Err(DryrunError::UnexpectedBoot(format!(
                    "restore[{case}]: the target disk was MODIFIED despite the abort — a write \
                     occurred before the restore payload was verified/checked (PRE != POST whole-disk hash)"
                )));
            }
        }
    }
    Ok(())
}

/// Byte-patch the boot-fs region of the in-RAM `.img`: locate the `fb.rootfs-dev` sentinel within
/// `[boot_offset, boot_offset+boot_size)` and overwrite it with [`GATE_ROOTFS_DEV`] (the deploy CLI's
/// [`crate::deploy::prod::patch_rootfs_dev`], length-preserving). Fail-closed on a layout/image bounds
/// mismatch (so a bad layout can't slice past the image).
pub(crate) fn patch_boot_fs_rootfs_dev(
    image: &mut [u8],
    layout: &Layout,
) -> Result<(), DryrunError> {
    let image_len = image.len();
    let bad = |m: String| DryrunError::BootFsPatch(m);
    let start = usize::try_from(layout.boot_offset)
        .map_err(|_| bad("boot_offset overflows usize".into()))?;
    let size =
        usize::try_from(layout.boot_size).map_err(|_| bad("boot_size overflows usize".into()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| bad("boot region offset+size overflows".into()))?;
    let boot = image.get_mut(start..end).ok_or_else(|| {
        bad(format!(
            "boot region {start}..{end} past the {image_len}-byte .img"
        ))
    })?;
    crate::deploy::prod::patch_rootfs_dev(boot, GATE_ROOTFS_DEV).map_err(DryrunError::BootFsPatch)
}

/// How the restore payload (`restore.persist.img` + its `.sig`) is written into the install-disk
/// src-tree for the restore-from gate. The tarball CONTENT is irrelevant to the boot — C1 VERIFIES
/// it but does not APPLY it until 4.3 (the dd-only commit writes the pre-baked persist-skeleton); the
/// gate's teeth are the verify-before-write seam exercised over PRODUCED bytes.
enum RestoreStaging<'a> {
    /// A small in-RAM tarball + its detached signature bytes (the signed / wrong-key / tampered
    /// cases). The sig is the 254-byte dragonfruit bundle minted by `sign_bytes`.
    Bytes { payload: &'a [u8], sig: &'a [u8] },
    /// A SPARSE tarball of `logical_size` bytes — its `metadata().len()` is the size-cap input, while
    /// `mke2fs -d` hole-preservation keeps the staged ext4 inode at ~0 real blocks — plus any sig
    /// bytes. The over-cap case: the size cap aborts BEFORE the read, so the sig is never reached. That
    /// the abort is the CAP (not a sig failure) is proven by the `restore-size-cap` reason assertion in
    /// `run_restore_case`, not by the staged sig — which signs the small tarball, not this 2 GiB content.
    SparseOverCap { logical_size: u64, sig: &'a [u8] },
}

impl RestoreStaging<'_> {
    /// The REAL byte demand this staging adds to the source fs (sparse holes cost ~nothing).
    fn staged_real_bytes(&self) -> u64 {
        match self {
            RestoreStaging::Bytes { payload, sig } => (payload.len() + sig.len()) as u64,
            RestoreStaging::SparseOverCap { sig, .. } => sig.len() as u64,
        }
    }

    /// Write the restore payload + its detached `<name>.sig` into the src-tree `tree`, at the basename
    /// [`GATE_RESTORE_IMAGE_PATH`] resolves to off the mounted old-root.
    fn materialize(&self, tree: &Path) -> Result<(), DryrunError> {
        let name = GATE_RESTORE_IMAGE_PATH.trim_start_matches('/');
        let tar = tree.join(name);
        let sig = tree.join(format!("{name}.sig"));
        match self {
            RestoreStaging::Bytes {
                payload,
                sig: sig_bytes,
            } => {
                std::fs::write(&tar, payload).map_err(DryrunError::io("write restore payload"))?;
                std::fs::write(&sig, sig_bytes)
                    .map_err(DryrunError::io("write restore payload .sig"))?;
            }
            RestoreStaging::SparseOverCap {
                logical_size,
                sig: sig_bytes,
            } => {
                                                                                                      
                                                                                                     
                                                                                                  
                                                                                                        
                                                                                                  
                File::create(&tar)
                    .and_then(|f| f.set_len(*logical_size))
                    .map_err(DryrunError::io(
                        "create+size sparse over-cap restore payload",
                    ))?;
                std::fs::write(&sig, sig_bytes)
                    .map_err(DryrunError::io("write restore payload .sig"))?;
            }
        }
        Ok(())
    }
}

/// Build the composer-facing [`LayoutInfo`] view of the gate's parsed sidecar layout — the
/// harness twin of `read_image_artifacts`' mapping (the raw arm carries these numbers on the
/// append; there is no sidecar on the staged disk anymore).
pub(super) fn gate_layout_info(
    layout: &super::Layout,
    firmware: crate::deploy::build_image::Firmware,
) -> crate::deploy::prod_orchestrate::LayoutInfo {
    crate::deploy::prod_orchestrate::LayoutInfo {
        boot_offset: layout.boot_offset,
        boot_size: layout.boot_size,
        persist_skeleton_offset: layout.persist_skeleton_offset,
        persist_skeleton_size: layout.persist_skeleton_size,
        rootfs_offset: layout.rootfs_offset,
        rootfs_size: layout.rootfs_size,
        rootfs_verity_hash_offset: layout.rootfs_verity_hash_offset,
        firmware,
        weights_offset: layout.weights_offset,
        weights_size: layout.weights_size,
    }
}

                                                                                               
/// written host-side at the geometry-computed RAW TAIL WINDOW of the disk file (`File::seek` +
/// `write_all` — the harness twin of the operator's `dd oflag=seek_bytes` stream). Greenfield
/// stages NO filesystem at all (the raw arm mounts nothing); returns the window for the append.
pub(super) fn stage_install_disk(
    image: &[u8],
    layout_info: &crate::deploy::prod_orchestrate::LayoutInfo,
    wd: &Path,
    disk: &Path,
) -> Result<crate::deploy::prod::RawWindowSpec, DryrunError> {
    stage_install_disk_with_restore(image, layout_info, None, wd, disk)
}

/// As [`stage_install_disk`], but when `restore` is `Some` the ext4 source-partition construction
                                                                                                 
/// mounted old-root; the `.img` itself always rides the raw window). The window is placed with
/// restore_len = 0 deliberately: the gate stages hostile/over-cap restore cases whose refusal the
/// BOX must own — the harness must not pre-refuse them.
fn stage_install_disk_with_restore(
    image: &[u8],
    layout_info: &crate::deploy::prod_orchestrate::LayoutInfo,
    restore: Option<&RestoreStaging<'_>>,
    wd: &Path,
    disk: &Path,
) -> Result<crate::deploy::prod::RawWindowSpec, DryrunError> {
    let stage = |m: String| DryrunError::InstallDiskStage(m);

                                                                                         
                                                                                                
                                                                                               
                                                                                                 
                                                                                                
                                         
    let disk_bytes =
        GATE_INSTALL_DISK_BYTES.max(round_up_mib(3 * image.len() as u64 + 512 * 1024 * 1024));
    let window = crate::deploy::staging_geometry::place_and_check_window(
        layout_info,
        "vda",
        disk_bytes,
        image.len() as u64,
        0,
    )
    .map_err(|e| stage(format!("window placement: {e}")))?;

    let mut out = File::create(disk).map_err(DryrunError::io("create install disk"))?;
    out.set_len(disk_bytes)
        .map_err(DryrunError::io("size install disk"))?;

                                                                                            
    if let Some(r) = restore {
        let tree = wd.join("src-tree");
        std::fs::create_dir_all(&tree).map_err(DryrunError::io("create src-tree"))?;
        r.materialize(&tree)?;
        let restore_bytes = r.staged_real_bytes();
        let fs_bytes = round_up_mib(restore_bytes + 64 * 1024 * 1024);
        let fs_img = wd.join("src-fs.img");
        File::create(&fs_img)
            .and_then(|f| f.set_len(fs_bytes).map(|_| f))
            .map_err(DryrunError::io("create+size src-fs.img"))?;
        let status = Command::new("mke2fs")
            .args(["-t", "ext4", "-b", "4096", "-F", "-q", "-d"])
            .arg(&tree)
            .arg(&fs_img)
            .status()
            .map_err(|e| stage(format!("spawn mke2fs: {e}")))?;
        if !status.success() {
            return Err(stage(format!("mke2fs exited {status}")));
        }
        let fs_sectors = fs_bytes / 512;                                        
                                                                                                  
                                                                                           
        if GATE_SOURCE_FS_START_LBA * 512 + fs_bytes > window.offset {
            return Err(stage(format!(
                "restore source fs (ends {}) would reach the tail window ({}) — disk sizing bug",
                GATE_SOURCE_FS_START_LBA * 512 + fs_bytes,
                window.offset
            )));
        }
        let start_lba = u32::try_from(GATE_SOURCE_FS_START_LBA)
            .map_err(|_| stage("source LBA overflows u32".into()))?;
        let count = u32::try_from(fs_sectors)
            .map_err(|_| stage("source fs too large for a u32 MBR entry".into()))?;
        let mbr = build_single_partition_mbr(start_lba, count);
        out.write_all(&mbr).map_err(DryrunError::io("write MBR"))?;
        out.seek(SeekFrom::Start(GATE_SOURCE_FS_START_LBA * 512))                      
            .map_err(DryrunError::io("seek to partition start"))?;
        let mut fs_in = File::open(&fs_img).map_err(DryrunError::io("reopen src-fs.img"))?;
        std::io::copy(&mut fs_in, &mut out).map_err(DryrunError::io("copy fs into disk"))?;
    }

                                                                                               
                          
    out.seek(SeekFrom::Start(window.offset))
        .map_err(DryrunError::io("seek to tail window"))?;
    out.write_all(image)
        .map_err(DryrunError::io("write staged window"))?;
    out.sync_all()
        .map_err(DryrunError::io("sync install disk"))?;
    Ok(window)
}

                                                                                           
/// agreement; plan T12): four doomed variants, each booted through the REAL installer VM,
/// asserting (1) the console shows the SPECIFIC fail-closed refusal and (2) the partition table
/// was NEVER written — LBA0 of the disk file is still all-zero, the produced-bytes analog of the
/// unit suites' `!did_destructive`. Legs (c)/(d) hand-CRAFT appends the v2 composer refuses to
/// produce (that refusal is itself composer-tested); the box must fail closed on them anyway.
pub fn streaming_negative_legs(
    img: &Path,
    firmware: crate::deploy::build_image::Firmware,
    opts: &DryrunOpts,
) -> Result<(), DryrunError> {
    preflight()?;
    let layout = parse_layout(&layout_sidecar(img))?;
    let vmlinuz = local_artifact(img, "vmlinuz")?;
    let initramfs = local_artifact(img, "initramfs")?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-streamneg-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating streaming-negative workdir"))?;
    let wd = workdir.path();
    let log_dir = std::env::var_os("RECIPES_PROD_GATE_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| wd.to_path_buf());
    if log_dir != wd {
        std::fs::create_dir_all(&log_dir).map_err(DryrunError::io("creating gate log dir"))?;
    }
    let rootfs_data = wd.join("rootfs-data");
    slice(
        img,
        layout.rootfs_offset,
        layout.rootfs_verity_hash_offset,
        &rootfs_data,
    )?;
    let root_hash = recompute_verity_root_hash(&rootfs_data, &wd.join("verity.hash"))?;
    let mut image =
        std::fs::read(img).map_err(DryrunError::io(format!("read {}", img.display())))?;
    if firmware == crate::deploy::build_image::Firmware::Seabios {
        patch_boot_fs_rootfs_dev(&mut image, &layout)?;
    }
    let layout_info = gate_layout_info(&layout, firmware);
    let staged_sha = recipes_image_builder::image::sha256_hex(&image);

                                                                                           
                                                                                 
    let run_refusal = |case: &str,
                       disk: &Path,
                       append: &str,
                       reason_substr: &str|
     -> Result<(), DryrunError> {
        let console = log_dir.join(format!("streamneg-{case}-console.log"));
        match run_installer_qemu(&vmlinuz, &initramfs, &[disk], append, opts, &console) {
            Ok(()) => Err(DryrunError::UnexpectedBoot(format!(
                "streaming-negative[{case}]: the installer did NOT refuse — it completed an \
                 install that must fail closed. console tail:\n{}",
                console_tail(&console)
            ))),
            Err(DryrunError::InstallFailed(msg)) => {
                let log = std::fs::read_to_string(&console).unwrap_or_default();
                let matched = log
                    .lines()
                    .any(|l| l.contains("fb-init FATAL") && l.contains(reason_substr));
                if !matched {
                    return Err(DryrunError::InstallFailed(format!(
                        "streaming-negative[{case}]: aborted, but not with the expected \
                         {reason_substr:?} reason: {msg}\nconsole tail:\n{}",
                        console_tail(&console)
                    )));
                }
                                                                                   
                use std::io::Read as _;
                let mut lba0 = vec![0u8; 512];
                let mut f = File::open(disk).map_err(DryrunError::io("reopen negative disk"))?;
                f.read_exact(&mut lba0)
                    .map_err(DryrunError::io("read LBA0"))?;
                if lba0.iter().any(|&b| b != 0) {
                    return Err(DryrunError::UnexpectedBoot(format!(
                        "streaming-negative[{case}]: LBA0 is NOT zero — the partition table was \
                         written despite the refusal (verify-before-write broken)"
                    )));
                }
                Ok(())
            }
            Err(other) => Err(other),
        }
    };

                                                                                                  
                                                                              
    {
        let disk = wd.join("neg-digest-disk.img");
        let window = stage_install_disk(&image, &layout_info, wd, &disk)?;
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&disk)
                .map_err(DryrunError::io("reopen for flip"))?;
            let flip_at = window.offset + layout.rootfs_offset + layout.rootfs_size / 2;
            f.seek(SeekFrom::Start(flip_at))
                .map_err(DryrunError::io("seek flip"))?;
            use std::io::Read as _;
            let mut b = [0u8; 1];
                                                                                                 
            let mut rf = File::open(&disk).map_err(DryrunError::io("read flip byte"))?;
            rf.seek(SeekFrom::Start(flip_at))
                .map_err(DryrunError::io("seek read flip"))?;
            rf.read_exact(&mut b)
                .map_err(DryrunError::io("read flip"))?;
            b[0] ^= 0xFF;
            f.write_all(&b).map_err(DryrunError::io("write flip"))?;
            f.sync_all().map_err(DryrunError::io("sync flip"))?;
        }
        let append = crate::deploy::prod::build_installer_cmdline(
            &root_hash,
            layout.rootfs_verity_hash_offset,
            &window,
            &staged_sha,
            &layout_info,
            None,
            None,
        )
        .map_err(|e| DryrunError::QemuLaunch(format!("negative-leg cmdline: {e}")))?;
        run_refusal(
            "digest-flip",
            &disk,
            &append,
            "does not match fb.image-sha256",
        )?;
    }

                                                                                                   
                                                                                               
                                             
    {
        let disk = wd.join("neg-overlap-disk.img");
        let _good = stage_install_disk(&image, &layout_info, wd, &disk)?;
        let evil = crate::deploy::prod::RawWindowSpec {
            disk: "vda".to_string(),
            offset: 136 * 1024 * 1024,                                                   
            len: image.len() as u64,
        };
        let append = crate::deploy::prod::build_installer_cmdline(
            &root_hash,
            layout.rootfs_verity_hash_offset,
            &evil,
            &staged_sha,
            &layout_info,
            None,
            None,
        )
        .map_err(|e| DryrunError::QemuLaunch(format!("negative-leg cmdline: {e}")))?;
        run_refusal("window-overlap", &disk, &append, "overlaps the install's")?;
    }

                                                                                                  
                                                                                              
    {
        let disk = wd.join("neg-fw-disk.img");
        let window = stage_install_disk(&image, &layout_info, wd, &disk)?;
        let good = crate::deploy::prod::build_installer_cmdline(
            &root_hash,
            layout.rootfs_verity_hash_offset,
            &window,
            &staged_sha,
            &layout_info,
            None,
            None,
        )
        .map_err(|e| DryrunError::QemuLaunch(format!("negative-leg cmdline: {e}")))?;
        let (from, to) = match firmware {
            crate::deploy::build_image::Firmware::Seabios => (
                "fb.image-layout=fw:seabios,",
                "fb.image-layout=fw:seabios-gpt,",
            ),
            _ => (
                "fb.image-layout=fw:seabios-gpt,",
                "fb.image-layout=fw:seabios,",
            ),
        };
        let doctored = good.replacen(from, to, 1);
        if doctored == good {
            return Err(DryrunError::QemuLaunch(
                "negative-leg fw-mismatch: token surgery found nothing to replace".into(),
            ));
        }
        run_refusal("fw-mismatch", &disk, &doctored, "!= fb.firmware")?;
    }

                                                                                                  
                                                            
    {
        let disk = wd.join("neg-nosha-disk.img");
        let window = stage_install_disk(&image, &layout_info, wd, &disk)?;
        let good = crate::deploy::prod::build_installer_cmdline(
            &root_hash,
            layout.rootfs_verity_hash_offset,
            &window,
            &staged_sha,
            &layout_info,
            None,
            None,
        )
        .map_err(|e| DryrunError::QemuLaunch(format!("negative-leg cmdline: {e}")))?;
        let sha_token = format!(" fb.image-sha256={staged_sha}");
        let doctored = good.replacen(&sha_token, "", 1);
        if doctored == good {
            return Err(DryrunError::QemuLaunch(
                "negative-leg no-sha: token surgery found nothing to remove".into(),
            ));
        }
        run_refusal("no-sha", &disk, &doctored, "fb.image-sha256 not set")?;
    }

    Ok(())
}

/// Build a single-partition MBR sector-0 for the source disk: one 0x83 Linux entry at offset 446 (LBA
/// start + sector count, u32 LE; CHS = the `FE FF FF` use-LBA sentinel), boot signature `55 AA`. The
/// kernel's msdos partition parser materializes `/dev/vda1` from this so the installer can mount the
/// source. No boot code (phase 1 boots via QEMU `-kernel`, not this MBR).
fn build_single_partition_mbr(start_lba: u32, sector_count: u32) -> [u8; 512] {
    let mut mbr = [0u8; 512];
    let e = 446;
    mbr[e] = 0x00;                                                                                  
    mbr[e + 1..e + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);                                
    mbr[e + 4] = 0x83;         
    mbr[e + 5..e + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);                               
    mbr[e + 8..e + 12].copy_from_slice(&start_lba.to_le_bytes());
    mbr[e + 12..e + 16].copy_from_slice(&sector_count.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    mbr
}

                                                                                                   
/// kexec-equivalent), exercising the dd-only FFI; `-no-reboot` makes QEMU EXIT when the installer
/// reboots. Waits for that exit (a hang → timeout). The installer's PID-1 fatal path logs
/// `fb-init FATAL` to the console on any failure (which also reboots → exit), so a failed install
/// is caught here with its reason rather than surfacing as a phase-2 timeout.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_installer_phase(
    vmlinuz: &Path,
    initramfs: &Path,
    disk: &Path,
    root_hash: &str,
    verity_hash_offset: u64,
    layout_info: &crate::deploy::prod_orchestrate::LayoutInfo,
    window: &crate::deploy::prod::RawWindowSpec,
    image_sha256_hex: &str,
    restore_from: Option<&str>,
    min_ctr: Option<u64>,
    opts: &DryrunOpts,
    console: &Path,
) -> Result<(), DryrunError> {
                                                                                                
                                                                                               
                                                                                               
              
    let append = crate::deploy::prod::build_installer_cmdline(
        root_hash,
        verity_hash_offset,
        window,
        image_sha256_hex,
        layout_info,
        restore_from.map(|p| (GATE_SOURCE_PARTITION, p)),
        min_ctr,
    )
                                                                                            
                                                                                                 
                                                                                                
                                                                           
    .map_err(|e| DryrunError::QemuLaunch(format!("installer cmdline: {e}")))?;
    run_installer_qemu(vmlinuz, initramfs, &[disk], &append, opts, console)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_partition_mbr_has_a_valid_linux_entry_and_signature() {
                                                                                               
        let mbr = build_single_partition_mbr(2048, 524_288);                          
                          
        assert_eq!(&mbr[510..512], &[0x55, 0xAA]);
                                           
        assert_eq!(
            mbr[446], 0x00,
            "not active (the installer phase boots via -kernel)"
        );
        assert_eq!(mbr[450], 0x83, "Linux partition type");
        assert_eq!(
            &mbr[447..450],
            &[0xFE, 0xFF, 0xFF],
            "CHS-first use-LBA sentinel"
        );
        assert_eq!(
            &mbr[451..454],
            &[0xFE, 0xFF, 0xFF],
            "CHS-last use-LBA sentinel"
        );
        assert_eq!(
            u32::from_le_bytes(mbr[454..458].try_into().unwrap()),
            2048,
            "LBA start (little-endian)"
        );
        assert_eq!(
            u32::from_le_bytes(mbr[458..462].try_into().unwrap()),
            524_288,
            "sector count (little-endian)"
        );
                                                                         
        assert!(
            mbr[462..510].iter().all(|&b| b == 0),
            "only partition 1 is set"
        );
                                                                         
        assert!(
            mbr[..446].iter().all(|&b| b == 0),
            "440-byte boot-code area is zero"
        );
    }
}
