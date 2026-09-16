                                                                                        
//!
//! Deploy-feature-gated AND env-gated (heavy: a full greenfield install + four QEMU boots). SKIPPED
//! unless `RECIPES_PROD_IMG` points at a PRE-built `.img` built with BOTH `--operator-pubkey <key.pub>`
//! AND `--net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3"` (the QEMU user-net addressing),
//! and `RECIPES_PROD_PRIVKEY` points at the matching operator private key. Building an image in-test
//! is ~minutes, so — like `deploy_dryrun` — the operator-facing path and this test share the same
//! `install_disk_and_verify` core, but the test feeds it a PRE-built image.
//!
//! Build such an image:
//!   orchard build --domain box.test \
//!     --operator-pubkey <key.pub> \
//!     --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" \
//!     --out-dir <dir> --allow-dirty
//! then run:
//!   RECIPES_PROD_IMG=<dir>/<img>.img RECIPES_PROD_PRIVKEY=<key> \
//!     cargo test -p orchard --test deploy_prod_qemu -- --nocapture
//! (the sibling `<stem>.layout.toml` + `<stem>.vmlinuz` + `<stem>.initramfs` must be present; KVM at
//! /dev/kvm).
//!
                                                                                                      
//! the pre-baked boot-fs / rootfs / persist-skeleton, writes `mbr.bin` LAST, reboots; SeaBIOS then
//! boots the installed disk through the REAL chain (MBR → VBR → ldlinux → kernel) to a working runtime
//! — dropbear accepts the OPERATOR pubkey, recipes serves, `/` is ro (verity), `/proc/cmdline` carries
//! the byte-patched `fb.rootfs-dev=/dev/vda2`, persist resize2fs-filled its partition — AND a disk
                                                                                                               
//! empirical close for the installer.
//!
//! ASSERTED (persist-crash-recovery): `install_disk_and_verify` syncs `/persist` then re-boots the
//! installed disk after the unclean Phase-2 teardown, and asserts it auto-recovers the dirty fs
//! (journal-replay via `prepare-persist`'s `e2fsck -p`, then the journal-gated grow skips resize2fs) to
//! SERVICES with recipes serving 303 — acceptance #1, **Case B (a crash of a PROVISIONED box)**. The
//! mid-first-boot-provisioning empty-file case (recipes/haproxy choke on a 0-byte cookie.key / ca.crt) is
                                                                                                  
//! corruption→rescue path is acceptance #3b (`boot_rc4_corrupt_persist_and_verify`).
//!
//! ALSO ASSERTED (phase-4 holistic M-β): `clean_reboot_and_verify` then exercises the CLEAN-reboot leg —
//! SIGTERM to PID-1 runs the `.s6-svscan/SIGTERM`→`finish` shutdown→reboot exec handlers (the one
//! in-scope un-run BOOT-1 path: every other boot here is `-no-reboot` + an unclean SIGKILL), and the box
//! must cleanly reboot and come BACK to services (a misresolved finish handler → PID-1 panic → no reboot
//! → timeout). This whole gate is operator-run via `make boot-gate` (it is `#[ignore]`d, never a false green).

use std::path::Path;

                                                                                                           
                                                                                                          
                                                                              
#[test]
#[ignore = "boot gate: needs RECIPES_PROD_IMG + RECIPES_PROD_PRIVKEY + /dev/kvm; run via `make boot-gate`"]
fn installed_disk_boots_through_seabios_to_working_runtime() {
    let (Ok(img), Ok(privkey)) = (
        std::env::var("RECIPES_PROD_IMG"),
        std::env::var("RECIPES_PROD_PRIVKEY"),
    ) else {
        panic!(
            "deploy_prod_qemu gate invoked (--ignored) without RECIPES_PROD_IMG + RECIPES_PROD_PRIVKEY — \
             set them to a .img built with --operator-pubkey + --net (+ the matching privkey, /dev/kvm), \
             or run the gates via `make boot-gate`. A boot gate must never pass without asserting."
        );
    };
    orchard::deploy::dryrun::install_disk_and_verify(
        Path::new(&img),
        Path::new(&privkey),
        orchard::deploy::build_image::Firmware::Seabios,
                                                                                               
        &orchard::ceremony::leg_registry::installed_disk_opts(),
    )
    .expect(
        "greenfield install + SeaBIOS disk-boot should reach a working runtime + hold bootable-last",
    );
                                                                                                  
                                                                                                 
                                                               
    orchard::ceremony::gate_record::emit_leg_pass(
        Path::new(&img),
        "installed_disk_boots_through_seabios_to_working_runtime",
    )
    .expect("emit this leg's gate-record row");
}

                                                                                                          
                                                                                     
#[test]
#[ignore = "boot gate: needs RECIPES_SEABIOSGPT_IMG + RECIPES_SEABIOSGPT_PRIVKEY + /dev/kvm; run via `make boot-gate-seabios-gpt`"]
fn installed_seabios_gpt_disk_boots_through_seabios_to_working_runtime() {
                                                                                                       
                                                                                                  
                                                                                                         
                                                                                                       
                                                                                                         
                                                                                                            
                                                                                                   
    let (Ok(img), Ok(privkey)) = (
        std::env::var("RECIPES_SEABIOSGPT_IMG"),
        std::env::var("RECIPES_SEABIOSGPT_PRIVKEY"),
    ) else {
        panic!(
            "deploy_prod_qemu SeabiosGpt gate invoked (--ignored) without RECIPES_SEABIOSGPT_IMG + \
             RECIPES_SEABIOSGPT_PRIVKEY — set them to a `--firmware seabios-gpt` .img built with \
             --operator-pubkey + --net (+ the matching privkey, /dev/kvm), or run via \
             `make boot-gate-seabios-gpt`. A boot gate must never pass without asserting."
        );
    };
    orchard::deploy::dryrun::install_disk_and_verify(
        Path::new(&img),
        Path::new(&privkey),
        orchard::deploy::build_image::Firmware::SeabiosGpt,
        &orchard::deploy::dryrun::DryrunOpts::default(),
    )
    .expect(
        "SeabiosGpt greenfield install + SeaBIOS-on-GPT disk-boot should reach a working runtime + hold bootable-last",
    );
}
