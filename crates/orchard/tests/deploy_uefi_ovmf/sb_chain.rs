//! The UEFI SB-CHAIN runtime gates: §9.1 install+boot, the §9.2 signed chain, the §9.3a-f negative battery, §9.6 identity, + the 2 USB-repro gates.

use crate::common::*;
use std::path::Path;

                                                                                                           
                                                                                                 
                                                                   
#[test]
#[ignore = "boot gate: needs RECIPES_UEFI_IMG + _PRIVKEY + RECIPES_OVMF_CODE/_VARS + /dev/kvm; run via `make boot-gate`"]
fn uefi_installs_and_boots_through_ovmf() {
    let (Ok(img), Ok(privkey), Ok(ovmf_code), Ok(ovmf_vars)) = (
        std::env::var("RECIPES_UEFI_IMG"),
        std::env::var("RECIPES_UEFI_PRIVKEY"),
        std::env::var("RECIPES_OVMF_CODE"),
        std::env::var("RECIPES_OVMF_VARS"),
    ) else {
        panic!(
            "deploy_uefi_ovmf gate invoked (--ignored) without RECIPES_UEFI_IMG + RECIPES_UEFI_PRIVKEY \
             + RECIPES_OVMF_CODE + RECIPES_OVMF_VARS — set them to a --firmware uefi .img (+ the matching \
             operator privkey + the SB-OFF OVMF blobs, /dev/kvm), or run the gates via `make boot-gate`. \
             A boot gate must never pass without asserting."
        );
    };
                                                                                                       
                                                                                  
    let opts = orchard::deploy::dryrun::DryrunOpts {
        ssh_port: 2223,
        https_port: 8444,
        ..Default::default()
    };
    orchard::deploy::dryrun::install_uefi_disk_and_verify(
        Path::new(&img),
        Path::new(&privkey),
        &opts,
        Path::new(&ovmf_code),
        Path::new(&ovmf_vars),
    )
    .expect("GPT install + OVMF disk-boot should reach a working runtime (dropbear/recipes/ro-squashfs)");
}

                                                                                                     
                                                                                                
                                                                                                        
                                                                                                      
                                                                                                      
#[test]
                                                                                                    
                                                                                                          
                                                                                                      
#[ignore = "USB repro gate (SB-OFF, non-secure-boot image): needs RECIPES_UEFI_IMG + _PRIVKEY + RECIPES_OVMF_CODE/_VARS + sgdisk + /dev/kvm; run via `make boot-gate-uefi-usb`"]
fn uefi_usb_repro_boots_through_ovmf() {
    let (Ok(img), Ok(privkey), Ok(ovmf_code), Ok(ovmf_vars)) = (
        std::env::var("RECIPES_UEFI_IMG"),
        std::env::var("RECIPES_UEFI_PRIVKEY"),
        std::env::var("RECIPES_OVMF_CODE"),
        std::env::var("RECIPES_OVMF_VARS"),
    ) else {
        panic!(
            "uefi_usb_repro_boots_through_ovmf gate invoked (--ignored) without RECIPES_UEFI_IMG + \
             RECIPES_UEFI_PRIVKEY + RECIPES_OVMF_CODE + RECIPES_OVMF_VARS (+ sgdisk on PATH, /dev/kvm). \
             A boot gate must never pass without asserting."
        );
    };
    let opts = orchard::deploy::dryrun::DryrunOpts {
        ssh_port: 2223,
        https_port: 8444,
        ..Default::default()
    };
    orchard::deploy::dryrun::usb_repro_uefi_disk_and_observe(
        Path::new(&img),
        Path::new(&privkey),
        &opts,
        Path::new(&ovmf_code),
        Path::new(&ovmf_vars),
    )
    .expect("USB-assembled disk should boot through OVMF over USB/xHCI to services");
}

                                                                                              
                                                                                                        
                                                                                        
                                                                                                      
                                                                                            
                                                                          
                                                                     
                                                                                                      
                                                                                         
                                                                                                        
                                                                                                              
                                                                                                          
                                                                                       
                                                                                          
                                                                                                        
                                                                                              

/// Copy the SB img + ALL its sidecars into a scratch dir so a gate can sign/tamper its own copy
/// without disturbing the shared pre-built inputs. Returns the scratch `.img` path.
fn stage_sb_img_copy(env: &SbEnv, scratch: &Path) -> std::path::PathBuf {
    let dir = env.sb_img.parent().unwrap();
    let stem = env.sb_img.file_stem().unwrap().to_str().unwrap();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(stem))
        {
            std::fs::copy(&p, scratch.join(p.file_name().unwrap())).unwrap();
        }
    }
    scratch.join(env.sb_img.file_name().unwrap())
}

/// db-sign a staged img copy (the §9.2/§9.3b path) via `deploy sign-sb`.
fn sign_staged(env: &SbEnv, img: &Path) {
    orchard::deploy::sign_sb::sign_sb(&orchard::deploy::sign_sb::SignSbOpts {
        img: img.to_path_buf(),
        keys_dir: env.sb_keys_dir.parent().unwrap().to_path_buf(),
        rung: orchard::deploy::secure_boot_keys::SecureBootRung::Software,
        container_image: env.container_image.clone(),
        db_fingerprint_path: env.db_pin.clone(),
    })
    .expect("deploy sign-sb should db-sign + splice the boot PEs");
}

/// §9.2 — the SB thesis: a db-SIGNED loader+kernel, booted under ENFORCING OVMF (the `.secboot` CODE +
/// VARS enrolled from our PK/KEK/db), reaches services. The firmware verifies the loader, the loader's
/// `LoadImage` makes the firmware re-verify the kernel against db, the digest-gated initrd is served.
#[test]
#[ignore = "SB-ON boot gate (§9.2); needs the SB-ON env + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_boots_the_signed_chain() {
    let env = sb_env("uefi_sb_on_boots_the_signed_chain");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
    sign_staged(&env, &img);                                                   

                                                                                                  
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("virt-fw-vars should enroll our PK/KEK/db");

    orchard::deploy::dryrun::install_uefi_disk_and_verify(
        &img,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("SB-ON: the db-signed chain should boot through enforcing OVMF to services");
}

/// SB-ON USB reproduction — the FULL-fidelity laptop path: db-signed loader+kernel, ENFORCING OVMF
/// (enrolled VARS), the disk hand-assembled like `install-usb.sh` and booted over USB/xHCI (async
/// /dev/sda). This is the closest QEMU comes to what the laptop does; it exercises the SB chain AND the
/// async partuuid path together.
#[test]
#[ignore = "SB-ON USB repro gate; needs the SB-ON env + sgdisk + /dev/kvm; run via `make boot-gate-uefi-usb`"]
fn uefi_sb_on_usb_repro_boots_the_signed_chain() {
    let env = sb_env("uefi_sb_on_usb_repro_boots_the_signed_chain");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
    sign_staged(&env, &img);                                                   

    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("virt-fw-vars should enroll our PK/KEK/db");

    orchard::deploy::dryrun::usb_repro_uefi_disk_and_observe(
        &img,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("SB-ON USB: the db-signed chain should boot over USB/xHCI through enforcing OVMF to services");
}

/// §9.3a — an UNSIGNED loader, booted under enforcing OVMF, is REFUSED (no services), and the firmware
/// SIGNALS the Secure Boot rejection (`Access Denied` / `Security Violation` — not mere silence; the
                                                                                                         
/// the gate STRIPS the Authenticode signature from its own staged copy ([`unsign_esp_loader`]) to present a
/// genuinely-unsigned loader on the installed target — enforcing OVMF must then refuse it.
#[test]
#[ignore = "SB-ON negative gate (§9.3a); needs the SB-ON env + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_rejects_an_unsigned_loader() {
    let env = sb_env("uefi_sb_on_rejects_an_unsigned_loader");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
                                                                                                            
                                                                                                               
                                                                                                              
                                                                                              
    orchard::deploy::dryrun::unsign_esp_loader(&img)
        .expect("strip the loader's Authenticode signature so SB-ON must reject it");
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("enroll VARS");

    let console = orchard::deploy::dryrun::install_uefi_disk_expect_rejected(
        &img,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("SB-ON unsigned loader must be refused (no services)");
                                                                                                
                                                                                                             
                                                                                                        
                                                                                                            
                                                                                                              
                                                                                                   
                                                                                    
                                                                                          
    let lc = console.to_ascii_lowercase();
    let signalled = lc.contains("access denied") || lc.contains("security violation");
    assert!(
        signalled,
        "SB-ON unsigned-loader rejection must emit the Secure Boot refusal (Access Denied / Security \
         Violation); console was:\n{console}"
    );
}

/// §9.3d — a one-byte-tampered `\initrd` in the ESP makes the LOADER's SHA-256 gate halt (the
/// loader is db-signed + boots, but its baked digest no longer matches the served initrd). Distinct
                                                                                                  
#[test]
#[ignore = "SB-ON negative gate (§9.3d); needs the SB-ON env + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_halts_on_tampered_initrd() {
    let env = sb_env("uefi_sb_on_halts_on_tampered_initrd");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
    sign_staged(&env, &img);                                                                          
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("enroll VARS");

                                                                                                     
                                                                                   
    orchard::deploy::dryrun::tamper_esp_initrd(&img).expect("flip an initrd byte in the ESP");

    let console = orchard::deploy::dryrun::install_uefi_disk_expect_rejected(
        &img,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("SB-ON tampered initrd must halt the loader (no services)");
    assert!(
        console.contains("rambutan: initrd digest mismatch"),
        "the loader must print its initrd-digest-mismatch halt; console was:\n{console}"
    );
}

/// §9.3b — a signed loader + an UNSIGNED kernel: the firmware runs the db-signed loader, but its
/// `LoadImage(\vmlinuz)` re-verifies the swapped (unsigned) kernel against db, finds no signature, and
/// returns `EFI_SECURITY_VIOLATION` → the loader prints + halts, the kernel NEVER starts. The empirical
/// backstop for the most load-bearing mechanism fact in the spec (§3.2 step-5 / §12 item-1):
/// `LoadImage(SourceBuffer)` re-verifies even a memory load — the loader can't be tricked into running
/// an unverified kernel.
#[test]
#[ignore = "SB-ON negative gate (§9.3b); needs the SB-ON env + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_halts_on_unsigned_kernel() {
    let env = sb_env("uefi_sb_on_halts_on_unsigned_kernel");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
    sign_staged(&env, &img);                                                                         
                                                                                                          
                                                                   
    orchard::deploy::dryrun::replace_esp_vmlinuz_unsigned(&img)
        .expect("splice the unsigned kernel into the ESP");
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("enroll VARS");

    let console = orchard::deploy::dryrun::install_uefi_disk_expect_rejected(
        &img,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("SB-ON unsigned kernel must halt the loader at LoadImage (no services)");
    assert!(
        console.contains("rambutan: LoadImage(vmlinuz) refused"),
        "the loader must print its LoadImage-refused halt for the unsigned kernel; console was:\n{console}"
    );
}

/// §9.3c — a signed loader + a kernel signed by a NON-db key: distinct from §9.3b, the kernel IS validly
/// Authenticode-signed — just by a cert the firmware doesn't trust. `LoadImage` must STILL refuse it
/// (`EFI_SECURITY_VIOLATION` for a signed-but-untrusted image under EDK2 `DxeImageVerificationLib`),
/// proving the gate is db MEMBERSHIP, not "is it signed at all". Same loader halt as §9.3b.
#[test]
#[ignore = "SB-ON negative gate (§9.3c); needs the SB-ON env + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_halts_on_wrong_key_kernel() {
    let env = sb_env("uefi_sb_on_halts_on_wrong_key_kernel");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
    sign_staged(&env, &img);                                                                          
                                                                                                       
    orchard::deploy::dryrun::wrongkey_sign_vmlinuz_into_esp(&img, &env.container_image)
        .expect("wrong-key-sign + splice the kernel into the ESP");
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("enroll VARS");

    let console = orchard::deploy::dryrun::install_uefi_disk_expect_rejected(
        &img,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("SB-ON wrong-key kernel must halt the loader at LoadImage (no services)");
    assert!(
        console.contains("rambutan: LoadImage(vmlinuz) refused"),
        "the loader must refuse the wrong-key-signed kernel at LoadImage; console was:\n{console}"
    );
}

/// §9.3e — the loader IGNORES its own (attacker-injected) LoadOptions: the SOLE empirical proof of V4
                                                                                                         
/// kernel switches would break the loader's OWN cmdline delivery, so NO kernel-config belt is compatible
/// with this architecture; the closure rests entirely on the loader). Relocate the signed loader off the
/// default ESP path AND delete the default, then boot with a `Boot0001` whose OptionalData injects
/// `fb.injected=PWNED`. The box reaches services ONLY via `Boot0001` (anti-vacuity: no default path
/// to silently fall back to with empty LoadOptions) — so the loader provably ran WITH the injected
/// LoadOptions — and `/proc/cmdline` must STILL be the loader's baked const, the injection absent.
#[test]
#[ignore = "SB-ON V4 gate (§9.3e); needs the SB-ON env + python3/virt-firmware + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_ignores_injected_loadoptions() {
    let env = sb_env("uefi_sb_on_ignores_injected_loadoptions");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
    sign_staged(&env, &img);                                                    
                                                                                                        
                                                                                                     
    orchard::deploy::dryrun::relocate_esp_loader_off_default(&img)
        .expect("relocate the loader off the default ESP path");

                                                                                                       
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("enroll VARS");
    let injected = scratch.path().join("injected-VARS.fd");
    orchard::deploy::dryrun::build_injected_boot_vars(&enrolled, &injected, "fb.injected=PWNED")
        .expect("author the injected Boot0001");

    let cmdline = orchard::deploy::dryrun::install_uefi_disk_capture_cmdline(
        &img,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &injected,
    )
    .expect("the box must reach services via the injected Boot0001 (the default path is deleted)");

                                                                        
    assert!(
        !cmdline.contains("fb.injected") && !cmdline.contains("PWNED"),
        "injected LoadOptions must NOT reach the kernel; /proc/cmdline was:\n{cmdline}"
    );
                                                                                                          
                                                                           
    assert!(
        cmdline.contains("fb.firmware=uefi") && cmdline.contains("fb.root-hash="),
        "the baked cmdline must be present (loader-delivered, not the injection); /proc/cmdline was:\n{cmdline}"
    );
}

/// §9.3f — an `SB_REQUIRED=true` image booted on SB-OFF OVMF: the LOADER self-halts (its baked
/// `SB_REQUIRED` check reads SecureBoot!=1 and refuses) — proving the flag gates. Uses the SAME SB img
/// (SB_REQUIRED=true) but the PLAIN (non-enforcing) OVMF CODE + stock VARS.
#[test]
#[ignore = "SB-ON negative gate (§9.3f); needs RECIPES_OVMF_CODE (plain) + the SB env; run via `make boot-gate-uefi`"]
fn uefi_sb_required_image_halts_on_sb_off() {
    let env = sb_env("uefi_sb_required_image_halts_on_sb_off");
    let plain_code = std::env::var("RECIPES_OVMF_CODE")
        .expect("RECIPES_OVMF_CODE (the plain, non-secboot OVMF_CODE) for §9.3f");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
    sign_staged(&env, &img);                                                                           

    let console = orchard::deploy::dryrun::install_uefi_disk_expect_rejected(
        &img,
        &env.privkey,
        &sb_opts(),
        Path::new(&plain_code),
        &env.vars_template,                                               
    )
    .expect("SB_REQUIRED image on SB-OFF must self-halt (no services)");
    assert!(
        console.contains("rambutan: SB_REQUIRED but SecureBoot"),
        "the loader must print its SB_REQUIRED halt; console was:\n{console}"
    );
}

/// Offline precompute (§9.6): the host-key fingerprint derived from the image's baked seed + its
/// dm-verity root hash — the value the operator can compute without the box. The booted box's SERVICES
/// dropbear must present this exact key (the `services-keys-stage` oneshot uses the SAME
/// `derive-rescue-host-keys` derivation). `CARGO_BIN_EXE_orchard` is the test-built deploy binary.
fn expected_host_fp(img: &Path) -> String {
    let admin = env!("CARGO_BIN_EXE_orchard");
    let out = std::process::Command::new(admin)
        .args(["derive-rescue-offline", "--image"])
        .arg(img)
        .arg("--print-fingerprint")
        .output()
        .expect("run derive-rescue-host-keys --image --print-fingerprint");
    assert!(
        out.status.success(),
        "offline derive-rescue-host-keys failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .expect("a SHA256: fingerprint in the offline derive output")
        .to_string()
}

/// §9.6 — the build-identity handshake (carried bug-#7 regression gate). Boot the SB-ON box to services,
/// then assert its SERVICES dropbear host key equals the OFFLINE `derive-rescue-host-keys --image`
/// precompute. A match proves the cmdline-delivered `fb.root-hash` actually fed box-init's host-key
/// derivation — the box's cryptographic identity is bound to the exact rootfs the loader's baked cmdline
/// named (not some other fb.root-hash). Distinct from §9.2's "operator pubkey authenticates": this binds the
/// box's OWN identity to the verified rootfs.
#[test]
#[ignore = "SB-ON identity gate (§9.6); needs the SB-ON env + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_build_identity_handshake() {
    let env = sb_env("uefi_build_identity_handshake");
    let scratch = tempfile::tempdir().expect("scratch");
    let img = stage_sb_img_copy(&env, scratch.path());
    sign_staged(&env, &img);                                                      
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("enroll VARS");

                                                                                                         
    let expected = expected_host_fp(&img);

    let presented = orchard::deploy::dryrun::install_uefi_disk_capture_identity(
        &img,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("the SB-ON box must reach services and present an ed25519 host key");

    assert_eq!(
        presented, expected,
        "the box's services host key must equal the offline fb.root-hash-derived precompute \
         (cmdline-delivered fb.root-hash fed box-init's derivation); presented {presented}, expected {expected}"
    );
}
