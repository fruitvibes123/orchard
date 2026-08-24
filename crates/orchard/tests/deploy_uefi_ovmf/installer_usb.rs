//! The §9.5 signed-USB INSTALLER gates: install from a signed USB onto a blank target under enforcing SB (+ the no-eligible / ambiguous / tamper / unsigned / install-to negatives).

use crate::common::*;
use std::path::Path;

                                                                                               
/// RECIPES_UEFI_SB_IMG via `deploy build-installer-usb` + `deploy sign-installer-usb` with the SAME SB
/// family, passed as RECIPES_INSTALLER_USB_IMG) installs the box onto a BLANK internal target under
/// ENFORCING OVMF; the target — USB detached — then boots runtime services under SB. The 2-stage
/// produced-bytes proof that the install-time TCB closes: firmware SB-verifies the installer loader →
/// it verifies box.img's baked digest before any write → the box.img lands on the independently
/// selected target → that target boots the signed runtime chain. Exercises the 5.2/5.3 CLIs' output.
#[test]
#[ignore = "SB-ON §9.5a installer-USB gate; needs the SB-ON env + RECIPES_INSTALLER_USB_IMG + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_installer_usb_installs_and_target_boots() {
    let env = sb_env("uefi_sb_on_installer_usb_installs_and_target_boots");
    let usb = std::env::var("RECIPES_INSTALLER_USB_IMG").unwrap_or_else(|_| {
        panic!(
            "uefi_sb_on_installer_usb_installs_and_target_boots (--ignored) without \
             RECIPES_INSTALLER_USB_IMG — set it to a db-signed `deploy build-installer-usb` + \
             `deploy sign-installer-usb` image (built off RECIPES_UEFI_SB_IMG with the SAME SB \
             family that RECIPES_SB_KEYS_DIR enrolls), or run via `make boot-gate-uefi`. A boot gate \
             must never pass without asserting."
        )
    });
    let scratch = tempfile::tempdir().expect("scratch");
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("virt-fw-vars should enroll our PK/KEK/db");

    orchard::deploy::dryrun::install_from_usb_and_verify_target(
        Path::new(&usb),
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("§9.5a: signed USB install → blank target boots runtime under enforcing SB");
}

/// The §9.5d/§9.5b negatives share this signed-USB + enrolled-VARS setup (the SAME
/// `RECIPES_INSTALLER_USB_IMG` as §9.5a). The installer loader IS db-signed (it boots under SB); the
/// fail-closed halt comes from the installer's own logic (target selection / digest), not the firmware.
fn installer_usb_and_enrolled(scratch: &Path) -> (std::path::PathBuf, SbEnv, std::path::PathBuf) {
    let env = sb_env("uefi_sb_on_installer_usb negative");
    let usb = std::env::var("RECIPES_INSTALLER_USB_IMG").unwrap_or_else(|_| {
        panic!(
            "the §9.5 installer-USB negative gates need RECIPES_INSTALLER_USB_IMG (the db-signed \
             build-installer-usb + sign-installer-usb image) — or run via `make boot-gate-uefi`. \
             A boot gate must never pass without asserting."
        )
    });
    let enrolled = scratch.join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("virt-fw-vars should enroll our PK/KEK/db");
    (std::path::PathBuf::from(usb), env, enrolled)
}

/// §9.5d (no eligible target) — the signed USB boots the installer, but with NO fixed internal disk
/// attached, target selection finds none eligible (the USB is excluded as the SOURCE disk — `!= source`,
                                                                                                        
/// fail-closed `fb-init FATAL` halt, no write. Proves the destructive path refuses to guess a target.
#[test]
#[ignore = "SB-ON §9.5d (no-eligible) gate; needs the SB-ON env + RECIPES_INSTALLER_USB_IMG + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_installer_usb_halts_with_no_eligible_target() {
    let scratch = tempfile::tempdir().expect("scratch");
    let (usb, env, enrolled) = installer_usb_and_enrolled(scratch.path());
    orchard::deploy::dryrun::install_from_usb_expect_halt(
        &usb,
        &[],                                                                                                         
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
        "no eligible internal target disk",
    )
    .expect("§9.5d: no eligible target → fail-closed halt before any write");
}

/// §9.5d (ambiguous) — TWO blank fixed disks → target selection is ambiguous → fail-closed halt, and
/// BOTH disks left byte-untouched. The H-1 safety: the installer never guesses WHICH of >1 eligible
/// disks to wipe (the operator must disambiguate with `fb.install-to`).
#[test]
#[ignore = "SB-ON §9.5d (ambiguous) gate; needs the SB-ON env + RECIPES_INSTALLER_USB_IMG + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_installer_usb_halts_on_ambiguous_target() {
    let scratch = tempfile::tempdir().expect("scratch");
    let (usb, env, enrolled) = installer_usb_and_enrolled(scratch.path());
    let t1 = scratch.path().join("target-1.img");
    let t2 = scratch.path().join("target-2.img");
    for t in [&t1, &t2] {
        std::fs::File::create(t)
            .and_then(|f| f.set_len(6 * 1024 * 1024 * 1024))
            .expect("blank target");
    }
    orchard::deploy::dryrun::install_from_usb_expect_halt(
        &usb,
        &[&t1, &t2],                                             
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
        "ambiguous target",
    )
    .expect("§9.5d: two eligible targets → fail-closed halt + both byte-untouched");
}

/// §9.5b — verify-before-write: a tampered `box.img` on the USB (its SHA-256 ≠ the loader-baked
/// `fb.image-sha256`) makes the installer fail-closed at the digest check BEFORE any write, leaving the
/// target byte-untouched. The destructive path's load-bearing safety: the box never writes an image it
/// could not verify against the signed loader's baked digest.
#[test]
#[ignore = "SB-ON §9.5b (verify-before-write) gate; needs the SB-ON env + RECIPES_INSTALLER_USB_IMG + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_installer_usb_halts_on_tampered_box_img() {
    let scratch = tempfile::tempdir().expect("scratch");
    let (usb, env, enrolled) = installer_usb_and_enrolled(scratch.path());
                                                                                       
    let tampered = scratch.path().join("tampered-installer-usb.img");
    std::fs::copy(&usb, &tampered).expect("copy the installer USB");
    orchard::deploy::dryrun::tamper_installer_usb_box_img(&tampered)
        .expect("flip a byte in the USB's box.img");
    let target = scratch.path().join("target.img");
    std::fs::File::create(&target)
        .and_then(|f| f.set_len(6 * 1024 * 1024 * 1024))
        .expect("blank target");
    orchard::deploy::dryrun::install_from_usb_expect_halt(
        &tampered,
        &[&target],
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
        "box.img SHA-256 does not match",
    )
    .expect("§9.5b: tampered box.img → digest-mismatch halt before any write; target untouched");
}

/// §9.5c — an UNSIGNED installer USB (built by `build-installer-usb` but NOT `sign-installer-usb`'d) is
/// REFUSED by enforcing SB: the firmware won't run the unsigned loader, the installer never starts, the
/// target is byte-untouched. `RECIPES_INSTALLER_USB_UNSIGNED_IMG` is that unsigned image (built off the
/// SAME runtime img). The SB-chain proof for the USB-booted installer loader (cf. §9.3a, same loader/db).
#[test]
#[ignore = "SB-ON §9.5c (unsigned-loader refusal) gate; needs the SB-ON env + RECIPES_INSTALLER_USB_UNSIGNED_IMG + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_installer_usb_unsigned_loader_refused() {
    let env = sb_env("uefi_sb_on_installer_usb_unsigned_loader_refused");
    let unsigned = std::env::var("RECIPES_INSTALLER_USB_UNSIGNED_IMG").unwrap_or_else(|_| {
        panic!(
            "the §9.5c gate needs RECIPES_INSTALLER_USB_UNSIGNED_IMG (a `build-installer-usb` image NOT \
             run through `sign-installer-usb`) — or run via `make boot-gate-uefi`. A boot gate must \
             never pass without asserting."
        )
    });
    let scratch = tempfile::tempdir().expect("scratch");
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("virt-fw-vars should enroll our PK/KEK/db");
    let target = scratch.path().join("target.img");
    std::fs::File::create(&target)
        .and_then(|f| f.set_len(6 * 1024 * 1024 * 1024))
        .expect("blank target");
    orchard::deploy::dryrun::install_from_usb_expect_firmware_refusal(
        Path::new(&unsigned),
        &target,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect("§9.5c: unsigned installer loader refused by enforcing SB; target untouched");
}

/// §9.5d (`fb.install-to`) — a `fb.install-to=vda`-baked installer USB with TWO eligible disks installs
/// to EXACTLY the named disk (the operator's disambiguation), leaving the other byte-untouched, and the
/// named disk boots runtime under SB. `RECIPES_INSTALLER_USB_INSTALLTO_IMG` is that signed USB
/// (`build-installer-usb --install-to vda` + `sign-installer-usb`).
#[test]
#[ignore = "SB-ON §9.5d (fb.install-to) gate; needs the SB-ON env + RECIPES_INSTALLER_USB_INSTALLTO_IMG + /dev/kvm; run via `make boot-gate-uefi`"]
fn uefi_sb_on_installer_usb_install_to_selects_named_disk() {
    let env = sb_env("uefi_sb_on_installer_usb_install_to_selects_named_disk");
    let usb = std::env::var("RECIPES_INSTALLER_USB_INSTALLTO_IMG").unwrap_or_else(|_| {
        panic!(
            "the §9.5d fb.install-to gate needs RECIPES_INSTALLER_USB_INSTALLTO_IMG (a db-signed \
             `build-installer-usb --install-to vda` image) — or run via `make boot-gate-uefi`. A boot \
             gate must never pass without asserting."
        )
    });
    let scratch = tempfile::tempdir().expect("scratch");
    let named = scratch.path().join("named-vda.img");                                                          
    let other = scratch.path().join("other-vdb.img");
    for t in [&named, &other] {
        std::fs::File::create(t)
            .and_then(|f| f.set_len(6 * 1024 * 1024 * 1024))
            .expect("blank target");
    }
    let enrolled = scratch.path().join("enrolled-VARS.fd");
    orchard::deploy::dryrun::build_enrolled_sb_vars(
        &env.sb_keys_dir,
        &env.vars_template,
        &enrolled,
    )
    .expect("virt-fw-vars should enroll our PK/KEK/db");
    orchard::deploy::dryrun::install_from_usb_to_named_and_verify(
        Path::new(&usb),
        &named,
        &other,
        &env.privkey,
        &sb_opts(),
        &env.secboot_code,
        &enrolled,
    )
    .expect(
        "§9.5d fb.install-to: installs to exactly the named disk; other untouched; named boots",
    );
}
