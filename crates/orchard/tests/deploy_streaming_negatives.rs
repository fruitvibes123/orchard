                                                                                                 
                                                                    
//!
//! Four doomed variants per firmware arm, each booted through the REAL installer VM on a REAL
//! staged disk:
                                                                                                    
//!       digest pre-pass refuses (`does not match fb.image-sha256`).
                                                                                                  
//!       geometry gate refuses (`overlaps the install's`) strictly before any read of the window.
//!   (c) **fw-mismatch** (D3) — a hand-doctored `fb.image-layout=fw:…` disagreeing with
//!       `fb.firmware` → the box parse fails closed (`!= fb.firmware`). The v2 composer REFUSES to
//!       produce this append (composer-tested), so the leg crafts it by token surgery; the box must
//!       fail closed on an append it did not compose.
                                                                                                   
//!       (`fb.image-sha256 not set`), on the real cmdline through the real VM.
//!
//! Every leg asserts BOTH halves: the console carries the SPECIFIC `fb-init FATAL` reason, AND
//! LBA0 of the disk file is still all-zero — the produced-bytes analog of the unit suites'
//! `!did_destructive`. A refusal that already wrote the partition table would pass a
//! console-only assertion; it must not pass this one.
//!
//! Both firmware arms are gated because the two differ in exactly the places these legs probe: the
//! SeaBIOS arm byte-patches `fb.rootfs-dev` into the boot-fs while the BIOS+GPT arm carries a baked
//! PARTUUID, and leg (c)'s token surgery is per-arm. The production ceremony (`orchard prod`)
//! deploys `--firmware seabios-gpt`, so proving only the SeaBIOS arm would leave the arm that
//! actually ships unproven.
//!
//! Run via `make boot-gate-streaming-neg` (both arms, "exactly 2 passed"-guarded).

use std::path::Path;

/// SeaBIOS (MBR) arm — reuses the standard battery's reference `.img` (`RECIPES_PROD_IMG`), so the
/// firmware is declared by WHICH env var is set rather than by a separate, silently-mismatchable
/// firmware string. No operator privkey: these legs never reach a booted box.
///
                                                                                                   
/// reports "ignored" under the default run, executes only under `--ignored`, where a missing env
/// PANICS. No invocation reports success without asserting the produced bytes.
#[test]
#[ignore = "boot gate: needs RECIPES_PROD_IMG + /dev/kvm; run via `make boot-gate-streaming-neg`"]
fn streaming_negatives_fail_closed_seabios() {
    let Ok(img) = std::env::var("RECIPES_PROD_IMG") else {
        panic!(
            "streaming-negatives gate invoked (--ignored) without RECIPES_PROD_IMG — set it to the \
             SeaBIOS reference .img the standard battery uses (its sibling .layout.toml / .vmlinuz \
             / .initramfs must be present, /dev/kvm required), or run the gates via \
             `make boot-gate-streaming-neg`. A boot gate must never pass without asserting."
        );
    };
    orchard::deploy::dryrun::streaming_negative_legs(
        Path::new(&img),
        orchard::deploy::build_image::Firmware::Seabios,
        &orchard::deploy::dryrun::DryrunOpts::default(),
    )
    .expect(
        "every streaming negative leg must refuse with its SPECIFIC fb-init FATAL reason and leave \
         LBA0 zero (verify-before-write)",
    );
}

/// BIOS+GPT arm — the firmware the production `orchard prod` ceremony actually deploys. Keyed on
/// `RECIPES_SEABIOSGPT_IMG`, the same env the `boot-gate-seabios-gpt` arm uses.
///
                                                                                               
#[test]
#[ignore = "boot gate: needs RECIPES_SEABIOSGPT_IMG + /dev/kvm; run via `make boot-gate-streaming-neg`"]
fn streaming_negatives_fail_closed_seabios_gpt() {
    let Ok(img) = std::env::var("RECIPES_SEABIOSGPT_IMG") else {
        panic!(
            "streaming-negatives gate invoked (--ignored) without RECIPES_SEABIOSGPT_IMG — set it \
             to a `--firmware seabios-gpt` .img (its sibling .layout.toml / .vmlinuz / .initramfs \
             must be present, /dev/kvm required), or run the gates via \
             `make boot-gate-streaming-neg`. A boot gate must never pass without asserting."
        );
    };
    orchard::deploy::dryrun::streaming_negative_legs(
        Path::new(&img),
        orchard::deploy::build_image::Firmware::SeabiosGpt,
        &orchard::deploy::dryrun::DryrunOpts::default(),
    )
    .expect(
        "every streaming negative leg must refuse with its SPECIFIC fb-init FATAL reason and leave \
         LBA0 zero (verify-before-write)",
    );
}
