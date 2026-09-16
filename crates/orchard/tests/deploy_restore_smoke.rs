//! Task 4.3 / AC1+AC2+AC8 — the restore-from PRODUCED-BYTES gate (upgraded from the C1 verify gate).
//!
//! Env-gated AND `#[ignore]`d (heavy: a built `.img`, a container-assembled ≥64 MiB restore image,
//! seven QEMU installer runs + one full boot; needs /dev/kvm + docker). ONE `#[test]` by design —
//! the Makefile's fail-closed M-α guard greps `"test result: ok. 1 passed"` (orchard Makefile:171);
//! splitting into more `#[test]`s without bumping that guard fail-closed-blocks the whole boot gate.
//!
//! It proves on PRODUCED BYTES — the real `.img`, the real on-box installer, real block devices,
//! the REAL `orchard restore-image` assembly — that:
//!   - a realistic (≥64 MiB, blob+small-file+sentinel) ASSEMBLED restore image, signed by the baked
//!     anchor and run AT-FLOOR (`fb.min-ctr` == its bundle ctr), installs; the booted box carries
//!     the exact content (nonce sentinel bytes, manifest size/owner spot-checks, ≥400 tenant files),
//!     the persist fs GREW past the baked size (the first-boot grow), `findfs LABEL=persist`
//!     resolves (the §3a identity), and recipes serves;
//!   - SIX refusal classes each FATAL-abort in 7.pre with the target disk **byte-untouched**
//!     (whole-disk hash PRE == POST): wrong-key, tampered sig, over-cap (the §4b-1 RAM-aware cap),
//!     not-ext4 (the SIGNED daily tar passed as the image, C-R2-5), journal-present (§4b-3), and
//!     min-ctr-below-floor (quince CounterRollback — AC8's refuse half).
//!
//! (The exceeds-partition fit check is topology-impossible to stage here — the restore rides the
//! SAME disk the installer repartitions — and is pinned by the initramfs-init call-log unit.)
//!
//! Build a SeaBIOS `.img` with an SSH operator pubkey, the QEMU user-net addressing, AND an artifact
//! key set in its keys-dir (the restore trust anchor), then point the gate at it:
//!   orchard generate-keys --artifact-signing software --output-dir <keys>   # mints artifact-root.pub
//!   orchard build --domain box.test --keys-dir <keys> \
//!     --operator-pubkey <key.pub> \
//!     --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" \
//!     --out-dir <dir> --allow-dirty
//!   RECIPES_RESTORE_IMG=<dir>/<img>.img RECIPES_RESTORE_PRIVKEY=<key> RECIPES_RESTORE_KEYS_DIR=<keys> \
//!     cargo test -p orchard --test deploy_restore_smoke -- --ignored --nocapture
//! (the sibling `<stem>.layout.toml` + `<stem>.vmlinuz` + `<stem>.initramfs` must sit beside the
//! `.img`; KVM at /dev/kvm; docker for the in-gate assembly). RECIPES_RESTORE_KEYS_DIR MUST be the
//! SAME keys-dir the `.img` was built with. Operator-run via `make boot-gate`; never a false green.

use std::path::Path;

/// The env (a built `.img` with a baked artifact-root.pub + SSH operator key + net, the matching SSH
/// private key, and the artifact keys-dir the `.img` was baked with) the gate needs. PANICS if absent
                                                                                             
/// (`make boot-gate`); a missing env there is an operator error, never a silent pass — a boot gate must
/// never report success without asserting the produced bytes.
fn gate_env() -> (String, String, String) {
    match (
        std::env::var("RECIPES_RESTORE_IMG"),
        std::env::var("RECIPES_RESTORE_PRIVKEY"),
        std::env::var("RECIPES_RESTORE_KEYS_DIR"),
    ) {
        (Ok(img), Ok(privkey), Ok(keys_dir)) => (img, privkey, keys_dir),
        _ => panic!(
            "deploy_restore_smoke gate invoked (--ignored) without RECIPES_RESTORE_IMG + \
             RECIPES_RESTORE_PRIVKEY + RECIPES_RESTORE_KEYS_DIR — set them to a .img built with \
             --operator-pubkey + --net + --keys-dir <artifact-key-set> (the matching SSH privkey, and \
             that SAME keys-dir; /dev/kvm), or run the gates via `make boot-gate`. A boot gate must \
             never pass without asserting."
        ),
    }
}

#[test]
#[ignore = "boot gate: needs RECIPES_RESTORE_IMG + RECIPES_RESTORE_PRIVKEY + RECIPES_RESTORE_KEYS_DIR + /dev/kvm; run via `make boot-gate`"]
fn restore_from_verifies_before_any_write_on_produced_bytes() {
    let (img, privkey, keys_dir) = gate_env();
    orchard::deploy::dryrun::install_restore_from_and_verify(
        Path::new(&img),
        Path::new(&privkey),
        Path::new(&keys_dir),
                                                     
        &orchard::ceremony::leg_registry::restore_from_opts(),
    )
    .expect(
        "restore-from gate: the assembled at-floor restore must install with its exact content \
         (sentinel/manifest/grown/label) and recipes serving, and the six refusal classes \
         (wrong-key / tampered / over-cap / not-ext4 / journal-present / min-ctr-below-floor) \
         must each abort the installer BEFORE any write (target disk byte-untouched)",
    );
                                                                                                  
                                                                                                 
                                                               
    orchard::ceremony::gate_record::emit_leg_pass(
        Path::new(&img),
        "restore_from_verifies_before_any_write_on_produced_bytes",
    )
    .expect("emit this leg's gate-record row");
}
