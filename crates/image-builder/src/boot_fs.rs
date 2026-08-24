                                                                                                      
//!
//! Under O3 the runtime kernel cmdline lives INSIDE the pre-baked boot partition filesystem's
//! `extlinux.conf` (baked at build time, not assembled by the on-box installer). This module hosts
//! the pure pieces of that:
//!
//! - [`render_boot_fs_extlinux`] — the slot-A `extlinux.conf` (the moved `installer::render_slot_a_extlinux`).
//!   It carries the exact runtime grammar `initramfs_init::cmdline::parse_cmdline` consumes (fb.root-hash +
//!   verity-hash-offset + rootfs-dev) plus the kernel-consumed defense triple. The build renders it from
//!   the build's OWN verity fb.root-hash + hash-tree offset, so a bug here would silently disable a defense
//!   layer on every runtime boot — it is locked host-side.
//! - [`ROOTFS_DEV_SENTINEL`] / [`ROOTFS_DEV_FIELD_WIDTH`] — `extlinux.conf` cannot hardcode the target's
//!   disk path (`sda2` vs `vda2` vs `nvme0n1p2`) at build time. The build bakes a fixed-WIDTH sentinel
//!   field; the deploy CLI (a `patch_rootfs_dev` in `recipes::deploy::prod`, landing with the deploy-prod
//!   flow in Tasks 8-12 — not yet implemented) locates it by content in the
//!   boot-fs slice and overwrites it length-preserving with the `findmnt`-resolved device — operator-side,
                                                                                                         
//!   Sound because stock ext4 does not checksum file DATA blocks: a length-preserving data-block edit
//!   leaves the filesystem valid + mountable.

use crate::firmware::Firmware;

/// The byte width of the `fb.rootfs-dev` VALUE field baked into the boot-fs `extlinux.conf`. The
/// deploy CLI overwrites exactly these bytes length-preserving, so it must be ≥ the longest real device
/// path. `/dev/nvme0n1p2` is 14 bytes; 24 leaves comfortable slack and keeps the patch a fixed-size edit.
pub const ROOTFS_DEV_FIELD_WIDTH: usize = 24;

/// The placeholder baked into the `fb.rootfs-dev=` field — a unique, whitespace-free ASCII string
/// the deploy CLI finds by content (exactly once) and overwrites with `<device> + space-padding`. It is
/// EXACTLY [`ROOTFS_DEV_FIELD_WIDTH`] bytes (the length-preserving overwrite contract, locked by a test).
/// Whitespace-free so the un-patched boot-fs still parses as a single (bogus) cmdline token rather than
/// splitting the APPEND.
pub const ROOTFS_DEV_SENTINEL: &str = "RECIPES_ROOTFS_DEV_PATCH";

/// The fixed kernel-consumed defense triple propagated into slot A's runtime APPEND (mirrors
/// `recipes::deploy::prod::DEFENSE_TRIPLE` + the old `installer::render_slot_a_extlinux`). Kept verbatim
/// so the box's runtime posture (lockdown + IMA appraise + ptrace_scope) survives every boot.
const DEFENSE_TRIPLE: &str =
    "ro lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2";

/// Kernel console for the runtime boot. BOTH the VGA console (`tty0` — what a hypervisor VNC console
/// like Infomaniak's shows) AND the serial console (`ttyS0` — a provider serial console, and what the
/// QEMU `-nographic` boot-gate captures). Kernel printk goes to both, so the operator can watch the box
/// boot (verity / IMA / network bring-up / service start) whichever out-of-band console the substrate
/// exposes. The serial port on a rented VPS is already substrate-accessible (the box is sacrificial on
/// rented HW), so this adds operator visibility without a new exposure. `ttyS0` is last → `/dev/console`.
const RUNTIME_CONSOLE: &str = "console=tty0 console=ttyS0";

/// The kernel `panic=<secs>` reboot token's seconds value, rendered into BOTH SeaBIOS
/// extlinux APPENDs (MBR + GPT) — NOT into [`render_uefi_cmdline`], which must stay
                                                                                     
/// R4-3; that is why this is a separate token and not part of [`DEFENSE_TRIPLE`]).
/// A panicking kernel (a bad update slot, a driver wedge) now REBOOTS after this many
/// seconds instead of hanging forever — the A/B rollback enabler (the reboot lands on
/// the loader, whose already-cleared BOOTONCE falls back to the committed `DEFAULT`
                                                                                  
/// change on every SeaBIOS box (operator-gated 2026-07-15); it silently masks
/// hang-as-signal gates, so `clean_reboot_and_verify` is migrated in the same cycle.
/// Tunable: long enough to read the panic on an OOB console, short enough to bound
/// the rollback's downtime.
const PANIC_REBOOT_SECS: u32 = 10;

/// x86-64 `COMMAND_LINE_SIZE` — the kernel's fixed cmdline buffer INCLUDING its NUL terminator, so
/// the usable payload is `COMMAND_LINE_SIZE - 1` bytes. `arch/x86/include/asm/setup.h`. The
/// cross-crate TWIN of `orchard::deploy::prod::COMMAND_LINE_SIZE` (the kexec installer composer's
                                                                                                
/// posture as [`DEFENSE_TRIPLE`].
const COMMAND_LINE_SIZE: usize = 2048;

                                                                              
                                                                                  
/// `COMMAND_LINE_SIZE` is one number, but each composer feeds a DIFFERENT downstream with its own
/// limit, its own transport overhead, and its own failure mode. A guard sized against the bare
/// composed string, or against the wrong consumer, admits a line the consumer silently truncates or
/// refuses.
///
/// - extlinux ([`render_boot_fs_extlinux`], syslinux 6.04-pre1): the kernel does NOT receive the
///   bare `APPEND`. syslinux wraps it — `com32/elflink/ldlinux/readconfig.c:426` builds `me->cmdline`
///   = `<LINUX-path> <APPEND> initrd=<INITRD-path>` and `com32/elflink/ldlinux/kernel.c:49` prepends
///   `BOOT_IMAGE=<LINUX-path> `, so the kernel sees
///   `BOOT_IMAGE=<LINUX-path> <APPEND> initrd=<INITRD-path>`. `com32/lib/syslinux/load_linux.c:235-238`
///   truncates that to the kernel's advertised `cmdline_max_len` = `COMMAND_LINE_SIZE-1`,
///   NUL-terminating at `[cmdline_size-1]`, so the surviving payload is `COMMAND_LINE_SIZE-2` = 2046
///   bytes. Guard the RECONSTRUCTED kernel-visible string ([`extlinux_kernel_visible`]) against 2046,
///   not the bare APPEND. `com32/elflink/ldlinux/execute.c:59` also refuses `me->cmdline` at `MAX_CMDLINE_LEN` = 2048,
///   a looser bound the 2046 ceiling already implies. The earlier `head64.c::copy_bootdata`
///   attribution was wrong for this path: the bootloader clamps before the kernel ever sees an
///   over-long line.
/// - UEFI ([`render_uefi_cmdline`], [`render_installer_cmdline`]): the loader (rambutan's `[u16; 2048]`
///   buffer at `vendor/rambutan/src/main.rs:88-91`, bounded by `encode_cmdline_ucs2` at
///   `vendor/rambutan/src/core.rs:14-17`, + the kernel EFI stub, which truncates at
///   `>= COMMAND_LINE_SIZE`) sees the cmdline verbatim, no transport prefix, and bounds it at
///   `COMMAND_LINE_SIZE-1` = 2047 (N-1: 2047 payload + NUL). Guard the composed string against 2047.
///
/// `--net` (extlinux + runtime UEFI) and `--install-to` (installer UEFI) are the reachable
/// variable-length inputs; both belts ([`render_net_token`], the installer belt) and `validate_net`
/// are charset-only, so length is enforced HERE. A built artifact must never silently ship a cmdline
/// its consumer will cut or refuse, so the render fails closed (a build panic, fix-on-presentation,
/// like [`render_net_token`]). `lockdown=integrity` / `ima_appraise=enforce` are compile-time forced
/// by the pinned kernel config (`CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y`,
/// `CONFIG_IMA_APPRAISE_BUILD_POLICY=y`, this crate's `tests/kernel_config_assert.rs`), so those tokens are
/// present regardless of the cmdline budget. No runtime cut reaches the APPEND tail on any path: on
/// extlinux a clamp lands inside the trailing `initrd=` clause only for a kernel-visible length in
/// `[2047, 2071]` (`load_linux.c:235-238`) and the build-time guard panics before any such render
/// ships, and the UEFI loader halts on an oversize cmdline. The guard's job is to refuse a build whose cmdline the
/// consumer would clamp or reject, not to protect any one token from a runtime cut.
///
                                                                                                    
/// ends `… {RUNTIME_CONSOLE} {DEFENSE_TRIPLE}` while `prod::build_installer_cmdline` ends
/// `… {DEFENSE_TRIPLE} {INSTALLER_CONSOLE}`. Both are bounded below their consumer's limit, so
/// neither can silently truncate; the token order is left byte-unchanged and `boot-gate-uefi` is
/// owed no re-proof this cycle.
const EXTLINUX_CMDLINE_CEIL: usize = COMMAND_LINE_SIZE - 2;                                               
const UEFI_CMDLINE_CEIL: usize = COMMAND_LINE_SIZE - 1;                               

/// Reconstruct the kernel-visible cmdline the syslinux extlinux path produces from an `APPEND`:
/// `BOOT_IMAGE=<kernel-path> <APPEND> initrd=<initrd-path>` (readconfig.c:426 + kernel.c:49, syslinux
/// 6.04-pre1), so the budget guard measures what the kernel receives, not the bare APPEND.
fn extlinux_kernel_visible(append: &str, kernel_path: &str, initrd_path: &str) -> String {
    format!("BOOT_IMAGE={kernel_path} {append} initrd={initrd_path}")
}

                                                                                                   
/// the downstream consumer receives; `ceiling` is that consumer's payload limit
/// ([`EXTLINUX_CMDLINE_CEIL`] or [`UEFI_CMDLINE_CEIL`]). Over-budget is a build panic, not a shipped
/// artifact the consumer would cut or reject. The panic names COMMAND_LINE_SIZE for grep-ability.
fn assert_cmdline_fits(measured: &str, ceiling: usize, what: &str) {
    assert!(
        measured.len() <= ceiling,
        "the {what} is {} bytes, over its {ceiling}-byte consumer budget (the consumer's payload \
         limit below the x86-64 COMMAND_LINE_SIZE of {COMMAND_LINE_SIZE}: N-1 for the UEFI loader, \
         N-2 for the syslinux extlinux path; any transport is added to the MEASURED string, not \
         subtracted from this ceiling) — the \
         downstream would not carry this cmdline whole: syslinux clamps the extlinux kernel-visible \
         line at its cmdline_max_len, and the UEFI loader halts on an oversize cmdline. The \
         `--net` / `--install-to` value is the only unbounded input here; shorten it. \
         measured cmdline: {measured:?}",
        measured.len()
    );
}

/// Render the optional `fb.net=<value> ` token (trailing space so it slots cleanly), the ONE
/// chokepoint both firmware renders go through. Asserts the operator value is a single non-empty
/// whitespace-free token (network spec C1): a space would split it into a second cmdline token — worst
/// case an attacker-shaped `fb.net=x ima_appraise=off` last-wins override — so a whitespace-bearing
                                                                                                       
/// the CLI, this is the fail-closed render-side belt, and it closes the gap that `vendor/rambutan/build.rs:46`'s
/// space-permitting cmdline check left open). `None` bakes no token (box-init diverts to rescue/link-only).
fn render_net_token(net: Option<&str>) -> String {
    match net {
        Some(value) => {
                                                                                                          
                                                                                                        
                                                                                                           
                                                                                                           
                                                                                                              
            assert!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic() && b != b'"'),
                "fb.net must be one non-empty token of printable non-quote ASCII, got {value:?}"
            );
            format!("fb.net={value} ")
        }
        None => String::new(),
    }
}

/// Render the dha weights cmdline triple (Component E) — `fb.weights-dev=PARTUUID=…` (the fixed
/// [`WEIGHTS_PARTUUID`]) + the build-derived `fb.weights-hash=…`/`fb.weights-offset=…`, with a trailing
/// space so it slots cleanly before the next token. `None` ⇒ empty (a non-dha image renders no weights
                                                                                                           
/// free-form, so — like `root_hash` — they carry no injection belt. The grammar matches
/// `initramfs_init::cmdline::parse_cmdline` exactly (the LOCKED E2 parse side).
fn render_weights_tokens(weights: Option<WeightsCmdline>) -> String {
    match weights {
        Some(w) => format!(
            "fb.weights-dev=PARTUUID={WEIGHTS_PARTUUID} fb.weights-hash={} fb.weights-offset={} ",
            w.verity_root_hash, w.verity_hash_offset
        ),
        None => String::new(),
    }
}

/// Render slot A's `extlinux.conf` for the pre-baked boot-fs (build time). `root_hash` is the dm-verity
/// root digest; `verity_hash_offset` is the byte offset where the hash tree begins inside the rootfs
/// partition (= the padded squashfs size). Both come from the BUILD (not a per-target cmdline), so the
/// APPEND is fixed at bake time EXCEPT the `rootfs-dev` value (and the `firmware` token). On SeaBIOS it
/// carries [`ROOTFS_DEV_SENTINEL`] for the deploy CLI to byte-patch + no firmware token (runtime defaults
/// to Seabios); on SeabiosGpt it carries the fixed baked `PARTUUID=`[`SLOT_A_PARTUUID`] +
                                                                                                           
/// the separate [`render_uefi_cmdline`]. The grammar matches `initramfs_init::cmdline::parse_cmdline` exactly.
///
/// `net` is the operator's `fb.net=` VALUE (e.g. `mode=static;ip=…;gw=…;dns=…`), baked here at
/// build time per network spec C1 ("the operator/installer bakes the per-slot value into the extlinux
/// APPEND") — realized as a build-tool option (`deploy build --net`) under the O3 pre-baked design,
/// since the boot-fs APPEND is now build-rendered (the box does NO autodetect; box-init reads
/// `/proc/cmdline`). It rides as ONE whitespace-free cmdline token (the `render_net_token` belt); `None`
/// bakes no token, in which case box-init parses no `fb.net=` and diverts to rescue/link-only
/// (`box-init lib.rs`). Unlike `rootfs-dev` (findmnt-resolved per target → byte-patched), the network
/// config is known at build, so it is baked rather than carrying its own sentinel. `mode=dhcp` is the
/// documented seam (build-A fail-closes it at bring-up, network spec C4).
pub fn render_boot_fs_extlinux(
    root_hash: &str,
    verity_hash_offset: u64,
    net: Option<&str>,
    firmware: Firmware,
    weights: Option<WeightsCmdline>,
) -> String {
                                                                                                     
                                                                                           
    let net_token = render_net_token(net);
    let weights_token = render_weights_tokens(weights);
                                                                                                           
                                                                                                            
                                                                                                         
                                                                                                  
                                                                                                     
                                                                                                        
                                                                                             
                                                                                                           
                                                                                                        
                                                                          
    match firmware {
        Firmware::Seabios => {
            let append = format!(
                "fb.root-hash={root_hash} fb.verity-hash-offset={verity_hash_offset} \
                 fb.rootfs-dev={ROOTFS_DEV_SENTINEL} {weights_token}{net_token}\
                 panic={PANIC_REBOOT_SECS} {DEFENSE_TRIPLE} {RUNTIME_CONSOLE}"
            );
            assert_cmdline_fits(
                &extlinux_kernel_visible(&append, "/slot-a/vmlinuz", "/slot-a/initramfs"),
                EXTLINUX_CMDLINE_CEIL,
                "SeaBIOS-MBR kernel-visible cmdline",
            );
            format!(
                "DEFAULT recipes\nPROMPT 0\nTIMEOUT 0\nLABEL recipes\n  LINUX /slot-a/vmlinuz\n  \
                 INITRD /slot-a/initramfs\n  APPEND {append}\n"
            )
        }
        Firmware::SeabiosGpt => {
                                                                                           
                                                                                             
            assert!(
                root_hash.len() == 64
                    && root_hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "seabios-gpt fixed geometry needs a 64 lowercase hex root hash, got {root_hash:?}"
            );
            assert!(
                verity_hash_offset < 1_000_000_000_000,
                "seabios-gpt fixed geometry needs a 12-digit-max verity offset, got {verity_hash_offset}"
            );
            let label = |slot: &str, partuuid: &str| {
                let append = format!(
                    "fb.firmware=seabios-gpt fb.root-hash={root_hash} \
                     fb.verity-hash-offset={verity_hash_offset:012} fb.rootfs-dev=PARTUUID={partuuid} \
                     {weights_token}{net_token}panic={PANIC_REBOOT_SECS} {DEFENSE_TRIPLE} {RUNTIME_CONSOLE}"
                );
                assert_cmdline_fits(
                    &extlinux_kernel_visible(
                        &append,
                        &format!("/{slot}/vmlinuz"),
                        &format!("/{slot}/initramfs"),
                    ),
                    EXTLINUX_CMDLINE_CEIL,
                    "SeaBIOS-GPT kernel-visible cmdline",
                );
                format!(
                    "LABEL {slot}\n  LINUX /{slot}/vmlinuz\n  INITRD /{slot}/initramfs\n  APPEND {append}\n"
                )
            };
            format!(
                "DEFAULT slot-a  \nPROMPT 0\nNOESCAPE 1\nTIMEOUT 30\n{}{}",
                label("slot-a", SLOT_A_PARTUUID),
                label("slot-b", SLOT_B_PARTUUID),
            )
        }
        Firmware::Uefi => {
            unreachable!(
                "UEFI uses render_uefi_cmdline (the rambutan loader cmdline), not extlinux"
            )
        }
    }
}

/// Parse the `fb.verity-hash-offset=<N>` value out of a rendered slot-A `extlinux.conf` — the
/// inverse of [`render_boot_fs_extlinux`]'s offset field. The build's H-1 assertion uses it to
/// re-read the offset ACTUALLY baked into the boot-fs APPEND and confirm it equals the `.img`
/// layout's `rootfs_verity_hash_offset` (a baked-but-wrong offset → the runtime dm-verity table reads
/// the hash tree at the wrong block → boot loop). Returns `None` if the field is absent/non-numeric.
pub fn parse_verity_hash_offset(extlinux_conf: &str) -> Option<u64> {
    extlinux_conf
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("fb.verity-hash-offset="))
        .and_then(|v| v.parse::<u64>().ok())
}

                                                                             
                                                                                         
                                                                                      

/// The slot-A partition's GPT PARTUUID — the literal baked into the rambutan loader's cmdline const
/// (`fb.rootfs-dev=PARTUUID=…`, [`render_uefi_cmdline`]) AND written onto the slot-A GPT entry by
/// `initramfs_init::installer::build_gpt`. It MUST equal `initramfs_init::installer::SLOT_A_PARTUUID`, but
/// `initramfs-init` is a standalone `panic=abort` workspace (not a dependency here), so the constant is
/// necessarily DUPLICATED (D3, the cross-crate convention-duplication class — same posture as
/// `prod::DEFENSE_TRIPLE`). A drift breaks every UEFI boot (the kernel resolves a PARTUUID no partition
/// carries → no rootfs). Pinned to the literal by `slot_a_partuuid_is_the_canonical_literal`.
pub const SLOT_A_PARTUUID: &str = "04c92659-e47a-485b-b840-fe5561eaa0da";

/// The slot-B partition's GPT PARTUUID — baked into the two-label seabios-gpt conf's label-b
                                                           
/// `initramfs_init::installer::SLOT_B_PARTUUID` (which writes the GPT entry + zeroes the
/// partition at install), but `initramfs-init` is a standalone workspace, so the constant is
/// DUPLICATED (D3 — same posture as [`SLOT_A_PARTUUID`]). A drift makes every updated
/// (slot-b) boot resolve a PARTUUID no partition carries → no rootfs. Pinned by
/// `slot_b_partuuid_is_the_canonical_literal`.
pub const SLOT_B_PARTUUID: &str = "a5dff702-a9ff-41a1-9243-30e6136aba95";

/// The dha weights partition's GPT PARTUUID (Component E, O4=(a) GPT — the 5th GPT partition inserted
/// between rootfs-B and persist). The literal written onto the weights GPT entry by
/// `initramfs_init::installer::build_gpt` AND baked into the runtime cmdline as
/// `fb.weights-dev=PARTUUID=…` (the init's `resolve_partuuid` resolves it against the on-disk GPT, the
/// same idiom the rootfs `fb.rootfs-dev` uses). It MUST byte-equal `initramfs_init::installer::WEIGHTS_PARTUUID`,
/// but `initramfs-init` is a standalone `panic=abort` workspace (not a dependency here), so the constant
/// is DUPLICATED (D3, same posture as [`SLOT_A_PARTUUID`]). A drift breaks the weights mount on every dha
/// boot (the init resolves a PARTUUID no partition carries → no weights volume → creatine read fails).
/// Pinned to the literal by `weights_partuuid_is_the_canonical_literal`; distinctness from the slot/installer
/// PARTUUIDs by `installer_partuuids_are_the_canonical_literals`.
pub const WEIGHTS_PARTUUID: &str = "7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35";

/// The dha weights volume's runtime cmdline values (Component E render side). The device token is the
/// fixed [`WEIGHTS_PARTUUID`] (always the 5th GPT partition under O4=(a) GPT), so only the build-derived
/// dm-verity pair varies: `verity_root_hash` (the weights volume's verity root digest) + `verity_hash_offset`
/// (the byte offset where the weights squashfs ends + its hash tree begins). Rendered into the boot cmdline
/// as `fb.weights-dev=PARTUUID=… fb.weights-hash=… fb.weights-offset=…` and parsed back by
/// `initramfs_init::cmdline::parse_cmdline` into its `WeightsConfig` (the LOCKED E2 grammar). `None` at a
                                                                             
#[derive(Debug, Clone, Copy)]
pub struct WeightsCmdline<'a> {
    pub verity_root_hash: &'a str,
    pub verity_hash_offset: u64,
}

/// §9.5 UEFI signed-USB installer: the fixed PARTUUIDs of the installer USB's two partitions —
/// `INSTALLER_ESP_PARTUUID` (p1, the FAT16 ESP carrying the installer loader + shared kernel + shared
/// initramfs) and `INSTALLER_DATA_PARTUUID` (p2, the ext4 partition carrying `box.img` + its layout).
/// Like [`SLOT_A_PARTUUID`] these are baked into the USB GPT entries by [`build_installer_usb`] (Task
/// 5.1). **`INSTALLER_DATA_PARTUUID` MUST byte-equal `initramfs_init::installer::INSTALLER_DATA_PARTUUID`**
                                                                                                          
/// workspace (not a dependency here), so the constant is DUPLICATED (same D3 convention-duplication as
/// `SLOT_A_PARTUUID`), pinned to the literal by `installer_partuuids_are_the_canonical_literals`. The ESP
/// PARTUUID is build-side-only (firmware finds the loader via `\EFI\BOOT\BOOTX64.EFI`, not a GUID), so it
/// has no cross-crate twin. Both are fresh v4 UUIDs, distinct from the slot/ESP/persist/disk GUIDs.
pub const INSTALLER_ESP_PARTUUID: &str = "456a0909-778c-4a27-994a-b03d125e3421";
pub const INSTALLER_DATA_PARTUUID: &str = "988794b1-f4c5-49a3-aebe-12b2dd91e58d";

/// Render the UEFI kernel cmdline — the string the rambutan loader bakes as its `KERNEL_CMDLINE`
/// const (SB-loader plan L4; consumed by `build_efi_loader` as `RECIPES_LOADER_CMDLINE`, set on the
/// kernel's `LoadOptions` at boot — V2: the cmdline lives inside the SIGNED loader, no kernel-config
/// involvement). The UEFI analog of the SeaBIOS extlinux APPEND ([`render_boot_fs_extlinux`]) and the
/// SAME runtime grammar `initramfs_init::cmdline::parse_cmdline` consumes on both firmwares: the
                                                                                                        
/// bytes), `fb.firmware=uefi` (→ the in-init firmware branch + the installer's GPT commit arm),
/// `fb.rootfs-dev=PARTUUID=`[`SLOT_A_PARTUUID`] (resolved against the on-disk GPT, NOT
/// byte-patched — build-fixed + GPT-written, unlike SeaBIOS's per-target [`ROOTFS_DEV_SENTINEL`]),
/// the defense triple, the operator `net` token, and both consoles. `net` is the operator's
/// `fb.net=` VALUE (one whitespace-free token; `None` bakes none → box-init diverts to
/// rescue/link-only, identical to the SeaBIOS render).
pub fn render_uefi_cmdline(
    root_hash: &str,
    verity_hash_offset: u64,
    net: Option<&str>,
    weights: Option<WeightsCmdline>,
) -> String {
                                                                                                           
    let net_token = render_net_token(net);
    let weights_token = render_weights_tokens(weights);
    let cmdline = format!(
        "fb.firmware=uefi fb.root-hash={root_hash} \
         fb.verity-hash-offset={verity_hash_offset} \
         fb.rootfs-dev=PARTUUID={SLOT_A_PARTUUID} \
         {weights_token}{DEFENSE_TRIPLE} {net_token}{RUNTIME_CONSOLE}"
    );
    assert_cmdline_fits(&cmdline, UEFI_CMDLINE_CEIL, "UEFI runtime cmdline");
    cmdline
}

/// Render the §9.5 UEFI signed-USB INSTALLER cmdline — the string the SECOND rambutan loader bakes as
/// its `KERNEL_CMDLINE` const (distinct from the runtime [`render_uefi_cmdline`] and the kexec
                                                                                                     
/// lowercase-hex SHA-256 of the whole signed `box.img` (the installer's verify-before-write target,
/// signature-covered as a loader const); the optional `fb.install-to=` whole-disk override; `fb.firmware=uefi`;
/// the verity pair (DEAD WEIGHT the installer never consumes, but `initramfs_init::cmdline::parse_cmdline`
/// requires a valid pair for any `BootConfig` — bake the `box.img`'s OWN root hash, never a placeholder);
/// both consoles (a HEADLESS install must show the §6 fail-closed-halt reason); the defense triple. There is
/// **no `fb.rootfs-dev`** (installer mode) and **no `fb.image-from`** (the source is the built-in
/// `INSTALLER_DATA_PARTUUID`, resolved by the init — §9.5 R2-1). Byte-grammar pinned by the `make verify`
/// golden.
pub fn render_installer_cmdline(
    image_sha256_hex: &str,
    root_hash: &str,
    verity_offset: u64,
    install_to: Option<&str>,
) -> String {
                                                                                                         
                                                                               
    let install_to_token =
        match install_to {
            Some(dev) => {
                                                                                                             
                                                                                                                
                                                                                                               
                                                                                                      
                                                                                                                 
                assert!(
                !dev.is_empty()
                    && dev.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "fb.install-to must be one bare lowercase-alphanumeric device token, got {dev:?}"
            );
                format!("fb.install-to={dev} ")
            }
            None => String::new(),
        };
    let cmdline = format!(
        "fb.mode=installer fb.image-sha256={image_sha256_hex} \
         {install_to_token}fb.firmware=uefi fb.root-hash={root_hash} \
         fb.verity-hash-offset={verity_offset} {RUNTIME_CONSOLE} {DEFENSE_TRIPLE}"
    );
                                                                                                   
                                                                                                       
                                                                                                  
    assert_cmdline_fits(&cmdline, UEFI_CMDLINE_CEIL, "UEFI installer cmdline");
    cmdline
}

/// §9.5 M-2: the 64-char lowercase-hex SHA-256 of the WHOLE signed `box.img` file — the value baked into
/// the installer loader's [`render_installer_cmdline`] `fb.image-sha256` token and re-checked by the
/// init's verify-before-write. Hashing the ENTIRE signed file (not a sub-range) is the build-side half of
/// the build==install equality: the init hashes the same whole file. Per-sign, NOT reproducible — the
/// signed-PE `signingTime` lives inside the hashed bytes — so no repro gate asserts rebuild-equality of
/// it. Mirrors the `initrd_sha256_hex` idiom in `build::build` (same crate, same `sha2 0.10`).
pub fn installer_image_sha256_hex(signed_img: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(signed_img))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_installer_cmdline_full_token_golden() {
                                                                                                     
                                                                                                    
                                                                                                      
                                                                                                           
        let sha = "ab".repeat(32);                                  
        let cmd = render_installer_cmdline(&sha, "deadbeef", 8192, None);
        assert_eq!(
            cmd,
            format!(
                "fb.mode=installer fb.image-sha256={sha} fb.firmware=uefi fb.root-hash=deadbeef \
                 fb.verity-hash-offset=8192 console=tty0 console=ttyS0 \
                 ro lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2"
            )
        );
                                                                                                  
                                                            
        assert!(!cmd.contains("fb.rootfs-dev"), "{cmd:?}");
        assert!(!cmd.contains("fb.image-from"), "{cmd:?}");

                                                                                                       
        let cmd2 = render_installer_cmdline(&sha, "deadbeef", 8192, Some("nvme0n1"));
        assert!(
            cmd2.starts_with(&format!(
                "fb.mode=installer fb.image-sha256={sha} fb.install-to=nvme0n1 fb.firmware=uefi"
            )),
            "{cmd2:?}"
        );
        assert!(cmd2.ends_with("console=tty0 console=ttyS0 ro lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2"));
    }

    #[test]
    #[should_panic(expected = "fb.install-to must be one bare")]
    fn render_installer_cmdline_panics_on_a_smuggling_install_to() {
                                                                                                      
                                                                                                       
                                                                                                   
        let sha = "ab".repeat(32);
        let _ = render_installer_cmdline(&sha, "deadbeef", 8192, Some("nvme0n1 ima_appraise=off"));
    }

    #[test]
    fn installer_image_sha256_hex_is_whole_file_and_feeds_the_cmdline() {
                                                                                                          
                                                                                                           
                                                                                                           
        let img = b"a pretend signed box.img with a signingTime inside".to_vec();
        let h = installer_image_sha256_hex(&img);
        assert_eq!(h.len(), 64, "64 hex chars");
        assert!(
            h.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "lowercase hex only: {h:?}"
        );
                                                                                       
        let flip = |i: usize| {
            let mut v = img.clone();
            v[i] ^= 0x01;
            installer_image_sha256_hex(&v)
        };
        assert_ne!(flip(0), h, "first byte is covered");
        assert_ne!(flip(img.len() - 1), h, "last byte is covered");
                                                          
        let cmd = render_installer_cmdline(&h, "deadbeef", 8192, None);
        assert!(cmd.contains(&format!("fb.image-sha256={h} ")), "{cmd:?}");
    }

    #[test]
    fn installer_partuuids_are_the_canonical_literals() {
                                                                     
                                                                                                         
                                                                                                      
        assert_eq!(
            INSTALLER_ESP_PARTUUID,
            "456a0909-778c-4a27-994a-b03d125e3421"
        );
        assert_eq!(
            INSTALLER_DATA_PARTUUID,
            "988794b1-f4c5-49a3-aebe-12b2dd91e58d"
        );
        let all = [
            SLOT_A_PARTUUID,
            INSTALLER_ESP_PARTUUID,
            INSTALLER_DATA_PARTUUID,
            WEIGHTS_PARTUUID,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "installer/slot PARTUUIDs must be distinct");
            }
        }
    }

    #[test]
    fn parse_verity_hash_offset_roundtrips_the_render() {
                                                                                                
        let conf = render_boot_fs_extlinux("deadbeef", 14_860_288, None, Firmware::Seabios, None);
        assert_eq!(parse_verity_hash_offset(&conf), Some(14_860_288));
                                                                                    
        assert_eq!(parse_verity_hash_offset("APPEND fb.root-hash=x ro"), None);
        assert_eq!(
            parse_verity_hash_offset("APPEND fb.verity-hash-offset=notanumber ro"),
            None
        );
    }

    #[test]
    fn sentinel_is_exactly_the_field_width() {
                                                                                                   
                                                                      
        assert_eq!(ROOTFS_DEV_SENTINEL.len(), ROOTFS_DEV_FIELD_WIDTH);
    }

    #[test]
    fn sentinel_is_whitespace_free_and_unique_shaped() {
                                                                                                       
                                                                               
        assert!(!ROOTFS_DEV_SENTINEL.bytes().any(|b| b.is_ascii_whitespace()));
        assert!(ROOTFS_DEV_SENTINEL.starts_with("RECIPES_"));
    }

    #[test]
    fn extlinux_conf_carries_root_hash_offset_sentinel_and_defense_triple() {
        let conf = render_boot_fs_extlinux("deadbeef", 8192, None, Firmware::Seabios, None);
        assert!(conf.contains("fb.root-hash=deadbeef"), "{conf:?}");
        assert!(conf.contains("fb.verity-hash-offset=8192"), "{conf:?}");
        assert!(
            conf.contains(&format!("fb.rootfs-dev={ROOTFS_DEV_SENTINEL}")),
            "{conf:?}"
        );
        assert!(
            conf.contains(
                "ro lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2"
            ),
            "{conf:?}"
        );
                                                                                                 
        assert_eq!(conf.matches(ROOTFS_DEV_SENTINEL).count(), 1);
                                                                                                       
        assert!(conf.contains("console=tty0 console=ttyS0"), "{conf:?}");
                                                                                                       
        assert!(!conf.contains("fb.net="), "{conf:?}");
                                                                                                
        assert!(conf.contains("LINUX /slot-a/vmlinuz"));
        assert!(conf.contains("INITRD /slot-a/initramfs"));
    }

    #[test]
    fn seabios_gpt_append_carries_firmware_token_and_baked_partuuid_no_sentinel() {
                                                                                                     
                                                               
        let hex = "ab".repeat(32);
        let conf = render_boot_fs_extlinux(&hex, 8192, None, Firmware::SeabiosGpt, None);
        assert!(conf.contains("fb.firmware=seabios-gpt"), "{conf:?}");
        assert!(
            conf.contains(&format!("fb.rootfs-dev=PARTUUID={SLOT_A_PARTUUID}")),
            "{conf:?}"
        );
        assert!(
            !conf.contains(ROOTFS_DEV_SENTINEL),
            "SeabiosGpt bakes the PARTUUID, never the deploy sentinel: {conf:?}"
        );
                                                                                     
                                                                                
        assert!(conf.contains(&format!("fb.root-hash={hex}")), "{conf:?}");
        assert!(
            conf.contains("fb.verity-hash-offset=000000008192"),
            "{conf:?}"
        );
        assert!(conf.contains("ima_appraise=enforce"), "{conf:?}");
                                                                                             
        assert_eq!(parse_verity_hash_offset(&conf), Some(8192));
    }

    #[test]
    fn seabios_append_is_byte_unchanged_by_the_firmware_param() {
                                                                                                 
                                                       
        let conf = render_boot_fs_extlinux("deadbeef", 8192, None, Firmware::Seabios, None);
        assert!(
            !conf.contains("fb.firmware="),
            "SeaBIOS bakes no firmware token: {conf:?}"
        );
        assert!(
            conf.contains(&format!("fb.rootfs-dev={ROOTFS_DEV_SENTINEL}")),
            "{conf:?}"
        );
    }

    #[test]
    fn append_is_one_logical_line_with_single_spaces() {
                                                                                                     
                                                                                                  
                                                                                              
        let conf = render_boot_fs_extlinux("ab", 4096, None, Firmware::Seabios, None);
        let append = conf
            .lines()
            .find_map(|l| l.trim().strip_prefix("APPEND "))
            .expect("an APPEND line");
        assert!(
            !append.contains("  "),
            "no double spaces in the APPEND: {append:?}"
        );
                                                                          
        assert!(append.contains(&format!("fb.rootfs-dev={ROOTFS_DEV_SENTINEL} panic=10 ro ")));
    }

    #[test]
    fn append_bakes_recipes_net_when_present() {
                                                                                                
                                                                                                    
                                                                                                
        let net = "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3";
        let conf = render_boot_fs_extlinux("ab", 4096, Some(net), Firmware::Seabios, None);
        let append = conf
            .lines()
            .find_map(|l| l.trim().strip_prefix("APPEND "))
            .expect("an APPEND line");
        assert!(!append.contains("  "), "no double spaces: {append:?}");
        assert!(
            append.contains(&format!(
                "fb.rootfs-dev={ROOTFS_DEV_SENTINEL} fb.net={net} panic=10 ro "
            )),
            "net token slots between the sentinel and panic/defense: {append:?}"
        );
                                                                                                     
                                                                                                    
        assert_eq!(conf.matches(ROOTFS_DEV_SENTINEL).count(), 1);
        assert!(
            append
                .split_whitespace()
                .any(|t| t == format!("fb.net={net}")),
            "fb.net is a single token: {append:?}"
        );
    }

                                                                                                     
                                                                                                         
                                                                                                  
                                                                                                    
                                                                                                         
                                                                                                          
                                                                                  
    #[test]
    #[should_panic(expected = "printable non-quote ASCII")]
    fn net_with_space_panics_the_seabios_render() {
        let _ = render_boot_fs_extlinux(
            "ab",
            4096,
            Some("mode=static ima_appraise=off"),
            Firmware::Seabios,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "printable non-quote ASCII")]
    fn net_with_vertical_tab_panics_the_uefi_render() {
        let _ = render_uefi_cmdline("ab", 4096, Some("mode=static\u{0b}x"), None);
    }

    #[test]
    #[should_panic(expected = "printable non-quote ASCII")]
    fn net_with_0xa0_carrier_byte_panics() {
                                                                                                                
                                                                                                   
        let _ = render_uefi_cmdline("ab", 4096, Some("mode=static;dns=à"), None);
    }

    #[test]
    #[should_panic(expected = "printable non-quote ASCII")]
    fn net_with_quote_panics() {
                                                                                                    
                                                                                                        
        let _ = render_boot_fs_extlinux(
            "ab",
            4096,
            Some("mode=static;x=\"y"),
            Firmware::Seabios,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "printable non-quote ASCII")]
    fn empty_net_panics() {
        let _ = render_uefi_cmdline("ab", 4096, Some(""), None);
    }

                                                                                                  
                                                                                                 
                                                                                                     
                                                                                                     
                                                                                               
                                                                                                       
    fn overflowing_net() -> String {
        format!("mode=static;pad={}", "x".repeat(2500))
    }

    #[test]
    #[should_panic(expected = "COMMAND_LINE_SIZE")]
    fn long_net_overflows_the_seabios_mbr_append_guard() {
        let _ = render_boot_fs_extlinux(
            "ab",
            4096,
            Some(&overflowing_net()),
            Firmware::Seabios,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "COMMAND_LINE_SIZE")]
    fn long_net_overflows_the_seabios_gpt_append_guard() {
        let hex = "ab".repeat(32);
        let _ = render_boot_fs_extlinux(
            &hex,
            4096,
            Some(&overflowing_net()),
            Firmware::SeabiosGpt,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "COMMAND_LINE_SIZE")]
    fn long_net_overflows_the_uefi_cmdline_guard() {
        let _ = render_uefi_cmdline("ab", 4096, Some(&overflowing_net()), None);
    }

    #[test]
    fn a_realistic_net_value_stays_within_the_cmdline_budget() {
                                                                                                    
                                                                                               
                                                                                               
                                                                          
        let net = "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3;dns=10.0.2.4";
        let mbr = render_boot_fs_extlinux("ab", 4096, Some(net), Firmware::Seabios, None);
        assert!(mbr.contains(&format!("fb.net={net}")), "{mbr:?}");
        let hex = "ab".repeat(32);
        let gpt = render_boot_fs_extlinux(&hex, 4096, Some(net), Firmware::SeabiosGpt, None);
        assert!(gpt.contains(&format!("fb.net={net}")), "{gpt:?}");
        let uefi = render_uefi_cmdline("ab", 4096, Some(net), None);
        assert!(uefi.contains(&format!("fb.net={net}")), "{uefi:?}");
                                                                                            
        for dev in ["nvme0n1", "sda", "vda", "mmcblk0"] {
            let inst = render_installer_cmdline(&hex, &hex, 4096, Some(dev));
            assert!(inst.contains(&format!("fb.install-to={dev} ")), "{inst:?}");
        }
    }

    #[test]
    fn uefi_cmdline_carries_the_verity_pair_and_partuuid() {
                                                                                                
                                                                                                     
                                                                                                
                                                     
        let hex = "ab".repeat(32);
        let cmd = render_uefi_cmdline(&hex, 8192, None, None);
        assert!(cmd.contains(&format!("fb.root-hash={hex}")), "{cmd:?}");
        assert!(cmd.contains("fb.verity-hash-offset=8192"), "{cmd:?}");
        assert!(cmd.contains("fb.firmware=uefi"), "{cmd:?}");
        assert!(
            cmd.contains(&format!("fb.rootfs-dev=PARTUUID={SLOT_A_PARTUUID}")),
            "{cmd:?}"
        );
        assert!(
            cmd.contains(
                "ro lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2"
            ),
            "defense triple present: {cmd:?}"
        );
        assert!(cmd.contains("console=tty0 console=ttyS0"), "{cmd:?}");
        assert!(!cmd.contains("fb.net="), "no net token when None: {cmd:?}");
        assert!(!cmd.contains("  "), "single-spaced: {cmd:?}");
                                                                                              
                                                                            
        assert_eq!(parse_verity_hash_offset(&cmd), Some(8192));
                                                                                               
                                                                                        
        assert!(!cmd.contains("initrd="), "{cmd:?}");
    }

    #[test]
    fn render_uefi_cmdline_bakes_net_as_one_token_between_defense_and_console() {
        let net = "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3";
        let cmd = render_uefi_cmdline("ab", 4096, Some(net), None);
        assert!(!cmd.contains("  "), "single-spaced: {cmd:?}");
                                                                                                       
                                                                            
        assert!(
            cmd.split_whitespace().any(|t| t == format!("fb.net={net}")),
            "fb.net is a single token: {cmd:?}"
        );
        assert!(cmd.contains(&format!("ptrace_scope=2 fb.net={net} console=tty0")));
    }

    #[test]
    fn seabios_gpt_extlinux_two_label_geometry() {
                                                                                  
                                                                                         
                                                                                     
                                                                                      
                                                                                     
                                                                                   
        let hex = "ab".repeat(32);
        let conf = render_boot_fs_extlinux(&hex, 8192, None, Firmware::SeabiosGpt, None);

                                                       
        let labels: Vec<&str> = conf.lines().filter(|l| l.starts_with("LABEL ")).collect();
        assert_eq!(labels, ["LABEL slot-a", "LABEL slot-b"], "{conf:?}");

                                                                                    
                                                                                    
        let first = conf.lines().next().unwrap();
        assert_eq!(first, "DEFAULT slot-a  ");
        assert_eq!(first.len(), "DEFAULT ".len() + 8);

        assert!(conf.contains("\nPROMPT 0\n"), "{conf:?}");
        assert!(conf.contains("\nNOESCAPE 1\n"), "{conf:?}");
        assert!(conf.contains("\nTIMEOUT 30\n"), "{conf:?}");

                                                                                  
                                                    
        let appends: Vec<&str> = conf
            .lines()
            .filter_map(|l| l.trim().strip_prefix("APPEND "))
            .collect();
        assert_eq!(appends.len(), 2, "{conf:?}");
        for a in &appends {
            assert!(a.contains("fb.firmware=seabios-gpt "), "{a:?}");
            assert!(a.contains("panic=10 ro "), "{a:?}");
            assert!(a.contains(&format!("fb.root-hash={hex} ")), "{a:?}");
            assert!(a.contains("fb.verity-hash-offset=000000008192 "), "{a:?}");
            assert!(!a.contains("  "), "single-spaced: {a:?}");
            assert!(a.contains("console=tty0 console=ttyS0"), "{a:?}");
        }
        assert!(
            appends[0].contains(&format!("fb.rootfs-dev=PARTUUID={SLOT_A_PARTUUID}")),
            "{:?}",
            appends[0]
        );
        assert!(
            appends[1].contains(&format!("fb.rootfs-dev=PARTUUID={SLOT_B_PARTUUID}")),
            "{:?}",
            appends[1]
        );

                                                     
        for line in [
            "  LINUX /slot-a/vmlinuz\n",
            "  INITRD /slot-a/initramfs\n",
            "  LINUX /slot-b/vmlinuz\n",
            "  INITRD /slot-b/initramfs\n",
        ] {
            assert!(conf.contains(line), "{conf:?}");
        }

                                                                               
        assert_eq!(parse_verity_hash_offset(&conf), Some(8192));
    }

    #[test]
    #[should_panic(expected = "64 lowercase hex")]
    fn seabios_gpt_render_panics_on_a_short_root_hash() {
                                                                                        
                                                                                       
                                                      
        let _ = render_boot_fs_extlinux("deadbeef", 8192, None, Firmware::SeabiosGpt, None);
    }

    #[test]
    #[should_panic(expected = "12-digit")]
    fn seabios_gpt_render_panics_on_an_offset_wider_than_12_digits() {
        let hex = "ab".repeat(32);
        let _ = render_boot_fs_extlinux(&hex, 1_000_000_000_000, None, Firmware::SeabiosGpt, None);
    }

    #[test]
    fn seabios_mbr_gets_panic10_not_two_label() {
                                                                                      
                                                                                      
                                              
        let conf = render_boot_fs_extlinux("deadbeef", 8192, None, Firmware::Seabios, None);
        assert_eq!(
            conf.lines().filter(|l| l.starts_with("LABEL ")).count(),
            1,
            "{conf:?}"
        );
        assert!(conf.starts_with("DEFAULT recipes\n"), "{conf:?}");
        assert!(
            conf.contains("\nTIMEOUT 0\n"),
            "MBR keeps TIMEOUT 0: {conf:?}"
        );
        assert!(!conf.contains("NOESCAPE"), "{conf:?}");
        assert!(conf.contains("panic=10 ro "), "{conf:?}");
        assert!(
            conf.contains(&format!("fb.rootfs-dev={ROOTFS_DEV_SENTINEL}")),
            "{conf:?}"
        );
                                                                  
        assert!(conf.contains("fb.verity-hash-offset=8192 "), "{conf:?}");
        assert!(!conf.contains("fb.verity-hash-offset=000"), "{conf:?}");
    }

    #[test]
    fn uefi_render_byte_unchanged() {
                                                                                    
                                                                               
                                                                                      
                                                                                    
        let hex = "ab".repeat(32);
        let cmd = render_uefi_cmdline(&hex, 8192, None, None);
        assert_eq!(
            cmd,
            format!(
                "fb.firmware=uefi fb.root-hash={hex} fb.verity-hash-offset=8192 \
                 fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da \
                 ro lockdown=integrity ima_appraise=enforce \
                 sysctl.kernel.yama.ptrace_scope=2 console=tty0 console=ttyS0"
            )
        );
        assert!(!cmd.contains("panic="), "{cmd:?}");
    }

    #[test]
    fn slot_b_partuuid_is_the_canonical_literal() {
                                                                                     
                                                                                       
                                                                         
        assert_eq!(SLOT_B_PARTUUID, "a5dff702-a9ff-41a1-9243-30e6136aba95");
    }

    #[test]
    fn slot_a_partuuid_is_the_canonical_literal() {
                                                                                                           
                                                                                                          
                                                                                                          
        assert_eq!(SLOT_A_PARTUUID, "04c92659-e47a-485b-b840-fe5561eaa0da");
    }

    #[test]
    fn weights_partuuid_is_the_canonical_literal() {
                                                                                                
                                                                                                   
                                                                                                       
                                                                                                           
                                                                                              
        assert_eq!(WEIGHTS_PARTUUID, "7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35");
    }

    #[test]
    fn seabios_gpt_append_carries_the_weights_triple_when_present() {
                                                                                           
                                                                                                       
                                                                                                    
                                                                                        
        let w = WeightsCmdline {
            verity_root_hash: "cafef00d",
            verity_hash_offset: 2_097_152,
        };
        let hex = "ab".repeat(32);
        let conf = render_boot_fs_extlinux(&hex, 8192, None, Firmware::SeabiosGpt, Some(w));
        assert!(
            conf.contains(&format!(
                "fb.weights-dev=PARTUUID={WEIGHTS_PARTUUID} fb.weights-hash=cafef00d \
                 fb.weights-offset=2097152"
            )),
            "{conf:?}"
        );
                                                                                       
        let append = conf
            .lines()
            .find_map(|l| l.trim().strip_prefix("APPEND "))
            .expect("an APPEND line");
        assert!(!append.contains("  "), "no double spaces: {append:?}");
    }

    #[test]
    fn weights_tokens_absent_when_none_ac2() {
                                                                                                        
                                                                                                   
        let hex = "ab".repeat(32);
        let seabios = render_boot_fs_extlinux(&hex, 8192, None, Firmware::SeabiosGpt, None);
        assert!(!seabios.contains("fb.weights-"), "{seabios:?}");
        let uefi = render_uefi_cmdline("deadbeef", 8192, None, None);
        assert!(!uefi.contains("fb.weights-"), "{uefi:?}");
    }

    #[test]
    fn uefi_cmdline_carries_the_weights_triple_when_present() {
                                                                                              
        let w = WeightsCmdline {
            verity_root_hash: "cafef00d",
            verity_hash_offset: 2_097_152,
        };
        let cmd = render_uefi_cmdline("deadbeef", 8192, None, Some(w));
        assert!(
            cmd.contains(&format!(
                "fb.weights-dev=PARTUUID={WEIGHTS_PARTUUID} fb.weights-hash=cafef00d \
                 fb.weights-offset=2097152"
            )),
            "{cmd:?}"
        );
        assert!(!cmd.contains("  "), "single-spaced: {cmd:?}");
    }
}

/// The per-consumer cmdline-budget FLOOR, extracted via `#[path]` like `orchard`'s
/// `prod_tests.rs`: it needs this module's private `EXTLINUX_CMDLINE_CEIL` / `UEFI_CMDLINE_CEIL` to
/// freeze them, and it is one self-contained concern an audit lens can read without the renderers.
#[cfg(test)]
#[path = "boot_fs_cmdline_budget_tests.rs"]
mod boot_fs_cmdline_budget_tests;
