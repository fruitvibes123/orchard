//! The per-consumer kernel-cmdline budget FLOOR for the sibling `boot_fs.rs` (the audit floor,
                                                                                                
//! `#[path]` like `orchard`'s `prod_tests.rs`.
//!
                                                                                                 
//! runtime composer. What they do NOT hold, mutation-proven in that report: the BOUNDARY. Their
//! 2500-byte pad composes 2718 / 2771 / 2293 bytes — nothing within 250 bytes of the limit from
//! either side — so flipping the guard predicate left all four green, and `render_installer_cmdline`
//! had no overflow arm at all. This module pins each composer's exact boundary, the transport
//! accounting fixed, and the third composer, so a future boundary drift reds a test instead of
//! shipping a cmdline the consumer silently truncates (extlinux) or refuses (UEFI loader).
//!
//! Oracles are independent of the SUT (`writing-floors.md` Principle 4). The two ceilings are hand
//! literals derived from the CONSUMERS' own sources, cited per constant below, never read from the
//! guard's constants; the guard's constants are separately FROZEN against those literals (Principle
//! 2, form 1) so a silent re-tune reds here. The extlinux kernel-visible string is rebuilt in this
//! module from the REAL rendered `extlinux.conf`'s own `LINUX` / `INITRD` / `APPEND` lines, never by
//! calling the production `extlinux_kernel_visible`.
//!
//! Claim/coverage labels are per test. Every `contains(...)` assert on a panic message is
//! SLOT-SCOPED arm sanity (it proves the intended guard fired rather than a sibling belt), never the
//! behaviour claim itself.

use super::*;

/// The largest kernel-visible cmdline the extlinux path delivers UNTRUNCATED.
///
/// syslinux 6.04-pre1 (`pins.toml` `[syslinux]`, sha256 `3f6d50a57f3e…`; source read at that sha):
/// `com32/elflink/ldlinux/readconfig.c:426` builds `me->cmdline` = `<LINUX> <APPEND> initrd=<INITRD>`;
/// `com32/elflink/ldlinux/execute.c:71-83` splits that at the first space and `:169` calls
/// `new_linux_kernel(kernel, args)`; `com32/elflink/ldlinux/kernel.c:49` is
/// `sprintf(cmdline, "BOOT_IMAGE=%s %s", kernel_name, args)`. `com32/lib/syslinux/load_linux.c:171`
/// sets `cmdline_size = strlen(cmdline) + 1`, and `:235-237` truncates
/// (`cmdline_size = hdr.cmdline_max_len; cmdline[cmdline_size - 1] = '\0'`) once
/// `cmdline_size > hdr.cmdline_max_len`. The box's kernel is source-built from `pins.toml` `[kernel]`
/// version 6.18.34 (`build_tools_host.rs:663-668`; the `linux-virt` apk supplies only the base
/// `.config`): at v6.18.34 `arch/x86/boot/header.S:384` sets `cmdline_size` to `COMMAND_LINE_SIZE-1`,
/// and `arch/x86/include/asm/setup.h:7` is `#define COMMAND_LINE_SIZE 2048`, a plain #define no
/// Kconfig controls, so the kernel advertises `cmdline_max_len` = 2047 and the largest payload that
/// survives whole is 2046 bytes.
const EXTLINUX_KERNEL_VISIBLE_CEIL: usize = 2046;

/// The largest cmdline a UEFI boot survives.
///
/// rambutan, the signed loader (`vendor/rambutan`, in-tree at this ref): `src/core.rs:14-17`
/// (`encode_cmdline_ucs2`) computes `total = bytes.len() + 1` and returns `None` when
/// `total > out.len()`; `src/main.rs:90` sizes that buffer `[u16; 2048]`. `None` halts the loader
/// fail-closed (`main.rs:497-503`). Report N-1 measured the two downstream limits agreeing: the
/// kernel EFI stub truncates only at `>= COMMAND_LINE_SIZE`
/// (`drivers/firmware/efi/libstub/efi-stub-helper.c:349,390-393`, v6.18.34).
const UEFI_CMDLINE_CEIL_BYTES: usize = 2047;

/// The bytes syslinux adds around the APPEND on the way to the kernel:
/// `"BOOT_IMAGE="` (11) + `"/slot-a/vmlinuz"` (15) + `" "` (1) + `" initrd="` (8) +
/// `"/slot-a/initramfs"` (17) = 52. Both extlinux arms bake paths of these widths (`slot-b` is as
/// wide as `slot-a`), so the number is the same on MBR and GPT.
const EXTLINUX_TRANSPORT_BYTES: usize = 52;

const MBR_LABEL: &str = "recipes";

/// A 64-lowercase-hex root hash — the real shape, and what `Firmware::SeabiosGpt`'s fixed-geometry
/// belt requires.
fn root_hash() -> String {
    "ab".repeat(32)
}

/// Rebuild what syslinux hands the kernel for one `LABEL` of a REAL rendered `extlinux.conf`.
///
/// The independent oracle: it reads the shipped artifact's own `LINUX` / `INITRD` / `APPEND` values
/// and applies the bootloader's composition (the `EXTLINUX_KERNEL_VISIBLE_CEIL` citations), so a
/// drift in the production `extlinux_kernel_visible` — a dropped `initrd=` clause, a stale path
/// literal, a guard measuring a string the conf does not emit — is CAUGHT here rather than mirrored.
///
/// Fails closed (Principle 6): a missing label or a missing field PANICS. It never returns a short
/// string that would quietly satisfy a length assert.
fn kernel_visible_from_conf(conf: &str, label: &str) -> String {
    let (linux, initrd, append) = label_fields(conf, label);
    format!("BOOT_IMAGE={linux} {append} initrd={initrd}")
}

/// The `APPEND` value of one `LABEL`, i.e. the bytes actually baked into the boot-fs.
fn append_from_conf(conf: &str, label: &str) -> String {
    label_fields(conf, label).2
}

fn label_fields(conf: &str, label: &str) -> (String, String, String) {
    let mut lines = conf.lines();
    let header = format!("LABEL {label}");
    assert!(
        lines.any(|l| l == header),
        "fail-closed: no {header:?} line in the rendered conf {conf:?}"
    );
    let (mut linux, mut initrd, mut append) = (None, None, None);
    for line in lines.by_ref() {
        if line.starts_with("LABEL ") {
            break;
        }
        let field = line.trim_start();
        if let Some(v) = field.strip_prefix("LINUX ") {
            linux = Some(v.to_owned());
        } else if let Some(v) = field.strip_prefix("INITRD ") {
            initrd = Some(v.to_owned());
        } else if let Some(v) = field.strip_prefix("APPEND ") {
            append = Some(v.to_owned());
        }
    }
    (
        linux.unwrap_or_else(|| panic!("fail-closed: {header:?} has no LINUX line")),
        initrd.unwrap_or_else(|| panic!("fail-closed: {header:?} has no INITRD line")),
        append.unwrap_or_else(|| panic!("fail-closed: {header:?} has no APPEND line")),
    )
}

/// Run `f` and return its panic message, or `None` if it did not panic. The guards are `assert!`s,
/// so both boundary directions are observable in ONE test — the accepted side by rendering, the
/// refused side by this.
fn caught_panic(f: impl FnOnce()) -> Option<String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(()) => None,
        Err(payload) => Some(
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "<non-string panic payload>".to_owned()),
        ),
    }
}

const NET_PREFIX: &str = "mode=static;pad=";

/// A `--net` value of `NET_PREFIX.len() + pad` bytes, all `is_ascii_graphic` and quote-free so it
/// clears `render_net_token`'s belt and only the length guard can fire on it.
fn net_of(pad: usize) -> String {
    format!("{NET_PREFIX}{}", "x".repeat(pad))
}

/// The inverse of [`net_of`].
fn net_pad(net: &str) -> usize {
    net.len() - NET_PREFIX.len()
}

/// An `--install-to` value of `1 + pad` bytes, all `[a-z0-9]` and non-empty so it clears
/// `render_installer_cmdline`'s charset belt and only the length guard can fire on it.
fn dev_of(pad: usize) -> String {
    "a".repeat(pad + 1)
}

/// The variable-length input that lands `measure(build(pad))` on exactly `ceiling` bytes, and the
/// one-byte-longer input.
///
/// The mapping is linear because the value rides as ONE verbatim token, and the linearity is
/// MEASURED at two points here rather than assumed. Both probe points are far under the ceiling, so
/// this derivation never trips the guard it is used to test.
fn value_at_and_over(
    ceiling: usize,
    build: impl Fn(usize) -> String,
    measure: impl Fn(&str) -> usize,
) -> (String, String) {
    const BASE_PAD: usize = 8;
    let base = measure(&build(BASE_PAD));
    assert_eq!(
        measure(&build(BASE_PAD + 1)),
        base + 1,
        "arm sanity: one more input byte must be exactly one more composed byte (the value rides as \
         one verbatim token); the boundary derivation depends on it"
    );
    assert!(
        base < ceiling,
        "arm sanity: the probe render must sit under the {ceiling}-byte ceiling, got {base}"
    );
    let pad_at = BASE_PAD + (ceiling - base);
    (build(pad_at), build(pad_at + 1))
}

#[test]
fn the_kernel_visible_oracle_is_non_vacuous_and_fails_closed() {
                                                                                                
                                                                                                
                                                                                                  
    let one = "DEFAULT recipes\nLABEL recipes\n  LINUX /k\n  INITRD /i\n  APPEND a b\n";
    assert_eq!(
        kernel_visible_from_conf(one, "recipes"),
        "BOOT_IMAGE=/k a b initrd=/i"
    );
    assert_eq!(append_from_conf(one, "recipes"), "a b");

                                                                         
    let two = "LABEL slot-a\n  LINUX /a/k\n  INITRD /a/i\n  APPEND aa\n\
               LABEL slot-b\n  LINUX /b/k\n  INITRD /b/i\n  APPEND bb\n";
    assert_eq!(
        kernel_visible_from_conf(two, "slot-a"),
        "BOOT_IMAGE=/a/k aa initrd=/a/i"
    );
    assert_eq!(
        kernel_visible_from_conf(two, "slot-b"),
        "BOOT_IMAGE=/b/k bb initrd=/b/i"
    );

                                                          
    for broken in [
        "LABEL x\n  INITRD /i\n  APPEND a\n",
        "LABEL x\n  LINUX /k\n  APPEND a\n",
        "LABEL x\n  LINUX /k\n  INITRD /i\n",
        "LABEL y\n  LINUX /k\n  INITRD /i\n  APPEND a\n",
    ] {
        assert!(
            caught_panic(|| {
                let _ = kernel_visible_from_conf(broken, "x");
            })
            .is_some(),
            "the oracle must panic, not return a short string, on {broken:?}"
        );
    }
}

#[test]
fn the_guard_ceilings_are_frozen_to_their_consumers_limits() {
                                                                                                
                                                                                                     
                                                                                                     
    assert_eq!(
        EXTLINUX_CMDLINE_CEIL, EXTLINUX_KERNEL_VISIBLE_CEIL,
        "the extlinux guard must bound the kernel-visible string at syslinux load_linux.c's \
         surviving payload (COMMAND_LINE_SIZE-2 = 2046), not at some other number"
    );
    assert_eq!(
        UEFI_CMDLINE_CEIL, UEFI_CMDLINE_CEIL_BYTES,
        "the UEFI guard must bound the composed cmdline at the rambutan loader's [u16; 2048] \
         payload limit (COMMAND_LINE_SIZE-1 = 2047)"
    );
                                                                                                   
                                                                          
    assert_ne!(EXTLINUX_CMDLINE_CEIL, UEFI_CMDLINE_CEIL);
}

#[test]
fn extlinux_mbr_kernel_visible_boundary_is_exact() {
                                                                                                
                                                                                                
                                                                                              
                                                   
    let hex = root_hash();
    let render =
        |net: &str| render_boot_fs_extlinux(&hex, 4_096, Some(net), Firmware::Seabios, None);
    let measure = |net: &str| kernel_visible_from_conf(&render(net), MBR_LABEL).len();

    let (at, over) = value_at_and_over(EXTLINUX_KERNEL_VISIBLE_CEIL, net_of, measure);

                                                                    
    let conf = render(&at);
    assert_eq!(
        kernel_visible_from_conf(&conf, MBR_LABEL).len(),
        EXTLINUX_KERNEL_VISIBLE_CEIL,
        "the largest accepted SeaBIOS-MBR render must put exactly {EXTLINUX_KERNEL_VISIBLE_CEIL} \
         bytes in front of the kernel"
    );

                                       
    let msg = caught_panic(|| {
        let _ = render(&over);
    })
    .expect("one byte past the ceiling must panic the build");
                                                                                           
    assert!(
        msg.contains("SeaBIOS-MBR kernel-visible cmdline"),
        "the budget guard must be what fired: {msg}"
    );
}

#[test]
fn extlinux_gpt_kernel_visible_boundary_is_exact_on_both_labels() {
                                                                                                   
                                                                                            
    let hex = root_hash();
    let render =
        |net: &str| render_boot_fs_extlinux(&hex, 4_096, Some(net), Firmware::SeabiosGpt, None);
    let measure = |net: &str| kernel_visible_from_conf(&render(net), "slot-a").len();

    let (at, over) = value_at_and_over(EXTLINUX_KERNEL_VISIBLE_CEIL, net_of, measure);

    let conf = render(&at);
    for slot in ["slot-a", "slot-b"] {
        assert_eq!(
            kernel_visible_from_conf(&conf, slot).len(),
            EXTLINUX_KERNEL_VISIBLE_CEIL,
            "the largest accepted SeaBIOS-GPT render must put exactly \
             {EXTLINUX_KERNEL_VISIBLE_CEIL} bytes in front of the kernel on {slot}"
        );
    }

    let msg = caught_panic(|| {
        let _ = render(&over);
    })
    .expect("one byte past the ceiling must panic the build");
    assert!(
        msg.contains("SeaBIOS-GPT kernel-visible cmdline"),
        "the budget guard must be what fired: {msg}"
    );
}

#[test]
fn extlinux_budget_accounts_for_the_syslinux_transport_not_the_bare_append() {
                                                                                                
                                                                                               
                                                                                                  
                                                                                            
                               
      
                                                                                                   
                                                                                                  
                                                                                                   
                                                                                                   
                                                                                            
    let hex = root_hash();
    let render =
        |net: &str| render_boot_fs_extlinux(&hex, 4_096, Some(net), Firmware::Seabios, None);
    let measure = |net: &str| kernel_visible_from_conf(&render(net), MBR_LABEL).len();
    let (at, _) = value_at_and_over(EXTLINUX_KERNEL_VISIBLE_CEIL, net_of, measure);

                                                                 
    let conf = render(&at);
    let append = append_from_conf(&conf, MBR_LABEL);
    let visible = kernel_visible_from_conf(&conf, MBR_LABEL);
    assert_eq!(
        visible.len() - append.len(),
        EXTLINUX_TRANSPORT_BYTES,
        "syslinux wraps the APPEND in BOOT_IMAGE=<LINUX> … initrd=<INITRD>; a change to those path \
         widths changes the APPEND budget and must be re-derived, not absorbed silently"
    );
    assert_eq!(
        append.len(),
        EXTLINUX_KERNEL_VISIBLE_CEIL - EXTLINUX_TRANSPORT_BYTES,
        "the largest bakeable APPEND is the ceiling minus the transport"
    );

                                                                                                 
                                                                 
    let shorter = render(&net_of(net_pad(&at) - EXTLINUX_TRANSPORT_BYTES));
    assert_eq!(
        append_from_conf(&shorter, MBR_LABEL).len(),
        append.len() - EXTLINUX_TRANSPORT_BYTES,
        "arm sanity: 52 fewer input bytes are 52 fewer APPEND bytes"
    );

                                                                                            
                                                                                             
    let vector = net_of(net_pad(&at) + EXTLINUX_TRANSPORT_BYTES);
    let msg = caught_panic(|| {
        let _ = render(&vector);
    })
    .expect(
        "an APPEND that fits the bare ceiling but overflows the kernel-visible one must panic",
    );
    assert!(
        msg.contains("SeaBIOS-MBR kernel-visible cmdline"),
        "the budget guard must be what fired: {msg}"
    );
}

#[test]
fn uefi_runtime_cmdline_boundary_is_exact() {
                                                                                                     
                                                                                                     
                                                                   
    let hex = root_hash();
    let render = |net: &str| render_uefi_cmdline(&hex, 4_096, Some(net), None);
    let measure = |net: &str| render(net).len();

    let (at, over) = value_at_and_over(UEFI_CMDLINE_CEIL_BYTES, net_of, measure);

    assert_eq!(
        render(&at).len(),
        UEFI_CMDLINE_CEIL_BYTES,
        "the largest accepted UEFI runtime cmdline must be exactly {UEFI_CMDLINE_CEIL_BYTES} bytes"
    );

    let msg = caught_panic(|| {
        let _ = render(&over);
    })
    .expect("one byte past the ceiling must panic the build");
    assert!(
        msg.contains("UEFI runtime cmdline"),
        "the budget guard must be what fired: {msg}"
    );
}

#[test]
fn uefi_installer_cmdline_boundary_is_exact() {
                                                                                                
                                                                                                
                                                                                                 
                                                                                                   
    let hex = root_hash();
    let render = |dev: &str| render_installer_cmdline(&hex, &hex, 4_096, Some(dev));
    let measure = |dev: &str| render(dev).len();

    let (at, over) = value_at_and_over(UEFI_CMDLINE_CEIL_BYTES, dev_of, measure);

                                                                                                  
    for dev in [&at, &over] {
        assert!(
            !dev.is_empty()
                && dev
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "the vector must be a legal bare device token, or the belt fires instead: {dev:?}"
        );
    }

    let cmdline = render(&at);
    assert_eq!(
        cmdline.len(),
        UEFI_CMDLINE_CEIL_BYTES,
        "the largest accepted UEFI installer cmdline must be exactly {UEFI_CMDLINE_CEIL_BYTES} bytes"
    );
    assert!(
        cmdline.contains(&format!("fb.install-to={at} ")),
        "arm sanity: the long value is what filled the budget"
    );

    let msg = caught_panic(|| {
        let _ = render(&over);
    })
    .expect("one byte past the ceiling must panic the build");
    assert!(
        msg.contains("UEFI installer cmdline"),
        "the LENGTH guard must be what fired, not the charset belt: {msg}"
    );
}
