                                                                                                 

use recipes_image_builder::kernel::{assert_kernel_config, ConfigAssertError, KernelConfigPins};

fn pins() -> KernelConfigPins {
    let toml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-config-pins.toml"
    ));
    KernelConfigPins::from_toml_str(toml).expect("kernel-config-pins.toml parses")
}

/// A complete, realistic `.config` satisfying every pin (`=y` literal; `=n` as kconfig's disabled
/// form `# CONFIG_X is not set`; prefix lines with per-build path content), plus the unrelated
/// lines a real `.config` carries — so the assertion is checking presence, not an exact set.
fn complete_config(pins: &KernelConfigPins) -> String {
    let mut lines = vec![
        "# Automatically generated file; DO NOT EDIT.".to_string(),
        "# Linux/x86_64 Kernel Configuration".to_string(),
        "CONFIG_CC_VERSION_TEXT=\"gcc (Alpine) 14.2.0\"".to_string(),
        "CONFIG_64BIT=y".to_string(),
    ];
    for cfg in pins.exact_match.iter().chain(&pins.observe_exact) {
        match cfg.strip_suffix("=n") {
            Some(sym) => lines.push(format!("# {sym} is not set")),
            None => lines.push(cfg.clone()),
        }
    }
    for prefix in &pins.prefix_match {
        lines.push(format!("{prefix}certs/recipes-ca.pem\""));
    }
    lines.push("CONFIG_PRINTK_TIME=y".to_string());
    lines.join("\n")
}

#[test]
fn pins_cover_the_spec_blocks() {
    let pins = pins();
                                                                                                   
                                                                               
                                                                                            
                                                                                     
                                                                                                        
                                                                                                        
                                                                                                            
                                                                                        
                                                                                             
                                                                                                
                                                                                                        
                                                                                     
                                                                             
                                                                                  
                                                                                                      
                                                                                     
                                                                                               
                                                                                                          
                                                                                               
                                                                                                         
                                                                                        
                                                                                      
                                                                                                
                                                                                        
                                                                                                        
                                                                                                             
                                                                                                          
                                                                                                      
                                                                                                  
                                                                                    
    assert_eq!(pins.exact_match.len(), 60, "exact-match symbol count");
                                              
    assert_eq!(pins.observe_exact.len(), 18, "observe-exact symbol count");
    assert_eq!(pins.prefix_match.len(), 1, "prefix-match symbol count");
}

                                                                                              
/// asserts the LENGTH, so a swap — delete one pin, add another — keeps the count at 18 and stays
/// green. Sorted-list equality reddens on an addition, a deletion, a rename, a value change and a
/// duplicate alike.
///
/// Model: the toml-decoded `observe_exact` strings compared literally, embedded quotes included.
/// Not claimed here: that these symbols exist in any kernel (kernel_pin_sources.rs), that no
/// fragment force-sets them (kernel_pin_sources.rs), or that a produced `.config` satisfies them
/// (the pin gate).
#[test]
fn the_observe_exact_set_is_exactly_the_18_h1_pins() {
    const H1: [&str; 18] = [
        "CONFIG_RANDOMIZE_BASE=y",
        "CONFIG_RANDOMIZE_MEMORY=y",
        "CONFIG_STACKPROTECTOR_STRONG=y",
        "CONFIG_FORTIFY_SOURCE=y",
        "CONFIG_HARDENED_USERCOPY=y",
        "CONFIG_SLAB_FREELIST_RANDOM=y",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y",
        "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION=y",
        "CONFIG_MITIGATION_RETPOLINE=y",
        "CONFIG_STRICT_KERNEL_RWX=y",
        "CONFIG_VMAP_STACK=y",
        "CONFIG_LEGACY_VSYSCALL_NONE=y",
        "CONFIG_STRICT_DEVMEM=y",
        "CONFIG_IO_STRICT_DEVMEM=y",
        "CONFIG_SECURITY_DMESG_RESTRICT=y",
        "CONFIG_ZERO_CALL_USED_REGS=y",
        "CONFIG_BPF_UNPRIV_DEFAULT_OFF=y",
        r#"CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity""#,
    ];
    let mut want: Vec<String> = H1.iter().map(|s| (*s).to_string()).collect();
    want.sort();
    let mut got = pins().observe_exact;
    got.sort();
    assert_eq!(
        got, want,
        "the H-1 observe set drifted; re-freeze this list only with the change"
    );
}

/// C3: the four USB boot-media drivers live in the two per-substrate blocks — bare-metal-uefi asserts
/// them present (`=y`, because it boots off USB media), vps-kvm forbids them (the absence assert) AND
/// arms a fail-closed `CONFIG_USB`-prefix guard so a NEW USB `=y` driver the exact list never named is
/// still caught. The blocks are exact inverses over the same four lines, so a symbol can never be
/// simultaneously required and forbidden. Deliberately USB-ONLY: the DISK transports
/// (SCSI/ATA/NVMe/BLK_DEV_SD) are force-set + PINNED in the shared block on BOTH substrates,
/// so the box boots on any KVM hypervisor's virtio-blk / virtio-scsi / NVMe / SATA disk.
#[test]
fn substrate_blocks_split_the_usb_configs() {
    const USB: [&str; 4] = [
        "CONFIG_USB=y",
        "CONFIG_USB_XHCI_HCD=y",
        "CONFIG_USB_EHCI_HCD=y",
        "CONFIG_USB_STORAGE=y",
    ];
    let bm = KernelConfigPins::from_toml_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-config-pins-baremetal.toml"
    )))
    .expect("bare-metal block parses");
    let vk = KernelConfigPins::from_toml_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-config-pins-vpskvm.toml"
    )))
    .expect("vps-kvm block parses");
    for s in USB {
        assert!(
            bm.exact_match.contains(&s.to_string()),
            "bare-metal must assert {s}"
        );
        assert!(
            vk.forbidden.contains(&s.to_string()),
            "vps-kvm must forbid {s}"
        );
    }
                                                                                           
    assert!(bm.forbidden.is_empty(), "bare-metal block forbids nothing");
    assert!(
        vk.exact_match.is_empty(),
        "vps-kvm block requires no USB =y"
    );
                                                                                                 
                                                                           
    assert!(
        vk.forbidden_prefix.contains(&"CONFIG_USB".to_string()),
        "vps-kvm must arm the CONFIG_USB fail-closed prefix guard"
    );
    assert!(
        bm.forbidden_prefix.is_empty(),
        "bare-metal keeps USB, so it arms no forbidden prefix"
    );
                                                                                                      
    for allow in &vk.forbidden_prefix_allow {
        assert!(
            vk.forbidden_prefix.iter().any(|p| allow.starts_with(p)),
            "allowlist entry {allow} is not under any forbidden_prefix — dead entry"
        );
    }
}

/// C3: tie the SOURCE hardening fragments to the substrate blocks. The SHARED `kernel-hardening.config`
/// force-sets NONE of the vps-kvm-forbidden configs; `kernel-hardening-baremetal.config` force-ENABLES
/// EVERY one (bare-metal's `exact_match`); and `kernel-hardening-vpskvm.config` force-DISABLES every
/// one (`# CONFIG_X is not set`) — because the produced-bytes gate found the linux-virt BASE actively
/// ships the USB host/storage stack (as `CONFIG_USB=m`, which `CONFIG_MODULES=n` promotes to builtin),
/// so vps-kvm must ACTIVELY disable it, not merely omit a force-enable. (Deliberately USB-only: the
/// disk transports the base also ships — SCSI/ATA/NVMe — STAY, so the box boots on any KVM disk.) Fast
/// (no-docker) lock on the fragment split `build-kernel.sh` merges.
#[test]
fn the_hardening_fragments_match_the_substrate_blocks() {
    let shared = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-hardening.config"
    ));
    let baremetal = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-hardening-baremetal.config"
    ));
    let vpskvm_frag = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-hardening-vpskvm.config"
    ));
    let vpskvm = KernelConfigPins::from_toml_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-config-pins-vpskvm.toml"
    )))
    .unwrap();
    assert!(
        !vpskvm.forbidden.is_empty(),
        "the vps-kvm block must forbid something"
    );
    for forbidden in &vpskvm.forbidden {
        let sym = forbidden.strip_suffix("=y").unwrap_or(forbidden);
        let disabled = format!("# {sym} is not set");
        assert!(
            !shared.lines().any(|l| l.trim() == forbidden),
            "the SHARED hardening fragment force-sets a vps-kvm-forbidden config: {forbidden}"
        );
        assert!(
            baremetal.lines().any(|l| l.trim() == forbidden),
            "the bare-metal hardening fragment must force-ENABLE {forbidden}"
        );
        assert!(
            vpskvm_frag.lines().any(|l| l.trim() == disabled),
            "the vps-kvm hardening fragment must force-DISABLE {sym} (`{disabled}`)"
        );
    }
}

/// C3/L-2: the fail-closed prefix guard fires in the PRODUCTION path — load the REAL vps-kvm block,
/// union it with the shared pins exactly as the bake does, and confirm a USB host controller the exact
/// `forbidden` list never names (a future kernel bump's new driver) is STILL rejected, while the clean
/// merged config passes. Complements the synthetic unit test in `kernel::tests` by exercising the
/// shipped toml + `union()` — a regression that emptied `forbidden_prefix` or dropped the vps-kvm block
/// from the union would be caught here, not only by the expensive produced-bytes gate.
#[test]
fn the_real_vpskvm_prefix_guard_rejects_an_unenumerated_usb_driver() {
    let merged = pins().union(
        &KernelConfigPins::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/kernel-config-pins-vpskvm.toml"
        )))
        .expect("vps-kvm block parses"),
    );
                                                                                                          
    let rogue = format!("{}\nCONFIG_USB_XHCI_PLATFORM=y\n", complete_config(&merged));
    let err = assert_kernel_config(&rogue, &merged).unwrap_err();
    assert!(
        matches!(err, ConfigAssertError::Missing(ref m)
            if m.contains("CONFIG_USB_XHCI_PLATFORM") && m.contains("forbidden config domain")),
        "the real vps-kvm prefix guard must reject an un-enumerated USB driver: {err:?}"
    );
                                                                                               
    assert!(
        assert_kernel_config(&complete_config(&merged), &merged).is_ok(),
        "the clean merged vps-kvm config must pass"
    );
}

/// C3/F-1 (R2 audit): lock the USB_PCI shed at the FAST-test level. The produced-bytes gate + the
/// fail-closed prefix guard both catch a re-enabled USB_PCI, but neither is a `cargo test`. USB_PCI is
/// `default y, depends on PCI` (NOT gated on CONFIG_USB), so the parent disable does NOT cascade it and
/// it compiles live `pci-quirks.o`; the vps-kvm fragment must ACTIVELY disable it and the allowlist must
/// NOT re-admit it. Catches two silent regressions that would otherwise pass cargo test + clippy: deleting
/// the fragment's `# CONFIG_USB_PCI is not set` line, or re-adding CONFIG_USB_PCI(_AMD) to the allowlist.
#[test]
fn the_vpskvm_fragment_disables_usb_pci_and_the_allowlist_excludes_it() {
    let frag = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-hardening-vpskvm.config"
    ));
    assert!(
        frag.lines().any(|l| l.trim() == "# CONFIG_USB_PCI is not set"),
        "the vps-kvm fragment must force-DISABLE CONFIG_USB_PCI (it compiles live pci-quirks.o; the \
         CONFIG_USB parent disable does not cascade a PCI-gated symbol — audit F-1)"
    );
    let vpskvm = KernelConfigPins::from_toml_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-config-pins-vpskvm.toml"
    )))
    .unwrap();
    for sym in ["CONFIG_USB_PCI", "CONFIG_USB_PCI_AMD"] {
        assert!(
            !vpskvm.forbidden_prefix_allow.iter().any(|a| a == sym),
            "{sym} must NOT be allowlisted — it pulls in code, so the CONFIG_USB prefix guard must \
             forbid it (audit F-1); allowlist only genuinely inert flags"
        );
    }
}

#[test]
fn complete_config_passes() {
    let pins = pins();
    assert_kernel_config(&complete_config(&pins), &pins).expect("complete .config passes");
}

#[test]
fn missing_required_y_symbol_fails() {
    let pins = pins();
    let stripped: String = complete_config(&pins)
        .lines()
        .filter(|l| *l != "CONFIG_IMA_APPRAISE=y")
        .collect::<Vec<_>>()
        .join("\n");
    let err = assert_kernel_config(&stripped, &pins).unwrap_err();
    assert!(
        matches!(err, ConfigAssertError::Missing(ref m) if m == "FAIL: CONFIG_IMA_APPRAISE=y not in .config"),
        "got {err:?}"
    );
}

#[test]
fn modules_enabled_fails() {
                                                                                     
                                                                                                
                                                                                           
    let pins = pins();
    let flipped = complete_config(&pins).replace("# CONFIG_MODULES is not set", "CONFIG_MODULES=y");
    let err = assert_kernel_config(&flipped, &pins).unwrap_err();
    assert!(
        matches!(err, ConfigAssertError::Missing(ref m) if m == "FAIL: CONFIG_MODULES=n not in .config"),
        "got {err:?}"
    );
}

#[test]
fn disabled_modules_in_canonical_form_passes() {
                                                                                                 
                                                                                                   
                                                         
    let pins = pins();
    let cfg = complete_config(&pins);
    assert!(cfg.contains("# CONFIG_MODULES is not set"));
    assert_kernel_config(&cfg, &pins).expect("canonical disabled form is accepted");
}

#[test]
fn missing_system_trusted_keys_fails() {
    let pins = pins();
    let stripped: String = complete_config(&pins)
        .lines()
        .filter(|l| !l.starts_with("CONFIG_SYSTEM_TRUSTED_KEYS=\""))
        .collect::<Vec<_>>()
        .join("\n");
    let err = assert_kernel_config(&stripped, &pins).unwrap_err();
    assert!(
        matches!(err, ConfigAssertError::Missing(ref m) if m == "FAIL: CONFIG_SYSTEM_TRUSTED_KEYS not set"),
        "got {err:?}"
    );
}

#[test]
fn hardening_fragment_satisfies_every_pin() {
                                                                                                  
                                                                                                 
                                                                                                    
                                                                                
    let mut pins = pins();
    pins.observe_exact = vec![];
    let fragment = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/kernel-hardening.config"
    ));
    assert_kernel_config(fragment, &pins).expect(
        "kernel-hardening.config must satisfy every force-set kernel-config-pin (no drift)",
    );
}

#[test]
fn real_dotconfig_if_present() {
                                                                                                
                                                                                           
    let Ok(path) = std::env::var("RECIPES_DOTCONFIG") else {
        return;
    };
    let dot_config = std::fs::read_to_string(&path).expect("read RECIPES_DOTCONFIG");
    assert_kernel_config(&dot_config, &pins())
        .expect("real olddefconfig output must satisfy every pin");
}
