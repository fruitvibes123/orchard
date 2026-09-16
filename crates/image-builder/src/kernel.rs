//! Custom-kernel build driver + the build-time CONFIG assertion.
//!
//! The assertion is the regression guard for defense layers 4/5/6: `make olddefconfig` can
                                                                                                 
//! unnoticed for 7 audit rounds, leaving lockdown absent). [`assert_kernel_config`] checks every
//! required symbol against the produced `.config` (post-`olddefconfig`, Rust-side after
                                                                                           
//! message.
//!
//! **kconfig `=n` note.** The spec's build-pipeline block writes the assertion as
//! `grep -qx "^$cfg$" .config` for every symbol including `CONFIG_MODULES=n`. But kconfig emits a
//! *disabled* bool/tristate as `# CONFIG_X is not set`, never `CONFIG_X=n` — so the literal grep
//! would never match a real `.config` and the build would always abort on the two `=n` pins. This
//! implementation accepts the canonical disabled form (achieving the intent: the symbol is OFF),
//! which is a correctness fix over the spec's literal grep (flagged for a spec-wording fold).

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigAssertError {
    /// A required symbol is absent / has the wrong value. Carries the spec's exact message.
    #[error("{0}")]
    Missing(String),
    /// `kernel-config-pins.toml` failed to parse.
    #[error("kernel-config-pins.toml: {0}")]
    Pins(String),
}

/// Required kernel CONFIG symbols (mirrors the spec build-pipeline CONFIG-assertion block).
///
/// `deny_unknown_fields` (audit I-1): a mistyped key (e.g. `forbidden_prefixes`) is a HARD parse error,
/// not a silent no-op — otherwise a typo could disarm the `forbidden_prefix` security guard unnoticed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelConfigPins {
    /// Bool/tristate/value symbols whose `.config` line must match exactly, e.g. `CONFIG_IMA=y`.
    /// A `=n` entry asserts the symbol is DISABLED and accepts kconfig's `# CONFIG_X is not set`.
    pub exact_match: Vec<String>,
    /// Observed symbols: asserted in the produced `.config` post-olddefconfig, and MUST NOT appear
    /// in any hardening fragment — the fragment never force-repairs them, so a base-config drift
    /// fails the build. Same match semantics and failure message as [`Self::exact_match`].
                                                                                               
    #[serde(default)]
    pub observe_exact: Vec<String>,
    /// String-valued symbols with per-build content (a key path) — the `.config` must contain a
    /// line STARTING with the prefix, e.g. `CONFIG_SYSTEM_TRUSTED_KEYS="`.
    pub prefix_match: Vec<String>,
    /// C3 substrate gating: `CONFIG_X=y` lines that must NOT appear (the absence assert). Satisfied
    /// by kconfig's `# CONFIG_X is not set` comment OR total omission; refused only on the live `=y`.
    /// Empty on the shared/bare-metal blocks; the vps-kvm block forbids the USB boot-media drivers so a
    /// base-config drift that re-enables them FAILS the build rather than shipping unused attack
    /// surface. `#[serde(default)]` ⇒ existing pin files (no `forbidden` key) parse unchanged.
    #[serde(default)]
    pub forbidden: Vec<String>,
    /// C3 FAIL-CLOSED domain guard: config-symbol PREFIXES whose `=y` members are ALL forbidden, except
    /// the `forbidden_prefix_allow` exceptions. Where `forbidden` blacklists specific symbols (fragile —
    /// a kernel bump can add a new driver under the same bus that the list doesn't name), this forbids
    /// the whole DOMAIN by prefix: e.g. `CONFIG_USB` rejects every USB `=y` driver, current or future.
    /// The vps-kvm block uses it for the USB stack (a VPS never boots off USB media). Empty elsewhere.
    #[serde(default)]
    pub forbidden_prefix: Vec<String>,
    /// The allowlist for [`Self::forbidden_prefix`]: exact symbols that MAY be `=y` inside a forbidden
    /// domain — INERT infra/helper flags that are NOT drivers (e.g. `CONFIG_USB_SUPPORT`, the menuconfig
    /// gate; `CONFIG_USB_ARCH_HAS_HCD`, a `def_bool` capability marker) — with the host stack disabled they
    /// pull in no compiled driver. Keeps the domain guard fail-closed on real DRIVERS while not tripping on
    /// non-driver plumbing. An entry that actually pulls in code (`CONFIG_USB_PCI` → `pci-quirks.o`) does
    /// NOT belong here — force-disable it in the fragment instead, so the guard forbids it (audit F-1). Empty elsewhere.
    #[serde(default)]
    pub forbidden_prefix_allow: Vec<String>,
}

impl KernelConfigPins {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigAssertError> {
        toml::from_str(s).map_err(|e| ConfigAssertError::Pins(e.to_string()))
    }

    /// C3: the UNION of this (shared) block with a substrate block — the bake asserts the
    /// concatenation (`exact ∪ exact`, `prefix ∪ prefix`, `forbidden ∪ forbidden`). Order-preserving
    /// (shared first, then the substrate's), so `assert_kernel_config`'s first-miss message is stable.
    pub fn union(&self, other: &KernelConfigPins) -> KernelConfigPins {
        let cat = |a: &[String], b: &[String]| a.iter().chain(b).cloned().collect();
        KernelConfigPins {
            exact_match: cat(&self.exact_match, &other.exact_match),
            observe_exact: cat(&self.observe_exact, &other.observe_exact),
            prefix_match: cat(&self.prefix_match, &other.prefix_match),
            forbidden: cat(&self.forbidden, &other.forbidden),
            forbidden_prefix: cat(&self.forbidden_prefix, &other.forbidden_prefix),
            forbidden_prefix_allow: cat(
                &self.forbidden_prefix_allow,
                &other.forbidden_prefix_allow,
            ),
        }
    }
}

/// Whole-line match for an exact/observe pin. A `=n` entry accepts kconfig's canonical disabled
/// form `# CONFIG_X is not set` (the literal `CONFIG_X=n` too, harmlessly).
fn exact_line_present(dot_config: &str, cfg: &str) -> bool {
    match cfg.strip_suffix("=n") {
        Some(sym) => {
            let disabled = format!("# {sym} is not set");
            dot_config
                .lines()
                .any(|l| l == disabled.as_str() || l == cfg)
        }
        None => dot_config.lines().any(|l| l == cfg),
    }
}

/// Assert every required CONFIG is present in the produced `.config`. Returns the first failure
/// with the spec's message; the build aborts on the first miss.
pub fn assert_kernel_config(
    dot_config: &str,
    pins: &KernelConfigPins,
) -> Result<(), ConfigAssertError> {
    for cfg in pins.exact_match.iter().chain(&pins.observe_exact) {
        if !exact_line_present(dot_config, cfg) {
            return Err(ConfigAssertError::Missing(format!(
                "FAIL: {cfg} not in .config"
            )));
        }
    }

    for prefix in &pins.prefix_match {
        if !dot_config.lines().any(|l| l.starts_with(prefix.as_str())) {
            let sym = prefix.split('=').next().unwrap_or(prefix.as_str());
            return Err(ConfigAssertError::Missing(format!("FAIL: {sym} not set")));
        }
    }

                                                                                                   
                                                                                       
                                                                                                    
    for entry in &pins.forbidden {
        if dot_config.lines().any(|l| l == entry.as_str()) {
            return Err(ConfigAssertError::Missing(format!(
                "FAIL: {entry} present but forbidden for this substrate"
            )));
        }
    }

                                                                                                  
                                                                                                    
                                                                                                    
                                                                                 
    if !pins.forbidden_prefix.is_empty() {
        for line in dot_config.lines() {
            let Some(sym) = line.strip_suffix("=y") else {
                continue;
            };
            let forbidden_domain = pins
                .forbidden_prefix
                .iter()
                .any(|p| sym.starts_with(p.as_str()));
            let allowed = pins.forbidden_prefix_allow.iter().any(|a| a == sym);
            if forbidden_domain && !allowed {
                return Err(ConfigAssertError::Missing(format!(
                    "FAIL: {sym}=y is in a forbidden config domain for this substrate \
                     (fail-closed prefix guard; add to forbidden_prefix_allow only if intentionally kept)"
                )));
            }
        }
    }

    Ok(())
}

                                                                                
                                                                                 
                                                                     
                                                                                  
                                                    

#[cfg(test)]
mod tests {
    use super::*;

    /// L5 (SB-loader plan Task 2.1): ONE plain kernel serves both firmwares — the
    /// shared pins carry the EFI bootability pair (the loader `LoadImage`s this PE)
    /// and the UEFI tty0 console chain (operability pins, not security pins —
                                                                  
    #[test]
    fn shared_pins_require_efi_stub_and_console_chain() {
        let pins = KernelConfigPins::from_toml_str(include_str!("../kernel-config-pins.toml"))
            .expect("shared pins parse");
        for s in [
            "CONFIG_EFI=y",
            "CONFIG_EFI_STUB=y",
            "CONFIG_SYSFB=y",
            "CONFIG_SYSFB_SIMPLEFB=y",
            "CONFIG_DRM_SIMPLEDRM=y",
            "CONFIG_FRAMEBUFFER_CONSOLE=y",
        ] {
            assert!(
                pins.exact_match.contains(&s.to_string()),
                "missing pin: {s}"
            );
        }
    }

                                                                                                  
    /// carry a symbol is satisfied by kconfig's disabled comment OR total absence, and refuses only
    /// the live `=y` line (the vps-kvm side forbids the four USB host/storage drivers).
    #[test]
    fn forbidden_passes_on_disabled_comment_and_on_omission_fails_on_present() {
        let pins = KernelConfigPins {
            exact_match: vec![],
            observe_exact: vec![],
            prefix_match: vec![],
            forbidden: vec!["CONFIG_USB=y".into()],
            forbidden_prefix: vec![],
            forbidden_prefix_allow: vec![],
        };
        assert!(
            assert_kernel_config("# CONFIG_USB is not set\n", &pins).is_ok(),
            "disabled comment ⇒ ok"
        );
        assert!(
            assert_kernel_config("CONFIG_OTHER=y\n", &pins).is_ok(),
            "total omission ⇒ ok"
        );
        let e = assert_kernel_config("CONFIG_USB=y\n", &pins).unwrap_err();
        assert!(
            matches!(e, ConfigAssertError::Missing(_)),
            "present =y ⇒ fail"
        );
    }

    /// C3 fail-closed domain guard: `forbidden_prefix` rejects ANY `=y` symbol under the prefix except
    /// the explicit allowlist — catching a driver the exact `forbidden` list never named.
    #[test]
    fn forbidden_prefix_fails_closed_on_any_domain_driver_except_the_allowlist() {
        let pins = KernelConfigPins {
            exact_match: vec![],
            observe_exact: vec![],
            prefix_match: vec![],
            forbidden: vec![],
            forbidden_prefix: vec!["CONFIG_USB".into()],
            forbidden_prefix_allow: vec!["CONFIG_USB_SUPPORT".into()],
        };
                                                                                                
        let e = assert_kernel_config("CONFIG_USB_NEW_HCD=y\n", &pins).unwrap_err();
        assert!(
            matches!(e, ConfigAssertError::Missing(ref m) if m.contains("CONFIG_USB_NEW_HCD")),
            "a new in-domain driver must fail: {e:?}"
        );
                                                                                                    
        assert!(
            assert_kernel_config(
                "CONFIG_USB_SUPPORT=y\n# CONFIG_USB is not set\nCONFIG_VIRTIO_BLK=y\n",
                &pins
            )
            .is_ok(),
            "allowlisted flag + disabled USB + unrelated =y ⇒ ok"
        );
    }

    /// C3: `union` concatenates shared + substrate, and the merged block asserts BOTH halves — the
    /// shared `=y` presence AND the substrate's `forbidden` absence, in one `assert_kernel_config`.
    #[test]
    fn union_concatenates_and_asserts_both_blocks() {
        let shared = KernelConfigPins {
            exact_match: vec!["CONFIG_IMA=y".into()],
            observe_exact: vec![],
            prefix_match: vec![],
            forbidden: vec![],
            forbidden_prefix: vec![],
            forbidden_prefix_allow: vec![],
        };
        let vpskvm = KernelConfigPins {
            exact_match: vec![],
            observe_exact: vec![],
            prefix_match: vec![],
            forbidden: vec!["CONFIG_USB=y".into()],
            forbidden_prefix: vec![],
            forbidden_prefix_allow: vec![],
        };
        let merged = shared.union(&vpskvm);
        assert_eq!(merged.exact_match, vec!["CONFIG_IMA=y".to_string()]);
        assert_eq!(merged.forbidden, vec!["CONFIG_USB=y".to_string()]);
        assert!(
            assert_kernel_config("CONFIG_IMA=y\n# CONFIG_USB is not set\n", &merged).is_ok(),
            "IMA present + USB disabled ⇒ ok"
        );
        assert!(
            assert_kernel_config("CONFIG_IMA=y\nCONFIG_USB=y\n", &merged).is_err(),
            "USB re-enabled ⇒ fail"
        );
        assert!(
            assert_kernel_config("# CONFIG_USB is not set\n", &merged).is_err(),
            "IMA missing ⇒ fail"
        );
    }

    /// A synthetic post-olddefconfig `.config` that satisfies the SHARED pins (every
    /// exact symbol in its kconfig form + content for each prefix symbol).
    fn good_shared_config() -> String {
        let pins = KernelConfigPins::from_toml_str(include_str!("../kernel-config-pins.toml"))
            .expect("shared pins parse");
        let mut c = String::new();
        for sym in pins.exact_match.iter().chain(&pins.observe_exact) {
            match sym.strip_suffix("=n") {
                Some(s) => c.push_str(&format!("# {s} is not set\n")),
                None => c.push_str(&format!("{sym}\n")),
            }
        }
        c.push_str("CONFIG_SYSTEM_TRUSTED_KEYS=\"/build/ca.pem\"\n");
        c
    }

                                                                                   
    /// ONE kernel both firmwares boot must keep the EFI pair AND the integrity base;
    /// olddefconfig dropping either aborts the build before any .img write.
    #[test]
    fn shared_pins_pass_a_good_config_and_catch_silent_drops() {
        let pins = KernelConfigPins::from_toml_str(include_str!("../kernel-config-pins.toml"))
            .expect("shared pins parse");
        assert!(assert_kernel_config(&good_shared_config(), &pins).is_ok());

                                                                                           
        let dropped_stub = good_shared_config().replace("CONFIG_EFI_STUB=y\n", "");
        assert!(assert_kernel_config(&dropped_stub, &pins).is_err());

                                                                                    
                                                   
        let dropped_con = good_shared_config().replace("CONFIG_DRM_SIMPLEDRM=y\n", "");
        assert!(assert_kernel_config(&dropped_con, &pins).is_err());

                                                                               
        let no_ima = good_shared_config().replace("CONFIG_IMA_APPRAISE=y\n", "");
        assert!(assert_kernel_config(&no_ima, &pins).is_err());
    }

    /// An `observe_exact` symbol absent from the produced `.config` fails with the same error type
                                                                         
    #[test]
    fn observe_exact_absent_fails_like_exact_match() {
        let pins = KernelConfigPins {
            exact_match: vec![],
            observe_exact: vec!["CONFIG_RANDOMIZE_BASE=y".into()],
            prefix_match: vec![],
            forbidden: vec![],
            forbidden_prefix: vec![],
            forbidden_prefix_allow: vec![],
        };
        assert!(assert_kernel_config("CONFIG_RANDOMIZE_BASE=y\n", &pins).is_ok());
        let e = assert_kernel_config("# CONFIG_RANDOMIZE_BASE is not set\n", &pins).unwrap_err();
        assert!(
            matches!(e, ConfigAssertError::Missing(ref m)
                if m == "FAIL: CONFIG_RANDOMIZE_BASE=y not in .config"),
            "got {e:?}"
        );
    }
}
