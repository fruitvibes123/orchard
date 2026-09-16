//! What the kernel pin files and hardening fragments DECLARE, checked against the grammar the
//! pinned kernel's kconfig parser accepts and against that kernel's Kconfig symbol namespace.
//! Sibling to kernel_config_assert.rs, which drives the assertion against a produced `.config`.

use recipes_image_builder::kconfig_namespace::parse_header;
use recipes_image_builder::kernel::{assert_kernel_config, ConfigAssertError, KernelConfigPins};
use recipes_image_builder::pins::Pins;
use std::collections::BTreeSet;

const SHARED_PINS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/kernel-config-pins.toml"
));
const VPSKVM_PINS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/kernel-config-pins-vpskvm.toml"
));
const BAREMETAL_PINS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/kernel-config-pins-baremetal.toml"
));
const SHARED_FRAGMENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/kernel-hardening.config"
));
const VPSKVM_FRAGMENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/kernel-hardening-vpskvm.config"
));
const BAREMETAL_FRAGMENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/kernel-hardening-baremetal.config"
));
const PINS_TOML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../pins.toml"));

fn fragments() -> [(&'static str, &'static str); 3] {
    [
        ("kernel-hardening.config", SHARED_FRAGMENT),
        ("kernel-hardening-vpskvm.config", VPSKVM_FRAGMENT),
        ("kernel-hardening-baremetal.config", BAREMETAL_FRAGMENT),
    ]
}

fn pin_blocks() -> [(&'static str, KernelConfigPins); 3] {
    [
        ("kernel-config-pins.toml", parse(SHARED_PINS)),
        ("kernel-config-pins-vpskvm.toml", parse(VPSKVM_PINS)),
        ("kernel-config-pins-baremetal.toml", parse(BAREMETAL_PINS)),
    ]
}

fn substrate_blocks() -> [(&'static str, KernelConfigPins); 2] {
    [
        ("kernel-config-pins-vpskvm.toml", parse(VPSKVM_PINS)),
        ("kernel-config-pins-baremetal.toml", parse(BAREMETAL_PINS)),
    ]
}

fn parse(toml: &str) -> KernelConfigPins {
    KernelConfigPins::from_toml_str(toml).expect("pin block parses")
}

/// The symbol half of a pin entry: everything before the first `=`. Covers `CONFIG_X=y`,
/// `CONFIG_X=n`, the quoted string entries, and the `prefix_match` stems (`CONFIG_X="`).
fn symbol_of(entry: &str) -> String {
    entry
        .split_once('=')
        .map(|(sym, _)| sym)
        .unwrap_or(entry)
        .to_string()
}

/// One fragment line that SETS a symbol. `value` is `n` for the disabled form, matching kconfig.
struct Decl {
    symbol: String,
    value: String,
}

/// The declarations a `.config` fragment makes, in the grammar `conf_read_simple` accepts
/// (linux-6.18.34 `scripts/kconfig/confdata.c`): `CONFIG_<name>=<value>` at column 0, or exactly
/// `# CONFIG_<name> is not set`. Leading whitespace disqualifies both forms, and a `#` line that
/// mentions a symbol without the disabled form is not a declaration. `merge_config.sh` appends the whole fragment to
/// the merged file, so what kconfig reads there is what force-sets a symbol.
fn declarations(fragment: &str) -> Vec<Decl> {
    let mut out = Vec::new();
    for line in fragment.lines() {
        if let Some(rest) = line.strip_prefix("# CONFIG_") {
            let Some((name, tail)) = rest.split_once(' ') else {
                continue;
            };
            if name.is_empty() || tail != "is not set" {
                continue;
            }
            out.push(Decl {
                symbol: format!("CONFIG_{name}"),
                value: "n".to_string(),
            });
        } else if let Some(rest) = line.strip_prefix("CONFIG_") {
            let Some((name, value)) = rest.split_once('=') else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            out.push(Decl {
                symbol: format!("CONFIG_{name}"),
                value: value.to_string(),
            });
        }
    }
    out
}

/// A fragment's live (non-disabled) declarations rendered as the prefix guard's `=y` lines.
fn live_declaration_lines(fragment: &str) -> String {
    declarations(fragment)
        .into_iter()
        .filter(|d| d.value != "n")
        .map(|d| format!("{}=y\n", d.symbol))
        .collect()
}

/// A pins block carrying only the substrate's prefix-domain lists, so `assert_kernel_config`
/// exercises the domain guard and nothing else.
fn domain_probe(block: &KernelConfigPins) -> KernelConfigPins {
    KernelConfigPins {
        exact_match: vec![],
        observe_exact: vec![],
        prefix_match: vec![],
        forbidden: vec![],
        forbidden_prefix: block.forbidden_prefix.clone(),
        forbidden_prefix_allow: block.forbidden_prefix_allow.clone(),
    }
}

                                                                                                
                         
                                                                                                

                                                                                            
/// fragment line for an observed symbol turns the observe pin back into a force-set — the merge
/// deletes the base's line for that symbol and appends the fragment's, so a base drift self-heals
/// and the pin reports nothing. That reconversion is what `ce9bff1` removed.
///
/// Model: the declaration grammar above, over the three fragments named in `fragments()`, banning
/// the union of every pin block's `observe_exact`. Blind spots: the base config is not read, so
/// what the BASE carries for an observed symbol is outside this check (the pin gate owns it on the
/// produced `.config`); a fragment file not named here is not scanned.
#[test]
fn no_hardening_fragment_declares_an_observed_symbol() {
    let blocks = pin_blocks();
    let observed: BTreeSet<String> = blocks
        .iter()
        .flat_map(|(_, pins)| pins.observe_exact.iter().map(|e| symbol_of(e)))
        .collect();
                                                     
    for (file, pins) in substrate_blocks() {
        assert!(
            pins.observe_exact.is_empty(),
            "arm sanity: {file} gained an observe_exact — extend the freeze/membership tests \
             in kernel_config_assert.rs before using it"
        );
    }
    assert_eq!(
        observed.len(),
        18,
        "arm sanity: the observe set is the 18 H-1 pins"
    );

    for (file, text) in fragments() {
        let decls = declarations(text);
        assert!(
            !decls.is_empty(),
            "arm sanity: {file} parsed to zero declarations — the scan went blind"
        );
        for d in &decls {
            assert!(
                !observed.contains(&d.symbol),
                "{file} declares {}, which kernel-config-pins.toml OBSERVES: a fragment line \
                 force-sets it, so a base drift self-heals instead of failing the pin",
                d.symbol
            );
        }
    }

    let shared: BTreeSet<String> = declarations(SHARED_FRAGMENT)
        .into_iter()
        .map(|d| d.symbol)
        .collect();
    assert!(
        shared.contains("CONFIG_IMA"),
        "arm sanity: the `=y` form is recognized in the real fragment"
    );
    assert!(
        shared.contains("CONFIG_MODULES"),
        "arm sanity: the disabled form is recognized in the real fragment"
    );
}

/// Self-test for the C1 scanner: it fires on both declaration forms and stays silent on the
/// comment shapes the fragments carry, none of which kconfig reads as a declaration.
#[test]
fn the_declaration_scanner_fires_on_both_forms_and_not_on_comments() {
    for planted in [
        "CONFIG_RANDOMIZE_BASE=y",
        "# CONFIG_RANDOMIZE_BASE is not set",
    ] {
        let frag = format!("# header\n\n{planted}\nCONFIG_OTHER=y\n");
        assert!(
            declarations(&frag)
                .iter()
                .any(|d| d.symbol == "CONFIG_RANDOMIZE_BASE"),
            "the scanner missed `{planted}`"
        );
    }
    for ignored in [
        "# CONFIG_RANDOMIZE_BASE is pinned in kernel-config-pins.toml",
        "# CONFIG_RANDOMIZE_BASE REMOVED",
        "#CONFIG_RANDOMIZE_BASE=y",
        "  CONFIG_RANDOMIZE_BASE=y",
        "CONFIG_RANDOMIZE_BASE",
    ] {
        assert!(
            declarations(ignored).is_empty(),
            "the scanner fired on a non-declaration: `{ignored}`"
        );
    }
}

                                                                                                
                                                      
                                                                                                

/// A line whose first non-whitespace character is `#`.
fn is_comment_line(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// The exact kconfig disabled-declaration form `# CONFIG_<name> is not set` at column 0.
/// `conf_read_simple` reads it as a declaration, so it is exempt from the comment-token rule.
fn is_disabled_declaration(line: &str) -> bool {
    match line.strip_prefix("# CONFIG_") {
        Some(rest) => match rest.split_once(' ') {
            Some((name, tail)) => !name.is_empty() && tail == "is not set",
            None => false,
        },
        None => false,
    }
}

/// A comment line (not the disabled-declaration form) carrying a `CONFIG_` token. `merge_config.sh`
/// re-locates symbol names with an unanchored `grep -w`, so a `CONFIG_`-prefixed token in a comment
/// re-enters the tool's data path even when a non-word char follows it.
fn comment_names_a_config_symbol(line: &str) -> bool {
    is_comment_line(line) && !is_disabled_declaration(line) && line.contains("CONFIG_")
}

                                                                                               
/// token; symbols are named in comments without the prefix.
#[test]
fn no_fragment_comment_names_a_config_symbol() {
    for (file, text) in fragments() {
        for (i, line) in text.lines().enumerate() {
            assert!(
                !comment_names_a_config_symbol(line),
                "{file}:{} names a config symbol by its prefixed token in a comment: \
                 merge_config.sh's `grep -w` re-matches it; name the symbol without the prefix",
                i + 1
            );
        }
    }
}

/// Self-test for C2: the disabled-declaration form is exempt, a prose line naming a symbol fires,
/// and the angle-bracket placeholder fires (it still carries the `CONFIG_` token).
#[test]
fn the_comment_token_scan_exempts_the_disabled_form_and_fires_on_prose() {
    assert!(!comment_names_a_config_symbol("# CONFIG_USB is not set"));
    assert!(comment_names_a_config_symbol(
        "# CONFIG_USB is not set (the guard)"
    ));
    assert!(comment_names_a_config_symbol(
        "# force-disable CONFIG_USB here"
    ));
    assert!(comment_names_a_config_symbol(
        "# no CONFIG_<sym> tokens in comments"
    ));
    assert!(!comment_names_a_config_symbol(
        "# names USB and USB_PCI without a prefix"
    ));
    assert!(!comment_names_a_config_symbol("CONFIG_USB=y"));
}

                                                                                                
                                                    
                                                                                                

                                                                                     
/// `forbidden_prefix` domain, except that block's `forbidden_prefix_allow` entries.
/// `the_hardening_fragments_match_the_substrate_blocks` covers the exact `forbidden` list only, so
/// an UNPINNED force-set under the prefix passes every cargo test and fails first in the vps-kvm
/// kernel build. The domain decision is made by the production guard: the extracted live
/// declarations go to `assert_kernel_config` with the substrate's two prefix lists.
///
/// Model: every symbol the shared fragment declares with a value other than the disabled form,
/// rendered as the guard's `=y` line — `=m` is included because the pinned `CONFIG_MODULES=n`
/// promotes it to builtin. Blind spot: symbols the BASE carries and the fragment never names are
/// outside this scan; the produced-config gate owns those.
#[test]
fn the_shared_fragment_force_sets_nothing_in_a_substrate_forbidden_domain() {
    let live = live_declaration_lines(SHARED_FRAGMENT);
    assert!(
        !live.is_empty(),
        "arm sanity: the shared fragment yielded no live declaration — the scan went blind"
    );
    let mut armed = 0usize;
    for (file, block) in substrate_blocks() {
        if block.forbidden_prefix.is_empty() {
            continue;
        }
        armed += 1;
        if let Err(e) = assert_kernel_config(&live, &domain_probe(&block)) {
            panic!(
                "the shared hardening fragment force-sets a symbol {file} forbids by prefix: {e}"
            );
        }
    }
    assert!(
        armed > 0,
        "arm sanity: no substrate block arms a forbidden_prefix — the check is vacuous"
    );
}

/// Self-test for C3, over a SYNTHETIC fragment so it stays independent of the shipped one: a
/// driver planted under the real armed prefix fires, an `=m` force-set fires, the disabled form
/// does not, and no allowlisted flag does.
#[test]
fn the_forbidden_domain_check_fires_on_a_planted_domain_driver() {
    let (file, block) = substrate_blocks()
        .into_iter()
        .find(|(_, p)| !p.forbidden_prefix.is_empty())
        .expect("a substrate block must arm a forbidden_prefix");
    let prefix = block.forbidden_prefix[0].clone();
    let probe = domain_probe(&block);
    let base = "CONFIG_IMA=y\n# CONFIG_MODULES is not set\n";

    let planted = format!("{base}{prefix}_FLOOR_SELFTEST=y\n");
    let err = assert_kernel_config(&live_declaration_lines(&planted), &probe).unwrap_err();
    assert!(
        matches!(err, ConfigAssertError::Missing(ref m)
            if m.contains("_FLOOR_SELFTEST") && m.contains("forbidden config domain")),
        "{file}: a planted in-domain force-set must fire: {err:?}"
    );

    let modular = format!("{base}{prefix}_FLOOR_SELFTEST=m\n");
    assert!(
        assert_kernel_config(&live_declaration_lines(&modular), &probe).is_err(),
        "{file}: an `=m` in-domain force-set must fire (MODULES=n promotes it to builtin)"
    );

    let disabled = format!("{base}# {prefix}_FLOOR_SELFTEST is not set\n");
    assert!(
        assert_kernel_config(&live_declaration_lines(&disabled), &probe).is_ok(),
        "{file}: the disabled form is not a force-set"
    );

    for allow in &block.forbidden_prefix_allow {
        let benign = format!("{base}{allow}=y\n");
        assert!(
            assert_kernel_config(&live_declaration_lines(&benign), &probe).is_ok(),
            "{file}: the allowlisted flag {allow} must not fire"
        );
    }
}

                                                                                                
                                                                         
                                                                                                

/// The pinned kernel's Kconfig declaration set, keyed by `pins.toml [kernel].version`. Absent
/// fixture ⇒ panic: a kernel bump must regenerate it, and skipping would fail open.
fn kconfig_namespace() -> (String, BTreeSet<String>) {
    let pins = Pins::from_toml_str(PINS_TOML).expect("pins.toml parses");
    let version = pins.kernel.version;
    let sha256 = pins.kernel.sha256;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("kconfig-namespace-{version}.txt"));
    let regen = format!(
        "cargo run -p recipes-image-builder --bin regen-kconfig-namespace -- \
         <staged linux-{version}.tar.xz>"
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "no Kconfig namespace fixture for the pinned kernel {version} at {}: {e}\n\
             regenerate it: {regen}",
            path.display()
        )
    });
                                                                                                 
                                                                                                 
                                 
    let header = text
        .lines()
        .next()
        .and_then(parse_header)
        .unwrap_or_else(|| {
            panic!(
                "fixture {} has no `# linux-<version> <sha256> kconfig namespace` header; \
                 regenerate: {regen}",
                path.display()
            )
        });
    assert_eq!(
        header.version,
        version,
        "fixture {} stamps kernel {} but pins.toml [kernel].version is {version} — \
         the fixture is from another tree; regenerate: {regen}",
        path.display(),
        header.version
    );
    assert_eq!(
        header.sha256,
        sha256,
        "fixture {} stamps sha256 {} but pins.toml [kernel].sha256 is {sha256} — \
         the fixture is from another tarball; regenerate: {regen}",
        path.display(),
        header.sha256
    );
    let set: BTreeSet<String> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    (version, set)
}

/// Every symbol NAME the pin files and fragments reference, with the file that references it.
/// `forbidden_prefix` entries are prefixes rather than symbols, so they are excluded.
fn referenced_symbol_names() -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for (file, pins) in pin_blocks() {
        for entry in pins
            .exact_match
            .iter()
            .chain(&pins.observe_exact)
            .chain(&pins.prefix_match)
            .chain(&pins.forbidden)
        {
            out.push((symbol_of(entry), file));
        }
        for allow in &pins.forbidden_prefix_allow {
            out.push((allow.clone(), file));
        }
    }
    for (file, text) in fragments() {
        for d in declarations(text) {
            out.push((d.symbol, file));
        }
    }
    out
}

                                                                                                  
/// in the pinned kernel's Kconfig namespace. `hardening_fragment_satisfies_every_pin` proves the
/// two hand-edited files AGREE; a name no kernel emits is written into both and passes, which is
                                                                                  
/// `config`/`menuconfig` declaration set of the sha-verified pinned tarball, produced by the
/// `regen-kconfig-namespace` bin (`kconfig_namespace` module).
///
/// Claimed: the NAME is declared somewhere in that version's Kconfig files. Not claimed: that the
/// pinned VALUE is reachable, that the symbol's dependencies are satisfiable, or that it reaches
/// the produced `.config`. Blind spot: the fixture spans every architecture's Kconfig files, so a
/// symbol declared only for another arch passes here; x86_64 reachability is the pin gate's.
#[test]
fn every_referenced_symbol_name_exists_in_the_pinned_kernels_kconfig_namespace() {
    let (version, namespace) = kconfig_namespace();
    let referenced = referenced_symbol_names();

    for anchor in [
        "CONFIG_IMA",                                      
        "CONFIG_RANDOMIZE_BASE",                             
        "CONFIG_SYSTEM_TRUSTED_KEYS",                       
        "CONFIG_USB_STORAGE",                                                      
        "CONFIG_USB_ARCH_HAS_HCD",                                     
        "CONFIG_MODULES",                                              
        "CONFIG_EXT4_FS",                                          
    ] {
        assert!(
            referenced.iter().any(|(sym, _)| sym == anchor),
            "arm sanity: {anchor} was not collected — a source arm went unread"
        );
    }

    let mut absent: Vec<String> = referenced
        .iter()
        .filter(|(sym, _)| !namespace.contains(sym))
        .map(|(sym, file)| format!("{sym} ({file})"))
        .collect();
    absent.sort();
    absent.dedup();
    assert!(
        absent.is_empty(),
        "symbol names absent from the linux-{version} Kconfig namespace: {}",
        absent.join(", ")
    );
}

/// Self-test for C4. Absent: the two phantom symbols this project shipped, one whole-name
/// control, and three names declared only in the walk's excluded subtrees. Present: live pins
/// plus the two Documentation/Kconfig symbols, which pin the exclusion boundary in the widening
                                                              
#[test]
fn the_kconfig_namespace_fixture_rejects_the_shipped_phantoms() {
    let (version, namespace) = kconfig_namespace();
    for phantom in [
        "CONFIG_LOCK_DOWN_KERNEL",
        "CONFIG_INITRAMFS_PRESERVE_XATTRS",
        "CONFIG_IMA_FLOOR_SELFTEST",
                                                                                                   
           
        "CONFIG_BAD_DEPENDS",
        "CONFIG_CORE_BELL_A_ADVANCED",
        "CONFIG_FOO",
    ] {
        assert!(
            !namespace.contains(phantom),
            "the linux-{version} namespace contains {phantom}, which is recorded as absent"
        );
    }
    for real in [
        "CONFIG_IMA",
        "CONFIG_LSM",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_USB",
                                                                                            
                                                                                     
                                                             
        "CONFIG_WARN_MISSING_DOCUMENTS",
        "CONFIG_WARN_ABI_ERRORS",
    ] {
        assert!(
            namespace.contains(real),
            "the linux-{version} namespace is missing {real} — the fixture is truncated or misparsed"
        );
    }
}

                                                                                            
/// namespace — at least one fixture symbol starts with it. `forbidden_prefix` is excluded from the
/// name gate (a prefix is not a symbol), so a typo'd prefix would otherwise guard an empty domain
/// with nothing red.
///
/// Claimed: the prefix names at least one symbol that exists in that version's Kconfig files. Not
/// claimed: that a symbol under the prefix is reachable in any produced `.config`.
#[test]
fn every_forbidden_prefix_matches_a_name_in_the_pinned_kernels_kconfig_namespace() {
    let (version, namespace) = kconfig_namespace();
    let mut checked = 0usize;
    for (file, pins) in pin_blocks() {
        for prefix in &pins.forbidden_prefix {
            checked += 1;
            assert!(
                namespace.iter().any(|sym| sym.starts_with(prefix)),
                "forbidden_prefix {prefix} ({file}) matches no symbol in the linux-{version} \
                 Kconfig namespace: it guards an empty domain (a typo, or a symbol the kernel dropped)"
            );
        }
    }
    assert!(
        checked > 0,
        "arm sanity: no forbidden_prefix entry was checked — a source arm went unread"
    );
}
