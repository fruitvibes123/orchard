                                                                                                  
//! the derivation of its hermeticity from its OWN configuration.
//!
//! The predicate is the leg's ACTUAL network mode, never the helper's capability. Each leg
//! registers its own `DryrunOpts`/`DebianE2eOpts` constructor here, THE LEG BODY BOOTS THROUGH
//! THAT ENTRY, and the derivation drives the registered constructor into the leg's boot path's
//! REAL netdev builder and classifies the leg hermetic iff the produced argv carries
//! `,restrict=on`. Driving a builder with a synthetic `restrict_net = true` would measure
//! capability: every launcher here is capable, and what matters is which ones switch it on.
//!
//! Grounded at 2026-08-19 (the plan's `0fbb20c` snapshot is stale, see the plan's Task-7 note):
//! `DryrunOpts::default().restrict_net` is `true` since the si land, all three services-box
//! launchers render through the one `qemu::user_netdev_arg`
//! (`deploy/dryrun/qemu.rs:97,316,421`), and `prod_e2e` keeps its own builder — so the derivation
//! drives two builders, and a hermetic SeaBIOS installed-disk leg EXISTS.

use super::gate_record::{BootPath, LegSpec};
use crate::deploy::dryrun::DryrunOpts;
use crate::deploy::prod_e2e::DebianE2eOpts;

/// How a leg configures its guest. The variant selects which netdev builder the derivation
/// drives, so a leg cannot be classified by a builder it does not use.
#[derive(Clone, Copy)]
pub enum LegOpts {
    Dryrun(fn() -> DryrunOpts),
    DebianE2e(fn() -> DebianE2eOpts),
    /// The leg launches no guest (the byte-reproducibility bakes). It boots nothing, so it has no
                                                                                       
    NoGuest,
}

/// One registered gate leg.
pub struct GateLeg {
    /// The leg id the gate record carries. Equal to the test fn name, so a record row and a
    /// `cargo test` name filter denote the same thing without a translation table.
    pub id: &'static str,
    /// The test binary the leg lives in (`--test <binary>`).
    pub test_binary: &'static str,
    pub boot_path: BootPath,
    pub opts: LegOpts,
}

impl GateLeg {
    /// Does this leg boot the image? Derived from the opts variant, not declared twice.
    pub fn boots(&self) -> bool {
        !matches!(self.opts, LegOpts::NoGuest)
    }

    /// The leg's ACTUAL network mode, derived by driving its own registered constructor through
    /// the real builder its boot path uses.
    pub fn hermetic(&self) -> bool {
        match self.opts {
            LegOpts::NoGuest => false,
            LegOpts::Dryrun(make) => {
                crate::deploy::dryrun::qemu::user_netdev_arg(&make()).contains(",restrict=on")
            }
            LegOpts::DebianE2e(make) => {
                let o = make();
                crate::deploy::prod_e2e::debian_user_netdev_arg(o.forward_port, o.restrict_net)
                    .contains(",restrict=on")
            }
        }
    }

    pub fn spec(&self) -> LegSpec {
        LegSpec {
            id: self.id.to_string(),
            boots: self.boots(),
            hermetic: self.hermetic(),
            boot_path: self.boot_path,
        }
    }
}

                                                                                                   

/// `deploy_dryrun::dryrun_boots_to_working_runtime`. The leg adds its HTTP probe on top; that
/// setter is proven network-neutral by `builder_setters_never_touch_the_network_mode`.
pub fn dryrun_runtime_opts() -> DryrunOpts {
    DryrunOpts::default()
}

/// `deploy_prod_qemu::installed_disk_boots_through_seabios_to_working_runtime`.
pub fn installed_disk_opts() -> DryrunOpts {
    DryrunOpts::default()
}

/// `deploy_rescue_smoke::rescue_bundle_activates_on_corrupt_persist`.
pub fn rescue_bundle_opts() -> DryrunOpts {
    DryrunOpts::default()
}

/// `deploy_rescue_smoke::rescue_activates_on_rc4_corrupt_persist` — distinct host ports so the two
/// rescue legs can run in parallel (the defaults would collide).
pub fn rescue_rc4_opts() -> DryrunOpts {
    DryrunOpts {
        ssh_port: 2223,
        https_port: 8444,
        ..DryrunOpts::default()
    }
}

/// `deploy_restore_smoke::restore_from_verifies_before_any_write_on_produced_bytes`.
pub fn restore_from_opts() -> DryrunOpts {
    DryrunOpts::default()
}

/// `deploy_prod_e2e::debian_guest_kexec_takeover_installs_the_box_and_identity_passes`.
pub fn prod_e2e_opts() -> DebianE2eOpts {
    DebianE2eOpts::default()
}

/// `deploy_ceremony_e2e::the_ceremony_installs_a_serving_box_from_a_profile_on_produced_bytes` —
                                                                                         
pub fn ceremony_e2e_opts() -> DebianE2eOpts {
    DebianE2eOpts::default()
}

/// The registered legs. Only legs a ceremony gate target can declare belong here; the
/// whole-package bake set is represented by its selector, not enumerated (see `Selector`).
pub static REGISTRY: &[GateLeg] = &[
    GateLeg {
        id: "dryrun_boots_to_working_runtime",
        test_binary: "deploy_dryrun",
        boot_path: BootPath::DirectKernel,
        opts: LegOpts::Dryrun(dryrun_runtime_opts),
    },
    GateLeg {
        id: "installed_disk_boots_through_seabios_to_working_runtime",
        test_binary: "deploy_prod_qemu",
        boot_path: BootPath::SeabiosInstalledDisk,
        opts: LegOpts::Dryrun(installed_disk_opts),
    },
    GateLeg {
        id: "rescue_bundle_activates_on_corrupt_persist",
        test_binary: "deploy_rescue_smoke",
        boot_path: BootPath::DirectKernel,
        opts: LegOpts::Dryrun(rescue_bundle_opts),
    },
    GateLeg {
        id: "rescue_activates_on_rc4_corrupt_persist",
        test_binary: "deploy_rescue_smoke",
        boot_path: BootPath::DirectKernel,
        opts: LegOpts::Dryrun(rescue_rc4_opts),
    },
    GateLeg {
        id: "restore_from_verifies_before_any_write_on_produced_bytes",
        test_binary: "deploy_restore_smoke",
        boot_path: BootPath::SeabiosInstalledDisk,
        opts: LegOpts::Dryrun(restore_from_opts),
    },
    GateLeg {
        id: "the_ceremony_installs_a_serving_box_from_a_profile_on_produced_bytes",
        test_binary: "deploy_ceremony_e2e",
        boot_path: BootPath::ProdE2e,
        opts: LegOpts::DebianE2e(ceremony_e2e_opts),
    },
    GateLeg {
        id: "debian_guest_kexec_takeover_installs_the_box_and_identity_passes",
        test_binary: "deploy_prod_e2e",
        boot_path: BootPath::ProdE2e,
        opts: LegOpts::DebianE2e(prod_e2e_opts),
    },
];

pub fn leg(id: &str) -> Option<&'static GateLeg> {
    REGISTRY.iter().find(|l| l.id == id)
}

                                                                                                    

/// What one `cargo test` invocation in a gate recipe selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// `--test <binary> -- … <name>`: the named legs of one test binary.
    Named {
        test_binary: String,
        names: Vec<String>,
    },
    /// `--test <binary> -- … --skip <name>`: every ignored leg of that binary EXCEPT the skipped
    /// ones. Not enumerable from the recipe alone — the binary's own ignored set decides.
    AllExceptSkipped {
        test_binary: String,
        skipped: Vec<String>,
    },
    /// `--test <binary> -- --ignored` with no name filter: every ignored leg of that binary.
    AllOfBinary { test_binary: String },
    /// No `--test` token: the whole package's ignored set (`cargo test -p <pkg> -- --ignored`).
    WholePackageIgnored { package: String },
    /// `$(MAKE) <target>`: the recipe delegates part of its composition to another target. The
    /// legs are that target's, so the derivation FOLLOWS it — a delegation the parser merely
    /// skipped would silently shrink the declared composition, which is the false green the
    /// fail-closed rule exists to prevent.
    Delegates { target: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: String,
    pub why: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unclassifiable `cargo test` line ({}): {}",
            self.why, self.line
        )
    }
}

/// Extract a make target's recipe lines (the tab-indented block after `<target>:`).
pub fn recipe_of(makefile: &str, target: &str) -> Option<Vec<String>> {
    let head = format!("{target}:");
    let mut lines = makefile.lines();
    lines
        .by_ref()
        .find(|l| l.trim_end() == head || l.starts_with(&head))?;
    let mut out = Vec::new();
    for l in lines {
                                                                                            
        if l.starts_with('\t') {
            out.push(l.trim_start_matches('\t').to_string());
        } else if l.trim().is_empty() || l.trim_start().starts_with('#') {
            continue;
        } else {
            break;
        }
    }
    Some(out)
}

/// Classify EVERY `cargo test` invocation in a recipe. FAIL-CLOSED: a `cargo test` line this
/// parser cannot classify is an Err, never a skip — a silently-dropped invocation would let the
/// agreement test green a composition that runs legs it never declared.
pub fn selectors_of(recipe: &[String]) -> Result<Vec<Selector>, ParseError> {
    let mut out = Vec::new();
    for line in recipe {
        if !is_invocation(line) {
            continue;
        }
        out.push(classify_line(line)?);
    }
    Ok(out)
}

/// Is this recipe line a `cargo test` INVOCATION? Two shapes mention `cargo test` without being
/// one, and both are excluded by what they ARE rather than by a keyword: a make recipe COMMENT
/// (`#` first), and an `echo` whose message quotes a command. Everything else containing
/// `cargo test` must classify or hard-fail — the exclusions are narrow so the fail-closed rule
/// keeps its reach.
fn is_invocation(line: &str) -> bool {
    if !line.contains("cargo test") && !line.contains("$(MAKE)") {
        return false;
    }
    let cmd = line
        .trim_start()
        .trim_start_matches(['@', '-'])
        .trim_start();
    if cmd.starts_with('#') {
        return false;
    }
    if cmd.starts_with("echo ") || cmd.starts_with("echo\t") {
        return false;
    }
    true
}

fn classify_line(line: &str) -> Result<Selector, ParseError> {
    let err = |why: &str| ParseError {
        line: line.to_string(),
        why: why.to_string(),
    };
    if let Some(at) = line.find("$(MAKE)") {
        let rest = line[at + "$(MAKE)".len()..].trim();
        let target = rest
            .split_whitespace()
            .next()
            .ok_or_else(|| err("`$(MAKE)` with no target"))?;
        if target.starts_with('-') || target.contains('=') {
            return Err(err(
                "a `$(MAKE)` line carrying flags or variables is not modelled",
            ));
        }
        return Ok(Selector::Delegates {
            target: target.to_string(),
        });
    }
                                                                                           
                                                                                                
    let at = line
        .find("cargo test")
        .ok_or_else(|| err("no `cargo test`"))?;
    let tail = &line[at..];
                                                                                              
                                                      
    let end = tail
        .find(" 2>&1")
        .or_else(|| tail.find(" |"))
        .or_else(|| tail.find(')'))
        .unwrap_or(tail.len());
    let toks: Vec<&str> = tail[..end].split_whitespace().collect();
    let package = match toks.iter().position(|t| *t == "-p") {
        Some(i) => toks
            .get(i + 1)
            .ok_or_else(|| err("`-p` with no package"))?
            .to_string(),
        None => {
            return Err(err(
                "no `-p <package>` — this parser models package-scoped gates only",
            ));
        }
    };
    let test_binary = toks
        .iter()
        .position(|t| *t == "--test")
        .map(|i| match toks.get(i + 1) {
                                                                                                  
                                                                                                  
            Some(t) if !t.starts_with('-') => Ok((*t).to_string()),
            _ => Err(err("`--test` with no binary name")),
        })
        .transpose()?;
    let sep = toks.iter().position(|t| *t == "--");
    let after: &[&str] = match sep {
        Some(i) => &toks[i + 1..],
        None => &[],
    };
    if !after.contains(&"--ignored") {
        return Err(err(
            "no `--ignored` after `--` — a gate leg is an ignored test",
        ));
    }
                                                                               
    const HARNESS_FLAGS: &[&str] = &["--ignored", "--nocapture", "--include-ignored", "--exact"];
    let mut names = Vec::new();
    let mut skipped = Vec::new();
    let mut i = 0;
    while i < after.len() {
        let t = after[i];
        if t == "--skip" {
            let n = after
                .get(i + 1)
                .ok_or_else(|| err("`--skip` with no name"))?;
            skipped.push((*n).to_string());
            i += 2;
            continue;
        }
        if HARNESS_FLAGS.contains(&t) {
            i += 1;
            continue;
        }
        if t.starts_with("--") {
            return Err(err("unknown harness flag after `--`"));
        }
        names.push(t.to_string());
        i += 1;
    }
    let Some(test_binary) = test_binary else {
        if !names.is_empty() || !skipped.is_empty() {
            return Err(err("a name filter with no `--test` binary is not modelled"));
        }
        return Ok(Selector::WholePackageIgnored { package });
    };
    Ok(match (names.is_empty(), skipped.is_empty()) {
        (false, true) => Selector::Named { test_binary, names },
        (true, false) => Selector::AllExceptSkipped {
            test_binary,
            skipped,
        },
        (true, true) => Selector::AllOfBinary { test_binary },
        (false, false) => return Err(err("both a name filter and `--skip` is not modelled")),
    })
}

/// The composition a gate target declares, for targets whose every invocation names its legs
/// explicitly. Returns `Err` for a target this cannot enumerate — a whole-package or
/// skip-filtered invocation depends on a binary's own ignored set, which the recipe does not
/// carry, so the composition is not derivable from the Makefile alone and saying otherwise would
/// be the false-green the fail-closed parser exists to prevent.
pub fn composition_of(
    makefile: &str,
    target: &str,
) -> Result<super::gate_record::DeclaredComposition, String> {
    let mut seen = Vec::new();
    let legs = legs_of(makefile, target, &mut seen)?;
    Ok(super::gate_record::DeclaredComposition {
        gate_target: target.to_string(),
        legs,
    })
}

/// The recursive half. `seen` bounds delegation: a target that delegates back into the chain is a
/// cycle, and a cycle in a GATE recipe would otherwise be an infinite composition.
fn legs_of(
    makefile: &str,
    target: &str,
    seen: &mut Vec<String>,
) -> Result<Vec<super::gate_record::LegSpec>, String> {
    if seen.iter().any(|t| t == target) {
        return Err(format!(
            "gate target `{target}` delegates back into its own chain ({seen:?}) — a cycle has no              composition"
        ));
    }
    seen.push(target.to_string());
    let recipe = recipe_of(makefile, target).ok_or_else(|| format!("no target `{target}`"))?;
    let selectors = selectors_of(&recipe).map_err(|e| e.to_string())?;
    let mut legs = Vec::new();
    for s in &selectors {
        match s {
            Selector::Named { test_binary, names } => {
                for n in names {
                    let l = leg(n).ok_or_else(|| {
                        format!(
                            "target `{target}` names leg `{n}`, which the registry does not carry"
                        )
                    })?;
                    if l.test_binary != test_binary {
                        return Err(format!(
                            "leg `{n}` is registered in `{}` and the recipe runs it via `--test {test_binary}`",
                            l.test_binary
                        ));
                    }
                    legs.push(l.spec());
                }
            }
            Selector::Delegates { target: sub } => {
                for spec in legs_of(makefile, sub, seen)? {
                    if !legs.contains(&spec) {
                        legs.push(spec);
                    }
                }
            }
            other => {
                return Err(format!(
                    "target `{target}` carries an invocation this derivation cannot enumerate \
                     ({other:?}): its leg set depends on a test binary's own ignored set, not on \
                     the recipe"
                ));
            }
        }
    }
    Ok(legs)
}
