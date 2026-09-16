                                                                                               
//! hints and the guide's command table are RENDERED FROM THE SPINE, so ceremony knowledge has one
//! home instead of four (guide / epilogue strings / doctor scopes / runbooks) that drift apart.
//!
//! The P1 evidence this closes: the frozen 2026-07 build hint recommended a bare
//! `orchard dryrun --image <img>`, which for a real-domain image boots a live `fb-acme` under open
                                                                                                  
//! true of a HAND-WRITTEN string that no test compared to anything.

use std::path::Path;

use super::spine::{SPINE, StepId};
use super::test_domains::{DomainClass, classify};

/// One row of the guide's command table, rendered from a spine step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRow {
    pub invocation: String,
    pub purpose: String,
}

                                                                                           
/// `cargo run -p orchard --`, never an absolute `target/release` path — because that is the form
/// the C8 shim makes true from any checkout.
pub const INVOCATION_FORM: &str = "orchard";

                                                                                                 
/// by `ceremony_selftests::derived_surfaces_carry_one_invocation_form`.
pub const BANNED_INVOCATION_FORMS: &[&str] = &["cargo run -p orchard", "target/release/orchard"];

                                                                                               
/// verbs the ceremony does not model are the guide's own and live in the exclusion set.
pub fn spine_command_rows() -> Vec<CommandRow> {
    let mut rows = Vec::new();
    for step in SPINE.iter() {
        let Some(verb) = step.verb else { continue };
        let path = verb.command_path().join(" ");
        let row = CommandRow {
            invocation: format!("{INVOCATION_FORM} {path}"),
            purpose: format!("{} ({})", step.explain, step.id.token()),
        };
        if !rows.contains(&row) {
            rows.push(row);
        }
    }
    rows
}

                                                                                                 
/// so a new hint cannot join them silently. The two Secure-Boot hints are out of the spine's
/// coverage (the SB rung joins in a later cycle); the maintenance rows are the guide's own.
pub const DERIVED_SURFACE_EXCLUSIONS: &[&str] = &[
    "generate_keys_secure_boot_next_steps",
    "sign_sb_next_steps",
    "orchard sync-pins",
    "orchard refresh-apk-lock",
    "orchard update-cert-fingerprints",
    "orchard market store status",
    "orchard market store prune",
];

                                                                           
///
/// A test-domain image may be gated by the ceremony's own composition. A real-domain image's
/// baked `fb-acme` reaches a live ACME endpoint the moment it boots, so the hint must never
/// suggest a bare `dryrun` (the P1 defect) and never a verification command that boots it under
/// open NAT: it names the gate whose composition is hermetic AND exercises the production
/// installed-disk boot, and when no such composition exists it names the S8 refusal and the debt
/// instead of inventing a command.
pub fn build_next_steps(img: &Path, domain: &str, repo_root: &Path) -> Vec<String> {
    let img = img.display();
    let gate = super::spine::CEREMONY_GATE_TARGET;
    match classify(domain) {
        DomainClass::Test => vec![
            format!(
                "{INVOCATION_FORM} run <profile> --target <ip>    # the ceremony gates and \
                 installs this image"
            ),
            format!(
                "make {gate}    # or gate it alone: needs /dev/kvm and this image at \
                 RECIPES_DRYRUN_IMG + RECIPES_PROD_IMG ({img})"
            ),
        ],
        DomainClass::Real => match real_domain_gate(repo_root) {
            Some(target) => vec![
                format!(
                    "{INVOCATION_FORM} run <profile> --target <ip>    # {domain} is a real domain: \
                     its gate boot must be hermetic, and `make {target}` is"
                ),
                format!("make {target}    # the hermetic installed-disk composition ({img})"),
            ],
            None => vec![
                format!(
                    "# {domain} is a real domain, so this image's gate boot must be hermetic AND \
                     must exercise the SeaBIOS installed-disk boot. No composition satisfies both \
                     yet (spec Q7), so S8 REFUSES this image — there is no command to run here."
                ),
                format!(
                    "# To proceed, build for a test domain, or land the Q7 hermeticity item. The \
                     image is at {img}."
                ),
            ],
        },
    }
}

/// The ceremony's gate target when its DECLARED COMPOSITION is hermetic AND exercises the
/// production installed-disk boot; `None` otherwise. Derived exactly as S10's own precondition
/// derives it (`gate_record::s10_precondition`): read the target's recipe from the Makefile and
/// apply the predicate to the legs `composition_of` enumerates — never to the whole leg registry.
/// The predicate and the target are the ONE the precondition uses (`CEREMONY_GATE_TARGET`), so a
/// `Some` here is a gate S10 will accept and a `None` is a gate it would refuse; scanning the
/// registry instead answered over a set the gate never runs and named a divergent literal
                                  
pub fn real_domain_gate(repo_root: &Path) -> Option<&'static str> {
    let target = super::spine::CEREMONY_GATE_TARGET;
    let makefile = std::fs::read_to_string(repo_root.join("Makefile")).ok()?;
    let declared = super::leg_registry::composition_of(&makefile, target).ok()?;
    super::gate_record::satisfies_real_domain(&declared.legs).then_some(target)
}

/// The step a hint points at after S7, for the derivation arm to anchor on.
pub const POST_BUILD_STEP: StepId = StepId::S8BootGate;
