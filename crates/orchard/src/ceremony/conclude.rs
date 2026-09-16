                                                                                              
                                                                                                 
//! private fields and every producer lives in THIS file, so neither the orchard bin nor any other
//! lib module can fabricate either (the verify-fold P-A4 producer-inside-the-lib shape is
//! unrepresentable outside this module). What each type certifies is stated on the type; what it
//! does NOT certify is stated next to it.

use clap::Parser as _;

use super::emit::{emit_stderr, emit_stdout};
use super::porcelain::{ExitClass, OwedStop, class_of_outcome, refusal_record, result_record};
use super::refusal::Refusal;
use crate::cli::{Cli, MarketSub, OrchardCmd};

/// The ceremony's porcelain choice, derived ONCE from the parsed command by `porcelain_of` (the
/// sole producer; fields private). Carrying the choice as a witness instead of raw
/// `Option<&str>` + `bool` arguments closes the verify-fold P-A2/P-A3 shape: a post-parse early
/// abort cannot hand `conclude` a bare `None` (or a wrong `print_context`) to skip its records —
/// it needs a `PorcelainChoice`, and the only path to one is the derivation over the real
/// command. Named residual (accepted, review + fresh-audit surface): a caller deriving from a
/// DECOY `OrchardCmd` or passing a fabricated `print_context` flag; that spelling constructs a
/// second command value and no longer resembles the sanctioned template at the parse site.
pub struct PorcelainChoice {
    verb: Option<&'static str>,
    print_context: bool,
}

/// The verb's `--porcelain` flag + its record token, for the spine-modeled non-interactive verbs
                                                                                                
/// live by `ceremony_selftests::porcelain_flag_is_load_bearing_for_every_spine_modeled_verb`,
/// which drives every spine verb's flag through the real binary (R6 I-5 stands: derive from the
/// clap surface when this list next changes shape — this move kept it verbatim).
pub fn porcelain_of(cmd: &OrchardCmd, print_context: bool) -> PorcelainChoice {
    let verb = match cmd {
        OrchardCmd::GenerateKeys {
            porcelain: true, ..
        } => Some("generate-keys"),
        OrchardCmd::Prime {
            porcelain: true, ..
        } => Some("prime"),
        OrchardCmd::Vendor {
            porcelain: true, ..
        } => Some("vendor"),
        OrchardCmd::Build {
            porcelain: true, ..
        } => Some("build"),
        OrchardCmd::Prod {
            porcelain: true, ..
        } => Some("prod"),
        OrchardCmd::Run {
            porcelain: true, ..
        } => Some("run"),
        OrchardCmd::Market {
            sub: MarketSub::Upgrade {
                porcelain: true, ..
            },
        } => Some("market upgrade"),
        _ => None,
    };
    PorcelainChoice {
        verb,
        print_context,
    }
}

                                                                                          
/// verbatim (clap supplies its trailing newline; no `Error:` prefix), and both conclusion paths
                                                      
#[derive(Debug)]
pub struct UsageError(pub String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

                                                                                             
                                                                                             
/// derived `PorcelainChoice`) and the PRIVATE `usage_concluded` behind `parse_or_usage`
/// (pre-parse), both in this module — so a recordless conclusion cannot be built outside this
/// file, and the Q-N10 delegation shape (a lib wrapper reaching a pub usage constructor) is
/// unrepresentable against a private fn.
///
/// # The exit-surface residual set — canonical home
///
/// THE ONE HOME of what the three exit-discipline mechanisms (TYPE / LINT / BINARY ARMS, named in
/// `main.rs`'s crate-root block) do NOT close. It lived at four sites in this crate and drifted
                                                                                              
/// nothing themselves. Extend or shrink this list here, and nowhere else.
///
/// 1. A DECOY-command derivation. `porcelain_of` is the sole producer of `PorcelainChoice`, but a
///    caller may derive from a fabricated `OrchardCmd` and hand `conclude` a choice carrying no
///    verb, dropping the records the real context owes. Review surface; the one literal
///    derivation site in `main.rs` is count- and argument-frozen by
                                                                                           
/// 2. Edits INSIDE this module. The pub surface is frozen by
///    `enforcement_config::conclude_module_pub_surface_is_frozen` and the producer spellings are
///    counted by `conclusion_producers_in_conclude_rs_are_the_frozen_census` (`Concluded {`,
///    `PorcelainChoice {`, `Self {`), but the BODIES of the existing pub fns are review +
///    fresh-audit surface.
/// 3. The annotated process terminators: the verb-owned exits (`porcelain.rs`
///    `VERB_OWNED_EXIT_SITES`), the broken-pipe backstop, and help/version `Error::exit`. Bounded
///    by the clippy `disallowed_methods` list plus
///    `enforcement_config::disallowed_method_allows_are_call_site_scoped`, which pins each
///    `#[allow]` to its one call line but bounds no COUNT of such sites.
/// 4. A panic: exit 101, or 141 through the broken-pipe backstop, with no records emitted.
///    `ExitClass::Crash` has no producer in `src/` and gains one with the Task-6 runner.
pub struct Concluded {
    class: ExitClass,
}

impl Concluded {
    pub fn class(&self) -> &ExitClass {
        &self.class
    }
}

                                                                                                
/// the help/version exit-0 render, and the usage conclusion live HERE, so `usage_concluded`
/// stays private and post-parse code (bin or lib) cannot reach it. clap routes ONLY
/// DisplayHelp/DisplayVersion to stdout+exit-0 (grounded in clap_builder 4.6.0
                                                                                              
                                                                                                  
/// command exists, so none are owed.
pub fn parse_or_usage() -> Result<Cli, Concluded> {
    match Cli::try_parse() {
        Ok(cli) => Ok(cli),
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                                                                                                 
                                                    
                #[allow(clippy::disallowed_methods)]
                e.exit();
            }
            Err(usage_concluded(UsageError(format!("{e}"))))
        }
    }
}

                                                                                               
/// the witness carries none by construction.
fn usage_concluded(e: UsageError) -> Concluded {
    emit_stderr(&e.to_string());
    Concluded {
        class: ExitClass::Failure,
    }
}

/// The post-parse exit-surface tail: decides the class (typed `Refusal` → refusal-with-cure;
/// `UsageError` and any other Err → operator-fixable `Failure`, exit 1, NOT crash —
                                                                                                 
/// refusal record when refused, then the result record, suppressed ONLY for a SUCCESSFUL
                                                                                                     
                                                                                              
/// closed consumer pipe still exits with the class code.
pub fn conclude(
    choice: PorcelainChoice,
    outcome: Result<(), Box<dyn std::error::Error>>,
) -> Concluded {
                                                                                         
                                        
    let class = class_of_outcome(&outcome);
    if let Err(e) = &outcome {
        match (
            e.downcast_ref::<OwedStop>(),
            e.downcast_ref::<Refusal>(),
            e.downcast_ref::<UsageError>(),
        ) {
            (Some(o), _, _) => emit_stderr(&format!("{o}\n")),
            (None, Some(r), _) => emit_stderr(&format!("{r}\n")),
            (None, None, Some(u)) => emit_stderr(&u.to_string()),
            (None, None, None) => emit_stderr(&render_plain(e.as_ref())),
        }
    }
    if let Some(verb) = choice.verb {
        let suppress_result = choice.print_context && outcome.is_ok();
        if let Err(e) = &outcome {
                                                                                               
                                      
            if let Some(o) = e.downcast_ref::<OwedStop>() {
                emit_stdout(&format!("{}\n", refusal_record(&o.refusal).render()));
            } else if let Some(r) = e.downcast_ref::<Refusal>() {
                emit_stdout(&format!("{}\n", refusal_record(r).render()));
            }
        }
        if !suppress_result {
            emit_stdout(&format!("{}\n", result_record(verb, &class).render()));
        }
    }
    Concluded { class }
}

                                                                                            
fn render_plain(e: &dyn std::error::Error) -> String {
    format!("Error: {e}\n")
}

#[cfg(test)]
mod tests {
    use super::render_plain;

                                                                                         
    /// disclosure keeps its newline bytes; a `Debug` render would escape them to `\\n`.
    #[test]
    fn render_plain_preserves_newlines() {
        let e: Box<dyn std::error::Error> = "first line\nsecond line".to_string().into();
        let rendered = render_plain(e.as_ref());
        assert_eq!(rendered, "Error: first line\nsecond line\n");
        assert!(!rendered.contains("\\n"), "escaped newline in {rendered:?}");
    }
}
