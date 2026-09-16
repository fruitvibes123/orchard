//! The guided-ceremony module tree (spec
                                                                                             
                                                                                           
                                                                                                
                                                                                            
//! `tests/ceremony_selftests.rs`; the runner/gate/interview arms in `tests/ceremony_{runner,gate,
//! interview}.rs`.

pub mod admission;
pub mod classify;
pub mod conclude;
pub mod consent;
pub mod derive;
pub mod disclosure;
pub mod emit;
pub mod gate_commit;
pub mod gate_record;
pub mod handoff;
pub mod interview;
pub mod leg_registry;
pub mod lock;
pub mod param;
pub mod porcelain;
pub mod preflight;
pub mod probes;
pub mod records;
pub mod refusal;
pub mod runner;
pub mod spine;
pub mod summary;
pub mod test_domains;

pub use crate::utf8path::Utf8PathBuf;
pub use admission::{Admitted, Measured, PlannedStep, RunInvocation};
pub use classify::{FlagClass, VerbClass, VerbId, flag_table, verb_class};
pub use emit::{emit_stderr, emit_stdout};
pub use param::{DefaultWithSource, ParamClass, ParamRecord, ParamValues};
pub use porcelain::{ExitClass, OwedKind, OwedStop, PorcelainRecord, exit_code};
pub use probes::{DoneProbe, DoneResult, Probe, ProbeCtx, ProbeResult, SubjectOrigin};
pub use refusal::{Cure, Refusal, RefusalId};
pub use spine::{
    CheckoutRef, ExecutorClass, GateClass, Invocation, Program, SPINE, SiblingId, Step, StepId,
    WriteClass, WriteDecl, spine_modeled_verbs,
};
