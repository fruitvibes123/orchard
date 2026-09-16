//! The `ChildCall` → `std::process::Command` translation, driven against a real spawned process
                                                                                                 
//! every `ChildCall` — the runner→step loop and the guide→run spawn both route through it — and it
//! appeared in no test file, so dropping the cwd or the env application inside it reddened nothing.
//!
//! Recorder: `/usr/bin/env` execs `/bin/sh`, which reports the argv, the physical cwd and two env
//! keys it was given. The oracle is the literal this file composed, never a second read of
//! `ChildCall`. `env` is the program because with NO arguments it prints the environment and exits
//! 0 (run 2026-08-26), so a mutation that drops `call.args` fails these arms instead of leaving a
//! bare `/bin/sh` reading the inherited stdin of the `inherit_stdio` regime.
//!
//! What these arms do NOT cover: `Program::SelfExe`'s `current_exe()` resolution, the child's own
//! reading of the env (the recorder is not `orchard`), and the non-zero-exit `ChildOutcome::Failed`
//! rendering.
//!
//! Cwd states: `ChildCwd::At` is driven by the two regime arms, `ChildCwd::Inherit` by the third.
//! The `Inherit` arm reads the parent's directory before the spawn and compares it to the child's,
//! so a chdir racing it reddens instead of passing; no test in this binary chdirs, and the one
//! `set_current_dir` in the package is in another test binary, another process.

use orchard::ceremony::runner::{ChildCall, ChildCwd, ChildOutcome, Executor, ProcessExecutor};
use orchard::ceremony::spine::{Program, SPINE};

/// Prints one line per positional arg, then the physical cwd, then the two env keys. `pwd -P`
/// reports `getcwd()` rather than an inherited `$PWD`, so a dropped `current_dir` cannot read back
/// as the caller's own directory value.
const REPORT_TO_STDOUT: &str = "printf 'ARGV %s\\n' \"$@\"; \
     printf 'CWD %s\\n' \"$(pwd -P)\"; \
     printf 'ENV_A %s\\n' \"${ORCHARD_FLOOR_ENV_A-unset}\"; \
     printf 'ENV_B %s\\n' \"${ORCHARD_FLOOR_ENV_B-unset}\"";

/// The same report written to the file named by `$1`: in the inherited regime the child holds the
/// real descriptors and the sink is never called, so stdout carries nothing back.
const REPORT_TO_FILE: &str = "{ printf 'ARGV %s\\n' \"$2\"; \
     printf 'CWD %s\\n' \"$(pwd -P)\"; \
     printf 'ENV_A %s\\n' \"${ORCHARD_FLOOR_ENV_A-unset}\"; \
     printf 'ENV_B %s\\n' \"${ORCHARD_FLOOR_ENV_B-unset}\"; } > \"$1\"";

fn call(args: &[&str], cwd: ChildCwd, inherit_stdio: bool) -> ChildCall {
    ChildCall {
        step: SPINE[0].id,
        program: Program::External("/usr/bin/env"),
        args: args.iter().map(|a| (*a).to_string()).collect(),
        cwd,
        env: vec![
            ("ORCHARD_FLOOR_ENV_A".to_string(), "a-value".to_string()),
            ("ORCHARD_FLOOR_ENV_B".to_string(), "b-value".to_string()),
        ],
        inherit_stdio,
    }
}

#[test]
fn the_piped_regime_carries_args_cwd_and_env_into_the_spawned_process() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = std::fs::canonicalize(tmp.path()).expect("canonicalize");
    let mut lines: Vec<String> = Vec::new();
    let outcome = ProcessExecutor.run(
        &call(
            &[
                "/bin/sh",
                "-c",
                REPORT_TO_STDOUT,
                "floor-recorder",
                "alpha-1",
                "beta-2",
            ],
            ChildCwd::At(cwd.clone()),
            false,
        ),
        &mut |line| lines.push(line.to_string()),
    );
                                                                                       
    assert!(
        matches!(outcome, ChildOutcome::Ok),
        "the recorder did not run: {outcome:?} (lines {lines:?})"
    );
    assert_eq!(
        lines,
        vec![
            "ARGV alpha-1".to_string(),
            "ARGV beta-2".to_string(),
            format!("CWD {}", cwd.display()),
            "ENV_A a-value".to_string(),
            "ENV_B b-value".to_string(),
        ],
        "the spawned process did not observe the call's args, cwd and env additions"
    );
}

#[test]
fn the_inherited_regime_spawns_the_same_call_and_never_calls_the_sink() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = std::fs::canonicalize(tmp.path()).expect("canonicalize");
    let report = cwd.join("report");
    let mut lines: Vec<String> = Vec::new();
    let outcome = ProcessExecutor.run(
        &call(
            &[
                "/bin/sh",
                "-c",
                REPORT_TO_FILE,
                "floor-recorder",
                &report.display().to_string(),
                "gamma-3",
            ],
            ChildCwd::At(cwd.clone()),
            true,
        ),
        &mut |line| lines.push(line.to_string()),
    );
    assert!(
        matches!(outcome, ChildOutcome::Ok),
        "the recorder did not run: {outcome:?}"
    );
    let text = std::fs::read_to_string(&report).unwrap_or_else(|e| {
        panic!(
            "the inherited regime spawned no recorder: {} ({e})",
            report.display()
        )
    });
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        vec![
            "ARGV gamma-3",
            &format!("CWD {}", cwd.display()),
            "ENV_A a-value",
            "ENV_B b-value",
        ],
        "the inherited-regime child did not observe the call's args, cwd and env additions"
    );
    assert!(
        lines.is_empty(),
        "the inherited regime gives the child the real descriptors, so the sink stays unused: \
         {lines:?}"
    );
}

#[test]
fn an_inherit_call_reaches_the_child_with_the_parents_own_directory() {
                                                                                                  
                                                                                             
                                                                            
                                                                                                  
                            
    #[allow(clippy::disallowed_methods)]
    let parent = std::env::current_dir().expect("current_dir");
    let here = std::fs::canonicalize(&parent).expect("canonicalize");
    let mut lines: Vec<String> = Vec::new();
    let outcome = ProcessExecutor.run(
        &call(
            &[
                "/bin/sh",
                "-c",
                REPORT_TO_STDOUT,
                "floor-recorder",
                "delta-4",
            ],
            ChildCwd::Inherit,
            false,
        ),
        &mut |line| lines.push(line.to_string()),
    );
                                                                                       
    assert!(
        matches!(outcome, ChildOutcome::Ok),
        "the recorder did not run: {outcome:?} (lines {lines:?})"
    );
    assert_eq!(
        lines,
        vec![
            "ARGV delta-4".to_string(),
            format!("CWD {}", here.display()),
            "ENV_A a-value".to_string(),
            "ENV_B b-value".to_string(),
        ],
        "an Inherit call must reach the child with the parent's own physical cwd"
    );
}
