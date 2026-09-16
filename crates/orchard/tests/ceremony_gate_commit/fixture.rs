//! Real-checkout fixtures for the R16 constructed-commit arms: a git repo with the ceremony's
//! declared paths, the run records that speak for them, and git-side oracles read with `git`
//! itself. Every arm in the parent file drives `run_ceremony` over one of these.

use std::path::{Path, PathBuf};

use orchard::ceremony::Utf8PathBuf;
use orchard::ceremony::admission::{self, Measured, RunInvocation, resolve_values};
use orchard::ceremony::param::ParamValues;
use orchard::ceremony::probes::ProbeCtx;
use orchard::ceremony::records::{RunRecords, StepRecord, finalize_path_record, open_path_record};
use orchard::ceremony::runner::{
    ChildCall, ChildOutcome, Executor, Reporter, RunnerDeps, run_ceremony,
};
use orchard::ceremony::spine::{SPINE, StepId};
use orchard::deploy::context::{ContextSources, ResolvedContext, ValueSource};
use orchard::deploy::profile::Profile;

/// Build a `Utf8PathBuf` from a test path (tmp paths are UTF-8).
pub fn u8p(p: impl AsRef<Path>) -> Utf8PathBuf {
    Utf8PathBuf::from(p.as_ref().to_str().expect("utf8 test path"))
}

/// A container tag no host has, so S1's artifact probe is deterministically not-done.
const ABSENT_TAG: &str = "orchard-ceremony-test-absent:tag";

/// The tracked declared path of every fixture here (a repo-relative string).
pub const TRACKED: &str = "crates/image-builder/pinned-cert-fingerprints.toml";
/// The untracked declared path of every fixture here.
pub const VENDORED: &str = "vendor/x.tar.xz";
/// The bytes every fixture writes at a declared path.
pub const BYTES: &[u8] = b"a\nb\nc\nd\n";

pub struct Fixture {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub ctx: ResolvedContext,
}

impl Fixture {
    pub fn at(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

/// Records every call and answers Ok.
pub struct FakeExec {
    pub calls: Vec<ChildCall>,
}

impl Executor for FakeExec {
    fn run(&mut self, call: &ChildCall, _sink: &mut dyn FnMut(&str)) -> ChildOutcome {
        self.calls.push(call.clone());
        ChildOutcome::Ok
    }
}

pub fn ceremony_profile() -> Profile {
    Profile {
        ip: Some("203.0.113.5".into()),
        container_image: Some(ABSENT_TAG.into()),
        tenant_repo: Some("recipes".into()),
        tenant_artifacts: Some("binary:recipes-app".into()),
        tenant_source_ref: Some("f0ad0fc".into()),
        domain: Some("box.test".into()),
        net: Some("mode=dhcp".into()),
        ..Default::default()
    }
}

/// Run `git` in `root` and return its trimmed stdout; a non-zero exit panics with git's stderr.
/// The test-side oracle: what git says, never what the code under test computed.
pub fn git_out(root: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim_end().to_string()
}

/// `git` in `root` returning (exit-success, stdout, stderr) without asserting.
pub fn git_try(root: &Path, args: &[&str]) -> (bool, String, String) {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("git");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim_end().to_string(),
        String::from_utf8_lossy(&out.stderr).trim_end().to_string(),
    )
}

pub fn git_head(root: &Path) -> String {
    git_out(root, &["rev-parse", "HEAD"])
}

pub fn git_log_message(root: &Path, rev: &str) -> String {
    git_out(root, &["log", "-1", "--format=%B", rev])
}

/// The paths one commit changed, from git's own `show --name-only`. `--no-renames` so a landed
/// removal-plus-addition reports both halves rather than one `R` row.
pub fn git_show_names(root: &Path, rev: &str) -> Vec<String> {
    git_out(
        root,
        &["show", "--name-only", "--no-renames", "--format=", rev],
    )
    .lines()
    .filter(|l| !l.trim().is_empty())
    .map(str::to_string)
    .collect()
}

/// The mode and object type `ls-tree` reports at HEAD for one path.
pub fn landed_entry(root: &Path, rel: &str) -> Option<(String, String)> {
    let raw = git_out(root, &["ls-tree", "HEAD", "--", rel]);
    let line = raw.lines().next()?;
    let (meta, _) = line.split_once('\t')?;
    let mut f = meta.split_whitespace();
    Some((f.next()?.to_string(), f.next()?.to_string()))
}

fn base_fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("orchard");
    std::fs::create_dir_all(&root).expect("root");
    let store = tmp.path().join("artifact-store");
    std::fs::create_dir_all(&store).expect("store");
    let ctx = ResolvedContext {
        repo_root: u8p(&root),
        artifact_store: u8p(&store),
        repo_manifest: u8p(root.join("repo-manifest.toml")),
        sources: ContextSources {
            repo_root: ValueSource::Flag,
            artifact_store: ValueSource::Flag,
            repo_manifest: ValueSource::Flag,
            context_file: None,
        },
    };
    Fixture {
        _tmp: tmp,
        root,
        ctx,
    }
}

fn record_done(
    records: &mut RunRecords,
    step_id: StepId,
    ctx: &ProbeCtx,
    values: &ParamValues,
    measured: &Measured,
) {
    let step = SPINE.iter().find(|s| s.id == step_id).expect("step");
    let mut params = std::collections::BTreeMap::new();
    for p in step.params {
        if let Some(v) = values.get(p.name) {
            params.insert(p.name.to_string(), v.to_string());
        }
    }
    let mut identities = std::collections::BTreeMap::new();
    for id in step.input_identities {
        if let Some(v) = admission::identity_value(id.id, ctx, values, measured) {
            identities.insert(id.id.to_string(), v);
        }
    }
    records
        .record_step(StepRecord {
            step: step_id.token().to_string(),
            run_id: records.run_id().to_string(),
            params,
            input_identities: identities,
            produced: Default::default(),
        })
        .expect("record");
}

/// The gate fixture: a real checkout whose only not-done step is the clean-tree step the gate fires
/// before, the tracked declared path committed at a baseline, and the records handle bound to the
/// checkout (so `core.fileMode` is read from it). `setup` runs on the committed baseline, for the
/// arms that need more history, a git marker, or a different HEAD shape.
pub fn gate_fixture_opts(
    init_extra: &[&str],
    setup: impl FnOnce(&Path),
) -> (
    Fixture,
    RunRecords,
    admission::Admitted,
    RunInvocation,
    Profile,
) {
    let fx = base_fixture();
    let profile = ceremony_profile();
    let mut i = RunInvocation {
        profile_path: "boxes/alpha.toml".into(),
        target: Some("203.0.113.5".into()),
        ..Default::default()
    };
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    let mut records = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1")
        .expect("records")
        .with_checkout(&fx.root);
    for id in [
        StepId::S2OperatorKeys,
        StepId::S5TenantPublish,
        StepId::S6TenantRepin,
        StepId::S7ImageBuild,
        StepId::S8BootGate,
        StepId::S9BoxPreflight,
        StepId::S10ProdInstall,
    ] {
        record_done(&mut records, id, &probe_ctx, &values, &Measured::default());
    }
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted");
    let tracked = fx.at(TRACKED);
    std::fs::create_dir_all(tracked.parent().expect("parent")).expect("mk crates");
    std::fs::write(&tracked, "a\nb\nc\n").expect("baseline write");
    let mut init = vec!["init", "-q"];
    init.extend_from_slice(init_extra);
    for args in [
        init,
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["config", "core.fileMode", "true"],
    ] {
        git_out(&fx.root, &args);
    }
    git_out(&fx.root, &["add", "-A"]);
    git_out(&fx.root, &["commit", "-qm", "baseline"]);
                                                                                                 
    setup(&fx.root);
                                                                                                  
                                              
    let records = records.with_checkout(&fx.root);
                                                                                                   
                                                                             
    let repo_form = fx.root.join(".repo-form");
    std::fs::create_dir_all(&repo_form).expect("mk repo-form");
    i.repo_form_dir = Some(u8p(&repo_form));
    (fx, records, admitted, i, profile)
}

/// Ratify the executing checkout's declared space from its current state, under the current
/// environment (so a decoy `GIT_CONFIG_*` or a test's config edit is captured). The delta-refusal
/// behaviour is exercised by the floor arms that ratify then mutate, not by these helpers.
pub fn ratify_executing(fx: &Fixture, i: &RunInvocation) {
                                                                                                   
                                                                            
    if let Ok(body) = orchard::ceremony::gate_commit::declared_space_body(&fx.root) {
        std::fs::write(i.ratified_file(&fx.ctx.repo_root, "executing"), body)
            .expect("write executing.keys");
    }
}

pub fn gate_fixture_with(
    setup: impl FnOnce(&Path),
) -> (
    Fixture,
    RunRecords,
    admission::Admitted,
    RunInvocation,
    Profile,
) {
    gate_fixture_opts(&[], setup)
}

pub fn gate_fixture() -> (
    Fixture,
    RunRecords,
    admission::Admitted,
    RunInvocation,
    Profile,
) {
    gate_fixture_opts(&[], |_| {})
}

/// What one driven gate run answered, plus every child call the executor saw.
pub struct GateRun {
    pub outcome: Result<(), Box<dyn std::error::Error>>,
    pub calls: Vec<ChildCall>,
}

impl GateRun {
    /// The typed `Refusal` the run stopped on; panics with the error otherwise.
    pub fn refusal(&self) -> &orchard::ceremony::refusal::Refusal {
        let err = self
            .outcome
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("the run was expected to refuse, it succeeded"));
        err.downcast_ref::<orchard::ceremony::refusal::Refusal>()
            .unwrap_or_else(|| panic!("expected a typed Refusal, got: {err}"))
    }
}

/// Drive one whole ceremony run over `fx`. `prompt` answers the consent prompt (`is_tty` true) or
/// panics when the arm claims the stop is pre-prompt; `--commit` is taken from `i.commit`.
pub fn run_gate(
    fx: &Fixture,
    records: &mut RunRecords,
    admitted: &admission::Admitted,
    i: &RunInvocation,
    profile: &Profile,
    is_tty: bool,
    prompt: &dyn Fn() -> char,
) -> GateRun {
    ratify_executing(fx, i);
    run_gate_preratified(fx, records, admitted, i, profile, is_tty, prompt)
}

/// [`run_gate`] WITHOUT the pre-run ratification: for an arm that ratifies a baseline itself and
/// then edits the checkout's configuration, so the gate meets a declared-space delta.
pub fn run_gate_preratified(
    fx: &Fixture,
    records: &mut RunRecords,
    admitted: &admission::Admitted,
    i: &RunInvocation,
    profile: &Profile,
    is_tty: bool,
    prompt: &dyn Fn() -> char,
) -> GateRun {
    let _guard = fd1_guard();
    let reporter = Reporter { porcelain: true };
    let mut exec = FakeExec { calls: vec![] };
    let outcome = {
        let mut deps = RunnerDeps {
            exec: &mut exec,
            reporter: &reporter,
            lock_token: None,
            is_tty,
            prompt,
            editor: None,
        };
        run_ceremony(admitted, i, &fx.ctx, profile, records, &mut deps)
    };
    GateRun {
        outcome,
        calls: exec.calls,
    }
}

/// `run_gate` with the forwarded `--commit` token and a prompt that panics.
pub fn run_gate_headless(
    fx: &Fixture,
    records: &mut RunRecords,
    admitted: &admission::Admitted,
    i: &RunInvocation,
    profile: &Profile,
) -> GateRun {
    let prompt = || panic!("the forwarded token commits with no prompt");
    run_gate(fx, records, admitted, i, profile, false, &prompt)
}

/// `run_gate` at a terminal with a prompt that panics: for an arm claiming a PRE-PROMPT stop.
pub fn run_gate_pre_prompt(
    fx: &Fixture,
    records: &mut RunRecords,
    admitted: &admission::Admitted,
    i: &RunInvocation,
    profile: &Profile,
) -> GateRun {
    let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
    run_gate(fx, records, admitted, i, profile, true, &prompt)
}

/// Record one declared path as this run's write of `bytes`, leaving it dirty in the checkout.
/// `exec` chmods it +x before the finalize, so the witness carries the exec bit.
pub fn record_write(fx: &Fixture, records: &mut RunRecords, rel: &str, bytes: &[u8], exec: bool) {
    use std::os::unix::fs::PermissionsExt as _;
    let p = fx.at(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mk parent");
    }
    let tok = open_path_record(records, &p).expect("open entry");
    std::fs::write(&p, bytes).expect("this run's write");
    if exec {
        let mut perm = std::fs::metadata(&p).expect("stat").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).expect("chmod +x");
    }
    finalize_path_record(records, tok).expect("finalize");
}

/// Dirty both declared paths of a `gate_fixture` as this run's writes: the tracked one staged, the
/// vendored one untracked. Returns the relative paths in dirt-scan order.
pub fn dirty_the_declared_pair(fx: &Fixture, records: &mut RunRecords) -> Vec<String> {
    record_write(fx, records, TRACKED, BYTES, false);
    record_write(fx, records, VENDORED, BYTES, false);
    git_out(&fx.root, &["add", TRACKED]);
    vec![TRACKED.to_string(), VENDORED.to_string()]
}

/// Serializes the arms in this file: [`capture_fd1`] redirects the PROCESS's fd 1, so an arm that
/// reads operator text and an arm that writes it cannot overlap.
static FD1_ARMS: std::sync::Mutex<()> = std::sync::Mutex::new(());

thread_local! {
    /// How many [`Fd1Guard`]s this thread holds: the capture wraps a `run_gate` that takes the same
    /// guard, so the second acquisition on one thread must not block on the first.
    static FD1_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub struct Fd1Guard(#[allow(dead_code)] Option<std::sync::MutexGuard<'static, ()>>);

impl Drop for Fd1Guard {
    fn drop(&mut self) {
        FD1_DEPTH.with(|d| d.set(d.get() - 1));
    }
}

fn fd1_guard() -> Fd1Guard {
    let depth = FD1_DEPTH.with(|d| {
        let was = d.get();
        d.set(was + 1);
        was
    });
    if depth == 0 {
        Fd1Guard(Some(FD1_ARMS.lock().unwrap_or_else(|e| e.into_inner())))
    } else {
        Fd1Guard(None)
    }
}

/// Capture what the process writes to FD 1 while `f` runs. `emit_stdout` writes to the descriptor
/// rather than through `print!`, so the harness's own capture does not see it.
pub fn capture_fd1<T>(f: impl FnOnce() -> T) -> (T, String) {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    let _guard = fd1_guard();
    let sink = tempfile::NamedTempFile::new().expect("capture sink");
    let _ = std::io::stdout().flush();
    let saved = unsafe { libc::dup(1) };
    assert!(saved >= 0, "dup(1) failed");
    assert!(
        unsafe { libc::dup2(sink.as_file().as_raw_fd(), 1) } >= 0,
        "dup2 onto fd 1 failed"
    );
    let out = f();
    let _ = std::io::stdout().flush();
    assert!(
        unsafe { libc::dup2(saved, 1) } >= 0,
        "restoring fd 1 failed"
    );
    unsafe { libc::close(saved) };
    let text = std::fs::read_to_string(sink.path()).expect("read the capture");
    (out, text)
}

/// A records handle on the same dir under a DIFFERENT run id: what a later ceremony run opens.
pub fn records_as_run(fx: &Fixture, run_id: &str) -> RunRecords {
    RunRecords::open_dir(&fx.at("boxes/alpha.d"), run_id)
        .expect("records")
        .with_checkout(&fx.root)
}

/// Arm a hook installed by [`install_hook`]: the hook bodies here act only once this file exists,
/// so the fixture's own index writes (a `git add`) never trip them.
pub fn arm_hook(root: &Path) {
    std::fs::write(root.join(".git/hook-armed"), "").expect("arm the hook");
}

/// The dirt scan's DECLARED paths, through the production read the gate itself uses.
pub fn declared_dirt(root: &Path) -> Vec<String> {
    match admission::git_dirty_paths(root) {
        admission::DirtScan::Scanned(v) => v
            .into_iter()
            .filter(|p| admission::is_declared(p))
            .collect(),
        admission::DirtScan::Unevaluable(m) => {
            panic!("the fixture root is not a readable repo: {m}")
        }
    }
}

/// Install a repository hook, executable, with `body` after a `#!/bin/sh` line.
pub fn install_hook(root: &Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = root.join(".git/hooks");
    std::fs::create_dir_all(&dir).expect("mk hooks");
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}")).expect("write hook");
    let mut perm = std::fs::metadata(&p).expect("stat").permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&p, perm).expect("chmod +x");
}

/// A gate fixture whose executing checkout is a LINKED worktree of a main repository whose path
/// carries the byte 0xFF. In a linked worktree `--git-path` answers an absolute path in the main
/// repository's bytes (pC16c_8/_9), so the marker and grafts predicates must read those bytes.
/// Returns the main repository's git dir and the linked worktree's git dir so an arm can plant a
/// marker and grafts where git reads them.
pub fn gate_fixture_linked_nonutf8() -> (
    Fixture,
    RunRecords,
    admission::Admitted,
    RunInvocation,
    Profile,
    PathBuf,
    PathBuf,
) {
    gate_fixture_linked_nonutf8_with(|_| {})
}

/// [`gate_fixture_linked_nonutf8`] whose `setup` runs INSIDE the linked worktree on the committed
/// baseline, so an arm can leave a real git operation in progress there.
pub fn gate_fixture_linked_nonutf8_with(
    setup: impl FnOnce(&Path),
) -> (
    Fixture,
    RunRecords,
    admission::Admitted,
    RunInvocation,
    Profile,
    PathBuf,
    PathBuf,
) {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut nm = b"main".to_vec();
    nm.push(0xff);
    let main = tmp.path().join(PathBuf::from(OsString::from_vec(nm)));
    std::fs::create_dir_all(&main).expect("mk main");
    let tracked_main = main.join(TRACKED);
    std::fs::create_dir_all(tracked_main.parent().expect("parent")).expect("mk crates");
    std::fs::write(&tracked_main, "a\nb\nc\n").expect("baseline write");
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["config", "core.fileMode", "true"],
    ] {
        git_out(&main, &args);
    }
    git_out(&main, &["add", "-A"]);
    git_out(&main, &["commit", "-qm", "baseline"]);
    git_out(&main, &["branch", "wt"]);
    let root = tmp.path().join("linked");
    git_out(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            root.to_str().expect("linked path is utf8"),
            "wt",
        ],
    );
    setup(&root);
                                                                                                 
    let main_git_dir = main.join(".git");
    let worktree_git_dir = main_git_dir.join("worktrees").join("linked");

    let store = tmp.path().join("artifact-store");
    std::fs::create_dir_all(&store).expect("store");
    let ctx = ResolvedContext {
        repo_root: u8p(&root),
        artifact_store: u8p(&store),
        repo_manifest: u8p(root.join("repo-manifest.toml")),
        sources: ContextSources {
            repo_root: ValueSource::Flag,
            artifact_store: ValueSource::Flag,
            repo_manifest: ValueSource::Flag,
            context_file: None,
        },
    };
    let fx = Fixture {
        _tmp: tmp,
        root: root.clone(),
        ctx,
    };

    let profile = ceremony_profile();
    let mut i = RunInvocation {
        profile_path: "boxes/alpha.toml".into(),
        target: Some("203.0.113.5".into()),
        ..Default::default()
    };
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    let mut records = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1")
        .expect("records")
        .with_checkout(&fx.root);
    for id in [
        StepId::S2OperatorKeys,
        StepId::S5TenantPublish,
        StepId::S6TenantRepin,
        StepId::S7ImageBuild,
        StepId::S8BootGate,
        StepId::S9BoxPreflight,
        StepId::S10ProdInstall,
    ] {
        record_done(&mut records, id, &probe_ctx, &values, &Measured::default());
    }
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted");
    let records = records.with_checkout(&fx.root);
    let repo_form = fx.root.join(".repo-form");
    std::fs::create_dir_all(&repo_form).expect("mk repo-form");
    i.repo_form_dir = Some(u8p(&repo_form));
    (
        fx,
        records,
        admitted,
        i,
        profile,
        main_git_dir,
        worktree_git_dir,
    )
}
