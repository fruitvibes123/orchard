                                                                                                     
//! the verified witness through git plumbing — blob, tree, commit, ref compare-and-swap — so the
//! landed artifact's identity is the construction: no porcelain commit runs, no host commit hook
//! runs, no owed path string reaches git's argv, and the landed HEAD is compared to the constructed
//! commit id. Porcelain's finesse-state classes each lose their entry point.
//!
//! Every git command the ceremony issues runs through the [`Git`] runner over [`ceremony_git`]: `git
//! --no-replace-objects -C <repo> ...` with a `GIT_*` environment stripped to a pass-through
//! allowlist, so an inherited `GIT_DIR`, `GIT_INDEX_FILE` or `GIT_OBJECT_DIRECTORY` cannot answer
//! for another repository
                                                                    

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::records::{
    ContentState, DeclaredPathName, DirtClass, GateContent, PathWitness, RunRecords,
};
use super::refusal::{
    GitReadFailure, GitReadPurpose, GitRunError, InProgressOp, Refusal, RefusalId,
    RepoFormCondition, TypedCure,
};

/// The `GIT_*` names copied through to a ceremony git command unchanged (§3.11): ident and dates,
/// and the config-location variables. Every other `GIT_*` name is stripped (unmodelled input fails
/// closed to "not passed"); `GIT_INDEX_FILE` is set only by [`ceremony_git_indexed`].
const GIT_PASSTHROUGH: &[&str] = &[
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
];

/// A `git` command in `repo_root` with the §3.11 child environment: `--no-replace-objects`, `-C
/// <repo_root>`, every inherited `GIT_*` removed except [`GIT_PASSTHROUGH`]. Every ceremony git
/// spawn constructs through this.
fn ceremony_git(repo_root: &Path) -> Command {
    let mut cmd = Command::new("git");
    for (name, _) in std::env::vars_os() {
        if is_stripped_git_var(&name) {
            cmd.env_remove(&name);
        }
    }
                                                                                                    
                                                                                                    
                                                                            
    cmd.env("GIT_NO_LAZY_FETCH", "1");
    cmd.arg("--no-replace-objects").arg("-C").arg(repo_root);
    cmd
}

/// The [`ceremony_git`] command with `GIT_INDEX_FILE` set to a private index (§3.4 construction).
fn ceremony_git_indexed(repo_root: &Path, index: &Path) -> Command {
    let mut cmd = ceremony_git(repo_root);
    cmd.env("GIT_INDEX_FILE", index);
    cmd
}

/// True for a `GIT_*` name outside the pass-through allowlist.
fn is_stripped_git_var(name: &std::ffi::OsStr) -> bool {
    #[cfg(unix)]
    let starts_git = {
        use std::os::unix::ffi::OsStrExt as _;
        name.as_bytes().starts_with(b"GIT_")
    };
    #[cfg(not(unix))]
    let starts_git = name.to_str().is_some_and(|s| s.starts_with("GIT_"));
    if !starts_git {
        return false;
    }
    match name.to_str() {
        Some(s) => !GIT_PASSTHROUGH.contains(&s),
                                                                             
        None => true,
    }
}

                                                                                                    

/// exit 0 → the decoded stdout `T`; a non-zero exit → the exit code and the lossy-decoded stderr.
/// `stderr` feeds `Display` only (§8 Q-stderr).
pub(in crate::ceremony) enum GitReply<T> {
    Ok(T),
    Exit { code: Option<i32>, stderr: String },
}

/// The single seam every ceremony git command constructs through (§1.1). `new` fixes the repo root
/// and the §3.11 child environment; `index` sets the private `GIT_INDEX_FILE`; the four terminals
/// spawn and decode.
pub(in crate::ceremony) struct Git {
    repo_root: PathBuf,
    index: Option<PathBuf>,
    args: Vec<std::ffi::OsString>,
}

impl Git {
    pub(in crate::ceremony) fn new(repo_root: &Path) -> Self {
        Git {
            repo_root: repo_root.to_path_buf(),
            index: None,
            args: Vec::new(),
        }
    }

    pub(in crate::ceremony) fn index(mut self, index: &Path) -> Self {
        self.index = Some(index.to_path_buf());
        self
    }

    pub(in crate::ceremony) fn args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(std::ffi::OsString::from));
        self
    }

    pub(in crate::ceremony) fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    fn command(&self) -> Command {
        let mut cmd = match &self.index {
            Some(index) => ceremony_git_indexed(&self.repo_root, index),
            None => ceremony_git(&self.repo_root),
        };
        cmd.args(&self.args);
        cmd
    }

    /// exit 0 required; stdout decoded strict (§1.2); trailing whitespace kept, the caller trims.
    pub(in crate::ceremony) fn text(self, op: &str) -> Result<String, GitRunError> {
        utf8(op, &run(self.command(), op)?)
    }

    /// exit 0 → `Ok(text)` (strict); non-zero → `Exit { code, stderr }`; spawn failure → `Err(Spawn)`.
    pub(in crate::ceremony) fn text_or_exit(
        self,
        op: &str,
    ) -> Result<GitReply<String>, GitRunError> {
        Ok(match spawn_reply(self.command(), op)? {
            SpawnReply::Ok(stdout) => GitReply::Ok(utf8(op, &stdout)?),
            SpawnReply::Exit { code, stderr } => GitReply::Exit { code, stderr },
        })
    }

    /// stdout as bytes; non-zero → `Exit`; spawn failure → `Err(Spawn)`. Consumers: blob content,
    /// the `for-each-ref refs/replace/` emptiness predicate, `measure_key_set`'s per-field decode
    /// (§1.1).
    pub(in crate::ceremony) fn content_or_exit(
        self,
        op: &str,
    ) -> Result<GitReply<Vec<u8>>, GitRunError> {
        Ok(match spawn_reply(self.command(), op)? {
            SpawnReply::Ok(stdout) => GitReply::Ok(stdout),
            SpawnReply::Exit { code, stderr } => GitReply::Exit { code, stderr },
        })
    }

    /// stdin fed, exit 0 required, stdout strict (§1.1).
    pub(in crate::ceremony) fn text_with_stdin(
        self,
        input: &[u8],
        op: &str,
    ) -> Result<String, GitRunError> {
        utf8(op, &run_stdin(self.command(), input, op)?)
    }
}

/// Capture stdout of a ceremony git command with a null stdin; a non-zero exit is `Exit`.
fn run(mut cmd: Command, op: &str) -> Result<Vec<u8>, GitRunError> {
    let out = cmd.output().map_err(|e| GitRunError::Spawn {
        op: op.to_string(),
        err: e.to_string(),
    })?;
    if !out.status.success() {
        return Err(GitRunError::Exit {
            op: op.to_string(),
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(out.stdout)
}

enum SpawnReply {
    Ok(Vec<u8>),
    Exit { code: Option<i32>, stderr: String },
}

/// Spawn with a null stdin; a non-zero exit yields its code and lossy stderr rather than an error.
/// Only a spawn/IO failure is `Err`.
fn spawn_reply(mut cmd: Command, op: &str) -> Result<SpawnReply, GitRunError> {
    let out = cmd.output().map_err(|e| GitRunError::Spawn {
        op: op.to_string(),
        err: e.to_string(),
    })?;
    if out.status.success() {
        return Ok(SpawnReply::Ok(out.stdout));
    }
    Ok(SpawnReply::Exit {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
    })
}

/// Feed `input` on stdin, capture stdout. A spawn or stdin/wait I/O failure is `Spawn`; a non-zero
/// exit is `Exit`.
fn run_stdin(mut cmd: Command, input: &[u8], op: &str) -> Result<Vec<u8>, GitRunError> {
    use std::io::Write as _;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let spawn_err = |err: String| GitRunError::Spawn {
        op: op.to_string(),
        err,
    };
    let mut child = cmd.spawn().map_err(|e| spawn_err(e.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input)
            .map_err(|e| spawn_err(format!("stdin write: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| spawn_err(format!("wait: {e}")))?;
    if !out.status.success() {
        return Err(GitRunError::Exit {
            op: op.to_string(),
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(out.stdout)
}

/// The `sample` for [`GitRunError::NonUtf8Output`]: `escape_ascii`, cut to 120 characters (§1.2).
pub(crate) fn non_utf8_sample(bytes: &[u8]) -> String {
    bytes.escape_ascii().to_string().chars().take(120).collect()
}

/// The record enclosing `offset`, delimited by the nearest NUL or LF on either side (excluded); the
/// whole slice when neither delimiter is present (§1.7).
pub(in crate::ceremony) fn offending_record(bytes: &[u8], offset: usize) -> &[u8] {
    let is_delim = |b: &u8| *b == b'\0' || *b == b'\n';
    let start = bytes[..offset]
        .iter()
        .rposition(is_delim)
        .map_or(0, |i| i + 1);
    let end = bytes[offset..]
        .iter()
        .position(is_delim)
        .map_or(bytes.len(), |i| offset + i);
    &bytes[start..end]
}

/// Decode git's output as UTF-8; a non-UTF-8 sequence is [`GitRunError::NonUtf8Output`] (§1.2), so
/// the site fails closed rather than substituting U+FFFD. The sample is the offending record around
/// the first invalid byte (§1.7).
pub(in crate::ceremony) fn utf8(op: &str, bytes: &[u8]) -> Result<String, GitRunError> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s.to_string()),
        Err(e) => Err(GitRunError::NonUtf8Output {
            op: op.to_string(),
            sample: non_utf8_sample(offending_record(bytes, e.valid_up_to())),
        }),
    }
}

/// The one trailing LF git appends to a `--git-path` answer removed, the rest a `PathBuf` (§1.3).
fn git_path_pathbuf(text: &str) -> PathBuf {
    PathBuf::from(text.strip_suffix('\n').unwrap_or(text))
}

/// The `ExitStatus` Display for an exit `code`; a signal (code `None`) names no number.
pub(in crate::ceremony) fn exit_status_string(code: Option<i32>) -> String {
    match code {
        Some(c) => format!("exit status: {c}"),
        None => "terminated by a signal".to_string(),
    }
}

fn config_read(repo_root: &Path, args: &[&str], op: &str) -> Result<String, GitRunError> {
    match Git::new(repo_root).args(args).text_or_exit(op)? {
        GitReply::Ok(value) => Ok(value),
        GitReply::Exit { code, stderr } => Err(GitRunError::Exit {
            op: op.to_string(),
            status: exit_status_string(code),
            stderr,
        }),
    }
}

fn unreadable(e: GitRunError) -> Refusal {
    unreadable_at(
        "cannot read the checkout's git state for the commit gate",
        e,
    )
}

fn unreadable_at(what: &str, e: GitRunError) -> Refusal {
    let detail = format!("{what}: {e}");
    Refusal::typed(
        RefusalId::GitStateUnreadable,
        detail,
        &GitReadFailure {
            purpose: GitReadPurpose::CommitGate,
            outcome: e,
        },
    )
}

fn form_refusal(cond: RepoFormCondition, detail: String) -> Refusal {
    Refusal::typed(RefusalId::RepositoryFormUnmodelled, detail, &cond)
}

/// The cure is a total match over `error`; `stage` names the command in the text.
pub(in crate::ceremony) enum Stage {
    HashObject,
    ReadTree,
    UpdateIndex,
    WriteTree,
    LsTree,
    LsTreeParse,
    DiffTree,
    CommitTree,
    SigningRead,
    MessageFile,
}

impl Stage {
    fn label(&self) -> &'static str {
        match self {
            Stage::HashObject => "hash-object",
            Stage::ReadTree => "read-tree",
            Stage::UpdateIndex => "update-index --index-info",
            Stage::WriteTree => "write-tree",
            Stage::LsTree => "ls-tree",
            Stage::LsTreeParse => "ls-tree parse",
            Stage::DiffTree => "diff-tree",
            Stage::CommitTree => "commit-tree",
            Stage::SigningRead => "commit.gpgSign",
            Stage::MessageFile => "message file",
        }
    }
}

pub(in crate::ceremony) enum StageError {
    Spawn(String),
    Exit { status: String, stderr: String },
    Parse(String),
    MessageFile(std::io::Error),
}

impl StageError {
    fn from_git(e: GitRunError) -> Self {
        match e {
            GitRunError::Spawn { err, .. } => StageError::Spawn(err),
            GitRunError::Exit { status, stderr, .. } => StageError::Exit { status, stderr },
            e @ GitRunError::NonUtf8Output { .. } => StageError::Parse(e.to_string()),
        }
    }

    /// The error text carried in the detail (git's own line, the parser record, or the I/O error).
    fn render(&self, stage: &Stage) -> String {
        let label = stage.label();
        match self {
            StageError::Spawn(err) => format!("`git {label}` could not run: {err}"),
            StageError::Exit { status, stderr } => {
                format!("`git {label}` failed ({status}): {stderr}")
            }
            StageError::Parse(d) => d.clone(),
            StageError::MessageFile(e) => e.to_string(),
        }
    }
}

pub(in crate::ceremony) struct StageFailure {
    pub stage: Stage,
    pub error: StageError,
}

impl TypedCure for StageFailure {
    fn cure(&self) -> String {
        let stage = self.stage.label();
        match &self.error {
            StageError::Spawn(err) => format!(
                "git could not be spawned at `{stage}` ({err}); check that git is on PATH and \
                 executable, then re-run"
            ),
            StageError::Exit { .. } => format!(
                "git refused the ceremony's commit at `{stage}`; the detail carries git's own \
                 reason; repair what it names, then re-run"
            ),
            StageError::Parse(_) => format!(
                "the ceremony could not parse git's `{stage}` output; the detail carries the \
                 record; report it"
            ),
            StageError::MessageFile(_) => "the commit could not be prepared (temp file); check \
                 TMPDIR space and permissions, then re-run"
                .to_string(),
        }
    }
}

/// A `CeremonyCommitRefused` from a construction or commit stage, cured by the typed
/// [`StageFailure`]; the detail carries git's own line (or the parser record, or the I/O error).
fn stage_refusal(stage: Stage, prefix: String, error: StageError) -> Box<dyn std::error::Error> {
    let detail = format!("{prefix}: {}", error.render(&stage));
    Box::new(Refusal::typed(
        RefusalId::CeremonyCommitRefused,
        detail,
        &StageFailure { stage, error },
    ))
}

/// The constructed tree changed a path outside the owed set (§3.4c). The extra paths carry git's
                                                            
pub(in crate::ceremony) struct TreeDeltaExcess {
    pub extra: Vec<(char, DeclaredPathName)>,
}

impl TreeDeltaExcess {
                                                                         
    fn detail(&self) -> String {
        let listed = self
            .extra
            .iter()
            .map(|(c, p)| format!("{c} {p}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("the constructed commit would change path(s) outside the owed set: {listed}")
    }
}

impl TypedCure for TreeDeltaExcess {
    fn cure(&self) -> String {
        "a directory/file collision with a HEAD entry the dirt scan did not report (hidden by \
         `assume-unchanged` or `skip-worktree`, or an entry under a directory the owed path \
         replaces); settle the collision at the named path(s) (`git update-index \
         --no-assume-unchanged` / `--no-skip-worktree`, or remove the colliding entry), then re-run"
            .to_string()
    }
}

/// The post-swap identity read (§3.8 step 5): HEAD read against the constructed commit, and the
/// settle result. The detail states whether the settle ran; the cure names the by-hand recovery.
pub(in crate::ceremony) struct IdentityFailure {
    pub head: Result<String, GitRunError>,
    pub settle: Result<(), GitRunError>,
    pub c_new: String,
}

impl IdentityFailure {
    fn settle_clause(&self) -> String {
        match &self.settle {
            Ok(_) => {
                "the settle ran; the index holds the constructed commit's entries at the owed \
                      paths"
                    .to_string()
            }
            Err(d) => format!(
                "the settle failed ({d}); the index holds the pre-commit entries at the owed paths"
            ),
        }
    }

    fn detail(&self) -> String {
        let clause = self.settle_clause();
        let c_new = &self.c_new;
        match &self.head {
            Ok(h) => format!(
                "the landed HEAD {h} does not equal the constructed commit {c_new}; a ref moved \
                 between the swap and the identity read; {clause}"
            ),
            Err(d) => {
                format!("the identity read failed after the swap to {c_new}: {d}; {clause}")
            }
        }
    }
}

impl TypedCure for IdentityFailure {
    fn cure(&self) -> String {
        let c_new = &self.c_new;
        match &self.head {
            Ok(_) => format!(
                "inspect `git log -1 HEAD` against {c_new}; a hook or a concurrent ref move \
                 replaced HEAD after the swap — settle by hand, then re-run"
            ),
            Err(_) => {
                format!("inspect `git log -1 HEAD` against {c_new}, settle by hand, then re-run")
            }
        }
    }
}

/// The settle of the operator's index failed after a verified commit landed (§3.8 step 4/5). The
/// cure names the NUL-separated owed-path file the gate wrote beside its records and the one
/// `restore --staged` command that consumes it; no path name is embedded in a command
                                                                                 
pub(in crate::ceremony) struct SettleFailed {
    pub error: GitRunError,
    pub owed: Vec<DeclaredPathName>,
    pub pathspec_file: Result<std::path::PathBuf, String>,
}

fn shell_word(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl TypedCure for SettleFailed {
    fn cure(&self) -> String {
        let listed: Vec<String> = self.owed.iter().map(|p| p.to_string()).collect();
        match &self.pathspec_file {
            Ok(file) => format!(
                "the commit is landed; the index still carries pre-commit entries at the owed \
                 paths {}; run `git --literal-pathspecs restore --staged \
                 --pathspec-from-file={} --pathspec-file-nul` (the file lists exactly those paths, \
                 NUL-separated), or re-run after the lock clears",
                listed.join(", "),
                shell_word(&file.display().to_string())
            ),
            Err(e) => format!(
                "the commit is landed; the index still carries pre-commit entries at the owed \
                 paths {}; the pathspec file could not be written ({e}), so unstage each listed \
                 path by hand, or re-run after the lock clears",
                listed.join(", ")
            ),
        }
    }
}

                                                                                                     

/// The gate's first step (before the dirt scan): refuse pre-prompt on a named checkout outside its
/// operator-ratified form (§1.4). `ratified_file` is the checkout's declared-space file
/// (`<repo_form_dir>/<checkout>.keys`); `checkout` names it in the refusal. Each read failure is
/// itself a refusal.
pub(in crate::ceremony) fn check_repository_contract(
    repo_root: &Path,
    ratified_file: &super::Utf8PathBuf,
    checkout: &str,
    admit: &str,
    purpose: GitReadPurpose,
) -> Result<(), Refusal> {
    let unreadable_p = |e: GitRunError| -> Refusal {
        let detail = format!("cannot read the {checkout} checkout's git state: {e}");
        Refusal::typed(
            RefusalId::GitStateUnreadable,
            detail,
            &GitReadFailure {
                purpose,
                outcome: e,
            },
        )
    };
                                                                                                   
                                                                                                
    let replace = match Git::new(repo_root)
        .args(&[
            "for-each-ref",
            "--count=1",
            "--format=%(refname)",
            "refs/replace/",
        ])
        .content_or_exit("for-each-ref refs/replace/")
        .map_err(unreadable_p)?
    {
        GitReply::Ok(bytes) => bytes,
        GitReply::Exit { code, stderr } => {
            return Err(unreadable_p(GitRunError::Exit {
                op: "for-each-ref refs/replace/".to_string(),
                status: exit_status_string(code),
                stderr,
            }));
        }
    };
    if !replace.trim_ascii().is_empty() {
        return Err(form_refusal(
            RepoFormCondition::ReplaceRefs,
            "the repository carries a replace ref (a ref under refs/replace/)".to_string(),
        ));
    }

                                                                                                      
                                                                       
    let grafts_rel = Git::new(repo_root)
        .args(&["rev-parse", "--git-path", "info/grafts"])
        .text("rev-parse --git-path info/grafts")
        .map_err(|e| match e {
            GitRunError::NonUtf8Output { .. } => {
                let detail = format!("cannot read the {checkout} checkout's repository form: {e}");
                form_refusal(RepoFormCondition::Unreadable(e), detail)
            }
            _ => unreadable_p(e),
        })?;
    if repo_root.join(git_path_pathbuf(&grafts_rel)).exists() {
        return Err(form_refusal(
            RepoFormCondition::Grafts,
            "the repository carries an info/grafts file".to_string(),
        ));
    }

                     
    let shallow = Git::new(repo_root)
        .args(&["rev-parse", "--is-shallow-repository"])
        .text("rev-parse --is-shallow-repository")
        .map_err(unreadable_p)?;
    if shallow.trim() == "true" {
        return Err(form_refusal(
            RepoFormCondition::ShallowClone,
            "the repository is a shallow clone (.git/shallow present)".to_string(),
        ));
    }

                                                                          
    let measured = measure_key_set(repo_root).map_err(|e| {
        let detail =
            format!("cannot read the {checkout} checkout's git configuration listing: {e}");
        form_refusal(RepoFormCondition::Unreadable(e), detail)
    })?;
    let ratified = match super::admission::read_ratified(ratified_file) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(form_refusal(
                RepoFormCondition::NoDeclaredSpace {
                    checkout: checkout.to_string(),
                    admit: admit.to_string(),
                },
                format!(
                    "the {checkout} checkout has no ratified declared space at {}",
                    ratified_file.display()
                ),
            ));
        }
        Err(e) => {
            return Err(form_refusal(
                RepoFormCondition::RatifiedUnreadable {
                    checkout: checkout.to_string(),
                    file: ratified_file.clone(),
                    error: e.to_string(),
                    admit: admit.to_string(),
                },
                format!(
                    "the {checkout} checkout's ratified declared-space file exists and cannot be \
                     read: {e}"
                ),
            ));
        }
    };
    let ratified_set: BTreeSet<&str> = ratified.lines().filter(|l| !l.is_empty()).collect();
    let measured_set: BTreeSet<&str> = measured.iter().map(String::as_str).collect();
    let added: Vec<String> = measured_set
        .difference(&ratified_set)
        .map(|s| s.to_string())
        .collect();
    let removed: Vec<String> = ratified_set
        .difference(&measured_set)
        .map(|s| s.to_string())
        .collect();
    if !added.is_empty() || !removed.is_empty() {
        let detail = format!(
            "the {checkout} checkout's declared space differs from the ratified file: added \
             {added:?}, removed {removed:?}"
        );
        return Err(form_refusal(
            RepoFormCondition::DeclaredSpaceDelta {
                checkout: checkout.to_string(),
                added,
                removed,
                admit: admit.to_string(),
            },
            detail,
        ));
    }
    Ok(())
}

/// The declared-space file body for `repo_root` (§2.2): sorted lines: `{scope}\t{key}`;
/// `{scope}\t{key}\t{value:?}` at a value-sensitive key with a value; `{scope}\t{key}\t` at a
/// value-sensitive key with no value; LF-terminated.
pub fn declared_space_body(repo_root: &Path) -> Result<String, GitRunError> {
    let mut s = String::new();
    for line in measure_key_set(repo_root)? {
        s.push_str(&line);
        s.push('\n');
    }
    Ok(s)
}

/// Value-sensitive keys by whole-key equality, as git emits them (section and variable lowercased,
/// subsection verbatim; git-config(1) §0.2). Each key's value names a program git executes inside
/// the gate's commands, or selects whether or which such execution happens.
pub const VALUE_SENSITIVE_EXACT: &[&str] = &[
    "core.fsmonitor",
    "core.hookspath",
    "core.attributesfile",
    "attr.tree",
    "commit.gpgsign",
    "gpg.format",
    "gpg.program",
    "gpg.openpgp.program",
    "gpg.x509.program",
    "gpg.ssh.program",
    "gpg.ssh.defaultkeycommand",
];

/// Value-sensitive `(section, variable)` pairs; a match needs a non-empty subsection.
pub const VALUE_SENSITIVE_PATTERNED: &[(&str, &str)] = &[
    ("hook", "command"),
    ("hook", "event"),
    ("hook", "enabled"),
    ("filter", "clean"),
    ("filter", "process"),
];

/// Whether the config key's value enters the declared space (§2.1): exact membership, or a
/// `(section, variable)` pattern with a non-empty subsection between them.
pub fn is_value_sensitive(key: &str) -> bool {
    if VALUE_SENSITIVE_EXACT.contains(&key) {
        return true;
    }
    let Some((section, rest)) = key.split_once('.') else {
        return false;
    };
    let Some((subsection, variable)) = rest.rsplit_once('.') else {
        return false;
    };
    !subsection.is_empty() && VALUE_SENSITIVE_PATTERNED.contains(&(section, variable))
}

/// The checkout's declared space through git's own listing (§2.2), sorted and deduplicated, one
/// record per entry in one of three forms: `<scope>\t<key>`; `<scope>\t<key>\t<value:?>` (the
/// value's `Debug` form) at a value-sensitive key with a value; `<scope>\t<key>\t` at a
/// value-sensitive key with no value. `git config --list --show-scope --null` emits
/// `<scope> NUL <key> [LF <value>] NUL` per entry (git-config(1) --show-scope, -z); a valueless
/// key carries no LF and takes the third form. `scope` and `key` decode strict through [`utf8`],
/// and the value only at a value-sensitive key; a non-UTF-8 value at a keys-only key never enters
/// a line and never refuses.
pub(in crate::ceremony) fn measure_key_set(repo_root: &Path) -> Result<Vec<String>, GitRunError> {
    let op = "config --list --show-scope --null";
    let raw = match Git::new(repo_root)
        .args(&["config", "--list", "--show-scope", "--null"])
        .content_or_exit(op)?
    {
        GitReply::Ok(bytes) => bytes,
        GitReply::Exit { code, stderr } => {
            return Err(GitRunError::Exit {
                op: op.to_string(),
                status: exit_status_string(code),
                stderr,
            });
        }
    };
    let fields: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut i = 0;
    while i + 1 < fields.len() {
        let scope_bytes = fields[i];
        let rest = fields[i + 1];
        i += 2;
        if scope_bytes.is_empty() {
            continue;
        }
        let scope = utf8(op, scope_bytes)?;
        let (key_bytes, value_bytes) = match rest.iter().position(|&b| b == b'\n') {
            Some(p) => (&rest[..p], Some(&rest[p + 1..])),
            None => (rest, None),
        };
        let key = utf8(op, key_bytes)?;
        if is_value_sensitive(&key) {
            match value_bytes {
                Some(v) => {
                    let value = utf8(op, v)?;
                    set.insert(format!("{scope}\t{key}\t{value:?}"));
                }
                None => {
                    set.insert(format!("{scope}\t{key}\t"));
                }
            }
        } else {
            set.insert(format!("{scope}\t{key}"));
        }
    }
    Ok(set.into_iter().collect())
}

                                                                                                     

/// The gate never advances HEAD during an in-progress git operation (§3.1): git's own marker set,
/// one predicate per marker kind. Refuses `partial-commit-blocked` with the operation-typed cure.
pub(in crate::ceremony) fn refuse_if_in_progress(repo_root: &Path) -> Result<(), Refusal> {
    if let Some(op) = detect_in_progress(repo_root)? {
        let detail = format!(
            "a git {} is in progress at the executing checkout; the gate does not advance HEAD \
             mid-operation",
            op.label()
        );
        return Err(Refusal::typed(RefusalId::PartialCommitBlocked, detail, &op));
    }
    Ok(())
}

/// The in-progress operation, git's `wt_status_get_state` precedence: rebase, then merge, then
/// cherry-pick/revert (sequencer), then bisect.
fn detect_in_progress(repo_root: &Path) -> Result<Option<InProgressOp>, Refusal> {
    if git_path_exists(repo_root, "rebase-apply")? {
                                                              
        if git_path_exists(repo_root, "rebase-apply/applying")? {
            return Ok(Some(InProgressOp::Am));
        }
        return Ok(Some(InProgressOp::Rebase));
    }
    if git_path_exists(repo_root, "rebase-merge")? {
        return Ok(Some(InProgressOp::Rebase));
    }
    if git_path_exists(repo_root, "MERGE_HEAD")? {
        return Ok(Some(InProgressOp::Merge));
    }
    if pseudo_ref_exists(repo_root, "CHERRY_PICK_HEAD")? {
        return Ok(Some(InProgressOp::CherryPick));
    }
    if pseudo_ref_exists(repo_root, "REVERT_HEAD")? {
        return Ok(Some(InProgressOp::Revert));
    }
                                                                                                    
                                                                                              
    if git_path_exists(repo_root, "sequencer")? {
        return Ok(Some(sequencer_op(repo_root)));
    }
    if git_path_exists(repo_root, "BISECT_LOG")? {
        return Ok(Some(InProgressOp::Bisect));
    }
    Ok(None)
}

/// `git rev-parse --git-path <name>` joined onto the root exists (relative for a main worktree,
/// absolute for a linked one).
fn git_path_exists(repo_root: &Path, name: &str) -> Result<bool, Refusal> {
    let text = Git::new(repo_root)
        .args(&["rev-parse", "--git-path", name])
        .text("rev-parse --git-path")
        .map_err(unreadable)?;
    Ok(repo_root.join(git_path_pathbuf(&text)).exists())
}

/// `git rev-parse --verify --quiet <name>` exit 0 (the ref store, so it holds under reftable where
/// no file exists at `--git-path`).
fn pseudo_ref_exists(repo_root: &Path, name: &str) -> Result<bool, Refusal> {
    let op = format!("rev-parse --verify {name}");
    match Git::new(repo_root)
        .args(&["rev-parse", "--verify", "--quiet", name])
        .text_or_exit(&op)
        .map_err(unreadable)?
    {
        GitReply::Ok(_) => Ok(true),
        GitReply::Exit { .. } => Ok(false),
    }
}

/// The sequencer's operation from its todo's first command; defaults to cherry-pick.
fn sequencer_op(repo_root: &Path) -> InProgressOp {
    if let Ok(rel) = Git::new(repo_root)
        .args(&["rev-parse", "--git-path", "sequencer/todo"])
        .text("rev-parse --git-path sequencer/todo")
        && let Ok(todo) = std::fs::read_to_string(repo_root.join(git_path_pathbuf(&rel)))
    {
        for line in todo.lines() {
            let word = line.split_whitespace().next().unwrap_or("");
            match word {
                "revert" => return InProgressOp::Revert,
                "pick" | "cherry-pick" | "p" => return InProgressOp::CherryPick,
                _ => continue,
            }
        }
    }
    InProgressOp::CherryPick
}

                                                                                                      

static TEMP_INDEX_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The constructed tree and its parent, plus the index-info records the settle replays and the owed
/// paths the settle and identity-failure cures name.
pub(in crate::ceremony) struct Prepared {
    parent: String,
    tree: String,
    index_info: Vec<u8>,
    owed_paths: Vec<DeclaredPathName>,
    records_dir: std::path::PathBuf,
}

/// §3.2-§3.5: read the parent, construct one blob per present owed path (re-reading the worktree and
/// refusing on any divergence from the witness), build the tree in a private index, check every
/// record landed and the changed set is contained in the owed set, and stop when nothing lands.
pub(in crate::ceremony) fn prepare(
    repo_root: &Path,
    records_dir: &Path,
    rec: &RunRecords,
    owed: &[(DeclaredPathName, DirtClass)],
    witnesses: &BTreeMap<DeclaredPathName, PathWitness>,
) -> Result<Prepared, Box<dyn std::error::Error>> {
                                                          
    let parent = Git::new(repo_root)
        .args(&["rev-parse", "--verify", "HEAD^{commit}"])
        .text("rev-parse HEAD^{commit}")
        .map_err(|e| {
            Box::new(unreadable_at("read HEAD for the commit gate", e))
                as Box<dyn std::error::Error>
        })?
        .trim()
        .to_string();
    let t_head = Git::new(repo_root)
        .args(&["rev-parse", "HEAD^{tree}"])
        .text("rev-parse HEAD^{tree}")
        .map_err(|e| {
            Box::new(unreadable_at("read HEAD tree for the commit gate", e))
                as Box<dyn std::error::Error>
        })?
        .trim()
        .to_string();
    let zero_oid = "0".repeat(parent.len());

                                           
    let mut index_info: Vec<u8> = Vec::new();
                                                                          
    let mut present: Vec<(String, String, String)> = Vec::new();
    let mut absent: Vec<String> = Vec::new();
    for (path, _class) in owed {
        let witness = witnesses.get(path).ok_or_else(|| {
            Box::new(Refusal::new(
                RefusalId::InternalInvariantViolated,
                format!("owed path {path} reached construction with no witness"),
            )) as Box<dyn std::error::Error>
        })?;
        let abspath = repo_root.join(path.as_str());
        let content = rec.gate_content(&abspath);
        let moved = |detail: String| -> Box<dyn std::error::Error> {
            Box::new(Refusal::new(RefusalId::GateContentMoved, detail))
        };
        match content {
            Err((_class, detail)) => {
                return Err(moved(format!(
                    "declared path {path} is no longer a readable regular file at construction: \
                     {detail}"
                )));
            }
            Ok(GateContent::Absent) => match &witness.post {
                ContentState::Absent => {
                    absent.push(path.as_str().to_string());
                    push_record(&mut index_info, "0", &zero_oid, path.as_str());
                }
                ContentState::Sha256 { .. } => {
                    return Err(moved(format!(
                        "declared path {path} recorded present, absent at construction"
                    )));
                }
            },
            Ok(GateContent::Present { bytes, state }) => {
                if state != witness.post {
                    return Err(moved(format!(
                        "declared path {path} changed between classification and construction"
                    )));
                }
                let exec = matches!(&state, ContentState::Sha256 { exec: true, .. });
                let blob = Git::new(repo_root)
                    .args(&["hash-object", "-w", "--stdin"])
                    .text_with_stdin(&bytes, "hash-object")
                    .map_err(|e| {
                        stage_refusal(
                            Stage::HashObject,
                            format!("hash the declared path {path}"),
                            StageError::from_git(e),
                        )
                    })?
                    .trim()
                    .to_string();
                let mode = if exec { "100755" } else { "100644" };
                push_record(&mut index_info, mode, &blob, path.as_str());
                present.push((path.as_str().to_string(), mode.to_string(), blob));
            }
        }
    }

                                                  
    let tmp = records_dir.join(format!(
        "gate-index-{}-{}",
        std::process::id(),
        TEMP_INDEX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let stage_refused = |stage: Stage, e: GitRunError| -> Box<dyn std::error::Error> {
        let prefix = format!("the ceremony's gate commit failed at `{}`", stage.label());
        stage_refusal(stage, prefix, StageError::from_git(e))
    };
    let build = (|| -> Result<String, Box<dyn std::error::Error>> {
        Git::new(repo_root)
            .index(&tmp)
            .args(&["read-tree", "HEAD"])
            .text("read-tree")
            .map_err(|e| stage_refused(Stage::ReadTree, e))?;
        Git::new(repo_root)
            .index(&tmp)
            .args(&["update-index", "-z", "--index-info"])
            .text_with_stdin(&index_info, "update-index --index-info")
            .map_err(|e| stage_refused(Stage::UpdateIndex, e))?;
        Ok(Git::new(repo_root)
            .index(&tmp)
            .args(&["write-tree"])
            .text("write-tree")
            .map_err(|e| stage_refused(Stage::WriteTree, e))?
            .trim()
            .to_string())
    })();
    let _ = std::fs::remove_file(&tmp);
    let t_new = build?;

                             
    let landed_raw = Git::new(repo_root)
        .args(&["ls-tree", "-r", "-z", &t_new])
        .text("ls-tree -r -z <T_new>")
        .map_err(|e| stage_refused(Stage::LsTree, e))?;
    let landed = parse_ls_tree(&landed_raw).map_err(|d| {
        stage_refusal(
            Stage::LsTreeParse,
            "the ceremony's gate commit failed at `ls-tree parse`".to_string(),
            StageError::Parse(d),
        )
    })?;
    for (path, mode, blob) in &present {
        match landed.get(path) {
            Some((m, t, o)) if t == "blob" && o == blob && m == mode => {}
            _ => {
                return Err(record_dropped(path));
            }
        }
    }
    for path in &absent {
        if landed.contains_key(path) {
            return Err(record_dropped(path));
        }
    }

                                                                                                     
                                                              
    let raw = Git::new(repo_root)
        .args(&[
            "diff-tree",
            "--no-renames",
            "-r",
            "--name-status",
            "-z",
            &t_head,
            &t_new,
        ])
        .text("diff-tree <T_head> <T_new>")
        .map_err(|e| stage_refused(Stage::DiffTree, e))?;
    let mut fields = raw.split('\0').filter(|s| !s.is_empty());
    let mut changed: BTreeMap<String, char> = BTreeMap::new();
    while let (Some(status), Some(path)) = (fields.next(), fields.next()) {
        changed.insert(path.to_string(), status.chars().next().unwrap_or('?'));
    }
    let owed_set: BTreeSet<String> = owed.iter().map(|(p, _)| p.as_str().to_string()).collect();
    let extra: Vec<(char, DeclaredPathName)> = changed
        .iter()
        .filter(|(p, _)| !owed_set.contains(*p))
        .map(|(p, c)| (*c, DeclaredPathName::new(p.clone())))
        .collect();
    if !extra.is_empty() {
        let excess = TreeDeltaExcess { extra };
        let detail = excess.detail();
        return Err(Box::new(Refusal::typed(
            RefusalId::GateTreeDeltaExceedsOwed,
            detail,
            &excess,
        )));
    }

                                
    if changed.is_empty() {
        return Err(Box::new(Refusal::new(
            RefusalId::CommitPreviewEmpty,
            format!(
                "no owed declared path holds a change against HEAD for the ceremony to commit: {:?}",
                owed_set
            ),
        )));
    }

    Ok(Prepared {
        parent,
        tree: t_new,
        index_info,
        owed_paths: owed.iter().map(|(p, _)| p.clone()).collect(),
        records_dir: records_dir.to_path_buf(),
    })
}

fn record_dropped(path: &str) -> Box<dyn std::error::Error> {
    Box::new(Refusal::new(
        RefusalId::GateRecordDropped,
        format!("git dropped the declared path {path:?} from the constructed tree"),
    ))
}

/// One NUL-terminated `<mode> SP <oid> SP 0 TAB <path>` index-info record. The path field is literal.
fn push_record(buf: &mut Vec<u8>, mode: &str, oid: &str, path: &str) {
    buf.extend_from_slice(format!("{mode} {oid} 0\t{path}").as_bytes());
    buf.push(0);
}

/// `git ls-tree -r -z` records: `<mode> SP <type> SP <oid> TAB <path>`, the path field everything
/// after the first tab (verbatim under `-z`). Returns path -> (mode, type, oid).
#[allow(clippy::type_complexity)]
fn parse_ls_tree(text: &str) -> Result<BTreeMap<String, (String, String, String)>, String> {
    let mut out = BTreeMap::new();
    for rec in text.split('\0').filter(|r| !r.is_empty()) {
        let (meta, path) = rec
            .split_once('\t')
            .ok_or_else(|| format!("ls-tree record {rec:?} has no tab"))?;
        let mut f = meta.split(' ');
        let mode = f
            .next()
            .ok_or_else(|| format!("ls-tree record {rec:?} has no mode"))?;
        let otype = f
            .next()
            .ok_or_else(|| format!("ls-tree record {rec:?} has no type"))?;
        let oid = f
            .next()
            .ok_or_else(|| format!("ls-tree record {rec:?} has no oid"))?;
        out.insert(
            path.to_string(),
            (mode.to_string(), otype.to_string(), oid.to_string()),
        );
    }
    Ok(out)
}

                                                                                                     

/// The state of HEAD after a refused `update-ref` compare-and-swap, read once more. `parent` is the
/// parent the swap expected.
enum CasRefusal {
    /// HEAD advanced to `now`, so the swap's old-value check failed.
    Moved { parent: String, now: String },
    /// HEAD is still at `parent`; git refused the update for another reason (a hook, a stale lock).
    Unmoved { parent: String },
    /// The HEAD read after the refused update could not complete.
    HeadUnreadable { detail: String },
}

impl CasRefusal {
    /// The computed HEAD state, appended to git's own line in the detail.
    fn head_state(&self) -> String {
        match self {
            CasRefusal::Moved { parent, now } => {
                format!("HEAD is now at {now}, no longer at {parent}")
            }
            CasRefusal::Unmoved { parent } => format!("HEAD is still at {parent}"),
            CasRefusal::HeadUnreadable { detail, .. } => {
                format!("the HEAD read after the refused update failed: {detail}")
            }
        }
    }
}

impl TypedCure for CasRefusal {
    fn cure(&self) -> String {
        match self {
            CasRefusal::Moved { parent, now } => format!(
                "HEAD is at {now}, no longer at {parent}; another git operation advanced HEAD \
                 while the gate held consent; re-run"
            ),
            CasRefusal::Unmoved { parent } => format!(
                "HEAD is still at {parent}; git refused the ref update for the reason in the \
                 detail; repair what git names, then re-run"
            ),
            CasRefusal::HeadUnreadable { detail, .. } => format!(
                "the HEAD read after the refused update failed ({detail}); inspect \
                 `git rev-parse HEAD` by hand, then re-run"
            ),
        }
    }
}

/// §3.8: sign-read, `commit-tree`, the `update-ref` compare-and-swap, the settle of the real index,
/// and the identity read. The exits, in precedence: a CAS refusal (HEAD unmoved, no settle); an
/// identity-read failure (`ceremony-commit-verify-failed`); a settle failure with the identity read
/// passing (`gate-settle-failed`, the commit landed); otherwise the commit is landed.
pub(in crate::ceremony) fn commit(
    repo_root: &Path,
    prepared: &Prepared,
    message: &str,
    profile: &str,
) -> Result<(), Box<dyn std::error::Error>> {
                                                 
    let mut msgfile = tempfile::NamedTempFile::new().map_err(|e| {
        stage_refusal(
            Stage::MessageFile,
            "the commit message file could not be created".to_string(),
            StageError::MessageFile(e),
        )
    })?;
    {
        use std::io::Write as _;
        msgfile
            .write_all(message.as_bytes())
            .and_then(|()| msgfile.flush())
            .map_err(|e| {
                stage_refusal(
                    Stage::MessageFile,
                    "the commit message file could not be written".to_string(),
                    StageError::MessageFile(e),
                )
            })?;
    }

                                                                                               
                                                       
    let sign = match config_read(
        repo_root,
        &["config", "--type=bool", "--default=false", "commit.gpgSign"],
        "config commit.gpgSign",
    ) {
        Ok(v) => v.trim() == "true",
        Err(e) => {
            return Err(stage_refusal(
                Stage::SigningRead,
                "commit.gpgSign is malformed".to_string(),
                StageError::from_git(e),
            ));
        }
    };

                      
    let mut commit_tree =
        Git::new(repo_root).args(&["commit-tree", &prepared.tree, "-p", &prepared.parent]);
    if sign {
        commit_tree = commit_tree.arg("-S");
    }
    let c_new = commit_tree
        .arg("-F")
        .arg(msgfile.path())
        .text("commit-tree")
        .map_err(|e| {
            stage_refusal(
                Stage::CommitTree,
                "the ceremony's gate commit failed at `commit-tree`".to_string(),
                StageError::from_git(e),
            )
        })?
        .trim()
        .to_string();

                                      
    if let Err(d) = Git::new(repo_root)
        .args(&[
            "update-ref",
            "-m",
            &format!("ceremony({profile}): gate commit"),
            "HEAD",
            &c_new,
            &prepared.parent,
        ])
        .text("update-ref HEAD")
    {
        let parent = prepared.parent.clone();
        let cas = match Git::new(repo_root)
            .args(&["rev-parse", "HEAD"])
            .text("rev-parse HEAD")
        {
            Ok(out) => {
                let now = out.trim();
                if now == prepared.parent {
                    CasRefusal::Unmoved { parent }
                } else {
                    CasRefusal::Moved {
                        parent,
                        now: now.to_string(),
                    }
                }
            }
            Err(hd) => CasRefusal::HeadUnreadable {
                detail: hd.to_string(),
            },
        };
        let detail = format!("{d}; {}", cas.head_state());
        return Err(Box::new(Refusal::typed(
            RefusalId::CeremonyCommitRefused,
            detail,
            &cas,
        )));
    }

                                                                                               
    let settle: Result<(), GitRunError> = Git::new(repo_root)
        .args(&["update-index", "-z", "--index-info"])
        .text_with_stdin(&prepared.index_info, "update-index --index-info (settle)")
        .map(|_| ());

                                          
    let head = Git::new(repo_root)
        .args(&["rev-parse", "HEAD"])
        .text("rev-parse HEAD")
        .map(|s| s.trim().to_string());
    let head_ok = matches!(&head, Ok(h) if *h == c_new);
    if !head_ok {
        let idf = IdentityFailure {
            head,
            settle,
            c_new: c_new.clone(),
        };
        let detail = idf.detail();
        return Err(Box::new(Refusal::typed(
            RefusalId::CommitVerifyFailed,
            detail,
            &idf,
        )));
    }

                                                                                            
    if let Err(e) = settle {
        let pathspec_file = {
            let file = prepared.records_dir.join("gate-settle-owed.paths");
            let mut bytes = Vec::new();
            for p in &prepared.owed_paths {
                bytes.extend_from_slice(p.as_str().as_bytes());
                bytes.push(0);
            }
            std::fs::write(&file, &bytes)
                .map(|()| file)
                .map_err(|e| e.to_string())
        };
        let sf = SettleFailed {
            error: e,
            owed: prepared.owed_paths.clone(),
            pathspec_file,
        };
        let detail = format!(
            "the commit landed at {c_new} and the identity read verified it, but the settle of the \
             operator's index at the owed paths failed: {}",
            sf.error
        );
        return Err(Box::new(Refusal::typed(
            RefusalId::GateSettleFailed,
            detail,
            &sf,
        )));
    }

    Ok(())
}

#[cfg(test)]
#[path = "gate_commit_tests.rs"]
mod tests;
