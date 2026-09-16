                                                                                                       
//! records, never from a scan of the tree. The witness is the content contract — a committable path
//! is one whose current bytes and exec bit hash-match a finalized record (`records::verified_record`),
//! verified again at construction and bound by the constructed commit id (§3.3, §3.8). The renderer
//! is pure: it reads no git state; the executing call path supplies the rows.
//!
//! The one git read kept here is the §3.6 discard note (the staged edits the settle overwrites),
//! computed once before the prompt through the §3.11 command builder. A git read it cannot complete
//! refuses `git-state-unreadable`.

use std::collections::BTreeSet;
use std::path::Path;

use super::records::{DeclaredPathName, DirtClass};
use super::refusal::{GitReadFailure, GitReadPurpose, GitRunError, Refusal, RefusalId};

/// One row at the gate, ready to render. The executing gate builds `Executing` rows from the
/// classifier's witness; the sibling gate builds `Sibling` rows for content the store does not
/// recognize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateRow {
    Executing {
        path: DeclaredPathName,
        class: DirtClass,
        run_id: String,
        this_run: bool,
        /// The recorded post-hash's 12-hex prefix; empty for a recorded deletion (`Absent`).
        sha_prefix: String,
        /// The current byte length; `None` for a recorded deletion.
        len: Option<u64>,
    },
    Sibling {
        path: DeclaredPathName,
        /// The worktree byte length, best-effort; `None` when unreadable.
        len: Option<u64>,
    },
}

/// The discard note's overwritten-path set, each rendered through [`DeclaredPathName`] (the single
/// escaping render), in a brace-wrapped comma list.
pub fn render_overwrite_set(discards: &BTreeSet<String>) -> String {
    let inner = discards
        .iter()
        .map(|p| DeclaredPathName::new(p.clone()).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{inner}}}")
}

/// Render the rows: one line each, then a path-count footer. Pure — no git reads.
pub fn render_rows(rows: &[GateRow]) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(rows.len() + 1);
    for row in rows {
        lines.push(match row {
            GateRow::Executing {
                path,
                class,
                run_id,
                this_run,
                sha_prefix,
                len,
            } => {
                let run = if *this_run {
                    "this run".to_string()
                } else {
                    format!("prior run {}", &run_id[..run_id.len().min(8)])
                };
                let sha = if sha_prefix.is_empty() {
                    String::new()
                } else {
                    format!(" {sha_prefix}")
                };
                let bytes = match len {
                    Some(n) => format!(" {n} bytes"),
                    None => String::new(),
                };
                format!(" {path} [{}] {run}{sha}{bytes}", class.cause_phrase())
            }
            GateRow::Sibling { path, len } => {
                let bytes = match len {
                    Some(n) => format!(" {n} bytes"),
                    None => String::new(),
                };
                format!(" {path}{bytes} not recognized as ceremony output")
            }
        });
    }
    lines.push(format!(" {} declared path(s)", rows.len()));
    lines.join("\n")
}

/// The staged edits the commit's settle would overwrite (§3.6 discard note): `git diff --cached
/// --name-only -z --no-renames` over the WHOLE index (no pathspec), intersected in-process with the
/// owed set by exact string. `--no-renames` lists a staged rename's source. No owed path reaches
               
pub fn discard_set(root: &Path, owed: &[&str]) -> Result<BTreeSet<String>, Refusal> {
    let staged = git_set(
        root,
        &["diff", "--cached", "--name-only", "-z", "--no-renames"],
    )?;
    let owed_set: BTreeSet<&str> = owed.iter().copied().collect();
    Ok(staged
        .into_iter()
        .filter(|p| owed_set.contains(p.as_str()))
        .collect())
}

/// `git <args>` in `root` through the §3.11 command builder, NUL-split into a set; a spawn failure
/// or non-zero exit is a fail-closed `git-state-unreadable`.
fn git_set(root: &Path, args: &[&str]) -> Result<BTreeSet<String>, Refusal> {
    let raw = git_read(root, args)?;
    Ok(raw
        .split('\0')
        .filter(|f| !f.is_empty())
        .map(|f| f.to_string())
        .collect())
}

fn git_read(root: &Path, args: &[&str]) -> Result<String, Refusal> {
    super::gate_commit::Git::new(root)
        .args(args)
        .text(args[0])
        .map_err(unreadable)
}

fn unreadable(e: GitRunError) -> Refusal {
    let detail = format!("cannot read the checkout's git state for the commit gate: {e}");
    Refusal::typed(
        RefusalId::GitStateUnreadable,
        detail,
        &GitReadFailure {
            purpose: GitReadPurpose::CommitGate,
            outcome: e,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_executing_and_sibling_rows_with_the_path_count_footer() {
        let rows = vec![
            GateRow::Executing {
                path: DeclaredPathName::new("consume-pins.toml"),
                class: DirtClass::CleanOrRecorded,
                run_id: "1700-42".to_string(),
                this_run: true,
                sha_prefix: "0123456789ab".to_string(),
                len: Some(120),
            },
            GateRow::Executing {
                path: DeclaredPathName::new("vendor/gone"),
                class: DirtClass::PriorRunRecorded,
                run_id: "1600-9prior".to_string(),
                this_run: false,
                sha_prefix: String::new(),
                len: None,
            },
            GateRow::Sibling {
                path: DeclaredPathName::new("published-pins.toml"),
                len: Some(64),
            },
        ];
        let text = render_rows(&rows);
        assert!(text.contains(
            " \"consume-pins.toml\" [recorded by this run] this run 0123456789ab 120 bytes"
        ));
                                                                         
        assert!(text.contains(" \"vendor/gone\" [recorded by a prior run] prior run 1600-9pr\n"));
        assert!(
            text.contains(" \"published-pins.toml\" 64 bytes not recognized as ceremony output")
        );
        assert!(text.ends_with(" 3 declared path(s)"));
    }
}
