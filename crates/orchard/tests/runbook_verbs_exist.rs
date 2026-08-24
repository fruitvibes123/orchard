                                                                                                      
                                                                                                                     
//! it extracts every `orchard <verb> [--<flag>]` inline-code span from the section and asserts each against
//! the ACTUAL clap CLI surface (`orchard <verb> --help`). This catches the audit R1 F-1 defect class — a
//! runbook naming a NON-COMPOSABLE flag (the worked example: `orchard update --artifact-pin`, which does
//! not exist — `--artifact-pin` is `prod`-only). A missing / empty / mislocated section FAILS the test
//! (never a vacuous pass — that fail-open is the exact mode this guard exists to prevent).

use std::path::PathBuf;
use std::process::Command;

/// `orchard_guide.md` lives at the orchard REPO ROOT (not `crates/orchard/`); `CARGO_MANIFEST_DIR` is
/// `crates/orchard`, so `../..` is the repo root (the same relocation `verify.rs`'s container test uses).
fn guide_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("orchard_guide.md")
}

/// Extract the "Key rotation" H2 section (from its `## … Key rotation` heading to the next `## ` heading
/// or EOF).
fn key_rotation_section(guide: &str) -> String {
    let mut section = String::new();
    let mut in_section = false;
    for line in guide.lines() {
        if line.starts_with("## ") && line.to_lowercase().contains("key rotation") {
            in_section = true;
            section.push_str(line);
            section.push('\n');
            continue;
        }
        if in_section {
            if line.starts_with("## ") {
                break;                        
            }
            section.push_str(line);
            section.push('\n');
        }
    }
    section
}

/// Trim a `--flag` token of trailing punctuation (keep alphanumerics + `-`); `""` if not a real flag.
fn clean_flag(t: &str) -> String {
    if !t.starts_with("--") {
        return String::new();
    }
    let f = t.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
    if f.len() > 2 {
        f.to_string()
    } else {
        String::new()
    }
}

/// Extract `(verb, flags)` from every single-backtick inline-code span that STARTS with `orchard `.
/// Inline code spans are the ODD-indexed pieces of a split on the backtick (balanced backticks assumed —
/// the section uses inline spans only, no fences).
fn extract_orchard_invocations(section: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for span in section.split('`').skip(1).step_by(2) {
        let mut toks = span.split_whitespace();
        if toks.next() != Some("orchard") {
            continue;
        }
        let Some(verb) = toks.next() else { continue };
        if verb.is_empty() || !verb.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            continue;
        }
        let flags: Vec<String> = toks.map(clean_flag).filter(|t| !t.is_empty()).collect();
        out.push((verb.to_string(), flags));
    }
    out
}

/// Extract `--flag` tokens from inline-code spans that do NOT start with `orchard` — a flag named in its
                                                                                                         
/// too (audit Sonnet M3 / Opus I4), even though attribution to a specific verb is weaker.
fn extract_bare_flags(section: &str) -> Vec<String> {
    let mut out = Vec::new();
    for span in section.split('`').skip(1).step_by(2) {
        let mut toks = span.split_whitespace();
        match toks.next() {
            Some("orchard") => continue,                                          
            Some(first) if first.starts_with("--") => {
                for t in std::iter::once(first).chain(toks) {
                    let f = clean_flag(t);
                    if !f.is_empty() {
                        out.push(f);
                    }
                }
            }
            _ => continue,
        }
    }
    out
}

#[test]
fn runbook_only_names_existing_verbs() {
    let path = guide_path();
    let guide =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let section = key_rotation_section(&guide);

                                                                                                          
    assert!(
        section.trim().len() > 400,
        "the `Key rotation` runbook section is missing or too small ({} bytes at {}) — the runbook guard \
         must not pass vacuously",
        section.trim().len(),
        path.display()
    );

    let bin = env!("CARGO_BIN_EXE_orchard");
    let invocations = extract_orchard_invocations(&section);
                                                                                     
    assert!(
        invocations.len() >= 8,
        "expected ≥8 `orchard …` invocations in the runbook, found {} — the section looks malformed",
        invocations.len()
    );

                                                                                           
    let mut valid_flags = std::collections::HashSet::new();
    for (verb, flags) in &invocations {
        let help = Command::new(bin)
            .arg(verb)
            .arg("--help")
            .output()
            .unwrap_or_else(|e| panic!("running `orchard {verb} --help`: {e}"));
        assert!(
            help.status.success(),
            "the runbook names `orchard {verb}`, but it is NOT a CLI verb (F-1 class)"
        );
        let help_text = String::from_utf8_lossy(&help.stdout);
        for flag in flags {
            assert!(
                help_text.contains(flag.as_str()),
                "the runbook names `orchard {verb} {flag}`, but {flag} is NOT a flag of `{verb}` \
                 (F-1 class: a non-composable flag — e.g. `orchard update --artifact-pin`)"
            );
        }
        for tok in help_text.split_whitespace() {
            let f = clean_flag(tok);
            if !f.is_empty() {
                valid_flags.insert(f);
            }
        }
    }

                                                                                                      
                                                                                 
    for flag in extract_bare_flags(&section) {
        assert!(
            valid_flags.contains(&flag),
            "the runbook names a bare `{flag}`, but no referenced `orchard` verb accepts it"
        );
    }
}
