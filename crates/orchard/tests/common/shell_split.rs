//! The oracle for a printed command: the shell that will receive it.
//!
//! An operator resumes by pasting the printed line into a shell, so the reader that stands in for
//! that operator is the host `/bin/sh` itself, given the line as script text. A reader that split
//! on single spaces agreed with an unquoted composer whatever it rendered; the R16f probe 4
//! measurement is `probes-r16-design-review/pC16f_4_quote_instance.rs`.

/// Split `printed` the way `/bin/sh` splits it: the leading `orchard` word is dropped and the rest
/// is interpolated into `set -- <rest>`, so quote removal, field splitting, pathname expansion and
/// parameter expansion all happen as they do for the operator's paste. The tokens come back
/// NUL-separated, so a token carrying a space, a tab or a newline survives the read.
///
/// Fails closed: a shell that refuses the line (an unbalanced quote) or writes to stderr panics
/// rather than returning a short token list a comparison would then read as a difference.
pub fn shell_split(printed: &str) -> Vec<String> {
    let rest = printed.strip_prefix("orchard ").unwrap_or_else(|| {
        panic!("the printed command does not open with the program name: {printed:?}")
    });
    let script = format!("set -- {rest}\nfor a; do printf '%s\\0' \"$a\"; done");
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("spawn /bin/sh");
    assert!(
        out.status.success() && out.stderr.is_empty(),
        "/bin/sh refused the printed command ({:?}): {}\n{printed:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let mut bytes = out.stdout;
    if bytes.is_empty() {
        return Vec::new();
    }
    assert_eq!(
        bytes.pop(),
        Some(0),
        "the reader's output is not NUL-terminated, so the last token is truncated: {printed:?}"
    );
    bytes
        .split(|b| *b == 0)
        .map(|t| {
            String::from_utf8(t.to_vec())
                .unwrap_or_else(|e| panic!("the shell returned a non-UTF-8 token: {e}"))
        })
        .collect()
}
