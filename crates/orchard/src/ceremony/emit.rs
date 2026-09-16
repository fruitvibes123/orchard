                                                                                                   
//! to a closed downstream pipe (`| head`) returns `Err(EPIPE)` (SIGPIPE is SIG_IGN, Rust's default)
//! and the macro UNWRAPS it, panicking the process to 101/`crash` — a false internal-fault class off
//! the exit chokepoint. The porcelain records, the `--print-context`/doctor render, the refusal /
//! error render, and the `ORCHARD_LOCK_DIR` disclosure are MACHINE surfaces a fleet wrapper reads
//! (and may `| head`); they write through these helpers, which lock the handle, `write_all`, and
//! DISCARD the result, so a closed consumer lets the process fall through to its honest class code.
//! Lives in the LIB (not main.rs) so `ceremony::lock`'s disclosure can share the one property.
//! Human-progress `println!`s stay as-is and are backstopped by main()'s broken-pipe panic hook.

use std::io::Write as _;

/// Write `s` to stdout, ignoring a broken-pipe (or any) write error.
pub fn emit_stdout(s: &str) {
    let _ = std::io::stdout().lock().write_all(s.as_bytes());
}

/// Write `s` to stderr, ignoring a broken-pipe (or any) write error.
pub fn emit_stderr(s: &str) {
    let _ = std::io::stderr().lock().write_all(s.as_bytes());
}
