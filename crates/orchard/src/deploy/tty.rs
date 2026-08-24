                                                                                   
                                                                                  
//! stdin is not an interactive terminal (no `-it`, a pipe, a redirect) the read
//! ABORTS — fail-closed, so the host `orchard` never buffers or forwards it and the
//! passphrase can't be slipped in from a script/pipe. The passphrase lives only in
//! `Zeroizing` buffers for its whole lifetime here.
//!
//! Inherent upstream residual (F-7): `rpassword`'s `SafeString` wipes its final buffer
//! on drop but not the intermediate reallocations from character-by-character growth
//! while typing (a general zeroize/`String` limitation, not fixable in this module).

use super::keys::DeployKeyError;
use zeroize::Zeroizing;

/// Refuse unless stdin is an interactive terminal (the `-it` pty). Fail-closed:
                                                                           
///
/// NOTE (F-5, verified): `rpassword` itself reads/writes `/dev/tty`, not stdin — so this
/// gate is deliberately on STDIN and runs FIRST. A non-interactive stdin (pipe/redirect)
/// aborts HERE before `/dev/tty` is ever opened, so a decoy piped passphrase can't slip
/// past by way of an available `/dev/tty`. The error message is the gate's SIGNATURE (the
/// tests assert on it) so a removed gate can't masquerade as a working one.
pub(crate) fn require_interactive_stdin() -> Result<(), DeployKeyError> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(DeployKeyError::Import(
            "passphrase requires an interactive TTY (stdin is not a terminal) — the docker \
             rung must run with `-it`; refusing to read a passphrase from a pipe/redirect"
                .into(),
        ))
    }
}

fn prompt(p: &str) -> Result<Zeroizing<String>, DeployKeyError> {
    rpassword::prompt_password(p)
        .map(Zeroizing::new)
        .map_err(|e| DeployKeyError::Import(format!("passphrase read failed: {e}")))
}

/// A NEW passphrase pair (keygen) is valid iff non-empty AND the two entries match. Pure —
/// separated from the TTY read so the fail-closed logic is unit-testable (the read itself
/// needs a real pty). A typo (mismatch) or an empty passphrase MUST abort, so the operator
/// never wraps the keys under an unrecoverable/absent passphrase.
fn validate_new_passphrase(first: &[u8], again: &[u8]) -> Result<(), DeployKeyError> {
    if first.is_empty() {
        return Err(DeployKeyError::Import(
            "passphrase must not be empty".into(),
        ));
    }
    if first != again {
        return Err(DeployKeyError::Import("passphrases do not match".into()));
    }
    Ok(())
}

/// Read an EXISTING passphrase once (the sign / unwrap path), echo off. Fail-closed on
/// a non-TTY stdin.
pub fn read_passphrase(p: &str) -> Result<Zeroizing<Vec<u8>>, DeployKeyError> {
    require_interactive_stdin()?;
    Ok(Zeroizing::new(prompt(p)?.as_bytes().to_vec()))
}

/// Read a NEW passphrase WITH confirmation (the keygen / wrap path): entered twice, must
/// match, must be non-empty. Fail-closed on a non-TTY stdin, on empty, or on a mismatch.
pub fn read_new_passphrase(p: &str, confirm: &str) -> Result<Zeroizing<Vec<u8>>, DeployKeyError> {
    require_interactive_stdin()?;
    let first = prompt(p)?;
    let again = prompt(confirm)?;
    validate_new_passphrase(first.as_bytes(), again.as_bytes())?;
    Ok(Zeroizing::new(first.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

                                                                                           
                                                                                        
    #[test]
    fn require_interactive_stdin_aborts_when_stdin_is_not_a_tty() {
        let e = require_interactive_stdin().unwrap_err();
        assert!(
            e.to_string().contains("not a terminal"),
            "gate must name the missing TTY: {e}"
        );
    }

                                                                                           
                                                                                         
                                                                                           
                                                                                      
    #[test]
    fn reads_fail_closed_via_the_gate_not_incidental_io() {
        for r in [
            read_passphrase("pw: "),
            read_new_passphrase("pw: ", "confirm: "),
        ] {
            let e = r.unwrap_err();
            assert!(
                e.to_string().contains("not a terminal"),
                "must fail via the isatty gate, got: {e}"
            );
        }
    }

                                                                                 
    #[test]
    fn validate_new_passphrase_rejects_empty_and_mismatch() {
        assert!(validate_new_passphrase(b"", b"").is_err(), "empty rejected");
        assert!(
            validate_new_passphrase(b"abc", b"abd").is_err(),
            "mismatch rejected"
        );
        assert!(validate_new_passphrase(b"correct horse", b"correct horse").is_ok());
    }
}
