//! The operator-local host-key PIN STORE for `orchard update` (os-update A/B v1 T20, component C-E).
//!
//! The prod ceremony's two trust legs use PER-INVOCATION ephemeral `known_hosts` files — there is NO
//! persisted known-good store (`prod_orchestrate.rs`). The update ceremony connects to an
//! ALREADY-DEPLOYED box repeatedly (push updates over its life), so it needs a DURABLE per-host pin: a
//! box's first update goes through a NON-SILENT bootstrap (an interactive y/N, or an explicit
//! `--host-fingerprint`), and every later update VERIFIES against the stored pin. A key CHANGE is
//! REFUSED — never silently re-TOFU'd, and no flag (`--confirmed` included) can override it (the store
//! never even sees `--confirmed`; a mismatch is a hard refusal by construction).
//!
//! Reuses [`super::prod::host_key_decision`] for the first-contact decision (the SAME pure TOFU logic
//! the prod ceremony uses), NOT the destructive prod ceremony itself — the persisted store is the only
//! new mechanism. Pin file = `<pin_dir>/<sanitized-host>`, one trimmed fingerprint line.

use std::path::{Path, PathBuf};

use super::prod::{HostKeyDecision, host_key_decision};

/// A trusted host-key pin (the box's SSH host-key fingerprint the ceremony connects under).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedKey {
    pub fingerprint: String,
}

/// The outcome of a successful [`resolve_host_pin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinOutcome {
    /// The presented key matched an existing stored pin — proceed silently (a normal reconnect).
    Stable(PinnedKey),
    /// First contact: the pin was just written (an explicit `--host-fingerprint` matched, or the
    /// operator's interactive assent was carried in). NON-SILENT by construction — never reached under
    /// an unattended `--confirmed` with no fingerprint.
    Bootstrapped(PinnedKey),
}

/// Why a host-pin resolution refused (all fail-closed — the ceremony aborts on any of them).
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// The stored pin exists and the presented key DIFFERS. Refused unconditionally — a key change on
    /// an established box is a security event the operator must resolve by hand (inspect + delete the
    /// pin deliberately), never a silent re-pin. `--confirmed` cannot reach this decision.
    #[error(
        "host {host}: the presented SSH host key does NOT match the stored pin — refusing to silently \
         re-pin (a key change is a security event). stored={stored}, presented={presented}. If this is \
         an intended re-key, delete {pin_path} deliberately and re-run to re-bootstrap."
    )]
    SilentOverrideRefused {
        host: String,
        stored: String,
        presented: String,
        pin_path: String,
    },
    /// First contact with an explicit `--host-fingerprint` that does NOT match the presented key.
    #[error(
        "host {host}: --host-fingerprint {expected} does not match the presented host key {presented}"
    )]
    FingerprintMismatch {
        host: String,
        expected: String,
        presented: String,
    },
    /// First contact with no stored pin, no `--host-fingerprint`, and an interactive prompt IS possible.
    /// The caller must obtain the operator's y/N assent, then [`commit_pin`]. NOT an error the ceremony
    /// aborts on — it is the "prompt me" signal (carried as an error so the resolve stays write-free).
    #[error(
        "host {host}: first contact — the operator must confirm the presented host key {presented}"
    )]
    FirstContactNeedsConfirm { host: String, presented: String },
    /// First contact, no pin, no `--host-fingerprint`, and NO interactive terminal (a `--confirmed`
    /// fleet loop, or CI). A box's first update can never silently TOFU — pass `--host-fingerprint` or
    /// run the first update interactively.
    #[error(
        "host {host}: first contact with no stored pin and no --host-fingerprint on a non-interactive \
         run — refusing to silently trust-on-first-use. Run the first update interactively (to confirm \
         the key) or pass --host-fingerprint <sha>."
    )]
    NoPinNonInteractive { host: String },
    /// A [`supersede_pin`] found the store NOT in the state the caller proved trust against — either
    /// no pin at all, or a different fingerprint (a racing writer, or the caller's evidence is stale).
    /// Fail-closed: the supersede only ever replaces the exact pin the ceremony verified before its
    /// push; anything else is resolved by hand.
    #[error(
        "host {host}: supersede refused — the stored pin is {stored:?} but the ceremony verified \
         {expected}; the store changed underneath the ceremony (resolve by hand)"
    )]
    SupersedeMismatch {
        host: String,
        expected: String,
        stored: Option<String>,
    },
    #[error("host-pin io at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Inputs to a host-pin resolution.
pub struct HostPinOpts<'a> {
    /// `--host-fingerprint` — the operator's explicit assertion of the box's SSH host key. On FIRST
    /// contact it bootstraps the pin (the e2e/CI + pre-verified-operator path). On an ESTABLISHED pin
    /// it is ALSO checked, against the key the box actually presents: a value disagreeing with the
                                                                                                 
    /// NOTE the update ceremony rotates the pin to the image-derived key on every COMMITTED flip, so a
    /// fleet loop must NOT keep passing the fingerprint it first bootstrapped with — it would
    /// mismatch after the first update. `None` ⇒ interactive-confirm or fail-closed on first contact.
    pub host_fingerprint: Option<&'a str>,
    /// Whether an interactive terminal is available to prompt for first-contact assent. Note this is
    /// NOT `--confirmed`: `--confirmed` (the unattended fleet flag) deliberately does NOT grant
    /// first-contact assent, so it is not even an input here.
    pub is_tty: bool,
    /// The pin store directory (`~/.config/recipes-deploy/host-pins/`); injected so tests use a tempdir.
    pub pin_dir: &'a Path,
}

/// The pin file for `host` under `pin_dir`. The host (a domain or IP) is sanitized to a safe filename —
/// every byte outside `[A-Za-z0-9.-]` becomes `_` so a hostile/odd host string can never traverse out of
/// `pin_dir` or collide with a control name.
fn pin_path(pin_dir: &Path, host: &str) -> PathBuf {
    let safe: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
                                                                                                          
                                                                                                        
                                                           
    let safe = if safe.is_empty() || safe == "." || safe == ".." {
        format!("_{safe}")
    } else {
        safe
    };
    pin_dir.join(safe)
}

/// Read the stored pin for `host`, if any. A trimmed single-line fingerprint; absent ⇒ `Ok(None)`.
fn read_pin(pin_dir: &Path, host: &str) -> Result<Option<String>, PinError> {
    let path = pin_path(pin_dir, host);
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(PinError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Persist `presented` as the pin for `host` (0600, dir 0700). Idempotent — writes verbatim. Called on a
/// trusted first contact (an `--host-fingerprint` match inside [`resolve_host_pin`], or by the ceremony
/// after interactive y/N assent). NEVER overwrites a DIFFERING pin — the caller reaches here only after
/// `resolve_host_pin` has ruled out a change (a `SilentOverrideRefused` short-circuits first).
pub fn commit_pin(
    host: &str,
    presented: &str,
    opts: &HostPinOpts<'_>,
) -> Result<PinnedKey, PinError> {
    std::fs::create_dir_all(opts.pin_dir).map_err(|source| PinError::Io {
        path: opts.pin_dir.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(opts.pin_dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = pin_path(opts.pin_dir, host);
    let line = format!("{}\n", presented.trim());
    std::fs::write(&path, &line).map_err(|source| PinError::Io {
        path: path.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(PinnedKey {
        fingerprint: presented.trim().to_string(),
    })
}

/// Resolve trust for `host`'s presented SSH host key against the persisted pin store. WRITE-FREE except
/// the trusted-first-contact-with-matching-`--host-fingerprint` path (which pins by construction):
/// - a stored pin that MATCHES ⇒ `Ok(Stable)` (silent reconnect);
/// - a stored pin that DIFFERS ⇒ `Err(SilentOverrideRefused)` (unconditional — no flag overrides);
/// - first contact with `--host-fingerprint` matching ⇒ pin written, `Ok(Bootstrapped)`;
/// - first contact with `--host-fingerprint` NOT matching ⇒ `Err(FingerprintMismatch)`;
/// - first contact, no fingerprint, interactive ⇒ `Err(FirstContactNeedsConfirm)` (the ceremony prompts
///   then calls [`commit_pin`]);
/// - first contact, no fingerprint, non-interactive ⇒ `Err(NoPinNonInteractive)`.
pub fn resolve_host_pin(
    host: &str,
    presented: &str,
    opts: &HostPinOpts<'_>,
) -> Result<PinOutcome, PinError> {
                                                                                                             
                                                                                                         
                                                                                                       
    if let Some(stored) = read_pin(opts.pin_dir, host)? {
                                                                                                  
                                                                                                     
                                                                                                      
                                                                                                    
                                                                                                    
                                                                                              
        if let Some(fp) = opts.host_fingerprint
            && fp.trim() != presented.trim()
        {
            return Err(PinError::FingerprintMismatch {
                host: host.to_string(),
                expected: fp.trim().to_string(),
                presented: presented.trim().to_string(),
            });
        }
        return match host_key_decision(Some(&stored), opts.is_tty, presented) {
            HostKeyDecision::Accept => Ok(PinOutcome::Stable(PinnedKey {
                fingerprint: stored,
            })),
                                                                     
            HostKeyDecision::Abort => Err(PinError::SilentOverrideRefused {
                host: host.to_string(),
                stored,
                presented: presented.trim().to_string(),
                pin_path: pin_path(opts.pin_dir, host).display().to_string(),
            }),
                                                                        
            HostKeyDecision::ConfirmInteractively(_) | HostKeyDecision::FailClosed => {
                unreachable!("a present stored pin yields only Accept/Abort")
            }
        };
    }

                                                                                                     
    match host_key_decision(opts.host_fingerprint, opts.is_tty, presented) {
                                                                                                          
        HostKeyDecision::Accept => commit_pin(host, presented, opts).map(PinOutcome::Bootstrapped),
                                                  
        HostKeyDecision::Abort => Err(PinError::FingerprintMismatch {
            host: host.to_string(),
            expected: opts.host_fingerprint.unwrap_or_default().trim().to_string(),
            presented: presented.trim().to_string(),
        }),
                                                                                  
        HostKeyDecision::ConfirmInteractively(_) => Err(PinError::FirstContactNeedsConfirm {
            host: host.to_string(),
            presented: presented.trim().to_string(),
        }),
                                                                                                      
        HostKeyDecision::FailClosed => Err(PinError::NoPinNonInteractive {
            host: host.to_string(),
        }),
    }
}

/// Deliberate, evidence-based pin REPLACEMENT for a known key rotation — the update ceremony's
/// COMMITTED slot flip. The box's runtime host key is IMAGE-DERIVED (`oneshots_offline`), so a
/// committed A/B flip rotates it BY CONSTRUCTION, and the new key was derived locally from the
/// operator's own signed image — categorically different from an unexplained key change, which
/// stays [`PinError::SilentOverrideRefused`] with no override. Fail-closed on the store's state:
/// the CURRENT stored pin must equal `expected_current` (the fingerprint the ceremony resolved
/// trust against before its push) or the supersede refuses.
///
                                                                                                 
                                                                                               
/// untouched), then the new pin is written to a temp file in the same dir and `rename`d over the pin
/// path — a single atomic replace. An interruption
/// at any point leaves EITHER the old pin (rename not yet done) or the new pin (done), never an
/// absent pin that would downgrade the unconditional key-change refusal to a first-contact TOFU.
pub fn supersede_pin(
    host: &str,
    expected_current: &str,
    new_fingerprint: &str,
    opts: &HostPinOpts<'_>,
) -> Result<PinnedKey, PinError> {
    let stored = read_pin(opts.pin_dir, host)?;
    if stored.as_deref() != Some(expected_current.trim()) {
        return Err(PinError::SupersedeMismatch {
            host: host.to_string(),
            expected: expected_current.trim().to_string(),
            stored,
        });
    }
    let path = pin_path(opts.pin_dir, host);
    let io = |source: std::io::Error| PinError::Io {
        path: path.display().to_string(),
        source,
    };
                                                                                                     
                                                                                                       
                                                                                                   
                                                                                                       
                                                                  
    let suffix: String = {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(expected_current.trim().as_bytes());
        d[..8].iter().map(|b| format!("{b:02x}")).collect()
    };
    let archive = path.with_file_name(format!(
        "{}.superseded-{suffix}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    std::fs::copy(&path, &archive).map_err(io)?;
                                                                                                    
                                                                            
    let tmp = path.with_file_name(format!(
        "{}.tmp-{suffix}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    std::fs::write(&tmp, format!("{}\n", new_fingerprint.trim())).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path).map_err(io)?;
    Ok(PinnedKey {
        fingerprint: new_fingerprint.trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn opts<'a>(dir: &'a Path, fp: Option<&'a str>, is_tty: bool) -> HostPinOpts<'a> {
        HostPinOpts {
            host_fingerprint: fp,
            is_tty,
            pin_dir: dir,
        }
    }

    #[test]
    fn explicit_fingerprint_disagreeing_with_the_presented_key_is_caught_even_with_a_pin() {
                                                                                                    
                                                                                                        
                                             
        let dir = tempfile::tempdir().unwrap();
        commit_pin("box.example", KEY_A, &opts(dir.path(), None, false)).unwrap();
        let err = resolve_host_pin("box.example", KEY_A, &opts(dir.path(), Some(KEY_B), false))
            .unwrap_err();
        assert!(matches!(err, PinError::FingerprintMismatch { .. }), "{err}");
    }

    #[test]
    fn explicit_fingerprint_matching_the_presented_key_still_refuses_a_pin_change() {
                                                                                                   
                                                                                                 
                                                                                                    
        let dir = tempfile::tempdir().unwrap();
        commit_pin("box.example", KEY_A, &opts(dir.path(), None, false)).unwrap();
        let err = resolve_host_pin("box.example", KEY_B, &opts(dir.path(), Some(KEY_B), false))
            .unwrap_err();
        assert!(
            matches!(err, PinError::SilentOverrideRefused { .. }),
            "{err}"
        );
    }

    #[test]
    fn supersede_replaces_exactly_the_expected_pin_and_archives_the_old() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path(), None, false);
        commit_pin("box.example", KEY_A, &o).unwrap();
        let out = supersede_pin("box.example", KEY_A, KEY_B, &o).unwrap();
        assert_eq!(out.fingerprint, KEY_B);
        let stored = std::fs::read_to_string(pin_path(dir.path(), "box.example")).unwrap();
        assert_eq!(stored.trim(), KEY_B, "the new pin is stored");
                                                  
        let archived: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("superseded"))
            .collect();
        assert_eq!(archived.len(), 1, "exactly one archive");
        let content = std::fs::read_to_string(archived[0].path()).unwrap();
        assert_eq!(content.trim(), KEY_A, "the archive holds the OLD pin");
    }

                                                                                             
    /// (`+` vs `/`, both in OpenSSH's alphabet) share every alnum prefix, so the archive suffix must
    /// come from the whole fingerprint. Two successive supersedes must leave two archives holding
    /// their own old pin; the pre-fix prefix suffix produced ONE filename and `fs::copy` overwrote
    /// the first archive.
    #[test]
    fn two_old_pins_differing_only_outside_the_alnum_prefix_archive_to_distinct_files() {
        const FPR_PLUS: &str = "SHA256:klzBaauEGBWY+DN3wwX0gXle1bfnBXgbcRQp2Z6WiQA";
        const FPR_SLASH: &str = "SHA256:klzBaauEGBWY/DN3wwX0gXle1bfnBXgbcRQp2Z6WiQA";
                                                                                                       
        assert_ne!(FPR_PLUS, FPR_SLASH);
        let alnum = |s: &str| -> String {
            s.trim_start_matches("SHA256:")
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(12)
                .collect()
        };
        assert_eq!(alnum(FPR_PLUS), alnum(FPR_SLASH), "no collision to test");

        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path(), None, false);
        commit_pin("box.example", FPR_PLUS, &o).unwrap();
                                                                                                
        supersede_pin("box.example", FPR_PLUS, FPR_SLASH, &o).unwrap();
        supersede_pin("box.example", FPR_SLASH, KEY_B, &o).unwrap();

        let mut archived: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".superseded-"))
            .map(|e| {
                std::fs::read_to_string(e.path())
                    .unwrap()
                    .trim()
                    .to_string()
            })
            .collect();
        archived.sort();
                                                                                               
        let mut want = vec![FPR_PLUS.to_string(), FPR_SLASH.to_string()];
        want.sort();
        assert_eq!(archived, want, "an archive was overwritten or invented");
    }

    #[test]
    fn supersede_refuses_a_store_that_changed_underneath() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path(), None, false);
        commit_pin("box.example", KEY_B, &o).unwrap();                          
        let err = supersede_pin("box.example", KEY_A, KEY_B, &o).unwrap_err();
        assert!(matches!(err, PinError::SupersedeMismatch { .. }), "{err}");
        let stored = std::fs::read_to_string(pin_path(dir.path(), "box.example")).unwrap();
        assert_eq!(stored.trim(), KEY_B, "the store is untouched");
    }

    #[test]
    fn supersede_refuses_an_absent_pin() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path(), None, false);
        let err = supersede_pin("box.example", KEY_A, KEY_B, &o).unwrap_err();
        assert!(matches!(
            err,
            PinError::SupersedeMismatch { stored: None, .. }
        ));
    }

    #[test]
    fn host_pin_first_contact_writes() {
                                                                                                      
                                                                    
        let dir = tempfile::tempdir().unwrap();
        let out =
            resolve_host_pin("box.example", KEY_A, &opts(dir.path(), Some(KEY_A), false)).unwrap();
        assert_eq!(
            out,
            PinOutcome::Bootstrapped(PinnedKey {
                fingerprint: KEY_A.to_string()
            })
        );
                             
        let stored = std::fs::read_to_string(pin_path(dir.path(), "box.example")).unwrap();
        assert_eq!(stored.trim(), KEY_A);
    }

    #[test]
    fn host_pin_stable_reconnect() {
                                                                                                 
        let dir = tempfile::tempdir().unwrap();
        commit_pin("box.example", KEY_A, &opts(dir.path(), None, false)).unwrap();
        let out = resolve_host_pin("box.example", KEY_A, &opts(dir.path(), None, false)).unwrap();
        assert_eq!(
            out,
            PinOutcome::Stable(PinnedKey {
                fingerprint: KEY_A.to_string()
            })
        );
    }

    #[test]
    fn host_pin_change_refused() {
                                                                                                          
                                                                                                      
                                                                                                         
        let dir = tempfile::tempdir().unwrap();
        commit_pin("box.example", KEY_A, &opts(dir.path(), None, false)).unwrap();
        for o in [
            opts(dir.path(), None, false),                         
            opts(dir.path(), None, true),                      
            opts(dir.path(), Some(KEY_B), true),                                                
        ] {
            let err = resolve_host_pin("box.example", KEY_B, &o).unwrap_err();
            assert!(
                matches!(err, PinError::SilentOverrideRefused { .. }),
                "a key change must be refused, got {err:?}"
            );
        }
                                            
        let stored = std::fs::read_to_string(pin_path(dir.path(), "box.example")).unwrap();
        assert_eq!(stored.trim(), KEY_A);
    }

    #[test]
    fn host_pin_first_contact_needs_confirm_on_tty() {
                                                                                              
        let dir = tempfile::tempdir().unwrap();
        let err =
            resolve_host_pin("box.example", KEY_A, &opts(dir.path(), None, true)).unwrap_err();
        assert!(
            matches!(err, PinError::FirstContactNeedsConfirm { .. }),
            "{err:?}"
        );
        assert!(
            !pin_path(dir.path(), "box.example").exists(),
            "resolve must not write on confirm-needed"
        );
    }

    #[test]
    fn host_pin_first_contact_non_interactive_refused() {
                                                                                                         
        let dir = tempfile::tempdir().unwrap();
        let err =
            resolve_host_pin("box.example", KEY_A, &opts(dir.path(), None, false)).unwrap_err();
        assert!(
            matches!(err, PinError::NoPinNonInteractive { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn host_pin_first_contact_fingerprint_mismatch() {
                                                                                                    
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_host_pin("box.example", KEY_A, &opts(dir.path(), Some(KEY_B), false))
            .unwrap_err();
        assert!(
            matches!(err, PinError::FingerprintMismatch { .. }),
            "{err:?}"
        );
        assert!(!pin_path(dir.path(), "box.example").exists());
    }

    #[test]
    fn pin_path_sanitizes_the_host() {
                                                                                                  
        let dir = Path::new("/pins");
        assert_eq!(pin_path(dir, "1.2.3.4"), Path::new("/pins/1.2.3.4"));
                                                                                                       
        assert_eq!(pin_path(dir, "a/../b"), Path::new("/pins/a_.._b"));
        assert_eq!(
            pin_path(dir, "box.example.org"),
            Path::new("/pins/box.example.org")
        );
                                                                                               
        assert_eq!(pin_path(dir, ".."), Path::new("/pins/_.."));
        assert_eq!(pin_path(dir, "."), Path::new("/pins/_."));
        assert_eq!(pin_path(dir, "/"), Path::new("/pins/_"));
    }
}
