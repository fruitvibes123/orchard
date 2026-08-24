                                                                                                     
//! (paths + public pins), NOT intent. WHITELIST-parsed (`deny_unknown_fields`) — any key outside the
//! schema REFUSES; the known destructive keys refuse with a tailored message. The operator still
//! types the target + supplies the wipe intent; the profile only removes the retype toil.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Keys that encode DESTRUCTIVE intent — flag/TTY-only, NEVER from a config file. Recognized purely
                                                                                             
const DESTRUCTIVE_KEYS: &[&str] = &[
    "wipe_confirmed",
    "restore_from",
    "restore_min_ctr",
    "allow_dirty",
];

/// The whitelisted profile schema — paths + public pins only, never key material or confirmations.
/// `deny_unknown_fields` makes ANY key outside this set (destructive keys, inline secrets, typos) a
/// hard refusal.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub net: Option<String>,
    pub operator_pubkey: Option<PathBuf>,
    pub recovery_pubkey: Option<PathBuf>,
    pub ssh_identity: Option<PathBuf>,
    pub box_login_identity: Option<PathBuf>,
    pub host_fingerprint: Option<String>,
    pub runtime_hostkey_fingerprint: Option<String>,
    pub keys_dir: Option<PathBuf>,
    pub out_dir: Option<PathBuf>,
}

/// Parse a profile from a TOML string. FIRST a destructive-key pre-scan (for the tailored message),
/// THEN `deny_unknown_fields` (the generic refusal for anything else outside the whitelist).
pub fn load_str(s: &str) -> Result<Profile, String> {
                                                                                                  
                                                                                                      
                                                                                                      
                                                                                                   
    let table: toml::Table = toml::from_str(s).map_err(|e| format!("profile parse: {e}"))?;
    for k in DESTRUCTIVE_KEYS {
        if table.contains_key(*k) {
            return Err(format!(
                "profile contains `{k}` — destructive intent (--wipe-confirmed / --restore-from / \
                 --restore-min-ctr / --allow-dirty) can NEVER come from a config file; it is \
                 flag/TTY-only. Remove `{k}` from the profile and pass it on the command line."
            ));
        }
    }
    toml::from_str(s).map_err(|e| format!("profile parse: {e}"))
}

/// Load + parse a profile from a file.
pub fn load(path: &Path) -> Result<Profile, String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| format!("read profile {}: {e}", path.display()))?;
    load_str(&s)
}

                                                                                                  
/// precisely because no profile-suppliable key keeps a clap default (they were stripped in the clap
/// restructuring), so a `None` flag genuinely means "not passed", not "defaulted".
pub fn pick<T: Clone>(flag: Option<T>, profile: Option<T>, default: Option<T>) -> Option<T> {
    flag.or(profile).or(default)
}

                                                                                                
/// profile hard-refuses, naming BOTH sources. This is the guard that REPLACES clap's parse-time
/// required-arg enforcement — clap only relaxes it when `--profile` is present, so this check is what
/// closes the cell clap no longer covers. The caller runs it BEFORE any remote or destructive action.
pub fn require_present<'a, T>(
    name: &str,
    flag_key: &str,
    profile_key: &str,
    value: Option<&'a T>,
) -> Result<&'a T, String> {
    value.ok_or_else(|| {
        format!(
            "{name} is required but was supplied by NEITHER the {flag_key} flag NOR the profile's \
             `{profile_key}` key — pass {flag_key} or add `{profile_key}` to the profile (aborting \
             before any remote or destructive action)"
        )
    })
}

/// The typed `<ip>` target is authoritative and always required; when the profile ALSO carries an
/// `ip`, a mismatch refuses (catches grabbing the wrong box's profile). The profile ip NEVER
                                                                               
pub fn ip_cross_check(typed: &str, profile_ip: Option<&str>) -> Result<(), String> {
    match profile_ip {
        Some(p) if p != typed => Err(format!(
            "the typed target `{typed}` does not match the profile's `ip = \"{p}\"` — you may be \
             pointing the wrong box's profile at this target; aborting. (The typed target is \
             authoritative; fix one to match, or drop `ip` from the profile.)"
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_whitelisted_keys() {
        let p =
            load_str("ip = \"203.0.113.5\"\nport = 2222\ndomain = \"box.example.com\"\n").unwrap();
        assert_eq!(p.ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(p.port, Some(2222));
    }

    #[test]
    fn refuses_an_unknown_key() {
        let e = load_str("frobnicate = true\n").unwrap_err();
        assert!(e.contains("frobnicate") || e.contains("unknown"), "{e}");
    }

    #[test]
    fn refuses_a_destructive_key_with_the_tailored_message() {
        for k in [
            "wipe_confirmed",
            "restore_from",
            "restore_min_ctr",
            "allow_dirty",
        ] {
            let e = load_str(&format!("{k} = true\n")).unwrap_err();
            assert!(e.contains("destructive intent"), "key {k}: {e}");
            assert!(e.contains(k), "names the key {k}: {e}");
        }
    }

    #[test]
    fn refuses_a_key_material_looking_key() {
                                                                                                     
        let e = load_str("private_key = \"-----BEGIN...\"\n").unwrap_err();
        assert!(!e.is_empty());
    }

    #[test]
    fn a_multiline_string_value_is_not_a_destructive_key() {
                                                                                                       
                                                                          
        let p = load_str("domain = \"\"\"\nwipe_confirmed = true\n\"\"\"\n").unwrap();
        assert!(p.domain.as_deref().unwrap().contains("wipe_confirmed"));
    }

    #[test]
    fn flag_beats_profile_beats_default() {
        assert_eq!(pick(Some(1), Some(2), Some(3)), Some(1));
        assert_eq!(pick(None, Some(2), Some(3)), Some(2));
        assert_eq!(pick::<i32>(None, None, Some(3)), Some(3));
    }

    #[test]
    fn port_from_profile_reaches_the_ceremony() {
                                                                                                         
        assert_eq!(pick(None, Some(2222u16), Some(22u16)), Some(2222));
    }

    #[test]
    fn missing_required_value_refuses_naming_both_sources() {
        let e = require_present(
            "operator pubkey",
            "--pubkey",
            "operator_pubkey",
            None::<&PathBuf>,
        )
        .unwrap_err();
        assert!(
            e.contains("--pubkey") && e.contains("operator_pubkey"),
            "{e}"
        );
    }

    #[test]
    fn ip_cross_check_refuses_on_mismatch_proceeds_on_match() {
        assert!(ip_cross_check("203.0.113.5", Some("203.0.113.5")).is_ok());
        assert!(ip_cross_check("203.0.113.5", Some("198.51.100.9")).is_err());
        assert!(ip_cross_check("203.0.113.5", None).is_ok());                                    
    }
}
