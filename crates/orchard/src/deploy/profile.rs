                                                                                                     
//! (paths + public pins), NOT intent. WHITELIST-parsed (`deny_unknown_fields`) — any key outside the
//! schema REFUSES; the known destructive keys refuse with a tailored message. The operator still
//! types the target + supplies the wipe intent; the profile only removes the retype toil.

use serde::{Deserialize, Serialize};
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub net: Option<String>,
    pub operator_pubkey: Option<PathBuf>,
    pub recovery_pubkey: Option<PathBuf>,
    pub ssh_identity: Option<PathBuf>,
    /// The PRE-KEXEC login user (guided-ceremony plan-inputs §Transport). The ceremony connects
    /// as the substrate's cloud user and `sudo`s the privileged steps, so a provider restriction
    /// on the root key (Infomaniak's `command="…exit 142"`, which returns after every reinstall)
    /// never bites. Clouds differ (`debian`, `ubuntu`, `ec2-user`), and a fixture whose
    /// provisioning login IS root sets it to `root`, which skips the sudo wrapper. Post-install
    /// reconnect is unaffected: that leg is the box's own dropbear.
    pub provisioning_user: Option<String>,
    pub box_login_identity: Option<PathBuf>,
    pub host_fingerprint: Option<String>,
    pub runtime_hostkey_fingerprint: Option<String>,
    pub keys_dir: Option<PathBuf>,
    pub out_dir: Option<PathBuf>,
                                                                                            
                                                                                                   
    pub repo_root: Option<PathBuf>,
    pub artifact_store: Option<PathBuf>,
    pub repo_manifest: Option<PathBuf>,
                                                                                               
                                                                                                
                                                                      
    pub schema_version: Option<u32>,
    pub firmware: Option<String>,
    pub image_version: Option<u64>,
    pub container_image: Option<String>,
    pub manifest: Option<PathBuf>,
    pub tenant_source_ref: Option<String>,
    pub tenant_repo: Option<String>,
    pub tenant_artifacts: Option<String>,
    pub gate_target: Option<String>,
    pub dha_weights_gguf: Option<PathBuf>,
}

                                                       
pub const PROFILE_SCHEMA_VERSION: u32 = 1;

                                                                                              
/// `profile_keys_match_the_schema` test locks it to the struct — a drifted list is a red test).
pub const PROFILE_KEYS: &[&str] = &[
    "ip",
    "port",
    "domain",
    "net",
    "operator_pubkey",
    "recovery_pubkey",
    "ssh_identity",
    "provisioning_user",
    "box_login_identity",
    "host_fingerprint",
    "runtime_hostkey_fingerprint",
    "keys_dir",
    "out_dir",
    "repo_root",
    "artifact_store",
    "repo_manifest",
    "schema_version",
    "firmware",
    "image_version",
    "container_image",
    "manifest",
    "tenant_source_ref",
    "tenant_repo",
    "tenant_artifacts",
    "gate_target",
    "dha_weights_gguf",
];

                                                                                                    
                                                                                                    
                                                                                               
                                                                                                
                                                                                           
                                                                          

/// Profile keys `orchard build` consumes — merged into the build opts (domain/net/keys_dir/out_dir/
/// firmware/image_version/container_image/manifest/dha_weights_gguf) or the resolved context
/// (repo_root/artifact_store/repo_manifest) or the skew check (schema_version).
pub const BUILD_CONSUMED_KEYS: &[&str] = &[
    "domain",
    "net",
    "keys_dir",
    "out_dir",
    "firmware",
    "image_version",
    "container_image",
    "manifest",
    "dha_weights_gguf",
    "repo_root",
    "artifact_store",
    "repo_manifest",
    "schema_version",
];

/// Profile keys `orchard build` does NOT consume: the deploy-only keys and the Task-6-deferred
/// ceremony keys. `build` prints these (when present) as the ignored-key note.
pub const BUILD_NOTED_KEYS: &[&str] = &[
    "ip",
    "port",
    "provisioning_user",
    "operator_pubkey",
    "recovery_pubkey",
    "ssh_identity",
    "provisioning_user",
    "box_login_identity",
    "host_fingerprint",
    "runtime_hostkey_fingerprint",
    "tenant_source_ref",
    "tenant_repo",
    "tenant_artifacts",
    "gate_target",
];

/// Profile keys `orchard prod` consumes (the deploy merges + firmware + the resolved context +
/// the skew check). prod's inline build is a one-shot greenfield, so image_version/manifest/
/// dha_weights_gguf are deliberately NOT consumed (hardcoded greenfield values) and are noted.
pub const PROD_CONSUMED_KEYS: &[&str] = &[
    "ip",
    "port",
    "provisioning_user",
    "domain",
    "net",
    "operator_pubkey",
    "recovery_pubkey",
    "ssh_identity",
    "provisioning_user",
    "box_login_identity",
    "host_fingerprint",
    "runtime_hostkey_fingerprint",
    "keys_dir",
    "out_dir",
    "repo_root",
    "artifact_store",
    "repo_manifest",
    "schema_version",
    "firmware",
    "container_image",
];

/// Profile keys `orchard prod` does NOT consume: build-only + greenfield-hardcoded + the
/// Task-6-deferred ceremony keys.
pub const PROD_NOTED_KEYS: &[&str] = &[
    "image_version",
    "manifest",
    "dha_weights_gguf",
    "tenant_source_ref",
    "tenant_repo",
    "tenant_artifacts",
    "gate_target",
];

/// The profile keys PRESENT in `prof` that a verb deliberately ignores (its `noted` set), in
                                                                                        
/// serializing the typed profile (a None Option serializes to JSON null and is filtered out), so
/// the list is derived from the schema, never a hand map that drops a key silently.
pub fn noted_keys_present(prof: &Profile, noted: &[&str]) -> Vec<&'static str> {
    let present = present_keys(prof);
    PROFILE_KEYS
        .iter()
        .copied()
        .filter(|k| noted.contains(k) && present.contains(*k))
        .collect()
}

fn present_keys(prof: &Profile) -> std::collections::BTreeSet<String> {
                                                                                            
                                                                                 
    serde_json::to_value(prof)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .map(|o| {
            o.iter()
                .filter(|(_, val)| !val.is_null())
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default()
}

                                                                                                   
/// `build` calls so the profile values reach the image, and
/// `build_manifest_weights_threads_the_profile_values` asserts the resolved value IS the profile
/// value (independent oracle). Prior to this the build arm read only the clap flags, so a box
/// profile recording its manifest/weights built the pinned reference tenant / a non-dha image.
pub fn build_manifest_weights(
    flag_manifest: Option<PathBuf>,
    flag_weights: Option<PathBuf>,
    prof: Option<&Profile>,
) -> (Option<PathBuf>, Option<PathBuf>) {
    (
        pick(flag_manifest, prof.and_then(|p| p.manifest.clone()), None),
        pick(
            flag_weights,
            prof.and_then(|p| p.dha_weights_gguf.clone()),
            None,
        ),
    )
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
                                                                                
                                                                                          
                                                                                                 
                                                                                                    
                                                                                                 
                                                                                                  
                                                                                            
    if let Some(v) = table
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        && v > i64::from(PROFILE_SCHEMA_VERSION)
    {
                                                                                                   
                                                                 
                                                    
                                                                                              
                                                                                             
        return Err(format!(
            "{SCHEMA_SKEW_PREFIX}profile schema_version {v} is newer than this orchard understands \
             (≤ {PROFILE_SCHEMA_VERSION}) — upgrade orchard, or set the profile's schema_version \
             to {PROFILE_SCHEMA_VERSION} and remove any keys this version then rejects"
        ));
    }
    let profile: Profile = toml::from_str(s).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("unknown field") {
                                                                                             
                                                                         
            format!(
                "profile parse: {msg} — if this profile was written by a newer orchard, the \
                 unknown key is a newer schema: upgrade orchard (or remove the key)"
            )
        } else {
            format!("profile parse: {msg}")
        }
    })?;
    Ok(profile)
}

/// The sentinel prefix a schema-skew error carries so a caller can re-raise it as a typed refusal.
pub const SCHEMA_SKEW_PREFIX: &str = "[schema-skew] ";

                                                                                                 
/// NEVER contain — destructive intent keys, raw key material, a typed confirmation token.
/// Returns the first offender found (None = clean). The destructive-key check PARSES the TOML and
                                                                          
/// quoted, and dotted key forms the load gate already catches; the same parsed structure the load
/// gate uses is used here so the two never disagree. A non-TOML input (an unexpected shape) falls
/// back to the raw scan, fail-closed.
pub fn scan_for_forbidden_content(text: &str) -> Option<String> {
    match toml::from_str::<toml::Table>(text) {
        Ok(table) => {
            if let Some(k) = find_destructive_key(&table) {
                return Some(format!("destructive key `{k}`"));
            }
        }
        Err(_) => {
                                                                                        
            for k in DESTRUCTIVE_KEYS {
                if text.contains(k) {
                    return Some(format!("destructive key `{k}` (raw scan)"));
                }
            }
        }
    }
    if text.contains("-----BEGIN") {
        return Some("raw key material (-----BEGIN block)".into());
    }
    if text.contains("--wipe-confirmed") {
        return Some("a typed destructive token (--wipe-confirmed)".into());
    }
    None
}

/// Walk a parsed TOML table for any `DESTRUCTIVE_KEYS` member at any depth (nested tables/arrays).
fn find_destructive_key(table: &toml::Table) -> Option<&'static str> {
    for (key, value) in table {
        if let Some(hit) = DESTRUCTIVE_KEYS.iter().find(|k| **k == key.as_str()) {
            return Some(hit);
        }
        if let Some(hit) = find_destructive_in_value(value) {
            return Some(hit);
        }
    }
    None
}

fn find_destructive_in_value(value: &toml::Value) -> Option<&'static str> {
    match value {
        toml::Value::Table(t) => find_destructive_key(t),
        toml::Value::Array(a) => a.iter().find_map(find_destructive_in_value),
        _ => None,
    }
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
    fn profile_keys_match_the_schema() {
                                                                                                 
                                                                                    
                                                                                                 
                       
        let full = Profile {
            ip: Some("h".into()),
            port: Some(22),
            domain: Some("d".into()),
            net: Some("n".into()),
            operator_pubkey: Some("/k".into()),
            recovery_pubkey: Some("/k".into()),
            ssh_identity: Some("/k".into()),
            provisioning_user: Some("debian".into()),
            box_login_identity: Some("/k".into()),
            host_fingerprint: Some("f".into()),
            runtime_hostkey_fingerprint: Some("f".into()),
            keys_dir: Some("/k".into()),
            out_dir: Some("/o".into()),
            repo_root: Some("/r".into()),
            artifact_store: Some("/s".into()),
            repo_manifest: Some("/m".into()),
            schema_version: Some(1),
            firmware: Some("seabios".into()),
            image_version: Some(0),
            container_image: Some("recipes-imgbuild:dev".into()),
            manifest: Some("/m.toml".into()),
            tenant_source_ref: Some("abc".into()),
            tenant_repo: Some("recipes".into()),
            tenant_artifacts: Some("binary:recipes-app".into()),
            gate_target: Some("boot-gate".into()),
            dha_weights_gguf: Some("/w.gguf".into()),
        };
        let json = serde_json::to_value(&full).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = PROFILE_KEYS.to_vec();
        expected.sort_unstable();
        let mut got = keys.clone();
        got.sort_unstable();
        assert_eq!(got, expected, "PROFILE_KEYS drifted from the schema");
    }

    #[test]
    fn accepts_the_context_keys() {
                                                                                          
                                                                                                
        let p = load_str(
            "repo_root = \"/eco/orchard\"\nartifact_store = \"/eco/artifact-store\"\n\
             repo_manifest = \"/eco/orchard/repo-manifest.toml\"\n",
        )
        .unwrap();
        assert_eq!(p.repo_root.as_deref(), Some(Path::new("/eco/orchard")));
        assert_eq!(
            p.artifact_store.as_deref(),
            Some(Path::new("/eco/artifact-store"))
        );
        assert_eq!(
            p.repo_manifest.as_deref(),
            Some(Path::new("/eco/orchard/repo-manifest.toml"))
        );
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

    fn assert_classification_total(verb: &str, consumed: &[&str], noted: &[&str]) {
        use std::collections::BTreeSet;
        let consumed: BTreeSet<&str> = consumed.iter().copied().collect();
        let noted: BTreeSet<&str> = noted.iter().copied().collect();
        let overlap: Vec<&str> = consumed.intersection(&noted).copied().collect();
        assert!(
            overlap.is_empty(),
            "{verb}: keys both consumed AND noted: {overlap:?}"
        );
        let all: BTreeSet<&str> = PROFILE_KEYS.iter().copied().collect();
        for k in consumed.iter().chain(noted.iter()) {
            assert!(
                all.contains(k),
                "{verb}: `{k}` is not a PROFILE_KEYS member"
            );
        }
        let mut union = consumed;
        union.extend(noted);
        assert_eq!(
            union, all,
            "{verb}: consumed ∪ noted must be EXACTLY PROFILE_KEYS — a new schema key must be \
             classified (fail-closed)"
        );
    }

    #[test]
    fn build_key_classification_is_total_and_disjoint() {
                                                                                                     
                                                                                                    
                                            
        assert_classification_total("build", BUILD_CONSUMED_KEYS, BUILD_NOTED_KEYS);
    }

    #[test]
    fn prod_key_classification_is_total_and_disjoint() {
        assert_classification_total("prod", PROD_CONSUMED_KEYS, PROD_NOTED_KEYS);
    }

    #[test]
    fn build_manifest_weights_threads_the_profile_values() {
                                                                                                      
                                                                           
        let prof = Profile {
            manifest: Some("/m.toml".into()),
            dha_weights_gguf: Some("/w.gguf".into()),
            ..Default::default()
        };
        let (m, w) = build_manifest_weights(None, None, Some(&prof));
        assert_eq!(m.as_deref(), Some(Path::new("/m.toml")));
        assert_eq!(w.as_deref(), Some(Path::new("/w.gguf")));
        let (m2, _) = build_manifest_weights(Some("/flag.toml".into()), None, Some(&prof));
        assert_eq!(
            m2.as_deref(),
            Some(Path::new("/flag.toml")),
            "flag beats profile"
        );
        let (m3, w3) = build_manifest_weights(None, None, None);
        assert!(m3.is_none() && w3.is_none(), "no flag, no profile ⇒ None");
    }

    #[test]
    fn noted_keys_present_lists_only_present_ignored_keys() {
                                                                                                  
        let prof = Profile {
            ip: Some("203.0.113.5".into()),
            gate_target: Some("boot-gate".into()),
            domain: Some("box.test".into()),                                     
            ..Default::default()
        };
        assert_eq!(
            noted_keys_present(&prof, BUILD_NOTED_KEYS),
            vec!["ip", "gate_target"]
        );
                                                                                                   
                                      
        let cer = Profile {
            tenant_repo: Some("recipes".into()),
            ..Default::default()
        };
        assert_eq!(
            noted_keys_present(&cer, BUILD_NOTED_KEYS),
            vec!["tenant_repo"]
        );
    }
}
