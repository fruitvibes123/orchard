                                                                                                 
//! EXHAUSTIVE match over the real clap enums (no catch-all, so a new variant is a compile error —
                                                                                                 
//! spine data checked total against a RECURSIVE walk of the spine-modeled verbs' clap surfaces,
                                                                                              
//! walk would be vacuous).

use std::collections::BTreeSet;

use clap::CommandFactory;

use crate::cli::{Cli, MarketSub, OrchardCmd, StoreSub};

                                                                                               
                                                                                   
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbClass {
    Writing,
    ReadOnly,
}

                                                                                    
                                                                                              
                                                                                       
pub fn verb_class(cmd: &OrchardCmd) -> VerbClass {
    use VerbClass::*;
    match cmd {
                                                    
        OrchardCmd::DeriveRescueOffline { .. } => ReadOnly,
                                                           
        OrchardCmd::GenerateKeys { .. } => Writing,
                                               
        OrchardCmd::Redelegate { .. } => Writing,
                                                                
        OrchardCmd::Update { .. } => Writing,
                                                               
        OrchardCmd::DeployModel { .. } => Writing,
                                                      
        OrchardCmd::Status { .. } => ReadOnly,
                                                                     
        OrchardCmd::RotateKey { .. } => Writing,
                                                    
        OrchardCmd::SignBackup { .. } => Writing,
                                                                                
        OrchardCmd::SignInContainer { .. } => Writing,
                                                                                     
        OrchardCmd::SignSb { .. } => Writing,
                                                     
        OrchardCmd::UpdateCertFingerprints { .. } => Writing,
                                                               
        OrchardCmd::Build { .. } => Writing,
                                            
        OrchardCmd::RestoreImage { .. } => Writing,
                                                                  
        OrchardCmd::BuildInstallerUsb { .. } => Writing,
                                                                     
        OrchardCmd::SignInstallerUsb { .. } => Writing,
                                                                          
        OrchardCmd::Dryrun { .. } => Writing,
                                               
        OrchardCmd::Doctor { .. } => ReadOnly,
                                   
        OrchardCmd::Prod { .. } => Writing,
                                                                                              
                                                                                       
        OrchardCmd::Guide { .. } => Writing,
                                                                                              
                                                                                 
        OrchardCmd::Run { .. } => Writing,
                                                         
        OrchardCmd::ReclaimTail { .. } => Writing,
                                              
        OrchardCmd::RefreshApkLock { .. } => Writing,
                                                                                         
                                         
        OrchardCmd::SyncPins { .. } => Writing,
                                                
        OrchardCmd::Vendor { .. } => Writing,
                                                                             
        OrchardCmd::Prime { .. } => Writing,
        OrchardCmd::Admit { .. } => Writing,
        OrchardCmd::Market { sub } => match sub {
            MarketSub::Verify { .. } => ReadOnly,
            MarketSub::Outdated { .. } => ReadOnly,
            MarketSub::Upgrade { .. } => Writing,
            MarketSub::Store { sub } => match sub {
                StoreSub::Status { .. } => ReadOnly,
                                                                                                  
                StoreSub::Prune { .. } => Writing,
                                                                            
                StoreSub::Migrate => Writing,
            },
        },
                                                                                                
                                                                                                
                                                                              
    }
}

                                                                                                
                                                                                           
                                                                                                  
/// globals + its positional profile, so it has no `flag_table` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerbId {
    GenerateKeys,
    Prime,
    Vendor,
    MarketUpgrade,
    Build,
    Prod,
    Guide,
    Run,
                                                                                                     
    /// so enabling the feature leaves those matches without an arm for it and the build fails — the
    /// totality demonstration for the classification domain (FAC-GC-11).
    #[cfg(feature = "ceremony-seed-unclassified-verb")]
    CeremonySeedUnclassifiedVerbId,
}

impl VerbId {
    /// Every variant, compiler-forced (FAC-GC-11): `succ` is a match with no catch-all, so a new
                                                                                                      
    /// the enum. The `ceremony-seed-unclassified-verb` seed proves the forcing.
    pub fn all() -> impl Iterator<Item = VerbId> {
        std::iter::successors(Some(VerbId::GenerateKeys), |v| match v {
            VerbId::GenerateKeys => Some(VerbId::Prime),
            VerbId::Prime => Some(VerbId::Vendor),
            VerbId::Vendor => Some(VerbId::MarketUpgrade),
            VerbId::MarketUpgrade => Some(VerbId::Build),
            VerbId::Build => Some(VerbId::Prod),
            VerbId::Prod => Some(VerbId::Guide),
            VerbId::Guide => Some(VerbId::Run),
            VerbId::Run => None,
        })
    }

    /// The clap path of this verb under the root command (the walk anchor).
    pub fn command_path(self) -> &'static [&'static str] {
        match self {
            VerbId::GenerateKeys => &["generate-keys"],
            VerbId::Prime => &["prime"],
            VerbId::Vendor => &["vendor"],
            VerbId::MarketUpgrade => &["market", "upgrade"],
            VerbId::Build => &["build"],
            VerbId::Prod => &["prod"],
            VerbId::Guide => &["guide"],
            VerbId::Run => &["run"],
        }
    }
}

                                                                                           
                                                                                                 
/// no interactive confirmation and disables no guard, and is forwardable only when typed on the
/// executing invocation, never composed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagClass {
    ConsentBearing,
    GuardDisabling,
    ForwardablePin,
    MandatoryDestructiveToken,
    Benign,
}

/// The context/global flags defined at the root and propagated to every verb (clap
/// `global = true`) plus clap's auto help/version: classified Benign once, for every verb.
pub const GLOBAL_BENIGN_FLAGS: &[&str] = &[
    "repo-root",
    "artifact-store",
    "repo-manifest",
    "context",
    "print-context",
    "help",
    "version",
];

/// The per-flag classification table over the spine-modeled verbs' clap surfaces (long names,
/// canonical form; aliases resolve to their canonical flag in the walk). Totality against the
                                                                              
pub fn flag_table() -> &'static [(VerbId, &'static str, FlagClass)] {
    use FlagClass::*;
    use VerbId::*;
    &[
                                  
        (GenerateKeys, "porcelain", Benign),
        (GenerateKeys, "force", GuardDisabling),
        (GenerateKeys, "output-dir", Benign),
        (GenerateKeys, "subject", Benign),
        (GenerateKeys, "regenerate-master-key", Benign),
        (GenerateKeys, "artifact-signing", Benign),
        (GenerateKeys, "delegation-window-days", Benign),
        (GenerateKeys, "artifact-keys-only", Benign),
        (GenerateKeys, "secure-boot", Benign),
        (GenerateKeys, "sb-rsa", Benign),
        (GenerateKeys, "sb-db-fingerprint-path", Benign),
        (GenerateKeys, "signing-key-token", Benign),
        (GenerateKeys, "import-image-signing", Benign),
        (GenerateKeys, "import-image-signing-cert", Benign),
        (GenerateKeys, "import-signing-ca", Benign),
        (GenerateKeys, "import-signing-ca-cert", Benign),
        (GenerateKeys, "import-ima", Benign),
        (GenerateKeys, "import-ima-cert", Benign),
                          
        (Prime, "porcelain", Benign),
        (Prime, "kbuild-dir", Benign),
        (Prime, "syslinux-dir", Benign),
                           
        (Vendor, "porcelain", Benign),
        (Vendor, "store", Benign),
                                   
        (MarketUpgrade, "porcelain", Benign),
        (MarketUpgrade, "source", Benign),
        (MarketUpgrade, "binary", Benign),
        (MarketUpgrade, "config", Benign),
        (MarketUpgrade, "apks", Benign),
        (MarketUpgrade, "kernel", Benign),
        (MarketUpgrade, "rust", Benign),
        (MarketUpgrade, "all", Benign),
        (MarketUpgrade, "dry-run", Benign),
        (MarketUpgrade, "container-image", Benign),
        (MarketUpgrade, "build-dir", Benign),
                                                                                            
        (MarketUpgrade, "commit", ConsentBearing),
        (MarketUpgrade, "no-commit", Benign),
                          
        (Build, "porcelain", Benign),
        (Build, "profile", Benign),
        (Build, "domain", Benign),
        (Build, "keys-dir", Benign),
        (Build, "out-dir", Benign),
        (Build, "ksrc", Benign),
        (Build, "syslinux-src", Benign),
        (Build, "container-image", Benign),
                                        
        (Build, "allow-dirty", GuardDisabling),
        (Build, "verify", Benign),
        (Build, "recovery-pubkey", Benign),
        (Build, "operator-pubkey", Benign),
        (Build, "firmware", Benign),
        (Build, "substrate", Benign),
        (Build, "net", Benign),
        (Build, "secure-boot", Benign),
        (Build, "manifest", Benign),
        (Build, "image-version", Benign),
        (Build, "weights-anchor", Benign),
        (Build, "dha-weights-gguf", Benign),
        (Build, "dha-mmproj-gguf", Benign),
                         
        (Prod, "porcelain", Benign),
        (Prod, "profile", Benign),
        (Prod, "pubkey", Benign),
        (Prod, "image", Benign),
        (Prod, "ssh-identity", Benign),
        (Prod, "provisioning-user", Benign),
        (Prod, "box-login-identity", Benign),
        (Prod, "port", Benign),
        (Prod, "domain", Benign),
        (Prod, "keys-dir", Benign),
        (Prod, "out-dir", Benign),
        (Prod, "ksrc", Benign),
        (Prod, "syslinux-src", Benign),
        (Prod, "container-image", Benign),
                                                            
        (Prod, "allow-dirty", GuardDisabling),
        (Prod, "recovery-pubkey", Benign),
        (Prod, "net", Benign),
                                                                                            
                                                               
        (Prod, "wipe-confirmed", MandatoryDestructiveToken),
                                                                                
        (Prod, "host-fingerprint", ForwardablePin),
        (Prod, "known-hosts", ForwardablePin),
        (Prod, "runtime-hostkey-fingerprint", ForwardablePin),
        (Prod, "artifact-pin", ForwardablePin),
        (Prod, "reclaim-tail", Benign),
        (Prod, "reclaim-timeout-secs", Benign),
        (Prod, "restore-from", Benign),
        (Prod, "restore-min-ctr", Benign),
        (Prod, "image-stage-dir", Benign),
        (Prod, "reconnect-timeout-secs", Benign),
                                                                                                        
        (Guide, "repo-form-dir", Benign),
                                              
        (Run, "target", Benign),
        (Run, "image-version", Benign),
                                                                                             
        (Run, "commit", ConsentBearing),
                                                                                                   
        (Run, "wipe-confirmed", MandatoryDestructiveToken),
        (Run, "porcelain", Benign),
        (Run, "repo-form-dir", Benign),
    ]
}

/// One collected flag from the clap walk: its canonical long name + every alias.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalkedFlag {
    pub long: String,
    pub aliases: Vec<String>,
}

/// Recursively collect every long flag (+ arg aliases) of the command node at `path` under the
                                                                                            
/// applied at every level, `Arg::get_all_aliases` — NOT `Command::get_all_aliases`, which
/// returns subcommand aliases; R7 I-4).
pub fn walk_long_flags(path: &[&str]) -> Vec<WalkedFlag> {
    let root = Cli::command();
    let mut node = &root;
    for seg in path {
        node = node
            .get_subcommands()
            .find(|c| c.get_name() == *seg)
            .unwrap_or_else(|| panic!("no subcommand {seg:?} under {:?}", node.get_name()));
    }
    let mut out = Vec::new();
    collect(node, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect(cmd: &clap::Command, out: &mut Vec<WalkedFlag>) {
    for a in cmd.get_arguments() {
        if let Some(long) = a.get_long() {
            let aliases = a
                .get_all_aliases()
                .unwrap_or_default()
                .iter()
                .map(|s| s.to_string())
                .collect();
            out.push(WalkedFlag {
                long: long.to_string(),
                aliases,
            });
        }
    }
    for sub in cmd.get_subcommands() {
        collect(sub, out);
    }
}

/// The classified flag set for one verb, canonical names (the arm-14 domain).
pub fn table_flags_of(verb: VerbId) -> BTreeSet<&'static str> {
    flag_table()
        .iter()
        .filter(|(v, _, _)| *v == verb)
        .map(|(_, f, _)| *f)
        .collect()
}

/// Resolve a composed token's class for a verb: canonical name or ALIAS (aliases classify as
/// their canonical flag — `--yes` ⇒ `commit` ⇒ ConsentBearing).
pub fn class_of_token(verb: VerbId, token: &str) -> Option<FlagClass> {
    let name = token.trim_start_matches("--");
    let name = name.split('=').next().unwrap_or(name);
    if GLOBAL_BENIGN_FLAGS.contains(&name) {
        return Some(FlagClass::Benign);
    }
                     
    if let Some((_, _, c)) = flag_table()
        .iter()
        .find(|(v, f, _)| *v == verb && *f == name)
    {
        return Some(*c);
    }
                                                        
    for wf in walk_long_flags(verb.command_path()) {
        if wf.aliases.iter().any(|a| a == name) {
            return flag_table()
                .iter()
                .find(|(v, f, _)| *v == verb && *f == wf.long)
                .map(|(_, _, c)| *c);
        }
    }
    None
}

                                                                                                   
/// `--`-prefixed token", so a `-x` — including clap's auto `-h` — composed unchecked. This resolves
/// the short character through the verb's REAL clap surface (`Arg::get_short`) to its long name and
/// classifies that. `None` when the token is not a single recognized short flag on this verb (a
                                                                                                   
/// than reading it as a value, keeping the composed surface long-flags-only.
pub fn class_of_short_token(verb: VerbId, token: &str) -> Option<FlagClass> {
    let short = token.strip_prefix('-').filter(|s| !s.starts_with('-'))?;
    if short.chars().count() != 1 {
        return None;
    }
    let c = short.chars().next()?;
    let long = short_flag_long(verb, c)?;
    class_of_token(verb, &long)
}

                                                                                                 
                                                                                            
pub const NO_OP_EXIT_FLAGS: &[&str] = &["help", "version", "print-context"];

/// Whether a composed token (long or short spelling) resolves to a `NO_OP_EXIT_FLAGS` member.
pub fn is_no_op_exit_token(verb: VerbId, token: &str) -> bool {
    let long = if let Some(name) = token.strip_prefix("--") {
        name.split('=').next().unwrap_or(name).to_string()
    } else if let Some(short) = token.strip_prefix('-').filter(|s| !s.starts_with('-')) {
        let mut chars = short.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => match short_flag_long(verb, c) {
                Some(l) => l,
                None => return false,
            },
            _ => return false,
        }
    } else {
        return false;
    };
    NO_OP_EXIT_FLAGS.contains(&long.as_str())
}

/// The long name of a short flag on `verb`, via the real clap surface (short → long, so the class
/// table — long-name-keyed — can classify it). Recurses into subcommands like `walk_long_flags`.
fn short_flag_long(verb: VerbId, short: char) -> Option<String> {
    fn find(cmd: &clap::Command, short: char) -> Option<String> {
        for a in cmd.get_arguments() {
            if a.get_short() == Some(short) {
                return a.get_long().map(|l| l.to_string());
            }
        }
        cmd.get_subcommands().find_map(|s| find(s, short))
    }
    let root = Cli::command();
    let mut node = &root;
    for seg in verb.command_path() {
        node = node.get_subcommands().find(|c| c.get_name() == *seg)?;
    }
    find(node, short)
}
