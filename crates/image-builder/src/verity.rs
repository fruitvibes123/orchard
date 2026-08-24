                                                                                                 
//!
//! `veritysetup format --no-superblock` as bounded build-glue. BOOT-CRITICAL (QEMU boot-test
//! 2026-05-28): the hash tree is written WITHOUT a veritysetup superblock. The init's dm-verity
//! table (`initramfs-init::verity`) reads the tree starting at `hash_start_block = offset/4096`
//! with nothing to skip; a superblock there is read as the first hash block →
//! `dm-verity: metadata block N is corrupted` → fail-closed reboot loop. `--no-superblock` also
                                                                                               
//! workaround) is gone, so the fixed salt alone yields a byte-identical tree. Block sizes are pinned
//! to 4096 (matching the init's table + the squashfs alignment), not left to the veritysetup default
                            

use std::path::Path;

                                                                                            
/// determinism). 32 bytes = 64 hex chars (sha256 verity).
pub const FIXED_SALT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The validated `veritysetup format` argv for a DETERMINISTIC, superblock-LESS hash tree.
/// `data` = the rootfs squashfs; `hash_out` = the hash-tree output file. `--no-superblock` is
/// BOOT-CRITICAL (see the module doc): the init's dm-verity table reads the tree at the hash offset
/// with no superblock to skip. Block sizes pinned to 4096; the fixed salt makes the tree
/// reproducible (no superblock UUID). The emitted root hash goes into the (signed) kernel cmdline.
pub fn veritysetup_format_argv(data: &Path, hash_out: &Path) -> Vec<String> {
    vec![
        "format".into(),
        "--no-superblock".into(),
        "--data-block-size=4096".into(),
        "--hash-block-size=4096".into(),
        format!("--salt={FIXED_SALT}"),
        data.to_string_lossy().into_owned(),
        hash_out.to_string_lossy().into_owned(),
    ]
}

/// Extract the 64-hex dm-verity root hash from `veritysetup format`'s stdout (its `Root hash:\t<hex>`
/// line). Single source for the consumers — `deploy dryrun`'s recompute + the offline
/// `derive-rescue-host-keys --image` precompute — so their parses can't drift apart and silently
/// desync the TOFU host-key derivation. Case-insensitive on the label; validates exactly 64 hex chars.
pub fn parse_veritysetup_root_hash(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let (label, rest) = line.split_once(':')?;
        if !label.trim().eq_ignore_ascii_case("root hash") {
            return None;
        }
        let hex = rest.trim();
        (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())).then(|| hex.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn argv_pins_no_superblock_block_sizes_and_salt() {
        let argv = veritysetup_format_argv(
            &PathBuf::from("/build/rootfs.sqfs"),
            &PathBuf::from("/build/verity.hash"),
        );
        assert_eq!(argv[0], "format");
        assert!(
            argv.iter().any(|a| a == "--no-superblock"),
            "BOOT-CRITICAL: no superblock (the init's dm table reads the tree at offset/4096)"
        );
        assert!(argv.iter().any(|a| a == "--data-block-size=4096"));
        assert!(argv.iter().any(|a| a == "--hash-block-size=4096"));
        assert!(
            argv.iter().any(|a| a == &format!("--salt={FIXED_SALT}")),
            "fixed salt → reproducible tree (no superblock UUID needed)"
        );
        assert!(
            !argv.iter().any(|a| a.starts_with("--uuid=")),
            "no superblock → no --uuid"
        );
        assert_eq!(
            FIXED_SALT.len(),
            64,
            "sha256 verity salt is 32 bytes / 64 hex"
        );
    }

    #[test]
    fn parses_root_hash_case_insensitively_and_validates_64_hex() {
        let hex = "ab".repeat(32);                
        assert_eq!(
            parse_veritysetup_root_hash(&format!("Data blocks: 10\nRoot hash:\t{hex}\nSalt: 00\n")),
            Some(hex.clone())
        );
        assert_eq!(
            parse_veritysetup_root_hash(&format!("root hash:   {hex}")),
            Some(hex.clone())
        );
        assert_eq!(parse_veritysetup_root_hash("no root hash here"), None);
        assert_eq!(parse_veritysetup_root_hash("Root hash:\tdeadbeef"), None);             
        assert_eq!(
            parse_veritysetup_root_hash(&format!("Root hash:\t{}", "z".repeat(64))),
            None           
        );
    }
}
