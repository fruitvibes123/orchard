                                                                              
//!
//! Build signing is NOW the in-tree DETERMINISTIC [`crate::ima_evm_signer`] (RFC-6979 ECDSA, byte-
//! reproducible). This module retains [`evmctl_sign_argv`] (the validated `evmctl sign --portable
//! --imasig -a sha256` argv) — now the signer's differential-test ORACLE, NOT the build signer. (The
                                                                                                        
//! `pseudo_manifest` via the `S_IFREG` map-mode check; the old `should_ima_sign` `FileType` predicate
//! was retired with the map-driven walk.) evmctl, empirically grounded on ima-evm-utils 1.6.2 + an ECDSA-P256 key
//! (2026-05-25), writes `security.ima` (type 0x03, v2, sha256 — the content sig the kernel's
//! BPRM/MMAP appraisal verifies) + PORTABLE `security.evm` (type 0x05, NOT the fs-bound HMAC type
                                                                                                     
//! (proven by `ima_evm_signer`'s differential test). evmctl is a build-HOST tool, never in the image.
//!
//! ## Build-env preconditions (empirically determined — the build container must honour these)
//! Setting `security.*` xattrs requires **CAP_SYS_ADMIN**, and the staging filesystem must
//! support `security.*` xattrs — **overlayfs FILTERS them**, so the staging tree lives on a
//! tmpfs or real-fs mount. The container therefore runs `--cap-add SYS_ADMIN --tmpfs <staging>`
//! (or a real-fs volume); `mksquashfs -xattrs` then captures the xattrs into the image.
//! Without both, evmctl fails `Setting IMA sig xattr failed (errno: Operation not permitted)`.
//!
//! `-a sha256` is REQUIRED explicitly: evmctl 1.6.2 + openssl 3.x garbles the default digest name.

use std::path::Path;

/// The validated `evmctl` argv that writes `security.ima` + portable `security.evm` on `file`.
/// (`--portable` => EVM type 0x05; `--imasig` => also the IMA content sig; `-a sha256` explicit.)
pub fn evmctl_sign_argv(key: &Path, file: &Path) -> Vec<String> {
    vec![
        "sign".into(),
        "--portable".into(),
        "--imasig".into(),
        "-a".into(),
        "sha256".into(),
        "--key".into(),
        key.to_string_lossy().into_owned(),
        file.to_string_lossy().into_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn evmctl_argv_is_portable_imasig_sha256() {
        let argv = evmctl_sign_argv(&p("/k/ima.key"), &p("/s/usr/bin/recipes"));
        assert_eq!(argv[0], "sign");
        assert!(argv.contains(&"--portable".to_string()), "EVM type 0x05");
        assert!(argv.contains(&"--imasig".to_string()), "security.ima too");
        let a = argv.iter().position(|x| x == "-a").unwrap();
        assert_eq!(argv[a + 1], "sha256");
        assert_eq!(argv.last().unwrap(), "/s/usr/bin/recipes");
    }
}
