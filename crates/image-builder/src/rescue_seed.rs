                                                                                            
//!
//! Calls the Task 1.1 crate (`grape`, host-key derivation) to derive the 32-byte seed
//! (HKDF-SHA256 over the operator master-key + the build's public inputs), then bakes it into the
//! read-only rootfs at `/etc/dropbear/rescue-host-key-seed`, mode 0600 root:root (`-all-root` at
//! mksquashfs time makes it root-owned). At boot the rescue init re-derives the actual dropbear
//! host key from this seed + the dm-verity root hash (the crate's runtime stage). The seed file is
//! IMA-signed like every other rootfs file; its integrity at rest is dm-verity + the `.img` PKCS7.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use grape::{derive_seed, DeriveError, PublicInputs};
use zeroize::Zeroize;

/// Derive + write the 32-byte rescue-host-key-seed into `staging_root/etc/dropbear/` at mode 0600.
/// `master_key_path` is the operator-secret `rescue-seed-master.key` (32 bytes, never on the image).
pub fn write_rescue_seed(
    staging_root: &Path,
    master_key_path: &Path,
    inputs: &PublicInputs,
) -> Result<(), DeriveError> {
    let mut seed = derive_seed(master_key_path, inputs)?;
    let dir = staging_root.join("etc/dropbear");
    fs::create_dir_all(&dir).map_err(DeriveError::Write)?;
    let path = dir.join("rescue-host-key-seed");
    let written = fs::write(&path, seed).map_err(DeriveError::Write);
    seed.zeroize();                                                                
    written?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(DeriveError::Write)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use grape::seed_from_inputs;

    #[test]
    fn writes_deterministic_seed_at_0600() {
        let base = std::env::temp_dir().join(format!("rescue-seed-{}", std::process::id()));
        let staging = base.join("staging");
        fs::create_dir_all(&staging).unwrap();
        let mk_path = base.join("master.key");
        let master = [7u8; 32];
        fs::write(&mk_path, master).unwrap();
        let inputs = PublicInputs::new("a".repeat(40), "3.23.0", "b".repeat(64)).unwrap();

        write_rescue_seed(&staging, &mk_path, &inputs).unwrap();

        let seed_path = staging.join("etc/dropbear/rescue-host-key-seed");
        let written = fs::read(&seed_path).unwrap();
        let mode = fs::metadata(&seed_path).unwrap().permissions().mode() & 0o777;
        let expected = seed_from_inputs(&master, &inputs).unwrap();
        fs::remove_dir_all(&base).ok();

        assert_eq!(written.len(), 32, "seed is 32 bytes");
        assert_eq!(mode, 0o600, "seed file is mode 0600");
        assert_eq!(
            written, expected,
            "seed matches the crate's deterministic derivation"
        );
    }
}
