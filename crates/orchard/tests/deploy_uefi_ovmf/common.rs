//! Shared SB-ON battery env + dryrun opts for the UEFI OVMF gates (used by both gate families).

pub(crate) struct SbEnv {
    pub(crate) sb_img: std::path::PathBuf,
    pub(crate) privkey: std::path::PathBuf,
    pub(crate) sb_keys_dir: std::path::PathBuf,
    pub(crate) db_pin: std::path::PathBuf,
    pub(crate) secboot_code: std::path::PathBuf,
    pub(crate) vars_template: std::path::PathBuf,
    pub(crate) container_image: String,
}

pub(crate) fn sb_env(gate: &str) -> SbEnv {
    let var = |k: &str| {
        std::env::var(k).unwrap_or_else(|_| {
            panic!(
                "{gate} (--ignored) without {k} — set the SB-ON battery env (RECIPES_UEFI_SB_IMG, \
                 RECIPES_UEFI_PRIVKEY, RECIPES_SB_KEYS_DIR, RECIPES_SB_DB_PIN, \
                 RECIPES_OVMF_CODE_SECBOOT, RECIPES_OVMF_VARS) or run via `make boot-gate-uefi`. \
                 A boot gate must never pass without asserting."
            )
        })
    };
    SbEnv {
        sb_img: var("RECIPES_UEFI_SB_IMG").into(),
        privkey: var("RECIPES_UEFI_PRIVKEY").into(),
        sb_keys_dir: std::path::PathBuf::from(var("RECIPES_SB_KEYS_DIR")).join("secure-boot"),
        db_pin: var("RECIPES_SB_DB_PIN").into(),
        secboot_code: var("RECIPES_OVMF_CODE_SECBOOT").into(),
        vars_template: var("RECIPES_OVMF_VARS").into(),
        container_image: std::env::var("RECIPES_CONTAINER_IMAGE")
            .unwrap_or_else(|_| "recipes-imgbuild:dev".to_string()),
    }
}

pub(crate) fn sb_opts() -> orchard::deploy::dryrun::DryrunOpts {
    orchard::deploy::dryrun::DryrunOpts {
        ssh_port: 2223,
        https_port: 8444,
        ..Default::default()
    }
}
