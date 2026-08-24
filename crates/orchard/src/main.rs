//! The `orchard` binary — the operator-host build/deploy factory CLI.
//!
                                                                                    
//! 2026-06-13): `recipes-admin deploy <sub>` is now `orchard <sub>`, and
//! `recipes-admin derive-rescue-host-keys --image` is now `orchard derive-rescue-offline`.
//! Operator-host only — never baked into the box image.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "orchard", version, about = "Recipes box build/deploy factory")]
#[command(after_help = "COMMAND GROUPS (lifecycle order):\n  \
    setup     generate-keys · prime · vendor · derive-rescue-offline · update-cert-fingerprints — bootstrap keys + fetch pinned sources\n  \
    build     build · dryrun · build-installer-usb — produce + locally boot-test the .img\n  \
    verify    doctor · verify (market verify) — readiness + supply-chain checks\n  \
    deploy    prod · sign-sb · sign-installer-usb · sign-backup · restore-image — ship to the box\n  \
    maintain  market (outdated/upgrade/store) · refresh-apk-lock · sync-pins — keep the pins current")]
struct Cli {
    #[command(subcommand)]
    command: OrchardCmd,
}

#[derive(clap::Subcommand)]
                                                                                                  
                                                                                            
                                                                                                  
                                                                                                    
                                                                                                   
                                                                                                   
#[allow(clippy::large_enum_variant)]
enum OrchardCmd {
    /// Offline operator precompute: derive the box's rescue/runtime host key from a local
    /// `.img` (+ its `.layout.toml`) for `~/.ssh/known_hosts` (TOFU), printing the requested
    /// form(s). Was `recipes-admin derive-rescue-host-keys --image`.
    #[command(display_order = 15)]
    DeriveRescueOffline {
        /// The local `.img` to derive from (its `.layout.toml` sibling must sit beside it).
        #[arg(long)]
        image: PathBuf,
        /// Print the OpenSSH `SHA256:…` fingerprint.
        #[arg(long)]
        print_fingerprint: bool,
        /// Print the `ssh-ed25519 AAAA…` public key.
        #[arg(long)]
        pubkey: bool,
        /// Print the full `<name>-rescue ssh-ed25519 AAAA…` known_hosts line.
        #[arg(long)]
        hostname: Option<String>,
    },
    /// Bootstrap the 7-file operator key set: a CA→leaf ECDSA-P256 hierarchy
    /// (image-signing + signing-CA self-signed; the IMA/EVM leaf CA-signed,
    /// digitalSignature-only) plus the 32-byte rescue-seed master key. Written
    /// atomically (all 7 or none) + writes the cert fingerprints into
    /// crates/image-builder/pinned-cert-fingerprints.toml.
    #[command(display_order = 10)]
    GenerateKeys {
        /// Overwrite an existing key set.
        #[arg(long)]
        force: bool,
        /// Keys directory (default ~/.config/recipes-deploy/keys).
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// Operator-distinguisher → OU in every cert DN (multi-operator
        /// audit trail). Printable, no '/', ≤ 64 chars.
        #[arg(long, value_parser = parse_subject_ou)]
        subject: Option<String>,
        /// Rotate ONLY rescue-seed-master.key (orthogonal to the mode flags).
        #[arg(long)]
        regenerate_master_key: bool,
                                                                                     
        /// `software` = root+worker+6 delegations on this host; `docker` = the same
        /// ceremony inside the pinned imgbuild container (keygen-environment isolation);
        /// `one-signer`/`two-signers` = hardware rungs (route to the 1C device ceremony,
        /// C4 — not available in this host-only build). Every rung emits the same cascade
        /// bundle. Additive: skips cert (re)gen when a cert set already exists.
        #[arg(long, value_parser = ["software", "docker", "one-signer", "two-signers"], conflicts_with = "regenerate_master_key")]
        artifact_signing: Option<String>,
        /// Validity window (days) for the software-rung delegations (default 365).
        /// The window is the rung's service life — expiry fails preflight for every
                                                                                     
        #[arg(long, default_value_t = 365)]
        delegation_window_days: u64,
                                                                                     
        /// artifact key set to --output-dir — no cert bootstrap, no committed-pin write
        /// (the in-container repo is read-only; the host writes the pin after). Used with
        /// --artifact-signing software (raw seeds) OR docker (passphrase-wrapped seeds,
        /// reading the passphrase from this container's -it TTY, echo off).
        #[arg(long, hide = true, requires = "artifact_signing")]
        artifact_keys_only: bool,
        /// Mint the Secure Boot PK/KEK/db RSA family instead of the main set (SB-loader
                                                                                
        /// `one-signer`/`two-signers` (db key on the air-gapped signer — routed, not
        /// yet available). Writes <keys-dir>/secure-boot/{PK,KEK,db}.{key,crt} + pins
        /// the PK/KEK/db cert fingerprints into crates/image-builder/pinned-secure-boot-db.toml.
        #[arg(
            long,
            group = "keygen_mode",
            value_name = "RUNG",
            conflicts_with = "regenerate_master_key"
        )]
        secure_boot: Option<String>,
        /// RSA modulus for the SB family: 3072 (default) or 2048 (the documented
        /// downgrade for firmware that rejects 3072).
        #[arg(long, default_value = "3072", requires = "secure_boot")]
        sb_rsa: String,
        /// Where to write the db/KEK/PK fingerprint anchor. Defaults to the committed repo path
        /// (crates/image-builder/pinned-secure-boot-db.toml — the operator's enrollment anchor).
        /// Override for a THROWAWAY test family so a gate mint never clobbers the committed anchor
                             
        #[arg(long, requires = "secure_boot", value_name = "PATH")]
        sb_db_fingerprint_path: Option<PathBuf>,
        /// Generate keys on a YubiKey/PIV slot (PIPELINE-phase; unsupported here).
        #[arg(long, group = "keygen_mode")]
        signing_key_token: Option<String>,
        /// Import an externally-generated set: the image-signing private key
        /// (requires the five sibling --import-* flags). Mutually exclusive
        /// with --signing-key-token.
        #[arg(
            long,
            group = "keygen_mode",
            requires_all = ["import_image_signing_cert", "import_signing_ca", "import_signing_ca_cert", "import_ima", "import_ima_cert"]
        )]
        import_image_signing: Option<PathBuf>,
        #[arg(long, requires = "import_image_signing")]
        import_image_signing_cert: Option<PathBuf>,
        #[arg(long, requires = "import_image_signing")]
        import_signing_ca: Option<PathBuf>,
        #[arg(long, requires = "import_image_signing")]
        import_signing_ca_cert: Option<PathBuf>,
        #[arg(long, requires = "import_image_signing")]
        import_ima: Option<PathBuf>,
        #[arg(long, requires = "import_image_signing")]
        import_ima_cert: Option<PathBuf>,
    },
    /// Mint the update-path delegations (UpdateImage/RootHash) over the EXISTING
    /// artifact root — for key sets minted before the update path (incl. the live
    /// box's). The box pins only the ROOT pubkey, so the new delegations verify
    /// WITHOUT a rebake. Prerequisite for BOTH `orchard update` (manifest signing)
    /// AND `orchard build` (which bakes the UpdateImage delegation ctr as
    /// min_delegation_ctr) — redelegate-before-build (R4-1). The root key is loaded
    /// ONLY for the mint (both custody classes; a wrapped docker-rung set prompts for
    /// the passphrase, unwrapping in memory only) and no key file is rewritten.
    #[command(display_order = 13)]
    Redelegate {
        /// Keys directory (default ~/.config/recipes-deploy/keys).
        #[arg(long)]
        keys_dir: Option<PathBuf>,
        /// Which update-path delegation(s) to mint. The four legacy purposes exist in
        /// every set by construction; rotating them is a future root-rotation ceremony.
        #[arg(long, value_enum, default_value_t = RedelegatePurposeArg::All)]
        purpose: RedelegatePurposeArg,
        /// Validity window (days) for the minted delegation(s) — same default + range
        /// as generate-keys' delegation window.
        #[arg(long, default_value_t = 365)]
        window_days: u64,
    },
    /// os-update A/B v1 (§5 C-E): push a signed OS-image update to a running seabios-gpt box. Verifies
    /// the build's signatures locally, connects under a persisted host-key pin (non-silent first
    /// contact), reads `fb-update status`, composes + signs an update manifest (UpdateImage delegation),
    /// streams it to the box's `fb-update apply`, then watches → COMMITTED / ROLLED-BACK / UNREACHABLE.
    /// Honest exits; never auto-retries. seabios-gpt only (an MBR box migrates via the GPT takeover).
    #[command(display_order = 46)]
    Update {
        /// The box host (domain or IP).
        host: String,
        /// The signed `.img` to push (its `.layout.toml`/`.vmlinuz`/`.initramfs`/`.sig` sidecars beside it).
        #[arg(long)]
        image: PathBuf,
        /// Operator key set dir (default ~/.config/recipes-deploy/keys) — the artifact pin + the
        /// UpdateImage sign key.
        #[arg(long)]
        keys_dir: Option<PathBuf>,
        /// The operator SSH identity for the box login (pubkey-only).
        #[arg(long)]
        identity: PathBuf,
        /// The box sshd port (default 22).
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Pre-authorize the push (a scripted fleet loop) — never a silent host-key TOFU (the pin
        /// bootstrap stays non-silent regardless). Omit to be prompted y/N interactively.
        #[arg(long)]
        confirmed: bool,
        /// Explicit box host-key fingerprint (`SHA256:…`) for a non-interactive FIRST contact (CI/fleet).
        /// A key CHANGE is always refused; this only bootstraps the first pin without a tty prompt.
        #[arg(long)]
        host_fingerprint: Option<String>,
    },
    /// Hotswap v4: push a new SIGNED model to a running runtime-weights box — a DATA hotswap
    /// (restart, not reboot; never touches the A/B slots). Packs the GGUF into the weights image
    /// (docker), signs its manifest with the operator's Purpose::Weights delegation, streams to
    /// `fb-weights swap`, and reports COMMITTED / REFUSED / DEGRADED faithfully (never auto-retries).
    DeployModel {
        /// The box host (domain or IP).
        host: String,
        /// The model GGUF to push (the operator supplies the bytes; the signed manifest pins them).
        #[arg(long)]
        model: PathBuf,
        /// Operator key set dir (default ~/.config/recipes-deploy/keys) — the Weights sign key.
        #[arg(long)]
        keys_dir: Option<PathBuf>,
        /// The operator SSH identity for the box login (pubkey-only).
        #[arg(long)]
        identity: PathBuf,
        /// The box sshd port (default 22).
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// The pinned build-container image (the weights squashfs+verity pack runs in it).
        #[arg(long, default_value = "recipes-imgbuild:dev")]
        container_image: String,
        /// Pre-authorize the push (a scripted loop) — the host-pin bootstrap stays non-silent.
        #[arg(long)]
        confirmed: bool,
        /// Explicit box host-key fingerprint (`SHA256:…`) for a non-interactive FIRST contact.
        #[arg(long)]
        host_fingerprint: Option<String>,
    },
                                                                                                       
    /// SSH transport and writes NOTHING box-side (mirrors `fb-update status`'s read-only posture).
    /// Optionally compares the box against a local `--image` (version/ctr/firmware/verity root) and/or a
    /// `--keys-dir` trust anchor. Honest exits: OK / MISMATCH / DEGRADED / PIN-MISMATCH / UNREACHABLE.
    #[command(display_order = 45)]
    Status {
        /// The box host (domain or IP).
        host: String,
        /// Compare the box against this local build (`.layout.toml`/boot-fs sidecars beside it).
        #[arg(long)]
        image: Option<PathBuf>,
        /// The operator SSH identity for the box login (pubkey-only) — REQUIRED (I-6).
        #[arg(long)]
        ssh_identity: PathBuf,
        /// Operator key set dir (for the trust-anchor comparison, `artifact-root.pub`).
        #[arg(long)]
        keys_dir: Option<PathBuf>,
        /// Explicit box host-key fingerprint (`SHA256:…`) for a non-interactive FIRST contact.
        #[arg(long)]
        host_fingerprint: Option<String>,
        /// The box sshd port (default 22).
        #[arg(long, default_value_t = 22)]
        port: u16,
    },
                                                                                                     
    /// authorized line from `--new-identity` (`ssh-keygen -y`, never a `--pubkey`), appends it (both keys
    /// valid), verifies the new key authenticates, then removes the old one — the atomic `mv` is the sole
    /// commit point and every abort leaves a working login. INTERACTIVE-ONLY (a passphrase may prompt).
    #[command(display_order = 48)]
    RotateKey {
        /// The box host (domain or IP).
        host: String,
        /// The NEW login private key (its pubkey is DERIVED, never trusted as a separate operand).
        #[arg(long)]
        new_identity: PathBuf,
        /// The CURRENT login private key — REQUIRED (I-6): authenticates the edit legs + derives the
        /// current authorized line for the step-1 gate.
        #[arg(long)]
        ssh_identity: PathBuf,
        /// Explicit box host-key fingerprint (`SHA256:…`) for a non-interactive FIRST contact.
        #[arg(long)]
        host_fingerprint: Option<String>,
        /// The box sshd port (default 22).
        #[arg(long, default_value_t = 22)]
        port: u16,
    },
    /// Sign a pulled backup tarball with the artifact WORKER key (purpose=backup).
    /// The box emits backups UNSIGNED (the CRUX: the box never signs) — the operator
                                                                                
    /// `<file>.sig` (the 254-byte dragonfruit bundle) beside the tarball.
    #[command(display_order = 44)]
    SignBackup {
        /// The pulled backup tarball to sign.
        file: PathBuf,
        /// Keys directory (default ~/.config/recipes-deploy/keys).
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// INTERNAL (the docker rung's in-container sign leg, §6 — never run by hand). Reads
    /// the wrap passphrase from THIS container's `-it` TTY (echo off, isatty fail-closed;
    /// the host never buffers it, §5/F-4), unwraps the worker key, and signs each named
    /// artifact in place (writing its 254-byte `.sig` sidecar). The `main()`-top
    /// PR_SET_DUMPABLE(0) guard has already fired before any seed material exists.
    #[command(hide = true)]
    SignInContainer {
        /// Keys dir — the container's read-only `/keys` mount. Defaults to the shared
        /// `IN_CONTAINER_KEYS_DIR` const so it can't drift from the mount target (L-2).
        #[arg(long, default_value = orchard::deploy::artifact_keys::IN_CONTAINER_KEYS_DIR)]
        keys_dir: PathBuf,
        /// The `.img` to sign (purpose=img), at its in-container `/out/…` path.
        #[arg(long)]
        img: Option<PathBuf>,
        /// The kexec vmlinuz to sign (purpose=kexec-vmlinuz).
        #[arg(long)]
        vmlinuz: Option<PathBuf>,
        /// The kexec initramfs to sign (purpose=kexec-initramfs).
        #[arg(long)]
        initramfs: Option<PathBuf>,
        /// A backup tarball to sign (purpose=backup).
        #[arg(long)]
        backup: Option<PathBuf>,
        /// A weights-record manifest to sign (purpose=weights).
        #[arg(long)]
        weights: Option<PathBuf>,
        /// An OS-update manifest to sign (purpose=update-image).
        #[arg(long)]
        update_image: Option<PathBuf>,
    },
    /// Authenticode-sign the UEFI boot PEs (the rambutan loader + the kernel) with the
    /// Secure Boot db key and splice them into the built `.img`'s ESP (SB-loader plan
                                                                                        
    /// `deploy build --firmware uefi` outputs (`<base>.{img,layout.toml,loader.efi,
    /// vmlinuz,sign-manifest.toml}`). Refuses a db.crt that doesn't match the committed
    /// pinned-secure-boot-db.toml. Rewrites `<base>.sha256` post-splice; the ed25519
    /// `.img` signature stays the documented un-wired forward-debt (it signs the
    /// post-splice image once wired).
    #[command(display_order = 42)]
    SignSb {
        /// The built `--firmware uefi` image.
        #[arg(long)]
        img: PathBuf,
        /// Operator key set dir (default ~/.config/recipes-deploy/keys).
        #[arg(long)]
        keys_dir: Option<PathBuf>,
        /// Custody rung: `software` (db key on host) now; hardware rungs routed.
        #[arg(long, default_value = "software")]
        secure_boot: String,
        /// Pinned build-container image (sbsign + mtools run inside it).
        #[arg(long, default_value = "recipes-imgbuild:dev")]
        container_image: String,
    },
    /// Recompute pinned cert fingerprints after a signing-key rotation. Pass the
    /// rotated cert path(s); un-passed sections are preserved. Commit the diff.
    #[command(display_order = 16)]
    UpdateCertFingerprints {
        #[arg(long)]
        image_signing: Option<PathBuf>,
        #[arg(long)]
        signing_ca: Option<PathBuf>,
        #[arg(long)]
        ima: Option<PathBuf>,
    },
    /// Build the image triple `recipes-image-<sha>.{img,layout.toml,sha256}` from the operator key
    /// set + pins. Run `deploy generate-keys` + `orchard prime` (or `make prime`) first.
                                                                                                   
    /// emits ed25519 `.sig` sidecars for the `.img`/vmlinuz/initramfs; otherwise it builds UNSIGNED
                                                                        
    #[command(display_order = 20)]
    Build {
        /// A named box's profile (`--profile boxes/<name>.toml`): supplies `domain`/`net`/`keys_dir`/
        /// `out_dir` VALUES; deploy-only keys in it are ignored with a printed note. Relaxes the
                                                                                                      
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Deployment domain (baked into the in-image haproxy cert path). RFC-1123 validated (M-2).
        /// Required unless a `--profile` supplies `domain` (re-enforced fail-closed post-merge).
        #[arg(long, value_parser = parse_domain, required_unless_present = "profile")]
        domain: Option<String>,
        /// Operator key set dir (default ~/.config/recipes-deploy/keys).
        #[arg(long)]
        keys_dir: Option<PathBuf>,
        /// Output dir for the `.img` triple. Flag > profile > builtin /tmp (default applied after the merge).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Staged kernel source tarball (`orchard prime` output; re-verified at consumption). Defaults
        /// to `/tmp/recipes-kbuild/linux-<pins.toml kernel.version>.tar.xz` (from the central manifest).
        #[arg(long)]
        ksrc: Option<PathBuf>,
        /// Staged syslinux source tarball (`orchard prime` output; the B1 boot-fs template source,
        /// re-verified at consumption). Defaults to `/tmp/recipes-syslinux/syslinux-<version>.tar.xz`.
        #[arg(long)]
        syslinux_src: Option<PathBuf>,
        /// Pinned build-container image ref (R.4 replaces the tag with an @sha256 digest).
        #[arg(long, default_value = "recipes-imgbuild:dev")]
        container_image: String,
        /// Build from a dirty git tree (taints the artifact NAME as <sha>-dirty; the
        /// rescue-seed IKM stays keyed on the clean commit — L-1).
        #[arg(long)]
        allow_dirty: bool,
        /// Determinism self-test (R.4 Task 3): build TWICE over identical inputs + slice-compare the
        /// three components (boot-fs/persist-skeleton/rootfs), printing a verdict + trust-boundary
        /// report. Roughly DOUBLES the build (two kernel compiles). Same-operator self-test only —
        /// proves determinism, NOT integrity (an independent rebuilder closes that gap).
        #[arg(long)]
        verify: bool,
        /// Operator recovery pubkey baked into the rescue dropbear's authorized_keys (in-rootfs, so
        /// it authenticates when /persist is unmountable). Validated derive-not-cat. Omit ⇒ placeholder.
        #[arg(long)]
        recovery_pubkey: Option<PathBuf>,
        /// Operator NORMAL-boot pubkey baked into the persist-skeleton's authorized_keys (the box's
        /// everyday login). Validated derive-not-cat. Omit ⇒ an un-loginable skeleton (placeholder).
        #[arg(long)]
        operator_pubkey: Option<PathBuf>,
        /// Boot firmware: `seabios` (default; Infomaniak is BIOS-only), `seabios-gpt` (legacy BIOS on a
        /// GPT disk — the dha-hosting box), or `uefi` (the rambutan Secure Boot loader path;
        /// OVMF-boot-proven, production substrate-gated).
        #[arg(long, value_parser = parse_firmware, default_value = "seabios")]
        firmware: orchard::deploy::build_image::Firmware,
        /// OPTIONAL cross-check (C3): assert the deploy substrate this build targets. The substrate is
        /// DERIVED from `--firmware` (seabios/seabios-gpt ⇒ `vps-kvm`, uefi ⇒ `bare-metal-uefi`); this
        /// flag can only AGREE or abort — a mismatch refuses naming both. Omit ⇒ the derivation stands.
        #[arg(long)]
        substrate: Option<String>,
        /// The box's network config baked into the boot-fs APPEND as `fb.net=<value>` (network
        /// spec C1) — e.g. `mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3`. One whitespace-free
        /// token. Omit ⇒ no `fb.net=` baked ⇒ the box diverts to rescue/link-only. `mode=dhcp`
        /// is the documented seam (build-A fail-closes it at bring-up).
        #[arg(long, value_parser = parse_net)]
        net: Option<String>,
        /// UEFI only (SB-loader plan): bake `SB_REQUIRED=true` into the rambutan loader so an SB-rung
        /// image refuses to run with Secure Boot disabled (fail closed). Sign it afterward with
        /// `deploy sign-sb` + enroll the matching PK/KEK/db. Omit ⇒ the SB-off rung (the loader runs
        /// unsigned on SB-off OVMF / rented UEFI). Ignored on SeaBIOS.
        #[arg(long)]
        secure_boot: bool,
        /// Operator-supplied service manifest (TOML; the §5.3 fail-closed schema). Omit ⇒ the pinned
        /// reference tenant (recipes), byte-identical to today's box. A non-recipes manifest builds +
                                                                                               
        /// escalating manifest is REFUSED at bake.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// os-update A/B v1 (§4i): the per-stream monotonic image serial baked into the rootfs +
        /// `.layout.toml`, the box's version-floor anti-rollback input. The operator OWNS the sequence
        /// (bump it whenever a ship supersedes — kernel OR any userspace/CVE change); the box refuses a
        /// pushed update whose version ≤ its floor. A committed constant (byte-reproducible). Omit ⇒ `0`
        /// (an unversioned dev/smoke build; a real fleet build passes an explicit, ratcheting serial).
        #[arg(long, default_value_t = 0)]
        image_version: u64,
        /// Hotswap v4: how a weights build anchors the model — `boot` (the dha fb.weights-*
        /// cmdline triple, the default) or `runtime` (NO cmdline; a Purpose::Weights-signed
        /// record baked at /persist/weights/current + the engine fb-weights setup prelude).
        #[arg(long, value_enum, default_value_t = WeightsAnchorArg::Boot)]
        weights_anchor: WeightsAnchorArg,
    },
                                                                                              
    /// sidecar) into a signed-ready, DETERMINISTIC persist ext4 image for
    /// `orchard prod --restore-from`. The image carries the box's persist identity
    /// (LABEL=persist, journal-less, pinned feature set) and is content-sized (bytes AND inodes,
    /// explicit -N) with the same first-boot grow the skeleton rides. Sign it afterward:
    /// `orchard sign-backup <out>`.
    #[command(display_order = 45)]
    RestoreImage {
        /// The daily `data-<ts>.tar.gz` (the fb-backup data leg).
        #[arg(long)]
        data: PathBuf,
        /// The daily `db-<ts>.sqlite` (the fb-backup db leg).
        #[arg(long)]
        db: PathBuf,
        /// Operator login pubkey staged at the skeleton authorized_keys path (validated
        /// derive-not-cat; the `prod --restore-from` preflight cross-checks the staged key
                                                
        #[arg(long)]
        operator_pubkey: PathBuf,
        /// Tenant root directory on persist (one safe path component).
        #[arg(long, default_value = "recipes")]
        root: String,
        /// The db's target path under <root>.
        #[arg(long, default_value = "recipes.db")]
        db_target: String,
        /// Explicit tenant owner `uid:gid` (strict u32:u32). Omit ⇒ derived from uniform tar
        /// entry owners; the assembler fails LOUD on ambiguity (I-R3-2).
        #[arg(long, value_parser = parse_db_owner)]
        db_owner: Option<(u32, u32)>,
        /// Output path for the persist image (e.g. `restore-<ts>.persist.img`).
        #[arg(long)]
        out: PathBuf,
        /// Pinned build-container image ref (the bake runs mke2fs in-container, no privilege).
        #[arg(long, default_value = "recipes-imgbuild:dev")]
        container_image: String,
        /// Print the FULL per-file staged manifest instead of the per-directory rollup (Component 8/8c).
        #[arg(long)]
        manifest_full: bool,
    },
    /// §9.5: assemble the signed-USB installer image from a built, `sign-sb`-signed runtime `.img`.
    /// Reads `--from` plus its `.layout.toml`/`.vmlinuz.signed`/`.initramfs` siblings, re-verifies
    /// `vendor/`, recomputes the box.img verity root hash, builds the 2nd (installer) rambutan loader
    /// and the ESP/ext4 USB partitions, then writes `recipes-installer-usb-<label>.{img,sha256}`
    /// beside the `--from` image. The installer loader is built `SB_REQUIRED` and UNSIGNED — db-sign
                                                                                                    
    /// the produced-bytes proof.
    #[command(display_order = 22)]
    BuildInstallerUsb {
        /// The built + `sign-sb`-signed runtime `.img` (its sidecars are derived from it).
        #[arg(long)]
        from: PathBuf,
        /// Optional whole-disk `fb.install-to` override baked into the installer cmdline; omit ⇒ the
        /// installer auto-selects the single eligible internal disk (fail-closed on 0/>1).
        #[arg(long, value_parser = parse_install_to)]
        install_to: Option<String>,
        /// Pinned build container (the 2nd loader build + the ESP/ext4 bakes run inside it).
        #[arg(long, default_value = "recipes-imgbuild:dev")]
        container_image: String,
    },
    /// §9.5: db-sign the installer loader inside a `build-installer-usb` image and splice it into the
                                                                                                     
    /// the USB's own `<base>.sha256`; does NOT touch the source runtime `.img`. Refuses a `db.crt`
    /// that doesn't match the committed `pinned-secure-boot-db.toml`. Enroll the matching PK/KEK/db,
    /// then boot the USB under enforcing Secure Boot.
    #[command(display_order = 43)]
    SignInstallerUsb {
        /// The `deploy build-installer-usb` output (`recipes-installer-usb-<label>.img`).
        #[arg(long)]
        img: PathBuf,
        /// Operator key set dir (default ~/.config/recipes-deploy/keys).
        #[arg(long)]
        keys_dir: Option<PathBuf>,
        /// Custody rung: `software` (db key on host) now; hardware rungs routed.
        #[arg(long, default_value = "software")]
        secure_boot: String,
        /// Pinned build-container image (sbsign + mtools run inside it).
        #[arg(long, default_value = "recipes-imgbuild:dev")]
        container_image: String,
    },
    /// Build (or boot a pre-built `--image`) the image in local QEMU/KVM and verify the runtime
    /// contract: dropbear accepts the operator pubkey, recipes answers, the rootfs is read-only
    /// (spec Phase-3 local smoke). Needs KVM + qemu-system-x86_64/veritysetup/ssh/curl/fakeroot/mke2fs.
    /// Verifies the NORMAL-boot contract ONLY — the rescue path (corrupt /persist → recovery-pubkey
    /// login) is covered by the `deploy_rescue_smoke` test, so this build path bakes no recovery pubkey.
    #[command(display_order = 21)]
    Dryrun {
        /// Leave the VM running after a successful verify (manual poking); prints the ssh command.
        #[arg(long)]
        keep_running: bool,
        /// Boot this pre-built `.img` (+ its sibling `.layout.toml`) instead of building — the fast
        /// operator path (a full build is ~14min). Absent ⇒ build first, per the spec.
        #[arg(long)]
        image: Option<PathBuf>,
        /// Deployment domain baked into the build (build path only). RFC-1123 validated.
        #[arg(long, default_value = "box.test", value_parser = parse_domain)]
        domain: String,
        /// Build from a dirty git tree (build path only; a local dev smoke usually is dirty).
        #[arg(long)]
        allow_dirty: bool,
        /// Guest RAM in MiB. The 1024 default suits a reference box; a WEIGHTS box needs enough for
        /// its resource domain plus box-init's 512 MiB reserve, or box-init correctly refuses the
        /// domain and reboots ("Σ + reserve exceeds MemTotal") — which reads as a boot failure but
                                                                                               
        #[arg(long, default_value_t = 1024)]
        memory_mb: u32,
    },
    /// Read-only readiness check: "am I ready to build/deploy?" ADVISORY — always exits 0, never a
    /// gate; every unmet check names its cure; a probe that cannot run reports "could not check".
    /// `--for <verb>` scopes the report to that verb's prerequisites (Component 2 / orchard-UX).
    #[command(display_order = 30)]
    Doctor {
        /// Scope to one verb's prerequisites (build|dryrun|prod|boot-gate). Omit ⇒ the full report.
        #[arg(long = "for", value_parser = ["build", "dryrun", "prod", "boot-gate"])]
        for_verb: Option<String>,
        /// The image to check sidecar-completeness against (prod scope).
        #[arg(long)]
        image: Option<PathBuf>,
        /// Operator key set dir (default ~/.config/recipes-deploy/keys).
        #[arg(long)]
        keys_dir: Option<PathBuf>,
    },
                                                                                          
                                                                                                   
    /// verify → kexec the installer → reconnect pinned to the image-DERIVED runtime host key →
    /// crypto-identity verify. DESTRUCTIVE: erases the target's WHOLE disk.
    #[command(display_order = 40)]
    Prod {
        /// Target IP (or lowercase hostname) of the provisioning Debian.
        ip: String,
        /// A named box's profile (`--profile boxes/<name>.toml`): supplies stable identity VALUES
        /// (paths + public pins), never intent. Relaxes the clap-required `--pubkey`/`--ssh-identity`
        /// (a fail-closed post-merge check re-enforces them); the wipe intent + typed target stay
                                                                                                      
        #[arg(long)]
        profile: Option<PathBuf>,
        /// The operator's box-login PUBKEY. Preflight-verified against the image's baked
        /// `<stem>.operator-pubkey.fpr` sidecar — a key mismatch aborts before anything runs.
        /// Required unless a `--profile` supplies `operator_pubkey` (re-enforced fail-closed post-merge).
        #[arg(long, required_unless_present = "profile")]
        pubkey: Option<PathBuf>,
        /// Deploy this prebuilt `.img` (its sidecars + vmlinuz/initramfs must sit beside it).
        /// Absent ⇒ build inline first (requires --domain, exactly like `deploy build`
                                                                             
        #[arg(long)]
        image: Option<PathBuf>,
        /// Provisioning-leg ssh PRIVATE key (the root key the provider/cloud-init injected).
        /// Required unless a `--profile` supplies `ssh_identity` (re-enforced fail-closed post-merge).
        #[arg(long, required_unless_present = "profile")]
        ssh_identity: Option<PathBuf>,
        /// Reconnect-leg ssh PRIVATE key. Default: --pubkey minus its .pub suffix — the
                                                        
        #[arg(long)]
        box_login_identity: Option<PathBuf>,
        /// Target sshd port. Both legs ride it — the box reuses 22 after install. Flag > profile >
        /// builtin 22 (the default is applied AFTER the merge, so a profile `port` isn't shadowed).
        #[arg(long)]
        port: Option<u16>,
        /// Leg-A pin: the provisioning host key's SHA256:… fingerprint (`ssh-keygen -lf` form).
        /// Without it, a TTY gets an explicit confirm; non-interactive runs FAIL CLOSED.
        #[arg(long)]
        host_fingerprint: Option<String>,
        /// Leg-A alternative: a pre-populated known_hosts file, used as-is. Conflicts with
        /// --host-fingerprint (the file IS the pin source; passing both previously ignored the
                                                                  
        #[arg(long, conflicts_with = "host_fingerprint")]
        known_hosts: Option<PathBuf>,
        /// Leg-B cross-check: the expected runtime host-key fingerprint (from
        /// `derive-rescue-host-keys --image <img> --print-fingerprint`). The ceremony always
        /// derives the pin from the image itself; this flag guards against the WRONG image.
        #[arg(long)]
        runtime_hostkey_fingerprint: Option<String>,
        /// Disk-backed staging dir on the target's / partition (never tmpfs — the installer
        /// reads the .img from the old root after kexec).
        #[arg(long, default_value = "/var/tmp/recipes-deploy")]
        image_stage_dir: String,
        /// Confirm the WHOLE-DISK erase (required; constructs the wipe token).
        #[arg(long)]
        wipe_confirmed: bool,
        /// How long to wait for the installed box to come up (install + reboot + first boot).
        #[arg(long, default_value_t = 600)]
        reconnect_timeout_secs: u64,
        /// Task 4.3: restore the box's /persist from this operator-assembled, SIGNED persist
        /// image (`orchard restore-image` output + `orchard sign-backup` sibling `.sig`). Runs
        /// the five-leg local preflight (sig-exists → verify+ctr-print → identity → staged-key
        /// cross-check → name guards) BEFORE any remote action, stages image+.sig beside the
        /// `.img`, and threads `fb.restore-from` (+ `fb.min-ctr`) to the installer.
        #[arg(long)]
        restore_from: Option<PathBuf>,
        /// Opt-in anti-rollback floor: refuse a restore bundle whose delegation monotonic_ctr is
        /// below this (the value a previous ceremony PRINTED). Enforced on the box inside its
        /// quince verify.
        #[arg(long, requires = "restore_from")]
        restore_min_ctr: Option<u64>,
        /// Off-host artifact-signing ROOT pin (64 hex). When set, preflight verifies the
        /// `.sig` bundles against THIS pin instead of `<keys-dir>/artifact-root.pub` — the
                                                                                                 
        #[arg(long, value_parser = parse_artifact_pin)]
        artifact_pin: Option<[u8; 32]>,
                                                                                            
        /// staging window intersects the grown root), run the consent-gated offline shrink so
        /// the window lands in unpartitioned space. Its own token — --wipe-confirmed does not
                            
        #[arg(long)]
        reclaim_tail: bool,
                                                                               
        #[arg(long)]
        reclaim_timeout_secs: Option<u64>,
                                                                                                 
        /// Deployment domain (inline build only).
        #[arg(long, value_parser = parse_domain)]
        domain: Option<String>,
        /// Operator key set dir (inline build only; default ~/.config/recipes-deploy/keys).
        #[arg(long)]
        keys_dir: Option<PathBuf>,
        /// Output dir for the inline-built `.img` triple. Flag > profile > builtin /tmp (default
        /// applied after the merge).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Pinned kernel source tree (inline build only).
        #[arg(long)]
        ksrc: Option<PathBuf>,
        /// Pinned syslinux source tarball (inline build only).
        #[arg(long)]
        syslinux_src: Option<PathBuf>,
        /// Pinned build-container image ref (inline build only).
        #[arg(long, default_value = "recipes-imgbuild:dev")]
        container_image: String,
        /// Build from a dirty git tree (inline build only).
        #[arg(long)]
        allow_dirty: bool,
        /// Recovery pubkey baked into the rescue dropbear (inline build only).
        #[arg(long)]
        recovery_pubkey: Option<PathBuf>,
        /// Network config baked as `fb.net=<value>` (inline build only).
        #[arg(long, value_parser = parse_net)]
        net: Option<String>,
    },
    /// D-2 standalone: prepare a default-provisioned VPS for `deploy prod` — the consent-gated
    /// offline shrink of the grown root, so the staging window lands in unpartitioned space
                                                                                         
    #[command(display_order = 32, name = "reclaim-tail")]
    ReclaimTail {
        /// Target IP (or lowercase hostname) of the provisioning Debian.
        ip: String,
                                                                                            
        #[arg(long)]
        image: PathBuf,
        /// Provisioning-leg ssh PRIVATE key.
        #[arg(long)]
        ssh_identity: PathBuf,
        /// Leg-A pin: the provisioning host key's SHA256:… fingerprint. Without it, a TTY gets
        /// an explicit confirm; non-interactive runs FAIL CLOSED.
        #[arg(long)]
        host_fingerprint: Option<String>,
        /// Target sshd port.
        #[arg(long, default_value_t = 22)]
        port: u16,
                                                                                  
        #[arg(long)]
        confirmed: bool,
                                                                               
        #[arg(long)]
        reclaim_timeout_secs: Option<u64>,
    },
    /// Regenerate crates/image-builder/pinned-apks.toml from apk-world.toml: resolve the runtime
    /// closure + pin the build-inputs (verify-before-record). Runs apk in the pinned build
    /// container; commit the resulting diff.
    #[command(display_order = 51)]
    RefreshApkLock {
        /// The pinned build-container image ref the apk closure resolution runs in.
        #[arg(long, default_value = "recipes-imgbuild:dev")]
        container_image: String,
    },
    /// Propagate the central pins.toml into the format-locked files (rust-toolchain.toml +
    /// the image-builder Containerfile FROM). Run after editing pins.toml. `--check` only verifies
    /// (fails closed on drift) — the same gate make verify runs via tests/pins_drift.rs.
    #[command(display_order = 52)]
    SyncPins {
        /// Verify-only: fail closed on drift instead of rewriting.
        #[arg(long)]
        check: bool,
    },
                                                                                              
    /// artifact store against consume-pins.toml + unpack into vendor/. Fail-closed on mismatch/absence.
    #[command(display_order = 12)]
    Vendor {
        /// The artifact store dir (default: $FRUIT_ARTIFACT_STORE, else <repo>/../artifact-store).
        #[arg(long)]
        store: Option<PathBuf>,
    },
                                                                                               
    /// fetch-*.sh). This is the NETWORK step, sited next to `vendor`; the bake re-verifies both
    /// tarballs at consumption, so `orchard build` stays fully offline.
    #[command(display_order = 11)]
    Prime {
        /// Staging dir for the kernel `.tar.xz` (default /tmp/recipes-kbuild).
        #[arg(long, default_value = orchard::deploy::build_image::DEFAULT_KBUILD_DIR)]
        kbuild_dir: PathBuf,
        /// Staging dir for the syslinux `.tar.xz` (default /tmp/recipes-syslinux).
        #[arg(long, default_value = orchard::deploy::build_image::DEFAULT_SYSLINUX_DIR)]
        syslinux_dir: PathBuf,
    },
    /// The pin-store tool (`market`): `verify` (the always-on, fail-closed `make verify` gate that
    /// consolidates the sha256 supply-chain pin checks) + `upgrade` (the staged, all-or-nothing
    /// orchestrator of a pin bump). Spec: 2026-06-22-pin-store-market-design.md.
    #[command(display_order = 50)]
    Market {
        #[command(subcommand)]
        sub: MarketSub,
    },
}

/// `market <sub>` — the pin-store tool's two subcommands.
#[derive(clap::Subcommand)]
enum MarketSub {
    /// Verify the pin store (read-only, fail-closed) — wired into `make verify`.
    Verify {
        /// Also run the thorough cert-trail audit (off the hot path).
        #[arg(long)]
        certs: bool,
        /// Also hash each artifact-store binary against its pin.
        #[arg(long)]
        all: bool,
        /// Permit a named owning repo to be absent (explicit, reviewed; the partial-checkout dev loop).
        /// Use `--allow-missing cert-trail` when the cookbook launchpad (the §3a-7 trail) isn't present.
        #[arg(long = "allow-missing", value_name = "REPO")]
        allow_missing: Vec<String>,
        /// Run ONLY the §3a-7 cert-presence leg against the live trail (the retrofit dry-run): report
        /// every bare-quoted live pin, fail-closed. Drives the cert-trail retrofit before §3a-7 goes hot.
        #[arg(long = "cert-presence")]
        cert_presence: bool,
    },
    /// Report apk pin drift vs the mirror (ADVISORY, read-only, fail-soft — never a gate; `market
    /// verify` stays the fail-closed gate). A GONE pin has aged off dl-cdn: `orchard build` will
    /// 404 on it until `market upgrade --apks` re-pins.
    Outdated {
        /// Exit non-zero when drift is found — a best-effort CI/cron NAG, not a security gate (an
        /// unreachable mirror still exits 0). Bare `--exit-drift` = nag on a GONE pin; `=any` =
        /// nag on any non-current pin.
        #[arg(long = "exit-drift", value_name = "WHEN", num_args = 0..=1, default_missing_value = "gone")]
        exit_drift: Option<String>,
        /// Classify the whole lock (the runtime closure too), not just the build_input 404 drivers.
        #[arg(long = "all-packages")]
        all_packages: bool,
    },
    /// Re-derive ONE target of the pin store (on-demand, MUTATING; commits ONLY on explicit consent —
    /// an interactive `y`/`e` or `--commit`, else it prints the ready `git commit`; NEVER silently,
    /// never a sibling repo). Pick exactly one of the targets below.
    Upgrade {
        /// A source-drop crate by its consume-pins `*-src` key (owning-repo publish → re-vendor → re-pin).
        #[arg(long)]
        source: Option<String>,
        /// A single binary by its consume-pins key (per-binary build → re-publish → re-pin that entry).
        #[arg(long)]
        binary: Option<String>,
        /// A single `kind=config` artifact by its consume-pins key — a config-subset re-pin (D8): the
        /// owning repo's config source must be git-tracked; no `--build-dir`, no whole-repo churn.
        #[arg(long)]
        config: Option<String>,
        /// The apk closure (re-resolve + dual-verify; NO binary rebuild).
        #[arg(long)]
        apks: bool,
        /// A new kernel version (fetch the signed sum → pins.toml → sync-pins).
        #[arg(long, value_name = "VERSION")]
        kernel: Option<String>,
        /// A new rust toolchain version (Component C): PGP-verify the release manifest (keyring/rust-lang),
        /// re-pin the toolchain, rebuild the build container by digest, recompile + re-pin ALL binaries.
        #[arg(long, value_name = "VERSION")]
        rust: Option<String>,
        /// The whole store (composes --rust ∪ --apks ∪ the whole-store re-pin).
        #[arg(long)]
        all: bool,
        /// Preview the orchestration plan WITHOUT executing — stage nothing, swap nothing (Task 10's preview).
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// The pinned build-container ref for an `--apks` closure re-resolution (required only for `--apks`).
        #[arg(long = "container-image", value_name = "IMAGE")]
        container_image: Option<String>,
        /// The build-only handoff dir holding the pre-built binaries (required for `--binary`; produce it with
        /// the owning repo's `build-only.sh`). grocer reads + ELF-asserts each binary from here.
        #[arg(long = "build-dir", value_name = "DIR")]
        build_dir: Option<PathBuf>,
                                                                                                    
        /// swapped paths with the composed message, no prompt. `--yes` = alias. This is the ONLY
        /// non-interactive commit path — a headless run without it never commits.
        #[arg(long, alias = "yes", conflicts_with = "no_commit")]
        commit: bool,
        /// Never commit — print the ready `git commit` command instead (an explicit opt-out beats
        /// everything; combining it with `--commit` is a usage error). The re-pin itself still runs.
        #[arg(long = "no-commit")]
        no_commit: bool,
    },
                                                                                          
    /// reference scan + advisory/consent-gated cleanup. Never a `market verify` leg.
    Store {
        #[command(subcommand)]
        sub: StoreSub,
    },
}

/// `market store <sub>`.
#[derive(clap::Subcommand)]
enum StoreSub {
    /// The reference scan report: referenced/unreferenced revisions, aliases, foreign entries,
    /// and any refusals (a prune would refuse on these). Read-only, always exit 0. Healthy classes
    /// collapse to counts; `--all` itemizes everything; `--full` shows the 64-hex digests.
    Status {
        /// Itemize the healthy bulk too (referenced revisions + aliases), not just the anomalies.
        #[arg(long)]
        all: bool,
        /// Show full 64-hex digests instead of the 12-hex abbreviation.
        #[arg(long)]
        full: bool,
    },
    /// Delete unreferenced `<key>@<sha>` revisions (consent-gated: the flag-less default IS the
    /// dry run — it only PRINTS candidates). Refuses outright, deleting nothing, if the
    /// reference scan is incomplete (any refusal in `market store status`).
    Prune {
        #[arg(long)]
        delete: bool,
        /// Show full 64-hex digests instead of the 12-hex abbreviation.
        #[arg(long)]
        full: bool,
    },
    /// Hardlink every legacy flat alias to its `<key>@sha256(bytes)` revision name (idempotent;
    /// keeps the flats — the dual-write transition is unaffected).
    Migrate,
}

/// Validate the `--subject` operator-distinguisher (becomes the OU). Reject the
/// DN separator + control chars so a value can't inject extra RDNs.
/// `orchard build --weights-anchor`: how a weights build anchors the model (hotswap v4 §7).
#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum WeightsAnchorArg {
    /// The dha boot-anchored shape (fb.weights-* cmdline). The pre-v4 default.
    Boot,
    /// Hotswap v4: runtime dm-verity from the persisted signed record (no fb.weights-* token).
    Runtime,
}

/// `orchard redelegate --purpose`: which update-path delegation(s) to mint.
#[derive(Clone, Copy, clap::ValueEnum)]
enum RedelegatePurposeArg {
    /// Both update-path delegations (the default).
    All,
    /// Purpose::UpdateImage only.
    UpdateImage,
    /// Purpose::RootHash only.
    RootHash,
    /// Purpose::Weights only (the hotswap-model manifest purpose — mints the delegation a
    /// pre-hotswap key set is missing).
    Weights,
}

fn parse_subject_ou(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("subject distinguisher is empty".into());
    }
    if s.len() > 64 {
        return Err("subject distinguisher exceeds 64 chars (X.509 OU upper bound)".into());
    }
    if s.contains('/') {
        return Err("subject distinguisher must not contain '/'".into());
    }
    if s.chars().any(|c| c.is_control()) {
        return Err("subject distinguisher contains a control character".into());
    }
    Ok(s.to_string())
}

/// `--domain` value_parser (M-2): RFC-1123-validate the operator domain before it reaches the box's
/// haproxy.cfg (mirrors `parse_subject_ou`; the load-bearing check is in `build_image`, since a
/// direct lib caller bypasses the CLI).
/// Parse `--db-owner uid:gid` — strict numeric u32 halves (the owner is applied numerically
/// in-container; names would depend on the container's passwd and are refused here).
fn parse_db_owner(s: &str) -> Result<(u32, u32), String> {
    let (u, g) = s
        .split_once(':')
        .ok_or_else(|| "expected uid:gid (e.g. 100:100)".to_string())?;
    let uid = u
        .parse::<u32>()
        .map_err(|_| format!("uid {u:?} is not a u32"))?;
    let gid = g
        .parse::<u32>()
        .map_err(|_| format!("gid {g:?} is not a u32"))?;
    Ok((uid, gid))
}

fn parse_domain(s: &str) -> Result<String, String> {
    orchard::deploy::build_image::validate_domain(s)
        .map(|()| s.to_string())
        .map_err(|e| e.to_string())
}

/// `--artifact-pin` value_parser: a 64-hex-char ed25519 root pubkey (the off-host
/// operator pin, for verifying artifact `.sig` bundles when it is held off the
                                                                            
fn parse_artifact_pin(s: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(s.trim()).map_err(|_| "artifact-pin must be 64 hex chars".to_string())?;
    <[u8; 32]>::try_from(raw)
        .map_err(|_| "artifact-pin must be 32 bytes (64 hex chars)".to_string())
}

/// `--firmware` value_parser: parse the `seabios`/`seabios-gpt`/`uefi` wire token (Firmware: FromStr).
/// All build a real `.img`; `seabios-gpt` is legacy BIOS on a GPT disk (the dha-hosting box); `uefi`
/// builds the rambutan loader path (production-substrate-gated).
fn parse_firmware(s: &str) -> Result<orchard::deploy::build_image::Firmware, String> {
    s.parse()
}

/// `--net` value_parser (early feedback): the `fb.net=` cmdline VALUE must be one whitespace-free
/// `mode=…` token (network spec C1). `build_image` re-validates fail-closed (the load-bearing layer);
/// box-init's `parse_net` does the full grammar/address-semantics check at boot.
fn parse_net(s: &str) -> Result<String, String> {
    orchard::deploy::build_image::validate_net(s)
}

                                                                                                      
/// the SB-signed installer cmdline (`fb.install-to=<dev>`), so it must be one bare device token —
/// `[a-z0-9]+`, no whitespace/quote that could smuggle a second cmdline token. Early CLI feedback +
/// the build-side belt; the init's `valid_install_to_dev` re-validates disk-class + whole-disk at boot,
/// and `render_installer_cmdline` re-asserts this same shape fail-closed.
fn parse_install_to(s: &str) -> Result<String, String> {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        Ok(s.to_string())
    } else {
        Err(format!(
            "fb.install-to must be one bare lowercase-alphanumeric whole-disk device name \
             (e.g. nvme0n1, sda), got {s:?}"
        ))
    }
}

fn default_keys_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("recipes-deploy").join("keys")
}

                                                                                 
/// the inline `deploy prod` build both call this, so they can't diverge. Signs the
/// three box-consumed artifacts when an artifact key set is present, else prints
/// the un-adopted/UNSIGNED notice.
fn report_artifact_signing(
    keys_dir: &std::path::Path,
    img: &std::path::Path,
    vmlinuz: &std::path::Path,
    initramfs: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
                                                                                    
                                                                               
                                                                                
                                                                             
    let pin_path = orchard::deploy::pinned_artifact_root_path(&repo_root()?);
    match orchard::deploy::artifact_sign::sign_build_outputs(
        keys_dir, &pin_path, img, vmlinuz, initramfs,
    )? {
        Some(sigs) => {
            for s in sigs {
                println!("  signed → {}", s.display());
            }
        }
        None => println!(
            "  artifact signing: no artifact key set in {} \
             (run `deploy generate-keys --artifact-signing …`) — built UNSIGNED",
            keys_dir.display()
        ),
    }
    Ok(())
}

fn run_deploy(cmd: OrchardCmd) -> Result<(), Box<dyn std::error::Error>> {
    use orchard::deploy::keys::{self, GenMode, GenerateKeysOpts, ImportPaths};
    match cmd {
        OrchardCmd::DeriveRescueOffline {
            image,
            print_fingerprint,
            pubkey,
            hostname,
        } => orchard::oneshots_offline::derive_rescue_offline(
            &image,
            print_fingerprint,
            pubkey,
            hostname.as_deref(),
        ),
        OrchardCmd::GenerateKeys {
            force,
            output_dir,
            subject,
            regenerate_master_key,
            artifact_signing,
            delegation_window_days,
            artifact_keys_only,
            secure_boot,
            sb_rsa,
            sb_db_fingerprint_path,
            signing_key_token,
            import_image_signing,
            import_image_signing_cert,
            import_signing_ca,
            import_signing_ca_cert,
            import_ima,
            import_ima_cert,
        } => {
                                                                                        
                                                         
            if let Some(rung_raw) = secure_boot {
                use orchard::deploy::secure_boot_keys::{
                    SbRsaBits, SecureBootKeysOpts, SecureBootRung, generate_secure_boot_keys,
                };
                let rung = SecureBootRung::parse(&rung_raw).ok_or_else(|| {
                    format!("--secure-boot {rung_raw:?}: want software | one-signer | two-signers")
                })?;
                let bits = SbRsaBits::parse(&sb_rsa)
                    .ok_or_else(|| format!("--sb-rsa {sb_rsa:?}: want 3072 | 2048"))?;
                let db_fingerprint_path = match sb_db_fingerprint_path {
                    Some(p) => p,
                    None => repo_sb_db_fingerprint_path()?,
                };
                let opts = SecureBootKeysOpts {
                    keys_dir: output_dir.unwrap_or_else(default_keys_dir),
                    db_fingerprint_path,
                    rung,
                    bits,
                    force,
                    subject_ou: subject,
                };
                generate_secure_boot_keys(&opts)?;
                println!(
                    "deploy generate-keys --secure-boot: wrote the PK/KEK/db family to \
                     {}/secure-boot + pinned the PK/KEK/db fingerprints into {}",
                    opts.keys_dir.display(),
                    opts.db_fingerprint_path.display()
                );
                                                                                                     
                                                                                                       
                print!(
                    "{}",
                    orchard::deploy::epilogue::next_steps(
                        &orchard::deploy::epilogue::generate_keys_secure_boot_next_steps(
                            &opts.db_fingerprint_path
                        )
                    )
                );
                return Ok(());
            }
            let mode = if let Some(slot) = signing_key_token {
                GenMode::Token { slot }
            } else if let Some(is_key) = import_image_signing {
                                                                            
                GenMode::Import(ImportPaths {
                    image_signing_key: is_key,
                    image_signing_cert: import_image_signing_cert.unwrap(),
                    signing_ca_key: import_signing_ca.unwrap(),
                    signing_ca_cert: import_signing_ca_cert.unwrap(),
                    ima_key: import_ima.unwrap(),
                    ima_cert: import_ima_cert.unwrap(),
                })
            } else {
                GenMode::Generate
            };
                                                                           
                                                                                    
            let fingerprints_path = if regenerate_master_key {
                PathBuf::new()
            } else {
                repo_fingerprints_path()?
            };
            let opts = GenerateKeysOpts {
                output_dir: output_dir.unwrap_or_else(default_keys_dir),
                subject_ou: subject,
                force,
                mode,
                regenerate_master_key,
                fingerprints_path,
            };

                                                                                    
                                                                                    
                                                                                   
            if let Some(rung) = artifact_signing {
                use orchard::deploy::artifact_keys;

                                                                                   
                                                                                       
                                                                                     
                                                                              
                if artifact_keys_only {
                                                                                           
                                                                                          
                                                                                         
                                                                                             
                                                    
                    orchard::deploy::dumpable::set_process_non_dumpable().map_err(|e| {
                        format!(
                            "generate-keys (in-container): refusing to mint seeds in a \
                             dumpable process (PR_SET_DUMPABLE failed): {e}"
                        )
                    })?;
                                                                                        
                                                                                              
                                                                                          
                                                                                         
                    match rung.as_str() {
                        "software" => {
                            artifact_keys::generate_artifact_keys(
                                &opts.output_dir,
                                delegation_window_days,
                                force,
                                artifact_keys::Custody::Raw,
                            )?;
                        }
                        "docker" => {
                            let pass = orchard::deploy::tty::read_new_passphrase(
                                "Set a passphrase to wrap the artifact-signing keys: ",
                                "Confirm passphrase: ",
                            )?;
                            artifact_keys::generate_artifact_keys(
                                &opts.output_dir,
                                delegation_window_days,
                                force,
                                artifact_keys::Custody::Wrapped { passphrase: &pass },
                            )?;
                        }
                        other => {
                            return Err(format!(
                                "--artifact-keys-only supports the software|docker rungs, not {other:?}"
                            )
                            .into());
                        }
                    }
                    println!(
                        "deploy generate-keys: artifact keys minted to {} \
                         (keys-only; the committed pin is written host-side)",
                        opts.output_dir.display()
                    );
                    return Ok(());
                }

                if !keys::signing_set_exists(&opts.output_dir) {
                    keys::generate_keys(&opts)?;                                     
                }
                let pin_path =
                    repo_fingerprints_path()?.with_file_name("pinned-artifact-root.toml");
                match rung.as_str() {
                    "software" => {
                        let root = artifact_keys::provision_software_rung(
                            &opts.output_dir,
                            &pin_path,
                            delegation_window_days,
                            force,
                        )?;
                        println!(
                            "deploy generate-keys: artifact-signing `software` rung — \
                             root pin ed25519:{} → {}",
                            hex::encode(root),
                            pin_path.display()
                        );
                    }
                    "docker" => {
                                                                                   
                                                                                           
                                                                                           
                                                                   
                                                                                       
                                                                                          
                                                                        
                        let image_id =
                            artifact_keys::resolve_image_id(artifact_keys::IMGBUILD_TAG)?;
                        eprintln!(
                            "resolved {} → {image_id} (this operation runs by that id)",
                            artifact_keys::IMGBUILD_TAG
                        );
                        let argv = artifact_keys::docker_keygen_argv(
                            &image_id,
                            &opts.output_dir,
                            delegation_window_days,
                            force,
                        )?;
                        eprintln!(
                            "artifact keygen in the pinned container: {}",
                            argv.join(" ")
                        );
                        let status = std::process::Command::new(&argv[0])
                            .args(&argv[1..])
                            .status()?;
                        if !status.success() {
                            return Err(format!("docker artifact keygen exited {status}").into());
                        }
                                                                                             
                                                                                            
                                                                                                  
                        let root_pub = artifact_keys::read_root_pub(&opts.output_dir)?;
                        orchard::deploy::fingerprints::set_artifact_root_pin(&pin_path, &root_pub)?;
                        println!(
                            "deploy generate-keys: artifact-signing `docker` rung — keys minted \
                             in-container (passphrase-wrapped at rest); root pin ed25519:{} → {} \
                             (written host-side)",
                            hex::encode(root_pub),
                            pin_path.display()
                        );
                    }
                    other => {
                        return Err(keys::DeployKeyError::HardwareRungNotYetAvailable(
                            other.to_string(),
                        )
                        .into());
                    }
                }
                print!(
                    "{}",
                    orchard::deploy::epilogue::next_steps(
                        &orchard::deploy::epilogue::generate_keys_next_steps(),
                    )
                );
                return Ok(());
            }

            keys::generate_keys(&opts)?;
            if regenerate_master_key {
                println!(
                    "deploy generate-keys: rotated rescue-seed-master.key in {}",
                    opts.output_dir.display()
                );
            } else {
                println!(
                    "deploy generate-keys: wrote key set to {} + fingerprints to {}",
                    opts.output_dir.display(),
                    opts.fingerprints_path.display()
                );
            }
            print!(
                "{}",
                orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::generate_keys_next_steps(),
                )
            );
            Ok(())
        }
        OrchardCmd::SignSb {
            img,
            keys_dir,
            secure_boot,
            container_image,
        } => {
            use orchard::deploy::secure_boot_keys::SecureBootRung;
            use orchard::deploy::sign_sb::{SignSbOpts, sign_sb};
            let rung = SecureBootRung::parse(&secure_boot).ok_or_else(|| {
                format!("--secure-boot {secure_boot:?}: want software | one-signer | two-signers")
            })?;
            let opts = SignSbOpts {
                img,
                keys_dir: keys_dir.unwrap_or_else(default_keys_dir),
                rung,
                container_image,
                db_fingerprint_path: repo_sb_db_fingerprint_path()?,
            };
            sign_sb(&opts)?;
            println!(
                "deploy sign-sb: db-signed loader+kernel spliced into {} (ESP), signed-PE \
                 sidecars written, .sha256 recomputed. NOTE: the operator ed25519 .img \
                 signature is the documented un-wired forward-debt — once wired it signs \
                 this post-splice image.",
                opts.img.display()
            );
            print!(
                "{}",
                orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::sign_sb_next_steps(&opts.img),
                )
            );
            Ok(())
        }
        OrchardCmd::BuildInstallerUsb {
            from,
            install_to,
            container_image,
        } => {
            use orchard::deploy::installer_usb_cmd::{InstallerUsbCliOpts, build_installer_usb};
            let opts = InstallerUsbCliOpts {
                from,
                install_to,
                container_image,
                repo_root: repo_root()?,
            };
            let out = build_installer_usb(&opts)?;
            println!(
                "deploy build-installer-usb: wrote {} (+ {}). The installer loader is UNSIGNED — \
                 run `deploy sign-installer-usb` to db-sign + splice it before enrolling/booting.",
                out.img.display(),
                out.sha256.display()
            );
            Ok(())
        }
        OrchardCmd::SignInstallerUsb {
            img,
            keys_dir,
            secure_boot,
            container_image,
        } => {
            use orchard::deploy::secure_boot_keys::SecureBootRung;
            use orchard::deploy::sign_installer_usb::{SignInstallerUsbOpts, sign_installer_usb};
            let rung = SecureBootRung::parse(&secure_boot).ok_or_else(|| {
                format!("--secure-boot {secure_boot:?}: want software | one-signer | two-signers")
            })?;
            let opts = SignInstallerUsbOpts {
                usb_img: img,
                keys_dir: keys_dir.unwrap_or_else(default_keys_dir),
                rung,
                container_image,
                db_fingerprint_path: repo_sb_db_fingerprint_path()?,
            };
            sign_installer_usb(&opts)?;
            println!(
                "deploy sign-installer-usb: db-signed installer loader spliced into {} (USB ESP), \
                 signed-loader sidecar written, .sha256 recomputed. The kernel was already signed at \
                 sign-sb time; enroll the matching PK/KEK/db, then boot the USB under enforcing SB.",
                opts.usb_img.display()
            );
            Ok(())
        }
        OrchardCmd::UpdateCertFingerprints {
            image_signing,
            signing_ca,
            ima,
        } => {
            use orchard::deploy::fingerprints::{CertFingerprintUpdate, update_cert_fingerprints};
            let toml_path = repo_fingerprints_path()?;
            update_cert_fingerprints(
                &toml_path,
                &CertFingerprintUpdate {
                    image_signing,
                    signing_ca,
                    ima,
                },
            )?;
            println!(
                "deploy update-cert-fingerprints: updated {}",
                toml_path.display()
            );
            Ok(())
        }
        OrchardCmd::Redelegate {
            keys_dir,
            purpose,
            window_days,
        } => {
            use dragonfruit::Purpose;
            use orchard::deploy::keys::DeployKeyError;
            use orchard::deploy::redelegate::redelegate;
            let keys_dir = keys_dir.unwrap_or_else(default_keys_dir);
            let purposes: &[Purpose] = match purpose {
                RedelegatePurposeArg::All => &[Purpose::UpdateImage, Purpose::RootHash],
                RedelegatePurposeArg::UpdateImage => &[Purpose::UpdateImage],
                RedelegatePurposeArg::RootHash => &[Purpose::RootHash],
                RedelegatePurposeArg::Weights => &[Purpose::Weights],
            };
                                                                                       
                                                                                    
                                                                                        
                                                                                        
            let minted = match redelegate(&keys_dir, purposes, window_days, None) {
                Ok(minted) => minted,
                Err(DeployKeyError::Passphrase { .. }) => {
                    let pass = orchard::deploy::tty::read_passphrase(
                        "Passphrase for the wrapped artifact keys: ",
                    )?;
                    redelegate(&keys_dir, purposes, window_days, Some(&pass))?
                }
                Err(e) => return Err(format!("redelegate: {e}").into()),
            };
            for m in &minted {
                println!(
                    "orchard redelegate: minted {:?} delegation -> {} \
                     (monotonic_ctr={}, window {window_days}d)",
                    m.purpose,
                    m.path.display(),
                    m.monotonic_ctr
                );
            }
            println!(
                "orchard redelegate: box trust anchor UNCHANGED (no rebake owed). \
                 next: orchard build (bakes min_delegation_ctr from the UpdateImage \
                 delegation) / orchard update"
            );
            Ok(())
        }
        OrchardCmd::Update {
            host,
            image,
            keys_dir,
            identity,
            port,
            confirmed,
            host_fingerprint,
        } => {
            use orchard::deploy::host_pins::HostPinOpts;
            use orchard::deploy::update::{
                Authorize, CeremonyOpts, SshUpdateOps, prepare_local_image, run_ceremony,
            };
            let keys_dir = keys_dir.unwrap_or_else(default_keys_dir);
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
                                                                                             
                                                                                               
                                                                                          
                                                                                            
                                            
            let pin_path = repo_root()
                .map(|r| orchard::deploy::pinned_artifact_root_path(&r))
                .unwrap_or_else(|_| keys_dir.join("no-committed-pin"));
                                                                                                         
                                                         
            let prepared = prepare_local_image(&image, &keys_dir)?;
            let pin_dir = default_keys_dir()
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("host-pins");
                                                                                                   
                                                                                                      
                                                                                                     
                                  
            let ops = SshUpdateOps::new(host.clone(), port, identity, is_tty)
                .with_post_flip_key(prepared.post_flip_hostkey.clone());
            let cer = CeremonyOpts {
                host: &host,
                keys_dir: &keys_dir,
                authorize: if confirmed {
                    Authorize::Confirmed
                } else {
                    Authorize::Interactive
                },
                host_pin: HostPinOpts {
                    host_fingerprint: host_fingerprint.as_deref(),
                    is_tty,
                    pin_dir: &pin_dir,
                },
            };
            let outcome = run_ceremony(&prepared, &pin_path, &cer, &ops)?;
            let orchard::deploy::update::CeremonyOutcome { report, pin } = &outcome;
            println!("orchard update: {}", report.summary());
            match pin {
                orchard::deploy::update::PinAction::Superseded { to } => println!(
                    "orchard update: host pin superseded to the image-derived runtime key {to} \
                     (the old pin is archived beside the store)"
                ),
                orchard::deploy::update::PinAction::SupersedeFailed { detail } => println!(
                    "orchard update: WARNING — committed, but the host pin could not be rotated \
                     ({detail}); the next contact will refuse against the stale pin until resolved \
                     by hand (re-pin to the pushed image's derived fingerprint)"
                ),
                orchard::deploy::update::PinAction::Unchanged => {}
            }
                                                                                                       
                                                                                                      
                                                                                                    
                                                                                                   
                                                                                                    
            if outcome.is_success() {
                Ok(())
            } else {
                Err(outcome.exit_reason().into())
            }
        }
        OrchardCmd::DeployModel {
            host,
            model,
            keys_dir,
            identity,
            port,
            container_image,
            confirmed,
            host_fingerprint,
        } => {
            use orchard::deploy::deploy_model::{
                ModelPushReport, SshModelOps, prepare_model_push, run_model_ceremony,
            };
            use orchard::deploy::host_pins::HostPinOpts;
            use orchard::deploy::update::{Authorize, CeremonyOpts};
            let keys_dir = keys_dir.unwrap_or_else(default_keys_dir);
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
            let root = repo_root()?;
                                                                                    
                                                            
            let pin_path = orchard::deploy::pinned_artifact_root_path(&root);
                                                                                              
                               
            let prepared = prepare_model_push(&model, &container_image, &root)?;
            let pin_dir = default_keys_dir()
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("host-pins");
            let ops = SshModelOps::new(host.clone(), port, identity, is_tty);
            let cer = CeremonyOpts {
                host: &host,
                keys_dir: &keys_dir,
                authorize: if confirmed {
                    Authorize::Confirmed
                } else {
                    Authorize::Interactive
                },
                host_pin: HostPinOpts {
                    host_fingerprint: host_fingerprint.as_deref(),
                    is_tty,
                    pin_dir: &pin_dir,
                },
            };
            match run_model_ceremony(&prepared, &pin_path, &cer, &ops)? {
                ModelPushReport::Committed => {
                    println!("orchard deploy-model: COMMITTED (the box serves the new model)");
                    Ok(())
                }
                ModelPushReport::Refused { detail } => {
                    println!("orchard deploy-model: REFUSED — {detail}");
                    Err("deploy-model refused".into())
                }
                ModelPushReport::Degraded { detail } => {
                    println!("orchard deploy-model: DEGRADED — {detail}");
                    Err("deploy-model degraded".into())
                }
            }
        }
        OrchardCmd::Status {
            host,
            image,
            ssh_identity,
            keys_dir,
            host_fingerprint,
            port,
        } => {
            use orchard::deploy::status::{StatusArgs, run};
            let pin_dir = default_keys_dir()
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("host-pins");
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
                                                                                                            
                                                                                                              
            let committed_pin = repo_fingerprints_path()
                .ok()
                .map(|p| p.with_file_name("pinned-artifact-root.toml"))
                .filter(|p| p.exists());
            let args = StatusArgs {
                host,
                port,
                image,
                ssh_identity,
                keys_dir,
                committed_pin,
                host_fingerprint,
                pin_dir,
                is_tty,
            };
                                                                                                         
            let exit = run(&args);
            use std::io::Write as _;
            std::io::stdout().flush().ok();
            std::process::exit(exit.code());
        }
        OrchardCmd::RotateKey {
            host,
            new_identity,
            ssh_identity,
            host_fingerprint,
            port,
        } => {
            use orchard::deploy::rotate_key::{RotateKeyArgs, run};
            let pin_dir = default_keys_dir()
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("host-pins");
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
            let args = RotateKeyArgs {
                host,
                port,
                new_identity,
                ssh_identity,
                host_fingerprint,
                pin_dir,
                is_tty,
            };
                                                                                                        
            let outcome = run(&args);
            use std::io::Write as _;
            std::io::stdout().flush().ok();
            std::process::exit(outcome.code());
        }
        OrchardCmd::SignBackup { file, output_dir } => {
            let keys_dir = output_dir.unwrap_or_else(default_keys_dir);
                                                                                         
                                                                                      
                                                                                       
                                                                                
                                                                      
            let pin_path = repo_root()
                .map(|r| orchard::deploy::pinned_artifact_root_path(&r))
                .unwrap_or_else(|_| keys_dir.join("no-committed-pin"));
            let sig =
                orchard::deploy::artifact_sign::sign_backup_routed(&keys_dir, &pin_path, &file)?;
            println!(
                "deploy sign-backup: signed {} → {} (purpose=backup)",
                file.display(),
                sig.display()
            );
            Ok(())
        }
        OrchardCmd::SignInContainer {
            keys_dir,
            img,
            vmlinuz,
            initramfs,
            backup,
            weights,
            update_image,
        } => {
            use orchard::deploy::artifact_keys::sign_in_container_pairs;
            use orchard::deploy::artifact_sign::sign_in_container_leaf;
                                                                                           
                                                                                             
                                                                                           
                                                                                             
                                                                                             
                                                                              
            orchard::deploy::dumpable::set_process_non_dumpable().map_err(|e| {
                format!(
                    "sign-in-container: refusing to unwrap a seed in a dumpable process \
                     (PR_SET_DUMPABLE failed): {e}"
                )
            })?;
                                                                                  
                                                                                               
            let pass = orchard::deploy::tty::read_passphrase(
                "Passphrase to unwrap the artifact-signing worker key: ",
            )?;
                                                                                        
                                                                                          
                                                                                          
                                                                                        
            let targets =
                sign_in_container_pairs(img, vmlinuz, initramfs, backup, weights, update_image);
            if targets.is_empty() {
                return Err("sign-in-container: no artifact given \
                            (pass --img/--vmlinuz/--initramfs/--backup/--weights/--update-image)"
                    .into());
            }
            let sigs = sign_in_container_leaf(&keys_dir, pass.as_slice(), &targets)?;
            for ((_, purpose), sig) in targets.iter().zip(sigs) {
                println!("  signed → {} (purpose={purpose:?})", sig.display());
            }
            Ok(())
        }
        OrchardCmd::RestoreImage {
            data,
            db,
            operator_pubkey,
            root,
            db_target,
            db_owner,
            out,
            container_image,
            manifest_full,
        } => {
            use recipes_image_builder::build_tools_host::HostBuildTools;
            use recipes_image_builder::restore_image::{
                RestoreImageSpec, check_restore_identity, plan_size, stage_restore,
            };
                                                                                               
                                                                                                  
                                                                                           
            let pubkey_line =
                orchard::deploy::build_image::read_validated_pubkey("operator", &operator_pubkey)?;
            let data_bytes =
                std::fs::read(&data).map_err(|e| format!("read --data {}: {e}", data.display()))?;
            let db_bytes =
                std::fs::read(&db).map_err(|e| format!("read --db {}: {e}", db.display()))?;
            let spec = RestoreImageSpec {
                data_tar_gz: &data_bytes,
                db: &db_bytes,
                operator_pubkey: pubkey_line.as_bytes(),
                root: &root,
                db_target: &db_target,
                db_owner,
            };
            let staged = stage_restore(&spec)?;
            let plan = plan_size(staged.content_bytes, staged.file_count)?;
            let tools = HostBuildTools::new(container_image, repo_root()?);
            let img = tools.bake_restore_image(&staged, plan)?;
            check_restore_identity(&img)?;
            std::fs::write(&out, &img)
                .map_err(|e| format!("write --out {}: {e}", out.display()))?;

                                                                                                
                                                                                                            
                                                                                                         
                                                                                                         
            let db_rel = format!("{root}/{db_target}");
            print!(
                "{}",
                orchard::deploy::report::restore_manifest_rollup(
                    &staged.manifest,
                    staged.resolved_db_owner,
                    &db_rel,
                    manifest_full,
                )
            );
            let (du, dg) = staged.resolved_db_owner;
            println!("resolved db-owner: {du}:{dg}");
            println!(
                "size plan: {} blocks ({} MiB) / {} inodes (explicit -N)",
                plan.blocks,
                plan.blocks * 4096 / (1024 * 1024),
                plan.inodes
            );
                                                                                                   
                                                                  
            let digest = orchard::deploy::artifact_sign::streaming_sha256(&out)?;
            println!(
                "restore image: {} ({} bytes, sha256 {})",
                out.display(),
                img.len(),
                hex::encode(digest)
            );
            println!("sign it: orchard sign-backup {}", out.display());
            Ok(())
        }
        OrchardCmd::Build {
            profile,
            domain,
            keys_dir,
            out_dir,
            ksrc,
            syslinux_src,
            container_image,
            allow_dirty,
            verify,
            recovery_pubkey,
            operator_pubkey,
            firmware,
            net,
            secure_boot,
            manifest,
            substrate,
            image_version,
            weights_anchor,
        } => {
            use orchard::deploy::build_image::{
                BuildImageOpts, build_image, check_substrate_flag, default_kernel_xz,
                default_syslinux_src,
            };
                                                                                                   
                                                                                    
            check_substrate_flag(firmware, substrate.as_deref())?;
                                                                                                        
                                                                                                       
                                                                                                         
            use orchard::deploy::profile::{pick, require_present};
            let profile = profile
                .map(|p| orchard::deploy::profile::load(&p))
                .transpose()?;
            let prof = profile.as_ref();
            if let Some(p) = prof {
                let ignored: Vec<&str> = [
                    ("ip", p.ip.is_some()),
                    ("port", p.port.is_some()),
                    ("operator_pubkey", p.operator_pubkey.is_some()),
                    ("recovery_pubkey", p.recovery_pubkey.is_some()),
                    ("ssh_identity", p.ssh_identity.is_some()),
                    ("box_login_identity", p.box_login_identity.is_some()),
                    ("host_fingerprint", p.host_fingerprint.is_some()),
                    (
                        "runtime_hostkey_fingerprint",
                        p.runtime_hostkey_fingerprint.is_some(),
                    ),
                ]
                .iter()
                .filter(|(_, present)| *present)
                .map(|(k, _)| *k)
                .collect();
                if !ignored.is_empty() {
                    println!(
                        "note: the profile's key(s) [{}] apply to `prod`, not `build` — ignored here.",
                        ignored.join(", ")
                    );
                }
            }
            let domain_merged = pick(domain, prof.and_then(|p| p.domain.clone()), None);
            let domain =
                require_present("domain", "--domain", "domain", domain_merged.as_ref())?.clone();
            let out_dir = pick(out_dir, prof.and_then(|p| p.out_dir.clone()), None)
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            let net = pick(net, prof.and_then(|p| p.net.clone()), None);
            let keys_dir = pick(keys_dir, prof.and_then(|p| p.keys_dir.clone()), None);
            let root = repo_root()?;
            let kernel_src = match ksrc {
                Some(p) => p,
                None => default_kernel_xz(&root)?,
            };
            let syslinux_src = match syslinux_src {
                Some(p) => p,
                None => default_syslinux_src(&root)?,
            };
            let opts = BuildImageOpts {
                keys_dir: keys_dir.unwrap_or_else(default_keys_dir),
                repo_root: root,
                kernel_src,
                syslinux_src,
                out_dir,
                domain,
                container_image,
                allow_dirty,
                recovery_pubkey,
                operator_pubkey,
                firmware,
                net,
                sb_required: secure_boot,
                manifest_path: manifest,
                image_version,
                runtime_weights: weights_anchor == WeightsAnchorArg::Runtime,
            };
            if verify {
                use orchard::deploy::verify::{render_report, verify_build};
                let outcome = verify_build(&opts)?;
                print!("{}", render_report(&outcome));
                if !outcome.identical {
                    return Err("determinism self-test FAILED: the two builds diverged \
                                (see the per-component report above)"
                        .into());
                }
                Ok(())
            } else {
                let out = build_image(&opts)?;
                println!(
                    "deploy build: wrote {} (+ .layout.toml + .sha256); verity root hash {}",
                    out.outputs.img.display(),
                    out.root_hash
                );
                                                                                     
                                                                                         
                                                                           
                report_artifact_signing(
                    &opts.keys_dir,
                    &out.outputs.img,
                    &out.outputs.vmlinuz,
                    &out.outputs.initramfs,
                )?;
                print!(
                    "{}",
                    orchard::deploy::epilogue::next_steps(
                        &orchard::deploy::epilogue::build_next_steps(&out.outputs.img),
                    )
                );
                Ok(())
            }
        }
        OrchardCmd::Dryrun {
            keep_running,
            image,
            domain,
            allow_dirty,
            memory_mb,
        } => {
            use orchard::deploy::dryrun::{DryrunOpts, boot_and_verify};
            let opts = DryrunOpts {
                keep_running,
                memory_mb,
                ..DryrunOpts::default()
            };
            let img = match image {
                Some(prebuilt) => prebuilt,
                None => {
                    use orchard::deploy::build_image::{
                        BuildImageOpts, build_image, default_kernel_xz, default_syslinux_src,
                    };
                    let root = repo_root()?;
                    let bopts = BuildImageOpts {
                        keys_dir: default_keys_dir(),
                        kernel_src: default_kernel_xz(&root)?,
                        syslinux_src: default_syslinux_src(&root)?,
                        repo_root: root,
                        out_dir: PathBuf::from("/tmp"),
                        domain,
                        container_image: "recipes-imgbuild:dev".to_string(),
                        allow_dirty,
                        recovery_pubkey: None,
                        operator_pubkey: None,
                        firmware: orchard::deploy::build_image::Firmware::Seabios,
                                                                                           
                                                                                         
                        net: None,
                        sb_required: false,
                        manifest_path: None,
                                                                                                        
                                                                                                          
                        image_version: 0,
                        runtime_weights: false,
                    };
                    let out = build_image(&bopts)?;
                    println!(
                        "deploy dryrun: built {} (verity root hash {})",
                        out.outputs.img.display(),
                        out.root_hash
                    );
                    out.outputs.img
                }
            };
            boot_and_verify(&img, &opts)?;
            println!(
                "deploy dryrun: PASS — image booted; dropbear accepted the operator pubkey, \
                 recipes answered, rootfs is read-only."
            );
            Ok(())
        }
        OrchardCmd::Doctor {
            for_verb,
            image,
            keys_dir,
        } => {
            use orchard::deploy::doctor::{Probes, Scope, render, run_checks};
            let keys_dir = keys_dir.unwrap_or_else(default_keys_dir);
                                                                                                        
            let repo = repo_root().unwrap_or_else(|_| PathBuf::from("."));
            let scope = match for_verb.as_deref() {
                Some("build") => Scope::Build,
                Some("dryrun") => Scope::Dryrun,
                Some("prod") => Scope::Prod {
                    image: image.clone(),
                },
                Some("boot-gate") => Scope::BootGate,
                _ => Scope::Full,
            };
            let probes = Probes::gather(&scope, &keys_dir, &repo);
            let checks = run_checks(&probes, &scope);
            print!("{}", render(&checks, &scope));
                                                                                                         
                                                                                    
            if matches!(scope, Scope::BootGate) {
                print!(
                    "\n{}",
                    orchard::deploy::epilogue::next_steps(
                        &orchard::deploy::epilogue::boot_gate_env_skeleton(image.as_deref()),
                    )
                );
            }
            Ok(())                                                    
        }
        OrchardCmd::Prod {
            ip,
            profile,
            pubkey,
            image,
            ssh_identity,
            box_login_identity,
            port,
            host_fingerprint,
            known_hosts,
            runtime_hostkey_fingerprint,
            image_stage_dir,
            wipe_confirmed,
            reconnect_timeout_secs,
            restore_from,
            restore_min_ctr,
            artifact_pin,
            reclaim_tail,
            reclaim_timeout_secs,
            domain,
            keys_dir,
            out_dir,
            ksrc,
            syslinux_src,
            container_image,
            allow_dirty,
            recovery_pubkey,
            net,
        } => {
            use orchard::deploy::build_image::{
                BuildImageOpts, build_image, default_kernel_xz, default_syslinux_src,
            };
            use orchard::deploy::prod::{WipeConfirmed, validate_target_host};
            use orchard::deploy::prod_orchestrate::{
                DeployProdOpts, ProcessOps, acquire_deploy_lock, deploy_prod,
                install_cancel_handler,
            };
            let ip = validate_target_host(&ip)?;
                                                                                                      
                                                                                                   
                                                                                                     
                                                                               
            use orchard::deploy::profile::{ip_cross_check, pick, require_present};
            let profile = profile
                .map(|p| orchard::deploy::profile::load(&p))
                .transpose()?;
            let prof = profile.as_ref();
            ip_cross_check(&ip, prof.and_then(|p| p.ip.as_deref()))?;
            let mut profile_sourced: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            if pubkey.is_none() && prof.and_then(|p| p.operator_pubkey.as_ref()).is_some() {
                profile_sourced.insert("operator_pubkey".into());
            }
            let pubkey_merged = pick(pubkey, prof.and_then(|p| p.operator_pubkey.clone()), None);
            let pubkey = require_present(
                "operator pubkey",
                "--pubkey",
                "operator_pubkey",
                pubkey_merged.as_ref(),
            )?
            .clone();
            let ssh_identity_merged = pick(
                ssh_identity,
                prof.and_then(|p| p.ssh_identity.clone()),
                None,
            );
            let ssh_identity = require_present(
                "ssh identity",
                "--ssh-identity",
                "ssh_identity",
                ssh_identity_merged.as_ref(),
            )?
            .clone();
            if port.is_none() && prof.and_then(|p| p.port).is_some() {
                profile_sourced.insert("port".into());
            }
            let port = pick(port, prof.and_then(|p| p.port), None).unwrap_or(22);
            let out_dir = pick(out_dir, prof.and_then(|p| p.out_dir.clone()), None)
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            let domain = pick(domain, prof.and_then(|p| p.domain.clone()), None);
            let net = pick(net, prof.and_then(|p| p.net.clone()), None);
            let keys_dir = pick(keys_dir, prof.and_then(|p| p.keys_dir.clone()), None);
            let box_login_identity = pick(
                box_login_identity,
                prof.and_then(|p| p.box_login_identity.clone()),
                None,
            );
            let host_fingerprint = pick(
                host_fingerprint,
                prof.and_then(|p| p.host_fingerprint.clone()),
                None,
            );
            let runtime_hostkey_fingerprint = pick(
                runtime_hostkey_fingerprint,
                prof.and_then(|p| p.runtime_hostkey_fingerprint.clone()),
                None,
            );
            let recovery_pubkey = pick(
                recovery_pubkey,
                prof.and_then(|p| p.recovery_pubkey.clone()),
                None,
            );
                                                                                                 
            install_cancel_handler();
                                                                             
            let _lock =
                acquire_deploy_lock(&std::env::temp_dir().join("recipes-deploy-locks"), &ip)?;
                                                                                            
                                                                                             
                                                                                              
                                                                                         
            let artifact_root_pin = orchard::deploy::artifact_verify::read_root_pin(
                &keys_dir.clone().unwrap_or_else(default_keys_dir),
                artifact_pin,
            )?;
                                                                                                
            let image = match image {
                Some(p) => p,
                None => {
                    let domain = domain
                        .ok_or("inline build needs --domain (or pass --image <prebuilt .img>)")?;
                    let root = repo_root()?;
                    let kernel_src = match ksrc {
                        Some(p) => p,
                        None => default_kernel_xz(&root)?,
                    };
                    let syslinux_src = match syslinux_src {
                        Some(p) => p,
                        None => default_syslinux_src(&root)?,
                    };
                    let opts = BuildImageOpts {
                        keys_dir: keys_dir.unwrap_or_else(default_keys_dir),
                        repo_root: root,
                        kernel_src,
                        syslinux_src,
                        out_dir,
                        domain,
                        container_image,
                        allow_dirty,
                        recovery_pubkey,
                        operator_pubkey: Some(pubkey.clone()),
                        firmware: orchard::deploy::build_image::Firmware::Seabios,
                        net,
                        sb_required: false,
                        manifest_path: None,
                                                                                                   
                                                                                                          
                                                                                                  
                        image_version: 0,
                        runtime_weights: false,
                    };
                    let out = build_image(&opts)?;
                    println!("deploy prod: built {}", out.outputs.img.display());
                                                                                   
                                                                                      
                                                                                     
                                                                                  
                                                                           
                    report_artifact_signing(
                        &opts.keys_dir,
                        &out.outputs.img,
                        &out.outputs.vmlinuz,
                        &out.outputs.initramfs,
                    )?;
                    out.outputs.img
                }
            };
                                                                                               
                                                                                                 
                                                                                            
            {
                use orchard::deploy::artifact_verify::preflight_verify_triple;
                let vmlinuz = image.with_extension("vmlinuz");
                let initramfs = image.with_extension("initramfs");
                let msg = preflight_verify_triple(
                    artifact_root_pin.as_ref(),
                    &image,
                    &vmlinuz,
                    &initramfs,
                )
                .map_err(|e| format!("deploy prod artifact preflight: {e}"))?;
                println!("deploy prod artifact preflight: {msg}");
            }
                                                                                       
            let box_login_identity = match box_login_identity {
                Some(p) => p,
                None => {
                    let p = pubkey.with_extension("");
                    if !p.is_file() {
                        return Err(format!(
                            "--box-login-identity not given and the conventional private half \
                             {} does not exist",
                            p.display()
                        )
                        .into());
                    }
                    p
                }
            };
                                                                                   
            let workdir = tempfile::Builder::new().prefix("recipes-prod-").tempdir()?;
            let provisioning_known_hosts = match &known_hosts {
                Some(p) => p.clone(),
                None => workdir.path().join("known_hosts_provisioning"),
            };
            let mut ops = ProcessOps {
                ip: ip.clone(),
                ssh_port: port,
                ssh_identity,
                box_login_identity,
                provisioning_known_hosts,
                reconnect_known_hosts: workdir.path().join("known_hosts_box"),
                step_started: None,
            };
            deploy_prod(
                &mut ops,
                DeployProdOpts {
                    ip,
                    pubkey,
                    image,
                    host_fingerprint,
                    known_hosts,
                    runtime_hostkey_fingerprint,
                    image_stage_dir,
                    wipe_confirmed: WipeConfirmed::from_flag(wipe_confirmed),
                    reconnect_timeout_secs,
                    restore_from,
                    restore_min_ctr,
                    artifact_pin: artifact_root_pin,
                    profile_sourced,
                    reclaim_tail,
                    reclaim_reboot_timeout_secs: reclaim_timeout_secs,
                },
            )?;
            Ok(())
        }
        OrchardCmd::ReclaimTail {
            ip,
            image,
            ssh_identity,
            host_fingerprint,
            port,
            confirmed,
            reclaim_timeout_secs,
        } => {
            use orchard::deploy::prod::validate_target_host;
            use orchard::deploy::prod_orchestrate::{
                ProcessOps, acquire_deploy_lock, install_cancel_handler,
            };
            use orchard::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
            let ip = validate_target_host(&ip)?;
            if !confirmed {
                return Err(
                    orchard::deploy::reclaim::consent::RECLAIM_STANDALONE_PRECONFIRM.into(),
                );
            }
            install_cancel_handler();
                                                                                  
            let _lock =
                acquire_deploy_lock(&std::env::temp_dir().join("recipes-deploy-locks"), &ip)?;
            let workdir = tempfile::Builder::new()
                .prefix("recipes-reclaim-")
                .tempdir()?;
            let mut ops = ProcessOps {
                ip: ip.clone(),
                ssh_port: port,
                ssh_identity: ssh_identity.clone(),
                                                                                              
                box_login_identity: ssh_identity,
                provisioning_known_hosts: workdir.path().join("known_hosts_provisioning"),
                reconnect_known_hosts: workdir.path().join("known_hosts_box"),
                step_started: None,
            };
            reclaim_tail_standalone(
                &mut ops,
                &StandaloneOpts {
                    ip,
                    image,
                    host_fingerprint,
                    timeout_secs: reclaim_timeout_secs,
                },
            )?;
            Ok(())
        }
        OrchardCmd::RefreshApkLock { container_image } => {
            use orchard::deploy::refresh_apk_lock::{RefreshApkLockOpts, refresh_apk_lock};
            let opts = RefreshApkLockOpts {
                repo_root: repo_root()?,
                container_image,
            };
            let path = refresh_apk_lock(&opts)?;
            println!("deploy refresh-apk-lock: regenerated {}", path.display());
            Ok(())
        }
        OrchardCmd::SyncPins { check } => {
            use orchard::deploy::sync_pins::{SyncPinsOpts, sync_pins};
            let opts = SyncPinsOpts {
                repo_root: repo_root()?,
                check,
            };
            println!("{}", sync_pins(&opts)?);
            Ok(())
        }
        OrchardCmd::Vendor { store } => {
            let root = repo_root()?;
            let store = match store {
                Some(s) => s,
                None => std::env::var_os("FRUIT_ARTIFACT_STORE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| root.join("../artifact-store")),
            };
            println!("{}", orchard::deploy::vendor_cmd::vendor(&root, &store)?);
            print!(
                "{}",
                orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::vendor_next_steps(),
                )
            );
            Ok(())
        }
        OrchardCmd::Prime {
            kbuild_dir,
            syslinux_dir,
        } => {
            use recipes_image_builder::pins::Pins;
            use recipes_image_builder::sources::{
                self, KERNEL_TAR_CEILING, KERNEL_XZ_CAP, SYSLINUX_TAR_CEILING, SYSLINUX_XZ_CAP,
            };
            let root = repo_root()?;
            let pins = Pins::load(&root)?;
            std::fs::create_dir_all(&kbuild_dir)?;
            std::fs::create_dir_all(&syslinux_dir)?;

            let kernel_staged = pins.kernel_tarball_path(&kbuild_dir);
            sources::prime_source(
                &recipes_image_builder::HttpFetcher::with_body_cap(KERNEL_XZ_CAP),
                &sources::kernel_xz_url(&pins.kernel.version)?,
                &pins.kernel.sha256,
                KERNEL_TAR_CEILING,
                &kernel_staged,
            )?;
            println!(
                "prime: kernel staged at {} (sha256 {})",
                kernel_staged.display(),
                pins.kernel.sha256
            );

            let syslinux_staged = pins.syslinux_tarball_path(&syslinux_dir);
            sources::prime_source(
                &recipes_image_builder::HttpFetcher::with_body_cap(SYSLINUX_XZ_CAP),
                &sources::syslinux_xz_url(&pins.syslinux.version)?,
                &pins.syslinux.sha256,
                SYSLINUX_TAR_CEILING,
                &syslinux_staged,
            )?;
            println!(
                "prime: syslinux staged at {} (sha256 {})",
                syslinux_staged.display(),
                pins.syslinux.sha256
            );
            print!(
                "{}",
                orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::prime_next_steps(),
                )
            );
            Ok(())
        }
        OrchardCmd::Market { sub } => match sub {
            MarketSub::Verify {
                certs,
                all,
                allow_missing,
                cert_presence,
            } => {
                use orchard::deploy::market::{VerifyOpts, cert_presence_dry_run, verify};
                let opts = VerifyOpts {
                    repo_root: repo_root()?,
                    certs,
                    all,
                    allow_missing,
                };
                let out = if cert_presence {
                    cert_presence_dry_run(&opts)?
                } else {
                    verify(&opts)?
                };
                println!("{out}");
                Ok(())
            }
            MarketSub::Outdated {
                exit_drift,
                all_packages,
            } => {
                use orchard::deploy::market::{
                    ExitDrift, OutdatedOpts, outdated, outdated_exit_code,
                };
                let when = match exit_drift.as_deref() {
                    None => ExitDrift::Never,
                    Some("gone") => ExitDrift::OnGone,
                    Some("any") => ExitDrift::OnAny,
                    Some(other) => {
                        return Err(
                            format!("--exit-drift takes `gone` or `any`, got `{other}`").into()
                        );
                    }
                };
                let report = outdated(&OutdatedOpts {
                    repo_root: repo_root()?,
                    all_packages,
                    fetch: Box::new(recipes_image_builder::HttpFetcher::new()),
                })?;
                println!("{}", report.text);
                let code = outdated_exit_code(when, &report);
                if code != 0 {
                    use std::io::Write as _;
                    std::io::stdout().flush().ok();
                    std::process::exit(code);
                }
                Ok(())
            }
            MarketSub::Upgrade {
                source,
                binary,
                config,
                apks,
                kernel,
                rust,
                all,
                dry_run,
                container_image,
                build_dir,
                commit,
                no_commit,
            } => {
                use orchard::deploy::market::{VerifyOpts, verify};
                use orchard::deploy::market_exec::{
                    ShellStepExec, Stage, default_store, execute, resolve_layout,
                };
                use orchard::deploy::market_upgrade::{UpgradeError, plan, render_plan};
                use recipes_image_builder::pin_manifest::PinManifest;
                use recipes_image_builder::repo_manifest::RepoManifest;
                let target = parse_upgrade_target(source, binary, config, apks, kernel, rust, all)?;
                let root = repo_root()?;
                let consume = PinManifest::load(&root.join("consume-pins.toml"))?;
                let manifest = RepoManifest::load(&root.join("repo-manifest.toml"))?;
                let steps = plan(&target, &manifest, &consume)?;
                println!("{}", render_plan(&target, &steps));
                if dry_run {
                                                                                                 
                                                                                                 
                                                              
                    if matches!(
                        target,
                        orchard::deploy::market_upgrade::Target::Apks
                            | orchard::deploy::market_upgrade::Target::All
                    ) {
                        println!(
                            "{}",
                            orchard::deploy::market::apks_dry_run_preview(
                                &root,
                                &recipes_image_builder::HttpFetcher::new(),
                            )
                        );
                    }
                    println!("market upgrade: --dry-run (nothing staged, nothing swapped)");
                    return Ok(());
                }
                                                                                                   
                                                                                             
                                                                                             
                                                                                                 
                                                  
                let container_image = match container_image {
                    some @ Some(_) => some,
                    None if matches!(
                        target,
                        orchard::deploy::market_upgrade::Target::Apks
                            | orchard::deploy::market_upgrade::Target::All
                    ) =>
                    {
                        Some(orchard::deploy::market::default_apks_container_image(
                            &recipes_image_builder::pins::Pins::load(&root)?,
                        ))
                    }
                    None => None,
                };
                                                                                                         
                                                                                                       
                let store = default_store(&root);
                let layout = resolve_layout(&manifest, root.clone(), store);
                                                                                                
                                                                                          
                let kernel_fetcher = recipes_image_builder::HttpFetcher::with_body_cap(
                    orchard::deploy::kernel_bump::KERNEL_XZ_CAP,
                );
                                                                                                      
                                                                                                        
                                                                          
                let rust_fetcher = recipes_image_builder::HttpFetcher::with_body_cap(
                    orchard::deploy::rust_bump::RUST_MANIFEST_CAP,
                );
                let container_builder = orchard::deploy::market_exec::DockerContainerBuilder {
                    source_date_epoch: 0,
                };
                let mut exec = ShellStepExec {
                    layout: &layout,
                    manifest: &manifest,
                    consume: &consume,
                    apk_container_image: container_image,
                    build_dir,
                    kernel_fetcher: Some(&kernel_fetcher),
                    rust_fetcher: Some(&rust_fetcher),
                    container_builder: Some(&container_builder),
                    rebuilt_digest: None,
                };
                let verify_staged = |stage: &Stage| {
                    let opts = VerifyOpts {
                        repo_root: stage.verify_root().to_path_buf(),
                        certs: false,
                        all: false,
                        allow_missing: vec![],
                    };
                    verify(&opts)
                        .map(|_| ())
                        .map_err(|e| UpgradeError::StagedVerify(e.to_string()))
                };
                let report = execute(&steps, &layout, &mut exec, &verify_staged)?;
                                                                                         
                                                                                                 
                                                                                               
                                                    
                use orchard::deploy::git_commit::{
                    Consent, GitCommit as _, ShellGit, UpgradeFlags, compose_message, consent_from,
                    edit_message_with, plan_commit, render_ready_command,
                };
                let cplan = plan_commit(&report.swapped, &layout);
                println!(
                    "market upgrade: staged + verified + SWAPPED {} path(s):",
                    report.swapped.len()
                );
                for p in &cplan.orchard {
                    println!("  [orchard]  {}", p.display());
                }
                for (name, (_, paths)) in &cplan.siblings {
                    for p in paths {
                        println!("  [{name}]  {}", p.display());
                    }
                }
                for p in &cplan.excluded {
                    println!(
                        "  [store]    {}  (store bytes, bound by their pins — not a git target)",
                        p.display()
                    );
                }

                                                                                                
                                                                                      
                                                                      
                use orchard::deploy::git_commit::diff_stat;
                if let Some(stat) = diff_stat(&root, &cplan.orchard) {
                    println!("--- diff --stat (orchard) ---");
                    println!("{stat}");
                }
                for (name, (repo_root_path, paths)) in &cplan.siblings {
                    if let Some(stat) = diff_stat(repo_root_path, paths) {
                        println!("--- diff --stat ({name}) ---");
                        println!("{stat}");
                    }
                }

                let mut message = compose_message(&target, &root, &cplan.orchard);
                println!("--- composed commit message ---");
                println!("{message}");
                println!("-------------------------------");

                let is_tty = {
                    use std::io::IsTerminal as _;
                    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
                };
                let flags = UpgradeFlags {
                    commit,
                    no_commit,
                    dry_run,
                };
                let mut consent = consent_from(&flags, is_tty, || {
                    use std::io::Write as _;
                    print!(
                        "commit the orchard paths? [y = commit / e = edit the message / N = print the command] "
                    );
                    std::io::stdout().flush().ok();
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).ok();
                    line.trim().chars().next().unwrap_or('n')
                });

                                                                                               
                                                                                                 
                                             
                if consent == Consent::EditThenCommit {
                    match edit_message_with(std::env::var_os("EDITOR").as_deref(), &message) {
                        Some(edited) => {
                            message = edited;
                            consent = Consent::Commit;
                        }
                        None => {
                            println!(
                                "market upgrade: edit aborted (no $EDITOR, editor failed, or empty message) — not committing."
                            );
                            consent = Consent::PrintOnly;
                        }
                    }
                }

                                                                                                 
                                            
                let msgfile = {
                    use std::io::Write as _;
                    let mut f = tempfile::NamedTempFile::new()?;
                    f.write_all(message.as_bytes())?;
                    f.flush()?;
                    let (_, path) = f.keep()?;
                    path
                };

                match consent {
                    Consent::Commit => {
                        if cplan.orchard.is_empty() {
                            println!(
                                "market upgrade: nothing to commit in orchard (no orchard-repo paths in the swap)."
                            );
                        } else {
                            ShellGit
                                .commit(&root, &cplan.orchard, &message)
                                .map_err(|e| -> Box<dyn std::error::Error> {
                                                                                                  
                                                                                        
                                    format!(
                                        "{e}\nthe re-pin itself is swapped + verified; commit by hand:\n  {}",
                                        render_ready_command(&root, &msgfile, &cplan.orchard)
                                    )
                                    .into()
                                })?;
                            println!(
                                "market upgrade: committed {} path(s) in orchard.",
                                cplan.orchard.len()
                            );
                        }
                    }
                    Consent::PrintOnly | Consent::EditThenCommit => {
                        if !cplan.orchard.is_empty() {
                            println!(
                                "market upgrade: NOT committed (no consent given) — the re-pin is done; commit when ready:"
                            );
                            println!(
                                "  {}",
                                render_ready_command(&root, &msgfile, &cplan.orchard)
                            );
                        }
                    }
                }
                if !cplan.siblings.is_empty() {
                    println!(
                        "sibling repos await their own commit (market never commits across repos):"
                    );
                    for (name, (repo_root_path, paths)) in &cplan.siblings {
                        println!(
                            "  [{name}] {}",
                            render_ready_command(repo_root_path, &msgfile, paths)
                        );
                    }
                }
                Ok(())
            }
            MarketSub::Store { sub } => match sub {
                StoreSub::Status { all, full } => {
                    use orchard::deploy::market_exec::default_store;
                    use orchard::deploy::store_admin::{render_status, scan_store};
                    use recipes_image_builder::repo_manifest::RepoManifest;
                    let root = repo_root()?;
                    let manifest = RepoManifest::load(&root.join("repo-manifest.toml"))?;
                    let store = default_store(&root);
                    let scan = scan_store(&store, &manifest, &root)?;
                    println!("{}", render_status(&scan, &store, all, full));
                    Ok(())
                }
                StoreSub::Prune { delete, full } => {
                    use orchard::deploy::market_exec::default_store;
                    use orchard::deploy::store_admin::{prune, render_prune, scan_store};
                    use recipes_image_builder::repo_manifest::RepoManifest;
                    let root = repo_root()?;
                    let manifest = RepoManifest::load(&root.join("repo-manifest.toml"))?;
                    let store = default_store(&root);
                    let scan = scan_store(&store, &manifest, &root)?;
                    let report = prune(&store, &scan, delete)?;
                    print!("{}", render_prune(&report, delete, &store, full));
                    if report.refused.is_some() {
                        use std::io::Write as _;
                        std::io::stdout().flush().ok();
                        std::process::exit(1);
                    }
                    Ok(())
                }
                StoreSub::Migrate => {
                    use orchard::deploy::market_exec::default_store;
                    use orchard::deploy::store_admin::{migrate, render_migrate};
                    let root = repo_root()?;
                    let store = default_store(&root);
                    let report = migrate(&store)?;
                    print!("{}", render_migrate(&report, &store));
                    Ok(())
                }
            },
        },
    }
}

/// Resolve the operator's `market upgrade` flags into EXACTLY one target (0 or >1 is a usage error).
fn parse_upgrade_target(
    source: Option<String>,
    binary: Option<String>,
    config: Option<String>,
    apks: bool,
    kernel: Option<String>,
    rust: Option<String>,
    all: bool,
) -> Result<orchard::deploy::market_upgrade::Target, Box<dyn std::error::Error>> {
    use orchard::deploy::market_upgrade::Target;
    let mut chosen: Vec<Target> = Vec::new();
    if let Some(s) = source {
        chosen.push(Target::Source(s));
    }
    if let Some(b) = binary {
                                                                                                             
                                                                                                        
                                                                     
        chosen.push(Target::Binary(b));
    }
    if let Some(c) = config {
                                                                                                           
                                                                                 
        chosen.push(Target::Config(c));
    }
    if apks {
        chosen.push(Target::Apks);
    }
    if let Some(k) = kernel {
        chosen.push(Target::Kernel(k));
    }
    if let Some(r) = rust {
                                                                                                        
                                                                                                 
                                                                                                  
        chosen.push(Target::Rust(r));
    }
    if all {
                                                                                                 
        chosen.push(Target::All);
    }
    match chosen.len() {
        1 => Ok(chosen.into_iter().next().unwrap()),
        0 => Err("market upgrade: pick exactly one target \
                  (--source/--binary/--config/--apks/--kernel/--rust/--all)"
            .into()),
        n => Err(format!("market upgrade: pick exactly ONE target, got {n}").into()),
    }
}

/// Resolve `./crates/image-builder/pinned-cert-fingerprints.toml`, refusing to
                                                                            
fn repo_fingerprints_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let crate_dir = PathBuf::from("crates/image-builder");
    if !crate_dir.is_dir() {
        return Err("run `deploy generate-keys` from the recipes repo root \
             (./crates/image-builder/ not found)"
            .into());
    }
    let cargo = std::fs::read_to_string("Cargo.toml")
        .map_err(|_| "run from the recipes repo root (./Cargo.toml not found)")?;
    if !cargo.contains("[workspace]") {
        return Err("./Cargo.toml is not the recipes workspace root".into());
    }
    Ok(crate_dir.join("pinned-cert-fingerprints.toml"))
}

/// The committed Secure Boot db-cert fingerprint pin (the enrollment anchor; SB-loader
/// plan Task 4.1). Same repo-root working-dir contract as `repo_fingerprints_path`.
fn repo_sb_db_fingerprint_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let crate_dir = PathBuf::from("crates/image-builder");
    if !crate_dir.is_dir() {
        return Err(
            "run `deploy generate-keys --secure-boot`/`deploy sign-sb` from the \
             recipes repo root (./crates/image-builder/ not found)"
                .into(),
        );
    }
    Ok(crate_dir.join("pinned-secure-boot-db.toml"))
}

/// Resolve the recipes repo root for `deploy build` (pins, trust anchors, build-kernel.sh live
                                                                                               
fn repo_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !PathBuf::from("crates/image-builder").is_dir() {
        return Err(
            "run `deploy build` from the recipes repo root (./crates/image-builder/ not found)"
                .into(),
        );
    }
    Ok(std::env::current_dir()?)
}

/// Render a fatal `run_deploy` error for the process boundary through `Display`, not `Debug`, so a
/// multi-line operator disclosure keeps its real newline bytes. `Box<dyn Error>`'s `Display`
/// forwards to the inner error's `Display`. `run_deploy` has one caller, and every value it returns
/// as `Err` routes through this function, regardless of the error's type or the source of its
                                                                                                  
/// enumerate, no completeness claim to maintain. The render half; `main`'s best-effort stderr write
/// + `exit(1)` is the wiring half (coverage gap: the main wiring is not process-spawn asserted).
fn render_fatal(e: &dyn std::error::Error) -> String {
    format!("Error: {e}")
}

fn main() {
                                                                                     
                                                                                     
                                                                                
                                                                                     
                                                                               
                                                                                   
                                                
    if let Err(e) = orchard::deploy::dumpable::set_process_non_dumpable() {
        eprintln!(
            "warning: could not mark the process non-dumpable (PR_SET_DUMPABLE): {e} — \
             continuing (host paths hold no seed material)"
        );
    }
    let cli = Cli::parse();
    if let Err(e) = run_deploy(cli.command) {
                                                                                             
                                                                                  
                                                                                                  
                                                                                                    
                                                           
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), "{}", render_fatal(e.as_ref()));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use orchard::deploy::build_image::Firmware;

                                                                                           
    /// newlines. `render_fatal` is the render half of the chokepoint; the `Box<dyn Error>` here is
    /// the `String`-into-`Box` path (the market-upgrade arm and every `String` ceremony), whose
    /// `Display` is the string itself. Claim: Display rendering preserves newline bytes at the
    /// boundary. Coverage gap: the `main` wiring (best-effort stderr write + `exit(1)`) is not
    /// process-spawn asserted.
    #[test]
    fn render_fatal_preserves_newlines() {
        let e: Box<dyn std::error::Error> = "first line\nsecond line".to_string().into();
        let rendered = render_fatal(e.as_ref());
        assert!(
            rendered.contains('\n'),
            "render_fatal must carry a real newline byte, got {rendered:?}"
        );
        assert!(
            !rendered.contains("\\n"),
            "render_fatal must not escape the newline to a literal backslash-n, got {rendered:?}"
        );
        assert_eq!(rendered, "Error: first line\nsecond line");
    }

                                                                                                 
    #[test]
    fn help_shows_the_group_legend() {
        let mut cmd = <Cli as clap::CommandFactory>::command();
        let help = cmd.render_long_help().to_string().to_lowercase();
        for group in ["setup", "build", "verify", "deploy", "maintain"] {
            assert!(help.contains(group), "legend missing {group}: {help}");
        }
    }

    #[test]
    fn doctor_for_boot_gate_parses_with_image() {
                                                                                                     
        let cli = Cli::try_parse_from([
            "orchard",
            "doctor",
            "--for",
            "boot-gate",
            "--image",
            "/tmp/x.img",
        ])
        .expect("`doctor --for boot-gate --image` must parse");
        match cli.command {
            OrchardCmd::Doctor {
                for_verb, image, ..
            } => {
                assert_eq!(for_verb.as_deref(), Some("boot-gate"));
                assert_eq!(image.as_deref(), Some(std::path::Path::new("/tmp/x.img")));
            }
            _ => panic!("expected the Doctor variant"),
        }
    }

    #[test]
    fn doctor_rejects_a_bogus_scope() {
        assert!(
            Cli::try_parse_from(["orchard", "doctor", "--for", "bogus"]).is_err(),
            "an out-of-set --for must fail at parse (fail-closed value_parser)"
        );
    }

    #[test]
    fn status_requires_ssh_identity() {
                                                                                       
        let cli = Cli::try_parse_from([
            "orchard",
            "status",
            "box.example",
            "--ssh-identity",
            "/k/id",
        ])
        .expect("`status <host> --ssh-identity` must parse");
        match cli.command {
            OrchardCmd::Status {
                host,
                ssh_identity,
                port,
                image,
                ..
            } => {
                assert_eq!(host, "box.example");
                assert_eq!(ssh_identity, std::path::PathBuf::from("/k/id"));
                assert_eq!(port, 22);
                assert!(image.is_none());
            }
            _ => panic!("expected the Status variant"),
        }
                                                                             
        assert!(
            Cli::try_parse_from(["orchard", "status", "box.example"]).is_err(),
            "--ssh-identity is REQUIRED (I-6)"
        );
    }

    #[test]
    fn rotate_key_requires_both_identities() {
                                                                                                        
        let cli = Cli::try_parse_from([
            "orchard",
            "rotate-key",
            "box.example",
            "--new-identity",
            "/k/new",
            "--ssh-identity",
            "/k/cur",
        ])
        .expect("both identities parse");
        match cli.command {
            OrchardCmd::RotateKey {
                host,
                new_identity,
                ssh_identity,
                port,
                ..
            } => {
                assert_eq!(host, "box.example");
                assert_eq!(new_identity, std::path::PathBuf::from("/k/new"));
                assert_eq!(ssh_identity, std::path::PathBuf::from("/k/cur"));
                assert_eq!(port, 22);
            }
            _ => panic!("expected the RotateKey variant"),
        }
                                                    
        assert!(
            Cli::try_parse_from([
                "orchard",
                "rotate-key",
                "box.example",
                "--ssh-identity",
                "/k/cur"
            ])
            .is_err(),
            "--new-identity is REQUIRED"
        );
        assert!(
            Cli::try_parse_from([
                "orchard",
                "rotate-key",
                "box.example",
                "--new-identity",
                "/k/new"
            ])
            .is_err(),
            "--ssh-identity is REQUIRED"
        );
    }

    #[test]
    fn prod_with_profile_and_wipe_parses_without_pubkey() {
                                                                                                   
                                                                                                        
        let r = Cli::try_parse_from([
            "orchard",
            "prod",
            "203.0.113.5",
            "--profile",
            "boxes/rezepte.toml",
            "--wipe-confirmed",
        ]);
        assert!(r.is_ok(), "must parse: {:?}", r.err());
    }

    #[test]
    fn prod_without_pubkey_or_profile_still_refuses_at_parse() {
                                                                                                          
        let r = Cli::try_parse_from(["orchard", "prod", "203.0.113.5", "--wipe-confirmed"]);
        assert!(r.is_err(), "no pubkey and no profile must fail at parse");
    }

    #[test]
    fn build_without_domain_or_profile_still_refuses_at_parse() {
        let r = Cli::try_parse_from(["orchard", "build"]);
        assert!(r.is_err(), "no domain and no profile must fail at parse");
    }

    #[test]
    fn build_accepts_the_optional_substrate_cross_check_flag() {
        let cli = Cli::try_parse_from([
            "orchard",
            "build",
            "--domain",
            "ex.com",
            "--substrate",
            "vps-kvm",
        ])
        .expect("build --substrate parses");
        match cli.command {
            OrchardCmd::Build {
                substrate,
                firmware,
                ..
            } => {
                assert_eq!(substrate.as_deref(), Some("vps-kvm"));
                assert_eq!(firmware, orchard::deploy::build_image::Firmware::Seabios);
            }
            _ => panic!("expected the Build subcommand"),
        }
                                                                    
        match Cli::try_parse_from(["orchard", "build", "--domain", "ex.com"])
            .unwrap()
            .command
        {
            OrchardCmd::Build { substrate, .. } => assert_eq!(substrate, None),
            _ => panic!("expected the Build subcommand"),
        }
    }

    #[test]
    fn restore_image_parses_db_owner_and_defaults() {
        let cli = Cli::try_parse_from([
            "orchard",
            "restore-image",
            "--data",
            "/b/data-1.tar.gz",
            "--db",
            "/b/db-1.sqlite",
            "--operator-pubkey",
            "/k/op.pub",
            "--db-owner",
            "100:100",
            "--out",
            "/tmp/restore-1.persist.img",
        ])
        .expect("`restore-image` with --db-owner must parse");
        match cli.command {
            OrchardCmd::RestoreImage {
                db_owner,
                root,
                db_target,
                ..
            } => {
                assert_eq!(db_owner, Some((100, 100)));
                assert_eq!(root, "recipes", "default tenant root");
                assert_eq!(db_target, "recipes.db", "default db target");
            }
            _ => panic!("expected the RestoreImage subcommand"),
        }
                                                                                 
        for bad in ["nonsense", "100", "100:", ":100", "-1:100", "100:1x"] {
            assert!(
                Cli::try_parse_from([
                    "orchard",
                    "restore-image",
                    "--data",
                    "/d",
                    "--db",
                    "/d2",
                    "--operator-pubkey",
                    "/k",
                    "--out",
                    "/o",
                    "--db-owner",
                    bad,
                ])
                .is_err(),
                "accepted --db-owner {bad:?}"
            );
        }
    }

    #[test]
    fn prod_restore_min_ctr_requires_restore_from() {
                                                                                                   
                                      
        assert!(
            Cli::try_parse_from([
                "orchard",
                "prod",
                "--pubkey",
                "/k/op.pub",
                "--ssh-identity",
                "/k/id",
                "--image",
                "/i/r.img",
                "--wipe-confirmed",
                "--restore-min-ctr",
                "7",
                "203.0.113.5",
            ])
            .is_err(),
            "--restore-min-ctr without --restore-from must refuse"
        );
        let cli = Cli::try_parse_from([
            "orchard",
            "prod",
            "--pubkey",
            "/k/op.pub",
            "--ssh-identity",
            "/k/id",
            "--image",
            "/i/r.img",
            "--wipe-confirmed",
            "--restore-from",
            "/b/restore-1.persist.img",
            "--restore-min-ctr",
            "7",
            "203.0.113.5",
        ])
        .expect("the restore pair parses");
        match cli.command {
            OrchardCmd::Prod {
                restore_from,
                restore_min_ctr,
                ..
            } => {
                assert_eq!(
                    restore_from.as_deref(),
                    Some(std::path::Path::new("/b/restore-1.persist.img"))
                );
                assert_eq!(restore_min_ctr, Some(7));
            }
            _ => panic!("expected Prod"),
        }
    }

    #[test]
    fn parse_install_to_rejects_smuggling_and_accepts_bare_device() {
                                                                                                      
                                                                                                   
                                                                                                         
                                                                                                            
        assert!(parse_install_to("nvme0n1").is_ok());
        assert!(parse_install_to("sda").is_ok());
        assert!(parse_install_to("mmcblk0").is_ok());
        assert!(parse_install_to("nvme0n1 ima_appraise=off").is_err());                                
        assert!(parse_install_to("sda\"").is_err());         
        assert!(parse_install_to("SDA").is_err());             
        assert!(parse_install_to("").is_err());         
    }

    #[test]
    fn build_installer_usb_parses_from_and_install_to() {
        let cli = Cli::try_parse_from([
            "orchard",
            "build-installer-usb",
            "--from",
            "/out/recipes-image-deadbeef.img",
            "--install-to",
            "nvme0n1",
        ])
        .expect("`build-installer-usb --from --install-to` must parse");
        match cli.command {
            OrchardCmd::BuildInstallerUsb {
                from, install_to, ..
            } => {
                assert_eq!(from, PathBuf::from("/out/recipes-image-deadbeef.img"));
                assert_eq!(install_to.as_deref(), Some("nvme0n1"));
            }
            _ => panic!("expected the BuildInstallerUsb subcommand"),
        }
    }

    #[test]
    fn build_installer_usb_install_to_is_optional() {
        let cli = Cli::try_parse_from(["orchard", "build-installer-usb", "--from", "/out/x.img"])
            .expect("`build-installer-usb` without `--install-to` must parse");
        match cli.command {
            OrchardCmd::BuildInstallerUsb { install_to, .. } => assert_eq!(install_to, None),
            _ => panic!("expected the BuildInstallerUsb subcommand"),
        }
    }

    #[test]
    fn sign_installer_usb_parses_img_and_defaults_to_the_software_rung() {
        let cli = Cli::try_parse_from([
            "orchard",
            "sign-installer-usb",
            "--img",
            "/out/recipes-installer-usb-deadbeef.img",
        ])
        .expect("`sign-installer-usb --img` must parse");
        match cli.command {
            OrchardCmd::SignInstallerUsb {
                img, secure_boot, ..
            } => {
                assert_eq!(
                    img,
                    PathBuf::from("/out/recipes-installer-usb-deadbeef.img")
                );
                assert_eq!(secure_boot, "software");                    
            }
            _ => panic!("expected the SignInstallerUsb subcommand"),
        }
    }

    #[test]
    fn parse_firmware_accepts_all_three_wire_tokens_and_fails_closed() {
                                                                                                       
        assert_eq!(parse_firmware("seabios").unwrap(), Firmware::Seabios);
        assert_eq!(parse_firmware("seabios-gpt").unwrap(), Firmware::SeabiosGpt);
        assert_eq!(parse_firmware("uefi").unwrap(), Firmware::Uefi);
        assert!(parse_firmware("bogus").is_err());
        assert!(parse_firmware("").is_err());
    }

    #[test]
    fn parse_upgrade_target_resolves_every_leg_incl_rust_and_all() {
        use orchard::deploy::market_upgrade::Target;
                                                                                                              
        match parse_upgrade_target(None, Some("fb-acme".into()), None, false, None, None, false) {
            Ok(Target::Binary(k)) => assert_eq!(k, "fb-acme"),
            other => panic!("--binary must resolve to Target::Binary, got {other:?}"),
        }
        match parse_upgrade_target(None, None, None, false, None, Some("1.97.0".into()), false) {
            Ok(Target::Rust(v)) => assert_eq!(v, "1.97.0"),
            other => panic!("--rust must resolve to Target::Rust, got {other:?}"),
        }
        match parse_upgrade_target(None, None, None, false, None, None, true) {
            Ok(Target::All) => {}
            other => panic!("--all must resolve to Target::All, got {other:?}"),
        }
                                                                 
        match parse_upgrade_target(
            None,
            None,
            Some("dha-epa-config".into()),
            false,
            None,
            None,
            false,
        ) {
            Ok(Target::Config(k)) => assert_eq!(k, "dha-epa-config"),
            other => panic!("--config must resolve to Target::Config, got {other:?}"),
        }
                                                                              
        assert!(
            parse_upgrade_target(None, None, None, false, None, Some("1.97.0".into()), true)
                .is_err()
        );
    }
}
