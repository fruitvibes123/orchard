                                                                                     
//! `MarketSub`/`StoreSub` + their value-parser helpers, relocated from `main.rs` into the lib so
                                                                                                 
//! compiler-total over this surface. The binary keeps only `Cli::parse()` + dispatch. No surface
//! change: the relocation is help-output byte-identical (oracle capture at the move).

use std::path::PathBuf;

use crate::ceremony::Utf8PathBuf;
use clap::Parser;

#[derive(Parser)]
#[command(name = "orchard", version, about = "Recipes box build/deploy factory")]
#[command(after_help = "COMMAND GROUPS (lifecycle order):\n  \
    setup     generate-keys · prime · vendor · derive-rescue-offline · update-cert-fingerprints — bootstrap keys + fetch pinned sources\n  \
    build     build · dryrun · build-installer-usb — produce + locally boot-test the .img\n  \
    verify    doctor · verify (market verify) — readiness + supply-chain checks\n  \
    deploy    prod · sign-sb · sign-installer-usb · sign-backup · restore-image — ship to the box\n  \
    maintain  market (outdated/upgrade/store) · refresh-apk-lock · sync-pins — keep the pins current")]
pub struct Cli {
    /// Override the repo root (context chain: flag > profile > env > context file > CWD default).
    #[arg(long, global = true, value_name = "DIR")]
    pub repo_root: Option<Utf8PathBuf>,
    /// Override the artifact store (chain as --repo-root; the env leg is $FRUIT_ARTIFACT_STORE).
    #[arg(long, global = true, value_name = "DIR")]
    pub artifact_store: Option<Utf8PathBuf>,
    /// Override the repo-manifest path (chain as --repo-root; default <repo root>/repo-manifest.toml).
    #[arg(long, global = true, value_name = "FILE")]
    pub repo_manifest: Option<Utf8PathBuf>,
    /// Read the context file from this path instead of
    /// <config base>/recipes-deploy/orchard-context.toml (XDG-first config base).
    #[arg(long, global = true, value_name = "FILE")]
    pub context: Option<Utf8PathBuf>,
    /// Print the resolved context (each value with its source) and exit without running the verb.
    #[arg(long, global = true)]
    pub print_context: bool,
    #[command(subcommand)]
    pub command: OrchardCmd,
}

#[derive(clap::Subcommand)]
                                                                                                  
                                                                                            
                                                                                                  
                                                                                                    
                                                                                                   
                                                                                                   
#[allow(clippy::large_enum_variant)]
pub enum OrchardCmd {
    /// Walk the install ceremony as a guided parameter interview (guided-ceremony C2): query each
    /// parameter with its explanation, default and live validation, write the box profile, show
    /// what the run will do, authorize once, then execute uninterrupted. Re-running over the same
    /// profile asks only what is still owed.
    #[command(display_order = 4)]
    Guide {
        /// The box profile to write and then run (`boxes/<name>.toml`). Created when absent.
        profile: Utf8PathBuf,
        /// The operator-ratified declared-space directory (§1.4); default `boxes/repo-form/`.
        /// Forwarded to the guided child `run`, so a directory ratified with `orchard admit
        /// --repo-form-dir <dir>` is the one the guided run compares against.
        #[arg(long, value_name = "DIR")]
        repo_form_dir: Option<Utf8PathBuf>,
    },
    /// Run the install ceremony over a saved box profile (guided-ceremony C3): admit, then walk
    /// the spine in order, skipping every step whose product this profile's records already
    /// bind. Judgment values are re-decided every run and destructive authorization is typed
    /// here, never carried by the profile.
    #[command(display_order = 5)]
    Run {
        /// The box profile (`boxes/<name>.toml`).
        profile: Utf8PathBuf,
                                                                                      
        /// required when the run still owes a destructive step.
        #[arg(long, value_name = "IP_OR_HOST")]
        target: Option<String>,
        /// The per-stream monotonic image serial — a judgment value, re-supplied every run that
                                       
        #[arg(long)]
        image_version: Option<u64>,
                                                                                     
        #[arg(long)]
        commit: bool,
        /// Confirm the WHOLE-DISK erase the install step performs; forwarded verbatim, composed
                       
        #[arg(long)]
        wipe_confirmed: bool,
        /// Emit line-oriented porcelain records instead of human output; children are piped and
                                       
        #[arg(long)]
        porcelain: bool,
        /// The operator-ratified declared-space directory (§1.4); default `boxes/repo-form/`. The
        /// gate compares each named checkout's git configuration against `<dir>/<checkout>.keys`
        /// (every scope-qualified key; the value at the program-valued keys git executes inside
        /// the gate's commands).
        #[arg(long, value_name = "DIR")]
        repo_form_dir: Option<Utf8PathBuf>,
    },
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
                                                                   
        /// prints last. Human output may interleave; consumers select lines by the locked
        /// kind prefixes.
        #[arg(long)]
        porcelain: bool,
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
        /// Mint the ed25519 artifact-signing key set (the operator MENU, Spec 2 §3):
        /// `software` = root+worker+6 delegations on this host; `docker` = the same
        /// ceremony inside the pinned imgbuild container (keygen-environment isolation);
        /// `one-signer`/`two-signers` = hardware rungs (route to the 1C device ceremony,
        /// C4 — not available in this host-only build). Every rung emits the same cascade
        /// bundle. Additive: skips cert (re)gen when a cert set already exists.
        #[arg(long, value_parser = ["software", "docker", "one-signer", "two-signers"], conflicts_with = "regenerate_master_key")]
        artifact_signing: Option<String>,
        /// Validity window (days) for the software-rung delegations (default 365).
        /// The window is the rung's service life — expiry fails preflight for every
        /// artifact — so it defaults long; expiry is a planned re-key (Spec 2 §3).
        #[arg(long, default_value_t = 365)]
        delegation_window_days: u64,
                                                                                      
        /// artifact key set to --output-dir — no cert bootstrap, no committed-pin write
        /// (the in-container repo is read-only; the host writes the pin after). Used with
        /// --artifact-signing software (raw seeds) OR docker (passphrase-wrapped seeds,
        /// reading the passphrase from this container's -it TTY, echo off).
        #[arg(long, hide = true, requires = "artifact_signing")]
        artifact_keys_only: bool,
        /// Mint the Secure Boot PK/KEK/db RSA family instead of the main set (SB-loader
        /// plan Task 4.1; spec §6): `software` (keys on host — the floor), or
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
    /// Phase 5a: read-only box inspection + drift comparison. Talks only operator↔box over the pinned
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
    /// Phase 5a: rotate the operator SSH LOGIN key with a never-locked-out invariant. Derives the new
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
        /// `IN_CONTAINER_KEYS_DIR` const so it can't drift from the mount target.
        #[arg(long, default_value = crate::deploy::artifact_keys::IN_CONTAINER_KEYS_DIR)]
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
    /// Task 4.2; spec §6.2). SB rungs only — SB-off rungs never run this. Inputs: the
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
    /// If an artifact key set is present (`--artifact-signing`, Spec 2 §3), the build additionally
    /// emits ed25519 `.sig` sidecars for the `.img`/vmlinuz/initramfs; otherwise it builds UNSIGNED
                                                                         
    #[command(display_order = 20)]
    Build {
                                                                   
        /// prints last. Human output may interleave; consumers select lines by the locked
        /// kind prefixes.
        #[arg(long)]
        porcelain: bool,
        /// A named box's profile (`--profile boxes/<name>.toml`): supplies `domain`/`net`/`keys_dir`/
        /// `out_dir` VALUES; deploy-only keys in it are ignored with a printed note. Relaxes the
        /// clap-required `--domain` (re-enforced fail-closed post-merge). Whitelist-parsed (spec §7).
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
                                                                                              
        #[arg(long)]
        container_image: Option<String>,
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
                                                                                                 
        /// flag > profile merge.
        #[arg(long, value_parser = parse_firmware)]
        firmware: Option<crate::deploy::build_image::Firmware>,
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
                                                                                                  
        #[arg(long)]
        image_version: Option<u64>,
        /// Hotswap v4: how a weights build anchors the model — `boot` (the dha fb.weights-*
        /// cmdline triple, the default) or `runtime` (NO cmdline; a Purpose::Weights-signed
        /// record baked at /persist/weights/current + the engine fb-weights setup prelude).
        #[arg(long, value_enum, default_value_t = WeightsAnchorArg::Boot)]
        weights_anchor: WeightsAnchorArg,
                                                                                              
        /// the flag-class totality arm reddens under `ceremony-seed-unclassified-flag`.
        #[cfg(feature = "ceremony-seed-unclassified-flag")]
        #[arg(long)]
        ceremony_seed_unclassified: bool,
                                                                                                
        /// env var — a process-env input that changes produced bytes is a build parameter).
        /// Re-hashed against the models.toml pin fail-closed at bake. Omit ⇒ a non-dha build.
        #[arg(long, value_name = "GGUF")]
        dha_weights_gguf: Option<PathBuf>,
        /// The projector GGUF (replaces RECIPES_DHA_MMPROJ_GGUF). Omit ⇒ the pinned file name
        /// resolved beside --dha-weights-gguf. Pin-verified either way.
        #[arg(long, value_name = "GGUF", requires = "dha_weights_gguf")]
        dha_mmproj_gguf: Option<PathBuf>,
    },
    /// Task 4.3 (spec §3): assemble the operator's daily backup pair (fb-backup data tar + db
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
        /// against its --pubkey — spec §5-4).
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
    /// and splice it next with `deploy sign-installer-usb`. The 2-stage SB-on OVMF gate (Phase 6) is
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
    /// USB's p1 ESP (spec §8). SB rungs only. Reuses the already-`sign-sb`-signed kernel; recomputes
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
    /// Greenfield kexec-takeover install onto a freshly-provisioned Debian VPS (Plan 3.4v2
    /// Phase 4.2): local preflight → Leg-A pinned connect → discovery → wipe gate → stage +
    /// verify → kexec the installer → reconnect pinned to the image-DERIVED runtime host key →
    /// crypto-identity verify. DESTRUCTIVE: erases the target's WHOLE disk.
    #[command(display_order = 40)]
    Prod {
                                                                   
        /// prints last. Human output may interleave; consumers select lines by the locked
        /// kind prefixes.
        #[arg(long)]
        porcelain: bool,
        /// Target IP (or lowercase hostname) of the provisioning Debian.
        ip: String,
        /// A named box's profile (`--profile boxes/<name>.toml`): supplies stable identity VALUES
        /// (paths + public pins), never intent. Relaxes the clap-required `--pubkey`/`--ssh-identity`
        /// (a fail-closed post-merge check re-enforces them); the wipe intent + typed target stay
        /// yours. Whitelist-parsed — an unknown or destructive key refuses (Component 5 / spec §7).
        #[arg(long)]
        profile: Option<PathBuf>,
        /// The operator's box-login PUBKEY. Preflight-verified against the image's baked
        /// `<stem>.operator-pubkey.fpr` sidecar — a key mismatch aborts before anything runs.
        /// Required unless a `--profile` supplies `operator_pubkey` (re-enforced fail-closed post-merge).
        #[arg(long, required_unless_present = "profile")]
        pubkey: Option<PathBuf>,
        /// Deploy this prebuilt `.img` (its sidecars + vmlinuz/initramfs must sit beside it).
        /// Absent ⇒ build inline first (requires a domain via --domain or the profile's
        /// `domain` key, exactly like `deploy build`
                                                                              
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
        /// The PRE-KEXEC login user (default: the substrate cloud user `debian`). The ceremony
        /// connects as this user and sudos the privileged steps, so a provider restriction on the
        /// root key never bites; `root` skips the sudo wrapper. The post-install reconnect is
        /// unaffected — that leg is the box's own dropbear.
        #[arg(long, value_name = "USER")]
        provisioning_user: Option<String>,
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
        /// D-2 reclaim-tail (spec 2026-07-28-reclaim-tail-design v19): when D-1 refuses (the
        /// staging window intersects the grown root), run the consent-gated offline shrink so
        /// the window lands in unpartitioned space. Its own token — --wipe-confirmed does not
                     
        #[arg(long)]
        reclaim_tail: bool,
        /// Override the reclaim reboot-poll bound (default 1800 s; spec §5.8).
        #[arg(long)]
        reclaim_timeout_secs: Option<u64>,
                                                                                                 
        /// Deployment domain (inline build only; the profile's `domain` key is the second
        /// source).
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
                                                                                              
        #[arg(long)]
        container_image: Option<String>,
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
        /// Override the reclaim reboot-poll bound (default 1800 s; spec §5.8).
        #[arg(long)]
        reclaim_timeout_secs: Option<u64>,
        /// The PRE-KEXEC login user (default: the substrate cloud user `debian`); `root` skips
        /// the sudo wrapper.
        #[arg(long, value_name = "USER")]
        provisioning_user: Option<String>,
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
                                                                   
        /// prints last. Human output may interleave; consumers select lines by the locked
        /// kind prefixes.
        #[arg(long)]
        porcelain: bool,
        /// The artifact store dir (folds into the context chain's flag tier; a disagreeing global
        /// --artifact-store refuses; default per the chain: profile > $FRUIT_ARTIFACT_STORE >
        /// context file > <repo root>/../artifact-store).
        #[arg(long)]
        store: Option<Utf8PathBuf>,
    },
                                                                                                
    /// fetch-*.sh). This is the NETWORK step, sited next to `vendor`; the bake re-verifies both
    /// tarballs at consumption, so `orchard build` stays fully offline.
    #[command(display_order = 11)]
    Prime {
                                                                   
        /// prints last. Human output may interleave; consumers select lines by the locked
        /// kind prefixes.
        #[arg(long)]
        porcelain: bool,
        /// Staging dir for the kernel `.tar.xz` (default /tmp/recipes-kbuild).
        #[arg(long, default_value = crate::deploy::build_image::DEFAULT_KBUILD_DIR)]
        kbuild_dir: PathBuf,
        /// Staging dir for the syslinux `.tar.xz` (default /tmp/recipes-syslinux).
        #[arg(long, default_value = crate::deploy::build_image::DEFAULT_SYSLINUX_DIR)]
        syslinux_dir: PathBuf,
    },
    /// Ratify a box's declared space (§1.5): measure each named checkout's git configuration
    /// (every scope-qualified key; the value at the program-valued keys git executes inside the
    /// gate's commands), print the diff against the ratified files, and write them only after an
    /// explicit typed authorize. Never runs a ceremony; a ceremony never writes the declared space.
    #[command(display_order = 12)]
    Admit {
        /// The box profile whose checkouts are ratified (`boxes/<name>.toml`).
        #[arg(long = "box", value_name = "PROFILE")]
        box_profile: Utf8PathBuf,
        /// The declared-space directory to write into; default `boxes/repo-form/`.
        #[arg(long, value_name = "DIR")]
        repo_form_dir: Option<Utf8PathBuf>,
    },
    /// The pin-store tool (`market`): `verify` (the always-on, fail-closed `make verify` gate that
    /// consolidates the sha256 supply-chain pin checks) + `upgrade` (the staged, all-or-nothing
    /// orchestrator of a pin bump). Spec: 2026-06-22-pin-store-market-design.md.
    #[command(display_order = 50)]
    Market {
        #[command(subcommand)]
        sub: MarketSub,
    },
                                                                                             
    /// `ceremony-seed-unclassified-verb` feature makes the classification match non-exhaustive
                                                                        
    #[cfg(feature = "ceremony-seed-unclassified-verb")]
    CeremonySeedUnclassified,
}

/// `market <sub>` — the pin-store tool's two subcommands.
#[derive(clap::Subcommand)]
pub enum MarketSub {
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
                                                                   
        /// prints last. Human output may interleave; consumers select lines by the locked
        /// kind prefixes.
        #[arg(long)]
        porcelain: bool,
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
        /// Pre-authorize the one-stop commit (spec §6.1): after the verified swap, commit orchard's
        /// swapped paths with the composed message, no prompt. `--yes` = alias. This is the ONLY
        /// non-interactive commit path — a headless run without it never commits.
        #[arg(long, alias = "yes", conflicts_with = "no_commit")]
        commit: bool,
        /// Never commit — print the ready `git commit` command instead (an explicit opt-out beats
        /// everything; combining it with `--commit` is a usage error). The re-pin itself still runs.
        #[arg(long = "no-commit")]
        no_commit: bool,
    },
    /// Store maintenance (the content-addressed layout, spec 2026-07-08): a worktree-aware
    /// reference scan + advisory/consent-gated cleanup. Never a `market verify` leg.
    Store {
        #[command(subcommand)]
        sub: StoreSub,
    },
}

/// `market store <sub>`.
#[derive(clap::Subcommand)]
pub enum StoreSub {
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
pub enum WeightsAnchorArg {
    /// The dha boot-anchored shape (fb.weights-* cmdline). The pre-v4 default.
    Boot,
    /// Hotswap v4: runtime dm-verity from the persisted signed record (no fb.weights-* token).
    Runtime,
}

/// `orchard redelegate --purpose`: which update-path delegation(s) to mint.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum RedelegatePurposeArg {
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
    crate::deploy::build_image::validate_domain(s)
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
pub fn parse_firmware(s: &str) -> Result<crate::deploy::build_image::Firmware, String> {
    s.parse()
}

/// `--net` value_parser (early feedback): the `fb.net=` cmdline VALUE must be one whitespace-free
/// `mode=…` token (network spec C1). `build_image` re-validates fail-closed (the load-bearing layer);
/// box-init's `parse_net` does the full grammar/address-semantics check at boot.
fn parse_net(s: &str) -> Result<String, String> {
    crate::deploy::build_image::validate_net(s)
}

/// `--install-to` value_parser (§9.5): the whole-disk override is baked VERBATIM into
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::build_image::Firmware;

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
    fn parse_firmware_accepts_all_three_wire_tokens_and_fails_closed() {
                                                                                                       
        assert_eq!(parse_firmware("seabios").unwrap(), Firmware::Seabios);
        assert_eq!(parse_firmware("seabios-gpt").unwrap(), Firmware::SeabiosGpt);
        assert_eq!(parse_firmware("uefi").unwrap(), Firmware::Uefi);
        assert!(parse_firmware("bogus").is_err());
        assert!(parse_firmware("").is_err());
    }
}
