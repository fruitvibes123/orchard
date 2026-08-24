# Orchard — image-building guide

How to build a box `.img` with Orchard, end to end: prerequisites, one-time setup, the build
command, how to verify the result, the build variants, and how to keep the pins fresh.

Orchard is the operator-host build/deploy factory. `orchard build` turns the operator key set plus a
set of pinned inputs into the box image triple. The box is an immutable distro (read-only
squashfs + dm-verity + IMA/EVM + an operator-signed `.img`); this guide covers producing that image,
not deploying it (deploy is `orchard prod`, out of scope here).

> This public tree is an exported copy of the operator's canonical repo — see the README's
> provenance note for what that means.

> Run every command below **from the orchard repo root** unless
> stated otherwise. The CLI is shown as `cargo run -p orchard -- <cmd>`; for repeated builds compile a
> release binary once (`cargo build --release -p orchard`) and call `./target/release/orchard <cmd>`.

---

## 1. What you are building

`orchard build` produces, in the output directory (default `/tmp`):

| File | What it is |
|------|------------|
| `recipes-image-<sha>.img` | the disk image (boot-fs ‖ persist-skeleton ‖ rootfs). `<sha>` is the clean HEAD commit; a `--allow-dirty` build is named `<sha>-dirty`. |
| `recipes-image-<sha>.layout.toml` | the partition/offset layout — needed to slice the image and recompute the verity root hash. |
| `recipes-image-<sha>.sha256` | the image checksum. |
| `…vmlinuz`, `…initramfs` | the kernel + initramfs sidecars, written beside the `.img` (the kexec/boot inputs). |
| `…operator-pubkey.fpr` | (only with `--operator-pubkey`) the `SHA256:…` fingerprint of the baked login key, used by `orchard prod` preflight. |
| `…loader.efi`, `…sign-manifest.toml` | (only with `--firmware uefi`) the unsigned rambutan loader PE + the digest manifest that `orchard sign-sb` consumes. |
| `…img.sig`, `…vmlinuz.sig`, `…initramfs.sig` | (only when an artifact-signing key set is present) the ed25519 detached signatures. |

A full build takes roughly **14 minutes** (most of it the from-source kernel compile).

---

## 2. Prerequisites

**Host toolchain**

- `rustup` with the pinned stable toolchain. `rust-toolchain.toml` selects it automatically
  (currently `1.96.0`, see `pins.toml [rust]`). For UEFI builds and `make verify`, add the loader
  target once: `rustup target add x86_64-unknown-uefi`.
- `git` — repo + worktree operations (`market store status` enumerates every worktree). Source
  tarballs are fetched and pin-verified **in-Rust** by `orchard prime` / `make prime` — no `curl`/
  `tar`/`xz` host tooling is needed for source acquisition (the pre-2026-07 fetch scripts are
  retired).
- `openssh` (`ssh-keygen`) — operator pubkeys are derived, never copied.

**Docker** — the musl + kernel builds run inside the pinned `recipes-imgbuild:dev` container, never on
the host (host builds would leak root-owned bind-mount artifacts). You need a working `docker` you can
invoke. `/tmp` needs ~15–20 GB free for one build.

**For local boot verification** (`orchard dryrun`, `make boot-gate`) — `/dev/kvm` plus
`qemu-system-x86_64`, `veritysetup` (cryptsetup), `ssh`, `curl`, `fakeroot`, and `mke2fs` (e2fsprogs)
on the host.

**For UEFI / Secure Boot** (only if you build `--firmware uefi`) — `OVMF`/edk2 firmware blobs,
`sbsign` (sbsigntool, in the container), and `virt-fw-vars` for the enrolled-VARS gate.

---

## 3. The input supply chain

```
  pins.toml ────────────────┐   (kernel / syslinux / rust versions + sha256)
                            │
  orchard prime ────────────┤   linux-<ver>.tar.xz       ──► /tmp/recipes-kbuild/
  (fetch+verify+stage)      │   syslinux-<ver>.tar.xz    ──► /tmp/recipes-syslinux/
                            │   (re-verified at consumption; bake extracts fresh)
                            │
  orchard generate-keys ────┤   7-file operator key set  ──► ~/.config/recipes-deploy/keys
                            │
  artifact-store/ ──────────┤   pinned binaries + service-manifest (fetched + sha256-verified)
  vendor/ ──────────────────┘   pinned source drops (grape/dragonfruit/fb-manifest/rambutan)
                            │
                            ▼
                     orchard build  ──►  recipes-image-<sha>.{img,layout.toml,sha256} (+ sidecars)
                  (runs in recipes-imgbuild:dev)
```

Two things make this a *pinned* supply chain:

- **`pins.toml`** is the central version manifest for the kernel, syslinux, and rust toolchain (version
  + sha256). It is the one place to bump those; `orchard sync-pins` propagates the rust pin into
  `rust-toolchain.toml` and the container `FROM`.
- **`consume-pins.toml`** lists every artifact the bake pulls from the operator **artifact store** —
  the in-image binaries (recipes-app, fb-*, box-init, the dha tenant's
  creatine-serve/dha-orchestrator/epa, …), the service-manifest, and the vendored source drops — each
  by sha256 (16 artifacts: 11 binary / 4 source / 1 config, across 6 owning repos). The bake verifies
  every input against this and **refuses on mismatch or absence**. The shas are copied from each owning
  repo's `published-pins.toml`.

The artifact store defaults to `Projects/fruit-ecosystem/artifact-store` (i.e. `<orchard>/../artifact-store`);
override with `FRUIT_ARTIFACT_STORE`. All the owning repos publish to the same default path.

---

## 4. One-time setup

Do these once (and after a relevant pin bump). If the artifact store and `vendor/` are already
populated in your checkout, you can skip §4.4.

### 4.1 Build the build container

The Containerfile has no `COPY`, so the build context is irrelevant:

```sh
docker build -t recipes-imgbuild:dev -f crates/image-builder/Containerfile crates/image-builder
```

This bakes the exact toolchain the bake shells out to (mksquashfs, veritysetup, evmctl, cpio, mke2fs,
extlinux, mformat, sbsign, the rust target, kernel makedepends). The built image's digest is the
authoritative anchor — a mirror moving a pinned apk makes `docker build` fail loudly; bump
intentionally.

### 4.2 Bootstrap the operator key set

```sh
cargo run -p orchard -- generate-keys
```

Writes the 7-file set to `~/.config/recipes-deploy/keys` (override with `--output-dir`): a
CA→leaf ECDSA-P256 hierarchy (image-signing + signing-CA + the IMA/EVM leaf) plus the 32-byte
rescue-seed master key. It also writes your cert fingerprints into the committed
`crates/image-builder/pinned-cert-fingerprints.toml` (the build's by-construction rescue-seed anchor).

> **Gotcha:** because `generate-keys` rewrites a tracked file, your tree is now dirty and the next
> clean build will refuse. **Commit** `pinned-cert-fingerprints.toml` (it pins *your* keys), or use
> `--allow-dirty` for throwaway local builds. Add `--subject "<ou>"` to stamp an operator OU into
> every cert DN. Use `--force` to overwrite an existing set.

Optional — to emit ed25519 artifact signatures on the build outputs, also provision the artifact
key set (additive; safe to run over an existing cert set):

```sh
cargo run -p orchard -- generate-keys --artifact-signing software
```

> **Redelegate-before-build (update path).** A fresh key set mints all six purpose
> delegations, including `UpdateImage`/`RootHash`. Any artifact key set minted **before**
> the OS-update path (including the live box's) lacks those two — and since `orchard build`
> bakes the `UpdateImage` delegation's `monotonic_ctr` as the image's `min_delegation_ctr`,
> **every** build/sign on such a set fails closed with an actionable error. The one-command
> fix mints them over your EXISTING root (box trust anchor unchanged — no rebake, no
> reinstall):
>
> ```sh
> cargo run -p orchard -- redelegate            # both update-path delegations
> ```
>
> Run it once per pre-update-path key set, before the next `orchard build` or
> `orchard update`. Re-running later is safe (it supersedes with a fresh issuance ctr,
> never a lower one). A wrapped (docker-rung) set prompts for its passphrase.

### 4.3 Prime the pinned kernel + syslinux source

```sh
make prime          # or: cargo run -p orchard -- prime
```

Fetches `linux-<pins.toml version>.tar.xz` + `syslinux-<version>.tar.xz`, verifies each against its
pinned sha256 (full liblzma decode + full-consumption assert), and stages the `.tar.xz` at
`/tmp/recipes-kbuild/` + `/tmp/recipes-syslinux/` (override with `--kbuild-dir`/`--syslinux-dir`).
This is the ONE network step — `orchard build` stays offline and **re-verifies both tarballs at
consumption**, extracting a fresh per-build tree (the bake never trusts the prime, and never sees an
unverified archive). The box kernel is built from source because `CONFIG_MODULES=n` + the
IMA/EVM/verity built-ins + forced lockdown require it.

### 4.4 Populate the artifact store and vendor the source drops

The bake pulls pinned binaries + the service-manifest from the artifact store, and compiles the
vendored source drops from `vendor/`.

**This public checkout ships `vendor/` populated and pinned** — the four source drops
(grape/dragonfruit/fb-manifest/rambutan) are committed, and `consume-pins.toml`'s `*-src` rows
assert exactly these bytes (the bake re-verifies them at every start), so no store or vendoring
step is needed for the source-compiled parts. Re-vendoring (`orchard vendor`) is a pin-bump flow
that expects the owning repos' publish tooling (operator-side, not part of the public trees).

**Binaries are yours to build and publish.** The public fruit-basket and seed-vault repos hold
the full source; clone them side by side (fruit-basket's crates path-dep seed-vault as a sibling
checkout). Build each fruit-basket binary as a musl release inside the pinned container (§4.1),
then publish it into your local store and re-pin its consume-pins key in one step:

```sh
docker run --rm -v "$PWD/..:/eco" -w /eco/fruit-basket recipes-imgbuild:dev \
  cargo build --release --target x86_64-unknown-linux-musl -p fb-acme
cargo run -p orchard -- market upgrade --binary fb-acme \
  --build-dir ../fruit-basket/target/x86_64-unknown-linux-musl/release
# repeat per key: fb-oneshots fb-backup fb-cert-check fb-update fb-mark-good fb-weights
#                 box-init initramfs-init
```

This is the general shape; a crate can carry its own feature/target requirements — each crate's
`Cargo.toml` is authoritative.

**The app tenant is bring-your-own.** The reference tenant (a private web app) is not published.
The box hosts one application backend declared by the service-manifest — the `fb-manifest` crate
in the public fruit-basket repo defines the schema, and the fruit-basket WHITEPAPER describes the
contract. Build any musl binary that serves the manifest's edge backend, publish it under the app
consume-pins key (`market upgrade --binary … --build-dir …`), author your manifest, and publish
it (`market upgrade --config service-manifest`).

The dha co-tenant trio (`creatine-serve`/`dha-orchestrator`/`epa`) comes from private provider
repos; a default single-tenant box does not bake them (`market verify --all` is the operator-side
check that expects all 16 artifacts).

> If a publish changes an artifact, re-pin its sha in `consume-pins.toml` (copy from the owning
> repo's `published-pins.toml`, or let `market upgrade` write it) before building — the bake
> refuses a stale pin.

---

## 5. Build the image

The minimal build (SeaBIOS, reference recipes tenant, no baked login key):

```sh
cargo run -p orchard -- build --domain box.example.com
```

A realistic production-shaped build:

```sh
cargo run -p orchard -- build \
    --domain box.example.com \
    --operator-pubkey ~/.ssh/id_ed25519.pub \
    --recovery-pubkey ~/.ssh/recovery_ed25519.pub \
    --net 'mode=static;ip=203.0.113.10/24;gw=203.0.113.1;dns=9.9.9.9' \
    --out-dir ~/images
```

### Build flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--profile <path>` | none | a named box's whitelist TOML (`boxes/<name>.toml`) supplying `domain`/`net`/`keys_dir`/`out_dir` VALUES (see §5.1). Relaxes the clap-required `--domain`, re-enforced fail-closed post-merge. Deploy-only keys in it are ignored with a printed note. |
| `--domain <d>` | *(required unless `--profile`)* | deployment domain, baked into the in-image haproxy cert path. RFC-1123 validated. |
| `--out-dir <dir>` | `/tmp` | output directory for the image triple. |
| `--keys-dir <dir>` | `~/.config/recipes-deploy/keys` | the operator key set from `generate-keys`. |
| `--ksrc <file>` | `/tmp/recipes-kbuild/linux-<pin>.tar.xz` | staged kernel source tarball (`orchard prime`; re-verified at consumption). |
| `--syslinux-src <file>` | `/tmp/recipes-syslinux/syslinux-<pin>.tar.xz` | pinned syslinux tarball. |
| `--container-image <ref>` | `recipes-imgbuild:dev` | the pinned build container. |
| `--operator-pubkey <path>` | placeholder | the box's everyday login key (persist-skeleton). Derive-not-cat. |
| `--recovery-pubkey <path>` | placeholder | the rescue dropbear's key (in-rootfs, works when `/persist` is unmountable). |
| `--net <token>` | none → rescue/link-only | one whitespace-free `mode=…` token baked as `fb.net=` (e.g. `mode=static;ip=…;gw=…;dns=…`). |
| `--firmware seabios\|seabios-gpt\|uefi` | `seabios` | boot firmware (see §7). Also DERIVES the deploy substrate (see §5.2). |
| `--substrate <s>` | none | OPTIONAL cross-check — assert the firmware-derived substrate (`vps-kvm` for the BIOS firmwares, `bare-metal-uefi` for `uefi`). Agrees or aborts naming both; never selects (see §5.2). |
| `--secure-boot` | off | UEFI only — bake `SB_REQUIRED=true`; sign afterward with `sign-sb`. |
| `--manifest <path>` | pinned recipes tenant | build a custom service topology (see §7). |
| `--allow-dirty` | off | build from a dirty tree; taints the name `<sha>-dirty`. |
| `--verify` | off | determinism self-test — builds **twice** and slice-compares (see §6). |

On success you'll see:

```
deploy build: wrote /tmp/recipes-image-<sha>.img (+ .layout.toml + .sha256); verity root hash <hex>
  artifact signing: … (signed → …  |  built UNSIGNED)
```

The build refuses early and loudly if a precondition is unmet — missing keys, missing kernel/syslinux
source, a dirty tree without `--allow-dirty`, a stale `orchard` binary, or a tampered/absent pinned
input. See §9.

### 5.1 Profiles — build a named box without retyping its flags

A **profile** is a small whitelist TOML that carries a box's stable build values so you type one
intent, not a flag wall. `orchard build --profile boxes/rezepte.toml` supplies `domain`, `net`,
`keys_dir`, and `out_dir`; a flag you ALSO pass on the command line WINS over the profile (flag >
profile > built-in default). The schema is a strict whitelist (`deny_unknown_fields`) — an unknown key
is a hard parse error, so a typo is loud, not silent.

Two rules keep it safe:

- **Destructive intent can NEVER come from a profile.** `wipe_confirmed` (or any destructive key) in a
  profile is refused at load. The wipe gate is a live operator keystroke, always.
- **A required value missing from BOTH flag and profile is a fail-closed refusal** that names both
  sources (e.g. "domain is required — pass `--domain` or set `domain` in the profile"), before any
  build or deploy action.

A profile is operator-side (a committed `boxes/<name>.toml` in your own repo is the intended home) —
never baked into a shipped artifact. `prod` takes `--profile` too (it adds the connection keys —
`ip`/`port`/`operator_pubkey`/`ssh_identity`/…); `build` ignores those deploy-only keys with a printed
note, so a mistyped expectation is visible, never silently dropped.

A named box's whole deploy then collapses to one intent — the profile carries the connection keys, and
the destructive wipe stays a live flag you type every time (it can never live in the profile):

```sh
orchard prod 203.0.113.5 --profile boxes/rezepte.toml --wipe-confirmed
```

### 5.2 Substrate — where the box will run

The **substrate** is DERIVED from `--firmware`: the two BIOS firmwares (`seabios`, `seabios-gpt`) run
on a KVM/virtio guest (`vps-kvm` — the production substrate), and `uefi` targets real bare-metal
(`bare-metal-uefi`). You never select the substrate directly; `--firmware` decides it.

The substrate drives the **full kernel-config gating**: a `vps-kvm` kernel FORBIDS the USB host/storage
driver stack (unused attack surface — a re-introduction fails the build, backed by a fail-closed
`CONFIG_USB`-prefix guard that also catches a *new* USB driver a kernel bump adds), while a
`bare-metal-uefi` kernel force-sets + asserts that stack present (it boots off USB media). The shed is
deliberately **USB-only**: the disk transports (SCSI/ATA/NVMe/virtio-scsi/BLK_DEV_SD) are force-set +
pinned on BOTH substrates, so the box boots on any KVM hypervisor's disk — virtio-blk, virtio-scsi,
NVMe, or emulated SATA. The produced `.layout.toml` records the chosen substrate. Pass `--substrate <s>` to cross-CHECK the
firmware-derived value — it agrees or aborts naming both; it is a belt-and-braces assertion, never an
override.

### 5.3 Watching a build

`orchard build` streams the container output with a phase banner + a running elapsed stamp at each
bake boundary (`=== squashfs (+123s) ===` …), ending on a `=== build complete (total Ns) ===`
capstone — structure over the existing stream, nothing hidden. On a TTY, `orchard prime` shows a
per-tarball fetch banner + cumulative-MiB progress; piped/headless output is unchanged.

### 5.4 Deploy staging — the raw tail window (streaming install)

`orchard prod` does **not** copy the `.img` as a file onto the target. It streams the
(sentinel-patched) image over SSH straight onto a **raw byte window at the tail of the target
disk** — below the GPT backup and below every range the install writes — then re-verifies the
staged siblings and the window with cache-bypassing reads (`iflag=direct`), composes the kexec
append (window coordinates + the **mandatory** image digest + the layout token), and fires. The
post-kexec installer re-validates the window's geometry and digest **before any destructive
write** and chunk-copies window → partitions with per-component `O_DIRECT` readbacks. Peak RAM is
O(8 MiB chunk) on **both** sides — an image larger than the target's RAM installs fine (the old
whole-image RAM preflight is retired; only a fixed 256 MiB installer floor remains).

**The two honest costs, stated plainly:**

- **The point of no return moves to "staging begun".** The window sits in the doomed Debian's
  free space while Debian is live — "any pre-kexec abort leaves the old system bootable" weakens
  to *probable* once staging begins. Recovery from any staging mishap = re-stage (idempotent,
  same window) or, worst case, the provider re-provision that is already this ceremony's
  documented prerequisite.
- **The disk-tail cost:** persist must be able to hold a full image copy during install — the
  staged window occupies `image_size` bytes of what becomes the persist partition's tail. The
  space is **reclaimed as ordinary free space after the first-boot grow** (ext4 never reads
  unallocated blocks; the residue is your own image's bytes).

**Diagnosis rule (window contention):** a ceremony that repeatedly aborts at the installer's
pre-table digest check *after clean staging readbacks* means the live Debian's allocation or
writeback is landing inside the tail window. The failure is fail-closed DoS, never silent —
remedy: a bigger disk, a smaller image, or re-provision. (Gross cases are refused up front by
the free-space advisory: an old root fs with less free space than the window aborts pre-staging.)

---

## 6. Verify the image

`make verify` proves only the **seam contract** (parsers, golden configs, unit logic) — **zero
produced bytes**. It is not a deploy-green. Verify the actual image with one of these:

### Readiness check — `orchard doctor`

Before a build or deploy, `orchard doctor` answers "am I ready?" — a READ-ONLY sweep of the
preconditions (the operator key set, the pinned kernel/syslinux source, the build container, `docker`
+ `/dev/kvm` for the gates, the artifact store). It is **advisory**: it always exits 0 (never a gate),
every unmet check names its concrete cure, and a probe that cannot run reports "could not check"
rather than a false pass.

```sh
cargo run -p orchard -- doctor                 # the full readiness sweep
cargo run -p orchard -- doctor --for build     # scope to one verb's prerequisites
cargo run -p orchard -- doctor --for boot-gate --image <img>   # incl. an env skeleton to export
```

`--for <verb>` narrows the report to `build` / `dryrun` / `prod` / `boot-gate`; the `boot-gate` scope
ends with the exact `RECIPES_*` env the gate needs so you can copy-paste it.

### Quick boot smoke — `orchard dryrun`

Boots a pre-built image under QEMU/KVM and asserts the runtime contract (dropbear accepts the
operator key, recipes answers, `/` is read-only):

```sh
cargo run -p orchard -- dryrun --image /tmp/recipes-image-<sha>.img      # boot a pre-built image
cargo run -p orchard -- dryrun --domain box.test                         # or build first, then boot
cargo run -p orchard -- dryrun --image <img> --keep-running              # leave the VM up for poking
```

### Produced-bytes proof — `make boot-gate`

The full SeaBIOS install → boot → rescue + crash-recovery chain on the real image. This is the gate
that has repeatedly caught what static review missed. It needs docker + `/dev/kvm` and the built
image(s) in the environment:

```sh
RECIPES_DRYRUN_IMG=<img> \
RECIPES_PROD_IMG=<img>   RECIPES_PROD_PRIVKEY=<key> \
RECIPES_RESCUE_IMG=<img> RECIPES_RESCUE_PRIVKEY=<key> \
make boot-gate
```

(The dryrun leg takes only `RECIPES_DRYRUN_IMG`; prod/rescue each also need their `_PRIVKEY`. The
`deploy_prod_e2e` leg additionally needs `RECIPES_PROD_E2E_DEBIAN_IMG` + `cloud-localds`.) The
gates panic if run without their env, so a run never silently false-greens.

### Determinism self-test — `orchard build --verify`

```sh
cargo run -p orchard -- build --domain box.test --verify
```

Builds twice over identical inputs and slice-compares the three components, printing a per-component
verdict. Roughly doubles build time. This proves the build *process* is deterministic for one
operator; it does not prove integrity (only an independent rebuilder closes that gap).

### Supply-chain fail-fast — `make repro-check`

Re-verifies every vendored source drop's sha256 and the verify-at-consumption gate. Cheap; run it
before trusting `vendor/`.

---

## 7. Build variants

**SeaBIOS vs UEFI** — `--firmware seabios` (default; Infomaniak is BIOS-only) or `--firmware uefi`
(the rambutan Secure Boot loader path, OVMF-boot-proven; production on real UEFI hardware is
substrate-gated). UEFI builds emit the extra `loader.efi` + `sign-manifest.toml` sidecars.

**Secure Boot** — build `--firmware uefi --secure-boot`, then Authenticode-sign the loader + kernel and
splice them into the ESP:

```sh
cargo run -p orchard -- sign-sb --img <uefi-img>
```

This requires the SB PK/KEK/db family (`generate-keys --secure-boot software`) and the matching
enrolled keys on the target. See the `boot-gate-uefi` target header in the `Makefile` for the full
OVMF gate env.

**Custom tenant** — `--manifest <path>` builds a non-recipes service topology from a TOML manifest
(the §5.3 fail-closed schema; a malformed or privilege-escalating manifest is refused at bake). See
`crates/image-builder/toy-tenant.toml` for a minimal worked example. Omitting `--manifest` builds the
pinned recipes reference tenant, byte-identical to today's box.

**Network** — `--net 'mode=static;ip=<cidr>;gw=<gw>;dns=<dns>'` bakes the static-IPv4 config. Omit it
and the box diverts to rescue/link-only. `mode=dhcp` parses but fail-closes at bring-up (documented
seam).

**Artifact signing** — if an artifact key set is present in `--keys-dir`, the build emits ed25519
`.sig` sidecars for the `.img`/vmlinuz/initramfs automatically; otherwise it builds UNSIGNED and says
so. Provision the keys with `generate-keys --artifact-signing software` (§4.2).

---

## 8. Maintenance — bumping pins

**The market triad — the primary maintenance flow.** Three verbs cover the pin-freshness
lifecycle; each leg does the mechanical work and leaves you the reviewable diff:

| verb | question it answers | semantics |
|------|---------------------|-----------|
| `orchard market verify` | is the pin store consistent + authentic right now? | the fail-closed gate (`make verify` runs it) |
| `orchard market outdated` | what has drifted / will 404? | advisory report; `--exit-drift` = a CI/cron nag (an unreachable mirror still exits 0); `--all-packages` = the whole closure |
| `orchard market upgrade --<leg>` | fix it | stage → staged `market verify` → swap → the consent gate |

Pinned apks age off dl-cdn on a clock (the mirror garbage-collects superseded revisions), so any
pinned box eventually hits `linux-virt: HTTP 404`-class drift: `market outdated` names it before a
build does, and a failed build's apk-404 error names the drift + the cure itself. `market upgrade
--apks --dry-run` previews the outcome (the pinned→mirror-current moves) before the container
re-resolution; `--container-image` defaults to the digest-pinned build container from `pins.toml`.

After a green swap, `market upgrade` shows the diff surface (`git diff --stat` per repo) plus a
commit message composed from the pin-file deltas, then asks `commit the orchard paths? [y = commit /
e = edit the message / N = print the command]` —
`--commit` (alias `--yes`) pre-authorizes, `--no-commit` never commits, and a headless run (CI,
cron, piped) NEVER commits: it prints the ready `git commit` command instead. The commit covers
ONLY orchard's swapped paths (pathspec-scoped — a dirty index is never swept in); sibling repos
get their ready `git -C <sibling> commit` printed, never run; store blobs are never a git target.

The manual procedures below remain the fallback / inner mechanism:

**Kernel / syslinux / rust** (`pins.toml`):

1. Edit the version + sha256 under `[kernel]` / `[syslinux]` / `[rust]`.
   - kernel: re-pin from kernel.org's signed sha256sums.
   - syslinux: re-pin over the upstream tarball (a major bump also needs the
     `Testing/<major.minor>/` URL segment updated in `SYSLINUX_ORG_BASE`,
     `crates/image-builder/src/sources.rs` — the retired fetch script's URL, typed).
   - rust: re-pin `container_digest` via `docker manifest inspect rust:<maj>.<min>-alpine`.
2. `cargo run -p orchard -- sync-pins` — regenerates `rust-toolchain.toml` + the container `FROM`.
3. `make verify` — the drift-check confirms every consumer agrees.
4. Re-fetch the source (§4.3) and rebuild the container (§4.1) for kernel/syslinux/rust bumps.

> Kernel bumps need UEFI-compat re-grounding (V1–V4 config symbols are arch + version sensitive).
> `make verify` is blind to this — re-check against the new kernel source and an OVMF boot.

**apk closure** (`crates/image-builder/pinned-apks.toml`): edit `apk-world.toml`, then
`cargo run -p orchard -- refresh-apk-lock` (resolves the closure in the container), and commit the diff.

**Consumed artifacts** (`consume-pins.toml`): after an owning repo's `make publish`, copy the new sha
from its `published-pins.toml`, then `make vendor` for source drops.

**Key rotation**: `generate-keys --force` (or `--regenerate-master-key` for just the rescue seed);
`update-cert-fingerprints` recomputes the pinned fingerprints after a signing-key rotation. Commit the
resulting pin diffs.

**Store maintenance — the content-addressed layout.** The shared artifact store is
content-addressed: every publish writes an additive `<key>@<sha256(bytes)>` revision blob
alongside (while the dual-write transition holds) the legacy flat `<key>` alias. This is what makes
parallel publishes safe by construction — a second worktree publishing a different revision of the
same key can never clobber the first (the incident this closes: a 2026-07-07 dha-branch publish
silently overwrote another stream's expected bytes under the old flat layout). Three verbs, all
advisory/maintenance — never a `market verify` leg:

| verb | question it answers | semantics |
|------|---------------------|-----------|
| `orchard market store status` | what's in the store, and is anything unreferenced? | a worktree-aware reference scan (orchard's own `consume-pins.toml` + every manifest repo's `published-pins.toml`, across EVERY `git worktree list` checkout of each, not just the primary); read-only, always exit 0 |
| `orchard market store prune [--delete]` | can I reclaim unreferenced revisions? | consent-gated: the flag-less default only PRINTS candidates (the dry run); `--delete` removes them — but REFUSES outright, deleting nothing, if the reference scan found ANY problem (an absent repo, unreadable pins, a stale/prunable worktree entry) |
| `orchard market store migrate` | bring an old flat-only store onto the CAS layout | hardlinks (copies on a cross-filesystem store) every alias to its `<key>@sha256(bytes)` revision name; idempotent, keeps the flats |

**Blind spot (read the `status` output's note):** the scan enumerates git **worktrees** of each
manifest repo — a plain directory *copy* of a repo (not a `git worktree add` checkout) is invisible
to it. Keep-all (never running `prune --delete`) is the safe posture around such copies; `status`
names every checkout it actually scanned.

**Transition note (un-migrated / dual-write stores):** `status` classifies *revisions* against the
pins; flat aliases are listed but not content-checked, so a stale or divergent alias — the pre-CAS
incident shape — is invisible to `status` alone. To audit one, run `migrate` first (the alias bytes
then exist as a revision, and divergent bytes surface as UNREFERENCED), or run `market verify`,
which re-hashes the store bytes your own checkout's pins resolve, fail-closed.

**The dual-write alias is a transition, not the permanent shape.** It exists so pre-CAS binaries
(old parallel-worktree publishes) keep working unmodified. Retiring it (flip
`DUAL_WRITE_FLAT_ALIAS` to `false` in `artifact_store.rs`, delete the alias branch + the prune
alias guard) is a named follow-up, gated on the dha and bench streams rebasing past this cycle —
do not flip it before then.

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `signing keys not found at …; run 'orchard generate-keys'` | §4.2 not done (or wrong `--keys-dir`). |
| `kernel source not found at …` | run §4.3 (or pass `--ksrc`). |
| `syslinux source tarball not found at …` | run §4.3 (or pass `--syslinux-src`). |
| `git working tree is dirty` | commit/stash, or `--allow-dirty`. Usually the `generate-keys` fingerprint write (§4.2) — commit it. |
| `orchard was compiled from commit … but HEAD is …` (STALE binary) | `cargo run` recompiles automatically after a commit; if it persists, `cargo build -p orchard`, or `--allow-dirty` (downgrades to a warning). |
| `vendor/ integrity: … expected >= 4` / sha mismatch | `vendor/` is stale or tampered — `make vendor`; if a pin moved, re-pin `consume-pins.toml`. |
| `config-virt not found in the pinned linux-virt apk` | the apk closure is stale — `refresh-apk-lock`. |
| `docker build` fails on an apk version | a mirror superseded a pinned patch — bump the version in the Containerfile intentionally. |
| `No space left on device` during cargo/kernel build | `/tmp` filled (needs ~15–20 GB). Clear leaked root-owned tempdirs: `docker run --rm -v /tmp:/t recipes-imgbuild:dev sh -c 'rm -rf /t/.tmp*'`. |

### 9.1 Reclaim-tail manual disarm (rows `R-ARMED` / `R-DISARM`)

A `--reclaim-tail` deploy that fails and reports the target "may still be armed" (rows `R-ARMED` or
`R-DISARM`) left an initramfs hook on the target that re-runs the disk shrink on the next boot. The
ceremony normally disarms it automatically; these rows mean it could not (the target was unreachable,
or the disarm did not verify). This is the procedure the failure text points here for. Disarm by
hand, on the target, in three steps — **all three are required**:

1. Remove the two installed files:
   - `rm -f /etc/initramfs-tools/hooks/orchard-reclaim`
   - `rm -f /etc/initramfs-tools/scripts/local-premount/orchard-reclaim`
2. Rebuild the initramfs so the removal takes effect. The running system's initrd still carries a
   baked copy of the script; deleting the source files alone does nothing until a rebuild:
   - `update-initramfs -u -k all`
3. Verify the script is gone from every built initrd, failing CLOSED if an initrd cannot be read (an
   empty glob or an `lsinitramfs` error must NOT read as clean — that is the positive control the
   automated disarm carries, `post.rs` `DISARM_VERIFY_CMD`; a bare `grep -c … = 0` prints `0` when
   the listing failed, and `R-DISARM` is exactly the unreadable-initrd case):
   ```
   for f in /boot/initrd.img-*; do
     [ -e "$f" ] || { echo "$f: NO INITRD -> treat as ARMED"; continue; }
     lsinitramfs "$f" >/tmp/ls-$$ 2>/dev/null || { echo "$f: lsinitramfs FAILED -> treat as ARMED"; continue; }
     grep -q local-premount/orchard-reclaim /tmp/ls-$$ && echo "$f: STILL ARMED" || echo "$f: clean"
   done; rm -f /tmp/ls-$$
   ```
   Every line must read `clean`. Any `ARMED` line means the target is not disarmed.

Do NOT reboot the box until every line reads `clean`. Deleting the two files without step 2 leaves
the already-built initrd armed: it re-runs `e2fsck` + `resize2fs` on the next boot, unattended.

Access: on an `R-ARMED` or unreachable target ssh may be down, so reach the box over your provider's
serial console or VNC (the channel `orchard prod` names for first contact). Every step above is local
to the target.

---

## 10. Command reference

| Command | Purpose |
|---------|---------|
| `orchard doctor [--for <verb>] [--image <img>]` | read-only readiness check ("am I ready?"); advisory, always exits 0 (§6). |
| `orchard generate-keys [--artifact-signing …] [--secure-boot …]` | bootstrap the operator / artifact / SB key sets. |
| `orchard prime [--kbuild-dir …] [--syslinux-dir …]` | fetch + verify + stage the pinned kernel/syslinux source (§4.3). |
| `orchard build --domain <d> [--profile <p>] [--firmware …] [--substrate <s>] …` | build the image triple (this guide; §5.1–5.2). |
| `orchard dryrun [--image <img>]` | boot + verify the runtime contract under QEMU. |
| `orchard sign-sb --img <uefi-img>` | Authenticode-sign + splice the UEFI PEs into the ESP. |
| `orchard build-installer-usb --from <img>` | assemble the signed-USB installer image (the UEFI Secure-Boot install path). |
| `orchard sign-installer-usb --img <usb-img>` | db-sign the installer loader + splice into the USB ESP. |
| `orchard sign-backup <file>` | sign a pulled backup / restore image with the artifact worker key. |
| `orchard restore-image --data … --db … --operator-pubkey … --out …` | assemble the daily pair into a signed-ready persist image (§11). |
| `orchard vendor` | fetch + verify + unpack the pinned source drops into `vendor/`. |
| `orchard sync-pins [--check]` | propagate `pins.toml` into the format-locked files. |
| `orchard refresh-apk-lock` | regenerate `pinned-apks.toml` from `apk-world.toml`. |
| `orchard market store status [--all] [--full]` | the CAS reference scan — healthy bulk collapses to a count, anomalies itemize (see below). |
| `orchard market store prune [--delete] [--full]` | reclaim unreferenced revisions (consent-gated; refuses on any scan doubt). |
| `orchard update-cert-fingerprints …` | recompute pinned cert fingerprints after a rotation. |
| `orchard derive-rescue-offline --image <img>` | derive the box's runtime host key for `known_hosts`. |
| `orchard prod …` | greenfield kexec-takeover install onto a VPS (deploy; out of scope here). |
| `orchard prod … --restore-from <image> [--restore-min-ctr <N>]` | the same takeover, restoring `/persist` from a signed image (§11). |
| `make verify` | seam contract (no produced bytes). |
| `make boot-gate` | produced-bytes proof on the real image. |
| `make vendor` / `make repro-check` | populate vendor / supply-chain fail-fast. |

**Report convention.** The advisory/report surfaces (`market store status`/`prune`, `restore-image`'s
staged manifest) collapse the HEALTHY bulk to a count and ALWAYS itemize the anomalies (unreferenced
revisions, foreign entries, owner deviations, a tar-smuggled `authorized_keys`), rendered columnar with
sha digests ABBREVIATED to 12-hex (git-style, display-only — the full sha still drives every prune /
integrity decision). `--all` itemizes the healthy bulk too; `--full` restores the 64-hex digests;
`restore-image --manifest-full` dumps every staged file.

For the authoritative flag set, see `cargo run -p orchard -- <cmd> --help` and the source under
`crates/orchard/src/`. The gate discipline lives in the `Makefile` headers.

## 11. Backup + restore

The box's `fb-backup` emits a daily pair — `data-<ts>.tar.gz` (the tenant tree) + `db-<ts>.sqlite`
(the app database) — which you pull off-box. Restoring means assembling that pair into a signed
persist **ext4 image** the installer dd's in place of the persist skeleton; the box never extracts
an archive (the dd-only rule).

1. **The daily pull** — fetch the pair off the box (scp) and keep it with your other pulls. Keep the
   originals: they carry the true mtimes (see item 7) and are the input for any future re-assembly.

2. **Assemble a restore image after each pull** (the standing drill):

   ```
   orchard restore-image --data data-<ts>.tar.gz --db db-<ts>.sqlite \
       --operator-pubkey ~/.ssh/box_operator.pub --out restore-<ts>.persist.img
   orchard sign-backup restore-<ts>.persist.img
   ```

   Keep the image + `.sig` beside the pulls. Assembling daily surfaces a non-assemblable or
   ambiguous-ownership backup within a day of its creation — not at disaster-recovery time. The
   printed staging manifest is your reviewable audit trail: a per-top-level-directory rollup (count +
   size) PLUS always-itemized anomaly rows — the db target, any tar-smuggled `authorized_keys`, and
   every entry whose owner deviates from the resolved db-owner (`--manifest-full` dumps every staged
   file). The printed `monotonic_ctr` line is the future `--restore-min-ctr` value (item 5).

3. **The restore ceremony** is the greenfield takeover plus one flag:

   ```
   orchard prod --image <img>.img --pubkey ~/.ssh/box_operator.pub \
       --restore-from restore-<ts>.persist.img [--restore-min-ctr <printed-ctr>] \
       --wipe-confirmed <ip>
   ```

   Five local preflight legs run BEFORE any remote contact: the `.sig` exists, the signature
   verifies (printing the bundle's `monotonic_ctr`), the image carries the persist identity
   (LABEL `persist`, journal-absent, ext4), the operator key STAGED INSIDE the image matches
   `--pubkey` (a mismatched key would restore a box you cannot log into), and the file names pass
   the staging guards. A restore with NO artifact-signing pin in force ABORTS — an unverified
   restore never rides (the box hard-requires the `.sig` anyway).

4. **Schema-forward review:** a restore image assembled from an OLD backup rides into a
   NEW app version; the app's migrations run forward on first boot. Review the app's migration
   notes between the backup's origin version and the image you install — schema-forward is
   supported, schema-BACKWARD (an old app over a new db) is not.

5. **Stale-restore caveat + the printed counter (§6e):** any validly-signed backup restores by
   default — including an old one (a "rollback" to yesterday's data is a FEATURE of disaster
   recovery). If you specifically want to refuse anything older than your latest assembly, pass
   `--restore-min-ctr <the printed ctr>`: the box refuses a bundle whose delegation counter is
   below the floor, inside its own verify.

6. **Tenant-uid caveat:** the manifest's tenant uid is baked into the backup's
   ownership. If the tenant uid CHANGES between the backup's origin image and the restore target,
   prior backups' ownership is invalid (first-boot `setup-dirs` normalizes only the top-level
   dir) — re-assemble with an explicit `--db-owner <uid>:<gid>` + an ownership review after any
   uid change. The reference tenant's daily tar is EXPECTED-UNIFORM (the app writes `ca.crt` as
   the tenant uid), so the assembler's uniform-owner default normally just works and its
   fail-loud on ambiguity is the exception path, not the norm.

7. **mtime note (§3c):** restored files carry the fixed bake epoch, not their original
   timestamps — the assembly is deterministic by construction. Original mtimes live in the
   retained daily tars; one more reason the pulls are kept, not rotated away after assembly.

## 12. OS self-update (A/B, seabios-gpt) — `orchard update`

Push a new OS image to a **running** seabios-gpt box without reinstalling. The box streams it to the
inactive A/B slot, one-try-boots it, health-probes, and commits-or-auto-rolls-back — two anti-rollback
floors refuse downgrades. **seabios-gpt only**; an MBR box migrates once via the GPT takeover +
restore-from, then updates this way.

**Prerequisites (once per key set):** the UpdateImage delegation must exist — run `orchard redelegate`
(§4.2) for any key set predating the update path. Build the update image with an explicit, **ratcheting**
per-stream serial: `orchard build … --image-version <N>` (bump N whenever a ship supersedes — a kernel
bump OR any userspace/CVE change; the box refuses a pushed image whose version ≤ its floor, and so does
`orchard update`'s own preflight, before it streams). Sign the build's triple as usual (the
software/docker rung). `orchard update` also needs **`veritysetup`** on the operator host — it derives
the box's post-flip runtime host key from the image (below), and fails closed with a naming message if
it is absent.

```sh
# First contact to a box is a NON-SILENT bootstrap: run it interactively (you confirm the box's SSH
# host key, which pins it), or pass --host-fingerprint <SHA256:…> for a scripted first contact.
cargo run -p orchard -- update box.example.org \
    --image out/recipes-image-<sha>.img \
    --identity ~/.ssh/box_operator \
    [--host-fingerprint SHA256:…]        # explicit pin for a non-interactive first contact
```

`--host-fingerprint` is not first-contact-only: when a pin already exists it is ALSO checked against
the key the box presents, and a value that disagrees is a hard refusal (a wrong-host guard). Because
the pin ROTATES to the image-derived key on every COMMITTED (below), a fleet loop must NOT keep
passing the fingerprint it first bootstrapped with — it would mismatch after the first update. Pass it
only to bootstrap first contact, or recompute it per run from the currently-installed image.

The ceremony (8 steps, all fail-closed, never auto-retries): [1] verifies the build's `.sig` triple
locally (refuses an unsigned build) and derives the image's post-flip runtime host key, cross-checked
against the signed `root_hash`; [2] reads the target's baked `image_version`/firmware + `root_hash`;
refuses a non-seabios-gpt image, and refuses a push at or below the box's floor (a re-push / a forgotten
`--image-version` bump) before streaming; [3] connects under the persisted host-key pin
(`~/.config/recipes-deploy/host-pins/`, verified + **refuse-silent-override** on an UNEXPLAINED key
change — even `--confirmed` cannot re-pin one) and reads `fb-update status`; [4] composes the signed
manifest; [5] asks you to **authorize** (y/N; `--confirmed` for a scripted fleet loop — never silent);
[6] signs with the UpdateImage delegation (fails closed with a "run `orchard redelegate`" message if
absent); [7] streams to the box's `fb-update apply` (the box has no scp — the frame rides ssh stdin);
[8] watches → prints **COMMITTED** / **ROLLED-BACK** / **UNREACHABLE** with an honest exit code.

The A/B flip rotates the box's runtime host key by construction (the key is image-derived), so the
watch authenticates the flipped box under the pushed image's derived key — a COMMITTED verdict is
therefore proof the box is running the pushed image (the peer booted it), not a self-reported version
number. The derived key identifies the IMAGE, not the box — two same-version boxes share it — which is
why the target host is fixed in step 3 under the durable pin, not by the key alone. On COMMITTED the
durable pin is **superseded** to that derived key automatically (the old pin archived beside it as
`<host>.superseded-<hex>`, the hex a digest of the old fingerprint); this is the ONE deliberate,
evidence-based re-pin, categorically apart
from the refused unexplained key change. A COMMITTED whose pin could not be rotated still prints
COMMITTED but exits non-zero and prints a WARNING — the next contact would otherwise refuse against the
stale pin.

- **ROLLED-BACK** means the box is serving the OLD version — the new slot failed its probation (a
  panic, a bad verity hash, or an unhealthy tenant) and auto-rolled back, OR the push never armed.
  Either way the box is unharmed. Investigate the image, don't retry blindly.
- **UNREACHABLE** means the box did not return a settled status under either the pre-push pin or the
  pushed image's key within the watch window. Two shapes, and the message distinguishes them: if the
  box was reachable on its PRE-PUSH key with a live probation record, fb-mark-good is still deciding
  (it can ride its full uptime deadline before rolling back) — the pin is NOT stale, re-run `orchard
  status` to read the settled verdict. Otherwise the box was not reached under either key — a slow
  boot, a stuck retry loop on the armed slot (the M1 residual), or a host-key mismatch; if it
  committed slowly past the deadline its key has rotated and the stored pin is stale, and the message
  names the derived fingerprint to re-pin to. Check the box's out-of-band console.

## 13. Key rotation

The box's trust rests on several key families with DIFFERENT rotation paths — most "rotate the keys"
needs are a one-command worker re-delegation, NOT a root rotation. Pick the row you need.

### 13.1 The key families

| Family | Where it lives | Referenced by | A rotation invalidates |
|---|---|---|---|
| Artifact ed25519 ROOT (cold) + its Backup / UpdateImage / RootHash delegations | `<keys-dir>/artifact-root.pub` + the delegation bundles; the box bakes `/etc/recipes/artifact-root.pub` | the committed `pinned-artifact-root.toml`; every `.sig` on `.img` / backup / update artifacts | every signature the box will accept — a new root needs a fresh image (the box verifies against its BAKED anchor) |
| ECDSA-P256 X.509 set (image-signing, IMA) | `<keys-dir>` (rcgen) | `pinned-cert-fingerprints.toml`; the kernel's baked CA | the IMA / image-signing chain — a rebake |
| `rescue-seed-master.key` (the rescue-host-key IKM) | `<keys-dir>/rescue-seed-master.key` | the derived `<host>-rescue` host key | the rescue known_hosts pin for every box built from it |
| SSH login keys (operator + baked recovery) | operator: your `~/.ssh/…`; recovery: baked into the image | the box's `authorized_keys.d/root` (operator) + the rescue path (recovery) | box login — operator live, recovery needs a rebake |

### 13.2 Worker rotation (routine — no box interaction)

Re-mint the update-path delegations over the EXISTING root with `orchard redelegate`. When: a delegation
window is expiring, or worker-key hygiene. This is the rotation the key cascade gives for free, and what
most "rotate the keys" needs actually are — the box trust anchor is untouched, so no rebake and no deploy.

### 13.3 Root rotation — the takeover path (the ONLY supported root rotation today)

Whether precautionary or a response to a SUSPECTED ROOT COMPROMISE, the mechanism is the same. The box
verifies an incoming update against its CURRENTLY-baked anchor, so no live update can install a manifest
chained to a new root; the greenfield takeover deliberately does NOT verify (the install-TCB ceiling),
which here works FOR you — the box is reinstalled from scratch under the new root with zero dependency on
the old anchor. When the root is COMPROMISED (not merely being cycled) the takeover is not just supported
but REQUIRED: any live-continuity path would honour attacker-reachable trust for one more hop.

1. Mint a fresh root into a NEW keys dir (never overwrite the old in place): `orchard generate-keys
   --artifact-signing` with a new `--output-dir`.
2. Build a fresh image (it bakes the NEW `artifact-root.pub`).
3. **Under the NEW keys dir, FIRST** assemble + sign the restore bundle: `orchard restore-image
   --operator-pubkey <login.pub>` (stage the operator pubkey out-of-band), then `orchard sign-backup`
   under the new root. `prod`'s five-leg preflight fail-closes if the bundle `.sig` does not chain to the
   new anchor, so this MUST precede the takeover.
4. Take over the box: `orchard prod --restore-from <image>` (add `--restore-min-ctr <N>` to pin the
   anti-rollback floor). `/persist` is recovered from the backup, not carried in place — schedule a fresh
   backup + a maintenance window.
5. Confirm the flip: `orchard status --keys-dir <new>` shows the box now presents the NEW `anchor_sha256`
   — the ONLY supported confirmation the takeover took hold.
6. THEN update operator-side trust: commit the new `pinned-artifact-root.toml`, run `orchard
   update-cert-fingerprints` if the X.509 set also rolled, re-sign retained backups with `orchard
   sign-backup` under the new root, and retire the old keys dir.

**Deferred:** live, no-reinstall trust-continuity rotation — do NOT hand-splice a directory of
new-anchor/old-signer files to fake it on the box's most critical key material. It is not performable with
existing verbs (there is no verify-pin/signing-key split on `orchard update`, and no operator re-sign
verb), and it is gated on the PIPELINE re-owning root custody.

### 13.4 `master.key` (rescue IKM) rotation

Rotate the rescue-seed master key through the orthogonal `orchard generate-keys --regenerate-master-key`
mode; it forces a `<host>-rescue` known_hosts refresh for every box built from it. NOTE artifact-root
rotation (13.3) does NOT touch the rescue IKM, so it forces no rescue-known_hosts churn on its own.

### 13.5 SSH login-key rotation

Rotate the operator LOGIN key with `orchard rotate-key <host> --new-identity <new> --ssh-identity
<current>`. It DERIVES the new authorized line from `--new-identity` (never a `--pubkey`), appends it
(both keys valid), verifies the new key authenticates, then removes the old one — every abort leaves a
working login. INTERACTIVE-ONLY (no scripted path; a passphrase may prompt on the terminal — a
passphrase-protected identity must be `ssh-add`-loaded, since the edit sessions run under `BatchMode`).
Two refused cases and their manual fixes:

- **The box's `authorized_keys` is not a shape it recognizes** (an extra/unknown key): it REFUSES rather
  than delete a key you did not expect — edit the file over your existing session, then re-run.
- **The new private key lives on ANOTHER machine:** transfer it to the machine you run from first, or run
  `rotate-key` from the machine that holds it — v1 derives the pubkey locally, so both keys must be present.

### 13.6 Restore interaction

A `orchard prod --restore-from` takeover authorizes the operator pubkey the ceremony STAGES out-of-band
(`orchard restore-image --operator-pubkey`), NOT one carried in the backup tar — but the daily backup also
captures `/persist/etc`, so a pre-rotation backup can re-introduce pre-rotation key state depending on the
assembler's precedence. Conservative posture: after any `--restore-from`, re-run `orchard rotate-key` if
the intended login state differs from what the staged pubkey established.
