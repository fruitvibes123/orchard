# Guided install quickstart

`orchard guide` installs fruit-basket, the appliance OS ("the box"), on one VPS for one application.
It asks for each parameter, builds the image, boots it under QEMU (the boot gate) and installs it
over the VPS's Debian. [`orchard_guide.md`](../orchard_guide.md) runs the same steps by hand (§4 to
§6) and covers the build variants, the pins, backup and restore, the OS update and key rotation.

> [!IMPORTANT]
> Ceremony steps 4 to 6 need inputs this release does not ship, so the ceremony does not complete on
> a public checkout:
>
> - An artifact store at `../artifact-store` holding the fruit-basket binaries and the four source
>   drops (`grape-src`, `dragonfruit-src`, `fb-manifest-src`, `rambutan-src`). Step 4 runs
>   `orchard vendor` from it and refuses without it. You build and publish the binaries from the
>   public fruit-basket repository (guide §4.4). The source drops come from the owning repositories'
>   publish tooling, which is not in the public trees.
> - The tenant's publish handoff tree at `/tmp/recipes-build-handoff`, which step 5 confirms. It
>   comes from the reference tenant `recipes`, a private web application. The image files and the
>   build container carry its name, and keep it when you bring your own application.
>
> The by-hand path completes: guide §4 to §7 with your own application manifest (§7), then
> `orchard prod <box-ip> --profile boxes/<name>.toml --wipe-confirmed` (§5.1; flags in §10), which
> is ceremony step 10. The ceremony is the reference operator's tool; making steps 4 to 6 pass on a
> public checkout is open work.

> [!NOTE]
> Self-hosting on your own hypervisor (TrueNAS, Proxmox or similar) or hardware: tooling that writes
> an installed disk image directly is in development. Until it ships, install a local target by one
> of two routes:
>
> - A VM running the Debian 13 cloud image, with Legacy BIOS boot, a virtio network device and a
>   static IPv4 address.
>   `orchard guide` installs over it as over a VPS; the [Target VPS](#target-vps) requirements
>   apply.
> - Bare metal with UEFI Secure Boot: the signed USB installer (guide §7;
>   `orchard build-installer-usb` and `orchard sign-installer-usb` in §10).

## Requirements

### Target VPS

- Provider: a commercial VPS, Hetzner Cloud or any provider of the same shape. The reference
  deployment runs on one small Infomaniak instance, and its NTP server is the baked default
  (Time).
- Image: the provider's stock Debian 13 cloud image. Debian 13's `kexec-tools` refuses an over-long
  kernel command line instead of truncating it, and the kexec safety margin rests on that. The tool
  does not check the release, so provision Debian 13.
- Login: add your SSH public key at provisioning. Debian's cloud image creates the user `debian`
  with passwordless `sudo`; Hetzner Cloud's Debian images log in as `root`. The interview asks for
  this user as `provisioning_user` (default `debian`; same profile key). `root` needs no `sudo`.
- `kexec-tools`: `apt-get install -y kexec-tools` on the VPS, under `sudo` unless the user is
  `root`. The ceremony checks for it at the install step, after the image build and the boot gate,
  and stops there if it is missing.
- Firmware: legacy BIOS. The default is `seabios`. `seabios-gpt` is the same BIOS boot on a GPT disk
  and the only layout `orchard update` (the A/B self-update without reinstall) works on, so choose
  it in the interview. UEFI is a separate path (guide §7).
- Network: one static public IPv4. The box bakes a static configuration; a DHCP or unparseable
  configuration diverts the box to its rescue branch with no address. The interview asks for the
  address with its prefix, the gateway and a DNS resolver, as the provider's panel lists them.
- Ports: the service manifest fixes them at 22 (SSH), 80 and 443; a provider firewall, if any,
  must pass those three. orchard dials the profile's `port` on Debian before the install and on the
  box after it, so it stays 22. A Debian image whose sshd listens on another port is not a
  supported target.
- Time: the clock comes from the hypervisor (kvm-clock). `ntpd` corrects it best-effort over plain
  NTP to one server baked at build, `pool.ntp.infomaniak.ch`; the egress firewall passes UDP 123.
  Plain NTP across the open internet to a server outside your own provider opens a time-tampering
  surface that authenticated NTP would close. Infomaniak's first-party server is already inside the
  reference deployment's trust base. On another provider, Hetzner included, decide whether to keep
  it; the setting is `NTP_SERVER` in `crates/image-builder/src/service_tree.rs`. Certificate
  validity is floor-gated separately and does not depend on NTP.
- Size: a small tier runs the reference tenant. `orchard prod` refuses a target with less than
  256 MiB of RAM before staging. A greenfield install copies in 8 MiB chunks, so an image larger
  than the RAM installs. The optional AI co-tenant `dha` (private repositories; a default box
  does not bake it) sets its own requirements.
- DNS: point the domain the box will serve at the VPS before the run. A box whose service manifest
  declares the certificate bootstrap hook (the reference tenant does) generates a self-signed
  certificate at first boot. `fb-acme` replaces it once the clock is past the image build epoch and
  HTTP-01 issuance over port 80 succeeds. A browser warning right after the install comes from the
  self-signed certificate.

### Install costs

The ceremony stages the image at the disk tail, kexecs into its own installer, and writes the box's
partition table, boot partition, root slot and persist skeleton over the disk. The Debian system is
not bootable afterward; bytes outside those extents are not erased. Guide §5.4 describes the
staging. The tool
prints three costs before the erase:

1. A stop before staging leaves Debian bootable. After staging begins, Debian probably survives a
   stop, with no guarantee. To recover from a staging mishap, re-run (staging is idempotent) or
   re-provision the VPS.
2. After the kexec, a failure is recoverable only through the provider's console.
3. The machine you run the ceremony from stages and verifies the installer, so it is inside the
   box's trust base. Use a host you trust.

### This machine

- A checkout of this repository, with no uncommitted or untracked file outside the paths the
  ceremony writes. The ceremony never commits or discards work it did not write, so it refuses
  until you commit or stash such files.
- `docker` (the build runs in a pinned container), `/dev/kvm`, the cargo toolchain, and the
  boot-gate tools `qemu-system-x86_64`, `qemu-img`, `veritysetup` (cryptsetup), `ssh`, `curl`,
  `fakeroot` and `mke2fs` (e2fsprogs). The boot gate runs after the image build, so a missing tool
  stops the run late; `orchard doctor --for build` and `orchard doctor --for boot-gate` check them
  up front.
- Two SSH public keys: your everyday box login, and a recovery key baked into the signed root
  filesystem. The recovery key is the only login of the rescue branch, which box-init enters when
  `/persist` is corrupt or absent, when another rescue-class boot step fails, or when network
  bring-up fails. One key may serve both; two keys can be rotated separately.
- SSH access to the VPS as its login user, with passwordless `sudo` unless the user is `root`:

  ```sh
  ssh -i <your-key> debian@<box-ip> 'sudo -n whoami'    # Debian cloud image; must print: root
  ssh -i <your-key> root@<box-ip> whoami                # Hetzner Cloud image; must print: root
  ```

## Install

Run every command from the root of your checkout.

1. Install the invocation shim once:

   ```sh
   cargo build --release -p orchard-shim
   cp target/release/orchard-shim ~/.local/bin/orchard
   ```

   `~/.local/bin` must be on your `PATH`. Inside a checkout, `orchard <verb>` runs
   `cargo build --release -p orchard` (a short no-op when nothing changed, a full build after a
   pull) and execs the result. Outside a checkout the shim refuses. Every `next:` hint the tool
   prints uses this form.

2. Start the ceremony:

   ```sh
   orchard guide boxes/<name>.toml
   ```

   - It confirms the target on every run. Accepting the displayed target never rewrites the profile;
     a target other than the stored one takes a re-type of the new target.
   - It asks for each parameter in turn, with its meaning, its default and the default's source, and
     shows values resolved from the profile or your context for confirmation. It rejects a wrong
     answer at once and asks again with the reason.
   - It writes your answers, the image version included, to the profile `boxes/<name>.toml` before
     anything executes, so a stopped run keeps them. The profile never holds a destructive
     confirmation or key material.
   - It asks for the erase authorization: type `--wipe-confirmed` exactly. Left empty, the run
     executes up to the erase, stops, and prints a resume command carrying every flag and the
     resolved context paths. Run it as printed.
   - It prints the plan (profile, resolved repo root, artifact store, target, every step with the
     ones it skips because their work is recorded, parameter values) and executes. Only the commit
     gate and the install step ask anything after this.

3. Ratify the git configuration. On a checkout with the step 4 to 6 inputs, the first run stops
   before the image build with `repository-form-unmodelled … has no ratified declared space`. Run:

   ```sh
   orchard admit --box boxes/<name>.toml
   ```

   `admit` shows the configuration (see [Declared space](#declared-space)) and writes it to
   `boxes/repo-form/` after you type `admit`. Commit those files: they are part of the box's
   configuration.

4. Resume. The declared-space stop prints only the `admit` command, so after `admit` use the
   general form below; any later stop prints its own resume command, carrying every flag of the
   stopped invocation:

   ```sh
   orchard run boxes/<name>.toml --target <box-ip> --image-version <n>
   ```

   `run` is the ceremony without the interview. It skips steps whose work the profile's records
   account for and re-executes the rest; after any failure, the same command resumes.
   `--image-version` is required on every invocation whose image build is still owed: `run` reads
   the image version only from this flag and refuses with the cure without it. `orchard build
   --profile` reads it from the profile, so check the profile value before building by hand.

5. Stay at the terminal for the install step. It prints what it will erase and waits for you to
   retype the target.

## Reference

### Declared space

The ceremony commits into your checkout through git, and refuses to commit while git's live
configuration differs from the ratified one. The declared space is every configuration key at every
scope, plus the value of each key that names a program git would execute during the run or selects
whether or which such execution happens: `core.fsmonitor`, `core.hooksPath`,
`core.attributesFile`, `attr.tree`, `commit.gpgSign`, `gpg.format`, `gpg.program`,
`gpg.openpgp.program`, `gpg.x509.program`, `gpg.ssh.program`, `gpg.ssh.defaultKeyCommand`,
`hook.<name>.command` / `.event` / `.enabled`, and `filter.<driver>.clean` / `.process`. Changing
any other key's value needs no new `admit`.

- The check runs at the commit gate, before the image build. The earlier steps execute first; a
  re-run after `admit` skips them.
- Re-run `admit` after any git configuration change. On a checkout that already carries a profile,
  run it before every `guide` or `run`.
- `--repo-form-dir <dir>` moves the ratified files; give the same directory to `guide` and `run`. A
  declared-space stop prints the `admit` command for the directory the run used.
- Paths and configuration keys the ceremony reads must be UTF-8. A non-UTF-8 file name or key in
  the checkout stops the run at the commit gate, which names it; rename the file or edit the key in
  `.git/config`, then re-run. A non-UTF-8 path argument is refused before anything runs.

### Unattended runs

`orchard run … --porcelain` prints one record per line and detaches the terminal from every step.
The commit gate then commits only under `--commit` and stops otherwise, and the install step takes
the typed `--wipe-confirmed` token with no retype.

### Exit codes

| Exit | Meaning |
|------|---------|
| 0 | done (including a run where every step was already done) |
| 1 | a step failed; its own output says why |
| 2 | refused, with the cure printed |
| 3 / 4 / 5 / 6 | an action is owed by you: a commit gate, a sibling checkout, an external step, or the destructive authorization |
| 101 (141 on a closed pipe) | the tool crashed; no record is written, and the run resumes from the last recorded step |

### Stops

Every stop names what is owed and how to clear it.

| Stop | Cause | Fix |
|------|-------|-----|
| `context-conflict` naming `--artifact-store` and `vendor --store` | the two flags are compared as spelled, so an absolute and a relative path to the same directory conflict | pass one of the two, or spell both the same way |
| a pasted resume or `admit` command refused | its `--target` or `--repo-form-dir` value starts with `-` | re-type that flag in the `=` spelling (`--target=-name`) |
| `repository-form-unmodelled` … `has no ratified declared space` | no `admit` yet for this checkout | run the `orchard admit` command the stop prints (it carries your `--repo-form-dir` and the resolved context), then re-run |
| `repository-form-unmodelled` … `declared space differs from the ratified file: added …, removed …` | git's configuration changed since you ratified it (a key added or removed at any scope, or a value changed at one of the program keys) | revert the change, or run the `orchard admit` command the stop prints, then re-run |
| `repository-form-unmodelled` … `ratified declared-space file exists and cannot be read` | the file under `boxes/repo-form/` is not UTF-8 text, is a directory, or is unreadable | restore it from a trusted copy (its git history when the file is tracked), or remove it and run the `orchard admit` command the stop prints, then re-run |
| `repository-form-unmodelled` … a replace ref, `info/grafts`, or a shallow clone | the checkout rewrites history in a way the gate does not commit onto | `git replace -d`, remove the grafts file, or `git fetch --unshallow`, then re-run |
| `git-state-unreadable` … `emitted bytes outside UTF-8 (…)` | a file name or configuration key in the checkout is outside UTF-8; the sample names it | rename the file, or edit the key in `.git/config`, to UTF-8, then re-run |
| `cannot measure the … checkout's declared space` … `emitted bytes outside UTF-8` (from `orchard admit`, exit 1) | a configuration key or value in that checkout is outside UTF-8; the sample names it | edit the key or value in `.git/config` to UTF-8, then re-run `admit` |
| `ceremony-tree-dirty` … `uncommitted changes outside the paths this ceremony writes` | a file the ceremony does not write is modified or untracked in the checkout | commit or stash the listed paths, then re-run |
| `lock-held` | another orchard invocation that writes is running on this host | wait for it, or stop it; one writing invocation per host |
| `invalid UTF-8 was detected` at the command line | a path you typed (the profile, `--repo-form-dir`, `--repo-root`, `--artifact-store`, `--repo-manifest`, `--context`) is outside UTF-8 | use a UTF-8 path |

### Records and diagnostics

- `orchard doctor` checks readiness and changes nothing.
- Run records live under `$XDG_STATE_HOME/orchard/records/<name>.d/` (default
  `~/.local/state/orchard/records/<name>.d/`; with `ORCHARD_STATE_DIR` set,
  `$ORCHARD_STATE_DIR/records/<name>.d/`). A re-run reads them to skip completed work; delete them
  and the ceremony re-does every step.
