# Guided install — quickstart

One page: the whole install as one ceremony. [`orchard_guide.md`](../orchard_guide.md) is the
reference: the same steps run by hand (§4 to §6), plus the build variants, the pins, backup and
restore, the OS update and key rotation.

**Names.** "The box" is the appliance OS, fruit-basket, installed on one machine for one
application. `recipes` is the reference tenant, the private web application the box was first
built to host; it names the image files and the build container, and the names stay when you
bring your own application. `dha` is an optional AI co-tenant from private repositories; a
default box does not bake it. A profile (`boxes/<name>.toml`) holds a box's stable answers. The
boot gate boots the built image under QEMU before anything touches the target.

Run every command on this page from the repo root, your checkout of this repository.

## Where this runs: the target box

The quickstart assumes a commercial VPS, Hetzner Cloud or any provider of the same shape. The
reference deployment runs on one small Infomaniak instance, and one build-time default below is
tied to that provider. Provision the box like this before you start:

- **Image: the provider's stock Debian 13 cloud image.** The ceremony's install runs from inside
  that Debian: it stages the appliance image in Debian's free space, kexecs into its own
  installer, and writes the image over the whole disk. Nothing of Debian survives the install.
  Until staging begins, a stop leaves Debian bootable; once the image is being staged into
  Debian's free space that survival is probable, not guaranteed, and a failure after the kexec is
  recoverable only through the provider's console. Recovery from a staging mishap is a re-run
  (the staging is idempotent) or a re-provision of the box. The machine you run the ceremony
  from is inside the installed box's trust base: it stages and verifies the installer, so run
  the ceremony from a host you trust. The tool prints these three costs before the erase; the
  guide's §5.4 states them. Debian 13 is the release the kexec safety margin is grounded on (its
  `kexec-tools` refuses an over-long kernel command line rather than truncating it); the tool
  does not check the release, so provision it as stated. Add your SSH public key at
  provisioning. The login user is the image's: Debian's own cloud image creates `debian` with
  passwordless `sudo`, and Hetzner Cloud's Debian images log you in as `root`. The interview asks
  for it as `provisioning_user` (default `debian`; profile key of the same name); a `root` user
  needs no `sudo`. Install `kexec-tools` on the box (`apt-get install -y kexec-tools`, under
  `sudo` where the user is not root): the ceremony checks for it at the install step, after the
  image build and the boot gate, and stops there without it.
- **Boot: legacy BIOS.** The default firmware is `seabios`. When the interview asks, choose
  `seabios-gpt`: it is the same BIOS boot with a GPT disk, and it is the only layout
  `orchard update` (the A/B self-update, no reinstall) works on. UEFI is a separate path, covered
  in [the guide](../orchard_guide.md) (§7).
- **Network: one public IPv4, static.** The box bakes a static configuration; DHCP is refused at
  bring-up. Have the address with its prefix, the gateway and a DNS resolver from the provider's
  panel; the interview asks for them.
- **Ports.** The box listens on 22 (SSH), 80 and 443; the set is fixed by the service manifest,
  and the provider firewall, if any, passes those three. The profile's `port` is the port orchard
  dials, on the Debian side before the install and on the box after it, so it stays 22: a Debian
  image whose sshd listens elsewhere is not a supported target.
- **Time.** The box's clock comes from the hypervisor (kvm-clock); `ntpd` is a best-effort
  correction over plain NTP to one server baked at build, `pool.ntp.infomaniak.ch`, and the
  egress firewall passes UDP 123. That server was chosen because it is first-party to the
  reference deployment's provider and so already inside the box's trust base: plain NTP to a
  server outside your own provider, across the open internet, reintroduces a time-tampering
  surface that authenticated NTP would guard. Certificate validity is floor-gated separately and
  does not hang on it. On any other provider, Hetzner included, the choice is yours to revisit;
  changing the server is a source edit (`NTP_SERVER` in `crates/image-builder/src/service_tree.rs`).
- **Size.** A small tier is enough for the reference tenant. The installer's own floor is 256 MiB
  of RAM, and an image larger than the box's RAM installs fine; the AI co-tenant, if you run one,
  sets its own requirements.
- **DNS.** Point the domain the box will serve at the address before the run. From first boot the
  box serves a self-signed certificate it wrote itself, and replaces it with the ACME certificate
  once issuance over port 80 succeeds; a browser warning right after the install is that
  bootstrap, not a failed install.

## What you need before you start

- A checkout of this repo, and on this machine `docker` + `/dev/kvm` (the build runs in a pinned
  container; the boot gate boots the produced bytes) plus the boot-gate host tools:
  `qemu-system-x86_64`, `qemu-img`, `veritysetup` (cryptsetup), `ssh`, `curl`, `fakeroot` and
  `mke2fs` (e2fsprogs). The gate runs after the image build, so a missing tool surfaces late;
  `orchard doctor --for build` and `orchard doctor --for boot-gate` check them before you start.
- The target box provisioned as the section above describes, reachable over SSH as its login
  user, with passwordless `sudo` unless that user is `root`. Check the access yourself:

  ```sh
  ssh -i <your-key> debian@<box-ip> 'sudo -n whoami'    # Debian cloud image; must print: root
  ssh -i <your-key> root@<box-ip> whoami                # Hetzner Cloud image; must print: root
  ```

- The inputs of ceremony steps 4 to 6, which this release does not ship: an artifact store
  beside the checkout (`../artifact-store`) holding the fruit-basket binaries and the four
  source drops (`grape-src`, `dragonfruit-src`, `fb-manifest-src`, `rambutan-src`), and the
  tenant's publish handoff tree at `/tmp/recipes-build-handoff`. Step 4 runs `orchard vendor`
  from the store and refuses without it; step 5 confirms the handoff tree. The binaries you
  build and publish from the public fruit-basket repository (guide §4.4); the source-drop
  publishes and the handoff come from the owning repositories' publish tooling, which is not in
  the public trees, and the reference tenant is private. On a public checkout, the by-hand path
  is the one that completes today: guide §4 to §7 with your own application manifest (§7), then
  the install by hand, `orchard prod <box-ip> --profile boxes/<name>.toml --wipe-confirmed`
  (§5.1; §10 has the flags), which is the ceremony's step 10. The ceremony is published as the
  reference operator's tool, and making its steps 4 to 6 pass on a public checkout is an open
  unit.
- Two SSH public keys: your everyday box login, and a recovery key used only if `/persist` is
  lost. They may be the same key; keeping them separate is what lets you rotate one.
- The domain the box will serve, with its DNS already pointing at the box.
- A clean checkout. The ceremony never commits or discards work it did not write, so it refuses
  while any file it does not write is uncommitted or untracked; commit or stash them first.

## Install the invocation shim (once)

```sh
cargo build --release -p orchard-shim
cp target/release/orchard-shim ~/.local/bin/orchard
```

Every command below, and every `next:` hint the tool prints, is written as `orchard <verb>`. The
shim resolves that name from anywhere inside a checkout: on every invocation it runs
`cargo build --release -p orchard` in the checkout (a short no-op when nothing changed, a full
build after a pull) and execs the result, so it needs the cargo toolchain. The working directory
is still the repo root, and outside a checkout the shim refuses and says so. `~/.local/bin` must
be on your `PATH`.

## Run the ceremony

```sh
orchard guide boxes/<name>.toml
```

That is the whole invocation. It will:

1. **Confirm the target** first, every run. If you confirm a target that differs from the one the
   profile stores, re-pointing is its own action: you re-type the new target to confirm it.
   Accepting the displayed target never rewrites the profile.
2. **Ask you for each parameter**, one at a time, with what it is, what it defaults to, and where
   that default comes from. Values it can already resolve, from the profile or from your context,
   are shown for you to confirm rather than retype. A wrong answer is caught immediately and
   asked again with the reason.
3. **Write the profile** to `boxes/<name>.toml` before anything executes, so a run that stops
   halfway does not cost you the answers. It holds the answers you gave, including the image
   version; never a destructive confirmation, never key material. `orchard run` takes the image
   version as a flag (`--image-version <n>`) on every invocation whose image build is still owed;
   it never reads it from the profile, and refuses with the cure when the flag is missing.
   `orchard build --profile` does read it from the profile, so check the value before building by
   hand.
4. **Ask you to authorize the erase.** The whole-disk erase is authorized by typing
   `--wipe-confirmed` exactly. Leave it empty and the run executes up to that step, stops, and
   prints the command to resume with. When the install step is reached with the ceremony's
   terminal attached, it asks once more: it prints what it is about to erase and waits for you
   to retype the target, so be at the terminal then. `orchard run --porcelain` detaches the
   terminal from every step: the commit gate then commits only under `--commit` and stops
   otherwise, and the install step takes the typed token alone, with no retype. The printed resume command carries every flag of the stopped invocation and the
   resolved context paths; run it as printed.
5. **Print what the run will do**: the profile, the resolved repo root, artifact store and target,
   every step with the ones it will skip because their work is already recorded, and the
   parameter values; then execute.
6. **Execute** without further questions, except the commit consent gate and the install step's
   retype prompt, each of which asks when it is reached.

## Ratify the declared space (after the first `guide`, and after any git configuration change)

The declared space is the set of git configuration keys the ceremony's commits depend on, at
every scope, with the values of the keys that name a program git would run. `orchard admit`
measures it and writes it down; a later run refuses to commit while the live configuration
differs from what you ratified. `orchard guide` writes the profile, so ratify after the first
run, not before it. On a checkout that already carries a profile, ratify before every `guide` or
`run`:

```sh
orchard admit --box boxes/<name>.toml
```

The ceremony commits into your checkout through git, so it refuses to COMMIT while git's effective
configuration differs from the one you ratified. The check runs at the commit gate, before the
image build: the earlier steps execute first, and a re-run after `admit` skips them. `admit` lists
every configuration key at every scope. For the keys whose value names a program git would execute
during the run, or selects whether or which such execution happens, it lists the value as well:
`core.fsmonitor`, `core.hooksPath`, `core.attributesFile`, `attr.tree`, `commit.gpgSign`,
`gpg.format`, `gpg.program`, `gpg.openpgp.program`, `gpg.x509.program`, `gpg.ssh.program`,
`gpg.ssh.defaultKeyCommand`, and `hook.<name>.command` / `.event` / `.enabled`,
`filter.<driver>.clean` / `.process`. Every other key's value is outside the declared space:
changing it forces no re-`admit`. It shows the diff
against what is ratified and writes only after you type `admit`. The ratified files live in
`boxes/repo-form/` (`--repo-form-dir <dir>` moves them; give the same directory to `guide` and `run`); a stop about the declared space prints the `admit` command for the directory the run used.
Commit them: they are part of the box's configuration.

Paths and configuration keys the ceremony reads must be UTF-8. A file name or a key outside UTF-8
anywhere in the checkout stops the run at the commit gate and names it; rename the file, or edit
the key in `.git/config`, and re-run. A path argument outside UTF-8 is refused before anything runs.

## Running it again

```sh
orchard run boxes/<name>.toml --target <box-ip> --image-version <n>
```

`run` is the same ceremony without the questions. Steps whose work this profile's records already
account for are skipped; anything else re-executes. It is safe to re-run after a failure — that is
how you resume.

Values re-decided every run (the image version) are typed on the invocation every time, on
purpose: they are judgments, not identity, so they are never carried silently from the profile.

## When it stops

Every stop names what is owed and how to clear it. The exit codes, so a wrapper can branch on
them:

| Exit | Meaning |
|------|---------|
| 0 | done (including a run where every step was already done) |
| 2 | refused, with the cure printed |
| 3 / 4 / 5 / 6 | an action is owed by you: a commit gate, a sibling checkout, an external step, or the destructive authorization |
| 1 | a step failed; its own output says why |
| 101 (141 on a closed pipe) | the tool itself crashed; no record is written, and the run resumes from the last recorded step |

Two stops you can clear by re-typing:

- `context-conflict` naming `--artifact-store` and `vendor --store`: the two flags are compared as
  you spelled them, so an absolute path beside a relative one for the same directory refuses. Pass
  one of the two, or spell both the same way.
- A printed resume or `admit` command whose `--target` or `--repo-form-dir` value starts with `-`
  is refused when pasted back. Re-type that flag in the `=` spelling (`--target=-name`).

## Stops about the checkout's form

| Stop | What it says | What you do |
|------|--------------|-------------|
| `repository-form-unmodelled` … `has no ratified declared space` | no `admit` yet for this checkout | run the `orchard admit` command the stop prints (it carries your `--repo-form-dir` and the resolved context), then re-run |
| `repository-form-unmodelled` … `declared space differs from the ratified file: added …, removed …` | git's configuration changed since you ratified it (a key added or removed at any scope, or a value changed at one of the program keys above) | revert the change, or run the `orchard admit` command the stop prints, then re-run |
| `repository-form-unmodelled` … `ratified declared-space file exists and cannot be read` | the file under `boxes/repo-form/` is not UTF-8 text, is a directory, or is unreadable | restore it from a trusted copy (its git history when the file is tracked), or remove it and run the `orchard admit` command the stop prints, then re-run |
| `repository-form-unmodelled` … a replace ref, `info/grafts`, or a shallow clone | the checkout rewrites history in a way the gate does not commit onto | `git replace -d`, remove the grafts file, or `git fetch --unshallow`, then re-run |
| `git-state-unreadable` … `emitted bytes outside UTF-8 (…)` | a file name or configuration key in the checkout is outside UTF-8; the sample names it | rename the file, or edit the key in `.git/config`, to UTF-8, then re-run |
| `cannot measure the … checkout's declared space` … `emitted bytes outside UTF-8` (from `orchard admit`, exit 1) | a configuration key or value in that checkout is outside UTF-8; the sample names it | edit the key or value in `.git/config` to UTF-8, then re-run `admit` |
| `ceremony-tree-dirty` … `uncommitted changes outside the paths this ceremony writes` | a file the ceremony does not write is modified or untracked in the checkout | commit or stash the listed paths, then re-run |
| `lock-held` | another orchard invocation that writes is running on this host | wait for it, or stop it; one writing invocation per host |
| `invalid UTF-8 was detected` at the command line | a path you typed (the profile, `--repo-form-dir`, `--repo-root`, `--artifact-store`, `--repo-manifest`, `--context`) is outside UTF-8 | use a UTF-8 path |

## If something looks wrong

- `orchard doctor` — read-only readiness, never changes anything.
- `orchard run … --porcelain` — one record per line for scripting; it also makes the run headless
  (no commit prompt, no retype at the install step; see item 4 above).
- The run's records live under `$XDG_STATE_HOME/orchard/records/<name>.d/` (default
  `~/.local/state/orchard/records/<name>.d/`; with `ORCHARD_STATE_DIR` set, under
  `$ORCHARD_STATE_DIR/records/<name>.d/`). They are what makes a re-run skip completed work;
  delete them and the ceremony re-does everything.
