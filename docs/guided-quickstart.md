# Guided install — quickstart

One page: the whole install as one ceremony. `orchard_guide.md` is the reference: the same steps
run by hand (§4 to §6), plus the build variants, the pins, backup and restore, the OS update and
key rotation.

## What you need before you start

- A checkout of this repo, and `docker` + `/dev/kvm` on this machine (the build runs in a pinned
  container; the gate boots the produced bytes).
- A freshly provisioned target box, reachable over SSH as its cloud user (`debian` on the Debian
  images this project deploys to) with passwordless `sudo`. Check it yourself:

  ```sh
  ssh -i <your-key> debian@<box-ip> 'sudo -n whoami'    # must print: root
  ```

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
shim makes that true from anywhere inside a checkout. It still needs a checkout — outside one it
refuses and says so.

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
   version; never a destructive confirmation, never key material. `orchard run` re-asks for the
   image version on every invocation regardless of what the profile stores; `orchard build
   --profile` does not, so check the value before building by hand.
4. **Ask you to authorize once.** The whole-disk erase is authorized by typing `--wipe-confirmed`
   exactly. Leave it empty and the run executes up to that step, stops, and prints the command to
   resume with. The printed resume command carries every flag of the stopped invocation and the
   resolved context paths; run it as printed.
5. **Print what the run will do**: the profile, the resolved repo root, artifact store and target,
   every step with the ones it will skip because their work is already recorded, and the
   parameter values; then execute.
6. **Execute uninterrupted**, except at the commit consent gate, which prompts when it is reached.

## Ratify the declared space (after the first `guide`, and after any git configuration change)

`orchard guide` writes the profile, so ratify after the first run, not before it. On a checkout
that already carries a profile, ratify before every `guide` or `run`:

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

Every stop names what is owed and how to clear it. Three kinds, distinguished by exit code so a
wrapper can branch on them:

| Exit | Meaning |
|------|---------|
| 0 | done (including a run where every step was already done) |
| 2 | refused, with the cure printed |
| 3 / 4 / 5 / 6 | an action is owed by you: a commit gate, a sibling checkout, an external step, or the destructive authorization |
| 1 | a step failed; its own output says why |

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
- `orchard run … --porcelain` — one record per line for scripting.
- The run's records live under `$XDG_STATE_HOME/orchard/records/<name>.d/` (default
  `~/.local/state/orchard/records/<name>.d/`; with `ORCHARD_STATE_DIR` set, under
  `$ORCHARD_STATE_DIR/records/<name>.d/`). They are what makes a re-run skip completed work;
  delete them and the ceremony re-does everything.
