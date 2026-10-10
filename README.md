# Orchard

The build/deploy factory for [Fruit Basket](https://github.com/fruitvibes123/fruit-basket), the
immutable integrity-enforcing appliance OS. `orchard build` turns an operator key set and a set of
pinned inputs into a bootable, dm-verity-sealed, IMA-signed disk image; the same CLI verifies,
boots, installs, updates, and backs up the box that image becomes.

> [!WARNING]
> Every line of code and documentation in this repository is LLM output, written end to end by
> Claude (Anthropic) under the direction and review of a human operator. Read and reuse it with
> that provenance in mind.

Orchard pins its inputs in three places: one pin manifest (`pins.toml`) for the kernel, bootloader,
and Rust toolchain; one consumed-artifact manifest (`consume-pins.toml`) that sha256-pins every
binary, source drop, and config the bake stages, verified at consumption and refused on mismatch or
absence; and one pinned build container, so musl and kernel builds never touch the host toolchain.
`CONFIG_MODULES=n` and the integrity built-ins require a kernel built from source, so Orchard
builds it from source. The image assembles deterministically, and the produced-bytes boot gates
prove install → boot → serve → crash-recover on the real image under QEMU/KVM.

Start with [`docs/guided-quickstart.md`](docs/guided-quickstart.md). The guided ceremony installs a
box as one resumable run: `orchard guide` interviews you once and writes a profile; `orchard run`
conducts the lifecycle from container build to post-boot check, with consent gates before anything
commits or touches a disk; `orchard admit` ratifies the checkout's git configuration.

[`orchard_guide.md`](orchard_guide.md) is the reference: the same steps by hand (§4 to §6), the
ceremony's map (§14), the build variants, maintenance (pin bumps), troubleshooting, backup and
restore, A/B self-update, and key rotation.

Two names in the tree refer to private projects. `recipes` is the reference tenant, the private web
application the box was first built to host. It names the image files, the build container, the
`RECIPES_*` gate variables and the key directory, and those names stay when you bring your own
application. `dha` is an optional AI co-tenant from private provider repositories; a default box
does not bake it.

## Components

| Crate | Role |
|---|---|
| `crates/image-builder` | the `.img` pipeline: apk acquisition, kernel bake, rootfs/boot-fs/persist assembly, service-manifest rendering, IMA/EVM signing, verity sealing |
| `crates/orchard` | the operator CLI: `guide` / `run` / `admit` (the guided ceremony), `build`, `dryrun`, `prod` (the install step), `update`, `doctor`, `prime`, `vendor`, `market` (the pin-store tool), key generation and rotation |
| `crates/grocer` | the content-addressed artifact-store publisher (fail-closed key and kind cross-checks, ELF and linkage asserts) |
| `crates/cashew` | pure-Rust verify-only OpenPGP/RSA detached-signature checker (kernel.org source verification) |
| `crates/syslinux-install` | the BIOS bootloader install helper |
| `crates/orchard-shim` | the invocation shim: installed as `orchard`, it runs `cargo build` for the CLI in the checkout on every invocation and execs the result |
| `vendor/` | committed, sha256-pinned source drops consumed by the bake: `grape` and `dragonfruit` ([seed-vault](https://github.com/fruitvibes123/seed-vault)), `fb-manifest` and `rambutan` ([fruit-basket](https://github.com/fruitvibes123/fruit-basket)) |

Together with the published fruit-basket and seed-vault repositories, Orchard covers the whole
build path: clone the three side by side, build the container, generate keys, build and publish the
fruit-basket binaries into your local artifact store, bring your own application backend per the
service-manifest schema, and bake a bootable image. The guide's §2 to §7 covers that path, and
`orchard prod` (§5.1) is the install.

## About this repository

An equivalence-gated release tool produces this repository from a private canonical repository.

- Internal non-doc comments are replaced with whitespace of the same length. Runs of trailing
  spaces and blank-looking lines are that padding. Doc comments publish as written.
- The release gate is compile-only. Orchard ships no binaries tied to this source, so the gate
  proves per-file token-stream identity, doc-comment byte-identity, and per-workspace compile
  checks inside the pinned container. Binary equivalence is gated in the repositories whose
  binaries ship.
- Some internal references remain. Doc comments, config and shell comments, and CLI help strings
  keep their citations of the operator's private specifications, audit reports, plans, tasks and
  decision records where the surrounding text carries the substance: bare `§n.m` section
  references, finding ids such as `audit R1 F-3`, task and component numbers, dated spec and
  decision names. Those documents are unpublished, so these references do not resolve in this tree;
  each one names the record behind the decision beside it. Identifiers this tree defines (refusal
  rows such as `R-DISARM`, constants, test names) are not in that class.
- The published `make verify` omits two legs of the canonical one, as the Makefile header declares.
  The padding is not rustfmt-clean, so `fmt-check` is left out; `market-verify` reads the
  operator's private pin-store ecosystem, so it is left out too.
- The `market` pin tool, the reclaim-tail install ceremony, and the deploy orchestration are
  operator-host tooling. They run on your machine against your fleet, and several of their
  cross-repo checks expect sibling checkouts that you provide.

## License

`GPL-2.0-only`; the text is in [`COPYING`](COPYING). Orchard is the operator-host build/deploy
factory for the Fruit Basket OS and is licensed to match the OS it builds. The box's verified-boot
model is the "tivoization" GPLv3 forbids, so Orchard is GPLv2, not v3 or AGPL; `-only` excludes
later GPL versions.

The license covers Orchard's own crates (`image-builder`, `orchard`, `orchard-shim`,
`syslinux-install`, `grocer`, `cashew`). The vendored source drops under `vendor/` keep their
upstream licenses and are not relicensed here. `grape` is `MIT OR Apache-2.0` (the license texts
are [LICENSE-MIT](https://github.com/fruitvibes123/seed-vault/blob/main/LICENSE-MIT) and
[LICENSE-APACHE](https://github.com/fruitvibes123/seed-vault/blob/main/LICENSE-APACHE) in the
seed-vault repository); `dragonfruit`, `fb-manifest` and `rambutan` are `GPL-2.0-only`.
