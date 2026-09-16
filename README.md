# Orchard

The build/deploy factory for [Fruit Basket](https://github.com/fruitvibes123/fruit-basket), the
immutable integrity-enforcing appliance OS: `orchard build` turns an operator key set plus a set
of pinned inputs into a bootable, dm-verity-sealed, IMA-signed disk image, and the same CLI
verifies, boots, installs, updates, and backs up the box that image becomes.

> [!WARNING]
> Every line of code and documentation in this repository is LLM output, written end to end by
> Claude (Anthropic) under the direction and review of a human operator. Read and reuse it with
> that provenance in mind.

The factory is deliberately narrow: one central pin manifest (`pins.toml`) for the kernel,
bootloader, and Rust toolchain; one consumed-artifact manifest (`consume-pins.toml`) that
sha256-pins every binary, source drop, and config the bake stages — verified at consumption,
refusing on mismatch or absence; one pinned build container so musl and kernel builds never
touch the host toolchain. The kernel is built from source (`CONFIG_MODULES=n` and the
integrity built-ins require it), the image assembles deterministically, and the produced-bytes
boot gates prove install → boot → serve → crash-recover on the real image under QEMU/KVM.

**Start here: [`docs/guided-quickstart.md`](docs/guided-quickstart.md)** — the guided ceremony
installs a box as one resumable run: `orchard guide` interviews you once and writes a profile,
`orchard run` conducts the whole lifecycle from container build to post-boot check with consent
gates before anything commits or touches a disk, `orchard admit` ratifies the checkout's git
configuration. **The reference: [`orchard_guide.md`](orchard_guide.md)** — the same steps by hand
(§4 to §6), the ceremony's map (§14), the build variants, maintenance (pin bumps),
troubleshooting, backup + restore, A/B self-update, and key rotation.

**Names.** `recipes` is the reference tenant, the private web application the box was first built
to host; it names the image files, the build container, the `RECIPES_*` gate variables and the
key directory, and those names stay when you bring your own application. `dha` is an optional AI
co-tenant from private provider repositories; a default box does not bake it.

## Components

| Crate | Role |
|---|---|
| `crates/image-builder` | the `.img` pipeline: apk acquisition, kernel bake, rootfs/boot-fs/persist assembly, service-manifest rendering, IMA/EVM signing, verity sealing |
| `crates/orchard` | the operator CLI: `guide` / `run` / `admit` (the guided ceremony), `build`, `dryrun`, `prod` (the install step), `update`, `doctor`, `prime`, `vendor`, `market` (the pin-store tool), key generation + rotation |
| `crates/grocer` | the content-addressed artifact-store publisher (fail-closed key+kind cross-checks, ELF/linkage asserts) |
| `crates/cashew` | pure-Rust verify-only OpenPGP/RSA detached-signature checker (kernel.org source verification) |
| `crates/syslinux-install` | the BIOS bootloader install helper |
| `crates/orchard-shim` | the invocation shim: installed as `orchard`, it runs `cargo build` for the CLI in the checkout on every invocation and execs the result |
| `vendor/` | committed, sha256-pinned source drops consumed by the bake: `grape` + `dragonfruit` ([seed-vault](https://github.com/fruitvibes123/seed-vault)), `fb-manifest` + `rambutan` ([fruit-basket](https://github.com/fruitvibes123/fruit-basket)) |

Together with the published fruit-basket and seed-vault repositories this closes the build loop:
clone the three side by side, build the container, generate keys, build + publish the
fruit-basket binaries into your local artifact store, bring your own application backend per the
service-manifest schema, and bake a bootable image — the guide's §2 to §7 is that path, and
`orchard prod` (§5.1) the install.

## About this repository

This is the published export of a private canonical repository, produced by an
equivalence-gated release tool:

- **Working comments are padded out, not deleted.** Internal non-doc comments are replaced with
  same-length whitespace; runs of trailing spaces and blank-looking lines are that padding. Doc
  comments publish as written.
- **The release gate is compile-only.** Orchard ships no binaries tied to this source, so the
  gate proves per-file token-stream identity, doc-comment byte-identity, and per-workspace
  compile checks inside the pinned container — not binary equivalence (that gate belongs to the
  repos whose binaries ship).
- **Some internal references remain.** Wherever a doc comment, a config or shell comment, or a
  CLI help string cites the operator's private specifications, audit reports, plans, tasks or
  decision records (bare `§n.m` section references, finding ids such as `audit R1 F-3`, task and
  component numbers, dated spec and decision names), the citation is kept where the surrounding
  text carries the substance. None of those documents is published, so no such reference
  resolves in this tree; each names the record behind the decision beside it. Identifiers this
  tree defines (refusal rows such as `R-DISARM`, constants, test names) are not in that class.
- **The published `make verify` differs from the canonical one** in two declared ways (see the
  Makefile header): no `fmt-check` (padding is not rustfmt-clean) and no `market-verify` (it
  reads the operator's private pin-store ecosystem).
- The `market` pin tool, the reclaim-tail install ceremony, and the deploy orchestration are
  operator-host tooling: they run on your machine against your fleet, and several of their
  cross-repo checks expect sibling checkouts that are yours to provide.

## License

`GPL-2.0-only` — see [`COPYING`](COPYING). Orchard is the operator-host build/deploy factory for
the Fruit Basket OS, relicensed to match the OS it builds: GPLv2 (not v3/AGPL — the box's
verified-boot model is the "tivoization" GPLv3 forbids), `-only` not `-or-later`.

Scope: Orchard's own crates (`image-builder`, `orchard`, `orchard-shim`, `syslinux-install`,
`grocer`, `cashew`). The vendored pinned source drops under `vendor/` keep their upstream licenses
and are not relicensed here: `grape` is `MIT OR Apache-2.0` (the license texts are
[LICENSE-MIT](https://github.com/fruitvibes123/seed-vault/blob/main/LICENSE-MIT) and
[LICENSE-APACHE](https://github.com/fruitvibes123/seed-vault/blob/main/LICENSE-APACHE) in the
seed-vault repository); `dragonfruit`, `fb-manifest` and `rambutan` are `GPL-2.0-only`.
