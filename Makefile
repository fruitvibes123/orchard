# Orchard — the build/deploy factory. CI runs `make verify` (the seam contract); the produced-bytes
# proofs are the boot-gate* targets below — run AFTER `orchard build`, NOT in `make verify`, and NOT
.PHONY: verify fmt-check lint crux-orchard cmdline-lock crypto-sentry market-verify pins pins-check vendor prime repro-check
# The published verify drops two canonical steps: fmt-check (this tree is a comment-stripped
# export — removed comments are space-padded, so rustfmt findings are the export's, not the
# code's) and market-verify (it reads the operator's private pin-store ecosystem: sibling repos
# + a cert trail; run it with explicit --allow-missing flags if you build your own store).
# Both remain as standalone targets.
verify: pins-check lint
	cargo test --workspace
	$(MAKE) ceremony-hostcfg
	$(MAKE) crux-orchard
	$(MAKE) cmdline-lock
	$(MAKE) crypto-sentry
	@echo "verify: OK (orchard — seam contract; boot-gate is separate)."

# market: the consolidated pin-store gate (the always-on, fail-closed verify root). Runs the full §3a
# check set behind ONE entry — provenance + cross-repo seed agreement + vendored re-derive + config
# re-derive + format-lock drift + apk shape-lock + §3a-7 cert-presence (the cookbook cert trail) — with an
# exact-check-set lock (a silently dropped leg fails closed). This is the first-class gate; the scattered
# per-check tests (pins_agree/pins_provenance/vendor_integrity/pins_drift/apk_verify) STILL run under
# `cargo test --workspace` (migrate-don't-retire), and pin_verify/pin_manifest_attrs are a DIFFERENT class
# (runtime tamper-refuse + parser fail-open) left independently wired. Strict: a partial checkout must pass
# explicit `--allow-missing <repo>` (incl. `cert-trail` when the cookbook launchpad is absent), never a
market-verify:
	cargo run -p orchard -- market verify

# Guided-ceremony seeded-violation drives (each EXPECTS a red — a seed that passes is the
# failure). Not part of `verify` (three extra feature builds); run at dev + audit checkpoints.
.PHONY: ceremony-seeds
ceremony-seeds:
	@echo "seed 1/3: compose-yes must COMPILE then redden compositions_stay with ITS OWN violation"
	@cargo test -q -p orchard --features ceremony-seed-compose-yes --test ceremony_selftests --no-run >/dev/null 2>&1 \
		|| { echo "ERROR: the compose-yes seed does not compile — the gate cannot tell a red arm from a broken build"; exit 1; }
	@out="$$(cargo test -q -p orchard --features ceremony-seed-compose-yes --test ceremony_selftests compositions_stay 2>&1)"; rc=$$?; \
		if [ $$rc -eq 0 ]; then echo "ERROR: the compose-yes seed did NOT redden its arm"; exit 1; fi; \
		echo "$$out" | grep -q "has forbidden class ConsentBearing" \
			|| { echo "ERROR: compositions_stay reddened for the WRONG reason (not the seeded --yes composition) — a seed-cfg-confined unrelated failure greens a false negative"; echo "$$out" | tail -20; exit 1; }
	@echo "seed 2/3: unclassified-flag must COMPILE then redden flag_classification with ITS OWN violation"
	@cargo test -q -p orchard --features ceremony-seed-unclassified-flag --test ceremony_selftests --no-run >/dev/null 2>&1 \
		|| { echo "ERROR: the unclassified-flag seed does not compile — the gate cannot tell a red arm from a broken build"; exit 1; }
	@out="$$(cargo test -q -p orchard --features ceremony-seed-unclassified-flag --test ceremony_selftests flag_classification 2>&1)"; rc=$$?; \
		if [ $$rc -eq 0 ]; then echo "ERROR: the unclassified-flag seed did NOT redden its arm"; exit 1; fi; \
		echo "$$out" | grep -q "ceremony-seed-unclassified" \
			|| { echo "ERROR: flag_classification reddened for the WRONG reason (not the seeded flag)"; echo "$$out" | tail -20; exit 1; }
	@echo "seed 3/3: unclassified-verb must fail the BUILD with ITS OWN non-exhaustive-match error"
	@out="$$(cargo build -q -p orchard --features ceremony-seed-unclassified-verb 2>&1)"; rc=$$?; \
		if [ $$rc -eq 0 ]; then echo "ERROR: the unclassified-verb seed did NOT fail the build"; exit 1; fi; \
		echo "$$out" | grep -q "CeremonySeedUnclassified" \
			|| { echo "ERROR: the unclassified-verb build failed for the WRONG reason (not the seeded verb's non-exhaustive match)"; echo "$$out" | tail -20; exit 1; }
	@echo "ceremony-seeds: OK (each seed reddens for its OWN seeded violation, verified by message)"

# Guided-ceremony floor row D'1: the R16 battery green under a non-empty host global and system git
# config, serially and (the declared-space family) at default parallelism (code-phaseR-r16-FLOOR5.md residuals 5, 9).
.PHONY: ceremony-hostcfg
CEREMONY_BATTERY := --lib --test ceremony_runner --test ceremony_selftests --test ceremony_gate \
	--test ceremony_interview --test ceremony_process_exec --test context_matrix \
	--test ceremony_gate_commit --test ceremony_declared_space --test ceremony_typed_cure \
	--test ceremony_path_render --test ceremony_declared_value --test ceremony_git_runner \
	--test ceremony_utf8_argv --test ceremony_floor_isolation
CEREMONY_BATTERY_TARGETS := 15
CEREMONY_PARALLEL := --test ceremony_declared_space --test ceremony_declared_value \
	--test ceremony_floor_isolation --test ceremony_git_runner --test ceremony_utf8_argv
CEREMONY_PARALLEL_TARGETS := 5
ceremony-hostcfg:
	@d=$$(mktemp -d) || exit 1; \
	printf '[hostglob]\n\tkey = 1\n' > $$d/global; \
	printf '[hostsys]\n\tkey = 1\n' > $$d/system; \
	fail() { echo "$$1"; printf '%s\n' "$$2" | grep -E '^test result|^ +[a-z_]+$$|panicked at' | head -40; rm -rf $$d; exit 1; }; \
	out=$$(GIT_CONFIG_GLOBAL=$$d/global GIT_CONFIG_SYSTEM=$$d/system \
		cargo test -q -p orchard --no-fail-fast $(CEREMONY_BATTERY) -- --test-threads=1 2>&1) || \
		fail "ERROR: ceremony-hostcfg serial failed under a host global+system git config" "$$out"; \
	n=$$(printf '%s\n' "$$out" | grep -c '^test result: ok\.'); \
	[ "$$n" = "$(CEREMONY_BATTERY_TARGETS)" ] || \
		fail "ERROR: ceremony-hostcfg serial reported $$n green targets, not $(CEREMONY_BATTERY_TARGETS) — refusing a false green" "$$out"; \
	echo "ceremony-hostcfg serial: $$n/$(CEREMONY_BATTERY_TARGETS) targets green under a host global+system git config"; \
	out=$$(GIT_CONFIG_GLOBAL=$$d/global GIT_CONFIG_SYSTEM=$$d/system \
		cargo test -q -p orchard --no-fail-fast $(CEREMONY_PARALLEL) 2>&1) || \
		fail "ERROR: ceremony-hostcfg parallel failed under a host global+system git config" "$$out"; \
	n=$$(printf '%s\n' "$$out" | grep -c '^test result: ok\.'); \
	[ "$$n" = "$(CEREMONY_PARALLEL_TARGETS)" ] || \
		fail "ERROR: ceremony-hostcfg parallel reported $$n green targets, not $(CEREMONY_PARALLEL_TARGETS) — refusing a false green" "$$out"; \
	echo "ceremony-hostcfg parallel: $$n/$(CEREMONY_PARALLEL_TARGETS) declared-space-family targets green at default parallelism"; \
	rm -rf $$d; \
	echo "ceremony-hostcfg: OK (the R16 battery is green under a host git config serially, and the declared-space family at default parallelism)"

# Orchard's per-repo pin generator is the existing `orchard sync-pins` (renders
# rust-toolchain.toml + syncs the image-builder Containerfile FROM from THIS repo's pins.toml).
# `make pins` regenerates; `make pins-check` fails closed on drift. The drift is also covered by
# tests/pins_drift.rs under `cargo test --workspace`; this is the named CLI hook (recipes/FB parity).
pins:
	cargo run -p orchard -- sync-pins
pins-check:
	cargo run -p orchard -- sync-pins --check
# (Re)populate vendor/ from the artifact store, verifying every *-src tarball's sha256
# against consume-pins.toml. Fail-closed. Needs the store populated (recipes/FB/seed-vault `make publish`).
vendor:
	cargo run -p orchard -- vendor
# Fetch + verify + stage the kernel/syslinux source tarballs (the in-Rust prime — replaces the
# retired fetch-*.sh). Network step, sited next to vendor: one operator prep ceremony. The bake
# re-verifies both tarballs at consumption (verify-at-consumption does not trust the prime).
prime:
	cargo run -p orchard -- prime
# The reproducible-assembly pre-check — re-verify the vendored source drops + the
# verify-at-consumption gate (fixed-sha by construction). The DEFINITIVE produced-bytes reproducibility
# proof is the boot-gate on a from-pins .img; this is the cheap fail-fast. NOT in `make verify` (it touches
# the store + vendor/, an operator action), like publish.
repro-check:
	./repro-check.sh

fmt-check:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

# CRUX "box never signs" — the Orchard share: dragonfruit[sign] is confined to the `orchard`
# CLI; the build crates (recipes-image-builder, syslinux-install) must NOT reach dragonfruit at all.
crux-orchard:
	@for crate in recipes-image-builder syslinux-install; do \
		cargo tree -p $$crate --edges normal >/dev/null 2>&1 || { echo "CRUX gate: $$crate not found (stale)"; exit 1; }; \
		if cargo tree -p $$crate --edges normal --invert dragonfruit 2>/dev/null | grep -q dragonfruit; then echo "CRUX violation: dragonfruit reachable from the build crate $$crate (must be confined to the orchard CLI)"; exit 1; fi; \
	done
	@cargo tree -p orchard --edges normal --invert dragonfruit 2>/dev/null | grep -q dragonfruit || { echo "CRUX anomaly: dragonfruit NOT reachable from orchard — the sign path moved? gate list stale"; exit 1; }
	@echo "CRUX Orchard OK: dragonfruit confined to the orchard CLI."

# cmdline-namespace lock: the FULL fb.* namespace grep, scoped to THIS repo's crates/
# (no recipes.* cmdline token or bare root-hash=). The same gate also runs in Fruit Basket; each
# repo's full regex over its own crates/ gives complete union coverage.
cmdline-lock:
	@if git grep -qE 'recipes\.(verity-hash-offset|rootfs-dev|mode|firmware|image-from|restore-from|net|injected)|recipes-injected' -- crates/; then echo "cmdline-namespace violation:"; git grep -nE 'recipes\.(verity-hash-offset|rootfs-dev|mode|firmware|image-from|restore-from|net|injected)|recipes-injected' -- crates/; exit 1; fi
	@if git grep -qE '(^|[^[:alnum:]._-])root-hash=' -- crates/; then echo "cmdline-namespace violation: bare root-hash="; git grep -nE '(^|[^[:alnum:]._-])root-hash=' -- crates/; exit 1; fi
	@echo "cmdline-namespace lock OK (orchard crates/)."

crypto-sentry:
	cargo test -p recipes-image-builder --test shipped_crate_allowlist
	cargo test -p recipes-image-builder --test zeroize_feature_guard

# boot-gate — the PRODUCED-BYTES proofs. These are deliberately
# NOT in `make verify`: `verify` proves the SEAM CONTRACT (parsers, golden configs, unit logic) but ZERO
# produced bytes. The boot gates assert the REAL artifact (byte-reproducible bakes; the SeaBIOS
# install->boot->rescue + crash-recovery chain on the produced .img) and need docker (bakes) + /dev/kvm +
# a built `.img`. They are `#[ignore]`d so the default `cargo test` reports them "ignored" (NEVER a false
# green); this target runs them via `--ignored`, where a missing env PANICS rather than silent-passing.
# Run AFTER `orchard build`, with RECIPES_{DRYRUN,PROD,RESCUE}_IMG (+ _PRIVKEY) set to it.
# The `deploy_prod_e2e` gate (the Debian-guest kexec-takeover) additionally needs
# RECIPES_PROD_E2E_DEBIAN_IMG (a pinned Debian generic-cloud qcow2) + cloud-localds; it reuses
# RECIPES_PROD_IMG/_PRIVKEY for the box. A missing Debian image FAILS this target loud (the
# env-panic propagates) — deliberately NOT caught/skipped: a skipped leg before the final "OK
# (produced bytes proven)" line would be a false green of the gate itself (the M-alpha class).
.PHONY: boot-gate
boot-gate:
	@echo "boot-gate: grocer atomicity gate FIRST — build-free, no docker/.img/kvm (cheap fail-fast)."
	# The grocer source-bump produced-bytes gate (atomicity + revision-blob legs over the
	# committed-pin anchor). Build-free: it builds grocer itself + drives the REAL binary through the REAL
	# executor on seed-vault's --source leg (the faked unit suite cannot prove this — it never runs grocer).
	# Self-armed via RECIPES_GROCER_GATE=1; a bare `cargo test --ignored` WITHOUT it PANICS (no silent skip).
	# NAME-FILTERED + "exactly 1 passed"-guarded (the M-α false-green guard) so a rename can't stale the filter.
	@out=$$(RECIPES_GROCER_GATE=1 cargo test -p orchard --test grocer_publish_gate -- --ignored --nocapture grocer_source_bump_is_atomic 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: grocer atomicity gate did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate: binary-publish gate (increment 2) — needs docker (build-only compile), no .img/kvm."
	# The binary-repo produced-bytes gate: drives a REAL `--binary fb-acme` publish
	# through the REAL grocer (ELF/linkage assert + hash + put) + the REAL executor — atomicity (forced
	# fail-before-swap → real trees byte-identical) + the §6 ELF control fires (a static-PIE-as-dynamic is
	# refused before any store write). Fills the gap grocer §9 named. Self-armed via RECIPES_BINARY_GATE=1;
	# a bare `--ignored` WITHOUT it PANICS. NAME-FILTERED + "1 passed"-guarded (the M-α false-green guard).
	# Needs the operator's fruit-basket checkout with its publish tooling (not in the public tree).
	@out=$$(RECIPES_BINARY_GATE=1 cargo test -p orchard --test binary_publish_gate -- --ignored --nocapture binary_publish_is_atomic_and_elf_asserts 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: binary-publish gate did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate: kernel-upgrade gate — build-free, no docker (fixture transport, REAL executor + verify + swap)."
	# The kernel-upgrade gate: Phase 1 (real ecosystem) proves the PRODUCTION fingerprint const
	# REJECTS a wrong signer with the real trees byte-identical; Phase 2 (a
	# disposable canonical copy, fixture-signer keyring) proves a verifiable bump LANDS the four-way pin +
	# post-swap `market verify --all` GREEN, and a tampered tarball leaves the copy byte-identical. Only the
	# NETWORK is faked. Self-armed via RECIPES_KERNEL_GATE=1; a bare `--ignored` WITHOUT it PANICS. The three
	# phases run in ONE #[test], so "1 passed"-GUARD it (the M-α false-green guard, like the gates above).
	@out=$$(RECIPES_KERNEL_GATE=1 cargo test -p orchard --test kernel_upgrade_gate -- --ignored --nocapture kernel_upgrade_is_verified_and_atomic 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: kernel-upgrade gate did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate: rust-upgrade gate — needs docker (Phase 3 container-rebuild), fixture transport."
	# The `market upgrade --rust` produced-bytes gate. Drives the REAL rust bump +
	# Phase 1 (real ecosystem) proves the REAL
	# SHA-1-self-signed Rust key LOADS via load_pinned_bare + the PRODUCTION RUST_SIGNER_FPR REJECTS a
	# throwaway sig (real trees byte-identical); Phase 2 (a disposable copy,
	# fixture-signer keyring) proves a verifiable bump LANDS the four-way pin + post-swap `market verify
	# --all` GREEN + a tampered manifest leaves the copy byte-identical; Phase 3 proves the docker
	# container-rebuild MECHANISM (build → double-build ROOTFS repro → digest-capture → stage → swap) on
	# a 2-line Containerfile (the REAL full toolchain rebuild is the named operator step). Self-armed via
	# RECIPES_RUST_GATE=1; a bare `--ignored` WITHOUT it PANICS. The four phases run in ONE #[test], so
	# "1 passed"-GUARD it (the M-α false-green guard, like the gates above).
	@out=$$(RECIPES_RUST_GATE=1 cargo test -p orchard --test rust_upgrade_gate -- --ignored --nocapture rust_upgrade_is_verified_and_atomic 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: rust-upgrade gate did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate: needs docker (build-side bakes) + /dev/kvm + RECIPES_{DRYRUN,PROD,RESCUE}_IMG (+ _PRIVKEY)."
	cargo test -p recipes-image-builder -- --ignored
	# deploy_dryrun.rs holds TWO #[ignore]d gates: the reference `dryrun_boots_to_working_runtime`
	# (this gate, RECIPES_DRYRUN_IMG) and the §9 toy `toy_manifest_boots_to_running_services` (a SEPARATE
	# `--manifest` .img, RECIPES_TOY_DRYRUN_IMG — `make boot-gate-toy`). NAME-FILTER to the reference so
	# the toy gate (different env/.img) doesn't run here; guard "exactly 1 passed" so a rename can't
	@out=$$(cargo test -p orchard --test deploy_dryrun -- --ignored --nocapture dryrun_boots_to_working_runtime 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: reference dryrun gate did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	# deploy_prod_qemu now holds TWO #[ignore]d gates: the SeaBIOS reference (this, RECIPES_PROD_IMG) and
	# the SeabiosGpt arm (a SEPARATE --firmware seabios-gpt .img, RECIPES_SEABIOSGPT_IMG — `make
	# boot-gate-seabios-gpt`). NAME-FILTER to the SeaBIOS gate so the SeabiosGpt gate (different env/.img)
	# doesn't run + panic here; guard "exactly 1 passed" so a rename can't silent-false-green the filter.
	@out=$$(cargo test -p orchard --test deploy_prod_qemu -- --ignored --nocapture installed_disk_boots_through_seabios_to_working_runtime 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: SeaBIOS prod-qemu gate did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	cargo test -p orchard --test deploy_rescue_smoke -- --ignored --nocapture
	# C1/AC7 restore-from VERIFY gate (signed proceeds + boots; wrong-key/tampered/over-cap abort BEFORE
	# any destructive write — target disk byte-untouched). Needs RECIPES_RESTORE_{IMG,PRIVKEY,KEYS_DIR};
	# KEYS_DIR is the artifact key set the .img baked as /etc/recipes/artifact-root.pub (the restore
	# trust anchor) — env-PANICs if unset. The 4 cases run in ONE #[test], so "1 passed"-GUARD it (the
	# M-α false-green guard, like the grocer/dryrun gates above): a deleted/un-ignored test → 0 tests →
	# `cargo test` exits 0 with the gate never running; the grep refuses that silent skip.
	@out=$$(cargo test -p orchard --test deploy_restore_smoke -- --ignored --nocapture 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: restore-from gate did not run (deleted? un-ignored? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate: the Debian-guest kexec-takeover e2e also needs RECIPES_PROD_E2E_DEBIAN_IMG + cloud-localds."
	# SKIPPED here: it needs the PRODUCTION co-tenant .img via its own RECIPES_PROD_WEIGHTS_IMG, which
	# this target's RECIPES_PROD_IMG is not — see `make boot-gate-prod-weights`. "2 passed"-GUARDED (the
	# M-alpha false-green guard, previously missing on this leg): a deleted/renamed/un-ignored test would
	# otherwise let `cargo test` exit 0 having run nothing.
	@out=$$(cargo test -p orchard --test deploy_prod_e2e -- --ignored --nocapture --skip installs_the_prod_weights_image 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 2 passed" || { echo "ERROR: prod-e2e reference legs did not run (renamed? filter stale / env unset) — refusing a false green"; exit 1; }
	@echo "boot-gate: OK (produced bytes proven)."
	@echo "boot-gate: the prod-weights e2e is SEPARATE (needs the prod co-tenant .img) — run \`make boot-gate-prod-weights\`."
	@echo "boot-gate: the non-recipes generalization gate is SEPARATE (needs a toy .img) — run \`make boot-gate-toy\`."
	@echo "boot-gate: the BIOS+GPT installer-arm gate is SEPARATE (needs a seabios-gpt .img) — run \`make boot-gate-seabios-gpt\`."
	@echo "boot-gate: the GPT deploy-prod kexec-takeover e2e is SEPARATE (needs a seabios-gpt .img) — run \`make boot-gate-seabios-gpt-e2e\`."
	@echo "boot-gate: the streaming installer's FAIL-CLOSED legs are SEPARATE (needs BOTH arms' .imgs) — run \`make boot-gate-streaming-neg\`."
	@echo "boot-gate: the UEFI/OVMF disk-boot gate is OPT-IN (substrate-deferred) — run \`make boot-gate-uefi\`."

# boot-gate-toy — the non-recipes generalization gate: a TOY `--manifest` tenant
# BOOTS TO RUNNING SERVICES, proving the de-hardcoding generalizes off recipes. SEPARATE from `boot-gate`
# because it needs its OWN `.img` (built `orchard build --manifest crates/image-builder/toy-tenant.toml`)
# at RECIPES_TOY_DRYRUN_IMG. Name-filtered + "1 passed"-guarded (same M-α false-green guard as above).
.PHONY: boot-gate-toy
.PHONY: boot-gate-ceremony-legs
# boot-gate-ceremony-legs — the LEG composition a ceremony's S8 runs. Separate from
# `boot-gate-ceremony` on purpose, and it is what the e2e fixture profile names as its
# `gate_target`: the e2e leg RUNS a ceremony, whose S8 invokes the gate target its profile names,
# so an e2e that named the target containing itself would recurse forever. the e2e's
# "never re-enters the battery containing itself" is exactly this, and
# `ceremony_gate::the_e2e_fixture_never_names_a_gate_target_containing_itself` holds it.
boot-gate-ceremony-legs:
	@echo "boot-gate-ceremony-legs: needs /dev/kvm + RECIPES_{DRYRUN,PROD}_IMG (+ _PRIVKEY) built from ONE ceremony."
	@out=$$(RECIPES_GATE_TARGET=boot-gate-ceremony-legs cargo test -p orchard --test deploy_dryrun -- --ignored --nocapture dryrun_boots_to_working_runtime 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: ceremony dryrun leg did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	@out=$$(RECIPES_GATE_TARGET=boot-gate-ceremony-legs cargo test -p orchard --test deploy_prod_qemu -- --ignored --nocapture installed_disk_boots_through_seabios_to_working_runtime 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: ceremony installed-disk leg did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate-ceremony-legs: OK (the declared composition booted the produced bytes)."

.PHONY: boot-gate-ceremony
# boot-gate-ceremony — the guided ceremony's OWN S8 composition.
# REDUCED on purpose: the ceremony gate proves the produced bytes boot, it does not re-run the full
# battery (that is `make boot-gate`). Every invocation here is `--test`-scoped AND name-filtered, so
# the declared leg set is derivable from this recipe alone — `ceremony::leg_registry::composition_of`
# refuses a target whose leg set depends on a test binary's own ignored set, and the agreement arm
# in `make verify` parses THIS target. Each leg emits its row into `<img>.gate-record.toml` on pass;
# the runner copies the finished record beside the profile at S8 completion.
# The e2e binary joins this recipe in Task 11.
boot-gate-ceremony:
	@echo "boot-gate-ceremony: needs /dev/kvm + RECIPES_{DRYRUN,PROD}_IMG (+ _PRIVKEY) built from ONE ceremony."
	$(MAKE) boot-gate-ceremony-legs
	@echo "boot-gate-ceremony: the end-to-end ceremony — needs RECIPES_CEREMONY_{IMG,PRIVKEY} + RECIPES_PROD_E2E_DEBIAN_IMG + cloud-localds."
	@out=$$(cargo test -p orchard --test deploy_ceremony_e2e -- --ignored --nocapture the_ceremony_installs_a_serving_box_from_a_profile_on_produced_bytes 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: the ceremony e2e did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate-ceremony: OK (the ceremony's declared composition booted the produced bytes)."

boot-gate-toy:
	@echo "boot-gate-toy: needs RECIPES_TOY_DRYRUN_IMG (a toy --manifest .img) + /dev/kvm."
	@out=$$(cargo test -p orchard --test deploy_dryrun -- --ignored --nocapture toy_manifest_boots_to_running_services 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: toy dryrun gate did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate-toy: OK (a non-recipes manifest boots to running services)."

# boot-gate-acme — the ACME cert-lifecycle produced-bytes gate: boots a from-pins
# REFERENCE recipes box (`-kernel`, serving haproxy on :443, root SSH) carrying the re-pinned fb-acme +
# fb-oneshots + the periodic_loop service-manifest, and drives the coupled watcher + renewer on the real
# RECIPES_ACME_IMG (host tools qemu/ssh/openssl + /dev/kvm; NO docker — `-kernel` boot, no install). ONE
# #[test], DOUBLE-guarded: cargo's exit code must be 0 (a real FAILED exits non-zero — a box-controlled
# --nocapture line can't forge a pass over it) AND the "1 passed" grep (the M-α false-green guard: a
# deleted/un-ignored test → 0 tests → cargo still exits 0, so the grep refuses that silent skip).
# RUN FOREGROUND: the full gate is ~90s (boot + several 10s watcher-reload poll windows +
# the renew legs) — longer than some background-task wall-clock limits, which SIGTERM `make` mid-run. The
.PHONY: boot-gate-acme
boot-gate-acme:
	@echo "boot-gate-acme: needs RECIPES_ACME_IMG (a from-pins reference .img) + /dev/kvm + host openssl. RUN FOREGROUND (~90s)."
	@out=$$(cargo test -p orchard --test deploy_acme_lifecycle -- --ignored --nocapture 2>&1); rc=$$?; \
	echo "$$out"; \
	{ [ $$rc -eq 0 ] && echo "$$out" | grep -q "test result: ok. 1 passed"; } || { echo "ERROR: acme-lifecycle gate did not run or did not pass (cargo rc=$$rc) — refusing a false green"; exit 1; }
	@echo "boot-gate-acme: OK (renewer + watcher cert lifecycle proven on produced bytes)."

# boot-gate-persist — the persist trust-file self-heal produced-bytes gate (Leg C
# + the ca.crt re-derive leg; Legs A + B not built): boots a from-pins reference
# box, corrupts full.pem (torn, then valid-cert-wrong-marker) and ca.crt over root SSH with a
# read-back, reboots from the same /persist, and asserts the heal (haproxy :443 leaf regenerates;
# ca.crt re-derives to the same identity, the box reaches services). SEPARATE from boot-gate because it needs its OWN reference .img carrying
# the persist-selfheal binaries at RECIPES_PERSIST_IMG (host tools qemu/ssh/openssl + /dev/kvm; NO
# docker — -kernel boot). ONE #[test], DOUBLE-guarded like boot-gate-acme: cargo's exit 0 AND the
# "1 passed" grep (the M-alpha false-green guard: 0 tests still exits 0, so the grep refuses a skip).
.PHONY: boot-gate-persist
boot-gate-persist:
	@echo "boot-gate-persist: needs RECIPES_PERSIST_IMG (a from-pins reference .img) + /dev/kvm + host openssl. RUN FOREGROUND (Leg C 3 boots, Leg D 2)."
	@out=$$(cargo test -p orchard --test deploy_persist_selfheal -- --ignored --nocapture 2>&1); rc=$$?; \
	echo "$$out"; \
	{ [ $$rc -eq 0 ] && echo "$$out" | grep -q "test result: ok. 1 passed"; } || { echo "ERROR: persist self-heal gate did not run or did not pass (cargo rc=$$rc) — refusing a false green"; exit 1; }
	@echo "boot-gate-persist: OK (torn full.pem + ca.crt heal on produced bytes)."

# boot-gate-lifecycle — the Phase-5a lifecycle produced-bytes gate: INSTALLS a
# seabios-gpt A/B .img to a real GPT disk (the dd-only installer), boots the INSTALLED disk through SeaBIOS,
# and drives `orchard status` (drift compare + read-only) + the rotate-key state machine (round-trip, 0644
# root:root, never-locked-out) against the LIVE box over real SSH. SEPARATE from `boot-gate` because it needs
# its OWN seabios-gpt A/B .img (fb-update present + baked fb.firmware/image_version) at RECIPES_LIFECYCLE_IMG,
# plus the matching operator private key at RECIPES_LIFECYCLE_PRIVKEY (the box boots from its BAKED persist-
# skeleton key — NOT an ephemeral gate key — so the rotate target authenticates + its derived line matches).
# Build it like the seabios-gpt arm, deriving a NO-COMMENT pubkey so the baked authorized_keys line equals
# `rotate_key::derive_line` (a `user@host` comment would fail the strict content-gate):
#   ssh-keygen -t ed25519 -N '' -f <key>; ssh-keygen -y -f <key> > <key>.pub
#   orchard build --firmware seabios-gpt --domain box.test --operator-pubkey <key>.pub \
#     --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" --out-dir <dir> --allow-dirty
# then RECIPES_LIFECYCLE_IMG=<dir>/<img>.img RECIPES_LIFECYCLE_PRIVKEY=<key>. ONE #[test], DOUBLE-guarded:
# (a) `cargo`'s exit code must be 0 (a real test FAILED exits non-zero — a box-controlled `--nocapture`
# line can't forge a pass over it), AND (b) the "1 passed" grep (the M-α false-green guard: a
# deleted/un-ignored test → 0 tests → `cargo test` still exits 0, so the grep refuses that silent skip).
.PHONY: boot-gate-lifecycle
boot-gate-lifecycle:
	@echo "boot-gate-lifecycle: needs RECIPES_LIFECYCLE_IMG + RECIPES_LIFECYCLE_PRIVKEY (a seabios-gpt A/B .img + its operator key) + /dev/kvm (host tools qemu/veritysetup/ssh/fakeroot/mke2fs; NO docker — greenfield install+boot)."
	@out=$$(cargo test -p orchard --test deploy_lifecycle_smoke -- --ignored --nocapture 2>&1); rc=$$?; \
	echo "$$out"; \
	{ [ $$rc -eq 0 ] && echo "$$out" | grep -q "test result: ok. 1 passed"; } || { echo "ERROR: lifecycle gate did not run or did not pass (cargo rc=$$rc) — refusing a false green (the cargo exit gates the grep, so a box-injected '--nocapture' line cannot mask a real FAILED)"; exit 1; }
	@echo "boot-gate-lifecycle: OK (orchard status + rotate-key proven on produced bytes)."

# boot-gate-seabios-gpt — the BIOS+GPT installer-arm produced-bytes convergence gate.
# SEPARATE from `boot-gate` because it needs its OWN `--firmware seabios-gpt` .img (the dha-hosting box
# arm; the default box is still SeaBIOS/MBR) at RECIPES_SEABIOSGPT_IMG (+ _PRIVKEY). Build it:
#   orchard build --firmware seabios-gpt --domain box.test --operator-pubkey <key.pub> \
#     --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" --out-dir <dir> --allow-dirty
# then RECIPES_SEABIOSGPT_IMG=<dir>/<img>.img RECIPES_SEABIOSGPT_PRIVKEY=<key>. Name-filtered + "1 passed"
# guarded (the M-α false-green guard): a SeaBIOS-on-GPT install + disk-boot to the runtime contract.
.PHONY: boot-gate-seabios-gpt
boot-gate-seabios-gpt:
	@echo "boot-gate-seabios-gpt: needs RECIPES_SEABIOSGPT_IMG + RECIPES_SEABIOSGPT_PRIVKEY + docker + /dev/kvm."
	@out=$$(cargo test -p orchard --test deploy_prod_qemu -- --ignored --nocapture installed_seabios_gpt_disk_boots_through_seabios_to_working_runtime 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: SeabiosGpt boot-gate did not run (renamed? filter stale / env unset) — refusing a false green"; exit 1; }
	@echo "boot-gate-seabios-gpt: OK (BIOS+GPT produced bytes proven)."

# e2e-kexec-fixture — build the Debian fixture the HERMETIC prod-e2e legs consume.
# NOT a gate: it asserts nothing about the box, it PRODUCES an input. The prod-e2e guest now runs
# `-netdev user,…,restrict=on` (no outbound NAT/DNS), because a box booted under open NAT ran its
# `fb-acme-renew` longrun against Let's Encrypt PRODUCTION — creating an ACME account from the
# operator's IP on every gate run. Hermetic means `kexec-tools` can no longer be apt-installed at
# boot, so it is baked in ONCE here. This is the only leg in the repo that needs outbound network.
# Run it again whenever the pinned Debian base is re-pinned. "1 passed"-guarded like the gates.
.PHONY: e2e-kexec-fixture
e2e-kexec-fixture:
	@echo "e2e-kexec-fixture: needs RECIPES_PROD_E2E_DEBIAN_BASE + RECIPES_KEXEC_FIXTURE_OUT + /dev/kvm + OUTBOUND NETWORK."
	@out=$$(cargo test -p orchard --test e2e_kexec_fixture -- --ignored --nocapture 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: the kexec fixture build did not run (renamed? env unset?) — refusing to report a fixture that was never written"; exit 1; }
	@echo "e2e-kexec-fixture: OK (record the printed sha256; point RECIPES_PROD_E2E_DEBIAN_IMG at the output)."

# boot-gate-reclaim — the reclaim-tail produced-bytes gate. Runs the REAL ceremony
# against the GROWN fixture (`make e2e-grown-fixture`), whose root fills its disk exactly as a
# default-provisioned VPS does — the state D-1 refuses unconditionally, and the only state in which
# these legs mean anything. "exactly 2 passed"-guarded (the M-alpha false-green guard): a leg that
# silently skipped would otherwise report a green over half the surface.
.PHONY: boot-gate-reclaim
boot-gate-reclaim:
	@echo "boot-gate-reclaim: needs RECIPES_RECLAIM_IMG + RECIPES_RECLAIM_PRIVKEY + RECIPES_RECLAIM_E2E_DEBIAN_IMG (the GROWN fixture) + /dev/kvm."
	@out=$$(cargo test -p orchard --test reclaim_e2e -- --ignored --nocapture 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 2 passed" || { echo "ERROR: the reclaim legs did not both run (renamed? env unset? one leg skipped) — refusing a false green"; exit 1; }
	@echo "boot-gate-reclaim: OK (RT-1 + RT-2 on produced bytes)."

# e2e-grown-fixture — build the DEFAULT-PROVISIONED Debian fixture the reclaim-tail gate consumes
# (D-2 §9): kexec-tools baked in, cloud-initramfs-growroot RETAINED, disk grown to 12 GiB, root
# grown to fill it on first boot. The builder fails closed if growroot is missing, the root did not
# grow, or the fstab lost its x-systemd.growfs token (RT-1 would go vacuous).
.PHONY: e2e-grown-fixture
e2e-grown-fixture:
	@echo "e2e-grown-fixture: needs RECIPES_PROD_E2E_DEBIAN_BASE + RECIPES_GROWN_FIXTURE_OUT + /dev/kvm + OUTBOUND NETWORK."
	@out=$$(cargo test -p orchard --test e2e_grown_fixture -- --ignored --nocapture 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: the grown fixture build did not run (renamed? env unset?) — refusing to report a fixture that was never written"; exit 1; }
	@echo "e2e-grown-fixture: OK (record the printed sha256; point RECIPES_RECLAIM_E2E_DEBIAN_IMG at the output)."

# boot-gate-streaming-neg — the streaming installer's FAIL-CLOSED legs. SEPARATE from
# `boot-gate` because it drives BOTH
# firmware arms and asserts REFUSALS rather than a working runtime: four doomed variants per arm
# (digest-flip / window-overlap / fw-mismatch / no-sha), each booted through the REAL installer VM on a
# REAL staged disk, asserting the SPECIFIC `fb-init FATAL` reason on the console AND that LBA0 of the
# disk file is still zero (the partition table was never written — verify-before-write). Reuses the two
# arms' existing images: RECIPES_PROD_IMG (SeaBIOS/MBR, the standard battery's reference) +
# RECIPES_SEABIOSGPT_IMG (the `--firmware seabios-gpt` arm the production `orchard prod` ceremony
# deploys). No privkey: these legs never reach a booted box. "exactly 2 passed"-guarded (the M-α
# false-green guard) — one arm silently skipping would report a green that proved half the surface.
.PHONY: boot-gate-streaming-neg
boot-gate-streaming-neg:
	@echo "boot-gate-streaming-neg: needs RECIPES_PROD_IMG + RECIPES_SEABIOSGPT_IMG + /dev/kvm (no docker, no privkey)."
	@out=$$(cargo test -p orchard --test deploy_streaming_negatives -- --ignored --nocapture 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 2 passed" || { echo "ERROR: streaming-negative legs did not both run (renamed? env unset? one arm skipped) — refusing a false green"; exit 1; }
	@echo "boot-gate-streaming-neg: OK (both firmware arms fail closed on produced bytes; table never written)."

# boot-gate-update — the os-update A/B PRODUCED-BYTES gate. SEPARATE from `boot-gate`:
# it needs TWO seabios-gpt .imgs (--image-version 1 installed + --image-version 2 streamed, same
# --operator-pubkey + --net) AND an artifact key set carrying the UpdateImage delegation (a
# `generate-keys --artifact-signing software` set, or a deploy set + `orchard redelegate`). Build them:
#   orchard redelegate --keys-dir <keys>   # if the set predates the update path
#   orchard build --firmware seabios-gpt --domain box.test --image-version 1 --keys-dir <keys> \
#     --operator-pubkey <op.pub> --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" \
#     --out-dir <v1> --allow-dirty          # then again with --image-version 2 --out-dir <v2>
# A THIRD image for G4 (the fb-mark-good deadline rollback): --image-version 2 --manifest <a copy of
# the reference service-manifest.toml with [probe] port set to a CLOSED port, e.g. 48443> --out-dir
# <v2u>. then RECIPES_UPDATE_V1_IMG=<v1>/<img>.img RECIPES_UPDATE_V2_IMG=<v2>/<img>.img
# RECIPES_UPDATE_V2_UNHEALTHY_IMG=<v2u>/<img>.img RECIPES_UPDATE_PRIVKEY=<op>
# RECIPES_UPDATE_KEYS_DIR=<keys>. The battery (G1 happy+commit+durable, the G5 refusal battery, G3
# panic=10 rollback + G6 + G9(i), G7 NOESCAPE, G4 mark-good deadline reboot()) runs in ONE #[test];
# "1 passed"-guarded (the M-α false-green guard): a deleted/un-ignored test → 0 tests → cargo exits 0
# with the gate never running; the grep refuses that silent skip.
.PHONY: boot-gate-update
boot-gate-update:
	@echo "boot-gate-update: needs RECIPES_UPDATE_{V1_IMG,V2_IMG,V2_UNHEALTHY_IMG,PRIVKEY,KEYS_DIR} + docker + /dev/kvm."
	@out=$$(cargo test -p orchard --test deploy_update_smoke -- --ignored --nocapture ab_update_cycle_on_produced_bytes 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: A/B update boot-gate did not run (renamed? filter stale / env unset) — refusing a false green"; exit 1; }
	@echo "boot-gate-update: OK (A/B update produced bytes proven)."

# boot-gate-seabios-gpt-e2e — the GPT deploy-prod arm's kexec-takeover e2e. SEPARATE from
# `boot-gate` (the proven MBR kexec e2e, byte-unchanged) and from `boot-gate-seabios-gpt` (the QEMU
# install gate) because it needs its OWN --firmware seabios-gpt .img built with --operator-pubkey +
# --net at RECIPES_SEABIOSGPT_PROD_E2E_IMG (+ _PRIVKEY) AND the shared RECIPES_PROD_E2E_DEBIAN_IMG.
# Name-filtered "1 passed"-guarded (M-alpha false-green guard).
.PHONY: boot-gate-seabios-gpt-e2e
boot-gate-seabios-gpt-e2e:
	@echo "boot-gate-seabios-gpt-e2e: needs RECIPES_SEABIOSGPT_PROD_E2E_IMG + _PRIVKEY + RECIPES_PROD_E2E_DEBIAN_IMG + docker + /dev/kvm + cloud-localds."
	@out=$$(cargo test -p orchard --test deploy_prod_seabios_gpt_e2e -- --ignored --nocapture 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: seabios-gpt kexec e2e gate did not run (renamed? filter stale / env unset) — refusing a false green"; exit 1; }
	@echo "boot-gate-seabios-gpt-e2e: OK (GPT kexec-takeover produced bytes proven)."

# boot-gate-prod-weights — the operator's REAL `deploy
# prod` ceremony proven against the PRODUCTION artifact. The prod co-tenant `.img` (the Qwen3-VL-2B pair
# in its weights volume, MEASURED 1804 MiB) is installed onto a Debian guest with 2048 MiB RAM. The
# image is slightly SMALLER than the guest, so the proof is not `image > RAM` but that the image cannot
# be BUFFERED whole: 1804.4 + the 256 MiB installer minimum = 2060.4 > 2048.0, by only 12.4 MiB, i.e. the retired
#
# SEPARATE from `boot-gate` because it needs its OWN `.img`: `boot-gate`'s RECIPES_PROD_IMG is a plain
# reference box, and one env cannot be both. Build it:
#   cargo run -p orchard -- build --dha-weights-gguf <qwen3-vl-2b-instruct-q4km.gguf> \
#     --firmware seabios-gpt --domain prod.test --manifest crates/image-builder/prod-cotenant.toml \
#     --operator-pubkey <key.pub> --recovery-pubkey <key.pub> \
#     --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" --out-dir <dir> --allow-dirty
# (the mmproj is picked up beside the model GGUF by its pinned name, or pass --dha-mmproj-gguf;
# both shas are verified fail-closed at bake; the guided ceremony retired the env form), then
#   RECIPES_PROD_WEIGHTS_IMG=<dir>/<img>.img RECIPES_PROD_WEIGHTS_PRIVKEY=<key> \
#   RECIPES_PROD_E2E_DEBIAN_IMG=<debian.qcow2>
# Name-filtered + "1 passed"-guarded (the M-alpha false-green guard). The harness ALSO refuses, before
# any boot, an image that is not the prod shape (unbufferable-in-RAM + a weights-payload floor against
# the pinned profile) — so pointing this at a bench fixture fails loud, not green.
.PHONY: boot-gate-prod-weights
boot-gate-prod-weights:
	@echo "boot-gate-prod-weights: needs RECIPES_PROD_WEIGHTS_IMG + _PRIVKEY + RECIPES_PROD_E2E_DEBIAN_IMG + docker + /dev/kvm + cloud-localds."
	@out=$$(cargo test -p orchard --test deploy_prod_e2e -- --ignored --nocapture installs_the_prod_weights_image 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: the prod-weights e2e did not run (renamed? filter stale / env unset) — refusing a false green"; exit 1; }
	@echo "boot-gate-prod-weights: OK (the prod co-tenant image, unbufferable in guest RAM, installed by the streaming ceremony)."

# from `boot-gate` because it needs its OWN dha `.img`: a `--firmware seabios-gpt --manifest
# crates/image-builder/dha-tenant.toml` build with `--dha-weights-gguf` (bakes the 5th GPT
# weights partition; the guided ceremony retired the env form). Build it:
#   cargo run -p orchard -- build --dha-weights-gguf <qwen2.5-coder-1.5b-q2_k.gguf> --firmware seabios-gpt \
#     --domain dha.test --manifest crates/image-builder/dha-tenant.toml --operator-pubkey <key.pub> \
#     --net "mode=static;ip=10.0.2.15/24;gw=10.0.2.2;dns=10.0.2.3" --out-dir <dir> --allow-dirty
# boot-gate-dha — the dha AI-tenant confinement produced-bytes gate. Build the dha .img first,
# then RECIPES_DHA_IMG=<dir>/<img>.img RECIPES_DHA_PRIVKEY=<key>. The two legs (F1–F4 confine+survive;
# F5 weights-tamper→EIO, box survives) both use the one `.img`. Name+count-guarded (the M-α false-green
# guard): a MISSING env PANICS under `--ignored`, so a bare run can never report a silent green. The
# tenant is a busybox STAND-IN (box-mechanism proof); the real-binary end-to-end is a follow-on component.
.PHONY: boot-gate-dha
boot-gate-dha:
	@echo "boot-gate-dha: needs RECIPES_DHA_IMG + RECIPES_DHA_PRIVKEY + docker + /dev/kvm."
	@# --test-threads=1: each leg boots QEMU with the SAME hostfwd ports (2222/8443) — concurrent legs
	@# race the ports and the loser dies at qemu startup (seen 2026-07-10), never a box verdict.
	@out=$$(cargo test -p orchard --test deploy_dha -- --ignored --nocapture --test-threads=1 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 2 passed" || { echo "ERROR: dha boot-gate did not run (renamed? filter stale / env unset) — refusing a false green"; exit 1; }
	@echo "boot-gate-dha: OK (dha tenant confinement + weights-EIO produced bytes proven)."

# ACs 1-11 + the 3 riders). SEPARATE from `boot-gate` and `boot-gate-dha` because it needs its OWN
# v4 `.img`: a `--firmware seabios-gpt --weights-anchor runtime --manifest
# crates/image-builder/hotswap-tenant.toml` build (models.toml-pinned GGUF baked; the signed
# weights record in the persist skeleton; NO fb.weights-* cmdline) PLUS the artifact key set that
# signed it, a PRE-redelegate snapshot of that set (the below-floor negative), and a DIFFERENT
# smaller push GGUF. Full build ceremony: crates/orchard/tests/deploy_model_gate.rs module doc.
# Env: RECIPES_HOTSWAP_IMG + RECIPES_HOTSWAP_PRIVKEY + RECIPES_HOTSWAP_KEYS_DIR +
#      RECIPES_HOTSWAP_KEYS_OLD_DIR + RECIPES_HOTSWAP_PUSH_GGUF (+ optional
# boot-gate-hotswap — the runtime-anchored model-swap produced-bytes gate. Needs its own
# dha-shaped .img + the hotswap env set (incl. the optional container override
#      RECIPES_HOTSWAP_CONTAINER_IMAGE, default recipes-imgbuild:dev).
# The two legs (swap battery; degrade/torn recovery) each install their own disk from the one
# `.img`. Name+count-guarded (the M-α false-green guard): a MISSING env PANICS under `--ignored`,
# so a bare run can never report a silent green.
.PHONY: boot-gate-hotswap
boot-gate-hotswap:
	@echo "boot-gate-hotswap: needs RECIPES_HOTSWAP_{IMG,PRIVKEY,KEYS_DIR,KEYS_OLD_DIR,PUSH_GGUF} + docker + /dev/kvm."
	@# --test-threads=1: both legs boot QEMU with the SAME hostfwd ports (2222/8443) — concurrent
	@# legs race the ports and the loser dies at qemu startup (the boot-gate-dha lesson).
	@out=$$(cargo test -p orchard --test deploy_model_gate -- --ignored --nocapture --test-threads=1 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 3 passed" || { echo "ERROR: hotswap boot-gate did not run (renamed? filter stale / env unset) — refusing a false green"; exit 1; }
	@echo "boot-gate-hotswap: OK (runtime-anchored model swap + degrade/torn recovery + deterministic crash-injection proven on produced bytes)."

# docker-sign-gate — the ATTENDED docker-rung signing e2e (the docker half). Proves a
# wrapped-custody set round-trips a weights + an update manifest through the pinned container and the
# bundles verify. ATTENDED by design: `docker_sign_argv` runs `-it` and the in-container passphrase
# read is isatty-fail-closed (the host never buffers it) — the operator types the wrap passphrase
# (`pw` for the test fixture) at each prompt. Runs in the T10 attended window; needs docker + the
# cached `recipes-imgbuild:dev`. Name+env-guarded: a bare run PANICS without RECIPES_DOCKER_SIGN_GATE=1.
.PHONY: docker-sign-gate
docker-sign-gate:
	@# Pre-check the gate test EXISTS before the attended run — a stale rename/filter would otherwise
	@# make `cargo test` exit 0 on "0 passed" (a false green). Caught loud, BEFORE you invest the time.
	@cargo test -p orchard --test docker_sign_gate -- --list 2>/dev/null | grep -q wrapped_custody_signs_weights \
	  || { echo "ERROR: docker-sign gate test missing/renamed — refusing a false green"; exit 1; }
	@echo "docker-sign-gate: ATTENDED — the container builds orchard from source then prompts TWICE"
	@echo "  (once per purpose, weights + update-image); type the wrap passphrase 'pw' at EACH prompt."
	@# Run LIVE (no output capture) so `docker run -it`'s prompt is a real TTY and you can see + answer it.
	@# `--exact` pins the name; a non-zero cargo exit (wrong passphrase / verify fail / build fail) fails here.
	RECIPES_DOCKER_SIGN_GATE=1 cargo test -p orchard --test docker_sign_gate -- --ignored --nocapture \
	  --exact wrapped_custody_signs_weights_and_update_manifests_in_the_container
	@echo "docker-sign-gate: 'test result: ok. 1 passed' above = the wrapped-custody docker rung is proven (AC-C2/AC-D2)."

# SEPARATE from `boot-gate` because it needs ONLY docker (the pinned recipes-imgbuild:dev), NOT a built
# boot-gate-per-uid — the per-uid rootfs-baking byte-level gate. Needs docker only — no
# .img or /dev/kvm: it bakes a REPRESENTATIVE tree (nested dirs / rel symlink / suid / a declared owner)
# and asserts D5 byte-identity (Ownership::Map == -all-root), the owner-exception bake (uid/gid/mode on
# ~3000-inode real-tree + the QEMU owner/exec/EROFS legs are the operator-run `make boot-gate` after
# `orchard build`. Count-guarded (M-α false-green guard): 4 legs must pass, else refuse a false green.
.PHONY: boot-gate-per-uid
boot-gate-per-uid:
	@echo "boot-gate-per-uid: needs docker + recipes-imgbuild:dev (no .img / no /dev/kvm)."
	@out=$$(cargo test -p recipes-image-builder --test per_uid_baking -- --ignored --nocapture 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 4 passed" || { echo "ERROR: per-uid byte-gate did not run (renamed? filter stale / docker down) — refusing a false green"; exit 1; }
	@echo "boot-gate-per-uid: OK (D5 byte-identity + owner-on-disk + byte-repro proven on representative bytes)."

# `boot-gate` because UEFI is substrate-deferred (Infomaniak is BIOS-only): forcing a UEFI `.img` on
# boot-gate-uefi — the UEFI/OVMF produced-bytes battery. SEPARATE from `boot-gate`: wiring it into
# every SeaBIOS boot-gate run would break the SeaBIOS-only operator. FOLD INTO `boot-gate` once a UEFI
# substrate ships. Two rungs, both `#[ignore]` + panic-without-env (M-α, never a false green):
#
# SB-OFF (§9.1 — the keystone; needs only the plain blobs):
#   RECIPES_UEFI_IMG=<dir>/<img>.img RECIPES_UEFI_PRIVKEY=<operator-key> \
#   RECIPES_OVMF_CODE=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
#   RECIPES_OVMF_VARS=/usr/share/edk2/x64/OVMF_VARS.4m.fd
#
# SB-ON (§9.2 positive + §9.3 negatives; needs a `--secure-boot` img + an SB family + the secboot CODE
# + virt-fw-vars on PATH):
#   RECIPES_UEFI_SB_IMG=<dir>/<sb-img>.img RECIPES_UEFI_PRIVKEY=<operator-key> \
#   RECIPES_SB_KEYS_DIR=<dir-with-secure-boot/> RECIPES_SB_DB_PIN=<keys-dir>/pinned-secure-boot-db.toml \
#   RECIPES_OVMF_CODE_SECBOOT=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
#   RECIPES_OVMF_CODE=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
#   RECIPES_OVMF_VARS=/usr/share/edk2/x64/OVMF_VARS.4m.fd
# (each gate signs/enrolls/tampers its OWN scratch copy; the §9.3f flag-gate also needs the plain CODE.)
# §9.5a (the signed-USB installer install->reboot->target-boots close) ALSO needs the installer USB —
# build it off the signed RECIPES_UEFI_SB_IMG with the SAME SB family, then point the gate at it:
#   orchard build-installer-usb --from <signed RECIPES_UEFI_SB_IMG>
#   orchard sign-installer-usb --img <the emitted recipes-installer-usb-*.img> --keys-dir <keys-dir>
#   RECIPES_INSTALLER_USB_IMG=<that signed recipes-installer-usb-*.img>
# RECIPES_SB_DB_PIN points at the TEST family's THROWAWAY pin. Mint the test family WITH the pin redirected
# OFF the repo path so it never clobbers the operator's committed anchor (which mirrors the tracked
#   orchard generate-keys --secure-boot software --output-dir <keys-dir> \
#       --sb-db-fingerprint-path <keys-dir>/pinned-secure-boot-db.toml
# then RECIPES_SB_DB_PIN=<keys-dir>/pinned-secure-boot-db.toml. (Default, no override → the committed repo
# anchor crates/image-builder/pinned-secure-boot-db.toml — the operator's real enrollment ceremony.)
.PHONY: boot-gate-uefi
boot-gate-uefi:
	@echo "boot-gate-uefi: SB-OFF needs RECIPES_UEFI_IMG; SB-ON needs RECIPES_UEFI_SB_IMG + RECIPES_SB_* + the secboot CODE + virt-fw-vars. /dev/kvm required."
	# The loader-PE double-build reproducibility gate (§9.4 part 1) — pure cargo (two clean release
	# x86_64-unknown-uefi builds), no KVM/docker; fixes its own inputs (panic-without-env does not apply).
	# unreachable by any make target until wired here). RECIPES_LOADER_DEV=1 lets the OUTER test-harness
	# compile (build.rs fail-closes without policy env); the test's INNER double-build env_removes it +
	# sets the real RECIPES_LOADER_* (so the reproduced PEs carry real baked policy, not the dev marker).
	RECIPES_LOADER_DEV=1 cargo test --manifest-path vendor/rambutan/Cargo.toml -- --ignored --nocapture
	# sbsign in the container), no KVM. Asserts Authenticode-DIGEST equivalence (sbsign embeds a wall-clock
	# signingTime, so raw byte-identity does NOT hold; the signed PE's hash-covered bytes reproduce the
	# unsigned build). NAME-FILTERED (the sibling --ignored deploy-lib tests are 28-min full .img builds),
	# so assert it ACTUALLY ran — a bare `cargo test -- <stale-name>` exits 0 "0 passed", a silent
	@out=$$(cargo test -p orchard --lib -- --ignored signed_pe_authenticode_bytes_reproduce_the_unsigned_build 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 1 passed" || { echo "ERROR: signed-PE repro gate did not run (renamed? filter stale) — refusing a false green"; exit 1; }
	# --test-threads=1: the boot gates are heavy QEMU/OVMF boots that bind FIXED hostfwd ports
	# (sb_opts() 2223/8444); running them in parallel both thrashes KVM and collides on the host-port
	# bind (two positive gates fighting for :2223 → the loser's QEMU dies = a false failure). Serialize.
	# The SB-off + SB-on battery, EXCLUDING the 6 §9.5 installer-USB gates (counted separately below, so
	# their pass-count is on a clean libtest summary line). --nocapture for live operator visibility;
	# --test-threads=1 serializes (heavy QEMU boots bind fixed hostfwd ports — see above).
	cargo test -p orchard --test deploy_uefi_ovmf -- --ignored --nocapture --test-threads=1 --skip installer_usb
	# The 6 §9.5 installer-USB gates, NAME-FILTERED and WITHOUT --nocapture so libtest emits a clean
	# the test, so "ok" lands on its own line → a per-name "NAME ... ok" grep false-REDs a fully-green
	# a deleted/renamed gate drops the count, an added one bumps it — either fails loud, never a false
	# green. (QEMU console goes to log files, not stdout, so the summary line is not spoofable.)
	@out=$$(cargo test -p orchard --test deploy_uefi_ovmf -- --ignored --test-threads=1 installer_usb 2>&1); \
	echo "$$out"; \
	echo "$$out" | grep -q "test result: ok. 6 passed" || { echo "ERROR: expected EXACTLY 6 §9.5 installer-USB gates to run+pass (deleted/renamed/added? filter stale) — refusing a false green"; exit 1; }
	@echo "boot-gate-uefi: OK (UEFI produced bytes proven, SB-off + SB-on + §9.5 installer-USB ×6 exact-count-guarded + loader repro + signed-PE repro)."

# boot-gate-uefi-usb — the bare-metal USB REPRODUCTION (2026-06-12 step-back). DIAGNOSTIC, not a gate:
# it assembles the disk EXACTLY as install-usb.sh does (sgdisk GPT + component dd) and USB-boots it
# through OVMF so the kernel enumerates it ASYNC as /dev/sda — the path the laptop boots, which the
# virtio boot-gate-uefi above is structurally blind to. A PASS means the USB/partuuid path works under
# QEMU (→ the laptop trouble is more firmware/SB/stick-specific). A FAIL is often the POINT: read the
# captured console (RECIPES_PROD_GATE_LOGDIR or the temp workdir) to watch resolve_partuuid spin / see
# whether /dev/sda ever appears. Needs `sgdisk` + /dev/kvm in addition to the boot-gate-uefi env.
.PHONY: boot-gate-uefi-usb
boot-gate-uefi-usb:
	@echo "boot-gate-uefi-usb: SB-OFF USB repro needs RECIPES_UEFI_IMG (a NON-secure-boot image) + _PRIVKEY + RECIPES_OVMF_CODE/_VARS + sgdisk + /dev/kvm."
	@echo "boot-gate-uefi-usb: a FAILURE here may BE the reproduction — read the console log it points to."
	cargo test -p orchard --test deploy_uefi_ovmf -- --ignored --nocapture uefi_usb_repro_boots_through_ovmf
	@echo "boot-gate-uefi-usb: SB-OFF USB repro done. For the FULL-fidelity SB-ON USB repro, set the SB-ON"
	@echo "  battery env (see boot-gate-uefi) and run:"
	@echo "  cargo test -p orchard --test deploy_uefi_ovmf -- --ignored --nocapture uefi_sb_on_usb_repro_boots_the_signed_chain"
