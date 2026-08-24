#!/usr/bin/env python3
"""Author a `Boot0001` load option carrying ATTACKER OptionalData on top of an
already-enrolled OVMF VARS — the LoadOptions-injection probe (the loader's
SOLE empirical close; deploy_uefi_ovmf.rs::uefi_sb_on_ignores_injected_loadoptions).

The UEFI boot manager hands a `Boot####` option's OptionalData to the launched
image as `EFI_LOADED_IMAGE_PROTOCOL.LoadOptions`. This fixture points `Boot0001`
at the RELOCATED loader (`\\EFI\\rambutan\\loader.efi`, a non-default path so the
default `\\EFI\\BOOT\\BOOTX64.EFI` removable route is gone — the gate deletes it,
making `Boot0001` the ONLY route to services, so a vacuous default-path boot
cannot mask a failure) and stuffs OptionalData with an injected cmdline. If the
box still reaches services with the BAKED cmdline (injected token absent), the
loader provably ignored its own LoadOptions.

Driven by the same `virt.firmware` library the SB-ON gate already requires for
`virt-fw-vars` (the enrolled-VARS fixture) — the narrowest tool for the one thing
the `virt-fw-vars` CLI cannot do: set a `Boot####` OptionalData. Test-only; runs
under the opt-in `make boot-gate-uefi`, never `make verify`.

Usage:
  uefi-inject-boot-option.py <in_vars> <out_vars> <esp_loader_path> <injected_cmdline>
    in_vars          enrolled OVMF VARS (PK/KEK/db already set)
    out_vars         output VARS (enrolled + Boot0001 + BootOrder=[0001])
    esp_loader_path  the relocated loader, e.g.  \\EFI\\rambutan\\loader.efi
    injected_cmdline e.g.  fb.injected=PWNED  (encoded as UCS-2 OptionalData)
"""
import sys

from virt.firmware.efi import devpath, ucs16
from virt.firmware.varstore import autodetect


def main() -> int:
    if len(sys.argv) != 5:
        sys.stderr.write(__doc__)
        return 2
    in_vars, out_vars, esp_loader_path, injected = sys.argv[1:5]

    varstore = autodetect.open_varstore(in_vars)
    if varstore is None:
        sys.stderr.write(f"could not open varstore {in_vars}\n")
        return 1
    varlist = varstore.get_varlist()

    # A file-path-only device path (no HD() prefix); OVMF short-form-expands it
    # across every SimpleFileSystem handle → it finds the loader on the installed
    # ESP. (`\\EFI\\rambutan\\loader.efi` is where the gate relocated the signed
    # loader.) The `filepath()` factory returns a DevicePath whose `__bytes__`
    # emits the FILEPATH node + the terminating END node.
    dp = devpath.DevicePath.filepath(esp_loader_path)

    # OptionalData = the injected cmdline as NUL-terminated UCS-2 — exactly how a
    # real cmdline would arrive in LoadOptions (the Linux EFI stub decodes UCS-2).
    optdata = bytes(ucs16.from_string(injected))

    # Boot0001 = the injected option; BootOrder = [0001] ONLY (no fallback entry —
    # if Boot0001 fails to launch, BDS finds nothing bootable → no services → the
    # gate fails loud, never a silent default-path pass).
    varlist.set_boot_entry(1, "fb-injected", dp, optdata)
    bootorder = varlist.get("BootOrder")
    if bootorder is None:
        bootorder = varlist.create("BootOrder")
    bootorder.set_boot_order([1])

    varstore.write_varstore(out_vars, varlist)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
