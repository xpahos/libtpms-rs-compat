#!/usr/bin/env python3
"""Verify the TIS ABI surface of the built libtpms and its consumers.

Two independent checks, both driven by ``nm``:

1. The Rust-built libtpms dynamic library must export every ``TPM_IO_*``
   symbol from tpm_tis.h.
2. No consumer binary or support library handed to ``--consumer`` may leave
   a ``TPM_IO_*`` symbol as a Mach-O "dynamically looked up" reference: on
   macOS ``-undefined dynamic_lookup`` builds succeed and then crash at the
   first call, which is exactly the failure mode this script exists to stop.

ELF consumers cannot defer resolution this way (the link would fail), so on
Linux only the export check applies to the library and consumers are
accepted as-is.
"""

import argparse
import subprocess
import sys

REQUIRED_TIS_SYMBOLS = (
    "TPM_IO_Hash_Start",
    "TPM_IO_Hash_Data",
    "TPM_IO_Hash_End",
    "TPM_IO_TpmEstablished_Get",
    "TPM_IO_TpmEstablished_Reset",
)


def _strip_underscore(name):
    return name[1:] if name.startswith("_") else name


def exported_symbols(nm_output):
    """Parse ``nm -gU`` (Mach-O) or ``nm -D --defined-only`` (ELF) output."""
    exported = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol = fields[-1]
        kind = fields[-2]
        if kind.upper() == "U":
            continue
        exported.add(_strip_underscore(symbol))
    return exported


def missing_exports(nm_output, required=REQUIRED_TIS_SYMBOLS):
    exported = exported_symbols(nm_output)
    return [symbol for symbol in required if symbol not in exported]


def dynamic_lookups(nm_m_output, required=REQUIRED_TIS_SYMBOLS):
    """Find required symbols a Mach-O binary leaves as dynamic lookups."""
    unresolved = set()
    for line in nm_m_output.splitlines():
        if "dynamically looked up" not in line:
            continue
        for token in line.split():
            name = _strip_underscore(token)
            if name in required:
                unresolved.add(name)
    return [symbol for symbol in required if symbol in unresolved]


def _run_nm(arguments):
    result = subprocess.run(
        arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            "'%s' failed: %s" % (" ".join(arguments), result.stderr.strip())
        )
    return result.stdout


def check_library(library, macho, nm="nm"):
    if macho:
        output = _run_nm([nm, "-gU", library])
    else:
        output = _run_nm([nm, "-D", "--defined-only", library])
    return missing_exports(output)


def check_consumer(consumer, macho, nm="nm"):
    if not macho:
        return []
    output = _run_nm([nm, "-m", consumer])
    return dynamic_lookups(output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, help="built libtpms dylib/so")
    parser.add_argument(
        "--consumer",
        action="append",
        default=[],
        help="swtpm binary or support library to scan for dynamic lookups",
    )
    parser.add_argument(
        "--format",
        choices=("macho", "elf"),
        default="macho" if sys.platform == "darwin" else "elf",
    )
    parser.add_argument("--nm", default="nm")
    args = parser.parse_args(argv)
    macho = args.format == "macho"

    status = 0
    try:
        for symbol in check_library(args.library, macho, args.nm):
            print(
                "error: %s does not export required TIS symbol %s"
                % (args.library, symbol),
                file=sys.stderr,
            )
            status = 1
        for consumer in args.consumer:
            for symbol in check_consumer(consumer, macho, args.nm):
                print(
                    "error: %s leaves TIS symbol %s as a dynamic lookup"
                    % (consumer, symbol),
                    file=sys.stderr,
                )
                status = 1
    except RuntimeError as error:
        print("error: %s" % error, file=sys.stderr)
        return 1
    if status == 0:
        print("verify-tis-symbols: OK (%s)" % args.library)
    return status


if __name__ == "__main__":
    sys.exit(main())
