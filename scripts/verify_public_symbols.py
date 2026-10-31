#!/usr/bin/env python3
"""Verify that a built libtpms exports every public libtpms symbol.

The required set is every name listed under a ``global:`` section of the
reference linker version script (``libtpms/src/libtpms.syms``). The library
is inspected with ``nm``: ``nm -gU`` for Mach-O, ``nm -D --defined-only`` for
ELF. Mach-O names lose their leading underscore and ELF names lose any
``@VERSION`` / ``@@VERSION`` suffix before comparison.

Only availability is checked: extra exports are allowed, and ELF symbol
versions are ignored.
"""

import argparse
import re
import subprocess
import sys

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_version_script(text):
    """Return the ``global:`` names of a GNU ld version script, in order."""
    symbols = []
    section = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.endswith("{"):
            section = None
            continue
        if line.startswith("}"):
            section = None
            continue
        if line in ("global:", "local:"):
            section = line[:-1]
            continue
        if section != "global":
            continue
        name = line.rstrip(";").strip()
        if not _IDENTIFIER_RE.match(name):
            raise ValueError("unsupported version-script entry: %r" % raw)
        if name not in symbols:
            symbols.append(name)
    return symbols


def _is_defined_export(kind):
    return kind == "i" or (kind.isupper() and kind != "U")


def exported_symbols(nm_output, macho):
    exported = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2 or not _is_defined_export(fields[-2]):
            continue
        name = fields[-1]
        if macho:
            if not name.startswith("_"):
                continue
            name = name[1:]
        else:
            name = name.split("@", 1)[0]
        exported.add(name)
    return exported


def missing_symbols(nm_output, required, macho):
    exported = exported_symbols(nm_output, macho)
    return [symbol for symbol in required if symbol not in exported]


def run_nm(library, macho, nm="nm"):
    arguments = [nm, "-gU", library] if macho else \
        [nm, "-D", "--defined-only", library]
    result = subprocess.run(
        arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            "'%s' failed: %s" % (" ".join(arguments), result.stderr.strip())
        )
    return result.stdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symbols", required=True,
                        help="reference version script (libtpms.syms)")
    parser.add_argument("--library", required=True,
                        help="built libtpms dylib/so")
    parser.add_argument(
        "--format",
        choices=("macho", "elf"),
        default="macho" if sys.platform == "darwin" else "elf",
    )
    parser.add_argument("--nm", default="nm")
    args = parser.parse_args(argv)
    macho = args.format == "macho"

    try:
        with open(args.symbols, "r", encoding="utf-8") as fh:
            required = parse_version_script(fh.read())
        if not required:
            raise ValueError("%s lists no global symbols" % args.symbols)
        missing = missing_symbols(run_nm(args.library, macho, args.nm),
                                  required, macho)
    except (OSError, RuntimeError, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 1
    for symbol in missing:
        print("error: %s does not export public libtpms symbol %s"
              % (args.library, symbol), file=sys.stderr)
    if missing:
        print("error: %d of %d public symbols from %s are missing"
              % (len(missing), len(required), args.symbols), file=sys.stderr)
        return 1
    print("verify-public-symbols: OK (%d symbols from %s in %s)"
          % (len(required), args.symbols, args.library))
    return 0


if __name__ == "__main__":
    sys.exit(main())
