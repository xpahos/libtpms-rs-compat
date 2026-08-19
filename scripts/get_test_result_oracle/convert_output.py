#!/usr/bin/env python3

import argparse
import re
import sys

RESPONSE = re.compile(r"^([A-Z0-9_]+): outer=(\d+) resp=([0-9a-f]+)$")
STATE = re.compile(r"^((?:PERMALL|VOLATILE)_[A-Z0-9_]+)=([0-9a-f]+)$")

KEPT_STATES = {
    "PERMALL_FAILURE_ENTRY",
    "VOLATILE_FAILURE_ENTRY",
    "PERMALL_AFTER_QUERIES",
    "VOLATILE_AFTER_QUERIES",
}

IGNORED_PREFIXES = ("restore:", "patched_fail_blocks=")


def convert(lines):
    records = []
    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if not line:
            continue
        match = RESPONSE.match(line)
        if match is not None:
            name, outer, payload = match.groups()
            if outer != "0":
                raise SystemExit(
                    f"line {number}: {name} answered TPMLIB_Process result {outer}"
                )
            records.append((name, payload))
            continue
        match = STATE.match(line)
        if match is not None:
            name, payload = match.groups()
            if name in KEPT_STATES:
                records.append((name, payload))
            continue
        if line.startswith(IGNORED_PREFIXES):
            continue
        raise SystemExit(f"line {number}: unrecognized harness output: {line!r}")

    names = [name for name, _ in records]
    if len(set(names)) != len(names):
        raise SystemExit("duplicate record names in the harness output")
    missing = KEPT_STATES - set(names)
    if missing:
        raise SystemExit(f"missing state records: {sorted(missing)}")
    return "".join(f"{name} {payload}\n" for name, payload in records)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input",
        nargs="?",
        help="harness stdout capture (defaults to stdin)",
    )
    parser.add_argument(
        "--output",
        help="listing file to write (defaults to stdout)",
    )
    args = parser.parse_args()

    if args.input:
        with open(args.input, encoding="ascii") as handle:
            listing = convert(handle)
    else:
        listing = convert(sys.stdin)

    if args.output:
        with open(args.output, "w", encoding="ascii") as handle:
            handle.write(listing)
    else:
        sys.stdout.write(listing)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
