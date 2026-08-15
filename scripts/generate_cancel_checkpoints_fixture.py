#!/usr/bin/env python3
"""Regenerate the cancellation-checkpoint fixture from the vendored libtpms.

Produces ``src/library/tpm2/testdata/cancel_checkpoints.txt``: one
``file<TAB>line<TAB>function<TAB>form`` record for every place the
vendored TPM 2 implementation polls the platform cancel flag, plus one
``macro`` record carrying the guard expression of ``CHECK_CANCELED``.

This is the oracle behind the Rust decision to give
``TPM2_SelfTest``/``TPM2_IncrementalSelfTest`` no cancellation
checkpoint: upstream polls the flag only from ECC/RSA code paths that
the Rust port does not implement.  Trying to observe that by *running*
the C library would be timing-sensitive -- the flag is cleared at
command start and the reachable operations are microseconds long -- so
the oracle pins the call sites in the source instead.

The enclosing function of every call site is resolved by tracking brace
depth over the comment- and literal-stripped translation unit, so
renaming or moving a checkpoint changes the fixture.

Determinism: the output depends only on the vendored sources under
``libtpms/src/tpm2``; no compiler, no network, no timestamps.

Usage:
    python3 scripts/generate_cancel_checkpoints_fixture.py
    python3 scripts/generate_cancel_checkpoints_fixture.py --check
"""

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TPM2_DIR = REPO_ROOT / "libtpms" / "src" / "tpm2"
FIXTURE = REPO_ROOT / "src" / "library" / "tpm2" / "testdata" / "cancel_checkpoints.txt"

POLL = "_plat__IsCanceled"
MACRO = "CHECK_CANCELED"

# The flag accessor itself and its own translation unit are not call sites.
SKIP_FUNCTIONS = {POLL, "_plat__SetCancel", "_plat__ClearCancel"}

TRAILING_IDENTIFIER = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")


def strip_noise(text: str) -> list[str]:
    """Blank out comments and string/char literals, preserving line count."""
    out: list[list[str]] = [list(line) for line in text.split("\n")]
    row = col = 0
    state = "code"
    while row < len(out):
        line = out[row]
        if col >= len(line):
            if state == "line_comment":
                state = "code"
            row, col = row + 1, 0
            continue
        char = line[col]
        pair = "".join(line[col : col + 2])
        if state == "code":
            if pair == "/*":
                line[col] = line[col + 1] = " "
                state, col = "block_comment", col + 2
                continue
            if pair == "//":
                state = "line_comment"
                continue
            if char in "\"'":
                state, col = ("string" if char == '"' else "char"), col + 1
                continue
            col += 1
            continue
        if state in ("line_comment", "block_comment"):
            if state == "block_comment" and pair == "*/":
                line[col] = line[col + 1] = " "
                state, col = "code", col + 2
                continue
            line[col] = " "
            col += 1
            continue
        # Inside a literal: keep the quotes, blank the payload.
        if char == "\\":
            line[col] = " "
            if col + 1 < len(line):
                line[col + 1] = " "
            col += 2
            continue
        if (state == "string" and char == '"') or (state == "char" and char == "'"):
            state = "code"
        else:
            line[col] = " "
        col += 1
    return ["".join(line) for line in out]


def preprocessor_mask(lines: list[str]) -> list[bool]:
    """True for every line that belongs to a preprocessor directive."""
    mask: list[bool] = []
    continued = False
    for line in lines:
        directive = continued or line.lstrip().startswith("#")
        mask.append(directive)
        continued = directive and line.rstrip().endswith("\\")
    return mask


def signature_name(signature: str) -> str | None:
    """The declarator name of a function signature, e.g. `int f(void)` -> `f`."""
    text = " ".join(signature.split())
    depth = 0
    for index in range(len(text) - 1, -1, -1):
        char = text[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                match = TRAILING_IDENTIFIER.search(text[:index])
                return match.group(1) if match else None
    return None


def function_spans(clean: list[str]) -> list[tuple[str, int, int]]:
    """Return (name, first_line, last_line) for every top-level function.

    The span starts at the first line of the signature, so a call site in
    a K&R-style parameter list still resolves to its own function.
    """
    spans: list[tuple[str, int, int]] = []
    mask = preprocessor_mask(clean)
    depth = 0
    signature = ""
    signature_start: int | None = None
    start: int | None = None
    name: str | None = None
    for index, line in enumerate(clean, start=1):
        if mask[index - 1]:
            continue
        for char in line:
            if char == "{":
                if depth == 0:
                    name = signature_name(signature)
                    start = signature_start if signature_start is not None else index
                depth += 1
                signature, signature_start = "", None
                continue
            if char == "}":
                depth -= 1
                if depth == 0 and name is not None and start is not None:
                    spans.append((name, start, index))
                    name = None
                signature, signature_start = "", None
                continue
            if depth == 0:
                if char == ";":
                    signature, signature_start = "", None
                    continue
                signature += char
                if signature_start is None and not char.isspace():
                    signature_start = index
        if depth == 0:
            signature += " "
    return spans


def enclosing(spans: list[tuple[str, int, int]], line: int) -> str:
    for name, first, last in spans:
        if first <= line <= last:
            return name
    return "<file scope>"


def macro_guard(clean: list[str], lines: list[str]) -> tuple[str, int, str] | None:
    for index, line in enumerate(clean, start=1):
        if re.match(rf"\s*#\s*define\s+{MACRO}\b", line):
            body: list[str] = []
            cursor = index - 1
            while cursor < len(lines):
                body.append(lines[cursor].strip().rstrip("\\").strip())
                if not lines[cursor].rstrip().endswith("\\"):
                    break
                cursor += 1
            joined = " ".join(part for part in body if part)
            guard = joined.split("if(", 1)[1].rsplit(")", 1)[0] if "if(" in joined else joined
            return (index, " ".join(guard.split()))
    return None


def build_fixture() -> str:
    records: list[tuple[str, int, str, str]] = []
    for path in sorted(TPM2_DIR.rglob("*.c")):
        text = path.read_text(errors="replace")
        if POLL not in text and MACRO not in text:
            continue
        lines = text.split("\n")
        clean = strip_noise(text)
        spans = function_spans(clean)
        relative = path.relative_to(REPO_ROOT).as_posix()

        guard = macro_guard(clean, lines)
        if guard is not None:
            records.append((relative, guard[0], "<macro>", f"{MACRO}: {guard[1]}"))

        mask = preprocessor_mask(clean)
        for number, line in enumerate(clean, start=1):
            if mask[number - 1]:
                continue
            for form in (MACRO, POLL):
                if not re.search(rf"\b{form}\b", line):
                    continue
                function = enclosing(spans, number)
                if function in SKIP_FUNCTIONS:
                    continue
                records.append((relative, number, function, form))
                break

    records.sort()
    header = [
        "# Generated by scripts/generate_cancel_checkpoints_fixture.py -- do not edit.",
        "# Every place the vendored TPM 2 code polls the platform cancel flag.",
        "# file\tline\tfunction\tform",
    ]
    body = [f"{path}\t{line}\t{function}\t{form}" for path, line, function, form in records]
    return "\n".join(header + body) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in fixture instead of rewriting it",
    )
    args = parser.parse_args()

    fixture = build_fixture()

    if args.check:
        current = FIXTURE.read_text() if FIXTURE.is_file() else None
        if current != fixture:
            print(
                f"error: {FIXTURE} is stale; rerun {Path(__file__).name}",
                file=sys.stderr,
            )
            return 1
        entries = sum(1 for line in fixture.splitlines() if not line.startswith("#"))
        print(f"{FIXTURE}: OK ({entries} entries)")
        return 0

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(fixture)
    entries = sum(1 for line in fixture.splitlines() if not line.startswith("#"))
    print(f"wrote {FIXTURE} ({entries} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
