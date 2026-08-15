#!/usr/bin/env python3
"""Regenerate the TPMLIB_ValidateState oracle fixture from the vendored libtpms.

Produces ``src/library/tpm2/testdata/validate_state_oracle.txt``: for every
scenario in ``scripts/validate_state_oracle.c``, the TPM_RESULT the
*real* vendored ``TPM2_ValidateState`` returns together with the exact host
callback sequence it makes.  The Rust unit tests replay the same scenarios
against the Rust library and compare against this record, so any upstream
change to source selection, callback order, or result mapping shows up as a
fixture diff.

The scenarios feed the vendored implementation the same blobs the Rust tests
use -- ``valid_permanent_state_fixture()`` plus the valid, bad-trailing-magic,
seed-mismatched and object-bearing ``*_volatile_state_fixture()`` blobs --
dumped from the crate through the ignored ``dump_permall_fixture`` /
``dump_volatilestate_fixture`` helpers into one directory, so both
implementations decode byte-identical input.

The harness in ``scripts/validate_state_oracle.c`` covers permanent, volatile,
save-state, combined and sequential masks plus the permanent state
``TPMLIB_SetState`` installs.

Each scenario runs in its own process: the vendored library installs permanent
state in globals, which is precisely the state this fixture pins.  Scenarios
that pin a sequence of calls emit one ``<scenario>.<step>`` record per call.

OpenSSL is located through ``pkg-config`` (``libcrypto``, then ``openssl``),
falling back to the usual MacPorts/Homebrew/``/usr/local``/``/usr`` prefixes.
``build_settings()`` is the single source of build inputs: the vendored library
and the oracle harness both get the selected ``CC``, the inherited
``CPPFLAGS``/``CFLAGS``/``LDFLAGS`` and the detected OpenSSL flags, each exactly
once.  Every value is parsed with ``shlex``, so compound commands such as
``CC="ccache clang"`` and quoted flags survive intact; no command ever runs
through a shell.

Unlike the other generators this one is not part of ``make check``: it needs a
full autotools build of the vendored library, not a handful of translation
units.  The default build lives under
``target/validate-state-oracle/libtpms-<fingerprint>``, where the fingerprint
covers the revision actually checked out in ``libtpms/`` (plus any modified,
deleted or untracked file there), the configure arguments, the detected
OpenSSL flags and every inherited build setting the vendored build consumes --
``CC`` (both the value and the compiler's own identity), ``CPPFLAGS``,
``CFLAGS`` and ``LDFLAGS`` -- so a stale library can never be reused silently.  ``--libtpms-build DIR`` bypasses the
fingerprint entirely: that directory is caller-managed and is reused as-is
whenever it already contains a built library.

Usage:
    python3 scripts/generate_validate_state_oracle.py
    python3 scripts/generate_validate_state_oracle.py --check
    python3 scripts/generate_validate_state_oracle.py --libtpms-build DIR
"""

import argparse
import collections
import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDORED = ROOT / "libtpms"
HARNESS = ROOT / "scripts" / "validate_state_oracle.c"
FIXTURE = ROOT / "src" / "library" / "tpm2" / "testdata" / "validate_state_oracle.txt"
BUILD_ROOT = ROOT / "target" / "validate-state-oracle"

SCENARIOS = [
    "permanent_only",
    "save_state_only",
    "combined_permanent_volatile",
    "permanent_then_volatile_only",
    "save_state_then_volatile_only",
    "failed_permanent_then_volatile_only",
    "combined_seed_mismatch_then_volatile_only",
    "cached_volatile_no_backend_permall",
    "backend_volatile_no_backend_permall",
    "backend_truncated_volatile_no_backend_permall",
    "backend_bad_digest_volatile_no_backend_permall",
    "no_volatile_anywhere",
    "empty_cached_volatile",
    "installed_then_empty_cached_permanent",
    "empty_cached_permanent_nothing_installed",
    "changed_backend_permall",
    "failed_set_state_volatile_then_volatile_only",
    "installed_bad_trailing_magic_volatile",
    "installed_seed_mismatch_volatile",
    "installed_bad_header_magic_volatile",
    "nothing_installed_valid_volatile",
    "nothing_installed_truncated_volatile",
    "nothing_installed_bad_digest_volatile",
    "nothing_installed_bad_trailing_magic_volatile",
    "nothing_installed_seed_mismatch_volatile",
    "nothing_installed_bad_header_magic_volatile",
    "installed_object_rsa",
    "installed_object_ecc",
    "installed_object_aes128",
    "installed_object_aes192",
    "nothing_installed_object_rsa",
    "nothing_installed_object_ecc",
    "nothing_installed_object_aes128",
    "nothing_installed_object_aes192",
    "running_tpm",
]

VOLATILE_FIXTURES = [
    "valid.bin",
    "bad_tag.bin",
    "seed_mismatch.bin",
    "rsa_object.bin",
    "ecc_object.bin",
    "aes128_object.bin",
    "aes192_object.bin",
]

HEADER = """\
# TPMLIB_ValidateState oracle: results and host callback sequences of the
# vendored C libtpms (libtpms/src/tpm_tpm2_interface.c, TPM2_ValidateState).
# Regenerate with scripts/generate_validate_state_oracle.py.
# scenario<TAB>result<TAB>callback events
"""

OPENSSL_PREFIXES = [
    "/opt/local/libexec/openssl3",
    "/opt/local",
    "/opt/homebrew/opt/openssl@3",
    "/opt/homebrew",
    "/usr/local/opt/openssl@3",
    "/usr/local",
    "/usr",
]


class CommandError(SystemExit):
    def __init__(self, command, result):
        message = [
            f"error: command failed with status {result.returncode}",
            f"  command: {' '.join(str(part) for part in command)}",
        ]
        for stream, text in (("stdout", result.stdout), ("stderr", result.stderr)):
            text = (text or "").strip()
            if text:
                message.append(f"  {stream}:")
                message.extend(f"    {line}" for line in text.splitlines()[-40:])
        super().__init__("\n".join(message))


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise CommandError(command, result)
    return result


def pkg_config(*args):
    for package in ("libcrypto", "openssl"):
        try:
            result = subprocess.run(
                ["pkg-config", *args, package], capture_output=True, text=True
            )
        except FileNotFoundError:
            return None
        if result.returncode == 0:
            return result.stdout.split()
    return None


def openssl_flags():
    cflags = pkg_config("--cflags")
    libs = pkg_config("--libs")
    if cflags is not None and libs is not None:
        return cflags, libs
    for prefix in OPENSSL_PREFIXES:
        include = Path(prefix) / "include" / "openssl" / "evp.h"
        if not include.exists():
            continue
        cflags = [] if prefix == "/usr" else [f"-I{prefix}/include"]
        libs = ([] if prefix == "/usr" else [f"-L{prefix}/lib"]) + ["-lcrypto"]
        return cflags, libs
    sys.exit(
        "error: cannot locate OpenSSL; install pkg-config metadata for libcrypto "
        "or set CPPFLAGS/LDFLAGS for a prefix in " + ", ".join(OPENSSL_PREFIXES)
    )


CONFIGURE_ARGS = ["--disable-shared"]
BUILD_ENVIRONMENT_KEYS = ("CC", "CPPFLAGS", "CFLAGS", "LDFLAGS")

BuildSettings = collections.namedtuple(
    "BuildSettings",
    "compiler identity cppflags cflags ldflags openssl_cflags openssl_libs",
)


def inherited_flags(key, environment):
    value = environment.get(key, "")
    try:
        return shlex.split(value)
    except ValueError as error:
        sys.exit(f"error: cannot parse {key}={value!r}: {error}")


def build_settings(openssl_cflags, openssl_libs, environment=None, identity=None):
    environment = os.environ if environment is None else environment
    compiler = compiler_command(environment.get("CC", "cc"))
    return BuildSettings(
        compiler=compiler,
        identity=compiler_identity(compiler) if identity is None else identity,
        cppflags=inherited_flags("CPPFLAGS", environment),
        cflags=inherited_flags("CFLAGS", environment),
        ldflags=inherited_flags("LDFLAGS", environment),
        openssl_cflags=list(openssl_cflags),
        openssl_libs=list(openssl_libs),
    )


def build_environment(settings, environment=None):
    environment = dict(os.environ if environment is None else environment)
    linker_paths = [flag for flag in settings.openssl_libs if flag.startswith("-L")]
    for key, detected in (
        ("CPPFLAGS", settings.openssl_cflags),
        ("CFLAGS", settings.openssl_cflags),
        ("LDFLAGS", linker_paths),
    ):
        merged = shlex.join([*detected, *inherited_flags(key, environment)])
        if merged:
            environment[key] = merged
    environment["CC"] = shlex.join(settings.compiler)
    return environment


def vendored_revision(vendored=VENDORED):
    probe = subprocess.run(
        ["git", "-C", str(vendored), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    revision = probe.stdout.strip() if probe.returncode == 0 else ""
    return revision or "unknown-revision"


def vendored_status(vendored=VENDORED):
    probe = subprocess.run(
        ["git", "-C", str(vendored), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        capture_output=True,
        text=True,
    )
    return probe.stdout if probe.returncode == 0 else None


def status_entries(status):
    """Parse ``--porcelain=v1 -z`` records into sorted (code, path, origin) tuples."""
    fields = status.split("\0")
    entries = []
    index = 0
    while index < len(fields):
        record = fields[index]
        index += 1
        if not record:
            continue
        code, path = record[:2], record[3:]
        origin = ""
        if "R" in code or "C" in code:
            if index < len(fields):
                origin = fields[index]
                index += 1
        entries.append((code, path, origin))
    return sorted(entries)


def vendored_fingerprint(vendored=VENDORED):
    digest = hashlib.sha256()
    digest.update(b"revision\x00" + vendored_revision(vendored).encode() + b"\x01")
    status = vendored_status(vendored)
    if status is None:
        digest.update(b"unversioned\x01")
        return digest.digest()
    for code, path, origin in status_entries(status):
        digest.update(code.encode() + b"\x00" + path.encode() + b"\x00" + origin.encode())
        content = Path(vendored) / path
        digest.update(
            hashlib.sha256(content.read_bytes()).digest() if content.is_file() else b"absent"
        )
        digest.update(b"\x01")
    return digest.digest()


def compiler_command(cc):
    try:
        command = shlex.split(cc)
    except ValueError as error:
        sys.exit(f"error: cannot parse CC={cc!r}: {error}")
    if not command:
        sys.exit("error: CC is empty; unset it or set it to a compiler command")
    return command


def compiler_identity(command):
    probe = [*command, "--version"]
    try:
        result = subprocess.run(probe, capture_output=True, text=True)
    except OSError as error:
        sys.exit(f"error: cannot run the compiler {shlex.join(command)}: {error}")
    if result.returncode != 0:
        raise CommandError(probe, result)
    return result.stdout


def build_inputs(settings):
    return [
        ("cc", shlex.join(settings.compiler)),
        ("cc-identity", settings.identity),
        ("cppflags", shlex.join(settings.cppflags)),
        ("cflags", shlex.join(settings.cflags)),
        ("ldflags", shlex.join(settings.ldflags)),
        ("configure", " ".join(CONFIGURE_ARGS)),
        ("openssl-cflags", shlex.join(settings.openssl_cflags)),
        ("openssl-libs", shlex.join(settings.openssl_libs)),
    ]


def fingerprint(inputs, vendored):
    digest = hashlib.sha256(vendored)
    for key, value in inputs:
        digest.update(key.encode() + b"\x00" + value.encode() + b"\x01")
    return digest.hexdigest()[:16]


def library_path(build_dir):
    return Path(build_dir) / "src" / ".libs" / "libtpms.a"


def build_libtpms(build_dir, settings):
    library = library_path(build_dir)
    if library.exists():
        return library
    if not (VENDORED / "configure.ac").exists():
        sys.exit("error: libtpms sources missing; run 'git submodule update --init libtpms'")
    build_dir.parent.mkdir(parents=True, exist_ok=True)
    if build_dir.exists():
        shutil.rmtree(build_dir)
    shutil.copytree(VENDORED, build_dir)
    environment = build_environment(settings)
    run(["./autogen.sh"], cwd=build_dir, env={**environment, "NOCONFIGURE": "1"})
    run(["./configure", *CONFIGURE_ARGS], cwd=build_dir, env=environment)
    run(["make", "-C", "src", "-j4"], cwd=build_dir, env=environment)
    if not library.exists():
        sys.exit(f"error: {library} was not built")
    return library


def dump_fixtures(workdir):
    blob_dir = workdir / "blobs"
    blob_dir.mkdir()
    permall = blob_dir / "permall.bin"
    prefix = blob_dir / "volatile-"
    for test, variable, value in (
        ("dump_permall_fixture", "PERMALL_DUMP_PATH", permall),
        ("dump_volatilestate_fixture", "VOLATILESTATE_DUMP_PREFIX", prefix),
    ):
        run(
            [
                "cargo",
                "test",
                "--all-features",
                "--lib",
                "--",
                "--ignored",
                "--exact",
                f"library::tpm2::tests::{test}",
            ],
            cwd=ROOT,
            env={**os.environ, variable: str(value)},
        )
    blobs = [permall, *(Path(f"{prefix}{name}") for name in VOLATILE_FIXTURES)]
    missing = [blob for blob in blobs if not blob.exists()]
    if missing:
        sys.exit("error: fixture dump did not write " + ", ".join(str(m) for m in missing))
    return blob_dir


def harness_command(settings, build_dir, binary):
    return [
        *settings.compiler,
        "-O1",
        *settings.cppflags,
        *settings.cflags,
        "-I",
        str(Path(build_dir) / "include"),
        *settings.openssl_cflags,
        "-o",
        str(binary),
        str(HARNESS),
        str(library_path(build_dir)),
        *settings.ldflags,
        *settings.openssl_libs,
    ]


def build_harness(settings, build_dir, workdir):
    binary = workdir / "validate_state_oracle"
    run(harness_command(settings, build_dir, binary))
    return binary


def collect(binary, blob_dir):
    lines = []
    for scenario in SCENARIOS:
        command = [str(binary), scenario, str(blob_dir)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise CommandError(command, result)
        records = [line for line in result.stdout.splitlines() if line.strip()]
        if not records:
            sys.exit(f"error: scenario {scenario} produced no record")
        for record in records:
            if not record.startswith(scenario):
                sys.exit(f"error: scenario {scenario} produced {record!r}")
        lines.extend(records)
    return HEADER + "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--libtpms-build", type=Path, default=None)
    args = parser.parse_args()

    settings = build_settings(*openssl_flags())
    build_dir = args.libtpms_build
    if build_dir is None:
        digest = fingerprint(build_inputs(settings), vendored_fingerprint())
        build_dir = BUILD_ROOT / f"libtpms-{digest}"
    build_libtpms(build_dir, settings)
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        blob_dir = dump_fixtures(workdir)
        binary = build_harness(settings, build_dir, workdir)
        content = collect(binary, blob_dir)

    if args.check:
        if not FIXTURE.exists():
            sys.exit(f"error: {FIXTURE} is missing")
        if FIXTURE.read_text() != content:
            sys.exit(f"error: {FIXTURE} is stale; rerun {Path(__file__).name}")
        print(f"{Path(__file__).name}: OK")
        return

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(content)
    print(f"wrote {FIXTURE}")


if __name__ == "__main__":
    main()
