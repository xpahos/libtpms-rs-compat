#!/usr/bin/env python3

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
SUBMODULE = REPO_ROOT / "libtpms"
HARNESS = HERE / "oracle.c"
OVERRIDES = HERE / "platform_overrides.c"
CONVERTER = HERE / "convert_output.py"
LISTING = HERE / "vectors.txt"
PACKER = REPO_ROOT / "scripts" / "generate_command_vectors_fixture.py"
FIXTURE = REPO_ROOT / "src" / "library" / "tpm2" / "testdata" / "oracles" / "get_test_result.bin"
DIGESTS = (
    REPO_ROOT
    / "src"
    / "library"
    / "tpm2"
    / "testdata"
    / "oracles"
    / "get_test_result_digests.txt"
)
DEFAULT_BUILD_DIR = REPO_ROOT / "target" / "get-test-result-oracle"

INTERNAL_DEFINES = [
    "-D_POSIX_",
    "-DTPM_POSIX",
    "-DTPM_LIBTPMS_CALLBACKS",
    "-DTPM_NV_DISK",
    "-DHAVE_CONFIG_H",
]


def run(command, cwd, log, env=None):
    with open(log, "ab") as handle:
        handle.write(f"$ {' '.join(map(str, command))}\n".encode())
        handle.flush()
        result = subprocess.run(
            list(map(str, command)),
            cwd=cwd,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode != 0:
        raise SystemExit(
            f"error: {' '.join(map(str, command))} failed "
            f"(exit {result.returncode}); see {log}"
        )


def pkg_config(*args):
    probe = subprocess.run(
        ["pkg-config", *args, "libcrypto"], capture_output=True, text=True
    )
    return probe.stdout.split() if probe.returncode == 0 else None


def openssl_env():
    env = dict(os.environ)
    cflags = pkg_config("--cflags")
    libs = pkg_config("--libs-only-L")
    if cflags is not None:
        env["CPPFLAGS"] = (env.get("CPPFLAGS", "") + " " + " ".join(cflags)).strip()
    if libs is not None:
        env["LDFLAGS"] = (env.get("LDFLAGS", "") + " " + " ".join(libs)).strip()
    return env


def build_and_run(build_dir):
    if not (SUBMODULE / "autogen.sh").is_file():
        raise SystemExit(
            "error: libtpms/autogen.sh not found; "
            "run 'git submodule update --init libtpms'"
        )

    source = build_dir / "libtpms-src"
    log = build_dir / "build.log"
    build_dir.mkdir(parents=True, exist_ok=True)
    log.write_bytes(b"")

    if source.exists():
        shutil.rmtree(source)
    shutil.copytree(SUBMODULE, source, ignore=shutil.ignore_patterns(".git"))

    env = openssl_env()
    if not (source / "configure").is_file():
        run(["./autogen.sh"], source, log, env)
    run(
        ["./configure", "--with-tpm2", "--with-openssl", "--disable-shared"],
        source,
        log,
        env,
    )
    run(["make", f"-j{os.cpu_count() or 2}"], source, log, env)

    archive = source / "src" / ".libs" / "libtpms.a"
    if not archive.is_file():
        raise SystemExit(f"error: {archive} was not built; see {log}")

    cc = env.get("CC", "cc")
    crypto_cflags = pkg_config("--cflags") or []
    crypto_libs = pkg_config("--cflags", "--libs") or ["-lcrypto"]

    overrides_object = build_dir / "platform_overrides.o"
    run(
        [
            cc,
            "-c",
            OVERRIDES,
            "-o",
            overrides_object,
            "-include",
            "tpm_library_conf.h",
            f"-I{source / 'src'}",
            f"-I{source / 'include' / 'libtpms'}",
            f"-I{source / 'src' / 'tpm2'}",
            f"-I{source / 'src' / 'tpm2' / 'crypto'}",
            f"-I{source / 'src' / 'tpm2' / 'crypto' / 'openssl'}",
            *INTERNAL_DEFINES,
            *crypto_cflags,
        ],
        build_dir,
        log,
        env,
    )

    harness = build_dir / "oracle"
    run(
        [
            cc,
            "-o",
            harness,
            HARNESS,
            overrides_object,
            f"-I{source / 'include'}",
            archive,
            *crypto_libs,
        ],
        build_dir,
        log,
        env,
    )

    output = build_dir / "oracle.out"
    with open(output, "wb") as stdout, open(build_dir / "oracle.err", "wb") as stderr:
        result = subprocess.run([str(harness)], stdout=stdout, stderr=stderr, check=False)
    if result.returncode != 0:
        raise SystemExit(
            f"error: the harness exited with {result.returncode}; "
            f"see {output} and {build_dir / 'oracle.err'}"
        )

    converted = build_dir / "vectors.txt"
    with open(output, encoding="ascii") as stdin, open(converted, "w") as stdout:
        subprocess.run(
            [sys.executable, str(CONVERTER)], stdin=stdin, stdout=stdout, check=True
        )
    return converted


def parse_listing(path):
    records = {}
    for line in Path(path).read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, payload = line.split(" ", 1)
        records[name] = payload
    return records


def compare_listings(fresh, tracked):
    errors = []
    only_fresh = sorted(set(fresh) - set(tracked))
    only_tracked = sorted(set(tracked) - set(fresh))
    if only_fresh:
        errors.append(f"records only in the fresh capture: {only_fresh}")
    if only_tracked:
        errors.append(f"records only in the tracked listing: {only_tracked}")
    for name in sorted(set(fresh) & set(tracked)):
        if fresh[name] != tracked[name]:
            errors.append(f"record {name} diverges from the tracked listing")
    return errors


def digest_table(records):
    lines = [
        "# Generated by scripts/get_test_result_oracle/regenerate.py -- do not edit.",
        "# name, payload length in bytes and SHA-256 of every record in",
        "# testdata/oracles/get_test_result.bin, in record (name) order.",
    ]
    for name in sorted(records):
        payload = bytes.fromhex(records[name])
        lines.append(f"{name} {len(payload)} {hashlib.sha256(payload).hexdigest()}")
    return "\n".join(lines) + "\n"


def verify_artifacts():
    errors = []
    packer = subprocess.run(
        [sys.executable, str(PACKER), "get-test-result", str(LISTING), "--check"],
        capture_output=True,
        text=True,
    )
    if packer.returncode != 0:
        errors.append(
            "vectors.txt does not pack into the committed fixture: "
            + packer.stderr.strip()
        )

    expected = digest_table(parse_listing(LISTING))
    current = DIGESTS.read_text() if DIGESTS.is_file() else None
    if current != expected:
        errors.append(f"{DIGESTS} is stale; rerun regenerate.py --capture")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"{FIXTURE.name} and {DIGESTS.name} are consistent with vectors.txt")
    return 0


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--verify",
        action="store_true",
        help="verify listing/fixture/digest consistency without building C",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="re-capture and require every record to match vectors.txt",
    )
    mode.add_argument(
        "--capture",
        action="store_true",
        help="re-capture, rewrite vectors.txt, repack the fixture and digests",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=DEFAULT_BUILD_DIR,
        help=f"scratch tree for the C build (default: {DEFAULT_BUILD_DIR})",
    )
    args = parser.parse_args()

    if args.verify:
        return verify_artifacts()

    converted = build_and_run(args.build_dir)

    if args.check:
        errors = compare_listings(parse_listing(converted), parse_listing(LISTING))
        if errors:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
            return 1
        print(f"{LISTING}: every record reproduces byte for byte")
        return verify_artifacts()

    shutil.copyfile(converted, LISTING)
    subprocess.run(
        [sys.executable, str(PACKER), "get-test-result", str(LISTING)], check=True
    )
    DIGESTS.write_text(digest_table(parse_listing(LISTING)))
    print(f"wrote {LISTING}, {FIXTURE} and {DIGESTS}")
    return verify_artifacts()


if __name__ == "__main__":
    raise SystemExit(main())
