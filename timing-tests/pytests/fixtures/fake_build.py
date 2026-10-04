import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def scenario():
    path = HERE / "scenario.json"
    return json.loads(path.read_text()) if path.is_file() else {}


def compile_probe(kind):
    compiler = os.environ.get("CC")
    if compiler is None:
        return 0
    result = subprocess.run([compiler, "-c", str(HERE / "cc_probe.c"), "-o", os.devnull], capture_output=True, text=True)
    (HERE / f"cc-probe-{kind}.json").write_text(json.dumps({"cc": compiler, "exit": result.returncode, "stderr": result.stderr}))
    if result.returncode != 0:
        print(f"compiling with CC={compiler!r} failed: {result.stderr}", file=sys.stderr)
    return result.returncode


def main():
    kind, output = sys.argv[1], Path(sys.argv[2])
    plan = scenario()
    if plan.get("build_fail") == kind:
        print(f"fake build of {kind} failed on purpose", file=sys.stderr)
        return 1
    if kind in ("rust-library", "timing-tool") and not os.environ.get("CARGO_TARGET_DIR"):
        print("CARGO_TARGET_DIR was not passed", file=sys.stderr)
        return 1
    if plan.get("compile_probe") and kind in ("rust-library", "timing-tool") and compile_probe(kind) != 0:
        return 1
    if plan.get("block_build") == kind:
        (HERE / f"building-{kind}").write_text(str(os.getpid()))
        while not (HERE / f"resume-build-{kind}").exists():
            time.sleep(0.02)
    tag = plan.get("build_tag", "v1")
    output.parent.mkdir(parents=True, exist_ok=True)
    if kind == "timing-tool":
        quote = lambda text: "'" + str(text).replace("'", "'\\''") + "'"
        with open(output, "w") as handle:
            handle.write(f"#!/bin/sh\n# build {tag}\nexec {quote(sys.executable)} {quote(HERE / 'fake_tool.py')} \"$@\"\n")
        output.chmod(output.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    else:
        with open(output, "w") as handle:
            handle.write(f"fake {kind} build {tag}\n")
    if kind == "reference-library":
        staging = output.parents[3]
        header = staging / "source" / "include" / "libtpms" / "tpm_library.h"
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(f"/* fake header {tag} */\n")
        (staging / "build" / "received-env.json").write_text(json.dumps(dict(os.environ), sort_keys=True))
        with open(HERE / "reference-builds.log", "a") as log:
            log.write(f"{os.getpid()} {staging}\n")
    print(f"built {kind} {tag} at {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
