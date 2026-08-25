import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
ROOT = SCRIPTS.parent
MANIFEST = HERE / "manifest.toml"
ATTRIBUTE_DATA = ROOT / "libtpms" / "src" / "tpm2" / "CommandAttributeData.h"
COMMAND_LIST = ROOT / "libtpms" / "src" / "tpm2" / "TpmProfile_CommandList.h"
UPSTREAM_CODES_RS = ROOT / "src" / "library" / "tpm2" / "command" / "upstream_codes.rs"
REGISTRY = ROOT / "src" / "library" / "tpm2" / "command" / "registry.rs"
VERSION_RS = ROOT / "src" / "version.rs"
CONFIGURE_AC = ROOT / "libtpms" / "configure.ac"
MAKEFILE = ROOT / "Makefile"
DOCKERFILE_RELATIVE = "scripts/golden_responses/Dockerfile"
DOCKERFILE = HERE / "Dockerfile"
DOCKER_REPOSITORY = "libtpms-golden"
IMAGE_IDENTITY_LABEL = "golden.identity"
SCENARIO_DIR = "scripts/golden_responses/scenarios/"
FIXTURE_DIR = "src/library/tpm2/testdata/golden_responses/"
READER_DIR = "src/library/tpm2/golden_responses/"
MANIFEST_PATH_RULES = (
    ("fixture", FIXTURE_DIR, ".bin"),
    ("reader", READER_DIR, ".rs"),
    ("scenario", SCENARIO_DIR, ".scenario"),
)
SUPPORTED_FAMILY_FIELDS = ("magic", "scenario", "fixture", "reader", "commands")
SUPPORTED_COMMAND_FIELDS = ("code", "status", "family", "reason", "alias")
SUPPORTED_TOP_LEVEL = ("reference", "families", "commands")
SUPPORTED_REFERENCE_ONLY = ("docker_platform",)
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.\-]*$")
ENTROPY_ALGORITHMS = {
    "splitmix64": (
        "0x9e3779b97f4a7c15",
        "0xbf58476d1ce4e5b9",
        "0x94d049bb133111eb",
    )
}
CONTEXT_SUBMODULES = ("libtpms",)
CONTEXT_SUBMODULE = "libtpms"
CONTEXT_SCRIPT_TREE = "scripts/golden_responses"
CONTEXT_EXCLUDED_SCRIPTS = ("scripts/golden_responses/manifest.toml",)
IMAGE_SHIM_PATH = "/usr/local/lib/entropy_shim.so"
ENTROPY_REQUEST_SIZES = (16, 5, 3, 8, 1)
ENTROPY_VECTORS = {
    "splitmix64": {
        "seed": "00000000c0ffee01",
        "outputs": (
            "cb1ddca4ab6c58bbf70ecab87de1cc7e",
            "5f61d17d0b",
            "d3e840",
            "ba9ca917ff637885",
            "52",
        ),
        "private": "7cf2f4a3b15e095b",
        "status": "1",
        "alternate_seed": "0000000000000001",
        "alternate_first": "c15c0289ec2d0a9167ec8e65a18debbe",
    }
}
CLOCK_IDS = (
    ("CLOCK_REALTIME", 0),
    ("CLOCK_MONOTONIC", 1),
    ("CLOCK_PROCESS_CPUTIME_ID", 2),
    ("CLOCK_THREAD_CPUTIME_ID", 3),
    ("CLOCK_MONOTONIC_RAW", 4),
    ("CLOCK_MONOTONIC_COARSE", 6),
    ("CLOCK_BOOTTIME", 7),
)
MONOTONIC_CLOCK_IDS = tuple(name for name, _ in CLOCK_IDS if name != "CLOCK_REALTIME")
CLOCK_BASE_NANOSECONDS = 1_000_000_000_000
CLOCK_FIRST_ADVANCE_MS = 250
CLOCK_SECOND_ADVANCE_MS = 750
CLOCK_DRIVER = (
    "import ctypes\n"
    "libc=ctypes.CDLL(None)\n"
    "class TS(ctypes.Structure):\n"
    "    _fields_=[('tv_sec',ctypes.c_long),('tv_nsec',ctypes.c_long)]\n"
    "def read(cid):\n"
    "    ts=TS()\n"
    "    if libc.clock_gettime(cid, ctypes.byref(ts))!=0: raise SystemExit('clock_gettime failed')\n"
    "    return ts.tv_sec*1000000000+ts.tv_nsec\n"
    "IDS=" + repr(list(CLOCK_IDS)) + "\n"
    "out=[]\n"
    "for name,cid in IDS:\n"
    "    out.append(name+'='+str(read(cid)))\n"
    "    out.append(name+'_repeat='+str(read(cid)))\n"
    "libc.golden_advance_monotonic_ms(ctypes.c_uint64(" + str(CLOCK_FIRST_ADVANCE_MS) + "))\n"
    "for name,cid in IDS:\n"
    "    out.append(name+'_first='+str(read(cid)))\n"
    "libc.golden_advance_monotonic_ms(ctypes.c_uint64(" + str(CLOCK_SECOND_ADVANCE_MS) + "))\n"
    "for name,cid in IDS:\n"
    "    out.append(name+'_second='+str(read(cid)))\n"
    "print(' '.join(out))\n"
)
ENTROPY_DRIVER = (
    "import ctypes,sys\n"
    "lib=ctypes.CDLL(sys.argv[1])\n"
    "out=[]\n"
    "for size in [int(token) for token in sys.argv[2].split(',')]:\n"
    "    buffer=(ctypes.c_ubyte*size)()\n"
    "    if lib.RAND_bytes(buffer,size)!=1: raise SystemExit('RAND_bytes failed')\n"
    "    out.append(bytes(buffer).hex())\n"
    "buffer=(ctypes.c_ubyte*8)()\n"
    "if lib.RAND_priv_bytes(buffer,8)!=1: raise SystemExit('RAND_priv_bytes failed')\n"
    "out.append(bytes(buffer).hex())\n"
    "out.append(str(lib.RAND_status()))\n"
    "if lib.RAND_bytes(buffer,0)!=1: raise SystemExit('zero-length request rejected')\n"
    "if lib.RAND_bytes(buffer,-1)!=0: raise SystemExit('negative request accepted')\n"
    "print(' '.join(out))\n"
)

CC_VEND = 0x2000_0000
VENDOR_COMMANDS = {"Vendor_TCG_Test"}

UPSTREAM_ENTRY = re.compile(
    r"\(COMMAND_ATTRIBUTES\)\(\(?CC_(\w+)(?:\s*\|\|\s*CC_(\w+))?\)?"
    r"\s*\*\s*//\s*0x([0-9a-fA-F]+)"
)
RUST_CONST = re.compile(r"const\s+TPM_CC_([A-Z0-9_]+)\s*:\s*u32\s*=\s*(0x[0-9a-fA-F_]+)\s*;")
RUST_TABLE_CODE = re.compile(r"^\s*code:\s*TPM_CC_([A-Z0-9_]+),", re.MULTILINE)
AC_INIT_VERSION = re.compile(r"AC_INIT\(\[libtpms\],\[([0-9.]+)\]\)")
MAKEFILE_VERSION = re.compile(r"^LIBTPMS_PC_VERSION\s*:=\s*([0-9.]+)", re.MULTILINE)
RUST_VERSION = re.compile(r"TPM_LIBRARY_VER_(MAJOR|MINOR|MICRO)\s*:\s*u32\s*=\s*(\d+)\s*;")
CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
DOCKER_FROM = re.compile(r"^FROM\s+([^@\s]+)@(sha256:[0-9a-f]+)", re.MULTILINE)
DOCKER_SNAPSHOT = re.compile(r"snapshot\.debian\.org/archive/[\w-]+/(\d{8}T\d{6}Z)")
DOCKER_FAKETIME = re.compile(r'FAKETIME="([^"]*)"')
DOCKER_SEED = re.compile(r"GOLDEN_ENTROPY_SEED=(\S+)")
DOCKER_CONFIGURE = re.compile(r"/configure\s+([^&\n]*)")
DOCKER_SHIM_COMPILE = re.compile(r"\bcc\s+([^&\n]*entropy_shim\.so[^&\n]*)")
DOCKER_APT_INSTALL = re.compile(r"apt-get\s+install\s+([^&\n]*)")
DOCKER_LD_PRELOAD = re.compile(r"LD_PRELOAD=(\S+)")
SHIM_MONOTONIC_BASE = re.compile(r"g_monotonic_nanoseconds\s*=\s*UINT64_C\((\d+)\)")
SHIM_MONOTONIC_STEP = re.compile(r"g_monotonic_nanoseconds\s*\+=\s*UINT64_C\((\d+)\)")
SHIM_CLOCK_ID = re.compile(r"clock_id\s*==\s*(CLOCK_[A-Z_]+)")
SHIM_SYMBOL = re.compile(r"^\w[\w \t*]*\b(\w+)\s*\([^;]*\)\s*$", re.MULTILINE)


class ManifestError(Exception):
    pass


class Violation:
    def __init__(self, code, message, family=None):
        self.code = code
        self.message = message
        self.family = family

    def render(self):
        prefix = f"[{self.code}]"
        if self.family:
            return f"{prefix} {self.family}: {self.message}"
        return f"{prefix} {self.message}"

    def __repr__(self):
        return self.render()

    def __eq__(self, other):
        return (
            isinstance(other, Violation)
            and (self.code, self.message, self.family)
            == (other.code, other.message, other.family)
        )

    def __hash__(self):
        return hash((self.code, self.message, self.family))


STALE_CODES = ("fixture-missing", "fixture-magic-mismatch")

EMPTY_SUMMARY = {
    "upstream": 0,
    "commands": {},
    "families": {},
    "records": 0,
    "libtpms_commit": None,
}


def render_violations(violations, stream=None):
    for violation in violations:
        print(f"  {violation.render()}", file=stream or sys.stderr)


def load_packer():
    spec = importlib.util.spec_from_file_location("fixture_format", HERE / "fixture_format.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_manifest():
    try:
        with MANIFEST.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise ManifestError(f"manifest.toml is not valid TOML: {error}") from None
    except OSError as error:
        raise ManifestError(f"manifest.toml cannot be read: {error}") from None


def parse_upstream_entries():
    for match in UPSTREAM_ENTRY.finditer(ATTRIBUTE_DATA.read_text("utf-8")):
        name, alias, code = match.group(1), match.group(2), int(match.group(3), 16)
        if name in VENDOR_COMMANDS:
            code |= CC_VEND
        yield name, alias, code


def parse_upstream():
    for name, _alias, code in parse_upstream_entries():
        yield name, code


def parse_reference_disabled():
    text = COMMAND_LIST.read_text("utf-8")
    return {match.group(1) for match in re.finditer(r"#define\s+CC_(\w+)\s+CC_NO", text)}


def parse_reference_implemented():
    text = ATTRIBUTE_DATA.read_text("utf-8")
    disabled = parse_reference_disabled()
    codes = []
    guard = None
    for line in text.splitlines():
        opened = re.match(r"#if \(PAD_LIST\s*\|\|\s*\(?(.*?)\)?\)\s*$", line)
        if opened:
            guard = re.findall(r"CC_(\w+)", opened.group(1))
            continue
        if re.match(r"#if \(PAD_LIST\s*\)", line):
            guard = []
            continue
        entry = re.search(r"TPMA_CC_INITIALIZER\(0x([0-9a-fA-F]{4})", line)
        if entry and guard is not None and any(name not in disabled for name in guard):
            codes.append(int(entry.group(1), 16))
    return codes


def parse_rust_upstream_codes():
    text = UPSTREAM_CODES_RS.read_text("utf-8")
    body = text.split("];", 1)[0]
    return [int(value.replace("_", ""), 16) for value in re.findall(r"0x([0-9a-f_]+),", body)]


def parse_upstream_aliases():
    return {code: alias for _name, alias, code in parse_upstream_entries() if alias}


def parse_registry():
    text = REGISTRY.read_text("utf-8")
    constants = {
        name: int(value.replace("_", ""), 16)
        for name, value in RUST_CONST.findall(text)
    }
    codes = {}
    for name in RUST_TABLE_CODE.findall(text):
        if name not in constants:
            raise SystemExit(f"{REGISTRY}: descriptor references unknown TPM_CC_{name}")
        codes[constants[name]] = name
    return codes


def parse_version():
    parts = dict(RUST_VERSION.findall(VERSION_RS.read_text("utf-8")))
    for field in ("MAJOR", "MINOR", "MICRO"):
        if field not in parts:
            raise SystemExit(f"{VERSION_RS}: TPM_LIBRARY_VER_{field} not found")
    return tuple(int(parts[field]) for field in ("MAJOR", "MINOR", "MICRO"))


def declared_versions():
    major, minor, micro = parse_version()
    versions = {"src/version.rs": f"{major}.{minor}.{micro}"}
    match = AC_INIT_VERSION.search(CONFIGURE_AC.read_text("utf-8")) if CONFIGURE_AC.is_file() else None
    versions["libtpms/configure.ac"] = match.group(1) if match else None
    match = MAKEFILE_VERSION.search(MAKEFILE.read_text("utf-8")) if MAKEFILE.is_file() else None
    versions["Makefile LIBTPMS_PC_VERSION"] = match.group(1) if match else None
    return versions


def upstream_to_rust(name):
    return CAMEL_BOUNDARY.sub("_", name).upper()


def parse_dockerfile(text):
    facts = {}
    joined = text.replace("\\\n", " ")
    match = DOCKER_FROM.search(text)
    facts["docker_from_name"] = match.group(1) if match else None
    facts["docker_from_digest"] = match.group(2) if match else None
    facts["docker_snapshots"] = DOCKER_SNAPSHOT.findall(text)
    match = DOCKER_CONFIGURE.search(joined)
    facts["docker_configure_flags"] = (
        [token for token in match.group(1).split() if token.startswith("--")]
        if match
        else []
    )
    match = DOCKER_SHIM_COMPILE.search(joined)
    facts["docker_shim_compile_flags"] = (
        [
            token
            for token in match.group(1).split()
            if token.startswith("-") and token != "-o"
        ]
        if match
        else None
    )
    match = DOCKER_APT_INSTALL.search(joined)
    tokens = (
        [token for token in match.group(1).split() if not token.startswith("-")]
        if match
        else []
    )
    facts["docker_package_tokens"] = tokens
    packages = []
    for token in tokens:
        name, separator, version = token.partition("=")
        packages.append((name, version if separator else None))
    facts["docker_packages"] = packages
    match = DOCKER_FAKETIME.search(text)
    facts["docker_faketime"] = match.group(1) if match else None
    match = DOCKER_SEED.search(text)
    facts["docker_entropy_seed"] = match.group(1) if match else None
    facts["docker_shim_referenced"] = "entropy_shim" in text
    match = DOCKER_LD_PRELOAD.search(text)
    facts["docker_ld_preload"] = match.group(1).split(":") if match else []
    return facts


def parse_shim_source(text):
    facts = {}
    match = SHIM_MONOTONIC_BASE.search(text)
    facts["shim_monotonic_base"] = int(match.group(1)) if match else None
    match = SHIM_MONOTONIC_STEP.search(text)
    facts["shim_monotonic_step"] = int(match.group(1)) if match else 0
    facts["shim_clocks"] = SHIM_CLOCK_ID.findall(text)
    facts["shim_symbols"] = set(SHIM_SYMBOL.findall(text))
    facts["shim_constants"] = {
        constant
        for constants in ENTROPY_ALGORITHMS.values()
        for constant in constants
        if constant in text.lower()
    }
    return facts


def git_output(arguments):
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout


def submodule_dirt(name):
    reasons = []
    for line in git_output(
        ["-C", str(ROOT / name), "status", "--porcelain", "--untracked-files=all"]
    ).splitlines():
        status, path = line[:2], line[3:]
        if status[0] not in " ?":
            reasons.append(f"staged change to {path}")
        elif status[1] != " " and status != "??":
            reasons.append(f"tracked modification to {path}")
        elif status == "??":
            reasons.append(f"untracked file {path}")
    return reasons


DOCKER_TIMEOUT_SECONDS = 3600


class DockerOutcome:
    def __init__(self, status, stdout="", stderr="", message=None):
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        self.message = message

    @property
    def ok(self):
        return self.status == "ok"


def stderr_tail(stderr, lines=5):
    tail = [line for line in stderr.strip().splitlines() if line.strip()][-lines:]
    return "\n".join(tail) if tail else "no stderr output"


def run_docker(arguments, allow_empty=False, timeout=DOCKER_TIMEOUT_SECONDS):
    label = " ".join(arguments[:2])
    try:
        result = subprocess.run(
            ["docker", *arguments],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=timeout,
        )
    except FileNotFoundError:
        return DockerOutcome("not-found", message="docker was not found on PATH")
    except subprocess.TimeoutExpired:
        return DockerOutcome(
            "timeout", message=f"'docker {label}' did not finish within {timeout}s"
        )
    if result.returncode != 0:
        return DockerOutcome(
            "failed",
            result.stdout,
            result.stderr,
            f"'docker {label}' exited {result.returncode}:\n{stderr_tail(result.stderr)}",
        )
    if not allow_empty and not result.stdout.strip():
        return DockerOutcome(
            "empty",
            result.stdout,
            result.stderr,
            f"'docker {label}' succeeded but produced no output:\n{stderr_tail(result.stderr)}",
        )
    return DockerOutcome("ok", result.stdout, result.stderr)


def docker_output(arguments, allow_empty=False):
    outcome = run_docker(arguments, allow_empty=allow_empty)
    return outcome.stdout if outcome.ok else None


def build_context(destination):
    destination = Path(destination)
    for path in sorted(
        git_output(["ls-files", "--", CONTEXT_SCRIPT_TREE]).split()
    ):
        if path in CONTEXT_EXCLUDED_SCRIPTS:
            continue
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        source = ROOT / path
        if source.is_symlink():
            os.symlink(os.readlink(source), target)
        else:
            shutil.copyfile(source, target)
            executable = stat.S_IMODE(source.stat().st_mode) & 0o111
            target.chmod(0o755 if executable else 0o644)
    submodule = destination / CONTEXT_SUBMODULE
    submodule.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(ROOT / CONTEXT_SUBMODULE), "archive", "--format=tar", "HEAD"],
        capture_output=True,
    )
    if archive.returncode != 0:
        raise SystemExit(f"git archive of {CONTEXT_SUBMODULE} failed: {archive.stderr.decode().strip()}")
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as handle:
        handle.extractall(submodule, filter="data")
    return context_paths(destination)


def context_entries(destination):
    destination = Path(destination)
    entries = []
    for path in sorted(destination.rglob("*"), key=lambda item: str(item.relative_to(destination))):
        relative = str(path.relative_to(destination))
        if path.is_symlink():
            entries.append(("symlink", relative, 0o777, os.readlink(path).encode("utf-8")))
        elif path.is_dir():
            entries.append(("directory", relative, 0o755, b""))
        elif path.is_file():
            executable = stat.S_IMODE(path.stat().st_mode) & 0o111
            entries.append(("file", relative, 0o755 if executable else 0o644, path.read_bytes()))
        else:
            raise SystemExit(f"{relative}: unsupported context entry type")
    return entries


def context_paths(destination):
    return [relative for kind, relative, _, _ in context_entries(destination) if kind == "file"]


def context_identity(destination, platform):
    digest = hashlib.sha256()
    digest.update(b"golden-context-v2\n")
    digest.update(f"platform={platform}\n".encode("utf-8"))
    for kind, relative, mode, payload in context_entries(destination):
        digest.update(f"{kind} {mode:04o} {len(payload)} {relative}\n".encode("utf-8"))
        digest.update(payload)
    return digest.hexdigest()


@contextlib.contextmanager
def capture_context(manifest):
    platform = reference_table(manifest).get("docker_platform")
    directory = tempfile.mkdtemp(prefix="golden-context-")
    try:
        build_context(directory)
        yield Path(directory), context_identity(directory, platform)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def image_identity(manifest):
    with capture_context(manifest) as (_directory, identity):
        return identity


def image_tag(identity):
    return f"{DOCKER_REPOSITORY}:{identity[:16]}"


def image_label(tag):
    label = docker_output(
        ["image", "inspect", tag, "--format", f"{{{{index .Config.Labels \"{IMAGE_IDENTITY_LABEL}\"}}}}"]
    )
    return label.strip() if label is not None else None


def image_platform(tag):
    platform = docker_output(
        ["image", "inspect", tag, "--format", "{{.Os}}/{{.Architecture}}"]
    )
    return platform.strip() if platform is not None else None


def collect_image_packages(tag, platform, names):
    listing = docker_run_output(
        tag, platform, ["--entrypoint", "dpkg-query"], ["-W", "-f", "${Package}=${Version}\n", *names]
    )
    if listing is None:
        return None
    packages = {}
    for line in listing.splitlines():
        if "=" in line:
            name, version = line.split("=", 1)
            packages[name] = version
    return packages


def docker_run_output(tag, platform, options, arguments, environment=(), mounts=(),
                      allow_empty=False):
    command = ["run", "--rm"]
    if platform:
        command += ["--platform", platform]
    for name, value in environment:
        command += ["-e", f"{name}={value}"]
    for source, target in mounts:
        command += ["-v", f"{source}:{target}"]
    command += [*options, tag, *arguments]
    return docker_output(command, allow_empty=allow_empty)


def entropy_outputs(tag, platform, shim_path, seed, mounts=()):
    sizes = ",".join(str(size) for size in ENTROPY_REQUEST_SIZES)
    return docker_run_output(
        tag,
        platform,
        ["--entrypoint", "python3"],
        ["-c", ENTROPY_DRIVER, shim_path, sizes],
        environment=(("GOLDEN_ENTROPY_SEED", seed), ("LD_PRELOAD", "")),
        mounts=mounts,
    )


def collect_entropy_facts(manifest, tag, platform, shim_path=IMAGE_SHIM_PATH, mounts=()):
    vectors = ENTROPY_VECTORS["splitmix64"]
    seed = parse_dockerfile(DOCKERFILE.read_text("utf-8")).get("docker_entropy_seed")
    facts = {
        "entropy_primary": entropy_outputs(tag, platform, shim_path, seed, mounts),
        "entropy_restart": entropy_outputs(tag, platform, shim_path, seed, mounts),
        "entropy_alternate": entropy_outputs(
            tag, platform, shim_path, vectors["alternate_seed"], mounts
        ),
        "entropy_invalid_seed": entropy_outputs(tag, platform, shim_path, "zz", mounts),
        "entropy_vector_seed": entropy_outputs(
            tag, platform, shim_path, vectors["seed"], mounts
        ),
    }
    return facts


def package_query():
    facts = parse_dockerfile(DOCKERFILE.read_text("utf-8"))
    return sorted(name for name, _ in facts.get("docker_packages", []))


def collect_image_facts(manifest, tag, shim_path=IMAGE_SHIM_PATH, mounts=()):
    reference = reference_table(manifest)
    platform = reference.get("docker_platform")
    facts = {
        "image_checked": True,
        "image_tag": tag,
        "image_platform": image_platform(tag),
        "image_packages": collect_image_packages(
            tag, platform, package_query(),
        ),
    }
    facts.update(collect_entropy_facts(manifest, tag, platform, shim_path, mounts))
    facts.update(collect_clock_facts(manifest, tag, platform, shim_path, mounts))
    facts.update(collect_reproducibility_facts(manifest, tag, platform))
    return facts


def collect_facts(manifest):
    if DOCKERFILE.is_file():
        facts = parse_dockerfile(DOCKERFILE.read_text("utf-8"))
    else:
        facts = {
            "docker_from_name": None,
            "docker_from_digest": None,
            "docker_snapshots": [],
            "docker_configure_flags": [],
            "docker_shim_compile_flags": None,
            "docker_packages": [],
            "docker_faketime": None,
            "docker_entropy_seed": None,
            "docker_shim_referenced": False,
            "docker_ld_preload": [],
        }
    shim_path = HERE / "entropy_shim.c"
    facts.update(
        parse_shim_source(
            shim_path.read_text("utf-8")
            if shim_path is not None and shim_path.is_file()
            else ""
        )
    )
    facts["libtpms_commit"] = git_output(
        ["-C", str(ROOT / "libtpms"), "rev-parse", "HEAD"]
    ).strip()
    facts["tracked_files"] = set(
        git_output(["ls-files", "--", "scripts/golden_responses"]).split()
    )
    candidates = set()
    for entry in well_formed_families(manifest).values():
        candidates.add(entry.get("scenario"))
    facts["existing_files"] = {
        path for path in candidates if path and (ROOT / path).is_file()
    }
    facts["submodule_dirt"] = {name: submodule_dirt(name) for name in CONTEXT_SUBMODULES}
    facts["tracked_replay_files"] = set(
        git_output(["ls-files", "--", READER_DIR, FIXTURE_DIR]).split()
    )
    facts["scenario_sources"] = {
        entry["scenario"]: (ROOT / entry["scenario"]).read_text("utf-8")
        for entry in well_formed_families(manifest).values()
        if isinstance(entry.get("scenario"), str) and (ROOT / entry["scenario"]).is_file()
    }
    facts["reader_sources"] = {
        entry["reader"]: (ROOT / entry["reader"]).read_text("utf-8")
        for entry in well_formed_families(manifest).values()
        if isinstance(entry.get("reader"), str) and (ROOT / entry["reader"]).is_file()
    }
    return facts


def reference_table(manifest):
    reference = manifest.get("reference") if isinstance(manifest, dict) else None
    return reference if isinstance(reference, dict) else {}


def path_violation(family, field, value, directory, suffix):
    def refuse(message):
        return Violation("paths", f"{field} {value!r} {message}", family)

    if not isinstance(value, str) or not value:
        return Violation("paths", f"{field} must be a non-empty string", family)
    if posixpath.isabs(value) or (len(value) > 1 and value[1] == ":"):
        return refuse("must be a relative path")
    if value != posixpath.normpath(value):
        return refuse("is not normalized")
    if ".." in value.split("/"):
        return refuse("escapes the repository")
    if not value.startswith(directory):
        return refuse(f"is outside {directory}")
    if not value.endswith(suffix):
        return refuse(f"does not end in {suffix}")
    if "/" in value[len(directory) :]:
        return refuse(f"is nested below {directory}")
    absolute = ROOT / value
    expected_parent = Path(os.path.normpath(ROOT.resolve() / directory))
    try:
        resolved_parent = absolute.parent.resolve()
        is_symlink = absolute.is_symlink()
        resolved = absolute.resolve()
    except OSError as error:
        return refuse(f"cannot be resolved: {error}")
    if resolved_parent != expected_parent:
        return refuse(f"resolves outside {directory} ({resolved_parent})")
    if is_symlink:
        return refuse(f"is a symlink to {os.readlink(absolute)}")
    if resolved != expected_parent / absolute.name:
        return refuse(f"resolves outside {directory} ({resolved})")
    return None


def validate_manifest_paths(manifest):
    violations = []
    families = manifest.get("families")
    if not isinstance(families, dict):
        return violations
    for family, entry in sorted(families.items()):
        if not isinstance(entry, dict):
            continue
        for field, directory, suffix in MANIFEST_PATH_RULES:
            if field not in entry:
                continue
            violation = path_violation(family, field, entry[field], directory, suffix)
            if violation is not None:
                violations.append(violation)
    return violations


def resolved_fixture_path(family, entry):
    violation = path_violation(
        family, "fixture", entry.get("fixture"), FIXTURE_DIR, ".bin"
    )
    if violation is not None:
        raise ValueError(violation)
    return ROOT / entry["fixture"]


def well_formed_families(manifest):
    families = manifest.get("families")
    if not isinstance(families, dict):
        return {}
    sound = {}
    for family, entry in families.items():
        if not isinstance(entry, dict):
            continue
        if any(key not in entry for key in SUPPORTED_FAMILY_FIELDS):
            continue
        if not isinstance(entry["magic"], str) or len(entry["magic"].encode("utf-8", "ignore")) != 8:
            continue
        if not entry["magic"].isascii():
            continue
        if any(not isinstance(entry[key], str) for key in ("scenario", "fixture", "reader")):
            continue
        if not isinstance(entry["commands"], list):
            continue
        if any(not isinstance(command, str) for command in entry["commands"]):
            continue
        if any(
            path_violation(family, field, entry.get(field), directory, suffix) is not None
            for field, directory, suffix in MANIFEST_PATH_RULES
        ):
            continue
        sound[family] = entry
    return sound


def well_formed_commands(manifest):
    commands = manifest.get("commands")
    if not isinstance(commands, dict):
        return {}
    sound = {}
    for name, entry in commands.items():
        if not isinstance(entry, dict):
            continue
        if not isinstance(entry.get("code"), int) or isinstance(entry.get("code"), bool):
            continue
        if not isinstance(entry.get("status"), str):
            continue
        if "family" in entry and not isinstance(entry["family"], str):
            continue
        if "reason" in entry and not isinstance(entry["reason"], str):
            continue
        sound[name] = entry
    return sound


def validate_manifest_shape(manifest):
    violations = []
    if not isinstance(manifest, dict):
        return [Violation("manifest", "the manifest is not a table")]
    for key in sorted(set(manifest) - set(SUPPORTED_TOP_LEVEL)):
        violations.append(Violation("manifest", f"unknown top-level table {key!r}"))
    reference = manifest.get("reference")
    if not isinstance(reference, dict):
        violations.append(Violation("manifest", "[reference] is missing or is not a table"))
    else:
        for key in sorted(set(reference) - set(SUPPORTED_REFERENCE_ONLY)):
            violations.append(Violation("manifest", f"unknown [reference] field {key!r}"))
        platform = reference.get("docker_platform")
        if not isinstance(platform, str) or not platform.strip():
            violations.append(Violation("manifest", "[reference].docker_platform must be a non-empty string"))
    families = manifest.get("families")
    if not isinstance(families, dict) or not families:
        violations.append(Violation("manifest", "[families] is missing or is not a table"))
        families = {}
    for family, entry in sorted(families.items()):
        if not isinstance(entry, dict):
            violations.append(Violation("manifest", "the family is not a table", family))
            continue
        for key in sorted(set(entry) - set(SUPPORTED_FAMILY_FIELDS)):
            violations.append(Violation("manifest", f"unknown field {key!r}", family))
        for key in SUPPORTED_FAMILY_FIELDS:
            if key not in entry:
                violations.append(Violation("manifest", f"missing {key!r}", family))
        magic = entry.get("magic")
        if magic is not None:
            if not isinstance(magic, str):
                violations.append(Violation("manifest", "magic must be a string", family))
            elif not magic.isascii():
                violations.append(Violation("manifest", "magic must be ASCII", family))
            elif len(magic) != 8:
                violations.append(
                    Violation("manifest", f"magic {magic!r} is {len(magic)} bytes, expected 8", family)
                )
        for key in ("scenario", "fixture", "reader"):
            value = entry.get(key)
            if value is not None and not isinstance(value, str):
                violations.append(Violation("manifest", f"{key} must be a string", family))
        commands = entry.get("commands")
        if commands is not None:
            if not isinstance(commands, list):
                violations.append(Violation("manifest", "commands must be a list", family))
            elif any(not isinstance(command, str) for command in commands):
                violations.append(Violation("manifest", "commands must be a list of strings", family))
    command_table = manifest.get("commands")
    if not isinstance(command_table, dict):
        violations.append(Violation("manifest", "[commands] is missing or is not a table"))
        command_table = {}
    for name, entry in sorted(command_table.items()):
        if not isinstance(entry, dict):
            violations.append(Violation("manifest", f"commands.{name}: the entry is not a table"))
            continue
        for key in sorted(set(entry) - set(SUPPORTED_COMMAND_FIELDS)):
            violations.append(Violation("manifest", f"commands.{name}: unknown field {key!r}"))
        if not isinstance(entry.get("code"), int) or isinstance(entry.get("code"), bool):
            violations.append(Violation("manifest", f"commands.{name}: code must be an integer"))
        if not isinstance(entry.get("status"), str):
            violations.append(Violation("manifest", f"commands.{name}: status must be a string"))
        for key in ("family", "reason", "alias"):
            if key in entry and not isinstance(entry[key], str):
                violations.append(Violation("manifest", f"commands.{name}: {key} must be a string"))
    return violations


def validate_capture_environment(manifest, facts):
    violations = []
    if facts.get("docker_from_digest") is None:
        violations.append(Violation("environment", "the Dockerfile does not pin its base image by digest"))
    if not facts.get("docker_snapshots"):
        violations.append(Violation("environment", "the Dockerfile does not pin a Debian snapshot"))
    if len(set(facts.get("docker_snapshots", []))) > 1:
        violations.append(Violation("environment", "the Dockerfile mixes Debian snapshots"))
    packages = facts.get("docker_packages", [])
    if not packages:
        violations.append(Violation("environment", "the Dockerfile installs no capture packages"))
    seen_packages = set()
    for name, version in packages:
        if not PACKAGE_NAME.match(name or ""):
            violations.append(Violation("environment", f"malformed package token {name!r}"))
            continue
        if version is None:
            violations.append(Violation("environment", f"{name} is installed without a pinned version"))
        elif not version.strip():
            violations.append(Violation("environment", f"{name} is pinned to an empty version"))
        if name in seen_packages:
            violations.append(Violation("environment", f"{name} is declared more than once"))
        seen_packages.add(name)
    if not facts.get("docker_configure_flags"):
        violations.append(Violation("environment", "the Dockerfile does not configure libtpms"))
    if "--disable-use-openssl-functions" not in facts.get("docker_configure_flags", []):
        violations.append(Violation("environment", "the capture build must disable the OpenSSL key generation functions"))
    if not facts.get("docker_faketime"):
        violations.append(Violation("environment", "the Dockerfile does not pin FAKETIME"))
    elif "x0" not in facts["docker_faketime"]:
        violations.append(Violation("environment", "FAKETIME must freeze the wall clock (x0)"))
    seed = facts.get("docker_entropy_seed")
    if not seed:
        violations.append(Violation("environment", "the Dockerfile does not pin GOLDEN_ENTROPY_SEED"))
    preloaded = [Path(entry).name for entry in facts.get("docker_ld_preload", [])]
    if not any(name.startswith("entropy_shim") for name in preloaded):
        violations.append(Violation("environment", f"the entropy shim is not preloaded {preloaded}"))
    for symbol in ("RAND_bytes", "RAND_priv_bytes", "RAND_status", "clock_gettime"):
        if symbol not in facts.get("shim_symbols", set()):
            violations.append(Violation("environment", f"the shim does not interpose {symbol}"))
    for constant in ENTROPY_ALGORITHMS["splitmix64"]:
        if constant not in facts.get("shim_constants", set()):
            violations.append(Violation("environment", f"the shim does not implement splitmix64 (missing {constant})"))
    if facts.get("shim_monotonic_step"):
        violations.append(Violation("environment", "the shim must not advance the monotonic clock per query"))
    if "golden_advance_monotonic_ms" not in facts.get("shim_symbols", set()):
        violations.append(Violation("environment", "the shim does not export golden_advance_monotonic_ms"))
    return violations


def validate_image(manifest, facts):
    violations = []
    if not facts.get("image_checked"):
        return violations
    installed = facts.get("image_packages")
    if installed is None:
        violations.append(Violation("image", "no capture image matching the audited inputs; run 'golden.py build'"))
    else:
        for name, version in sorted(facts.get("docker_packages", [])):
            if name not in installed:
                violations.append(
                    Violation("image", f"{name} is installed by the Dockerfile but absent from the image")
                )
            elif not installed[name].strip():
                violations.append(Violation("image", f"{name} reports an empty version"))
            elif version is not None and installed[name] != version:
                violations.append(
                    Violation("image", f"the Dockerfile pins {version!r}, the image has {installed[name]!r}", name)
                )
    declared = reference_table(manifest).get("docker_platform")
    actual = facts.get("image_platform")
    if declared != actual:
        violations.append(
            Violation("image", f"platform: manifest declares {declared!r}, the resolved image is {actual!r}")
        )
    violations.extend(validate_entropy_behavior(manifest, facts))
    violations.extend(validate_clock_behavior(manifest, facts))
    violations.extend(validate_reproducibility(manifest, facts))
    return violations



REPRODUCIBILITY_SCENARIO = "scenarios/reproducibility.scenario"
REPRODUCIBILITY_RECORDS = (
    "PERMALL_MANUFACTURED",
    "PERMALL_AFTER_STARTUP",
    "VOLATILE_AFTER_STARTUP",
    "RANDOM_A",
    "RANDOM_B",
    "CLOCK_READ",
    "PERMALL_AFTER_ADVANCE",
    "VOLATILE_AFTER_ADVANCE",
)
VALIDATED_IMAGES = set()


def collect_reproducibility_facts(manifest, tag, platform):
    if tag in VALIDATED_IMAGES:
        return {"reproducibility": "cached"}
    runs = []
    for _ in range(2):
        command = ["run", "--rm"]
        if platform:
            command += ["--platform", platform]
        command += [tag, REPRODUCIBILITY_SCENARIO]
        outcome = run_docker(command)
        if not outcome.ok:
            return {"reproducibility": None}
        runs.append(outcome.stdout)
    return {"reproducibility": runs}


def validate_reproducibility(manifest, facts):
    violations = []
    if not facts.get("image_checked"):
        return violations
    runs = facts.get("reproducibility")
    if runs == "cached":
        return violations
    if runs is None:
        violations.append(Violation("image", "reproducibility: the probe scenario did not run"))
        return violations
    first, second = runs
    if not first.strip():
        violations.append(Violation("image", "reproducibility: the probe produced no output"))
        return violations
    left = dict(line.split(maxsplit=1) for line in first.splitlines() if line.strip())
    right = dict(line.split(maxsplit=1) for line in second.splitlines() if line.strip())
    for name in REPRODUCIBILITY_RECORDS:
        if name not in left:
            violations.append(Violation("image", f"reproducibility: the probe did not record {name}"))
    if violations:
        return violations
    for name in left:
        if left[name] != right.get(name):
            violations.append(
                Violation("image", f"reproducibility: two fresh containers disagree on {name}")
            )
            return violations
    if left != right:
        violations.append(Violation("image", "reproducibility: two fresh containers produced different output"))
    if not violations:
        VALIDATED_IMAGES.add(facts.get("image_tag"))
    return violations


def clock_outputs(tag, platform, shim_path=IMAGE_SHIM_PATH, mounts=()):
    preload = f"{shim_path}:/usr/local/lib/libfaketime.so.1"
    return docker_run_output(
        tag,
        platform,
        ["--entrypoint", "python3"],
        ["-c", CLOCK_DRIVER],
        environment=(("LD_PRELOAD", preload),),
        mounts=mounts,
    )


def collect_clock_facts(manifest, tag, platform, shim_path=IMAGE_SHIM_PATH, mounts=()):
    first = clock_outputs(tag, platform, shim_path, mounts)
    second = clock_outputs(tag, platform, shim_path, mounts)
    return {"clock_probe": first, "clock_probe_restart": second}


def parse_clock_probe(text):
    readings = {}
    for token in (text or "").split():
        if "=" not in token:
            continue
        name, value = token.split("=", 1)
        try:
            readings[name] = int(value)
        except ValueError:
            return None
    return readings or None


def validate_clock_behavior(manifest, facts):
    violations = []
    if not facts.get("image_checked"):
        return violations
    readings = parse_clock_probe(facts.get("clock_probe"))
    if readings is None:
        violations.append(Violation("image", "clock contract: the compiled shim did not answer the probe"))
        return violations
    first = CLOCK_FIRST_ADVANCE_MS * 1_000_000
    total = (CLOCK_FIRST_ADVANCE_MS + CLOCK_SECOND_ADVANCE_MS) * 1_000_000
    for name in MONOTONIC_CLOCK_IDS:
        base = readings.get(name)
        if base != CLOCK_BASE_NANOSECONDS:
            violations.append(
                Violation("image", f"clock contract: {name} starts at {base}, expected {CLOCK_BASE_NANOSECONDS}")
            )
            continue
        if readings.get(f"{name}_repeat") != base:
            violations.append(
                Violation("image", f"clock contract: {name} advanced without an explicit request")
            )
        if readings.get(f"{name}_first") != base + first:
            violations.append(
                Violation("image", f"clock contract: {name} answered {readings.get(f'{name}_first')} after "
                f"advancing {CLOCK_FIRST_ADVANCE_MS} ms, expected {base + first}")
            )
        if readings.get(f"{name}_second") != base + total:
            violations.append(
                Violation("image", f"clock contract: {name} answered {readings.get(f'{name}_second')} after "
                f"two advances, expected {base + total}")
            )
    wall = readings.get("CLOCK_REALTIME")
    if wall is None:
        violations.append(Violation("image", "clock contract: CLOCK_REALTIME was not readable"))
    else:
        if readings.get("CLOCK_REALTIME_repeat") != wall:
            violations.append(Violation("image", "clock contract: the wall clock is not frozen"))
        if readings.get("CLOCK_REALTIME_second") != wall:
            violations.append(
                Violation("image", "clock contract: advancing the monotonic clock moved the wall clock")
            )
        expected_wall = frozen_wall_clock_nanoseconds(facts)
        if expected_wall is not None and wall != expected_wall:
            violations.append(
                Violation("image", f"clock contract: CLOCK_REALTIME is {wall}, the Dockerfile pins {expected_wall}")
            )
    restart = parse_clock_probe(facts.get("clock_probe_restart"))
    if restart is None:
        violations.append(Violation("image", "clock contract: the restart probe did not answer"))
    else:
        for name in MONOTONIC_CLOCK_IDS:
            if restart.get(name) != CLOCK_BASE_NANOSECONDS:
                violations.append(
                    Violation("image", f"clock contract: {name} does not restart from the canonical base")
                )
    return violations


def frozen_wall_clock_nanoseconds(facts):
    faketime = facts.get("docker_faketime") or ""
    match = re.match(r"@(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", faketime)
    if not match:
        return None
    import calendar

    stamp = calendar.timegm(tuple(int(part) for part in match.groups()) + (0, 0, 0))
    return stamp * 1_000_000_000


def validate_entropy_behavior(manifest, facts):
    violations = []
    if not facts.get("image_checked"):
        return violations
    vectors = ENTROPY_VECTORS["splitmix64"]
    primary = facts.get("entropy_primary")
    if primary is None:
        violations.append(Violation("image", "entropy contract: the compiled shim did not answer the probe"))
        return violations
    expected = [*vectors["outputs"], vectors["private"], vectors["status"]]
    if primary.split() != expected:
        violations.append(
            Violation("image", "entropy contract: the compiled shim does not produce the splitmix64 vectors "
            f"(got {primary.split()}, expected {expected})")
        )
    restart = facts.get("entropy_restart")
    if restart is not None and restart != primary:
        violations.append(
            Violation("image", "entropy contract: the compiled shim is not deterministic across restarts")
        )
    alternate = facts.get("entropy_alternate")
    if alternate is None:
        violations.append(Violation("image", "entropy contract: the alternate-seed probe did not answer"))
    else:
        first = alternate.split()[0] if alternate.split() else ""
        if first != vectors["alternate_first"]:
            violations.append(
                Violation("image", f"entropy contract: seed {vectors['alternate_seed']} produced {first!r}, "
                f"expected {vectors['alternate_first']!r}")
            )
        if alternate == primary:
            violations.append(Violation("image", "entropy contract: a different seed produced the same stream"))
    if facts.get("entropy_invalid_seed") is not None:
        violations.append(
            Violation("image", "entropy contract: the compiled shim accepted a non-hex GOLDEN_ENTROPY_SEED")
        )
    return violations


def validate_submodules(manifest, facts):
    violations = []
    for name in CONTEXT_SUBMODULES:
        for reason in facts.get("submodule_dirt", {}).get(name, []):
            violations.append(
                Violation("submodule", f"{name} is dirty and would enter the capture build: {reason}")
            )
    return violations


SCENARIO_OPS = {
    "profile": "json",
    "permall": "record",
    "snapshot": "snapshot",
    "checkpoint": "checkpoint",
    "restore": "reference",
    "restore-permanent": "reference",
    "reboot": "none",
    "version": "none",
    "remember-session": "none",
    "audited-getrandom": "record",
    "exclusive-audit": "record",
    "advance": "number",
    "locality": "number",
    "physical-presence": "flag",
    "fail-stores": "flag",
    "patch-failure-code": "number",
    "send": "labelled",
    "raw": "hex",
}
RECORD_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
HEX_PAYLOAD = re.compile(r"^[0-9a-f]+$")
COMMAND_TAGS = (0x8001, 0x8002)


def scenario_command_code(payload, errors, lineno):
    if len(payload) % 2:
        errors.append(f"line {lineno}: the command hex has an odd number of digits")
        return None
    if not HEX_PAYLOAD.match(payload):
        errors.append(f"line {lineno}: the command hex is not lower-case hexadecimal")
        return None
    packet = bytes.fromhex(payload)
    if len(packet) < 10:
        return None
    if int.from_bytes(packet[0:2], "big") not in COMMAND_TAGS:
        return None
    return int.from_bytes(packet[6:10], "big")


def parse_scenario(text):
    errors = []
    records = []
    codes = []
    known = set()
    seen = {}

    def record(name, lineno):
        if name in seen:
            errors.append(f"line {lineno}: duplicate record name {name} (also line {seen[name]})")
        seen.setdefault(name, lineno)
        records.append(name)

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        op, _, argument = line.partition(" ")
        argument = argument.strip()
        kind = SCENARIO_OPS.get(op)
        if kind is None:
            errors.append(f"line {lineno}: unknown op {op!r}")
            continue
        if kind == "none":
            if argument:
                errors.append(f"line {lineno}: {op} takes no argument")
            elif op == "version":
                record("VERSION", lineno)
            continue
        if not argument:
            errors.append(f"line {lineno}: {op} needs an argument")
            continue
        if kind == "json":
            try:
                profile = json.loads(argument)
            except ValueError as error:
                errors.append(f"line {lineno}: {op} argument is not valid JSON: {error}")
                continue
            if not isinstance(profile, dict):
                errors.append(f"line {lineno}: {op} argument must be a JSON object")
        elif kind == "number":
            if not argument.isdigit():
                errors.append(f"line {lineno}: {op} needs a decimal argument, got {argument!r}")
        elif kind == "flag":
            if argument not in ("0", "1"):
                errors.append(f"line {lineno}: {op} takes 0 or 1, got {argument!r}")
        elif kind in ("record", "snapshot", "checkpoint", "reference"):
            if not RECORD_NAME.match(argument):
                errors.append(f"line {lineno}: {op} name {argument!r} is not upper-case ASCII")
                continue
            if kind == "record":
                record(argument, lineno)
            elif kind == "snapshot":
                record(f"PERMALL_{argument}", lineno)
                record(f"VOLATILE_{argument}", lineno)
                known.add(argument)
            elif kind == "checkpoint":
                known.add(argument)
            elif argument not in known:
                errors.append(f"line {lineno}: {op} refers to the unknown checkpoint {argument}")
        elif kind == "labelled":
            name, _, payload = argument.partition(" ")
            if not payload.strip():
                errors.append(f"line {lineno}: {op} needs a name and a command")
                continue
            if not RECORD_NAME.match(name):
                errors.append(f"line {lineno}: {op} name {name!r} is not upper-case ASCII")
                continue
            record(name, lineno)
            code = scenario_command_code(payload.strip(), errors, lineno)
            if code is not None:
                codes.append(code)
        elif kind == "hex":
            code = scenario_command_code(argument, errors, lineno)
            if code is not None:
                codes.append(code)
    return records, codes, errors


def scenario_command_codes(manifest, entry, family):
    codes = set()
    for command in entry.get("commands", []):
        name = command.removeprefix("TPM2_")
        code = well_formed_commands(manifest).get(name, {}).get("code")
        if isinstance(code, int):
            codes.add((command, code))
    return codes


TEST_MODULE_ATTRIBUTE = re.compile(r"#\s*!?\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
TEST_MODULE_HEAD = re.compile(r"\s*mod\s+tests\b\s*")
FIXTURE_CONSTRUCTOR = re.compile(r"\bFixture\s*::\s*new\b")
FIXTURE_DECLARATION = re.compile(r"^const\s+(\w+)\s*:\s*Fixture\s*=\s*Fixture::new\($")
MAGIC_DECLARATION = re.compile(r'^const\s+(\w+)\s*:\s*&\[u8;\s*8\]\s*=\s*b"([ -~]{8})";$')
MASKED_MAGIC_DECLARATION = re.compile(r"^const\s+(\w+)\s*:\s*&\[u8;\s*8\]\s*=\s{12};$")
MASKED_INCLUDE_BYTES = re.compile(r"^include_bytes!\( +\)$")
INCLUDE_BYTES = re.compile(r'^include_bytes!\("([^"]+)"\)$')
MAGIC_LITERAL = re.compile(r'^b"([ -~]{8})"$')
LABEL_LITERAL = re.compile(r'^"[^"]*"$')
IDENTIFIER = re.compile(r"^\w+$")
RAW_STRING_OPENING = re.compile(r'b?r(#*)"')
CHAR_LITERAL = re.compile(r"'(\\.|[^\\'\n])'")
IDENTIFIER_CHARACTER = re.compile(r"\w")


def mask_rust_literals(source):
    masked = list(source)
    length = len(source)
    index = 0

    def blank(start, end):
        for position in range(start, end):
            if masked[position] != "\n":
                masked[position] = " "

    def is_prefix(position):
        return position == 0 or not IDENTIFIER_CHARACTER.match(source[position - 1])

    while index < length:
        character = source[index]
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 0
            while index < length:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                    if depth == 0:
                        break
                else:
                    index += 1
            if depth != 0:
                return "".join(masked), "an unterminated block comment"
            blank(start, index)
            continue
        opening = RAW_STRING_OPENING.match(source, index) if is_prefix(index) else None
        if opening:
            terminator = '"' + "#" * len(opening.group(1))
            end = source.find(terminator, opening.end())
            if end < 0:
                return "".join(masked), "an unterminated raw string literal"
            index = end + len(terminator)
            blank(opening.start(), index)
            continue
        quoted = character == '"' or (
            character == "b" and source.startswith('b"', index) and is_prefix(index)
        )
        if quoted:
            start = index
            index += 2 if character == "b" else 1
            closed = False
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == "\n":
                    break
                if source[index] == '"':
                    index += 1
                    closed = True
                    break
                index += 1
            if not closed:
                return "".join(masked), "an unterminated string literal"
            blank(start, index)
            continue
        quote = None
        if character == "'":
            quote = index
        elif character == "b" and source.startswith("b'", index) and is_prefix(index):
            quote = index + 1
        if quote is not None:
            literal = CHAR_LITERAL.match(source, quote)
            if literal:
                blank(index, literal.end())
                index = literal.end()
                continue
        index += 1
    return "".join(masked), None


def mask_test_modules(masked):
    production = list(masked)
    index = 0
    while True:
        attribute = TEST_MODULE_ATTRIBUTE.search(masked, index)
        if attribute is None:
            return "".join(production), None
        head = TEST_MODULE_HEAD.match(masked, attribute.end())
        if head is None:
            index = attribute.end()
            continue
        if head.end() >= len(masked) or masked[head.end()] != "{":
            return "".join(production), "a #[cfg(test)] mod tests item without a body"
        depth = 0
        position = head.end()
        while position < len(masked):
            if masked[position] == "{":
                depth += 1
            elif masked[position] == "}":
                depth -= 1
                if depth == 0:
                    position += 1
                    break
            position += 1
        if depth != 0:
            return "".join(production), "an unbalanced #[cfg(test)] mod tests body"
        for offset in range(attribute.start(), position):
            if production[offset] != "\n":
                production[offset] = " "
        index = position


def parse_reader_fixtures(reader, source):
    errors = []
    declarations = []
    masked, failure = mask_rust_literals(source)
    if failure is not None:
        return [], [f"the source cannot be scanned: {failure}"]
    masked, failure = mask_test_modules(masked)
    if failure is not None:
        return [], [f"the source cannot be scanned: {failure}"]
    lines = source.splitlines()
    masked_lines = masked.splitlines()
    constructors = len(FIXTURE_CONSTRUCTOR.findall(masked))
    accounted = 0
    magics = {}
    for line, masked_line in zip(lines, masked_lines):
        structure = MASKED_MAGIC_DECLARATION.match(masked_line.strip())
        declared = MAGIC_DECLARATION.match(line.strip())
        if structure and declared and structure.group(1) == declared.group(1):
            magics[declared.group(1)] = declared.group(2)
    index = 0
    while index < len(lines):
        stripped = masked_lines[index].strip()
        opening = FIXTURE_DECLARATION.match(stripped)
        index += 1
        if not opening:
            found = len(FIXTURE_CONSTRUCTOR.findall(stripped))
            if found:
                accounted += found
                errors.append(f"line {index}: unparsable Fixture::new declaration")
            continue
        accounted += len(FIXTURE_CONSTRUCTOR.findall(stripped))
        name = opening.group(1)
        arguments = []
        closed = False
        malformed = False
        while index < len(lines):
            line, masked_line = lines[index], masked_lines[index]
            index += 1
            if masked_line.strip() == ");":
                closed = True
                break
            trimmed = masked_line.rstrip()
            if not trimmed.endswith(","):
                errors.append(f"{name}: unparsable argument {line.strip()!r}")
                malformed = True
                break
            cut = len(trimmed) - 1
            arguments.append((line[:cut].strip(), masked_line[:cut].strip()))
        if malformed:
            continue
        if not closed:
            errors.append(f"{name}: the declaration is not closed")
            continue
        if len(arguments) != 3:
            errors.append(f"{name}: expected 3 arguments, found {len(arguments)}")
            continue
        (label, masked_label), (declared_magic, masked_magic), (payload, masked_payload) = arguments
        if masked_label or not LABEL_LITERAL.match(label):
            errors.append(f"{name}: the label {label!r} is not a string literal")
            continue
        magic = magics.get(declared_magic) if IDENTIFIER.match(masked_magic) else None
        if magic is None and not masked_magic:
            literal = MAGIC_LITERAL.match(declared_magic)
            magic = literal.group(1) if literal else None
        if magic is None:
            errors.append(f"{name}: the magic {declared_magic!r} is not an 8-byte literal")
            continue
        included = INCLUDE_BYTES.match(payload)
        if included is None or not MASKED_INCLUDE_BYTES.match(masked_payload):
            errors.append(f"{name}: the payload {payload!r} is not an include_bytes! call")
            continue
        path = posixpath.normpath(
            posixpath.join(posixpath.dirname(reader), included.group(1))
        )
        declarations.append({"name": name, "magic": magic, "fixture": path})
    if accounted != constructors:
        errors.append(
            f"{constructors} Fixture::new constructor(s) are present, {accounted} could be located"
        )
    return declarations, errors


def reader_association_violations(family, entry, reader, source):
    violations = []
    declarations, errors = parse_reader_fixtures(reader, source)
    for error in errors:
        violations.append(Violation("replay", f"{reader}: {error}", family))
    fixture = entry.get("fixture")
    magic = entry.get("magic")
    matching = [
        declaration
        for declaration in declarations
        if declaration["magic"] == magic and declaration["fixture"] == fixture
    ]
    if len(matching) == 1:
        return violations
    if len(matching) > 1:
        names = ", ".join(declaration["name"] for declaration in matching)
        violations.append(
            Violation("replay", f"{reader} declares {fixture} with {magic} more than once ({names})", family)
        )
        return violations
    by_fixture = [d for d in declarations if d["fixture"] == fixture]
    by_magic = [d for d in declarations if d["magic"] == magic]
    if by_fixture:
        found = ", ".join(sorted({d["magic"] for d in by_fixture}))
        violations.append(
            Violation("replay", f"{reader} opens {fixture} with {found}, the manifest declares {magic}", family)
        )
    elif by_magic:
        found = ", ".join(sorted({d["fixture"] for d in by_magic}))
        violations.append(
            Violation("replay", f"{reader} uses {magic} for {found}, not for {fixture}", family)
        )
    else:
        violations.append(
            Violation("replay", f"{reader} declares no Fixture::new for {fixture} with {magic}", family)
        )
    return violations


def validate_readers(manifest, facts):
    violations = []
    sources = facts.get("reader_sources", {})
    tracked = facts.get("tracked_replay_files", set())
    fixtures = {}
    commands = {}
    for family, entry in sorted(well_formed_families(manifest).items()):
        reader = entry.get("reader")
        fixture = entry.get("fixture")
        if fixture in fixtures:
            violations.append(
                Violation("replay", f"fixture {fixture} is already used by {fixtures[fixture]}", family)
            )
        fixtures.setdefault(fixture, family)
        for command in entry.get("commands", []):
            if command in commands:
                violations.append(
                    Violation("replay", f"{command} is already covered by {commands[command]}", family)
                )
            commands.setdefault(command, family)
        for path in (reader, fixture):
            if isinstance(path, str) and path not in tracked:
                violations.append(Violation("replay", f"{path} is not tracked by git", family))
        source = sources.get(reader)
        if source is None:
            continue
        violations.extend(reader_association_violations(family, entry, reader, source))
    return violations


def validate_scenarios(manifest, facts):
    violations = []
    assigned = {}
    for family, entry in well_formed_families(manifest).items():
        scenario = entry.get("scenario")
        if not scenario:
            violations.append(Violation("capture", "missing 'scenario'", family))
            continue
        if scenario in assigned:
            violations.append(
                Violation("capture", f"duplicate scenario assignment {scenario} (also {assigned[scenario]})", family)
            )
        assigned.setdefault(scenario, family)
        normalized = posixpath.normpath(scenario)
        if normalized != scenario or not scenario.startswith(SCENARIO_DIR):
            violations.append(Violation("capture", f"scenario {scenario} is outside {SCENARIO_DIR}", family))
        elif scenario not in facts.get("existing_files", set()):
            violations.append(Violation("capture", f"scenario {scenario} does not exist", family))
        elif scenario not in facts.get("tracked_files", set()):
            violations.append(Violation("capture", f"scenario {scenario} is not tracked by git", family))
        source = facts.get("scenario_sources", {}).get(scenario)
        if source is None:
            continue
        _records, codes, errors = parse_scenario(source)
        for error in errors:
            violations.append(Violation("scenario", f"{scenario}: {error}", family))
        for command, code in sorted(scenario_command_codes(manifest, entry, family)):
            if code not in codes:
                violations.append(
                    Violation("scenario", f"{scenario} never runs {command} ({code:#06x})", family)
                )
    return violations


def validate_fixture(packer, magic, path):
    return [name for name, _ in packer.unpack(magic, path.read_bytes())]


def audit(_args):
    return run_audit()


def audit_violations(manifest, facts):
    return collect_violations(manifest, facts)[0]


def collect_violations(manifest, facts=None, packer=None):
    packer = packer or load_packer()
    violations = list(validate_manifest_shape(manifest))
    if not isinstance(manifest, dict):
        return violations, EMPTY_SUMMARY
    violations += validate_manifest_paths(manifest)
    commands = well_formed_commands(manifest)
    families = well_formed_families(manifest)

    def violate(check, message, family=None):
        violations.append(Violation(check, message, family))

    upstream = dict(parse_upstream())
    upstream_codes = {code: name for name, code in upstream.items()}
    manifest_codes = {}
    for name, entry in commands.items():
        code = entry.get("code")
        if not isinstance(code, int):
            violate("upstream", f"{name}: missing integer 'code'")
            continue
        if code in manifest_codes:
            violate("upstream", f"{name}: duplicate code {code:#06x} (also {manifest_codes[code]})")
        manifest_codes[code] = name
    for code, name in sorted(upstream_codes.items()):
        if code not in manifest_codes:
            violate("upstream", f"CC_{name} ({code:#06x}) has no [commands] entry")
        elif manifest_codes[code] != name:
            violate("upstream", f"{code:#06x}: manifest says {manifest_codes[code]}, upstream says {name}")
    for code, name in sorted(manifest_codes.items()):
        if code not in upstream_codes:
            violate("upstream", f"[commands.{name}] ({code:#010x}) has no upstream counterpart")
    aliases = parse_upstream_aliases()
    for name, entry in sorted(commands.items()):
        code = entry.get("code")
        declared = entry.get("alias")
        expected = aliases.get(code)
        if declared is not None and expected is None:
            violate("upstream", f"{name}: upstream declares no alias for {code:#06x}")
        elif declared is not None and declared != expected:
            violate("upstream", f"{name}: upstream names the alias {expected}, the manifest says {declared}")
        elif declared is None and expected is not None:
            violate("upstream", f"{name}: upstream also names {code:#06x} CC_{expected}")

    reference_codes = parse_reference_implemented()
    rust_codes = parse_rust_upstream_codes()
    if rust_codes != reference_codes:
        missing = sorted(set(reference_codes) - set(rust_codes))
        extra = sorted(set(rust_codes) - set(reference_codes))
        if missing:
            violate(
                "upstream",
                "upstream_codes.rs is missing "
                + ", ".join(f"{code:#06x}" for code in missing),
            )
        if extra:
            violate(
                "upstream",
                "upstream_codes.rs lists non-reference "
                + ", ".join(f"{code:#06x}" for code in extra),
            )
        if not missing and not extra:
            violate("upstream", "upstream_codes.rs is not sorted like the reference table")

    registry = parse_registry()
    implemented = {
        entry["code"]: name
        for name, entry in commands.items()
        if entry.get("status") == "implemented" and isinstance(entry.get("code"), int)
    }
    for code, const in sorted(registry.items()):
        if code not in implemented:
            status = commands.get(manifest_codes.get(code, ""), {}).get("status", "absent")
            violate("registry", f"TPM_CC_{const} ({code:#06x}) is in the registry but the manifest says '{status}'")
    for code, name in sorted(implemented.items()):
        if code not in registry:
            violate("registry", f"[commands.{name}] is 'implemented' but {code:#06x} is not in the registry")
        elif registry[code] != upstream_to_rust(name):
            violate("registry", f"{code:#06x}: {name} maps to {upstream_to_rust(name)}, registry names it TPM_CC_{registry[code]}")

    for name, entry in sorted(commands.items()):
        if entry.get("status") == "implemented":
            family = entry.get("family")
            if family is not None:
                if family not in families:
                    violate("coverage", f"{name}: family '{family}' is not in [families]")
                elif f"TPM2_{name}" not in families[family].get("commands", []):
                    violate("coverage", f"{name}: family '{family}' does not list TPM2_{name}")
            elif not entry.get("reason", "").strip():
                violate("coverage", f"{name}: implemented but neither covered by a family nor waived with a reason")
        elif entry.get("status") == "waived" and not entry.get("reason", "").strip():
            violate("coverage", f"{name}: waived without a reason")
        elif entry.get("status") not in ("implemented", "todo", "waived"):
            violate("coverage", f"{name}: unknown status '{entry.get('status')}'")
    for family, entry in sorted(families.items()):
        for command in entry.get("commands", []):
            name = command.removeprefix("TPM2_")
            if commands.get(name, {}).get("family") != family:
                violate("coverage", f"lists {command} but [commands.{name}] does not point back", family)

    disabled = parse_reference_disabled()
    for name, entry in sorted(commands.items()):
        status = entry.get("status")
        symbol = f"CC_{name}"
        code = entry.get("code")
        if status == "waived":
            if name not in disabled:
                violate(
                    "profile",
                    f"{name}: waived, but the pinned profile does not set {symbol} to CC_NO",
                )
            else:
                reason = entry.get("reason", "")
                if not re.search(rf"\b{re.escape(symbol)}\b", reason):
                    violate("profile", f"{name}: the waiver reason does not name {symbol}")
                elif not re.search(r"\bCC_NO\b", reason):
                    violate("profile", f"{name}: the waiver reason does not name CC_NO")
            if isinstance(code, int) and code in registry:
                violate(
                    "profile",
                    f"{name}: waived, but {code:#06x} is registered as TPM_CC_{registry[code]}",
                )
        elif name in disabled:
            violate(
                "profile",
                f"{name}: the pinned profile sets {symbol} to CC_NO, so the manifest must waive "
                f"it rather than record '{status}'",
            )

    record_counts = {}
    for family, entry in sorted(families.items()):
        reader = ROOT / entry["reader"]
        if not reader.is_file():
            violate("fixtures", f"reader {entry['reader']} does not exist", family)
        magic = entry["magic"].encode("ascii")
        try:
            fixture = resolved_fixture_path(family, entry)
        except ValueError:
            continue
        if not fixture.is_file():
            violate("fixture-missing", "the committed fixture is missing", family)
            continue
        try:
            record_counts[family] = len(validate_fixture(packer, magic, fixture))
        except packer.FixtureFormatError:
            violate(
                "fixture-magic-mismatch",
                "the committed fixture does not parse with its declared magic",
                family,
            )
    seen_magic = {}
    for family, entry in sorted(families.items()):
        magic = entry.get("magic")
        if not isinstance(magic, str):
            continue
        if magic in seen_magic:
            violate("fixtures", f"magic {magic} is already used by {seen_magic[magic]}", family)
        seen_magic.setdefault(magic, family)

    if facts is None:
        facts = collect_facts(manifest)
    violations.extend(validate_capture_environment(manifest, facts))
    violations.extend(validate_submodules(manifest, facts))
    violations.extend(validate_scenarios(manifest, facts))
    violations.extend(validate_readers(manifest, facts))
    violations.extend(validate_image(manifest, facts))
    summary = {
        "upstream": len(upstream),
        "commands": commands,
        "families": families,
        "records": sum(record_counts.values()),
        "libtpms_commit": facts.get("libtpms_commit"),
    }
    return violations, summary


def run_audit(manifest=None, facts=None, quiet=False):
    if manifest is None:
        manifest = load_manifest()
    violations, summary = collect_violations(manifest, facts)
    reference = reference_table(manifest)
    commands = summary["commands"]
    families = summary["families"]
    major, minor, micro = parse_version()
    expected = f"v{major}.{minor}.{micro}"

    if quiet:
        render_violations(violations)
        return 1 if violations else 0
    statuses = [entry.get("status") for entry in commands.values()]
    covered = sum(1 for entry in commands.values() if entry.get("status") == "implemented" and "family" in entry)
    module_pinned = sum(1 for entry in commands.values() if entry.get("status") == "implemented" and "family" not in entry)

    print(f"upstream commands: {summary['upstream']}")
    print(f"manifest commands: {len(commands)}")
    print(f"implemented:       {statuses.count('implemented')} ({covered} fixture-covered, {module_pinned} module-pinned)")
    print(f"families:          {len(families)} ({summary['records']} records)")
    print(f"reference:         libtpms {expected} @ {summary['libtpms_commit']} (platform {reference.get('docker_platform')})")
    print(f"waived:            {statuses.count('waived')} (profile-disabled upstream commands)")
    print(f"roadmap todo: {statuses.count('todo')}")
    if violations:
        print(f"\n{len(violations)} violation(s):", file=sys.stderr)
        render_violations(violations)
        return 1
    print("audit: OK")
    return 0









def usable_image(tag, identity, platform):
    if image_label(tag) != identity:
        return False, f"{tag} does not carry the audited identity {identity}"
    actual = image_platform(tag)
    if platform and actual != platform:
        return False, f"{tag} is {actual}, the manifest declares {platform}"
    return True, None


def resolve_image(manifest, build=True):
    platform = reference_table(manifest).get("docker_platform")
    with capture_context(manifest) as (directory, identity):
        tag = image_tag(identity)
        usable, reason = usable_image(tag, identity, platform)
        if usable:
            return tag, None
        if not build:
            return None, f"no capture image matching the audited inputs: {reason}"
        command = [
            "build",
            "-f",
            str(directory / DOCKERFILE_RELATIVE),
            "-t",
            tag,
        ]
        if platform:
            command += ["--platform", platform]
        command += ["--label", f"{IMAGE_IDENTITY_LABEL}={identity}", str(directory)]
        outcome = run_docker(command, allow_empty=True)
        if not outcome.ok:
            return None, f"the build of {tag} failed: {outcome.message}"
        usable, reason = usable_image(tag, identity, platform)
        if not usable:
            return None, f"{tag} was built but is not usable: {reason}"
        return tag, None


def stale_fixture_families(manifest):
    packer = load_packer()
    stale = set()
    for family, entry in well_formed_families(manifest).items():
        try:
            fixture = resolved_fixture_path(family, entry)
        except ValueError:
            continue
        if not fixture.is_file():
            stale.add(family)
            continue
        try:
            packer.unpack(entry["magic"].encode("ascii"), fixture.read_bytes())
        except packer.FixtureFormatError:
            stale.add(family)
    return stale


def tolerated_stale(violation, allow_stale):
    return violation.code in STALE_CODES and violation.family in set(allow_stale)


def preflight(manifest, phase, allow_stale=()):
    facts = collect_facts(manifest)
    violations = audit_violations(manifest, facts)
    remaining = [
        violation for violation in violations if not tolerated_stale(violation, allow_stale)
    ]
    if remaining:
        render_violations(remaining)
        print(f"{phase}: the repository audit failed; nothing was built or run", file=sys.stderr)
        return 1
    if violations:
        print(
            f"{phase}: regenerating {', '.join(sorted(allow_stale))} whose committed fixture "
            "no longer matches the manifest"
        )
    return 0


def image_audit(manifest, tag, phase, allow_stale=()):
    facts = collect_facts(manifest)
    facts.update(collect_image_facts(manifest, tag))
    violations = audit_violations(manifest, facts)
    remaining = [
        violation for violation in violations if not tolerated_stale(violation, allow_stale)
    ]
    if remaining:
        render_violations(remaining)
        print(f"{phase}: the resolved image {tag} failed the reference audit", file=sys.stderr)
        return 1
    return 0


def build_image(_args):
    manifest = load_manifest()
    if preflight(manifest, "build") != 0:
        return 1
    tag, error = resolve_image(manifest)
    if error is not None:
        print(f"build: {error}", file=sys.stderr)
        return 1
    if image_audit(manifest, tag, "build") != 0:
        return 1
    platform = reference_table(manifest).get("docker_platform")
    print(f"build: {tag} {platform}")
    return 0


def capture_family(manifest, family, entry, tag, platform):
    packer = load_packer()
    scenario = entry.get("scenario", "")
    container_path = scenario.removeprefix("scripts/golden_responses/")
    command = ["run", "--rm"]
    if platform:
        command += ["--platform", platform]
    command += [tag, container_path]
    outcome = run_docker(command)
    if not outcome.ok:
        return None, f"the capture of {container_path} failed: {outcome.message}"
    listing = list(packer.read_listing(outcome.stdout))
    if not listing:
        return None, f"{container_path} produced no records"
    magic = entry["magic"].encode("ascii")
    blob = packer.pack(magic, listing)
    try:
        names = [name for name, _ in packer.unpack(magic, blob)]
    except SystemExit as error:
        return None, f"the packed fixture does not parse: {error}"
    if names != sorted(set(names)):
        return None, "the packed fixture is not sorted or holds duplicates"
    return blob, None


def prepare_capture(manifest, families, phase, allow_stale=()):
    if preflight(manifest, phase, allow_stale) != 0:
        return None, None, 1
    tag, error = resolve_image(manifest)
    if error is not None:
        print(f"{phase}: {error}", file=sys.stderr)
        return None, None, 1
    if image_audit(manifest, tag, phase, allow_stale) != 0:
        return None, None, 1
    platform = reference_table(manifest).get("docker_platform")
    print(f"{phase}: capture image {tag} ({platform})")
    return tag, platform, 0


def selected_families(manifest, args):
    families = well_formed_families(manifest)
    if getattr(args, "all", False):
        return list(families.items()), None
    name = getattr(args, "family", None)
    if name not in families:
        return None, f"{name}: not in the manifest (see 'list')"
    return [(name, families[name])], None


def verify(args):
    manifest = load_manifest()
    chosen, error = selected_families(manifest, args)
    if error is not None:
        print(f"verify: {error}", file=sys.stderr)
        return 1
    tag, platform, failed = prepare_capture(manifest, chosen, "verify")
    if failed:
        return 1
    for family, entry in chosen:
        blob, error = capture_family(manifest, family, entry, tag, platform)
        if error is not None:
            print(f"FAIL {family}: {error}", file=sys.stderr)
            return 1
        committed = (ROOT / entry["fixture"]).read_bytes()
        if blob != committed:
            print(f"FAIL {family}: the capture does not reproduce {entry['fixture']}", file=sys.stderr)
            return 1
        print(f"PASS {family} ({len(blob)} bytes)")
    print(f"\nverify: {len(chosen)}/{len(chosen)} families reproduce their fixtures")
    return 0


DEFAULT_FIXTURE_MODE = 0o644


def reserve_temporary(fixture, suffix, temporaries):
    handle, path = tempfile.mkstemp(
        dir=str(fixture.parent), prefix=f".{fixture.name}.", suffix=suffix
    )
    temporary = Path(path)
    temporaries.add(temporary)
    return handle, temporary


def discard_temporaries(temporaries):
    for leftover in list(temporaries):
        try:
            os.unlink(leftover)
        except OSError:
            pass
        temporaries.discard(leftover)


def prepare_replacements(staged, temporaries):
    prepared = []
    for family, entry, blob in staged:
        fixture = resolved_fixture_path(family, entry)
        existed = fixture.is_file()
        mode = stat.S_IMODE(fixture.stat().st_mode) if existed else DEFAULT_FIXTURE_MODE
        previous = fixture.read_bytes() if existed else None
        backup = None
        if existed:
            handle, backup = reserve_temporary(fixture, ".backup", temporaries)
            os.close(handle)
            shutil.copy2(fixture, backup)
        handle, staging = reserve_temporary(fixture, ".staged", temporaries)
        with os.fdopen(handle, "wb") as stream:
            stream.write(blob)
        os.chmod(staging, mode)
        prepared.append(
            {
                "family": family,
                "entry": entry,
                "fixture": fixture,
                "staging": staging,
                "backup": backup,
                "mode": mode,
                "existed": existed,
                "previous": previous,
                "blob": blob,
            }
        )
    return prepared


def apply_replacements(prepared, applied, temporaries, replace, hook):
    for record in prepared:
        if hook is not None:
            hook(record["family"], len(applied))
        applied.append(record)
        replace(record["staging"], record["fixture"])
        temporaries.discard(record["staging"])


def validate_replacements(applied):
    for record in applied:
        if record["fixture"].read_bytes() != record["blob"]:
            raise OSError(
                f"{record['family']}: the written fixture does not match the capture"
            )


INTERRUPTIONS = (KeyboardInterrupt, SystemExit)


def describe_interruption(error):
    detail = str(error)
    name = type(error).__name__
    return f"interrupted by {name} ({detail})" if detail else f"interrupted by {name}"


def rollback_report(failure, prefix="update"):
    lines = [f"{prefix}: {failure['error']}"]
    if failure["failed_restore"]:
        lines.append(
            f"{prefix}: ROLLBACK INCOMPLETE, could not restore {failure['failed_restore']}"
        )
        for path in failure.get("preserved_backups", []):
            lines.append(f"{prefix}: the original is preserved at {path}")
    else:
        lines.append(
            f"{prefix}: rolled back {len(failure['restored'])} fixture(s); "
            "the repository is unchanged"
        )
    return lines


def print_rollback_report(failure, prefix="update"):
    for line in rollback_report(failure, prefix):
        print(line, file=sys.stderr)


def replace_fixtures(staged, hook=None, replace=None):
    replace = replace or os.replace
    applied = []
    temporaries = set()
    try:
        prepared = prepare_replacements(staged, temporaries)
        apply_replacements(prepared, applied, temporaries, replace, hook)
        validate_replacements(applied)
    except BaseException as error:
        restored, failed_restore, preserved = roll_back(applied, temporaries)
        discard_temporaries(temporaries)
        interrupted = isinstance(error, INTERRUPTIONS)
        failure = {
            "error": describe_interruption(error) if interrupted else str(error),
            "restored": restored,
            "failed_restore": failed_restore,
            "preserved_backups": preserved,
        }
        if interrupted:
            print_rollback_report(failure)
            raise
        return None, failure
    discard_temporaries(temporaries)
    return [
        (record["family"], record["entry"], record["previous"], record["blob"])
        for record in applied
    ], None


def roll_back(pending, temporaries):
    restored = []
    failed_restore = []
    preserved = []
    for record in reversed(pending):
        fixture = record["fixture"]
        backup = record["backup"]
        try:
            if not record["existed"]:
                fixture.unlink(missing_ok=True)
            else:
                os.chmod(backup, record["mode"])
                os.replace(backup, fixture)
                temporaries.discard(backup)
            restored.append(record["family"])
        except OSError as restore_error:
            failed_restore.append(f"{record['family']}: {restore_error}")
            if backup is not None and backup.exists():
                temporaries.discard(backup)
                preserved.append(str(backup))
    return restored, failed_restore, preserved


def update(args):
    manifest = load_manifest()
    if getattr(args, "all", False) and not getattr(args, "confirm_reference_update", False):
        print("update --all requires --confirm-reference-update", file=sys.stderr)
        return 1
    chosen, error = selected_families(manifest, args)
    if error is not None:
        print(f"update: {error}", file=sys.stderr)
        return 1
    tag, platform, failed = prepare_capture(
        manifest,
        chosen,
        "update",
        allow_stale=stale_fixture_families(manifest) & {family for family, _ in chosen},
    )
    if failed:
        return 1
    packer = load_packer()
    staged = []
    for family, entry in chosen:
        blob, error = capture_family(manifest, family, entry, tag, platform)
        if error is not None:
            print(f"FAIL {family}: {error}", file=sys.stderr)
            print("update: no committed fixture was modified", file=sys.stderr)
            return 1
        staged.append((family, entry, blob))
    written, failure = replace_fixtures(staged, hook=getattr(args, "hook", None))
    if failure is not None:
        print_rollback_report(failure)
        return 1
    for family, entry, previous, blob in written:
        records = packer.unpack(entry["magic"].encode("ascii"), blob)
        before = "new fixture" if previous is None else hashlib.sha256(previous).hexdigest()[:16]
        print(
            f"updated {entry['fixture']}: {len(records)} records, "
            f"{before} -> {hashlib.sha256(blob).hexdigest()[:16]}"
        )
    print(f"update: {len(written)} fixture(s) replaced and verified")
    return 0


def diff(args):
    manifest = load_manifest()
    chosen, error = selected_families(manifest, args)
    if error is not None:
        print(f"diff: {error}", file=sys.stderr)
        return 1
    tag, platform, failed = prepare_capture(manifest, chosen, "diff")
    if failed:
        return 1
    packer = load_packer()
    for family, entry in chosen:
        blob, error = capture_family(manifest, family, entry, tag, platform)
        if error is not None:
            print(f"FAIL {family}: {error}", file=sys.stderr)
            return 1
        magic = entry["magic"].encode("ascii")
        fresh = dict(packer.unpack(magic, blob))
        committed = dict(packer.unpack(magic, (ROOT / entry["fixture"]).read_bytes()))
        for name in sorted(set(committed) | set(fresh)):
            if name not in fresh:
                print(f"{family}: {name} only in the committed fixture")
            elif name not in committed:
                print(f"{family}: {name} only in the capture")
            elif committed[name] != fresh[name]:
                print(
                    f"{family}: {name} differs "
                    f"({len(committed[name]) // 2} -> {len(fresh[name]) // 2} bytes)"
                )
    return 0


def list_families(_args):
    packer = load_packer()
    manifest = load_manifest()
    width = max(len(family) for family in manifest["families"])
    for family, entry in manifest["families"].items():
        magic = entry["magic"].encode("ascii")
        records = len(packer.unpack(magic, (ROOT / entry["fixture"]).read_bytes()))
        scenario = entry["scenario"].removeprefix(SCENARIO_DIR)
        print(
            f"{family:<{width}}  {records:>3} records  {scenario:<28}"
            f"{entry['fixture']}  {', '.join(entry['commands'])}"
        )
    return 0


def dump(args):
    packer = load_packer()
    manifest = load_manifest()
    families = well_formed_families(manifest)
    if args.family not in families:
        raise SystemExit(f"{args.family}: not in the manifest (see 'list')")
    entry = families[args.family]
    magic = entry["magic"].encode("ascii")
    try:
        records = packer.unpack(magic, (ROOT / entry["fixture"]).read_bytes())
    except packer.FixtureFormatError as error:
        print(f"dump: {entry['fixture']}: {error}", file=sys.stderr)
        return 1
    found = False
    for name, payload in records:
        if args.record is None or args.record == name:
            print(name, payload)
            found = True
    if not found:
        print(f"dump: {args.family} has no record named {args.record}", file=sys.stderr)
        return 1
    return 0




def build_parser():
    parser = argparse.ArgumentParser(
        description="Audit and drive the golden-response fixtures against manifest.toml."
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    audit_parser = subparsers.add_parser(
        "audit",
        help="check the manifest against the upstream table, the registry, the fixtures, the submodules, the Dockerfile and the capture image",
    )
    audit_parser.set_defaults(handler=audit)
    subparsers.add_parser(
        "build",
        help="audit, then resolve or build the content-identified capture image",
    ).set_defaults(handler=build_image)
    for name, handler, help_text in (
        ("verify", verify, "capture into temporary files and compare with the committed fixtures"),
        ("update", update, "capture and atomically replace the committed fixtures"),
        ("diff", diff, "report record-level differences without touching the repository"),
    ):
        subparser = subparsers.add_parser(name, help=help_text)
        group = subparser.add_mutually_exclusive_group(required=True)
        group.add_argument("family", nargs="?")
        group.add_argument("--all", action="store_true")
        if name == "update":
            subparser.add_argument("--confirm-reference-update", action="store_true")
        subparser.set_defaults(handler=handler)
    subparsers.add_parser(
        "list", help="table of families, record counts and commands"
    ).set_defaults(handler=list_families)
    subparser = subparsers.add_parser("dump", help="print a canonical 'NAME <hex>' listing")
    subparser.add_argument("family")
    subparser.add_argument("record", nargs="?")
    subparser.set_defaults(handler=dump)
    return parser


def main():
    args = build_parser().parse_args()
    try:
        status = args.handler(args)
    except ManifestError as error:
        print(f"golden.py: {error}", file=sys.stderr)
        status = 1
    sys.exit(status)


if __name__ == "__main__":
    main()
