#!/usr/bin/env python3
"""Single-command native Linux launcher for the tpms-timing-tests pipeline.

Usage from anywhere:  python3 timing-tests/run.py [options]
See timing-tests/README.md for prerequisites, options and interpretation.
"""

import argparse
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
import platform
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

if sys.version_info < (3, 10):
    sys.stderr.write("timing-tests/run.py needs Python 3.10 or newer\n")
    sys.exit(4)

LAUNCHER_FORMAT = "tpms-timing-launcher/v1"
RUST_TOOLCHAIN = "1.95.0"
EXIT_CODES = {"completed": 0, "incomplete": 3, "failed": 4}
RANK = {"completed": 0, "incomplete": 1, "failed": 2}
EXIT_USAGE = 2
GRACE_SECONDS = 10.0
REFERENCE_CONFIGURE = ["--with-tpm2", "--with-openssl", "--enable-shared", "--disable-static"]
REFERENCE_RECIPE = 2
BUILD_SETTINGS = ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR")
BASE_BUILD_ENV = ("PATH", "HOME", "TMPDIR")
NORMALIZED_BUILD_ENV = (
    "CXX", "CPP", "LIBS", "LD", "AR", "NM", "RANLIB", "STRIP", "OBJDUMP", "MAKEFLAGS", "MFLAGS",
    "GNUMAKEFLAGS", "CONFIG_SITE", "ACLOCAL_PATH", "M4", "CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH",
    "LD_LIBRARY_PATH", "OPENSSL_DIR", "OPENSSL_LIB_DIR", "OPENSSL_INCLUDE_DIR", "CCACHE_DIR",
)
UBUNTU_PACKAGES = "build-essential autoconf automake libtool pkg-config libssl-dev git curl ca-certificates python3"

DEFAULTS = {
    "seed": 42,
    "max_evaluations": 400,
    "search_duration_s": 1800,
    "search_samples": 100,
    "verify_budget": 60000,
    "verify_batch": 1000,
    "verify_repeats": 2,
    "verify_time_limit_s": 900,
    "max_verify_candidates": 16,
    "seed_diagnostics": 4,
    "control_search_evaluations": 400,
    "control_verify_budget": 40000,
    "replay_batches": 2,
    "operation_timeout_s": 300,
}


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compact_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def worst(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if RANK[a] >= RANK[b] else b


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def git_argv(path, *args):
    return ["git", "-c", f"safe.directory={path}", "-C", str(path), *args]


def repo_root():
    return Path(__file__).resolve().parent.parent


class LauncherParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(EXIT_USAGE)


def positive_int(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {text!r}")
    if value <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {value}")
    return value


def non_negative_int(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {text!r}")
    if value < 0:
        raise argparse.ArgumentTypeError(f"expected a non-negative integer, got {value}")
    return value


def build_parser():
    parser = LauncherParser(
        prog="timing-tests/run.py",
        description=(
            "Build both libtpms libraries and the timing-test tool, then run self-tests and live "
            "controls, adaptive P-521 ECDH_ZGen searches on both libraries, independent dudect "
            "verification, replay of every verified candidate and the combined report. "
            "Exit status: 0 completed, 3 incomplete, 4 failed, 2 invalid launcher arguments."
        ),
    )
    add = parser.add_argument
    add("--seed", type=non_negative_int, default=DEFAULTS["seed"], help="campaign seed for searches, controls and boundary diagnostics (default 42)")
    add("--max-evaluations", type=positive_int, default=DEFAULTS["max_evaluations"], help="maximum timed search evaluations per backend (default 400)")
    add("--search-duration-s", type=positive_int, default=DEFAULTS["search_duration_s"], help="maximum search duration per backend in seconds (default 1800)")
    add("--search-samples", type=positive_int, default=DEFAULTS["search_samples"], help="timed executions per class in each search batch; also used by replay (default 100)")
    add("--verify-budget", type=positive_int, default=DEFAULTS["verify_budget"], help="dudect measurements per repeat and backend (default 60000)")
    add("--verify-batch", type=positive_int, default=DEFAULTS["verify_batch"], help="dudect measurements per dudect_main call, at least 32 (default 1000)")
    add("--verify-repeats", type=positive_int, default=DEFAULTS["verify_repeats"], help="independent dudect repeats per backend; fewer than 2 can never be reproducible (default 2)")
    add("--verify-time-limit-s", type=positive_int, default=DEFAULTS["verify_time_limit_s"], help="wall-clock limit per dudect repeat and backend in seconds (default 900)")
    add("--max-verify-candidates", type=positive_int, default=DEFAULTS["max_verify_candidates"], help="maximum search candidates verified, highest search score first (default 16)")
    add("--seed-diagnostics", type=non_negative_int, default=DEFAULTS["seed_diagnostics"], help="boundary seed pairs verified as labelled diagnostics in addition to search candidates (default 4)")
    add("--control-search-evaluations", type=positive_int, default=DEFAULTS["control_search_evaluations"], help="evaluation budget of each live control search in the self-test (default 400)")
    add("--control-verify-budget", type=positive_int, default=DEFAULTS["control_verify_budget"], help="dudect measurements per live control repeat (default 40000)")
    add("--replay-batches", type=positive_int, default=DEFAULTS["replay_batches"], help="search-style batches per replayed candidate (default 2)")
    add("--operation-timeout-s", type=positive_int, default=DEFAULTS["operation_timeout_s"], help="upper bound for every single worker operation in seconds (default 300)")
    add("--cpu", type=non_negative_int, default=None, help="CPU for the measurement workers (default: highest CPU in this process's affinity set)")
    add("--output-dir", type=Path, default=None, help="new evidence directory; must not exist or must be empty (default: target/timing-tests/launcher/<timestamp>-<pid>)")
    add("--jobs", type=positive_int, default=None, help="parallel make jobs for the reference build (default: number of permitted CPUs)")
    add("--build-cache", type=Path, default=None, help="shared build cache directory (default: target/timing-tests/native); safe to share between concurrent invocations")
    add("--fixture", type=Path, default=None, help=argparse.SUPPRESS)
    return parser


def allowed_cpus():
    if hasattr(os, "sched_getaffinity"):
        return sorted(os.sched_getaffinity(0))
    return None


def validate(args, parser):
    problems = []
    if args.verify_batch < 32:
        problems.append("--verify-batch must be at least 32 (the dudect worker rejects smaller batches)")
    if args.verify_budget < args.verify_batch:
        problems.append("--verify-budget must be at least --verify-batch")
    if args.control_verify_budget < 1000:
        problems.append("--control-verify-budget must be at least 1000 (the self-test uses batches of 1000)")
    if args.search_samples < 2:
        problems.append("--search-samples must be at least 2")
    allowed = allowed_cpus()
    if args.cpu is not None and allowed is not None and args.cpu not in allowed:
        problems.append(f"--cpu {args.cpu} is not in this process's affinity set {allowed}")
    if args.fixture is not None and not (args.fixture / "fake_build.py").is_file():
        problems.append("fixture directory lacks fake_build.py")
    if args.output_dir is not None:
        out = args.output_dir.expanduser()
        if out.exists() and (not out.is_dir() or any(out.iterdir())):
            problems.append(f"--output-dir {out} already exists and is not an empty directory; refusing to overwrite evidence")
    if problems:
        parser.print_usage(sys.stderr)
        for problem in problems:
            sys.stderr.write(f"{parser.prog}: error: {problem}\n")
        sys.exit(EXIT_USAGE)


def capture(argv, cwd=None, env=None):
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, str(error)
    return result.returncode, result.stdout.strip()


def set_child_subreaper():
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(36, 1, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def reap_orphans():
    reaped = []
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return reaped
        if pid == 0:
            return reaped
        reaped.append(pid)


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def group_members(pgid):
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    members = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if int(fields[2]) == pgid and fields[0] != "Z":
            members.append(int(entry.name))
    return members


def live_group(pgid):
    reap_orphans()
    members = group_members(pgid)
    if members is not None:
        return members
    return [pgid] if group_alive(pgid) else []


def stop_group(pgid, grace=GRACE_SECONDS):
    if not live_group(pgid):
        return []
    survivors = live_group(pgid)
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return survivors
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and live_group(pgid):
        time.sleep(0.1)
    if live_group(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and live_group(pgid):
            time.sleep(0.05)
    reap_orphans()
    return survivors


def main_child_exited(process):
    if process.returncode is not None:
        return True
    try:
        status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return True
    return status is not None


class Interrupted(Exception):
    pass


class Stage:
    def __init__(self, name, title, log):
        self.record = {
            "name": name,
            "title": title,
            "status": "pending",
            "outcome": None,
            "exit_code": None,
            "started": None,
            "finished": None,
            "log": str(log),
            "commands": [],
            "run_dirs": [],
            "detail": None,
        }


class Launcher:
    def __init__(self, args):
        self.args = args
        self.repo = repo_root()
        self.fixture = args.fixture.resolve() if args.fixture else None
        stamp = f"{compact_utc()}-{os.getpid():x}"
        default_out = self.repo / "target" / "timing-tests" / "launcher" / stamp
        self.evidence = (args.output_dir.expanduser() if args.output_dir else default_out).resolve()
        if args.build_cache is not None:
            self.cache = args.build_cache.expanduser().resolve()
        elif self.fixture:
            self.cache = self.evidence / "fixture-build"
        else:
            self.cache = self.repo / "target" / "timing-tests" / "native"
        self.artifacts = self.evidence / "artifacts"
        self.work = self.evidence / "work"
        self.summary_error = None
        self.cancelled_groups = set()
        self.signalled_after_exit = set()
        self.logs = self.evidence / "logs"
        self.runs = self.evidence / "runs"
        self.report_dir = self.evidence / "report"
        self.stages = []
        self.current = None
        self.interrupt_signal = None
        self.interrupt_time = None
        self.cargo = ["cargo"]
        self.cpu = None
        self.paths = {}
        self.compiler = None
        self.environment = {}
        self.summary = {
            "format": LAUNCHER_FORMAT,
            "started": utc_now(),
            "finished": None,
            "repository": str(self.repo),
            "evidence_dir": str(self.evidence),
            "fixture_mode": bool(self.fixture),
            "argv": sys.argv,
            "parameters": {},
            "cpu": None,
            "stages": [],
            "aggregate_outcome": None,
            "exit_code": None,
            "report": None,
            "rust_report_overall_outcome": None,
            "rust_report_consistent": None,
            "exploratory": None,
            "build_cache": str(self.cache),
            "artifacts": {},
            "artifact_integrity": None,
            "explanations": [],
        }
        self.subreaper = False

    def say(self, text):
        print(f"[run.py] {text}", flush=True)

    def write_summary(self):
        self.summary["stages"] = [stage.record for stage in self.stages]
        path = self.evidence / "launcher-summary.json"
        temp = path.with_suffix(".json.tmp")
        try:
            temp.write_text(json.dumps(self.summary, indent=2, default=str))
            os.replace(temp, path)
        except OSError as error:
            if self.summary_error is None:
                sys.stderr.write(f"[run.py] error: cannot write launcher summary {path}: {error}\n")
            self.summary_error = f"{path}: {error}"

    def append_log(self, stage, text):
        log = stage.record.get("log")
        if not log:
            return
        try:
            with open(log, "a", encoding="utf-8", errors="replace") as handle:
                handle.write(text)
        except OSError as error:
            if self.summary_error is None:
                sys.stderr.write(f"[run.py] error: cannot write stage log {log}: {error}\n")

    def scenario(self):
        if not self.fixture:
            return {}
        try:
            return json.loads((self.fixture / "scenario.json").read_text())
        except (OSError, ValueError):
            return {}

    def fixture_point(self, point):
        if not self.fixture:
            return
        plan = self.scenario()
        if plan.get("signal_at") == point:
            os.kill(os.getpid(), signal.SIGINT)
        tamper = plan.get("tamper_at") or {}
        if tamper.get("point") == point:
            action = tamper.get("action")
            report = self.report_dir / "report.json"
            if action == "delete-report" and report.exists():
                report.unlink()
            elif action == "malform-report" and report.exists():
                os.chmod(report, 0o644)
                report.write_text("{\"overall_outcome\": ")
            elif action == "chmod-report" and report.exists():
                os.chmod(report, 0)
            elif action == "readonly-evidence":
                for path in (self.evidence, self.logs):
                    os.chmod(path, 0o555)
        if plan.get("pause_at") == point:
            marker = self.fixture / f"paused-{point}"
            marker.write_text(str(os.getpid()))
            resume = self.fixture / f"resume-{point}"
            while not resume.exists():
                if self.interrupt_signal is not None:
                    raise Interrupted()
                time.sleep(0.02)

    def on_signal(self, signum, frame):
        if self.interrupt_signal is None:
            self.interrupt_signal = signum
            self.interrupt_time = time.monotonic()
            name = signal.Signals(signum).name
            print(f"\n[run.py] received {name}; stopping the current stage and its process group", flush=True)
        if self.current is not None:
            self.cancel_current()

    def cancel_current(self):
        process = self.current
        if process.pid in self.cancelled_groups:
            return
        if main_child_exited(process):
            self.signalled_after_exit.add(process.pid)
            return
        self.cancelled_groups.add(process.pid)
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    def install_signals(self):
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, self.on_signal)

    def new_stage(self, name, title):
        log = self.logs / f"{len(self.stages) + 1:02d}-{name}.log"
        stage = Stage(name, title, log)
        self.stages.append(stage)
        return stage

    def begin(self, stage):
        stage.record["status"] = "running"
        stage.record["started"] = utc_now()
        self.say(f"stage {stage.record['name']}: {stage.record['title']}")
        self.say(f"  log: {stage.record['log']}")
        self.write_summary()

    def finish(self, stage, outcome, detail=None, exit_code=None):
        stage.record["finished"] = utc_now()
        stage.record["outcome"] = outcome
        stage.record["exit_code"] = exit_code
        if detail:
            stage.record["detail"] = detail
        if self.interrupt_signal is not None and outcome != "failed":
            stage.record["status"] = "interrupted"
            stage.record["outcome"] = "incomplete"
        else:
            stage.record["status"] = outcome
        self.say(f"  {stage.record['name']}: {stage.record['status']}" + (f" ({detail})" if detail else ""))
        self.write_summary()

    def skip(self, name, title, reason):
        stage = self.new_stage(name, title)
        stage.record["status"] = "skipped"
        stage.record["detail"] = reason
        stage.record["log"] = None
        self.say(f"stage {name}: skipped ({reason})")
        self.write_summary()
        return stage

    def run(self, stage, argv, cwd=None, env_extra=None, stdout_path=None, env_exact=None):
        self.fixture_point(f"before-start:{stage.record['name']}")
        if self.interrupt_signal is not None:
            raise Interrupted()
        argv = [str(a) for a in argv]
        cwd = Path(cwd) if cwd else self.repo
        if env_exact is not None:
            env = {k: str(v) for k, v in env_exact.items()}
            recorded = dict(env)
        else:
            env = dict(os.environ)
            env.update({k: str(v) for k, v in (env_extra or {}).items()})
            recorded = {k: str(v) for k, v in (env_extra or {}).items()}
        entry = {"argv": argv, "cwd": str(cwd), "env": recorded, "env_mode": "exact" if env_exact is not None else "inherited+overrides", "started": utc_now()}
        stage.record["commands"].append(entry)
        self.write_summary()
        with open(stage.record["log"], "a", encoding="utf-8", errors="replace") as log:
            log.write(f"$ cd {json.dumps(str(cwd))}\n$ {json.dumps(argv)}\n")
            if recorded:
                log.write(f"# env ({entry['env_mode']}) {json.dumps(recorded)}\n")
            log.flush()
            out = open(stdout_path, "wb") if stdout_path else log
            try:
                self.current = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=log, start_new_session=True)
            except OSError as error:
                entry["exit"] = None
                entry["error"] = str(error)
                log.write(f"# could not start: {error}\n")
                if stdout_path:
                    out.close()
                return None
            pgid = self.current.pid
            if self.interrupt_signal is not None:
                self.cancel_current()
            escalated = False
            while True:
                try:
                    code = self.current.wait(timeout=0.5)
                    self.fixture_point(f"after-wait:{stage.record['name']}")
                    break
                except subprocess.TimeoutExpired:
                    if pgid in self.cancelled_groups and not escalated and time.monotonic() - self.interrupt_time > GRACE_SECONDS:
                        escalated = True
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
            self.current = None
            entry["cancelled_by_signal"] = pgid in self.cancelled_groups
            if pgid in self.signalled_after_exit:
                entry["signal_after_exit"] = True
            if stdout_path:
                out.close()
            leftovers = stop_group(pgid, grace=2.0 if self.interrupt_signal else GRACE_SECONDS)
            entry["exit"] = code
            entry["finished"] = utc_now()
            if leftovers:
                entry["leftover_processes_stopped"] = leftovers
                log.write(f"# launcher stopped leftover processes of the command's process group: {leftovers}\n")
            log.write(f"# exit status {code}\n\n")
        self.write_summary()
        self.fixture_point(f"after-command:{stage.record['name']}")
        return code

    def run_checked(self, stage, argv, **kwargs):
        code = self.run(stage, argv, **kwargs)
        entry = stage.record["commands"][-1]
        if entry.get("cancelled_by_signal"):
            raise Interrupted()
        leftovers = entry.get("leftover_processes_stopped")
        if code != 0 or leftovers:
            reason = f"command exited with status {code}" if code != 0 else f"command left processes running: {leftovers}"
            raise StageFailure(reason)
        if self.interrupt_signal is not None:
            raise Interrupted()
        return code

    def verify_artifacts(self):
        changed = []
        for name, entry in self.summary.get("artifacts", {}).items():
            path = Path(entry["path"])
            try:
                if path.is_dir():
                    actual = tree_digest(path)
                else:
                    actual = sha256_file(path)
            except OSError as error:
                actual = f"unreadable: {error}"
            if actual != entry["sha256"]:
                changed.append(f"{name}: recorded {entry['sha256'][:16]}, now {actual[:16]}")
        self.summary["artifact_integrity"] = {"checked": utc_now(), "unchanged": not changed, "changed": changed}
        return changed

    def finalize(self):
        for stage in self.stages:
            if stage.record["status"] == "running":
                if self.interrupt_signal is not None:
                    self.finish(stage, "incomplete", "interrupted while the stage was running")
                else:
                    self.finish(stage, "failed", "the launcher stopped while this stage was running")
        if self.summary.get("artifacts"):
            changed = self.verify_artifacts()
            if changed:
                self.summary["explanations"].append("artifacts used by this invocation changed during the run: " + "; ".join(changed))
        aggregate = None
        explanations = []
        for stage in self.stages:
            record = stage.record
            if record["status"] == "skipped":
                explanations.append(f"{record['name']} skipped: {record['detail']}")
                continue
            if record["outcome"] is None:
                continue
            aggregate = worst(aggregate, record["outcome"])
            if record["outcome"] != "completed":
                explanations.append(f"{record['name']} {record['status']}: {record['detail'] or 'see log ' + record['log']}")
        if self.interrupt_signal is not None:
            aggregate = worst(aggregate, "incomplete")
            explanations.insert(0, f"interrupted by {signal.Signals(self.interrupt_signal).name}")
        integrity = self.summary.get("artifact_integrity")
        if integrity and not integrity["unchanged"]:
            aggregate = "failed"
            explanations.append("artifact integrity check failed: " + "; ".join(integrity["changed"]))
        if aggregate is None:
            aggregate = "failed"
        self.summary["aggregate_outcome"] = aggregate
        self.summary["exit_code"] = EXIT_CODES[aggregate]
        self.summary["explanations"] = [e for e in self.summary.get("explanations", []) if e not in explanations and not e.startswith("artifacts used by")] + explanations
        self.summary["finished"] = utc_now()
        self.write_summary()
        return aggregate

    def git(self, *args, cwd=None):
        code, out = capture(git_argv(cwd or self.repo, *args))
        return out if code == 0 else None

    def source_digest(self, root, paths):
        listed = None
        code, out = capture(git_argv(root, "ls-files", "-co", "--exclude-standard", "-z", "--", *paths))
        if code == 0:
            listed = sorted(p for p in out.split("\0") if p)
        else:
            listed = []
            for path in paths:
                base = root / path
                if base.is_file():
                    listed.append(path)
                for dirpath, _, files in os.walk(base):
                    for name in files:
                        listed.append(str(Path(dirpath, name).relative_to(root)))
            listed.sort()
        digest = hashlib.sha256()
        count = 0
        for rel in listed:
            full = root / rel
            if full.is_file():
                digest.update(rel.encode() + b"\0" + sha256_file(full).encode() + b"\n")
                count += 1
        return {"paths": paths, "files": count, "sha256": digest.hexdigest()}


class StageFailure(Exception):
    pass


def check_prerequisites(launcher):
    problems = []
    notes = []
    machine = platform.machine()
    if not sys.platform.startswith("linux") or machine not in ("x86_64", "AMD64"):
        problems.append(
            f"this launcher supports native Linux x86_64 only (found {sys.platform}/{machine}); the pinned dudect "
            "timer uses mfence+rdtsc, so other architectures cannot measure"
        )
        return problems, notes
    tools = {
        "git": "git",
        "cc": "build-essential",
        "make": "build-essential",
        "autoreconf": "autoconf",
        "automake": "automake",
        "libtoolize": "libtool",
        "pkg-config": "pkg-config",
        "curl": "curl",
        "tar": "tar",
    }
    missing = sorted({package for tool, package in tools.items() if shutil.which(tool) is None})
    if missing:
        problems.append(f"missing tools; install with: sudo apt-get install -y {' '.join(missing)}")
    if shutil.which("pkg-config"):
        for module in ("libcrypto", "libssl"):
            code, _ = capture(["pkg-config", "--exists", module])
            if code != 0:
                problems.append(f"OpenSSL development files not found ({module}.pc); install with: sudo apt-get install -y libssl-dev")
                break
        else:
            code, include = capture(["pkg-config", "--variable=includedir", "libcrypto"])
            if code == 0 and not Path(include or "/usr/include", "openssl", "evp.h").exists():
                problems.append("openssl/evp.h not found; install with: sudo apt-get install -y libssl-dev")
    rustup = shutil.which("rustup")
    if rustup:
        code, out = capture([rustup, "run", RUST_TOOLCHAIN, "rustc", "--version"])
        if code == 0 and out.startswith(f"rustc {RUST_TOOLCHAIN}"):
            launcher.cargo = [rustup, "run", RUST_TOOLCHAIN, "cargo"]
        else:
            problems.append(
                f"Rust {RUST_TOOLCHAIN} is not installed; run: rustup toolchain install {RUST_TOOLCHAIN} --profile minimal --component rustfmt,clippy"
            )
    else:
        code, out = capture(["rustc", "--version"])
        if code == 0 and out.startswith(f"rustc {RUST_TOOLCHAIN}") and shutil.which("cargo"):
            launcher.cargo = ["cargo"]
        else:
            problems.append(
                f"Rust {RUST_TOOLCHAIN} via rustup is required; install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | "
                f"sh -s -- -y --profile minimal --default-toolchain {RUST_TOOLCHAIN} && . \"$HOME/.cargo/env\""
            )
    for lock in (launcher.repo / "Cargo.lock", launcher.repo / "timing-tests" / "Cargo.lock"):
        if not lock.is_file():
            problems.append(f"{lock} is missing; the launcher builds with --locked and will not resolve dependencies itself")
    gitlink = launcher.git("ls-tree", "HEAD", "libtpms")
    commit = gitlink.split()[2] if gitlink and len(gitlink.split()) >= 3 else None
    if commit is None:
        problems.append("cannot read the pinned libtpms submodule commit from the repository (git ls-tree HEAD libtpms)")
    else:
        code, _ = capture(git_argv(launcher.repo / "libtpms", "cat-file", "-e", f"{commit}^{{commit}}"))
        if code != 0:
            problems.append(f"libtpms submodule commit {commit} is not available; run: git -C {json.dumps(str(launcher.repo))} submodule update --init libtpms")
        launcher.paths["reference_commit"] = commit
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    notes.append(
        f"first run needs network access: Cargo downloads locked crates into {cargo_home}, and the timing tool downloads "
        "dudect.h and its LICENSE from raw.githubusercontent.com at the pinned revision and verifies their SHA-256"
    )
    return problems, notes


def select_cpu(launcher):
    allowed = allowed_cpus()
    if launcher.args.cpu is not None:
        return launcher.args.cpu, "requested with --cpu", allowed
    if allowed:
        return allowed[-1], "highest CPU in the process affinity set", allowed
    return None, "no affinity interface on this platform; workers are not pinned", allowed


def record_environment(launcher):
    repo = launcher.repo
    env = {
        "python": sys.version,
        "platform": platform.platform(),
        "uname": list(platform.uname()),
        "launcher_sha256": sha256_file(Path(__file__).resolve()),
        "repository_revision": launcher.git("rev-parse", "HEAD"),
        "repository_dirty": (launcher.git("status", "--porcelain") or "").splitlines(),
        "libtpms_pinned_commit": launcher.paths.get("reference_commit"),
        "libtpms_checkout_head": launcher.git("rev-parse", "HEAD", cwd=repo / "libtpms"),
        "libtpms_checkout_dirty": (launcher.git("status", "--porcelain", cwd=repo / "libtpms") or "").splitlines(),
        "source_digests": {
            "timing_tests": launcher.source_digest(repo, ["timing-tests"]),
            "rust_library": launcher.source_digest(repo, ["src", "Cargo.toml", "build.rs"]),
        },
        "root_cargo_lock_sha256": sha256_file(repo / "Cargo.lock") if (repo / "Cargo.lock").is_file() else None,
        "cpu": {"selected": launcher.cpu, "affinity": allowed_cpus()},
        "host_settings": "the launcher does not change CPU governors, turbo, scheduling policy or any other system setting",
    }
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.startswith("model name"):
                env["cpu"]["model"] = line.split(":", 1)[1].strip()
                break
    release = Path("/etc/os-release")
    if release.is_file():
        env["os_release"] = release.read_text(errors="replace")
    if not launcher.fixture:
        for key, argv in {
            "rustc": [*launcher.cargo[:-1], "rustc", "--version", "--verbose"] if launcher.cargo[0] != "cargo" else ["rustc", "--version", "--verbose"],
            "cargo": [*launcher.cargo, "--version"],
            "cc": ["cc", "--version"],
            "libcrypto_pkg_config": ["pkg-config", "--modversion", "libcrypto"],
            "libcrypto_libdir": ["pkg-config", "--variable=libdir", "libcrypto"],
            "openssl_cli": ["openssl", "version", "-a"],
        }.items():
            env[key] = capture(argv, cwd=repo)[1]
    launcher.environment = env
    (launcher.evidence / "environment.json").write_text(json.dumps(env, indent=2, default=str))


def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(Path(root).rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode() + b"\0" + sha256_file(path).encode() + b"\n")
    return digest.hexdigest()


def copy_file_immutable(source, destination, mode):
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(f".{destination.name}.{secrets.token_hex(4)}.tmp")
    shutil.copyfile(source, temp)
    os.chmod(temp, mode)
    os.replace(temp, destination)
    return sha256_file(destination)


def copy_tree_immutable(source, destination):
    shutil.copytree(source, destination, symlinks=False)
    for path in destination.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o444)
    return tree_digest(destination)


class CacheLock:
    def __init__(self, launcher, stage, name):
        self.launcher = launcher
        self.stage = stage
        self.path = launcher.cache / "locks" / f"{name}.lock"
        self.name = name
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "a+")
        waited = False
        started = time.monotonic()
        while True:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not waited:
                    waited = True
                    self.launcher.append_log(self.stage, f"# waiting for build-cache lock {self.path} held by another invocation\n")
                    self.launcher.say(f"  waiting for build-cache lock {self.name} (another invocation is building or copying)")
                    if self.launcher.fixture:
                        (self.launcher.fixture / f"waiting-{self.name}").write_text(str(os.getpid()))
                if self.launcher.interrupt_signal is not None:
                    self.handle.close()
                    self.handle = None
                    raise Interrupted()
                time.sleep(0.05)
        if waited:
            self.launcher.append_log(self.stage, f"# acquired {self.path} after {time.monotonic() - started:.1f}s\n")
        return self

    def __exit__(self, *exc):
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
        return False


def publish_artifact(launcher, stage, name, source, destination, mode):
    if not source.is_file():
        raise StageFailure(f"build finished but {source} does not exist")
    cache_hash = sha256_file(source)
    used_hash = copy_file_immutable(source, destination, mode)
    if used_hash != cache_hash:
        raise StageFailure(f"copy of {source} does not match its cache hash")
    entry = {"path": str(destination), "sha256": used_hash, "cache_source": str(source)}
    launcher.summary["artifacts"][name] = entry
    stage.record.setdefault("artifacts", {})[name] = entry
    launcher.paths[name] = str(destination)
    return entry


def build_cargo_artifact(launcher, name, title, manifest, target_name, product, key, artifact, mode, fixture_kind):
    stage = launcher.new_stage(name, title)
    launcher.begin(stage)
    target = launcher.cache / target_name
    output = target / "release" / product
    with CacheLock(launcher, stage, target_name):
        if launcher.fixture:
            launcher.run_checked(stage, [sys.executable, launcher.fixture / "fake_build.py", fixture_kind, output], env_extra={"CARGO_TARGET_DIR": target, **compiler_environment(launcher)})
        else:
            launcher.run_checked(stage, [*launcher.cargo, "build", "--release", "--locked", "--manifest-path", manifest],
                                 env_extra={"CARGO_TARGET_DIR": target, **compiler_environment(launcher)})
        publish_artifact(launcher, stage, key, output, launcher.artifacts / artifact, mode)
    return stage


def build_stage_rust(launcher):
    stage = build_cargo_artifact(launcher, "build-rust-library", "build the Rust libtpms library (release, --locked) and take a private copy",
                                 launcher.repo / "Cargo.toml", "rust-lib-target", "libtpms.so", "rust_library", "rust_library.so", 0o444, "rust-library")
    launcher.finish(stage, "completed", exit_code=0)


def build_stage_tool(launcher):
    stage = build_cargo_artifact(launcher, "build-timing-tool", "build the tpms-timing-tests CLI (release, --locked) and take a private copy",
                                 launcher.repo / "timing-tests" / "Cargo.toml", "cargo", "tpms-timing-tests", "tool", "tpms-timing-tests", 0o555, "timing-tool")
    if not launcher.fixture:
        for key in ("rust_library", "reference_library"):
            stage.record[f"{key}_ldd"] = capture(["ldd", launcher.paths[key]])[1]
    launcher.finish(stage, "completed", exit_code=0)


def space_free(path):
    text = str(path)
    if not any(c.isspace() for c in text):
        return path
    alias = Path(tempfile.gettempdir()) / f"tpms-timing-{hashlib.sha256(text.encode()).hexdigest()[:12]}"
    if alias.is_symlink() and os.readlink(alias) != text:
        alias.unlink()
    if not alias.exists():
        alias.symlink_to(text)
    return alias


def reference_build_environment(source_env):
    env = {key: source_env[key] for key in BASE_BUILD_ENV if key in source_env}
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    settings = {key: source_env[key] for key in BUILD_SETTINGS if key in source_env}
    env.update(settings)
    normalized = sorted(key for key in NORMALIZED_BUILD_ENV if key in source_env)
    return env, settings, normalized


def tool_identity(command, env):
    path = shutil.which(command, path=env.get("PATH"))
    identity = {"command": command, "path": path, "version": None}
    if path:
        real = os.path.realpath(path)
        identity["realpath"] = real
        try:
            identity["sha256"] = sha256_file(real)
        except OSError as error:
            identity["sha256"] = f"unreadable: {error}"
        code, out = capture([path, "--version"], env=env)
        identity["version"] = "\n".join((out or "").splitlines()[:2]) if code == 0 else f"--version failed ({code})"
    return identity


SUPPORTED_CC_WRAPPERS = ("env", "ccache")
REJECTED_CC_WRAPPERS = (
    "sccache", "distcc", "icecc", "icecream", "colorgcc", "buildcache", "time", "nice", "ionice", "sudo",
    "doas", "chrt", "taskset", "stdbuf", "nohup", "xargs", "command", "exec", "sh", "bash", "dash", "zsh",
)
MASQUERADING_WRAPPERS = ("ccache", "sccache", "distcc", "icecc", "buildcache")
CC_FORMS = (
    "CC may be a compiler executable with option arguments ('gcc', '/usr/bin/clang -m64'), "
    "'env [NAME=VALUE ...] <compiler> [options]' or 'ccache <compiler> [options]'"
)


class CompilerError(Exception):
    pass


def is_script(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return False


def resolve_command_word(word, path_value):
    if "/" in word:
        if not os.path.isabs(word):
            raise CompilerError(f"relative path {word!r} in CC is ambiguous because configure runs in the build directory; use an absolute path or a command name")
        return word if os.path.isfile(word) and os.access(word, os.X_OK) else None
    return shutil.which(word, path=path_value)


def executable_identity(path, env):
    real = os.path.realpath(path)
    identity = {"path": path, "realpath": real, "sha256": sha256_file(real), "version": None}
    code, out = capture([path, "--version"], env=env)
    identity["version"] = "\n".join((out or "").splitlines()[:2]) if code == 0 else f"--version failed ({code})"
    return identity


def ccache_compiler(word, path_value, ccache_real):
    if "/" in word:
        return resolve_command_word(word, path_value)
    for directory in path_value.split(os.pathsep):
        candidate = os.path.join(directory or ".", word)
        if not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)):
            continue
        real = os.path.realpath(candidate)
        if real == ccache_real or os.path.basename(real) in MASQUERADING_WRAPPERS:
            continue
        return candidate
    return None


def resolve_cc(cc_value, env):
    try:
        words = shlex.split(cc_value)
    except ValueError as error:
        raise CompilerError(f"CC={cc_value!r} cannot be split into words: {error}")
    if not words:
        raise CompilerError("CC is set but empty")
    path_value = env.get("PATH", "")
    form = "plain"
    wrapper = None
    assignments = {}
    effective_env = dict(env)
    name = os.path.basename(words[0])
    compiler_words = words
    if name in SUPPORTED_CC_WRAPPERS:
        form = name
        wrapper_path = resolve_command_word(words[0], path_value)
        if wrapper_path is None:
            raise CompilerError(f"the CC wrapper {words[0]!r} was not found on PATH")
        if is_script(os.path.realpath(wrapper_path)):
            raise CompilerError(f"the CC wrapper {wrapper_path} is a script; only the real {name} executable is supported")
        wrapper = executable_identity(wrapper_path, env)
        compiler_words = words[1:]
        if form == "env":
            while compiler_words and "=" in compiler_words[0] and compiler_words[0].split("=", 1)[0].isidentifier():
                key, value = compiler_words[0].split("=", 1)
                assignments[key] = value
                compiler_words = compiler_words[1:]
            if compiler_words and compiler_words[0].startswith("-"):
                raise CompilerError(f"env option {compiler_words[0]!r} in CC is not supported; use 'env NAME=VALUE <compiler>'")
            effective_env.update(assignments)
    elif name in REJECTED_CC_WRAPPERS:
        raise CompilerError(f"the CC wrapper {name!r} is not supported because the compiler it runs cannot be identified; {CC_FORMS}")
    if not compiler_words:
        raise CompilerError(f"CC={cc_value!r} names a wrapper but no compiler; {CC_FORMS}")
    compiler, arguments = compiler_words[0], compiler_words[1:]
    if os.path.basename(compiler) in SUPPORTED_CC_WRAPPERS + REJECTED_CC_WRAPPERS:
        raise CompilerError(f"nested CC wrappers ({cc_value!r}) are not supported; {CC_FORMS}")
    stray = [argument for argument in arguments if not argument.startswith("-")]
    if stray:
        raise CompilerError(
            f"CC={cc_value!r} has non-option words {stray} after the compiler, so the compiler cannot be identified unambiguously; "
            f"{CC_FORMS}. CC is split like a shell word list, so quote paths that contain spaces"
        )
    if form == "ccache":
        compiler_path = ccache_compiler(compiler, effective_env.get("PATH", ""), wrapper["realpath"])
    else:
        compiler_path = resolve_command_word(compiler, effective_env.get("PATH", ""))
    if compiler_path is None:
        raise CompilerError(
            f"the C compiler {compiler!r} selected by CC={cc_value!r} was not found; "
            "CC is split like a shell word list, so quote paths that contain spaces"
        )
    real = os.path.realpath(compiler_path)
    if os.path.basename(real) in MASQUERADING_WRAPPERS:
        raise CompilerError(
            f"the compiler {compiler_path} resolves to {real}, a compiler wrapper masquerading as a compiler; "
            f"set CC to the real compiler or use 'ccache <compiler>'"
        )
    if is_script(real):
        raise CompilerError(
            f"the compiler {compiler_path} is a script, which can run a different compiler that the cache key cannot see; "
            "point CC at the compiler executable"
        )
    return {
        "form": form,
        "cc": cc_value,
        "argv": words,
        "arguments": arguments,
        "env_assignments": assignments,
        "wrapper": wrapper,
        "effective": executable_identity(compiler_path, effective_env),
        "supported_forms": CC_FORMS,
    }


def compiler_exec_argv(identity):
    argv = []
    if identity["wrapper"] is not None:
        argv.append(os.path.abspath(identity["wrapper"]["path"]))
    argv += [f"{key}={value}" for key, value in identity["env_assignments"].items()]
    argv.append(os.path.abspath(identity["effective"]["path"]))
    argv += identity["arguments"]
    return argv


def compiler_launcher_script(identity):
    words = " ".join(shlex.quote(word) for word in compiler_exec_argv(identity))
    return f"#!/bin/sh\nexec {words} \"$@\"\n"


def compiler_launcher_state(directory, digest):
    script = directory / "cc"
    if not script.is_file() or not os.access(script, os.X_OK):
        return "missing"
    if sha256_file(script) != digest:
        return "content differs from its digest"
    return "valid"


def materialize_compiler_launcher(launcher, stage, identity):
    text = compiler_launcher_script(identity)
    digest = hashlib.sha256(text.encode()).hexdigest()
    root = launcher.cache / "compilers"
    directory = root / digest[:32]
    with CacheLock(launcher, stage, f"compiler-{digest[:32]}"):
        state = compiler_launcher_state(directory, digest)
        if state != "valid":
            root.mkdir(parents=True, exist_ok=True)
            if directory.exists():
                discard = root / f".discard-{digest[:12]}-{secrets.token_hex(4)}"
                os.rename(directory, discard)
                os.chmod(discard, 0o755)
                shutil.rmtree(discard, ignore_errors=True)
            staging = root / f".staging-{digest[:12]}-{os.getpid()}-{secrets.token_hex(4)}"
            try:
                staging.mkdir()
                (staging / "cc").write_text(text)
                os.chmod(staging / "cc", 0o555)
                mapping = {"cc": identity["cc"], "form": identity["form"], "exec_argv": compiler_exec_argv(identity), "sha256": digest}
                (staging / "launcher.json").write_text(json.dumps(mapping, indent=2))
                os.chmod(staging / "launcher.json", 0o444)
                os.chmod(staging, 0o555)
                os.rename(staging, directory)
            finally:
                if staging.exists():
                    os.chmod(staging, 0o755)
                    shutil.rmtree(staging, ignore_errors=True)
            if compiler_launcher_state(directory, digest) != "valid":
                raise StageFailure(f"published compiler launcher {directory} failed validation")
    return {
        "path": str(directory / "cc"),
        "sha256": digest,
        "exec_argv": compiler_exec_argv(identity),
        "cache": "reused" if state == "valid" else f"created ({state})",
    }


def reference_fingerprint(launcher, commit, env, settings):
    compiler = resolve_cc(settings.get("CC", "cc"), env)
    compiler["launcher"] = {
        "sha256": hashlib.sha256(compiler_launcher_script(compiler).encode()).hexdigest(),
        "exec_argv": compiler_exec_argv(compiler),
    }
    openssl = {}
    for module in ("libcrypto", "libssl"):
        entry = {}
        for key, flag in (("version", "--modversion"), ("cflags", "--cflags"), ("libs", "--libs"), ("libdir", "--variable=libdir"), ("includedir", "--variable=includedir")):
            code, out = capture(["pkg-config", flag, module], env=env)
            entry[key] = out if code == 0 else None
        libdir = entry.get("libdir")
        shared = Path(libdir) / f"{module}.so" if libdir else None
        entry["shared_object_sha256"] = sha256_file(os.path.realpath(shared)) if shared and shared.exists() else None
        header = Path(entry.get("includedir") or "/usr/include") / "openssl" / "opensslv.h"
        entry["opensslv_h_sha256"] = sha256_file(header) if module == "libcrypto" and header.exists() else None
        openssl[module] = entry
    tools = {name: tool_identity(name, env) for name in ("make", "autoreconf", "automake", "libtoolize", "pkg-config", "sh")}
    fingerprint = {
        "recipe": REFERENCE_RECIPE,
        "commit": commit,
        "configure": REFERENCE_CONFIGURE,
        "settings": settings,
        "compiler": compiler,
        "openssl": openssl,
        "tools": tools,
        "fixture": bool(launcher.fixture),
    }
    key = hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest()
    return fingerprint, key


def reference_entry_state(entry, key):
    stamp_path = entry / "build-stamp.json"
    if not entry.exists():
        return "missing"
    try:
        stamp = json.loads(stamp_path.read_text())
    except (OSError, ValueError):
        return "stamp missing or unreadable"
    if stamp.get("key") != key:
        return "stamp key differs"
    library = entry / "build" / "src" / ".libs" / "libtpms.so"
    if not library.is_file():
        return "library missing"
    if sha256_file(library) != stamp.get("library_sha256"):
        return "library hash differs from its stamp"
    header = entry / "source" / "include" / "libtpms" / "tpm_library.h"
    if not header.is_file():
        return "headers missing"
    if tree_digest(entry / "source" / "include") != stamp.get("include_sha256"):
        return "headers differ from their stamp"
    return "valid"


def build_reference_into(launcher, stage, staging, commit, env):
    library = staging / "build" / "src" / ".libs" / "libtpms.so"
    (staging / "build").mkdir(parents=True)
    fixture_source = launcher.scenario().get("reference_source") if launcher.fixture else None
    if launcher.fixture and not fixture_source:
        launcher.run_checked(stage, [sys.executable, launcher.fixture / "fake_build.py", "reference-library", library], env_exact=env)
    else:
        source = staging / "source"
        if fixture_source:
            shutil.copytree(launcher.fixture / fixture_source, source)
        else:
            archive = staging / "source.tar"
            launcher.run_checked(stage, git_argv(launcher.repo / "libtpms", "archive", "--format=tar", commit), stdout_path=archive)
            source.mkdir()
            with tarfile.open(archive) as bundle:
                if sys.version_info >= (3, 12):
                    bundle.extractall(source, filter="data")
                else:
                    bundle.extractall(source)
            archive.unlink()
        alias = space_free(staging)
        launcher.run_checked(stage, ["sh", "./autogen.sh"], cwd=alias / "source", env_exact={**env, "NOCONFIGURE": "1"})
        launcher.run_checked(stage, [alias / "source" / "configure", *REFERENCE_CONFIGURE], cwd=alias / "build", env_exact=env)
        jobs = launcher.args.jobs or len(allowed_cpus() or [1]) or 1
        launcher.run_checked(stage, ["make", f"-j{jobs}"], cwd=alias / "build", env_exact=env)
    if not library.is_file():
        raise StageFailure(f"reference build finished but {library} does not exist")
    return library


def build_stage_reference(launcher):
    stage = launcher.new_stage("build-reference-library", "build (or reuse) the pinned C libtpms reference and take a private copy")
    launcher.begin(stage)
    commit = launcher.paths.get("reference_commit") or "fixture"
    env, settings, normalized = reference_build_environment(os.environ)
    try:
        fingerprint, key = reference_fingerprint(launcher, commit, env, settings)
    except CompilerError as error:
        stage.record["build_configuration"] = {"supported_settings": list(BUILD_SETTINGS), "settings": settings, "rejected_cc": str(error)}
        raise StageFailure(f"unsupported compiler configuration: {error}")
    compiler = materialize_compiler_launcher(launcher, stage, fingerprint["compiler"])
    preflight = launcher.compiler.get("launcher") if launcher.compiler else None
    if preflight is not None and preflight["sha256"] != compiler["sha256"]:
        raise StageFailure(
            f"CC now resolves to {compiler['exec_argv']}, but preflight resolved it to {preflight['exec_argv']}; "
            "the compiler configuration changed during the run"
        )
    env["CC"] = str(space_free(Path(compiler["path"]).parent) / "cc")
    stage.record["build_configuration"] = {
        "supported_settings": list(BUILD_SETTINGS),
        "settings": settings,
        "normalized_away": normalized,
        "environment": env,
        "fingerprint": fingerprint,
        "cache_key": key,
        "compiler_launcher": {**compiler, "configure_cc": env["CC"]},
    }
    root = launcher.cache / "reference"
    entry = root / key[:32]
    stage.record["cache_entry"] = str(entry)
    with CacheLock(launcher, stage, f"reference-{key[:32]}"):
        state = reference_entry_state(entry, key)
        if state == "valid":
            stage.record["cache"] = "reused"
            launcher.append_log(stage, f"# reusing reference cache entry {entry} (key {key})\n")
        else:
            stage.record["cache"] = f"rebuilt ({state})"
            root.mkdir(parents=True, exist_ok=True)
            if entry.exists():
                discard = root / f".discard-{key[:12]}-{secrets.token_hex(4)}"
                os.rename(entry, discard)
                shutil.rmtree(discard, ignore_errors=True)
            staging = root / f".staging-{key[:12]}-{os.getpid()}-{secrets.token_hex(4)}"
            try:
                library = build_reference_into(launcher, stage, staging, commit, env)
                include = staging / "source" / "include"
                if not (include / "libtpms" / "tpm_library.h").is_file():
                    raise StageFailure("reference build produced no libtpms headers")
                stamp = {"key": key, "fingerprint": fingerprint, "library_sha256": sha256_file(library), "include_sha256": tree_digest(include), "built": utc_now()}
                (staging / "build-stamp.json").write_text(json.dumps(stamp, indent=2))
                os.rename(staging, entry)
            finally:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)
            if reference_entry_state(entry, key) != "valid":
                raise StageFailure(f"published reference cache entry {entry} failed validation")
        publish_artifact(launcher, stage, "reference_library", entry / "build" / "src" / ".libs" / "libtpms.so", launcher.artifacts / "reference_library.so", 0o444)
        include_copy = launcher.artifacts / "include"
        digest = copy_tree_immutable(entry / "source" / "include", include_copy)
        launcher.summary["artifacts"]["libtpms_include"] = {"path": str(include_copy), "sha256": digest, "cache_source": str(entry / "source" / "include")}
    stage.record["artifacts"]["commit"] = commit
    launcher.finish(stage, "completed", exit_code=0)


def seed_worker_dependencies(launcher, stage):
    shared = launcher.cache / "deps"
    local = launcher.work / "deps"
    local.mkdir(parents=True, exist_ok=True)
    copied = []
    with CacheLock(launcher, stage, "deps"):
        if shared.is_dir():
            for entry in sorted(shared.iterdir()):
                if entry.is_dir() and not entry.name.startswith("."):
                    shutil.copytree(entry, local / entry.name)
                    copied.append(entry.name)
    return copied


def publish_worker_dependencies(launcher):
    shared = launcher.cache / "deps"
    local = launcher.work / "deps"
    published = []
    if not local.is_dir():
        return published
    stage = launcher.stages[-1]
    with CacheLock(launcher, stage, "deps"):
        shared.mkdir(parents=True, exist_ok=True)
        for entry in sorted(local.iterdir()):
            target = shared / entry.name
            if entry.is_dir() and not target.exists():
                staging = shared / f".staging-{entry.name}-{secrets.token_hex(4)}"
                shutil.copytree(entry, staging)
                os.rename(staging, target)
                published.append(entry.name)
    return published


def isolate_stage(launcher):
    stage = launcher.new_stage("isolate-artifacts", "freeze this invocation's private artifacts and worker work directory")
    launcher.begin(stage)
    copied = seed_worker_dependencies(launcher, stage)
    stage.record["worker_work_dir"] = str(launcher.work)
    stage.record["seeded_dependencies"] = copied
    launcher.environment["artifacts_used"] = launcher.summary["artifacts"]
    (launcher.evidence / "environment.json").write_text(json.dumps(launcher.environment, indent=2, default=str))
    launcher.append_log(stage, json.dumps(launcher.summary["artifacts"], indent=2) + "\n")
    launcher.fixture_point("artifacts-selected")
    launcher.finish(stage, "completed")


def compiler_environment(launcher):
    if "CC" in os.environ and launcher.compiler and launcher.compiler.get("launcher"):
        return {"CC": launcher.compiler["launcher"]["path"]}
    return {}


def tool_environment(launcher):
    return compiler_environment(launcher) or None


def tool_argv(launcher, *args):
    include = launcher.artifacts / "include"
    common = [
        launcher.paths["tool"],
        "--repo",
        launcher.repo,
        "--work-dir",
        launcher.work,
        "--operation-timeout-s",
        launcher.args.operation_timeout_s,
    ]
    tail = list(args)
    if launcher.fixture is None and include.is_dir():
        tail += ["--libtpms-include", include]
    if launcher.cpu is not None:
        tail += ["--cpu", launcher.cpu]
    return common + tail


def rust_stage(launcher, name, title, args, expect_run=True):
    stage = launcher.new_stage(name, title)
    launcher.begin(stage)
    out = launcher.runs / f"{len(launcher.stages):02d}-{name}"
    out.mkdir(parents=True)
    code = launcher.run(stage, tool_argv(launcher, *args, "--out-dir", out), env_extra=tool_environment(launcher))
    run_dirs = sorted(p for p in out.iterdir() if p.is_dir())
    stage.record["run_dirs"] = [str(p) for p in run_dirs]
    stage.record["out_dir"] = str(out)
    if stage.record["commands"][-1].get("cancelled_by_signal"):
        launcher.finish(stage, "incomplete", f"cancelled by signal; partial evidence kept in {out}", exit_code=code)
        raise Interrupted()
    leftovers = stage.record["commands"][-1].get("leftover_processes_stopped")
    outcome = {0: "completed", 3: "incomplete", 4: "failed"}.get(code, "failed")
    detail = None
    if code not in (0, 3, 4):
        detail = f"timing tool exited with unexpected status {code}"
    run_dir = None
    if expect_run:
        if len(run_dirs) != 1 or not (run_dirs[0] / "run.json").is_file():
            outcome = "failed"
            detail = f"expected exactly one run directory with run.json in {out}, found {[p.name for p in run_dirs]}"
        else:
            run_dir = run_dirs[0]
            try:
                state = json.loads((run_dir / "run.json").read_text())["state"]
            except (OSError, ValueError, KeyError) as error:
                state = None
                outcome = "failed"
                detail = f"unreadable run.json: {error}"
            expected_state = {"completed": "completed", "incomplete": "incomplete", "failed": "failed"}.get(outcome)
            if state is not None and code in (0, 3, 4) and state != expected_state:
                outcome = "failed"
                detail = f"exit status {code} disagrees with run.json state {state!r}"
            stage.record["run_state"] = state
            if state and state != "completed" and detail is None:
                try:
                    detail = json.loads((run_dir / "run.json").read_text()).get("detail")
                except (OSError, ValueError):
                    pass
    if leftovers:
        outcome = "failed"
        detail = f"timing tool exited but left processes running (stopped: {leftovers})"
    stage.record["run_dir"] = str(run_dir) if run_dir else None
    launcher.finish(stage, outcome, detail, exit_code=code)
    if launcher.interrupt_signal is not None:
        raise Interrupted()
    return stage, run_dir


def pipeline(launcher):
    args = launcher.args
    params = {
        "seed": args.seed,
        "max_evaluations": args.max_evaluations,
        "search_duration_s": args.search_duration_s,
        "search_samples": args.search_samples,
        "verify_budget": args.verify_budget,
        "verify_batch": args.verify_batch,
        "verify_repeats": args.verify_repeats,
        "verify_time_limit_s": args.verify_time_limit_s,
        "max_verify_candidates": args.max_verify_candidates,
        "seed_diagnostics": args.seed_diagnostics,
        "boundary_diagnostics": True,
        "control_search_evaluations": args.control_search_evaluations,
        "control_verify_budget": args.control_verify_budget,
        "replay_batches": args.replay_batches,
        "operation_timeout_s": args.operation_timeout_s,
        "cpu": args.cpu,
        "jobs": args.jobs,
    }
    launcher.summary["parameters"] = params
    stage = launcher.new_stage("preflight", "check platform, tools, Rust toolchain, OpenSSL and the libtpms submodule")
    launcher.begin(stage)
    if launcher.fixture:
        problems, notes = [], ["fixture mode: native prerequisite checks are replaced by controlled fixtures"]
        launcher.paths["reference_commit"] = "fixture"
    else:
        problems, notes = check_prerequisites(launcher)
    cc_env, cc_settings, _ = reference_build_environment(os.environ)
    identity = None
    if "CC" in cc_settings or resolve_command_word("cc", cc_env.get("PATH", "")):
        try:
            identity = resolve_cc(cc_settings.get("CC", "cc"), cc_env)
            notes.append(
                f"CC={identity['cc']!r} ({identity['form']} form) runs {compiler_exec_argv(identity)}"
            )
        except CompilerError as error:
            problems.append(f"unsupported compiler configuration: {error}")
    cpu, why, allowed = select_cpu(launcher)
    launcher.cpu = cpu
    launcher.summary["cpu"] = {"selected": cpu, "reason": why, "affinity": allowed}
    with open(stage.record["log"], "a") as log:
        for note in notes:
            log.write(f"note: {note}\n")
        for problem in problems:
            log.write(f"problem: {problem}\n")
    for note in notes:
        launcher.say(f"  note: {note}")
    for problem in problems:
        launcher.say(f"  prerequisite missing: {problem}")
    record_environment(launcher)
    if problems:
        launcher.finish(stage, "failed", "; ".join(problems))
        return "prerequisites"
    launcher.say(f"  workers pinned to CPU {cpu} ({why})" if cpu is not None else f"  {why}")
    if identity is not None:
        launcher.compiler = {"identity": identity, "launcher": materialize_compiler_launcher(launcher, stage, identity)}
        stage.record["compiler"] = launcher.compiler
        launcher.append_log(stage, f"note: compiler launcher {launcher.compiler['launcher']['path']} runs {launcher.compiler['launcher']['exec_argv']}\n")
    launcher.finish(stage, "completed")
    launcher.artifacts.mkdir(parents=True, exist_ok=True)
    for builder in (build_stage_rust, build_stage_reference, build_stage_tool, isolate_stage):
        try:
            builder(launcher)
        except StageFailure as error:
            launcher.finish(launcher.stages[-1], "failed", str(error))
            return "build"
    launcher.environment["binaries"] = {
        key: {"path": launcher.paths[key], "sha256": launcher.summary["artifacts"][key]["sha256"]}
        for key in ("rust_library", "reference_library", "tool")
    }
    (launcher.evidence / "environment.json").write_text(json.dumps(launcher.environment, indent=2, default=str))
    rust = launcher.paths["rust_library"]
    reference = launcher.paths["reference_library"]
    stage, selftest_run = rust_stage(
        launcher,
        "self-test",
        "deterministic self-tests and live positive/negative controls",
        [
            "self-test",
            "--live-controls",
            "positive,negative",
            "--seed",
            args.seed,
            "--search-evaluations",
            args.control_search_evaluations,
            "--verify-budget",
            args.control_verify_budget,
            "--verify-repeats",
            args.verify_repeats,
            "--verify-time-limit-s",
            args.verify_time_limit_s,
        ],
    )
    launcher.produced = [selftest_run] if selftest_run else []
    try:
        published = publish_worker_dependencies(launcher)
        if published:
            launcher.say(f"  published worker dependencies to the shared cache: {published}")
    except OSError as error:
        launcher.summary["explanations"].append(f"could not publish worker dependencies to the shared cache: {error}")
    if stage.record["outcome"] != "completed":
        return "controls"
    search_runs = []
    for backend, library_flag, library in (("rust", "--rust-lib", rust), ("reference", "--reference-lib", reference)):
        stage, run_dir = rust_stage(
            launcher,
            f"search-{backend}",
            f"adaptive search on the {backend} library",
            [
                "search",
                "--backend",
                backend,
                library_flag,
                library,
                "--seed",
                args.seed,
                "--max-evaluations",
                args.max_evaluations,
                "--max-duration-s",
                args.search_duration_s,
                "--samples-per-class",
                args.search_samples,
            ],
        )
        if run_dir:
            launcher.produced.append(run_dir)
        if stage.record["outcome"] == "failed":
            return "search"
        if stage.record["outcome"] == "completed":
            search_runs.append(run_dir)
        else:
            launcher.summary["explanations"].append(f"search-{backend} was incomplete; its candidates are excluded from verification")
    verify_args = [
        "verify",
        "--backend",
        "both",
        "--rust-lib",
        rust,
        "--reference-lib",
        reference,
        "--seed",
        args.seed,
        "--budget",
        args.verify_budget,
        "--batch",
        args.verify_batch,
        "--repeats",
        args.verify_repeats,
        "--time-limit-s",
        args.verify_time_limit_s,
        "--max-candidates",
        args.max_verify_candidates,
        "--seed-diagnostics",
        args.seed_diagnostics,
        "--include-seed-diagnostics",
    ]
    for run_dir in search_runs:
        verify_args += ["--search-run", run_dir]
    stage, verify_run = rust_stage(launcher, "verify", "independent dudect verification of the search candidates and boundary diagnostics", verify_args)
    if verify_run:
        launcher.produced.append(verify_run)
    if stage.record["outcome"] == "failed":
        return "verify"
    results_path = verify_run / "results.json" if verify_run else None
    try:
        results = json.loads(results_path.read_text())
        candidates = [Path(entry["candidate_file"]) for entry in results["results"]]
    except (AttributeError, OSError, ValueError, KeyError, TypeError) as error:
        launcher.skip("replay", "replay every verified candidate", f"verification results unavailable: {error}")
        return "replay-input"
    if not candidates:
        launcher.skip("replay", "replay every verified candidate", "verification produced no candidate results")
        return None
    for index, candidate in enumerate(candidates, 1):
        stage, run_dir = rust_stage(
            launcher,
            f"replay-{index:02d}",
            f"replay {candidate.name}",
            [
                "replay",
                "--backend",
                "both",
                "--rust-lib",
                rust,
                "--reference-lib",
                reference,
                "--candidate",
                candidate,
                "--samples-per-class",
                args.search_samples,
                "--batches",
                args.replay_batches,
                "--seed",
                args.seed,
            ],
        )
        stage.record["candidate"] = str(candidate)
        if run_dir:
            launcher.produced.append(run_dir)
    return None


def validate_report(report_json, report_md):
    try:
        text = report_json.read_text()
    except OSError as error:
        raise ValueError(f"report.json is unreadable: {error}")
    try:
        report = json.loads(text)
    except ValueError as error:
        raise ValueError(f"report.json is not valid JSON: {error}")
    if not isinstance(report, dict):
        raise ValueError("report.json is not a JSON object")
    reported = report.get("overall_outcome")
    if reported not in RANK:
        raise ValueError(f"report.json overall_outcome {reported!r} is not one of {sorted(RANK)}")
    runs = report.get("runs", [])
    if not isinstance(runs, list) or not all(isinstance(run, dict) for run in runs):
        raise ValueError("report.json runs is not a list of objects")
    try:
        report_md.read_text()
    except OSError as error:
        raise ValueError(f"report.md is unreadable: {error}")
    return report


def report_stage(launcher):
    produced = [p for p in getattr(launcher, "produced", []) if p]
    tool = launcher.paths.get("tool")
    if not tool or not produced:
        reason = "the timing tool was not built" if not tool else "no timing-tool run directory was produced"
        launcher.skip("report", "generate the combined report", reason)
        launcher.summary["explanations"].append(f"no Rust report was generated: {reason}")
        return
    stage = launcher.new_stage("report", "generate the combined JSON and Markdown report from saved artifacts")
    launcher.begin(stage)
    report_json = launcher.report_dir / "report.json"
    report_md = launcher.report_dir / "report.md"
    launcher.summary["report"] = None
    try:
        code = launcher.run(stage, [tool, "report", *produced, "--output", launcher.report_dir])
    except Interrupted:
        launcher.finish(stage, "incomplete", "interrupted before the report command started")
        return
    if stage.record["commands"][-1].get("cancelled_by_signal"):
        launcher.finish(stage, "incomplete", "the report command was cancelled by a signal; no report is claimed", exit_code=code)
        return
    if code != 0:
        launcher.finish(stage, "failed", f"report command exited with status {code}; no report is claimed", exit_code=code)
        return
    try:
        report = validate_report(report_json, report_md)
        expected = None
        for run_dir in produced:
            state = json.loads((run_dir / "run.json").read_text()).get("state")
            expected = worst(expected, {"completed": "completed", "failed": "failed"}.get(state, "incomplete"))
    except (ValueError, OSError) as error:
        launcher.finish(stage, "failed", f"report validation failed: {error}; no report is claimed", exit_code=code)
        return
    reported = report["overall_outcome"]
    launcher.summary["rust_report_overall_outcome"] = reported
    launcher.summary["rust_report_consistent"] = reported == expected
    launcher.summary["exploratory"] = any(run.get("exploratory") for run in report.get("runs", []))
    if reported != expected:
        launcher.finish(stage, "failed", f"report overall_outcome {reported!r} disagrees with the run states ({expected!r})", exit_code=code)
        return
    if launcher.interrupt_signal is not None:
        launcher.finish(stage, "incomplete", "interrupted after the report command completed; the report is not claimed", exit_code=code)
        return
    launcher.summary["report"] = {"json": str(report_json), "markdown": str(report_md)}
    launcher.finish(stage, "completed", exit_code=code)


SKIP_AFTER = {
    "prerequisites": ("prerequisites are missing", ["build-rust-library", "build-reference-library", "build-timing-tool", "isolate-artifacts", "self-test", "search-rust", "search-reference", "verify", "replay"]),
    "build": ("a build stage failed", ["build-rust-library", "build-reference-library", "build-timing-tool", "isolate-artifacts", "self-test", "search-rust", "search-reference", "verify", "replay"]),
    "controls": ("the self-test or live controls did not complete", ["search-rust", "search-reference", "verify", "replay"]),
    "search": ("an adaptive search failed", ["verify", "replay"]),
    "verify": ("verification failed", ["replay"]),
    "replay-input": (None, []),
    "internal": ("the launcher hit an internal error", ["build-rust-library", "build-reference-library", "build-timing-tool", "isolate-artifacts", "self-test", "search-rust", "search-reference", "verify", "replay"]),
}


def record_internal_error(launcher, error):
    import traceback

    text = traceback.format_exc()
    if launcher.current is not None:
        stop_group(launcher.current.pid, grace=2.0)
        launcher.current = None
    running = [s for s in launcher.stages if s.record["status"] == "running"]
    stage = running[-1] if running else launcher.new_stage("launcher-internal-error", "launcher internal error")
    if not running:
        stage.record["status"] = "running"
        stage.record["started"] = utc_now()
    launcher.append_log(stage, f"# launcher internal error\n{text}\n")
    launcher.finish(stage, "failed", f"launcher internal error: {error!r}")
    launcher.summary["internal_error"] = text


def guarded(launcher, step):
    try:
        return step()
    except Interrupted:
        return "interrupted"
    except StageFailure as error:
        running = [s for s in launcher.stages if s.record["status"] == "running"]
        if running:
            launcher.finish(running[-1], "failed", str(error))
        return "build"
    except Exception as error:
        record_internal_error(launcher, error)
        return "internal"


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    validate(args, parser)
    launcher = Launcher(args)
    try:
        launcher.evidence.mkdir(parents=True, exist_ok=True)
        if any(launcher.evidence.iterdir()):
            sys.stderr.write(f"{parser.prog}: error: evidence directory {launcher.evidence} is not empty; refusing to overwrite\n")
            return EXIT_USAGE
        launcher.logs.mkdir()
        launcher.runs.mkdir()
    except OSError as error:
        sys.stderr.write(f"{parser.prog}: error: cannot create evidence directory: {error}\n")
        return EXIT_USAGE
    launcher.subreaper = set_child_subreaper()
    launcher.install_signals()
    launcher.say(f"evidence directory: {launcher.evidence}")
    launcher.write_summary()
    stopped = guarded(launcher, lambda: pipeline(launcher))
    try:
        names = {s.record["name"] for s in launcher.stages}
        if stopped == "interrupted" or launcher.interrupt_signal is not None:
            sig = signal.Signals(launcher.interrupt_signal).name if launcher.interrupt_signal else "signal"
            for stage in launcher.stages:
                if stage.record["status"] == "running":
                    launcher.finish(stage, "incomplete", "interrupted")
            for name in ["build-rust-library", "build-reference-library", "build-timing-tool", "isolate-artifacts", "self-test", "search-rust", "search-reference", "verify", "replay", "report"]:
                if name not in names and not any(n.startswith(name) for n in names):
                    launcher.skip(name, name, f"not started: launcher interrupted by {sig}")
        else:
            if stopped in SKIP_AFTER and SKIP_AFTER[stopped][0]:
                reason, later = SKIP_AFTER[stopped]
                for name in later:
                    if name not in names:
                        launcher.skip(name, name, f"not run because {reason}")
            guarded(launcher, lambda: report_stage(launcher))
    except Exception as error:
        record_internal_error(launcher, error)
    try:
        outcome = launcher.finalize()
    except Exception as error:
        sys.stderr.write(f"[run.py] error: finalizing the launcher summary failed: {error!r}\n")
        return EXIT_CODES["failed"]
    print()
    launcher.say(f"overall outcome: {outcome.upper()} (exit {EXIT_CODES[outcome]})")
    report = launcher.summary.get("report")
    if report:
        launcher.say(f"report: {report['markdown']}")
        launcher.say(f"report outcome recorded by the timing tool: {launcher.summary['rust_report_overall_outcome']}")
    else:
        launcher.say("report: none generated (see explanations below)")
    launcher.say(f"evidence: {launcher.evidence}")
    launcher.say(f"launcher summary: {launcher.evidence / 'launcher-summary.json'}")
    exploratory = launcher.summary.get("exploratory")
    launcher.say(
        "measurements marked exploratory (virtualized or binary-translated host)" if exploratory
        else ("measurements not marked exploratory" if exploratory is False else "exploratory status unknown (no report)")
    )
    for explanation in launcher.summary["explanations"]:
        launcher.say(f"  - {explanation}")
    if launcher.summary_error is not None:
        sys.stderr.write(
            f"[run.py] error: the evidence could not be written completely ({launcher.summary_error}); "
            f"the pipeline outcome was {outcome}, but without a complete summary this invocation is reported as failed\n"
        )
        return EXIT_CODES["failed"]
    return EXIT_CODES[outcome]


if __name__ == "__main__":
    sys.exit(main())
