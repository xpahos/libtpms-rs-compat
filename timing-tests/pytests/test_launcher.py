import json
import os
import shlex
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN_PY = HERE.parent / "run.py"
FIXTURES = HERE / "fixtures"
SMALL = [
    "--max-evaluations", "3",
    "--search-duration-s", "60",
    "--search-samples", "10",
    "--verify-budget", "2000",
    "--verify-batch", "1000",
    "--verify-time-limit-s", "60",
    "--control-search-evaluations", "5",
    "--control-verify-budget", "2000",
]


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class LauncherCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tpms launcher "))
        self.fixture = self.tmp / "fixture dir"
        shutil.copytree(FIXTURES, self.fixture)
        self.out = self.tmp / "evidence out"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scenario(self, **plan):
        (self.fixture / "scenario.json").write_text(json.dumps(plan))

    def launch(self, *extra, run_py=RUN_PY, out=None):
        out = out or self.out
        argv = [sys.executable, str(run_py), "--fixture", str(self.fixture), "--output-dir", str(out), *SMALL, *extra]
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        summary_path = out / "launcher-summary.json"
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
        return result.returncode, result.stdout, summary

    def stages(self, summary):
        return {stage["name"]: stage for stage in summary["stages"]}

    def assert_skipped(self, summary, names, reason_part):
        stages = self.stages(summary)
        for name in names:
            self.assertIn(name, stages, name)
            self.assertEqual(stages[name]["status"], "skipped", name)
            self.assertIn(reason_part, stages[name]["detail"], name)


class PipelineOutcomes(LauncherCase):
    def test_successful_pipeline(self):
        self.scenario(verify={"exit": 0, "candidates": 3})
        code, output, summary = self.launch()
        self.assertEqual(code, 0, output)
        self.assertEqual(summary["aggregate_outcome"], "completed")
        stages = self.stages(summary)
        expected = ["preflight", "build-rust-library", "build-reference-library", "build-timing-tool", "isolate-artifacts", "self-test",
                    "search-rust", "search-reference", "verify", "replay-01", "replay-02", "replay-03", "report"]
        self.assertEqual([s["name"] for s in summary["stages"]], expected)
        self.assertTrue(all(stages[n]["status"] == "completed" for n in expected))
        self.assertEqual(summary["rust_report_overall_outcome"], "completed")
        self.assertTrue(summary["rust_report_consistent"])
        self.assertTrue(summary["exploratory"])
        self.assertTrue(Path(summary["report"]["markdown"]).is_file())
        self.assertIn("overall outcome: COMPLETED", output)
        self.assertIn("measurements marked exploratory", output)
        for stage in summary["stages"]:
            self.assertTrue(Path(stage["log"]).is_file(), stage["name"])
            for command in stage["commands"]:
                self.assertEqual(command["exit"], 0)
        self.assertTrue((self.out / "environment.json").is_file())
        report = json.loads(Path(summary["report"]["json"]).read_text())
        run_dirs = [d for s in summary["stages"] for d in s["run_dirs"]]
        self.assertEqual(sorted(report["inputs"]), sorted(run_dirs))

    def test_build_failure_stops_dependent_stages(self):
        self.scenario(build_fail="reference-library")
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        stages = self.stages(summary)
        self.assertEqual(stages["build-reference-library"]["status"], "failed")
        self.assert_skipped(summary, ["build-timing-tool", "self-test", "search-rust", "search-reference", "verify", "replay"], "a build stage failed")
        self.assert_skipped(summary, ["report"], "timing tool was not built")
        self.assertIsNone(summary["report"])
        self.assertIn("report: none generated", output)

    def test_self_test_failure_stops_timing_work_but_reports(self):
        self.scenario(**{"self-test": {"exit": 4, "detail": "positive control not detected"}})
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assert_skipped(summary, ["search-rust", "search-reference", "verify", "replay"], "self-test or live controls")
        stages = self.stages(summary)
        self.assertEqual(stages["report"]["status"], "completed")
        self.assertEqual(summary["aggregate_outcome"], "failed", "a successful report must not hide the failure")
        self.assertEqual(summary["rust_report_overall_outcome"], "failed")
        self.assertIn("positive control not detected", stages["self-test"]["detail"])

    def test_incomplete_verification_still_reaches_replay_and_report(self):
        self.scenario(verify={"exit": 3, "candidates": 2})
        code, output, summary = self.launch()
        self.assertEqual(code, 3, output)
        stages = self.stages(summary)
        self.assertEqual(stages["verify"]["status"], "incomplete")
        self.assertEqual(stages["replay-02"]["status"], "completed")
        self.assertEqual(stages["report"]["status"], "completed")
        self.assertEqual(summary["aggregate_outcome"], "incomplete")
        self.assertEqual(summary["rust_report_overall_outcome"], "incomplete")

    def test_failure_takes_precedence_over_incomplete(self):
        self.scenario(verify={"exit": 3, "candidates": 3}, replay={"fail_index": 2})
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        stages = self.stages(summary)
        self.assertEqual(stages["replay-02"]["status"], "failed")
        self.assertEqual(stages["replay-03"]["status"], "completed")
        self.assertEqual(summary["aggregate_outcome"], "failed")

    def test_incomplete_search_is_excluded_from_verification(self):
        self.scenario(**{"search-rust": {"exit": 3}})
        code, output, summary = self.launch()
        self.assertEqual(code, 3, output)
        stages = self.stages(summary)
        verify_argv = stages["verify"]["commands"][0]["argv"]
        searched = [verify_argv[i + 1] for i, a in enumerate(verify_argv) if a == "--search-run"]
        self.assertEqual(searched, [stages["search-reference"]["run_dir"]])

    def test_report_failure_is_a_failure_without_a_claimed_report(self):
        self.scenario(report={"exit": 4})
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assertEqual(self.stages(summary)["report"]["status"], "failed")
        self.assertIsNone(summary["report"])
        self.assertIn("report: none generated", output)

    def test_report_disagreeing_with_run_states_fails(self):
        self.scenario(verify={"exit": 3}, report={"overall": "completed"})
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assertFalse(summary["rust_report_consistent"])

    def test_tool_crash_and_state_mismatch_fail(self):
        self.scenario(**{"search-reference": {"exit": 0, "state": "incomplete"}})
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assertIn("disagrees with run.json state", self.stages(summary)["search-reference"]["detail"])
        self.assert_skipped(summary, ["verify", "replay"], "an adaptive search failed")

    def test_leftover_processes_fail_the_stage_and_are_stopped(self):
        self.scenario(leak="search-rust")
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        stage = self.stages(summary)["search-rust"]
        self.assertEqual(stage["status"], "failed")
        self.assertTrue(stage["commands"][0]["leftover_processes_stopped"])
        for pid in stage["commands"][0]["leftover_processes_stopped"]:
            deadline = time.monotonic() + 10
            while alive(pid) and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertFalse(alive(pid), pid)


class Association(LauncherCase):
    def test_runs_are_taken_from_this_invocation_only(self):
        self.scenario(decoy=True)
        code, output, summary = self.launch()
        self.assertEqual(code, 0, output)
        self.assertTrue(any((self.fixture / "shared-runs").iterdir()), "the decoy run exists")
        stages = self.stages(summary)
        verify_argv = stages["verify"]["commands"][0]["argv"]
        searched = [verify_argv[i + 1] for i, a in enumerate(verify_argv) if a == "--search-run"]
        self.assertEqual(searched, [stages["search-rust"]["run_dir"], stages["search-reference"]["run_dir"]])
        for path in searched:
            self.assertTrue(Path(path).is_relative_to(self.out.resolve()), path)

    def test_ambiguous_run_directories_fail(self):
        self.scenario(**{"search-rust": {"runs": 2}})
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assertIn("expected exactly one run directory", self.stages(summary)["search-rust"]["detail"])

    def test_missing_run_directory_fails(self):
        self.scenario(**{"self-test": {"runs": 0}})
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assertIn("expected exactly one run directory", self.stages(summary)["self-test"]["detail"])

    def test_existing_output_is_never_overwritten(self):
        self.scenario()
        self.out.mkdir()
        marker = self.out / "previous-evidence.txt"
        marker.write_text("keep me")
        code, output, summary = self.launch()
        self.assertEqual(code, 2, output)
        self.assertIn("refusing to overwrite", output)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["previous-evidence.txt"])
        self.assertEqual(marker.read_text(), "keep me")

    def test_paths_with_spaces_and_any_working_directory(self):
        repo = self.tmp / "repo with spaces"
        (repo / "timing-tests").mkdir(parents=True)
        shutil.copy(RUN_PY, repo / "timing-tests" / "run.py")
        self.scenario()
        out = self.tmp / "out dir" / "evidence one"
        argv = [sys.executable, str(repo / "timing-tests" / "run.py"), "--fixture", str(self.fixture), "--output-dir", str(out), *SMALL]
        result = subprocess.run(argv, cwd=str(self.tmp), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout)
        summary = json.loads((out / "launcher-summary.json").read_text())
        self.assertEqual(summary["repository"], str(repo.resolve()))
        self.assertTrue(Path(summary["report"]["markdown"]).is_file())


class Arguments(LauncherCase):
    def run_args(self, *extra):
        argv = [sys.executable, str(RUN_PY), "--fixture", str(self.fixture), "--output-dir", str(self.out), *extra]
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)

    def test_invalid_arguments_exit_2_before_work(self):
        for extra, needle in [
            (["--verify-batch", "16"], "at least 32"),
            (["--verify-budget", "500", "--verify-batch", "1000"], "at least --verify-batch"),
            (["--max-evaluations", "0"], "positive"),
            (["--seed", "x"], "integer"),
            (["--no-such-option"], "unrecognized"),
            (["--control-verify-budget", "10"], "at least 1000"),
        ]:
            result = self.run_args(*extra)
            self.assertEqual(result.returncode, 2, (extra, result.stdout))
            self.assertIn(needle, result.stdout, extra)
            self.assertFalse(self.out.exists(), extra)

    @unittest.skipUnless(hasattr(os, "sched_getaffinity"), "needs sched_getaffinity")
    def test_cpu_outside_affinity_is_rejected(self):
        result = self.run_args("--cpu", str(max(os.sched_getaffinity(0)) + 1000))
        self.assertEqual(result.returncode, 2, result.stdout)

    def test_help_documents_options(self):
        result = subprocess.run([sys.executable, str(RUN_PY), "--help"], stdout=subprocess.PIPE, text=True)
        for option in ["--seed", "--max-evaluations", "--search-duration-s", "--search-samples", "--verify-budget",
                       "--verify-batch", "--verify-repeats", "--verify-time-limit-s", "--max-verify-candidates",
                       "--cpu", "--output-dir"]:
            self.assertIn(option, result.stdout)
        self.assertNotIn("--fixture", result.stdout)

    @unittest.skipIf(sys.platform.startswith("linux") and platform.machine() == "x86_64", "native platform")
    def test_unsupported_platform_fails_actionably_before_building(self):
        argv = [sys.executable, str(RUN_PY), "--output-dir", str(self.out), *SMALL]
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
        self.assertEqual(result.returncode, 4, result.stdout)
        self.assertIn("native Linux x86_64 only", result.stdout)
        summary = json.loads((self.out / "launcher-summary.json").read_text())
        stages = {s["name"]: s for s in summary["stages"]}
        self.assertEqual(stages["preflight"]["status"], "failed")
        self.assertEqual(stages["build-rust-library"]["status"], "skipped")
        self.assertEqual(stages["build-rust-library"]["commands"], [])


class InternalErrors(LauncherCase):
    def test_unexpected_launcher_error_is_finalized_as_failure(self):
        self.scenario()
        driver = self.tmp / "driver.py"
        driver.write_text(
            "import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('launcher', {str(RUN_PY)!r})\n"
            "launcher = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(launcher)\n"
            "def boom(_):\n"
            "    raise RuntimeError('injected fault in build-timing-tool')\n"
            "launcher.build_stage_tool = boom\n"
            "sys.exit(launcher.main(sys.argv[1:]))\n"
        )
        argv = [sys.executable, str(driver), "--fixture", str(self.fixture), "--output-dir", str(self.out), *SMALL]
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        self.assertEqual(result.returncode, 4, result.stdout)
        self.assertNotIn("Traceback", result.stdout)
        summary = json.loads((self.out / "launcher-summary.json").read_text())
        self.assertEqual(summary["aggregate_outcome"], "failed")
        self.assertIn("injected fault", summary["internal_error"])
        self.assert_skipped(summary, ["self-test", "verify"], "internal error")
        stages = self.stages(summary)
        self.assertEqual(stages["build-reference-library"]["status"], "completed")
        self.assertEqual(stages["build-rust-library"]["commands"][0]["env"]["CARGO_TARGET_DIR"].endswith("rust-lib-target"), True)


def secrets_token():
    import secrets

    return secrets.token_hex(4)


def wait_for(predicate, what, process=None, timeout=120):
    deadline = time.monotonic() + timeout
    while not predicate():
        if process is not None and process.poll() is not None:
            raise AssertionError(f"process exited ({process.returncode}) before {what}: {process.stdout.read() if process.stdout else ''}")
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.02)


def sha256(path):
    import hashlib

    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Finalized(LauncherCase):
    def assert_finalized(self, summary, exit_code):
        self.assertIsNotNone(summary, "launcher-summary.json must exist")
        self.assertEqual(summary["exit_code"], exit_code)
        self.assertEqual(summary["aggregate_outcome"], {0: "completed", 3: "incomplete", 4: "failed"}[exit_code])
        self.assertIsNotNone(summary["finished"])
        running = [s["name"] for s in summary["stages"] if s["status"] in ("running", "pending")]
        self.assertEqual(running, [], "no stage may be left running")


class SharedCache(Finalized):
    def setUp(self):
        super().setUp()
        self.cache = self.tmp / "shared cache"
        self.fixture_b = self.tmp / "fixture b"
        shutil.copytree(FIXTURES, self.fixture_b)

    def start(self, fixture, out, plan, env=None):
        (fixture / "scenario.json").write_text(json.dumps(plan))
        argv = [sys.executable, str(RUN_PY), "--fixture", str(fixture), "--output-dir", str(out), "--build-cache", str(self.cache), *SMALL]
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)

    def finish(self, process, out):
        output, _ = process.communicate(timeout=300)
        summary_path = out / "launcher-summary.json"
        return process.returncode, output, json.loads(summary_path.read_text()) if summary_path.exists() else None

    def used(self, summary, stage_name):
        stage = self.stages(summary)[stage_name]
        return json.loads((Path(stage["run_dir"]) / "used.json").read_text())

    def test_active_run_keeps_its_artifacts_while_another_rebuilds_the_cache(self):
        out_a, out_b = self.tmp / "run a", self.tmp / "run b"
        run_a = self.start(self.fixture, out_a, {"build_tag": "A", "pause_at": "artifacts-selected"})
        wait_for(lambda: (self.fixture / "paused-artifacts-selected").exists(), "run A to select its artifacts", run_a)
        summary_a = json.loads((out_a / "launcher-summary.json").read_text())
        recorded = {name: entry["sha256"] for name, entry in summary_a["artifacts"].items()}
        entry = Path(self.stages(summary_a)["build-reference-library"]["cache_entry"])
        cached_library = entry / "build" / "src" / ".libs" / "libtpms.so"
        with open(cached_library, "w") as handle:
            handle.write("corrupted in place while run A is active\n")
        run_b = self.start(self.fixture_b, out_b, {"build_tag": "B"})
        code_b, output_b, summary_b = self.finish(run_b, out_b)
        self.assertEqual(code_b, 0, output_b)
        self.assertEqual(self.stages(summary_b)["build-reference-library"]["cache"], "rebuilt (library hash differs from its stamp)")
        self.assertIn("build B", (self.cache / "rust-lib-target" / "release" / "libtpms.so").read_text())
        self.assertIn("build B", (self.cache / "cargo" / "release" / "tpms-timing-tests").read_text())
        self.assertIn("build B", cached_library.read_text())
        (self.fixture / "resume-artifacts-selected").write_text("go")
        code_a, output_a, summary_a = self.finish(run_a, out_a)
        self.assertEqual(code_a, 0, output_a)
        self.assertEqual({name: entry["sha256"] for name, entry in summary_a["artifacts"].items()}, recorded)
        self.assertTrue(summary_a["artifact_integrity"]["unchanged"])
        for name, entry in summary_a["artifacts"].items():
            self.assertTrue(Path(entry["path"]).is_relative_to(out_a.resolve()), name)
        used = self.used(summary_a, "search-rust")
        self.assertEqual(used["--rust-lib"]["content"], "fake rust-library build A")
        self.assertEqual(used["--rust-lib"]["sha256"], recorded["rust_library"])
        self.assertEqual(used["tool_fixture"], str(self.fixture.resolve()))
        used = self.used(summary_a, "verify")
        self.assertEqual(used["--reference-lib"]["content"], "fake reference-library build A")
        self.assertEqual(used["--reference-lib"]["sha256"], recorded["reference_library"])
        self.assertEqual(self.used(summary_b, "verify")["--reference-lib"]["content"], "fake reference-library build B")
        self.assertEqual(sha256(summary_a["artifacts"]["tool"]["path"]), recorded["tool"])

    def test_concurrent_reference_construction_builds_once_and_shares_the_entry(self):
        out_a, out_b = self.tmp / "run a", self.tmp / "run b"
        run_a = self.start(self.fixture, out_a, {"block_build": "reference-library"})
        wait_for(lambda: (self.fixture / "building-reference-library").exists(), "run A to start the reference build", run_a)
        run_b = self.start(self.fixture_b, out_b, {})
        wait_for(lambda: any(self.fixture_b.glob("waiting-reference-*")), "run B to wait for the reference lock", run_b)
        self.assertFalse((self.fixture_b / "reference-builds.log").exists())
        (self.fixture / "resume-build-reference-library").write_text("go")
        code_a, output_a, summary_a = self.finish(run_a, out_a)
        code_b, output_b, summary_b = self.finish(run_b, out_b)
        self.assertEqual((code_a, code_b), (0, 0), output_a + output_b)
        self.assertTrue(self.stages(summary_a)["build-reference-library"]["cache"].startswith("rebuilt"))
        self.assertEqual(self.stages(summary_b)["build-reference-library"]["cache"], "reused")
        self.assertEqual(len((self.fixture / "reference-builds.log").read_text().splitlines()), 1)
        self.assertFalse((self.fixture_b / "reference-builds.log").exists())
        self.assertEqual(summary_a["artifacts"]["reference_library"]["sha256"], summary_b["artifacts"]["reference_library"]["sha256"])
        self.assertEqual([p.name for p in (self.cache / "reference").iterdir() if p.name.startswith(".")], [])

    def test_interrupt_while_waiting_for_a_lock_finalizes_as_incomplete(self):
        out_a, out_b = self.tmp / "run a", self.tmp / "run b"
        run_a = self.start(self.fixture, out_a, {"block_build": "reference-library"})
        wait_for(lambda: (self.fixture / "building-reference-library").exists(), "run A to start the reference build", run_a)
        run_b = self.start(self.fixture_b, out_b, {})
        wait_for(lambda: any(self.fixture_b.glob("waiting-reference-*")), "run B to wait for the reference lock", run_b)
        run_b.send_signal(signal.SIGINT)
        code_b, output_b, summary_b = self.finish(run_b, out_b)
        self.assertEqual(code_b, 3, output_b)
        self.assert_finalized(summary_b, 3)
        stages = self.stages(summary_b)
        self.assertEqual(stages["build-reference-library"]["status"], "interrupted")
        self.assert_skipped(summary_b, ["build-timing-tool", "self-test", "verify", "report"], "interrupted by SIGINT")
        (self.fixture / "resume-build-reference-library").write_text("go")
        code_a, output_a, summary_a = self.finish(run_a, out_a)
        self.assertEqual(code_a, 0, output_a)


def received_env(entry):
    received = json.loads((Path(entry) / "build" / "received-env.json").read_text())
    received.pop("__CF_USER_TEXT_ENCODING", None)
    return received


@unittest.skipIf(shutil.which("cc") is None, "needs a C compiler to build fake compiler executables")
class CacheIdentity(Finalized):
    def setUp(self):
        super().setUp()
        self.cache = self.tmp / "shared cache"
        self.bin = self.tmp / "tool bin"
        self.bin.mkdir()
        self.runs = 0
        for name, version in (("fakecc1", "1.0"), ("fakecc2", "2.0")):
            self.compiler(self.bin / name, f"fakecc {version}")

    def compiler(self, path, banner):
        path.parent.mkdir(parents=True, exist_ok=True)
        source = self.tmp / f"{path.name}-{secrets_token()}.c"
        source.write_text("#include <stdio.h>\nint main(void) { puts(\"" + banner + "\"); return 0; }\n")
        temp = path.with_name(path.name + ".new")
        subprocess.run(["cc", "-o", str(temp), str(source)], check=True)
        os.replace(temp, path)
        return path

    def build(self, expect=0, path_prefix=None, **env_overrides):
        self.runs += 1
        out = self.tmp / f"run {self.runs}"
        env = dict(os.environ)
        for key in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR", "MAKEFLAGS"):
            env.pop(key, None)
        if path_prefix:
            env["PATH"] = os.pathsep.join([*[str(p) for p in path_prefix], env["PATH"]])
        env.update({k: str(v) for k, v in env_overrides.items()})
        (self.fixture / "scenario.json").write_text(json.dumps({}))
        argv = [sys.executable, str(RUN_PY), "--fixture", str(self.fixture), "--output-dir", str(out), "--build-cache", str(self.cache), *SMALL]
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300, env=env)
        self.assertEqual(result.returncode, expect, result.stdout)
        summary = json.loads((out / "launcher-summary.json").read_text())
        self.assert_finalized(summary, expect)
        stages = self.stages(summary)
        if stages["preflight"]["status"] == "failed":
            return stages
        return stages["build-reference-library"]

    def entries(self):
        root = self.cache / "reference"
        return sorted(p.name for p in root.iterdir()) if root.exists() else []

    def effective(self, stage):
        return stage["build_configuration"]["fingerprint"]["compiler"]["effective"]

    def assert_launcher_runs(self, stage, configure_cc, cc):
        launcher = stage["build_configuration"]["compiler_launcher"]
        self.assertEqual(configure_cc, launcher["configure_cc"])
        self.assertFalse(any(c.isspace() for c in configure_cc), "configure must receive a CC without whitespace")
        self.assertEqual(os.path.realpath(configure_cc), os.path.realpath(launcher["path"]))
        compiler = stage["build_configuration"]["fingerprint"]["compiler"]
        self.assertEqual(launcher["exec_argv"], compiler["launcher"]["exec_argv"])
        self.assertEqual(launcher["sha256"], compiler["launcher"]["sha256"])
        words = shlex.split(cc)
        self.assertEqual(launcher["exec_argv"][-len(compiler["arguments"]) - 1], os.path.abspath(compiler["effective"]["path"]))
        self.assertEqual(launcher["exec_argv"][len(launcher["exec_argv"]) - len(compiler["arguments"]):], words[len(words) - len(compiler["arguments"]):])

    def test_effective_build_inputs_select_the_cache_entry(self):
        cc1 = shlex.quote(str(self.bin / "fakecc1"))
        base = self.build(CC=cc1)
        self.assertEqual(base["cache"], "rebuilt (missing)")
        received = received_env(base["cache_entry"])
        self.assertEqual(received, base["build_configuration"]["environment"])
        self.assertEqual(base["build_configuration"]["settings"], {"CC": cc1})
        self.assertIn("fakecc 1.0", self.effective(base)["version"])
        again = self.build(CC=cc1)
        self.assertEqual(again["cache"], "reused")
        self.assertEqual(again["build_configuration"]["cache_key"], base["build_configuration"]["cache_key"])
        keys = {base["build_configuration"]["cache_key"]}
        for overrides in (
            {"CC": shlex.quote(str(self.bin / "fakecc2"))},
            {"CC": cc1, "CFLAGS": "-O1"},
            {"CC": cc1, "CPPFLAGS": "-DTPMS_TIMING_TEST=1"},
            {"CC": cc1, "LDFLAGS": "-Wl,-z,now"},
            {"CC": cc1, "PKG_CONFIG_PATH": str(self.tmp / "pkgconfig")},
            {"CC": cc1, "PKG_CONFIG_LIBDIR": str(self.tmp / "pkgconfig")},
            {"CC": f"{cc1} -m64"},
        ):
            stage = self.build(**overrides)
            self.assertEqual(stage["cache"], "rebuilt (missing)", overrides)
            key = stage["build_configuration"]["cache_key"]
            self.assertNotIn(key, keys, overrides)
            keys.add(key)
            received = received_env(stage["cache_entry"])
            self.assertEqual(received, stage["build_configuration"]["environment"], overrides)
            for name, value in overrides.items():
                if name == "CC":
                    self.assert_launcher_runs(stage, received["CC"], value)
                else:
                    self.assertEqual(received[name], str(value))
        self.compiler(self.bin / "fakecc1", "fakecc 1.1")
        upgraded = self.build(CC=cc1)
        self.assertEqual(upgraded["cache"], "rebuilt (missing)", "a changed compiler binary must not reuse the entry")
        self.assertIn("fakecc 1.1", self.effective(upgraded)["version"])

    def test_env_wrapper_identifies_the_compiler_it_runs(self):
        compiler = self.bin / "fakecc1"
        cc = f"env {shlex.quote(str(compiler))}"
        first = self.build(CC=cc)
        fingerprint = first["build_configuration"]["fingerprint"]["compiler"]
        self.assertEqual(fingerprint["form"], "env")
        self.assertEqual(os.path.basename(fingerprint["wrapper"]["realpath"]), "env")
        self.assertEqual(fingerprint["effective"]["realpath"], os.path.realpath(compiler))
        self.assertEqual(self.build(CC=cc)["cache"], "reused")
        self.compiler(compiler, "fakecc 9.9")
        second = self.build(CC=cc)
        self.assertEqual(second["cache"], "rebuilt (missing)", "a replaced compiler behind env must not reuse the old entry")
        self.assertNotEqual(second["build_configuration"]["cache_key"], first["build_configuration"]["cache_key"])
        self.assertIn("fakecc 9.9", self.effective(second)["version"])
        assigned = self.build(CC=f"env LC_ALL=C {shlex.quote(str(compiler))} -O2")
        self.assertEqual(assigned["build_configuration"]["fingerprint"]["compiler"]["env_assignments"], {"LC_ALL": "C"})
        self.assertEqual(assigned["build_configuration"]["fingerprint"]["compiler"]["arguments"], ["-O2"])

    def test_env_wrapper_resolves_through_path_like_the_build(self):
        first_dir, second_dir = self.tmp / "path one", self.tmp / "path two"
        self.compiler(first_dir / "fakecc", "fakecc from path one")
        self.compiler(second_dir / "fakecc", "fakecc from path two")
        plain_one = self.build(CC="fakecc", path_prefix=[first_dir])
        self.assertEqual(self.build(CC="fakecc", path_prefix=[first_dir])["cache"], "reused")
        plain_two = self.build(CC="fakecc", path_prefix=[second_dir])
        self.assertEqual(plain_two["cache"], "rebuilt (missing)")
        self.assertIn("path two", self.effective(plain_two)["version"])
        env_one = self.build(CC="env fakecc", path_prefix=[first_dir])
        env_two = self.build(CC="env fakecc", path_prefix=[second_dir])
        self.assertEqual(env_two["cache"], "rebuilt (missing)")
        self.assertNotEqual(env_one["build_configuration"]["cache_key"], env_two["build_configuration"]["cache_key"])
        assigned = self.build(CC=f"env PATH={shlex.quote(str(second_dir))} fakecc", path_prefix=[first_dir])
        self.assertIn("path two", self.effective(assigned)["version"], "env PATH= assignments select the compiler like env does")
        self.assertNotEqual(plain_one["build_configuration"]["cache_key"], plain_two["build_configuration"]["cache_key"])

    def test_ccache_wrapper_identifies_the_compiler_it_runs(self):
        tools = self.tmp / "ccache bin"
        ccache = self.compiler(tools / "ccache", "ccache version 4.99 (fake)")
        real_dir = self.tmp / "real compilers"
        self.compiler(real_dir / "fakecc", "fakecc real 1")
        masquerade = self.tmp / "masquerade"
        masquerade.mkdir()
        (masquerade / "fakecc").symlink_to(ccache)
        first = self.build(CC="ccache fakecc", path_prefix=[tools, masquerade, real_dir])
        compiler = first["build_configuration"]["fingerprint"]["compiler"]
        self.assertEqual(compiler["form"], "ccache")
        self.assertEqual(compiler["wrapper"]["realpath"], os.path.realpath(ccache))
        self.assertEqual(compiler["effective"]["realpath"], os.path.realpath(real_dir / "fakecc"), "ccache skips its own masquerade link")
        self.assertEqual(self.build(CC="ccache fakecc", path_prefix=[tools, masquerade, real_dir])["cache"], "reused")
        self.compiler(real_dir / "fakecc", "fakecc real 2")
        second = self.build(CC="ccache fakecc", path_prefix=[tools, masquerade, real_dir])
        self.assertEqual(second["cache"], "rebuilt (missing)")
        self.assertIn("real 2", self.effective(second)["version"])

    def test_unsupported_compiler_forms_are_rejected_without_publishing(self):
        compiler = shlex.quote(str(self.bin / "fakecc1"))
        tools = self.tmp / "wrappers"
        ccache = self.compiler(tools / "ccache", "ccache version 4.99 (fake)")
        self.compiler(tools / "distcc", "distcc 3.4 (fake)")
        masquerade = self.tmp / "masquerade"
        masquerade.mkdir()
        (masquerade / "fakecc").symlink_to(ccache)
        script = self.tmp / "script cc"
        script.write_text(f"#!/bin/sh\nexec {compiler} \"$@\"\n")
        script.chmod(0o755)
        cases = [
            ({"CC": f"distcc {compiler}"}, None, "is not supported"),
            ({"CC": f"{compiler} extra-word"}, None, "non-option words"),
            ({"CC": f"env -i {compiler}"}, None, "env option"),
            ({"CC": f"env ccache {compiler}"}, [tools], "nested CC wrappers"),
            ({"CC": "./fakecc"}, None, "relative path"),
            ({"CC": "fakecc"}, [masquerade], "masquerading"),
            ({"CC": shlex.quote(str(script))}, None, "is a script"),
            ({"CC": str(self.bin / "fakecc1")}, None, "quote paths that contain spaces"),
            ({"CC": "env"}, None, "no compiler"),
        ]
        for overrides, prefix, needle in cases:
            with self.subTest(cc=overrides["CC"]):
                before = self.entries()
                stages = self.build(expect=4, path_prefix=prefix, **overrides)
                self.assertEqual(stages["preflight"]["status"], "failed")
                self.assertIn(needle, stages["preflight"]["detail"])
                self.assertIn("unsupported compiler configuration", stages["preflight"]["detail"])
                for name in ("build-rust-library", "build-reference-library", "build-timing-tool"):
                    self.assertEqual(stages[name]["status"], "skipped", name)
                    self.assertEqual(stages[name]["commands"], [], "nothing may be compiled")
                self.assertEqual(self.entries(), before, "no cache entry may be published")
        self.assertFalse((self.fixture / "reference-builds.log").exists())

    def test_normalized_settings_are_not_passed_and_do_not_split_the_cache(self):
        cc1 = shlex.quote(str(self.bin / "fakecc1"))
        base = self.build(CC=cc1)
        noisy = self.build(CC=cc1, MAKEFLAGS="-j1", LIBS="-lbogus", CPATH="/nowhere")
        self.assertEqual(noisy["cache"], "reused")
        self.assertEqual(noisy["build_configuration"]["normalized_away"], ["CPATH", "LIBS", "MAKEFLAGS"])
        rebuilt = self.build(CC=cc1, MAKEFLAGS="-j1")
        received = received_env(rebuilt["cache_entry"])
        self.assertNotIn("MAKEFLAGS", received)
        self.assertEqual(base["build_configuration"]["cache_key"], rebuilt["build_configuration"]["cache_key"])

    def test_missing_or_corrupted_cache_artifacts_are_rebuilt(self):
        cc1 = shlex.quote(str(self.bin / "fakecc1"))
        base = self.build(CC=cc1)
        entry = Path(base["cache_entry"])
        library = entry / "build" / "src" / ".libs" / "libtpms.so"
        library.unlink()
        self.assertEqual(self.build(CC=cc1)["cache"], "rebuilt (library missing)")
        library.write_text("bit rot\n")
        self.assertEqual(self.build(CC=cc1)["cache"], "rebuilt (library hash differs from its stamp)")
        (entry / "source" / "include" / "libtpms" / "tpm_library.h").write_text("tampered\n")
        self.assertEqual(self.build(CC=cc1)["cache"], "rebuilt (headers differ from their stamp)")
        (entry / "build-stamp.json").write_text("{not json")
        self.assertEqual(self.build(CC=cc1)["cache"], "rebuilt (stamp missing or unreadable)")
        self.assertEqual(self.build(CC=cc1)["cache"], "reused")


class ReportFinalization(Finalized):
    def test_malformed_report_artifacts_fail_and_finalize(self):
        for malformed, needle in (("json", "not valid JSON"), ("structure", "is not one of"), ("list", "not a JSON object")):
            with self.subTest(malformed=malformed):
                out = self.tmp / f"out {malformed}"
                self.scenario(report={"malformed": malformed})
                code, output, summary = self.launch(out=out)
                self.assertEqual(code, 4, output)
                self.assert_finalized(summary, 4)
                report = self.stages(summary)["report"]
                self.assertEqual(report["status"], "failed")
                self.assertIn(needle, report["detail"])
                self.assertIsNone(summary["report"])
                self.assertNotIn("Traceback", output)
                self.assertIn("report: none generated", output)

    def test_report_artifacts_disappearing_or_unreadable_before_validation_fail(self):
        actions = ["delete-report"] + ([] if os.geteuid() == 0 else ["chmod-report"])
        for action in actions:
            with self.subTest(action=action):
                out = self.tmp / f"out {action}"
                self.scenario(tamper_at={"point": "after-command:report", "action": action})
                code, output, summary = self.launch(out=out)
                self.assertEqual(code, 4, output)
                self.assert_finalized(summary, 4)
                self.assertIn("report.json is unreadable", self.stages(summary)["report"]["detail"])
                self.assertIsNone(summary["report"])

    def test_sigint_immediately_before_report_start(self):
        self.scenario(signal_at="before-start:report")
        code, output, summary = self.launch()
        self.assertEqual(code, 3, output)
        self.assert_finalized(summary, 3)
        report = self.stages(summary)["report"]
        self.assertEqual(report["status"], "interrupted")
        self.assertEqual(report["commands"], [])
        self.assertIsNone(summary["report"])
        self.assertNotIn("Traceback", output)

    def test_sigint_during_report_processing(self):
        self.scenario(signal_at="after-command:report")
        code, output, summary = self.launch()
        self.assertEqual(code, 3, output)
        self.assert_finalized(summary, 3)
        self.assertEqual(self.stages(summary)["report"]["status"], "interrupted")
        self.assertIsNone(summary["report"])

    def test_sigint_during_report_processing_after_a_failure_stays_failed(self):
        self.scenario(**{"search-reference": {"exit": 4}}, signal_at="after-command:report")
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assert_finalized(summary, 4)
        self.assertEqual(self.stages(summary)["report"]["status"], "interrupted")

    def test_failed_report_followed_by_sigint_stays_failed(self):
        self.scenario(report={"exit": 4}, signal_at="after-command:report")
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assert_finalized(summary, 4)
        report = self.stages(summary)["report"]
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["exit_code"], 4)
        self.assertFalse(report["commands"][0]["cancelled_by_signal"])
        self.assertIsNone(summary["report"])
        self.assertIn("interrupted by SIGINT", " ".join(summary["explanations"]))

    def test_invalid_report_followed_by_sigint_stays_failed(self):
        self.scenario(report={"malformed": "json"}, signal_at="after-command:report")
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assert_finalized(summary, 4)
        self.assertIn("not valid JSON", self.stages(summary)["report"]["detail"])

    def test_interrupting_an_active_report_command_cleans_up(self):
        self.scenario(hang="report")
        argv = [sys.executable, str(RUN_PY), "--fixture", str(self.fixture), "--output-dir", str(self.out), *SMALL]
        launcher = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_for(lambda: (self.fixture / "hang.json").exists(), "the report command to block", launcher)
        pids = json.loads((self.fixture / "hang.json").read_text())
        launcher.send_signal(signal.SIGINT)
        output, _ = launcher.communicate(timeout=60)
        self.assertEqual(launcher.returncode, 3, output)
        summary = json.loads((self.out / "launcher-summary.json").read_text())
        self.assert_finalized(summary, 3)
        self.assertEqual(self.stages(summary)["report"]["status"], "interrupted")
        for pid in (pids["tool"], pids["grandchild"]):
            wait_for(lambda: not alive(pid), f"process {pid} to exit", timeout=10)

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_unwritable_evidence_is_reported_without_masking_the_outcome(self):
        self.scenario(tamper_at={"point": "after-command:report", "action": "readonly-evidence"})
        try:
            code, output, summary = self.launch()
        finally:
            for path in (self.out, self.out / "logs"):
                if path.exists():
                    os.chmod(path, 0o755)
        self.assertEqual(code, 4, output)
        self.assertIn("cannot write launcher summary", output)
        self.assertIn("the pipeline outcome was completed", output)
        self.assertNotIn("Traceback", output)


class SignalAfterCompletion(Finalized):
    def test_failed_search_followed_by_sigint_stays_failed(self):
        self.scenario(**{"search-rust": {"exit": 4}}, signal_at="after-command:search-rust")
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assert_finalized(summary, 4)
        stages = self.stages(summary)
        self.assertEqual(stages["search-rust"]["status"], "failed")
        self.assertFalse(stages["search-rust"]["commands"][0]["cancelled_by_signal"])
        self.assert_skipped(summary, ["search-reference", "verify", "replay", "report"], "interrupted by SIGINT")

    def test_completed_search_followed_by_sigint_is_incomplete(self):
        self.scenario(signal_at="after-command:search-rust")
        code, output, summary = self.launch()
        self.assertEqual(code, 3, output)
        self.assert_finalized(summary, 3)
        self.assertEqual(self.stages(summary)["search-rust"]["status"], "interrupted")

    def test_incomplete_verification_followed_by_sigint_is_incomplete(self):
        self.scenario(verify={"exit": 3}, signal_at="after-command:verify")
        code, output, summary = self.launch()
        self.assertEqual(code, 3, output)
        self.assert_finalized(summary, 3)

    def test_failed_verification_followed_by_sigint_stays_failed(self):
        self.scenario(verify={"exit": 4}, signal_at="after-command:verify")
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assert_finalized(summary, 4)
        self.assertEqual(self.stages(summary)["verify"]["status"], "failed")

    def test_failed_build_followed_by_sigint_stays_failed(self):
        self.scenario(build_fail="rust-library", signal_at="after-command:build-rust-library")
        code, output, summary = self.launch()
        self.assertEqual(code, 4, output)
        self.assert_finalized(summary, 4)
        self.assertEqual(self.stages(summary)["build-rust-library"]["status"], "failed")

    def test_cancelled_search_is_incomplete_although_its_process_exits_nonzero(self):
        self.scenario(hang="search-rust")
        argv = [sys.executable, str(RUN_PY), "--fixture", str(self.fixture), "--output-dir", str(self.out), *SMALL]
        launcher = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_for(lambda: (self.fixture / "hang.json").exists(), "the search to block", launcher)
        pids = json.loads((self.fixture / "hang.json").read_text())
        launcher.send_signal(signal.SIGINT)
        output, _ = launcher.communicate(timeout=60)
        self.assertEqual(launcher.returncode, 3, output)
        summary = json.loads((self.out / "launcher-summary.json").read_text())
        self.assert_finalized(summary, 3)
        search = self.stages(summary)["search-rust"]
        self.assertEqual(search["status"], "interrupted")
        self.assertTrue(search["commands"][0]["cancelled_by_signal"])
        self.assertNotEqual(search["commands"][0]["exit"], 0)
        for pid in (pids["tool"], pids["grandchild"]):
            wait_for(lambda: not alive(pid), f"process {pid} to exit", timeout=10)


class SignalAfterWait(Finalized):
    def launch_after_wait(self, stage, **plan):
        self.scenario(**plan, signal_at=f"after-wait:{stage}")
        code, output, summary = self.launch()
        self.assert_finalized(summary, code)
        command = self.stages(summary)[stage]["commands"][-1]
        return code, output, summary, command

    def assert_observed_failure(self, stage, **plan):
        code, output, summary, command = self.launch_after_wait(stage, **plan)
        self.assertEqual(code, 4, output)
        self.assertEqual(summary["aggregate_outcome"], "failed")
        self.assertEqual(self.stages(summary)[stage]["status"], "failed")
        self.assertFalse(command["cancelled_by_signal"], "the command had already exited when the signal arrived")
        self.assertTrue(command.get("signal_after_exit"))
        self.assertIn("received SIGINT", output)
        return summary, command

    def test_failed_search_signalled_after_wait_stays_failed(self):
        summary, command = self.assert_observed_failure("search-rust", **{"search-rust": {"exit": 4}})
        self.assertEqual(command["exit"], 4)
        self.assertEqual(self.stages(summary)["search-rust"]["exit_code"], 4)
        self.assert_skipped(summary, ["search-reference", "verify", "replay", "report"], "interrupted by SIGINT")

    def test_failed_verification_signalled_after_wait_stays_failed(self):
        summary, command = self.assert_observed_failure("verify", verify={"exit": 4})
        self.assertEqual(command["exit"], 4)

    def test_failed_build_signalled_after_wait_stays_failed(self):
        summary, command = self.assert_observed_failure("build-rust-library", build_fail="rust-library")
        self.assertEqual(command["exit"], 1)

    def test_failed_report_signalled_after_wait_stays_failed(self):
        summary, command = self.assert_observed_failure("report", report={"exit": 4})
        self.assertEqual(command["exit"], 4)
        self.assertIsNone(summary["report"])

    def test_successful_command_signalled_after_wait_is_incomplete(self):
        code, output, summary, command = self.launch_after_wait("search-rust")
        self.assertEqual(code, 3, output)
        self.assertEqual(command["exit"], 0)
        self.assertFalse(command["cancelled_by_signal"])
        self.assertTrue(command.get("signal_after_exit"))
        self.assertEqual(self.stages(summary)["search-rust"]["status"], "interrupted")

    def test_exited_child_with_surviving_descendant_is_cleaned_up(self):
        code, output, summary, command = self.launch_after_wait("search-rust", leak="search-rust")
        leaked = json.loads((self.fixture / "leak.json").read_text())["leaked"]
        self.assertEqual(code, 4, output)
        self.assertEqual(command["exit"], 0)
        self.assertFalse(command["cancelled_by_signal"])
        if sys.platform.startswith("linux"):
            self.assertIn(leaked, command["leftover_processes_stopped"])
        else:
            self.assertTrue(command["leftover_processes_stopped"])
        self.assertEqual(self.stages(summary)["search-rust"]["status"], "failed")
        wait_for(lambda: not alive(leaked), f"leaked process {leaked} to exit", timeout=10)


class ExitDetection(unittest.TestCase):
    def setUp(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("timing_launcher", RUN_PY)
        self.run_py = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.run_py)

    def test_running_child_is_not_exited(self):
        reader, writer = os.pipe()
        child = subprocess.Popen([sys.executable, "-c", "import os,sys; os.read(int(sys.argv[1]), 1)", str(reader)], pass_fds=(reader,))
        try:
            self.assertFalse(self.run_py.main_child_exited(child))
        finally:
            os.write(writer, b"x")
            child.wait()
            os.close(reader)
            os.close(writer)

    def test_unreaped_child_counts_as_exited(self):
        child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(4)"])
        os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
        self.assertIsNone(child.returncode)
        self.assertTrue(self.run_py.main_child_exited(child))
        self.assertEqual(child.wait(), 4)

    def test_reaped_child_without_recorded_status_counts_as_exited(self):
        child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(4)"])
        os.waitpid(child.pid, 0)
        self.assertIsNone(child.returncode)
        self.assertTrue(self.run_py.main_child_exited(child))
        child.returncode = 4


@unittest.skipUnless(all(shutil.which(tool) for tool in ("cc", "make", "autoreconf")), "needs cc, make and autoreconf")
class CompilerExecution(Finalized):
    def setUp(self):
        super().setUp()
        self.cache = self.tmp / "shared cache"
        self.real_cc = shutil.which("cc")
        self.compiler = self.tmp / "real compiler dir" / "cc"
        self.compiler.parent.mkdir()
        self.compiler.symlink_to(self.real_cc)
        self.markers = self.tmp / "marker include dir"
        self.markers.mkdir()
        (self.markers / "tpms_cc_marker.h").write_text('#define TPMS_CC_MARKER "env-marker:present"\n')
        self.runs = 0

    def build(self, cc, expect=0):
        self.runs += 1
        out = self.tmp / f"run {self.runs}"
        env = dict(os.environ)
        for key in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS"):
            env.pop(key, None)
        env["CC"] = cc
        for name in ("cc-probe-rust-library.json", "cc-probe-timing-tool.json", "cc-probe-worker.json"):
            (self.fixture / name).unlink(missing_ok=True)
        self.scenario(reference_source="mini-libtpms", compile_probe=True)
        argv = [sys.executable, str(RUN_PY), "--fixture", str(self.fixture), "--output-dir", str(out), "--build-cache", str(self.cache), *SMALL]
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600, env=env)
        summary = json.loads((out / "launcher-summary.json").read_text())
        stage = self.stages(summary)["build-reference-library"]
        self.assertEqual(result.returncode, expect, result.stdout + "".join(Path(s["log"]).read_text() for s in summary["stages"] if s.get("log") and Path(s["log"]).exists()))
        self.assert_finalized(summary, expect)
        return summary, stage

    def library(self, summary):
        return Path(summary["artifacts"]["reference_library"]["path"]).read_bytes()

    def assert_compiled_everywhere(self, summary, stage, option, marker):
        names = [Path(c["argv"][0]).name for c in stage["commands"]]
        if stage["cache"] != "reused":
            self.assertEqual(names, ["sh", "configure", "make"])
            self.assertTrue(all(c["exit"] == 0 for c in stage["commands"]))
        library = self.library(summary)
        self.assertIn(f"cc-option:{option}".encode(), library, "the CC option reached the compiler during make")
        self.assertIn(marker.encode(), library)
        launcher = stage["build_configuration"]["compiler_launcher"]
        self.assertEqual(stage["build_configuration"]["environment"]["CC"], launcher["configure_cc"])
        for name in ("rust-library", "timing-tool", "worker"):
            probe = json.loads((self.fixture / f"cc-probe-{name}.json").read_text())
            self.assertEqual(probe["exit"], 0, probe)
            self.assertEqual(os.path.realpath(probe["cc"]), os.path.realpath(launcher["path"]), name)

    def test_quoted_compiler_path_works_through_configure_and_make(self):
        quoted = shlex.quote(str(self.compiler))
        summary, stage = self.build(f"{quoted} -DTPMS_CC_OPTION=plain")
        self.assertEqual(stage["cache"], "rebuilt (missing)")
        self.assert_compiled_everywhere(summary, stage, "plain", "env-marker:absent")
        self.assertEqual(stage["build_configuration"]["compiler_launcher"]["exec_argv"], [str(self.compiler), "-DTPMS_CC_OPTION=plain"])
        again_summary, again = self.build(f"{quoted} -DTPMS_CC_OPTION=plain")
        self.assertEqual(again["cache"], "reused")
        self.assertEqual(again["build_configuration"]["cache_key"], stage["build_configuration"]["cache_key"])
        self.assertEqual(again["build_configuration"]["compiler_launcher"]["cache"], "reused")
        self.assert_compiled_everywhere(again_summary, again, "plain", "env-marker:absent")
        script = Path(stage["build_configuration"]["compiler_launcher"]["path"])
        os.chmod(script.parent, 0o755)
        os.chmod(script, 0o755)
        script.write_text("#!/bin/sh\nexec /bin/false\n")
        os.chmod(script.parent, 0o555)
        repaired_summary, repaired = self.build(f"{quoted} -DTPMS_CC_OPTION=plain")
        preflight = self.stages(repaired_summary)["preflight"]["compiler"]["launcher"]
        self.assertEqual(preflight["cache"], "created (content differs from its digest)", "preflight replaces a tampered launcher")
        self.assertEqual(repaired["build_configuration"]["compiler_launcher"]["sha256"], preflight["sha256"])
        self.assertEqual(repaired["cache"], "reused")
        self.assert_compiled_everywhere(repaired_summary, repaired, "plain", "env-marker:absent")
        self.assertEqual([p.name for p in script.parent.parent.iterdir() if p.name.startswith(".")], [])

    def test_env_form_with_quoted_paths_forwards_assignments_and_options(self):
        cc = f"env CPATH={shlex.quote(str(self.markers))} {shlex.quote(str(self.compiler))} -DTPMS_CC_OPTION=env_form"
        summary, stage = self.build(cc)
        self.assertEqual(stage["cache"], "rebuilt (missing)")
        self.assert_compiled_everywhere(summary, stage, "env_form", "env-marker:present")
        compiler = stage["build_configuration"]["fingerprint"]["compiler"]
        self.assertEqual(compiler["form"], "env")
        self.assertEqual(compiler["env_assignments"], {"CPATH": str(self.markers)})
        self.assertEqual(stage["build_configuration"]["compiler_launcher"]["exec_argv"][1:],
                         [f"CPATH={self.markers}", str(self.compiler), "-DTPMS_CC_OPTION=env_form"])

    def test_changing_the_effective_compiler_selects_another_entry(self):
        quoted = shlex.quote(str(self.compiler))
        first_summary, first = self.build(f"{quoted} -DTPMS_CC_OPTION=one")
        other = self.tmp / "other compiler dir" / "cc"
        other.parent.mkdir()
        source = self.tmp / "forward.c"
        source.write_text(
            "#include <unistd.h>\nint main(int argc, char **argv) { (void)argc; argv[0] = " + json.dumps(self.real_cc) +
            "; execv(argv[0], argv); return 127; }\n"
        )
        subprocess.run(["cc", "-o", str(other), str(source)], check=True)
        second_summary, second = self.build(f"{shlex.quote(str(other))} -DTPMS_CC_OPTION=one")
        self.assertEqual(second["cache"], "rebuilt (missing)")
        self.assertNotEqual(second["build_configuration"]["cache_key"], first["build_configuration"]["cache_key"])
        self.assertEqual(second["build_configuration"]["compiler_launcher"]["exec_argv"], [str(other), "-DTPMS_CC_OPTION=one"])
        self.assertIn(b"cc-option:one", self.library(second_summary))
        _, option_changed = self.build(f"{quoted} -DTPMS_CC_OPTION=two")
        self.assertEqual(option_changed["cache"], "rebuilt (missing)")


class Interruption(LauncherCase):
    def test_sigint_stops_children_and_preserves_partial_evidence(self):
        self.scenario(hang="verify")
        argv = [sys.executable, str(RUN_PY), "--fixture", str(self.fixture), "--output-dir", str(self.out), *SMALL]
        launcher = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        marker = self.fixture / "hang.json"
        deadline = time.monotonic() + 120
        while not marker.exists():
            self.assertIsNone(launcher.poll(), "launcher ended before the verify stage blocked")
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        pids = json.loads(marker.read_text())
        launcher.send_signal(signal.SIGINT)
        output, _ = launcher.communicate(timeout=60)
        self.assertEqual(launcher.returncode, 3, output)
        for pid in (pids["tool"], pids["grandchild"]):
            deadline = time.monotonic() + 10
            while alive(pid) and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertFalse(alive(pid), f"process {pid} survived the launcher")
        summary = json.loads((self.out / "launcher-summary.json").read_text())
        self.assertEqual(summary["aggregate_outcome"], "incomplete")
        stages = {s["name"]: s for s in summary["stages"]}
        self.assertEqual(stages["verify"]["status"], "interrupted")
        self.assertEqual(stages["search-rust"]["status"], "completed")
        self.assert_skipped(summary, ["replay", "report"], "interrupted by SIGINT")
        self.assertTrue(Path(stages["verify"]["log"]).is_file())
        partial = Path(stages["verify"]["run_dirs"][0])
        self.assertTrue((partial / "run.json").is_file(), "partial verify evidence is preserved")
        self.assertIn("interrupted by SIGINT", " ".join(summary["explanations"]))

    def test_interruption_after_a_failure_stays_failed(self):
        self.scenario(**{"search-reference": {"exit": 4}}, hang="report")
        argv = [sys.executable, str(RUN_PY), "--fixture", str(self.fixture), "--output-dir", str(self.out), *SMALL]
        launcher = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        marker = self.fixture / "hang.json"
        deadline = time.monotonic() + 120
        while not marker.exists():
            self.assertIsNone(launcher.poll())
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        launcher.send_signal(signal.SIGTERM)
        output, _ = launcher.communicate(timeout=60)
        self.assertEqual(launcher.returncode, 4, output)
        summary = json.loads((self.out / "launcher-summary.json").read_text())
        self.assertEqual(summary["aggregate_outcome"], "failed")


if __name__ == "__main__":
    unittest.main()
