"""Microsoft adapter: selection, per-scenario supervision and strict reporting.

Supervision tests use fake tester and bridge processes driven by a plan file,
so they need no .NET, Docker, TPM or real multi-minute timeouts.
"""
import copy
from html import escape
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "validation" / "adapters" / "microsoft_scenarios.py"
spec = importlib.util.spec_from_file_location("microsoft_tss", HELPER)
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)
MANIFEST = ms.load_manifest(ROOT / "validation" / "adapters" / "microsoft-tss.manifest.json")
# The pinned checkout in the validation cache (Docker), or the host work directory.
UPSTREAM = next((p for p in (Path("/work/cache/sources/microsoft-tss"),
                             ROOT.parent / "target/external-validation/cache/sources/microsoft-tss")
                 if (p / ".git").is_dir()), Path("/nonexistent"))
FIXTURES = ROOT / "tests" / "fixtures" / "microsoft"
sys.path.insert(0, str(ROOT))
from validation import results as schema  # noqa: E402
from validation.collectors import microsoft as collector  # noqa: E402

# Fake upstream tester: argv is [... -device tcp -address A NAME] or [-tests].
FAKE_TESTER = textwrap.dedent(r'''
    import json, os, subprocess, sys, time
    from html import escape
    plan = json.loads(open(os.environ["FAKE_PLAN"]).read())
    name = sys.argv[-1]
    if name in ("-tests", "-profiles"):
        print(plan["discovery"][name]); sys.exit(0)
    behavior = plan["tester"].get(name, "pass")
    record = open(os.environ["FAKE_EVENTS"], "a")
    record.write("tester %d %s tmp=%s\n" % (os.getpid(), name, os.environ.get("TMPDIR")))
    record.flush()
    selected = "OtherScenario" if behavior == "wrong" else name
    print("TPM configuration:\nECC curves: NISTP256\n")
    print("Test Routines in current test run:\n" + selected + "\n", flush=True)

    def report(rows, title="All Tests PASSED", index=0):
        header = ["Test Name", "Succeeded", "Failed", "Aborted", "Average Time, s"]
        table = "<table>" + "".join("<tr>" + "".join(
            "<td><h3>" + escape(str(c)) + "</h3></td>" for c in row) + "</tr>"
            for row in [header] + rows) + "</table>"
        path = "TpmTests_%d.Report.html" % index
        open(path, "w").write("<body><h1>TPM Test Report</h1><h1>" + title + "</h1>"
                              + table + "</body>")
        return path

    infra = ["LibTesterInfra", 1, 0, 0, 0]
    if behavior.endswith("-then-hang"):
        kind = behavior[:-len("-then-hang")]
        if kind == "pass":
            report([infra, [name, 1, 0, 0, 0]])
        elif kind == "fail":
            print("Exception System.ArgumentException: AuthSession: boom")
            print("To reproduce use option: -seed d103da62cc26888b", flush=True)
            report([infra, [name, 0, 1, 0, 0]], "Some tests FAILED")
        elif kind == "malformed":
            report([infra, [name, "unknown", 0, 0, 0]])
        # The report file is closed; tell the test it may signal now.
        record.write("reported %d %s\n" % (os.getpid(), name)); record.flush()
        time.sleep(600)
    if behavior in ("hang", "orphan"):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        record.write("child %d %s\n" % (child.pid, name)); record.flush()
    if behavior == "hang":
        time.sleep(600)
    elif behavior == "fail":
        print("Exception System.ArgumentException: AuthSession: Attempt to construct "
              "from parametrized non-session handle")
        print("To reproduce use option: -seed d103da62cc26888b")
        report([infra, [name, 0, 1, 0, 0]], "Some tests FAILED")
    elif behavior == "aborted":
        report([infra, [name, 1, 0, 1, 0]], "All Tests PASSED but some were ABORTED")
    elif behavior == "infra-failed":
        report([["LibTesterInfra", 0, 1, 0, 0], [name, 1, 0, 0, 0]])
    elif behavior == "skip":
        print(name + " skipped")
        report([infra, [name, 1, 0, 0, 0]])
    elif behavior == "infra-only":
        report([infra])
    elif behavior == "no-report":
        pass
    elif behavior == "malformed":
        report([infra, [name, "unknown", 0, 0, 0]])
    elif behavior == "duplicate":
        report([infra, [name, 1, 0, 0, 0], [name, 1, 0, 0, 0]])
    elif behavior == "two-reports":
        report([infra, [name, 1, 0, 0, 0]]); report([infra, [name, 1, 0, 0, 0]], index=1)
    elif behavior == "stale":
        path = report([infra, [name, 1, 0, 0, 0]])
        os.utime(path, (time.time() - 3600, time.time() - 3600))
    elif behavior == "wrong":
        report([infra, ["OtherScenario", 1, 0, 0, 0]])
    elif behavior == "extra-row":
        report([infra, [name, 1, 0, 0, 0], ["TestRandom2", 1, 0, 0, 0]])
    elif behavior == "no-title":
        report([infra, [name, 1, 0, 0, 0]], "Something else")
    elif behavior == "abort":
        print("Unhandled exception. System.ArgumentOutOfRangeException: path too long", flush=True)
        os.abort()
    elif behavior == "slow":
        time.sleep(1.5); report([infra, [name, 1, 0, 0, 0]])
    elif behavior == "exit3":
        report([infra, [name, 1, 0, 0, 0]]); sys.exit(3)
    else:
        report([infra, [name, 1, 0, 0, 0]])
''')

# Fake bridge: publishes readiness like bridge.py and logs its lifetime.
FAKE_BRIDGE = textwrap.dedent(r'''
    import json, os, signal, sys, time
    from pathlib import Path
    ready = Path(sys.argv[sys.argv.index("--ready-file") + 1])
    scenario = ready.parent.name.split("-", 1)[1]
    plan = json.loads(open(os.environ["FAKE_PLAN"]).read())
    behavior = plan["bridge"].get(scenario, "ok")
    events = open(os.environ["FAKE_EVENTS"], "a")
    if behavior == "fail-start":
        print("bridge: cannot bind", file=sys.stderr); sys.exit(1)
    def stop(signum, frame):
        events.write("bridge-stop %d %s\n" % (os.getpid(), scenario)); events.flush()
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    events.write("bridge-start %d %s\n" % (os.getpid(), scenario)); events.flush()
    if behavior == "never-ready":
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        events.write("bridge-child %d %s\n" % (child.pid, scenario)); events.flush()
        while True:
            time.sleep(1)
    tmp = ready.with_name(ready.name + ".tmp")
    tmp.write_text(json.dumps({"pid": os.getpid()})); tmp.replace(ready)
    print("libtpms bridge ready: fake", flush=True)
    if behavior == "unsupported":
        print("bridge: unsupported simulator opcode 30", file=sys.stderr, flush=True)
    if behavior == "trace":
        print("bridge: command 0x00000176 response 0x00000903", file=sys.stderr, flush=True)
    if behavior == "die":
        time.sleep(0.5); sys.exit(7)
    while True:
        time.sleep(1)
''')


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); ask ps for its state.
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                           capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


def wait_dead(pid, seconds=3):
    deadline = time.monotonic() + seconds
    while alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not alive(pid)


class Fixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "tester.py").write_text(FAKE_TESTER)
        (self.root / "bridge.py").write_text(FAKE_BRIDGE)
        self.events = self.root / "events"
        self.events.touch()
        self.results = self.root / "results" / "microsoft-tss.run"
        self.results.parent.mkdir()

    def plan(self, tester=None, bridge=None, discovery=None):
        (self.root / "plan.json").write_text(json.dumps({
            "tester": tester or {}, "bridge": bridge or {}, "discovery": discovery or {}}))

    def argv(self, selection, timeout=30, extra=()):
        return [sys.executable, str(HELPER), "run", "--results", str(self.results),
                "--revision", MANIFEST["revision"], "--filter", selection,
                "--scenario-timeout", str(timeout), "--kill-grace", "1", "--skip-discovery",
                "--dotnet-command", json.dumps([sys.executable, str(self.root / "tester.py")]),
                "--bridge-command", json.dumps([sys.executable, str(self.root / "bridge.py")]),
                *extra]

    def env(self):
        return dict(os.environ, FAKE_PLAN=str(self.root / "plan.json"),
                    FAKE_EVENTS=str(self.events))

    def run_helper(self, selection, timeout=30, extra=()):
        result = subprocess.run(self.argv(selection, timeout, extra), env=self.env(),
                                capture_output=True, text=True, timeout=120)
        self.addCleanup(self.kill_leftovers, self.events)
        return result

    def kill_leftovers(self, events=None):
        # Bound per fixture: subtests call setUp() again and replace self.events.
        events = events or self.events
        if not events.exists():
            return
        for line in events.read_text().splitlines():
            pid = int(line.split()[1])
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def summary(self):
        return json.loads((self.results / "summary.json").read_text())

    def statuses(self):
        return {r["name"]: r["status"] for r in self.summary()["scenarios"]}

    def scenario(self, name):
        return next(r for r in self.summary()["scenarios"] if r["name"] == name)

    def pids(self, kind):
        return [(int(line.split()[1]), line.split()[2])
                for line in self.events.read_text().splitlines() if line.startswith(kind + " ")]


class SelectionTests(unittest.TestCase):
    def resolve(self, expression, manifest=MANIFEST):
        return ms.resolve(manifest, expression)["order"]

    def test_default_is_the_reviewed_all_profile(self):
        self.assertEqual(len(MANIFEST["expected_all"]), 12)
        self.assertEqual(self.resolve(""), MANIFEST["expected_all"])
        self.assertEqual(self.resolve("All"), MANIFEST["expected_all"])
        self.assertEqual(self.resolve("all"), MANIFEST["expected_all"])

    def test_exact_names_keep_explicit_order_after_profiles(self):
        self.assertEqual(self.resolve("TestSerialization TestRandom"),
                         ["TestSerialization", "TestRandom"])
        # Upstream documents that the "Test" prefix may be dropped.
        self.assertEqual(self.resolve("random"), ["TestRandom"])
        self.assertEqual(self.resolve("TestVendorSpecific,Infra"),
                         ["TestAutomaticAuth", "TestSerialization", "TestVendorSpecific"])

    def test_profiles_and_categories_expand_and_deduplicate(self):
        selection = ms.resolve(MANIFEST, "Misc, TestRandom random All")
        self.assertEqual(selection["order"], MANIFEST["expected_all"])
        self.assertEqual(selection["duplicates_removed"].count("TestRandom"), 3)
        self.assertEqual(self.resolve("Ecc"), ["EcdhSample"])
        self.assertEqual(self.resolve("Duplication"),
                         ["DuplicateImportRsaSample", "ExternalKeyImportSample"])
        self.assertNotIn("TestRandom", self.resolve("TbsAdmin"))
        self.assertIn("TestFailureMode", self.resolve("TbsAdmin"))

    def test_profile_filters_follow_the_advertised_device(self):
        manifest = copy.deepcopy(MANIFEST)
        manifest["device"]["ecc"] = False
        manifest["device"]["endpoint_info"] = 4  # raw mode, no platform, no PP
        order = self.resolve("All", manifest)
        for dropped in ("EcdhSample", "TestFailureMode", "TestTpmPlatformControls"):
            self.assertNotIn(dropped, order)
        # Explicit names bypass profile filtering upstream, and here.
        self.assertEqual(self.resolve("TestFailureMode", manifest), ["TestFailureMode"])

    def test_invalid_selections_are_rejected(self):
        for expression, message in (
                (",", "no test/profile names"), (" , , ", "no test/profile names"),
                ("   ", "no test/profile names"), ("\t", "no test/profile names"),
                ("!TestRandom", "Invalid"), ("Test-Random", "Invalid"),
                ("Bogus", "Unknown"), ("Rand", "abbreviated"), ("Sample", "abbreviated"),
                ("TbsStandardUser", "not supported per scenario"),
                ("NoTRM", "no runnable scenarios"), ("Slow", "no runnable scenarios"),
                ("TestRandom Bogus", "Unknown")):
            with self.subTest(expression=expression):
                with self.assertRaisesRegex(ms.SelectionError, message):
                    ms.resolve(MANIFEST, expression)

    def test_ambiguous_exact_names_are_rejected(self):
        manifest = copy.deepcopy(MANIFEST)
        manifest["tests"]["TestMisc"] = dict(manifest["tests"]["TestRandom"])
        with self.assertRaisesRegex(ms.SelectionError, "Ambiguous.*TestMisc.*Misc"):
            ms.resolve(manifest, "Misc")

    def test_manifest_device_matches_the_bridge_handshake(self):
        self.assertIn("u32(1) + u32(0x%02x) + u32(0)" % MANIFEST["device"]["endpoint_info"],
                      (ROOT / "bridge.py").read_text())


class MetadataTests(unittest.TestCase):
    def fake_source(self, root, manifest=MANIFEST):
        substrate = root / "Tpm2Tester/TestSubstrate"
        suite = root / "Tpm2Tester/TestSuite"
        substrate.mkdir(parents=True)
        suite.mkdir(parents=True)
        enums = "".join("    public enum %s : uint\n    {\n%s    }\n" % (name, "".join(
            "        %s = 0x%x, // comment\n" % item for item in values.items()))
            for name, values in manifest["enums"].items())
        (substrate / "TestAttributes.cs").write_text("namespace X {\n" + enums + "}\n")
        methods = []
        for name, test in manifest["tests"].items():
            args = [" | ".join("%s.%s" % (enum, flag) for flag in test[field])
                    for enum, field in (("Profile", "profile"), ("Privileges", "privileges"),
                                        ("Category", "category"))]
            if test["special"]:
                args.append(" | ".join("Special." + flag for flag in test["special"]))
            methods.append("        [Test(%s)]\n        void %s(Tpm2 tpm, TestContext c) {}\n"
                           % (",\n              ".join(args), name))
        methods.append("        [Test(Profile.Disabled, Privileges.Admin, Category.Misc)]\n"
                       "        void DisabledOne(Tpm2 tpm, TestContext c) {}\n")
        (suite / "Tests.cs").write_text("class T {\n" + "".join(methods) + "}\n")

    def test_manifest_matches_upstream_shaped_source(self):
        with tempfile.TemporaryDirectory() as temp:
            self.fake_source(Path(temp))
            ms.check_source(MANIFEST, temp, MANIFEST["revision"])

    def test_attribute_and_revision_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            changed = copy.deepcopy(MANIFEST)
            changed["tests"]["TestRandom"]["special"] = ["NeedsTpmResourceMgr"]
            self.fake_source(Path(temp), changed)
            with self.assertRaisesRegex(ms.MetadataError, "TestRandom attributes differ"):
                ms.check_source(MANIFEST, temp, MANIFEST["revision"])
            with self.assertRaisesRegex(ms.MetadataError, "adapter pins"):
                ms.check_source(MANIFEST, temp, "0" * 40)
        with tempfile.TemporaryDirectory() as temp:
            extra = copy.deepcopy(MANIFEST)
            extra["tests"]["TestNewUpstream"] = dict(extra["tests"]["TestRandom"])
            self.fake_source(Path(temp), extra)
            with self.assertRaisesRegex(ms.MetadataError, "upstream \\[Test\\] methods"):
                ms.check_source(MANIFEST, temp, MANIFEST["revision"])

    @unittest.skipUnless((UPSTREAM / ".git").is_dir(), "pinned upstream checkout not cached")
    def test_manifest_matches_cached_pinned_checkout(self):
        head = subprocess.run(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
        if head != MANIFEST["revision"]:
            self.skipTest("cached checkout is at %s" % head)
        ms.check_source(MANIFEST, UPSTREAM, MANIFEST["revision"])

    def discovery(self, tests_line, profiles_line):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            fake = temp / "fake.py"
            fake.write_text("import sys\nprint({'-tests': %r, '-profiles': %r}[sys.argv[1]])\n"
                            "print('Failed to initialize Tpm2Tester framework (bad command "
                            "line or no test cases found in MyTestCases). Aborting...')\n"
                            % (tests_line, profiles_line))
            ms.check_discovery(MANIFEST, [sys.executable, str(fake)], temp)

    def test_upstream_discovery_is_cross_checked(self):
        tests = ", ".join(sorted(MANIFEST["tests"]))
        profiles = ", ".join(MANIFEST["profiles"] + list(MANIFEST["enums"]["Category"]))
        self.discovery(tests, profiles)
        with self.assertRaisesRegex(ms.MetadataError, "-tests"):
            self.discovery(tests + ", TestNewUpstream", profiles)
        with self.assertRaisesRegex(ms.MetadataError, "-profiles"):
            self.discovery(tests, profiles.replace("NoTRM, ", ""))


class ReportTests(unittest.TestCase):
    """Direct parser checks, independent of process supervision."""

    def parse(self, body, name="TestRandom", age=0):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            path = temp / "TpmTests_0.Report.html"
            path.write_text(body)
            os.utime(path, (time.time() - age, time.time() - age))
            return ms.parse_report(temp, name, time.time())

    def test_upstream_shaped_report(self):
        body = ("<body><h1>TPM Test Report</h1><h1>All Tests PASSED</h1><table>"
                "<tr><td><h3>Test Name</h3></td><td><h3>Succeeded</h3></td><td><h3>Failed"
                "</h3></td><td><h3>Aborted</h3></td><td><h3>Average Time, s</h3></td></tr>"
                "<tr><td>TestRandom</td><td>1</td><td>0</td><td>0</td><td>0.1</td></tr>"
                "</table></body>")
        info, error = self.parse(body)
        self.assertIsNone(error)
        self.assertEqual(info["routines"]["TestRandom"], {"passed": 1, "failed": 0, "aborted": 0})
        self.assertIn("stale", self.parse(body, age=3600)[1])
        self.assertIn("no result for TestAutomaticAuth", self.parse(
            body.replace("TestRandom", "LibTesterInfra"), "TestAutomaticAuth")[1])
        self.assertIn("statistics table", self.parse("<body>garbage</body>")[1])


class SupervisionTests(Fixture):
    def test_hanging_scenario_is_bounded_and_later_scenarios_run(self):
        self.plan(tester={"TestFailureMode": "hang"}, bridge={"TestFailureMode": "unsupported"})
        started = time.monotonic()
        result = self.run_helper("TestFailureMode TestRandom", timeout=2)
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.statuses(), {"TestFailureMode": "TIMEOUT", "TestRandom": "PASS"})
        hung = self.scenario("TestFailureMode")
        self.assertTrue(hung["timed_out"])
        self.assertEqual(hung["unsupported_opcodes"], [30])
        self.assertIn("did not finish within 2s", hung["reason"])
        self.assertIn("opcode 30 (TestFailureMode)", hung["reason"])
        summary = self.summary()
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["status"], "FAIL")
        # Concise run log, with evidence paths for the unsuccessful scenario.
        self.assertRegex(result.stdout, r"\[ 1/2\] TestFailureMode +TIMEOUT")
        self.assertRegex(result.stdout, r"\[ 2/2\] TestRandom +PASS")
        self.assertIn("microsoft-tss.run/01-TestFailureMode/bridge.log", result.stdout)
        self.assertIn("TIMEOUT=1", result.stdout)
        for key in ("console_log", "bridge_log"):
            self.assertTrue((self.results.parent / hung[key]).is_file())

    def test_process_trees_are_reaped_and_bridges_are_fresh(self):
        self.plan(tester={"TestFailureMode": "hang"})
        self.run_helper("TestFailureMode TestRandom TestSerialization", timeout=1)
        for pid, _ in self.pids("tester") + self.pids("child"):
            self.assertTrue(wait_dead(pid), "tester process %d survived" % pid)
        events = [line.split() for line in self.events.read_text().splitlines()
                  if line.startswith("bridge-")]
        # Every bridge is started for one scenario and stopped before the next.
        self.assertEqual([e[0] for e in events], ["bridge-start", "bridge-stop"] * 3)
        self.assertEqual([e[2] for e in events[::2]],
                         ["TestFailureMode", "TestRandom", "TestSerialization"])
        self.assertEqual(len({e[1] for e in events}), 3)
        for pid in {int(e[1]) for e in events}:
            self.assertTrue(wait_dead(pid))
        tmpdirs = {t.split("tmp=")[1].split()[0]
                   for t in self.events.read_text().split("tester ")[1:]}
        self.assertEqual(len(tmpdirs), 3)
        for tmpdir in tmpdirs:
            # .NET puts Unix-socket mutexes there; sun_path is at most 108 bytes.
            self.assertLessEqual(len(tmpdir + "/CoreFxPipe_TPM_TESTER_MUTEX_99"), 107, tmpdir)
            self.assertFalse(Path(tmpdir).exists(), "private TMPDIR not removed")

    def test_children_left_after_normal_exit_are_killed_and_fail(self):
        self.plan(tester={"TestRandom": "orphan"})
        result = self.run_helper("TestRandom")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.statuses(), {"TestRandom": "ERROR"})
        self.assertIn("left processes running", self.scenario("TestRandom")["reason"])
        for pid, _ in self.pids("child"):
            self.assertTrue(wait_dead(pid))

    def test_exit_zero_is_not_success(self):
        cases = {"TestRandom": "fail", "TestSerialization": "skip",
                 "TestCertifyX509": "infra-only", "TestVendorSpecific": "no-report",
                 "EcdhSample": "aborted", "ActivateAikSample": "infra-failed"}
        self.plan(tester=cases)
        result = self.run_helper(" ".join(cases))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.statuses(), {
            "TestRandom": "FAIL", "TestSerialization": "SKIPPED", "TestCertifyX509": "ERROR",
            "TestVendorSpecific": "ERROR", "EcdhSample": "FAIL", "ActivateAikSample": "FAIL"})
        failed = self.scenario("TestRandom")
        self.assertEqual(failed["exit_code"], 0)
        self.assertEqual(failed["seeds"], ["d103da62cc26888b"])
        self.assertIn("ArgumentException: AuthSession", failed["reason"])
        self.assertIn("infrastructure-only", self.scenario("TestCertifyX509")["reason"])
        self.assertIn("no upstream HTML report", self.scenario("TestVendorSpecific")["reason"])
        self.assertEqual(self.scenario("TestSerialization")["skipped_messages"],
                         ["TestSerialization skipped"])

    def test_bad_reports_are_explicit_errors(self):
        cases = {"TestRandom": "malformed", "TestSerialization": "duplicate",
                 "TestTpmPlatformControls": "abort",
                 "TestCertifyX509": "two-reports", "TestVendorSpecific": "stale",
                 "EcdhSample": "wrong", "ActivateAikSample": "extra-row",
                 "TestAutomaticAuth": "no-title", "DuplicateImportRsaSample": "exit3"}
        self.plan(tester=cases)
        self.run_helper(" ".join(cases))
        reasons = {r["name"]: r["reason"] for r in self.summary()["scenarios"]}
        self.assertEqual(set(self.statuses().values()), {"ERROR"})
        for name, text in (("TestRandom", "malformed"), ("TestSerialization", "duplicate"),
                           ("TestCertifyX509", "multiple upstream HTML reports"),
                           ("TestVendorSpecific", "stale"),
                           ("EcdhSample", "did not select exactly EcdhSample"),
                           ("ActivateAikSample", "other scenarios: TestRandom2"),
                           ("TestAutomaticAuth", "no recognizable overall verdict"),
                           ("DuplicateImportRsaSample", "exited with status 3"),
                           ("TestTpmPlatformControls", "killed by SIGABRT"),
                           ("TestTpmPlatformControls", "ArgumentOutOfRangeException")):
            self.assertIn(text, reasons[name], name)

    def test_unsupported_operation_never_becomes_pass(self):
        self.plan(bridge={"TestRandom": "unsupported", "TestSerialization": "trace"})
        self.run_helper("TestRandom TestSerialization")
        self.assertEqual(self.statuses(), {"TestRandom": "ERROR", "TestSerialization": "PASS"})
        self.assertIn("unsupported simulator opcode 30", self.scenario("TestRandom")["reason"])
        self.assertEqual(self.scenario("TestSerialization")["last_error_responses"],
                         [{"command": "0x00000176", "response": "0x00000903"}])

    def test_bridge_failures_are_recorded_and_the_run_continues(self):
        self.plan(tester={"TestSerialization": "slow"},
                  bridge={"TestRandom": "fail-start", "TestSerialization": "die"})
        self.run_helper("TestRandom TestSerialization TestVendorSpecific")
        self.assertEqual(self.statuses(), {"TestRandom": "ERROR", "TestSerialization": "ERROR",
                                           "TestVendorSpecific": "PASS"})
        self.assertIn("before becoming ready", self.scenario("TestRandom")["reason"])
        self.assertIn("bridge exited with status 7 during the scenario",
                      self.scenario("TestSerialization")["reason"])

    def test_all_pass_is_the_only_zero_exit(self):
        self.plan()
        result = self.run_helper("TestRandom Ecc")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary()["status"], "PASS")
        selection = json.loads((self.results / "selection.json").read_text())
        self.assertEqual(selection["order"], ["EcdhSample", "TestRandom"])

    def test_invalid_selection_starts_nothing_and_leaves_a_summary(self):
        self.plan()
        result = self.run_helper("Rand")
        self.assertEqual(result.returncode, 2)
        self.assertIn("abbreviated", result.stderr)
        self.assertEqual(self.summary()["status"], "INVALID_SELECTION")
        self.assertEqual(self.events.read_text(), "")

    def wait_for_event(self, prefix, process, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if any(line.startswith(prefix) for line in self.events.read_text().splitlines()):
                return
            if process.poll() is not None:
                self.fail("supervisor exited before %r" % prefix)
            time.sleep(0.02)
        self.fail("never observed %r" % prefix)

    def start(self, selection, timeout=60):
        process = subprocess.Popen(self.argv(selection, timeout=timeout), env=self.env(),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.kill_leftovers, self.events)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        return process

    def test_interruption_before_bridge_readiness_reaps_the_bridge(self):
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=signum.name):
                self.setUp()
                self.plan(bridge={"TestSerialization": "never-ready"})
                process = self.start("TestRandom TestSerialization TestVendorSpecific")
                self.wait_for_event("bridge-child ", process)
                started = time.monotonic()
                process.send_signal(signum)
                stdout, stderr = process.communicate(timeout=20)
                self.assertLess(time.monotonic() - started, 10)
                self.assertEqual(process.returncode, 128 + signum, stderr)
                for pid, scenario in self.pids("bridge-start") + self.pids("bridge-child"):
                    self.assertTrue(wait_dead(pid), "%s bridge process %d survived"
                                    % (scenario, pid))
                self.assertEqual([s for _, s in self.pids("tester")], ["TestRandom"])
                summary = self.summary()
                self.assertFalse(summary["complete"])
                self.assertEqual(summary["status"], "INTERRUPTED")
                self.assertEqual(summary["interrupted_by"], signum.name)
                self.assertEqual(self.statuses(), {"TestRandom": "PASS",
                                                   "TestSerialization": "INTERRUPTED",
                                                   "TestVendorSpecific": "NOT_RUN"})
                self.assertEqual(self.scenario("TestRandom")["counts"]["passed"], 1)
                interrupted = self.scenario("TestSerialization")
                self.assertNotIn("tester_pid", interrupted)
                self.assertIsNotNone(interrupted["bridge_exit_code"])

    def assert_report_evidence(self, name, kind):
        result = self.scenario(name)
        if kind in ("pass", "fail"):
            self.assertEqual(result["report"],
                             "microsoft-tss.run/%s/TpmTests_0.Report.html" % result["directory"]
                             .split("/", 1)[1])
            self.assertIsNone(result["report_error"])
            self.assertEqual(result["counts"], {"passed": 1, "failed": 0, "aborted": 0}
                             if kind == "pass" else {"passed": 0, "failed": 1, "aborted": 0})
            self.assertEqual(result["infrastructure_counts"],
                             {"passed": 1, "failed": 0, "aborted": 0})
            self.assertTrue(result["report_title"].startswith(
                "All Tests PASSED" if kind == "pass" else "Some tests FAILED"))
            self.assertIn("report before termination", result["reason"])
        elif kind == "malformed":
            self.assertIn("malformed", result["report_error"])
            self.assertIsNone(result["counts"])
            self.assertIn("malformed", result["reason"])
        else:
            self.assertIsNone(result["report"])
            self.assertIn("no upstream HTML report", result["report_error"])
        if kind == "fail":
            self.assertEqual(result["seeds"], ["d103da62cc26888b"])
            self.assertEqual(result["exceptions"], ["System.ArgumentException: AuthSession: boom"])

    def test_reports_are_collected_from_timed_out_scenarios(self):
        cases = {"TestRandom": "pass", "TestSerialization": "fail",
                 "TestCertifyX509": "malformed", "TestVendorSpecific": "missing"}
        self.plan(tester={n: k + "-then-hang" for n, k in cases.items()},
                  bridge={"TestRandom": "unsupported"})
        result = self.run_helper(" ".join(cases), timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(set(self.statuses().values()), {"TIMEOUT"})
        for name, kind in cases.items():
            with self.subTest(name=name):
                scenario = self.scenario(name)
                self.assertTrue(scenario["timed_out"])
                self.assertIsNone(scenario["exit_code"])
                self.assertIn("did not finish within 2s", scenario["reason"])
                self.assert_report_evidence(name, kind)
        self.assertEqual(self.scenario("TestRandom")["unsupported_opcodes"], [30])
        self.assertIn("opcode 30", self.scenario("TestRandom")["reason"])

    def test_reports_are_collected_from_interrupted_scenarios(self):
        for kind in ("pass", "fail", "malformed", "missing"):
            with self.subTest(kind=kind):
                self.setUp()
                self.plan(tester={"TestRandom": kind + "-then-hang"})
                process = self.start("TestRandom TestSerialization")
                self.wait_for_event("reported ", process)
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=20)
                self.assertEqual(process.returncode, 128 + signal.SIGTERM)
                self.assertEqual(self.statuses(), {"TestRandom": "INTERRUPTED",
                                                   "TestSerialization": "NOT_RUN"})
                scenario = self.scenario("TestRandom")
                self.assertTrue(scenario["interrupted"])
                self.assertFalse(scenario["timed_out"])
                self.assertIn("SIGTERM stopped this scenario", scenario["reason"])
                self.assert_report_evidence("TestRandom", kind)
                for pid, _ in self.pids("tester") + self.pids("bridge-start"):
                    self.assertTrue(wait_dead(pid))

    def start_and_wait_for(self, selection, running):
        process = subprocess.Popen(self.argv(selection, timeout=60), env=self.env(),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.kill_leftovers, self.events)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                current = self.scenario(running)
                if current["status"] == "RUNNING" and self.pids("child"):
                    return process
            except (FileNotFoundError, ValueError, StopIteration):
                pass
            time.sleep(0.05)
        process.kill()
        self.fail("scenario %s never started" % running)

    def test_outer_interruption_finalizes_a_partial_summary(self):
        self.plan(tester={"TestFailureMode": "hang"})
        process = self.start_and_wait_for("TestRandom TestFailureMode TestSerialization",
                                          "TestFailureMode")
        process.send_signal(signal.SIGTERM)
        stdout, _ = process.communicate(timeout=20)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM)
        summary = self.summary()
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["status"], "INTERRUPTED")
        self.assertEqual(summary["interrupted_by"], "SIGTERM")
        self.assertEqual(self.statuses(), {"TestRandom": "PASS", "TestFailureMode": "INTERRUPTED",
                                           "TestSerialization": "NOT_RUN"})
        self.assertIn("NOT_RUN", stdout)
        for pid, _ in self.pids("tester") + self.pids("child") + self.pids("bridge-start"):
            self.assertTrue(wait_dead(pid), "process %d survived" % pid)

    def test_forced_termination_keeps_persisted_results(self):
        self.plan(tester={"TestFailureMode": "hang"})
        process = self.start_and_wait_for("TestRandom TestFailureMode TestSerialization",
                                          "TestFailureMode")
        process.kill()
        process.communicate()
        summary = self.summary()
        self.assertFalse(summary["complete"])
        self.assertEqual(self.statuses(), {"TestRandom": "PASS", "TestFailureMode": "RUNNING",
                                           "TestSerialization": "PENDING"})
        self.assertEqual(self.scenario("TestRandom")["counts"]["passed"], 1)


class ModuleEntryTests(unittest.TestCase):
    """The adapter runs the supervisor as `python3 -m validation.adapters.microsoft_scenarios`."""

    def run_module(self, expression):
        with tempfile.TemporaryDirectory() as temp:
            results = Path(temp) / "scenarios"
            result = subprocess.run(
                [sys.executable, "-m", "validation.adapters.microsoft_scenarios", "run",
                 "--results", str(results), "--revision", MANIFEST["revision"],
                 "--filter", expression, "--assembly", "/nonexistent.dll",
                 "--library", "/nonexistent.so"],
                cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT)),
                capture_output=True, text=True, timeout=60)
            summary = json.loads((results / "summary.json").read_text())
            return result, summary, list(results.glob("[0-9][0-9]-*"))

    def test_invalid_selection_is_rejected_before_execution(self):
        for expression in (",", " , , ", "   ", "\t", "Rand"):
            with self.subTest(expression=expression):
                result, summary, dirs = self.run_module(expression)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(summary["status"], "INVALID_SELECTION")
                self.assertEqual(dirs, [])


class CollectorTests(unittest.TestCase):
    """Real 12-scenario Rust summary from the pinned revision."""

    def collect(self, summary):
        suite = schema.new_suite("microsoft-tss")
        suite["state"] = "finished"
        suite["phases"] = [schema.phase_record("run", "PASS")]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "summary.json"
            path.write_text(json.dumps(summary))
            collector.collect(suite, path, prefix="rust/microsoft-tss",
                              termination="completed")
        return schema.finalize_suite(suite)

    def real(self):
        return json.loads((FIXTURES / "summary.json").read_text())

    def test_real_summary_maps_one_test_per_scenario(self):
        suite = self.collect(self.real())
        self.assertEqual(len(suite["tests"]), 12)
        self.assertEqual(suite["counts"], {"PASS": 9, "FAIL": 1, "TIMEOUT": 1, "SKIPPED": 1})
        self.assertNotIn("LibTesterInfra", {t["name"] for t in suite["tests"]})
        failure = next(t for t in suite["tests"] if t["name"] == "TestFailureMode")
        self.assertEqual(failure["status"], "TIMEOUT")
        self.assertEqual(failure["details"]["unsupported_opcodes"], [30])
        self.assertIn("opcode 30 (TestFailureMode)", failure["reason"])
        auth = next(t for t in suite["tests"] if t["name"] == "TestAutomaticAuth")
        self.assertEqual(auth["details"]["signature"]["exceptions"],
                         ["System.ArgumentException: AuthSession: Attempt to construct from "
                          "parametrized non-session handle"])
        self.assertNotIn("seeds", auth["details"]["signature"])
        self.assertTrue(auth["artifacts"]["report"].startswith("rust/microsoft-tss/"))
        self.assertEqual(suite["status"], "FAIL")
        self.assertTrue(suite["complete"])

    def test_unfinalized_supervisor_summary(self):
        summary = self.real()
        summary["status"], summary["complete"] = "RUNNING", False
        summary["scenarios"][7]["status"] = "RUNNING"
        for scenario in summary["scenarios"][8:]:
            scenario["status"] = "PENDING"
        suite = self.collect(summary)
        statuses = [t["status"] for t in suite["tests"]]
        self.assertEqual(statuses[7], "INTERRUPTED")
        self.assertEqual(set(statuses[8:]), {"NOT_RUN"})
        self.assertFalse(suite["complete"])
        self.assertIn("supervisor", [i["code"] for i in suite["issues"]])

    def test_missing_malformed_and_rejected_summaries(self):
        suite = schema.new_suite("microsoft-tss")
        collector.collect(suite, Path("/nonexistent/summary.json"), prefix="x",
                          termination="timeout")
        self.assertEqual(suite["issues"][0]["code"], "no-summary")
        for text, code in (("{not json", "malformed"),
                           (json.dumps({"status": "INVALID_SELECTION", "error": "Unknown name",
                                        "scenarios": []}), "selection")):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "summary.json"
                path.write_text(text)
                suite = schema.new_suite("microsoft-tss")
                suite["state"] = "finished"
                collector.collect(suite, path, prefix="x", termination="completed")
                self.assertEqual(suite["issues"][0]["code"], code)
                self.assertEqual(schema.finalize_suite(suite)["status"], "ERROR")


class CompareTests(unittest.TestCase):
    def test_compare_by_scenario_name(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            left = {"scenarios": [{"name": "A", "status": "PASS"},
                                  {"name": "B", "status": "FAIL", "exceptions": ["X: y"]}]}
            right = {"scenarios": [{"name": "B", "status": "FAIL", "exceptions": ["X: y"]},
                                   {"name": "A", "status": "PASS"}]}
            (temp / "l.json").write_text(json.dumps(left))
            (temp / "r.json").write_text(json.dumps(right))
            same = subprocess.run([sys.executable, str(HELPER), "compare", str(temp / "l.json"),
                                   str(temp / "r.json")], capture_output=True, text=True)
            self.assertEqual(same.returncode, 0, same.stdout)
            right["scenarios"][1]["status"] = "TIMEOUT"
            (temp / "r.json").write_text(json.dumps(right))
            differ = subprocess.run([sys.executable, str(HELPER), "compare", str(temp / "l.json"),
                                     str(temp / "r.json")], capture_output=True, text=True)
            self.assertEqual(differ.returncode, 1)
            self.assertRegex(differ.stdout, r"A +PASS +TIMEOUT +NO")


if __name__ == "__main__":
    unittest.main()
