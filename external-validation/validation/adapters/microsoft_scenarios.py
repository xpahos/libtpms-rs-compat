#!/usr/bin/env python3
"""Select, supervise and report Microsoft Tpm2Tester scenarios one at a time.

The upstream program runs a whole profile in one process, parses names with
prefix/substring matching and exits zero even when tests fail. A single hanging
scenario (TestFailureMode waits forever once the bridge rejects simulator
opcode 30) therefore used to hide every later result. This helper:

* resolves the requested native test/profile names against a reviewed manifest
  of the pinned revision, after cross-checking that manifest with upstream
  enums, [Test] attributes, -tests and -profiles;
* runs each resolved scenario by its exact name in a fresh directory, against a
  fresh bridge (fresh TPM state), with a per-scenario timeout, and kills the
  tester and bridge process groups before the next scenario starts;
* rewrites summary.json atomically after every scenario, so completed results
  survive a later timeout, signal or crash.

Nothing here edits upstream sources or answers simulator requests.
"""

import argparse
import json
import os
from pathlib import Path
import re
from html.parser import HTMLParser
import shutil
import signal
import subprocess
import sys
import tempfile
import time


SUITE = "microsoft-tss"
INFRA = "LibTesterInfra"
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
# Only upstream messages that mean selected work did not run. The pinned
# framework prints "<Test> skipped" from RunTest and from individual samples.
SKIP = re.compile(r"^(?:Some of the tests cannot be executed\b|These tests will be skipped:|"
                  r"[A-Za-z_]\w* skipped$)", re.IGNORECASE)
UNSUPPORTED = re.compile(r"^bridge: unsupported simulator opcode (\d+)$")
TRACED = re.compile(r"^bridge: command 0x([0-9a-f]{8}) response 0x([0-9a-f]{8})$")
EXCEPTION = re.compile(r"(?:\bUnhandled exception\. |\bException )(\S+?): (.*)$")
SEED = re.compile(r"To reproduce use option: -seed (\S+)")
# TSS.Net TcpTpmCommands at the pinned revision.
OPCODES = {9: "SignalCancelOn", 10: "SignalCancelOff", 12: "SignalNvOff",
           13: "SignalKeyCacheOn", 14: "SignalKeyCacheOff", 26: "ActGetSignaled",
           30: "TestFailureMode"}
# Profiles whose side effects cannot be reproduced by running members one by one.
UNSUPPORTED_PROFILES = {
    "TbsStandardUser": "it sets RunAsStandardUser, which also disables normal TPM "
                       "initialization; running its members by name would not "
                       "reproduce that configuration",
}
STATUSES = ("PASS", "FAIL", "SKIPPED", "ERROR", "TIMEOUT", "INTERRUPTED", "NOT_RUN")
EXIT_FAIL, EXIT_USAGE = 1, 2


class SelectionError(Exception):
    """The request cannot be mapped to an exact, non-empty scenario list."""


class MetadataError(Exception):
    """The reviewed manifest disagrees with the upstream checkout or binary."""


# ---------------------------------------------------------------- selection

def load_manifest(path):
    manifest = json.loads(Path(path).read_text())
    enums = manifest["enums"]
    for name, test in manifest["tests"].items():
        if not NAME.match(name):
            raise MetadataError("invalid manifest test name: %r" % name)
        for field, enum in (("profile", "Profile"), ("privileges", "Privileges"),
                            ("category", "Category"), ("special", "Special")):
            unknown = set(test[field]) - set(enums[enum])
            if unknown:
                raise MetadataError("%s: unknown %s flags %s" % (name, enum, sorted(unknown)))
    return manifest


def mask(manifest, enum, names):
    values = manifest["enums"][enum]
    result = 0
    for name in names:
        result |= values[name]
    return result


def attributes(manifest, name):
    test = manifest["tests"][name]
    return {"profile": mask(manifest, "Profile", test["profile"]),
            "privileges": mask(manifest, "Privileges", test["privileges"]),
            "category": mask(manifest, "Category", test["category"]),
            "special": mask(manifest, "Special", test["special"])}


def profile_members(manifest, profile, state):
    """TesterCmdLine.DefinedProfiles, transcribed; mutates disabled categories."""
    category = manifest["enums"]["Category"]
    privileges = manifest["enums"]["Privileges"]
    special = manifest["enums"]["Special"]
    comm = manifest["enums"]["Profile"]
    names = list(manifest["tests"])
    attrs = {name: attributes(manifest, name) for name in names}
    if profile == "All":
        state["disabled_category"] &= ~category["Slow"]
        return names
    predicates = {
        "TbsAdmin": lambda a: a["privileges"] & privileges["Admin"],
        "MinTpmTbsAdmin": lambda a: (a["profile"] == comm["MinTPM"]
                                     and a["privileges"] & privileges["Admin"]
                                     and not a["category"] & category["WLK"]),
        "NoTRM": lambda a: (a["special"] & special["NoTRM"]
                            and not a["category"] & category["WLK"]),
        "WlkHWInterfaceTests": lambda a: (a["profile"] in (comm["MinTPM"], comm["TPM20"])
                                          and not a["privileges"] & privileges["Special"]
                                          and a["category"] & category["WLK"]),
    }
    return [name for name in names if predicates[profile](attrs[name])]


def category_members(manifest, cat, state):
    value = manifest["enums"]["Category"][cat]
    state["disabled_category"] &= ~value
    # Enum.HasFlag(None) is true for every test, exactly as upstream.
    return [name for name in manifest["tests"]
            if attributes(manifest, name)["category"] & value == value]


def upstream_would_accept(manifest, token):
    """Fuzzy names the upstream parser accepts but this harness refuses."""
    lower = token.lower()
    tests = [t for t in manifest["tests"]
             if t.lower().startswith(lower) or t.lower().startswith("test" + lower)
             or (not lower.startswith("test") and len(lower) > 3 and lower in t.lower())]
    profiles = [p for p in manifest["profiles"] + list(manifest["enums"]["Category"])
                if p.lower().startswith(lower)]
    return profiles + tests


def resolve(manifest, expression):
    """Resolve a TEST_FILTER value exactly as upstream would order an explicit run.

    Returns a dict with the ordered scenario names and an audit trail.
    """
    if expression is None or expression == "":
        tokens, default = ["All"], True
    else:
        tokens, default = [t for t in re.split(r"[\s,]+", expression) if t], False
        if not tokens:
            raise SelectionError("Microsoft TEST_FILTER selected no test/profile names")
    tests = manifest["tests"]
    categories = manifest["enums"]["Category"]
    profiles = manifest["profiles"]
    enums = manifest["enums"]
    state = {"disabled_category": categories["Hidden"] | categories["Slow"]}
    from_profiles, explicit, expansions = [], [], []
    for token in tokens:
        if not NAME.match(token):
            raise SelectionError("Invalid Microsoft native test/profile name: %s" % token)
        lower = token.lower()
        test_hits = [n for n in tests if n.lower() in (lower, "test" + lower)]
        profile_hits = [p for p in profiles if p.lower() == lower]
        category_hits = sorted({c for c in categories if c.lower() == lower})
        hits = len(test_hits) + len(profile_hits) + len(category_hits)
        if hits > 1:
            raise SelectionError("Ambiguous Microsoft name %s: matches %s" % (
                token, ", ".join(test_hits + profile_hits + category_hits)))
        if not hits:
            fuzzy = upstream_would_accept(manifest, token)
            if fuzzy:
                raise SelectionError(
                    "Ambiguous or abbreviated Microsoft name %s (upstream would expand it "
                    "by prefix/substring to: %s); use an exact test or profile name"
                    % (token, ", ".join(fuzzy)))
            raise SelectionError("Unknown Microsoft test or profile name: %s" % token)
        if test_hits:
            explicit.append(test_hits[0])
            expansions.append({"token": token, "kind": "test", "members": test_hits})
        elif profile_hits:
            profile = profile_hits[0]
            if profile in UNSUPPORTED_PROFILES:
                raise SelectionError("Microsoft profile %s is not supported per scenario: %s"
                                     % (profile, UNSUPPORTED_PROFILES[profile]))
            members = profile_members(manifest, profile, state)
            from_profiles.extend(members)
            expansions.append({"token": token, "kind": "profile", "name": profile,
                               "candidates": members})
        else:
            members = category_members(manifest, category_hits[0], state)
            from_profiles.extend(members)
            expansions.append({"token": token, "kind": "category", "name": category_hits[0],
                               "candidates": members})
    # TesterCmdLine.GenerateTestSet: device filters apply to profile-derived
    # tests only; explicitly named tests are appended unfiltered.
    device = manifest["device"]
    disabled_special = 0
    special = enums["Special"]
    endpoint = device["endpoint_info"]
    platform, raw, presence = endpoint & 1, endpoint & 4, endpoint & 8
    if raw:  # TcpTpmDevice.HasRM() is false only in raw mode.
        disabled_special |= special["NeedsTpmResourceMgr"]
    if not device["wlk_build"]:
        state["disabled_category"] |= categories["WLK"]
    if not device["ecc"]:
        state["disabled_category"] |= categories["Ecc"]
    if not presence:
        disabled_special |= special["PhysicalPresence"]
    if not platform:
        disabled_special |= (special["PowerControl"] | special["Locality"] | special["Platform"]
                             | special["NoTRM"] | special["TbsBlocked"])
    filtered = []
    for name in from_profiles:
        attrs = attributes(manifest, name)
        if attrs["category"] & state["disabled_category"] or attrs["special"] & disabled_special:
            continue
        filtered.append(name)
    order, duplicates = [], []
    for name in sorted(filtered, key=lambda n: (n.lower(), n)) + explicit:
        (duplicates if name in order else order).append(name)
    order.sort(key=lambda n: bool(attributes(manifest, n)["special"] & special["RunAtEnd"]))
    if not order:
        raise SelectionError("Microsoft selection %s resolved to no runnable scenarios"
                             % " ".join(tokens))
    for item in expansions:
        if "candidates" in item:
            item["members"] = [n for n in item.pop("candidates") if n in filtered]
    return {"requested": tokens, "default": default, "expansions": expansions,
            "duplicates_removed": duplicates, "order": order}


# ------------------------------------------------------- upstream cross-checks

def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def source_enums(source):
    text = strip_comments((Path(source) / "Tpm2Tester/TestSubstrate/TestAttributes.cs")
                          .read_text(encoding="utf-8-sig"))
    enums = {}
    for name, body in re.findall(r"\benum\s+(\w+)\s*(?::\s*\w+\s*)?\{(.*?)\}", text, re.S):
        values = {}
        for entry in (e.strip() for e in body.split(",")):
            if not entry:
                continue
            key, _, value = (part.strip() for part in entry.partition("="))
            if not value:
                raise MetadataError("implicit enum value %s.%s" % (name, key))
            values[key] = values[value] if value in values else int(value, 0)
        enums[name] = values
    return enums


def source_tests(source, enums):
    order = ("Profile", "Privileges", "Category", "Special")
    found = {}
    for path in sorted((Path(source) / "Tpm2Tester/TestSuite").glob("*.cs")):
        text = strip_comments(path.read_text(encoding="utf-8-sig"))
        pattern = r"\[Test\(([^()]*)\)\]\s*(?:\[[^\]]*\]\s*)*(?:\w+\s+)*void\s+(\w+)\s*\("
        for args, method in re.findall(pattern, text):
            values = {}
            for position, arg in enumerate(a.strip() for a in args.split(",")):
                enum = order[position]
                total = 0
                for flag in (f.strip() for f in arg.split("|")):
                    prefix, _, member = flag.partition(".")
                    if prefix != enum or member not in enums[enum]:
                        raise MetadataError("%s: unexpected attribute %r" % (method, flag))
                    total |= enums[enum][member]
                values[enum] = total
            values.setdefault("Special", 0)
            if values["Profile"] & enums["Profile"]["Disabled"]:
                continue  # TestFramework skips disabled methods during discovery.
            if method in found:
                raise MetadataError("duplicate upstream test method %s" % method)
            found[method] = values
    return found


def check_source(manifest, source, revision):
    problems = []
    if revision != manifest["revision"]:
        problems.append("adapter pins %s, manifest reviews %s" % (revision, manifest["revision"]))
    enums = source_enums(source)
    for enum, values in manifest["enums"].items():
        if enums.get(enum) != values:
            problems.append("enum %s differs from upstream TestAttributes.cs" % enum)
    if not problems:
        upstream = source_tests(source, enums)
        if set(upstream) != set(manifest["tests"]):
            problems.append("upstream [Test] methods %s != manifest %s" % (
                sorted(upstream), sorted(manifest["tests"])))
        for name in sorted(set(upstream) & set(manifest["tests"])):
            ours = attributes(manifest, name)
            theirs = {"profile": upstream[name]["Profile"],
                      "privileges": upstream[name]["Privileges"],
                      "category": upstream[name]["Category"],
                      "special": upstream[name]["Special"]}
            if ours != theirs:
                problems.append("%s attributes differ: manifest %s upstream %s"
                                % (name, ours, theirs))
    if problems:
        raise MetadataError("; ".join(problems))


def name_lists(output):
    return [[n.strip() for n in line.split(",")] for line in output.splitlines()
            if re.fullmatch(r"[A-Za-z]\w*(?:, [A-Za-z]\w*)*", line.strip())]


def check_discovery(manifest, base_command, directory, timeout=60):
    expected = {
        "-tests": sorted(manifest["tests"]),
        "-profiles": sorted(set(manifest["profiles"]) | set(manifest["enums"]["Category"])),
    }
    for option, wanted in expected.items():
        log = directory / ("discovery%s.log" % option)
        with open(log, "wb") as output:
            try:
                subprocess.run(base_command + [option], stdout=output, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                raise MetadataError("upstream %s did not finish within %ds" % (option, timeout))
        lists = name_lists(log.read_text(errors="replace"))
        if len(lists) != 1 or sorted(lists[0]) != wanted:
            raise MetadataError("upstream %s output differs from the manifest; see %s"
                                % (option, log.name))


# ------------------------------------------------------------ report parsing

class Tables(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tables, self.headings = [], []
        self.table = self.row = self.cell = self.heading = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.table = []
        elif tag == "tr":
            self.row = []
        elif tag == "td":
            self.cell = []
        elif tag == "h1":
            self.heading = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)
        if self.heading is not None:
            self.heading.append(data)

    def handle_endtag(self, tag):
        if tag == "td" and self.cell is not None and self.row is not None:
            self.row.append("".join(self.cell).strip())
            self.cell = None
        elif tag == "tr" and self.row is not None and self.table is not None:
            self.table.append(self.row)
            self.row = None
        elif tag == "table" and self.table is not None:
            self.tables.append(self.table)
            self.table = None
        elif tag == "h1" and self.heading is not None:
            self.headings.append("".join(self.heading).strip())
            self.heading = None


def parse_report(directory, scenario, started):
    """Return (report info, error). Any error makes the outcome unknown."""
    reports = sorted(directory.glob("TpmTests_*.Report.html"))
    if not reports:
        return None, "no upstream HTML report was produced"
    if len(reports) > 1:
        return None, "multiple upstream HTML reports: %s" % ", ".join(r.name for r in reports)
    report = reports[0]
    info = {"report": report.name}
    if report.stat().st_mtime < started - 1:
        return info, "stale upstream report %s predates this scenario" % report.name
    try:
        parser = Tables()
        parser.feed(report.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as error:
        return info, "unreadable upstream report: %s" % error
    titles = [h for h in parser.headings if h.startswith(("All Tests PASSED", "Some tests FAILED"))]
    info["title"] = titles[0] if len(titles) == 1 else None
    tables = [t for t in parser.tables
              if t and t[0][:4] == ["Test Name", "Succeeded", "Failed", "Aborted"]]
    if len(tables) != 1:
        return info, "missing or ambiguous test routine statistics table"
    rows = {}
    for row in tables[0][1:]:
        if len(row) != 5 or any(not v.isdecimal() for v in row[1:4]):
            return info, "malformed test routine statistics row: %r" % (row,)
        if row[0] in rows:
            return info, "duplicate statistics row for %s" % row[0]
        rows[row[0]] = {"passed": int(row[1]), "failed": int(row[2]), "aborted": int(row[3])}
    info["routines"] = rows
    others = sorted(set(rows) - {scenario, INFRA})
    if others:
        return info, "report contains other scenarios: %s" % ", ".join(others)
    if scenario not in rows:
        return info, ("report has no result for %s (infrastructure-only report)" % scenario
                      if rows else "report has no test routine results")
    if info["title"] is None:
        return info, "report has no recognizable overall verdict"
    return info, None


def parse_console(path):
    text = path.read_text(encoding="utf-8-sig", errors="replace") if path.exists() else ""
    lines = [l.strip() for l in text.splitlines()]
    selected = None
    for index, line in enumerate(lines):
        if line == "Test Routines in current test run:" and index + 1 < len(lines):
            selected = [n.strip() for n in lines[index + 1].split(",") if n.strip()]
    ecc = [l.split(":", 1)[1].strip() for l in lines if l.startswith("ECC curves:")]
    return {
        "selected": selected,
        "skips": [l for l in lines if SKIP.search(l)],
        "exceptions": [m.group(1) + ": " + m.group(2).strip()
                       for m in map(EXCEPTION.search, lines) if m],
        "seeds": sorted(set(SEED.findall(text))),
        "ecc_curves": ecc[-1] if ecc else None,
        "tail": [l for l in lines if l][-6:],
    }


def parse_bridge(path):
    lines = path.read_text(errors="replace").splitlines() if path.exists() else []
    unsupported, traced, other = [], [], []
    for line in (l.strip() for l in lines):
        match = UNSUPPORTED.match(line)
        if match:
            unsupported.append(int(match.group(1)))
            continue
        match = TRACED.match(line)
        if match:
            traced.append({"command": "0x" + match.group(1), "response": "0x" + match.group(2)})
        elif line.startswith("bridge"):
            if not line.startswith("bridge: command ") and "ready" not in line:
                other.append(line)
    return {"unsupported_opcodes": unsupported, "error_responses": len(traced),
            "last_error_responses": traced[-5:], "bridge_errors": other[-5:]}


def signal_name(number):
    try:
        return signal.Signals(number).name
    except ValueError:
        return "signal %d" % number


def describe_unsupported(opcodes):
    return ", ".join("%d (%s)" % (o, OPCODES.get(o, "unknown")) for o in sorted(set(opcodes)))


def classify(result, scenario, directory, started):
    """Fill status/reason from the collected evidence. Only exact success is PASS."""
    console = parse_console(directory / "console.log")
    bridge = parse_bridge(directory / "bridge.log")
    result.update({k: console[k] for k in ("exceptions", "seeds", "ecc_curves")})
    result["skipped_messages"] = console["skips"]
    result["console_tail"] = console["tail"]
    result["selected_by_upstream"] = console["selected"]
    result.update(bridge)
    unsupported = bridge["unsupported_opcodes"]
    note = ("bridge rejected unsupported simulator opcode %s and closed the platform channel"
            % describe_unsupported(unsupported)) if unsupported else ""
    # Collect report evidence whatever ended the scenario; the process
    # outcome still decides the status (a report never upgrades a timeout).
    report_error = collect_report(result, scenario, directory, started)
    if result["status"] == "RUNNING" and result["timed_out"]:
        result["status"] = "TIMEOUT"
        result["reason"] = "tester did not finish within %ds" % result["timeout_seconds"]
    if result["status"] == "RUNNING":
        status, reason = outcome(result, scenario, console, note, report_error)
        result["status"], result["reason"] = status, reason
    elif result["status"] in ("TIMEOUT", "INTERRUPTED"):
        result["reason"] = "; ".join(r for r in (
            result["reason"], report_note(result, report_error)) if r)
    if note and note not in result["reason"]:
        result["reason"] = "; ".join(r for r in (result["reason"], note) if r)


def collect_report(result, scenario, directory, started):
    """Record whatever report evidence exists; return its validation error."""
    info, error = parse_report(directory, scenario, started)
    if info:
        result["report"] = info["report"]
        result["report_title"] = info.get("title")
        routines = info.get("routines", {})
        result["counts"] = routines.get(scenario)
        result["infrastructure_counts"] = routines.get(INFRA)
    result["report_error"] = error
    return error


def report_note(result, error):
    """Describe report evidence left by a scenario that did not finish."""
    if error:
        return "report: " + error
    counts = result["counts"]
    return ("report before termination: %s, passed=%d failed=%d aborted=%d"
            % (result["report_title"], counts["passed"], counts["failed"], counts["aborted"]))


def outcome(result, scenario, console, unsupported, error):
    problems = []
    if console["selected"] != [scenario]:
        problems.append("upstream did not select exactly %s (selected: %s)"
                        % (scenario, ", ".join(console["selected"] or ["nothing"])))
    if error:
        problems.append(error)
    code = result["exit_code"]
    exit_note = ("" if code == 0 else "tester was killed by %s" % signal_name(-code)
                 if code is not None and code < 0 else "tester exited with status %s" % code)
    if not problems:
        counts = result["counts"]
        infra = result["infrastructure_counts"] or {"failed": 0, "aborted": 0}
        title = result["report_title"]
        if (counts["failed"] or counts["aborted"] or infra["failed"] or infra["aborted"]
                or not title.startswith("All Tests PASSED") or "ABORTED" in title):
            details = ["upstream report: %d failed, %d aborted (%s: %d failed, %d aborted)"
                       % (counts["failed"], counts["aborted"], INFRA,
                          infra["failed"], infra["aborted"])]
            details += console["exceptions"][:1]
            details += ["seed %s" % s for s in console["seeds"][:1]]
            return "FAIL", "; ".join(details + ([exit_note] if exit_note else []))
    if exit_note:
        problems.append(exit_note)
    if problems:
        return "ERROR", "; ".join(problems + console["exceptions"][:1])
    if console["skips"]:
        return "SKIPPED", "; ".join(console["skips"])
    if not result["counts"]["passed"]:
        return "ERROR", "%s recorded no successful run" % scenario
    if unsupported:
        return "ERROR", unsupported
    if console["ecc_curves"] == "<NONE>":
        return "ERROR", "TPM reports no ECC curves; the manifest device assumption is wrong"
    return "PASS", ""


# --------------------------------------------------------------- supervision

class Interrupted(Exception):
    pass


class Supervisor:
    def __init__(self, args, selection):
        self.args = args
        self.selection = selection
        self.results = Path(args.results)
        self.signal = None
        self.summary = {
            "suite": SUITE,
            "revision": args.revision,
            "status": "RUNNING",
            "complete": False,
            "interrupted_by": None,
            "scenario_timeout_seconds": args.scenario_timeout,
            "selection": selection,
            "counts": {},
            "scenarios": [dict(name=n, index=i + 1, status="PENDING")
                          for i, n in enumerate(selection["order"])],
        }

    # -- helpers
    def on_signal(self, signum, frame):
        self.signal = signum

    def check_signal(self):
        if self.signal is not None:
            raise Interrupted()

    def write(self):
        counts = {}
        for item in self.summary["scenarios"]:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        self.summary["counts"] = counts
        path = self.results / "summary.json"
        temporary = path.with_name(".summary.json.%d.tmp" % os.getpid())
        with open(temporary, "w") as output:
            json.dump(self.summary, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)

    def relative(self, path):
        return os.path.relpath(path, self.results.parent)

    @staticmethod
    def group_alive(pgid):
        """Whether any non-zombie process remains in the group.

        Zombies do not count: an unreaped orphan (for example one adopted by a
        subreaper ancestor) must not make a killed group look alive.
        """
        proc = Path("/proc")
        if proc.is_dir():
            for entry in proc.glob("[0-9]*"):
                try:
                    text = (entry / "stat").read_text()
                except OSError:
                    continue
                fields = text[text.rfind(")") + 2:].split()
                if len(fields) > 2 and fields[2] == str(pgid) and fields[0] != "Z":
                    return True
            return False
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def stop_group(self, process, grace):
        """TERM, then KILL, the whole process group.

        Returns whether group members outlived an already-exited leader.
        """
        if process is None:
            return False
        pgid = process.pid
        outlived = process.poll() is not None and self.group_alive(pgid)
        if process.poll() is None or self.group_alive(pgid):
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                process.poll()
                if process.returncode is not None and not self.group_alive(pgid):
                    break
                time.sleep(0.05)
        if process.poll() is None or self.group_alive(pgid):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        deadline = time.monotonic() + 5
        while self.group_alive(pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if self.group_alive(pgid):
            raise RuntimeError("process group %d survived SIGKILL" % pgid)
        return outlived

    def spawn_bridge(self, directory):
        # Signal handlers only set a flag, so nothing can interrupt between
        # Popen returning and the caller taking ownership of the process.
        with open(directory / "bridge.log", "wb") as log:
            return subprocess.Popen(
                self.args.bridge_command + ["--ready-file", str(directory / "bridge-ready.json")],
                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True)

    def wait_for_bridge(self, process, directory):
        """Return None once ready, or a startup error; raises Interrupted."""
        ready = directory / "bridge-ready.json"
        deadline = time.monotonic() + self.args.bridge_start_timeout
        while time.monotonic() < deadline:
            self.check_signal()
            if process.poll() is not None:
                return "bridge exited with status %d before becoming ready" % process.returncode
            try:
                if json.loads(ready.read_text())["pid"] == process.pid:
                    return None
            except (FileNotFoundError, ValueError, KeyError):
                pass
            time.sleep(0.05)
        return "bridge did not become ready within %ds" % self.args.bridge_start_timeout

    # -- one scenario
    def run_scenario(self, result):
        name = result["name"]
        directory = self.results / ("%02d-%s" % (result["index"], name))
        directory.mkdir()
        # .NET named-pipe mutexes are Unix sockets in TMPDIR, whose paths are
        # limited to 108 bytes; keep a short private directory per scenario.
        private_tmp = tempfile.mkdtemp(prefix="mstss-", dir="/tmp")
        started = time.time()
        clock = time.monotonic()
        result.update(status="RUNNING", started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
                      directory=self.relative(directory),
                      console_log=self.relative(directory / "console.log"),
                      bridge_log=self.relative(directory / "bridge.log"),
                      timeout_seconds=self.args.scenario_timeout, timed_out=False,
                      interrupted=False, exit_code=None, reason="", report=None,
                      counts=None, infrastructure_counts=None, report_title=None)
        self.write()
        bridge = tester = start_error = None
        try:
            # Owned by this frame from the moment it exists; see finally.
            bridge = self.spawn_bridge(directory)
            result["bridge_pid"] = bridge.pid
            start_error = self.wait_for_bridge(bridge, directory)
            if start_error:
                result.update(status="ERROR", reason=start_error)
            else:
                env = dict(os.environ, TMPDIR=private_tmp)
                with open(directory / "console.log", "wb") as console:
                    tester = subprocess.Popen(self.args.tester_command + [name], cwd=directory,
                                              stdout=console, stderr=subprocess.STDOUT,
                                              stdin=subprocess.DEVNULL, env=env,
                                              start_new_session=True)
                result["tester_pid"] = tester.pid
                deadline = clock + self.args.scenario_timeout
                while tester.poll() is None:
                    self.check_signal()
                    if time.monotonic() >= deadline:
                        result["timed_out"] = True
                        break
                    time.sleep(0.05)
                result["exit_code"] = tester.poll()
                # A signal delivered as the tester exits still interrupts it.
                self.check_signal()
        except OSError as exc:
            start_error = "could not start %s: %s" % ("tester" if bridge else "bridge", exc)
            result.update(status="ERROR", reason=start_error)
        except Interrupted:
            result.update(status="INTERRUPTED", interrupted=True,
                          reason="whole-phase limit or signal %s stopped this scenario"
                          % signal_name(self.signal))
        finally:
            grace = 2 if self.signal is not None else self.args.kill_grace
            outlived = self.stop_group(tester, grace)
            if tester is not None and result["exit_code"] is None and not result["timed_out"]:
                result["exit_code"] = tester.returncode
            if tester is not None:
                result["tester_exit_code_after_cleanup"] = tester.returncode
            if outlived and result["status"] == "RUNNING":
                result["tester_left_processes"] = True
            shutil.rmtree(private_tmp, ignore_errors=True)
            bridge_died = bridge is not None and bridge.poll() is not None
            self.stop_group(bridge, grace)
            if bridge is not None:
                result["bridge_exit_code"] = bridge.returncode
                result["bridge_exited_during_scenario"] = bridge_died and not start_error
        result["duration_seconds"] = round(time.monotonic() - clock, 3)
        left_processes = result.pop("tester_left_processes", False)
        classify(result, name, directory, started)
        if result.get("bridge_exited_during_scenario"):
            result["reason"] = "; ".join(r for r in (
                "bridge exited with status %s during the scenario" % result["bridge_exit_code"],
                result["reason"]) if r)
            if result["status"] == "PASS":
                result["status"] = "ERROR"
        if left_processes:
            result["reason"] = "; ".join(r for r in (
                "tester left processes running after it exited", result["reason"]) if r)
            if result["status"] == "PASS":
                result["status"] = "ERROR"
        if result.get("report"):
            result["report"] = self.relative(directory / result["report"])
        return result

    def line(self, result):
        counts = result.get("counts") or {}
        detail = ("passed=%d failed=%d aborted=%d" % (counts["passed"], counts["failed"],
                                                      counts["aborted"]) if counts else "")
        reason = result.get("reason") or ""
        text = "[%2d/%d] %-30s %-11s %7.1fs  %s" % (
            result["index"], len(self.summary["scenarios"]), result["name"], result["status"],
            result.get("duration_seconds", 0.0), "; ".join(x for x in (detail, reason) if x))
        if result["status"] not in ("PASS", "NOT_RUN"):
            evidence = [result["console_log"], result["bridge_log"]]
            if result.get("report"):
                evidence.append(result["report"])
            text += "\n        evidence: " + ", ".join(evidence)
        return text

    def run(self):
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, self.on_signal)
        self.write()
        print("%s: %d scenario(s) in order: %s" % (SUITE, len(self.selection["order"]),
                                                  ", ".join(self.selection["order"])))
        print("%s: per-scenario timeout %ds; summary %s" % (
            SUITE, self.args.scenario_timeout, self.relative(self.results / "summary.json")),
            flush=True)
        for result in self.summary["scenarios"]:
            if self.signal is not None:
                break
            self.run_scenario(result)
            self.write()
            print(self.line(result), flush=True)
        for result in self.summary["scenarios"]:
            if result["status"] == "PENDING":
                result.update(status="NOT_RUN",
                              reason="not started: phase interrupted by %s"
                              % signal_name(self.signal))
        passed = all(r["status"] == "PASS" for r in self.summary["scenarios"])
        self.summary["complete"] = self.signal is None
        self.summary["interrupted_by"] = (signal_name(self.signal)
                                          if self.signal is not None else None)
        self.summary["status"] = ("INTERRUPTED" if self.signal is not None
                                  else "PASS" if passed else "FAIL")
        self.write()
        counts = self.summary["counts"]
        print("%s: %s -- %s" % (SUITE, self.summary["status"], ", ".join(
            "%s=%d" % (s, counts[s]) for s in STATUSES if s in counts)))
        for result in self.summary["scenarios"]:
            if result["status"] == "NOT_RUN":
                print(self.line(result))
        print("%s: details in %s" % (SUITE, self.relative(self.results / "summary.json")),
              flush=True)
        if self.signal is not None:
            return 128 + self.signal
        return 0 if passed else EXIT_FAIL


# ------------------------------------------------------------------- entry

def write_rejection(results, revision, requested, error, status="INVALID_SELECTION"):
    results.mkdir(parents=True, exist_ok=True)
    summary = {"suite": SUITE, "revision": revision, "status": status,
               "complete": False, "error": str(error), "requested": requested, "scenarios": []}
    (results / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


def raise_interrupted(signum, frame):
    raise Interrupted(signal_name(signum))


def command_run(args):
    results = Path(args.results)
    results.mkdir(parents=True, exist_ok=True)
    # Until the supervisor installs its own handlers, a signal aborts cleanly.
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, raise_interrupted)
    try:
        manifest = load_manifest(args.manifest)
        selection = resolve(manifest, args.filter)
        if args.source:
            check_source(manifest, args.source, args.revision)
            selection["source_metadata_check"] = "matched"
        if not args.skip_discovery:
            check_discovery(manifest, args.dotnet_command, results)
            selection["discovery_check"] = "matched"
    except (SelectionError, MetadataError, OSError, ValueError, KeyError) as error:
        print("%s: %s" % (SUITE, error), file=sys.stderr)
        write_rejection(results, args.revision, args.filter, error)
        return EXIT_USAGE
    except Interrupted as interrupted:
        write_rejection(results, args.revision, args.filter,
                        "interrupted by %s before any scenario started" % interrupted,
                        "INTERRUPTED")
        return EXIT_FAIL
    selection["manifest"] = str(args.manifest)
    (results / "selection.json").write_text(json.dumps(selection, indent=2) + "\n")
    return Supervisor(args, selection).run()


def command_resolve(args):
    try:
        selection = resolve(load_manifest(args.manifest), args.filter)
    except (SelectionError, MetadataError) as error:
        print("%s: %s" % (SUITE, error), file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps(selection, indent=2))
    return 0


def command_compare(args):
    """Compare two summary.json files by scenario name (e.g. Rust and reference C)."""
    left, right = (json.loads(Path(p).read_text()) for p in (args.left, args.right))
    by_name = [{r["name"]: r for r in s.get("scenarios", [])} for s in (left, right)]
    names = list(by_name[0]) + [n for n in by_name[1] if n not in by_name[0]]
    print("%-30s %-12s %-12s %s" % ("scenario", args.left_label, args.right_label, "same"))
    same_all = True
    for name in names:
        a, b = (m.get(name, {}) for m in by_name)
        key = lambda r: (r.get("status", "MISSING"), tuple(r.get("exceptions") or ()))
        same = key(a) == key(b)
        same_all &= same
        print("%-30s %-12s %-12s %s" % (name, a.get("status", "MISSING"),
                                         b.get("status", "MISSING"), "yes" if same else "NO"))
    return 0 if same_all else EXIT_FAIL


def positive(value):
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise argparse.ArgumentTypeError("must be a positive integer number of seconds")
    return int(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    manifest = Path(__file__).resolve().parent / "microsoft-tss.manifest.json"

    resolve_parser = commands.add_parser("resolve", help="print the resolved selection")
    resolve_parser.add_argument("--manifest", type=Path, default=manifest)
    resolve_parser.add_argument("--filter", default="")
    resolve_parser.set_defaults(handler=command_resolve)

    run = commands.add_parser("run", help="run each selected scenario in isolation")
    run.add_argument("--manifest", type=Path, default=manifest)
    run.add_argument("--filter", default="")
    run.add_argument("--results", required=True)
    run.add_argument("--revision", required=True)
    run.add_argument("--source", help="upstream checkout for the metadata cross-check")
    run.add_argument("--assembly", help="upstream Tpm2TestSuite.dll")
    run.add_argument("--library", help="libtpms shared library for the bridge")
    run.add_argument("--port", type=int, default=2321)
    run.add_argument("--platform-port", type=int, default=2322)
    run.add_argument("--dotnet-command", type=json.loads,
                     help="tests only: JSON argv replacing 'dotnet ASSEMBLY'")
    run.add_argument("--bridge-command", type=json.loads,
                     help="tests only: JSON argv replacing the bridge; --ready-file is appended")
    run.add_argument("--scenario-timeout", type=positive, default=120)
    run.add_argument("--bridge-start-timeout", type=positive, default=15)
    run.add_argument("--kill-grace", type=positive, default=5)
    run.add_argument("--skip-discovery", action="store_true",
                     help="tests only: do not run -tests/-profiles")
    run.set_defaults(handler=command_run)

    compare = commands.add_parser("compare", help="compare two summary.json files")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--left-label", default="left")
    compare.add_argument("--right-label", default="right")
    compare.set_defaults(handler=command_compare)

    args = parser.parse_args(argv)
    if args.command == "run":
        if args.dotnet_command is None:
            if not args.assembly:
                parser.error("--assembly is required")
            args.dotnet_command = ["dotnet", args.assembly]
        if args.bridge_command is None:
            if not args.library:
                parser.error("--library is required")
            args.bridge_command = [str(Path(__file__).resolve().parents[2] / "bridge.py"),
                                   "--library", args.library, "--port", str(args.port),
                                   "--platform-port", str(args.platform_port), "--trace-errors"]
        args.tester_command = args.dotnet_command + [
            "-device", "tcp", "-address", "127.0.0.1:%d" % args.port]
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
