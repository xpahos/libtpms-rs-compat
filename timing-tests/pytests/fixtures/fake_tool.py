import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATES = {0: "completed", 3: "incomplete", 4: "failed"}
RANK = {"completed": 0, "incomplete": 1, "failed": 2}


def scenario():
    path = HERE / "scenario.json"
    return json.loads(path.read_text()) if path.is_file() else {}


def option(args, name):
    values = [args[i + 1] for i, a in enumerate(args) if a == name and i + 1 < len(args)]
    return values


def counter(name):
    path = HERE / f"count-{name}"
    value = int(path.read_text()) + 1 if path.exists() else 1
    path.write_text(str(value))
    return value


def make_run(out, command, state, extra=None):
    run_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{command}-{os.getpid():x}{counter('runs'):04x}"
    run = Path(out) / run_id
    run.mkdir(parents=True)
    (run / "run.json").write_text(json.dumps({"format": "tpms-timing-run/v1", "run_id": run_id, "command": command, "state": state, "detail": (extra or {}).get("detail")}))
    (run / "manifest.json").write_text(json.dumps({"host": {"exploratory": True}}))
    (run / "argv.json").write_text(json.dumps(sys.argv[1:]))
    used = {"tool_fixture": str(HERE)}
    for flag in ("--rust-lib", "--reference-lib"):
        values = option(sys.argv[1:], flag)
        if values:
            data = Path(values[0]).read_bytes()
            used[flag] = {"path": values[0], "sha256": hashlib.sha256(data).hexdigest(), "content": data.decode(errors="replace").strip()}
    (run / "used.json").write_text(json.dumps(used))
    return run


def hang(key):
    child = subprocess.Popen(["sleep", "300"])
    (HERE / "hang.json").write_text(json.dumps({"stage": key, "tool": os.getpid(), "grandchild": child.pid}))
    while True:
        time.sleep(1)


def main():
    args = sys.argv[1:]
    commands = [a for a in args if a in ("self-test", "search", "verify", "replay", "report")]
    command = commands[0]
    plan = scenario()
    if command == "report":
        if plan.get("hang") == "report":
            hang("report")
        out = Path(option(args, "--output")[0])
        index = args.index("report")
        runs = []
        for value in args[index + 1:]:
            if value == "--output":
                break
            runs.append(Path(value))
        spec = plan.get("report", {})
        if spec.get("exit", 0) != 0:
            print("fake report failed", file=sys.stderr)
            return spec["exit"]
        overall = "completed"
        for run in runs:
            state = json.loads((run / "run.json").read_text())["state"]
            state = state if state in RANK else "incomplete"
            overall = state if RANK[state] > RANK[overall] else overall
        out.mkdir(parents=True, exist_ok=True)
        body = {"overall_outcome": spec.get("overall", overall), "runs": [{"exploratory": True} for _ in runs], "inputs": [str(r) for r in runs]}
        text = json.dumps(body)
        if spec.get("malformed") == "json":
            text = text[: len(text) // 2]
        elif spec.get("malformed") == "structure":
            text = json.dumps({"overall_outcome": "excellent", "runs": "all of them"})
        elif spec.get("malformed") == "list":
            text = json.dumps([body])
        (out / "report.json").write_text(text)
        (out / "report.md").write_text(f"# fake report\n\noverall {overall}\n")
        return 0
    if plan.get("compile_probe") and command == "self-test" and "CC" in os.environ:
        result = subprocess.run([os.environ["CC"], "-c", str(HERE / "cc_probe.c"), "-o", os.devnull], capture_output=True, text=True)
        (HERE / "cc-probe-worker.json").write_text(json.dumps({"cc": os.environ["CC"], "exit": result.returncode, "stderr": result.stderr}))
        if result.returncode != 0:
            print(f"worker compile with CC failed: {result.stderr}", file=sys.stderr)
            return 4
    key = command
    if command == "search":
        key = f"search-{option(args, '--backend')[0]}"
    spec = dict(plan.get(key, {}))
    if command == "replay":
        index = counter("replay")
        spec = dict(plan.get("replay", {}))
        if spec.get("fail_index") == index:
            spec["exit"] = 4
    out = Path(option(args, "--out-dir")[0])
    code = spec.get("exit", 0)
    state = spec.get("state", STATES.get(code, "failed"))
    if plan.get("decoy") and command == "search":
        make_run(HERE / "shared-runs", "search", "completed")
    runs = [make_run(out, command, "in-progress" if plan.get("hang") == key else state, {"detail": spec.get("detail")}) for _ in range(spec.get("runs", 1))]
    run = runs[0] if runs else None
    if command == "verify" and run is not None:
        candidates = run / "candidates"
        candidates.mkdir()
        results = []
        for i in range(spec.get("candidates", 2)):
            path = candidates / f"control-positive-{i:024d}.json"
            path.write_text(json.dumps({"format": "tpms-timing-candidate/v2", "id": f"rust-e{i:05d}"}))
            results.append({"artifact": path.stem, "candidate_file": str(path)})
        (run / "results.json").write_text(json.dumps({"format": "tpms-timing-verify-results/v2", "outcome": state, "results": results}))
    if plan.get("hang") == key:
        hang(key)
    if plan.get("leak") == key:
        leaked = subprocess.Popen(["sleep", "300"])
        (HERE / "leak.json").write_text(json.dumps({"stage": key, "tool": os.getpid(), "leaked": leaked.pid}))
    if plan.get("crash") == key:
        os.abort()
    print(f"fake {key} finished with exit {code}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
