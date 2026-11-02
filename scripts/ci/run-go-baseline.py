"""Remote Actions only: retain failures, skips and raw Go JSON evidence."""
import collections
import json
import os
from pathlib import Path
import subprocess
import sys

if os.environ.get("GITHUB_ACTIONS") != "true":
    sys.exit("This baseline may only run in GitHub Actions; local execution is forbidden.")

root = Path(os.environ["RUNNER_TEMP"])
evidence = root / "p0-evidence"
source = root / "p0-source" / "apps" / "api"
module = os.environ["BASELINE_MODULE"]
tags = os.environ["SINGBOX_TAGS"]
if module == "api":
    suites = [
        ("public-config", ["-tags", tags, "-run", "^TestP0PublicConfig$", "./internal/transport/handler"]),
        ("focused", ["-tags", tags, "./internal/transport/handler", "./internal/transport/compose", "./internal/dbinfra"]),
        ("full-api", ["-tags", tags, "./..."]),
    ]
else:
    source = source / "modules" / "relaykit"
    suites = [("full-relaykit", ["./..."])]

version = subprocess.run(["go", "version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(evidence / "go-version.txt").write_text(version.stdout)
results = []
failed = version.returncode != 0
for name, arguments in suites:
    command = ["go", "test", "-json", "-count=1", "-timeout=8m", "-p=2", *arguments]
    counts = collections.Counter()
    skips = []
    with (evidence / f"{name}.jsonl").open("w") as output, (evidence / f"{name}.stderr.log").open("w") as errors:
        process = subprocess.Popen(command, cwd=source, stdout=subprocess.PIPE, stderr=errors, text=True)
        for line in process.stdout:
            output.write(line)
            output.flush()
            print(line, end="", flush=True)
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            action = event.get("Action")
            if action in ("pass", "fail", "skip"):
                kind = "test" if event.get("Test") else "package"
                counts[f"{kind}_{action}"] += 1
                if action == "skip":
                    skips.append({key: event.get(key) for key in ("Package", "Test")})
        exit_code = process.wait()
    # A zero exit with zero completed tests is not a meaningful baseline.
    meaningful = counts["test_pass"] + counts["test_fail"] > 0
    failed = failed or exit_code != 0 or not meaningful
    results.append(dict(suite=name, command=command, cwd=str(source), exit_code=exit_code,
                        meaningful=meaningful, counts=dict(counts), skips=skips))
    (evidence / "results.json").write_text(json.dumps(results, indent=2))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"### {name}\nExit: {exit_code}; completed tests present: {meaningful}\n\n")
        summary.write(f"```json\n{json.dumps(dict(counts), indent=2)}\n```\n")
        summary.write("Skipped tests are NOT accepted as database/provider coverage; inspect artifacts.\n")

sys.exit(1 if failed else 0)
