#!/usr/bin/env python3
"""Remote-only fixed Go handler oracle and real Rust process differential tests."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
    raise SystemExit("GitHub-hosted Actions only")
spec = importlib.util.spec_from_file_location("ci", Path(__file__).with_name("p1-ci.py"))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
SHA = "a508a866cd9d84b9b540f2b1e4c2f5c6814e478a"


def oracle():
    source = Path(os.environ["RUNNER_TEMP"]) / "p1-go-source"
    upstream = ci.ROOT / "upstream-reference"
    actual = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if actual != SHA:
        raise RuntimeError("upstream identity mismatch")
    shutil.copytree(upstream, source)
    module = source / "apps/api"
    (module / "web/dist").mkdir(parents=True, exist_ok=True)
    (module / "web/dist/index.html").touch()
    shutil.copyfile(ci.ROOT / "scripts/ci/p1-go-fixture_test.go.txt",
                    module / "internal/transport/handler/p1_go_fixture_test.go")
    env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="-mod=readonly",
               UPSTREAM_SHA=SHA, P1_GO_FIXTURE=str(ci.evidence() / "go-fixture.json"))
    command = ["go", "test", "-json", "-count=1", "-tags", "with_gvisor,with_wireguard,with_utls",
               "./internal/transport/handler", "-run", "^TestP1ExportPublicConfig$"]
    result = subprocess.run(command, cwd=module, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, check=False)
    (ci.evidence() / "go-oracle.log").write_text(ci.redact(result.stdout))
    events = []
    for line in result.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    counts = {action: sum(event.get("Action") == action and "Test" in event for event in events)
              for action in ("pass", "fail", "skip")}
    ci.write_json("go-oracle.json", {"upstream_sha": actual, "command": command,
                                    "exit_code": result.returncode, "tests": counts})
    if result.returncode or counts != {"pass": 1, "fail": 0, "skip": 0}:
        raise RuntimeError("upstream oracle failed; see artifact")


def port_available(port):
    with socket.socket() as connection:
        connection.settimeout(0.1)
        return connection.connect_ex(("127.0.0.1", port)) != 0


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def scenario(name, dsn, expected, forbidden):
    port = free_port()
    env = {key: value for key, value in os.environ.items()
           if key not in ("TEST_POSTGRES_DSN", "SQL_DSN", "LOG_SQL_DSN", "PORT")}
    env.update(PORT=str(port), SQL_DSN=dsn, SYNC_FREQUENCY="60")
    log = tempfile.TemporaryFile()
    process = subprocess.Popen([str(ci.ROOT / "target/debug/newapi-server")],
                               cwd=ci.ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    record = {"name": name, "passed": False, "http_checks": 0, "exit_code": None,
              "startup_port": port, "skip": 0}
    try:
        deadline = time.monotonic() + 20
        if expected is None:
            while process.poll() is None and time.monotonic() < deadline:
                if not port_available(port):
                    raise AssertionError("invalid startup unexpectedly listened")
                time.sleep(0.025)
            if process.poll() is None or process.returncode == 0 or not port_available(port):
                raise AssertionError("invalid startup did not fail closed")
        else:
            while port_available(port):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError("server did not become reachable")
                time.sleep(0.025)
            # These expected JSON objects/statuses are captured Go handler responses,
            # never a second hand-authored Rust expected envelope.
            for response in expected:
                url = f"http://127.0.0.1:{port}" + response["path"]
                with urllib.request.urlopen(url, timeout=5) as actual:
                    if actual.status != response["status"] or json.load(actual) != response["body"]:
                        raise AssertionError("Go/Rust response mismatch")
                record["http_checks"] += 1
            process.send_signal(signal.SIGTERM)
            if process.wait(timeout=10) != 0 or not port_available(port):
                raise AssertionError("SIGTERM was not graceful")
        record["passed"] = True
    except Exception as error:
        record["failure_type"] = type(error).__name__
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        record["exit_code"] = process.returncode
        log.seek(0)
        output = log.read().decode("utf-8", errors="replace")
        log.close()
        leaked = any(value and value in output for value in [dsn, *forbidden])
        record["secret_leak"] = leaked
        if leaked:
            record["passed"] = False
        # Never preserve accidentally leaked canary/DSN, even on a red test.
        for value in [dsn, *forbidden]:
            if value:
                output = output.replace(value, "[REDACTED]")
        (ci.evidence() / ("process-" + name + ".log")).write_text(ci.redact(output))
        ci.write_json("process-" + name + ".json", record)
    return record


def smoke():
    oracle_data = json.loads((ci.evidence() / "go-fixture.json").read_text())
    if oracle_data["upstream_sha"] != SHA or len(oracle_data["fixtures"]) != 7:
        raise RuntimeError("incomplete upstream oracle")
    if not ci.run("server-build", ci.cargo("build", "--locked", "-p", "newapi-server", "--bin", "newapi-server")):
        raise RuntimeError("server build failed")
    records = []
    with tempfile.TemporaryDirectory(prefix="p1-process-", dir=os.environ["RUNNER_TEMP"]) as directory:
        for fixture in oracle_data["fixtures"]:
            db = Path(directory) / (fixture["name"] + ".sqlite")
            with sqlite3.connect(db) as connection:
                connection.execute('CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)')
                connection.executemany('INSERT INTO options ("key", "value") VALUES (?, ?)', fixture["options"].items())
                connection.execute('INSERT INTO options ("key", "value") VALUES (?, ?)',
                                   ("PrivateCredential", "p1-private-option-canary-67341"))
            records.append(scenario(fixture["name"], "sqlite://" + str(db), fixture["responses"],
                                    ["p1-private-option-canary-67341"]))
        missing = Path(directory) / "no-table.sqlite"
        sqlite3.connect(missing).close()
        records.append(scenario("missing-table", "sqlite://" + str(missing), None, []))
        records.append(scenario("invalid-dsn", "mysql://p1-user:p1-secret-canary-98314@127.0.0.1/never", None,
                                ["p1-user", "p1-secret-canary-98314"]))
    passed = sum(record["passed"] for record in records)
    ci.write_json("process-tests.json", {"upstream_sha": SHA, "total": len(records), "passed": passed,
                                        "failed": len(records) - passed, "skipped": 0,
                                        "http_checks": sum(record["http_checks"] for record in records)})
    if passed != 9 or sum(record["http_checks"] for record in records) != 35:
        raise RuntimeError("process differential tests failed")


if __name__ == "__main__":
    try:
        {"oracle": oracle, "smoke": smoke}[sys.argv[1]]()
    except Exception as error:
        ci.write_json("process-driver-error.json", {"mode": sys.argv[1], "type": type(error).__name__, "exit_code": 1})
        raise SystemExit(1) from None
