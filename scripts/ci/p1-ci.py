#!/usr/bin/env python3
"""Actions-only P1 driver. Never invoke build/test modes on a developer host."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
TOOLCHAIN = "1.99.1"


def evidence():
    path = Path(os.environ["RUNNER_TEMP"]) / "p1-evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


def redact(text):
    for name in ("TEST_POSTGRES_DSN", "TEST_REDIS_URL", "SQL_DSN", "PGPASSWORD"):
        value = os.environ.get(name)
        if value:
            text = text.replace(value, "[REDACTED]")
    return re.sub(r"(?i)((?:postgres(?:ql)?|rediss?)://)[^\s\"']+", r"\1[REDACTED]", text)


def write_json(name, value):
    (evidence() / name).write_text(redact(json.dumps(value, indent=2)) + "\n")


def test_counts(text):
    rows = re.findall(
        r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; "
        r"(\d+) ignored; (\d+) measured; (\d+) filtered out", text
    )
    return dict(zip(("passed", "failed", "ignored", "measured", "filtered"),
                    (sum(int(row[i]) for row in rows) for i in range(5))))


def run(label, args, require_tests=False):
    started = time.monotonic()
    process = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, check=False)
    if label == "metadata":
        (evidence() / "cargo-metadata.json").write_text(redact(process.stdout))
    output = redact(process.stdout + process.stderr)
    (evidence() / (label + ".log")).write_text(output)
    print(output, end="", flush=True)
    counts = test_counts(output) if require_tests else None
    if label == "driver-tests":
        match = re.search(r"Ran (\d+) tests? in", output)
        counts = {"total": int(match[1]) if match else 0, "exit_code": process.returncode,
                  "skipped": 0 if "skipped=" not in output else "see log"}
    policy_ok = not require_tests or (
        counts["passed"] > 0 and counts["failed"] == 0 and counts["ignored"] == 0
    )
    write_json(label + ".json", {
        "command": args, "exit_code": process.returncode,
        "seconds": round(time.monotonic() - started, 3), "tests": counts,
        "policy_ok": policy_ok,
    })
    return process.returncode == 0 and policy_ok


def cargo(*args):
    return ["cargo", "+" + TOOLCHAIN, *args]


def init():
    for name in ("TEST_POSTGRES_DSN", "PGPASSWORD"):
        if os.environ.get(name):
            print("::add-mask::" + os.environ[name], flush=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if sha != os.environ["GITHUB_SHA"]:
        raise RuntimeError("checkout/event SHA mismatch")
    write_json("identity.json", {
        "sha": sha, "run_id": os.environ["GITHUB_RUN_ID"],
        "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "url": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}",
        "toolchain": TOOLCHAIN, "database": os.environ.get("P1_DATABASE"),
        "image": os.environ.get("P1_POSTGRES_IMAGE"),
        "runner_image": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
        "lock_committed": (ROOT / "Cargo.lock").exists(),
    })
    shutil.copyfile(ROOT / ".github/workflows/p1-rust.yml", evidence() / "workflow.yml")


def manifest_policy():
    baseline = tomllib.loads((ROOT / "tools/dependency-probe/Cargo.toml").read_text())["dependencies"]
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    expected = {"crates/config", "crates/storage", "crates/catalog", "apps/server",
                "crates/identity", "crates/security", "crates/relay", "crates/billing",
                "crates/i18n"}
    if set(root["workspace"]["members"]) != expected:
        raise RuntimeError("unexpected P1 workspace membership")
    if "tools/dependency-probe" not in root["workspace"].get("exclude", []):
        raise RuntimeError("dependency probe must remain excluded")
    shared = root["workspace"].get("dependencies", {})
    for path in [ROOT / "Cargo.toml", *(ROOT / p / "Cargo.toml" for p in sorted(expected))]:
        manifest = tomllib.loads(path.read_text())
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in manifest.get(section, {}).items():
                if isinstance(spec, dict) and spec.get("workspace"):
                    spec = shared[name]
                actual_name = spec.get("package", name) if isinstance(spec, dict) else name
                if actual_name in ("moka", "sqlx-mysql"):
                    raise RuntimeError("forbidden P1 dependency")
                if actual_name in baseline:
                    expected_version = baseline[actual_name]
                    if isinstance(expected_version, dict):
                        expected_version = expected_version["version"]
                    version = spec.get("version") if isinstance(spec, dict) else spec
                    if version != expected_version:
                        raise RuntimeError("dependency differs from fixed probe version")
                if actual_name == "redis" and (not isinstance(spec, dict) or
                        spec.get("version") != "=0.32.7" or spec.get("default-features", True) or
                        set(spec.get("features", [])) != {"tokio-comp", "script"}):
                    raise RuntimeError("Redis must use fixed version and approved features")
                if actual_name == "sqlx" and (not isinstance(spec, dict) or
                        spec.get("default-features", True) or "mysql" in spec.get("features", [])):
                    raise RuntimeError("SQLx defaults/MySQL must be disabled")
    write_json("manifest-policy.json", {"exit_code": 0, "members": sorted(expected)})


def refresh_requested():
    return (os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("P1_REFRESH_LOCK") == "true")


def lock_command(exists):
    if refresh_requested():
        return "update" if exists else "generate-lockfile"
    if not exists:
        raise RuntimeError("root lock missing; explicit refresh_lock dispatch required")
    return None


def prepare():
    manifest_policy()
    lock = ROOT / "Cargo.lock"
    exists = lock.exists()
    refresh = refresh_requested()
    write_json("lock-status.json", {
        "generated": not exists and refresh, "refreshed": refresh,
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "requires_recovery_and_locked_rerun": refresh,
        "previous_sha256": hashlib.sha256(lock.read_bytes()).hexdigest() if exists else None,
    })
    command = lock_command(exists)
    if command and not run(command, cargo(command)):
        return False
    shutil.copyfile(lock, evidence() / "Cargo.lock")
    ok = True
    for label, args in (
        ("metadata", ("metadata", "--locked", "--format-version", "1")),
        ("tree", ("tree", "--locked")),
        ("features", ("tree", "--locked", "--edges", "features")),
    ):
        ok = run(label, cargo(*args)) and ok
    # Preserve exact manifests, not just their filenames or a dependency summary.
    for source in [ROOT / "Cargo.toml", *ROOT.glob("crates/*/Cargo.toml"),
                   *ROOT.glob("apps/*/Cargo.toml"), ROOT / "tools/dependency-probe/Cargo.toml"]:
        target = evidence() / "manifests" / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return ok


def request_json(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=45) as response:
        return json.load(response)


def images():
    # Read-only anonymous Docker Official Images registry authentication.
    result = {}
    for key, repository, tag in (("pg14", "postgres", "14"), ("pg17", "postgres", "17"),
                                 ("redis", "redis", "7.2.17-bookworm")):
        token = request_json("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/"
                             + repository + ":pull")["token"]
        req = urllib.request.Request(
            f"https://registry-1.docker.io/v2/library/{repository}/manifests/" + tag,
            headers={"Authorization": "Bearer " + token,
                     "Accept": "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json"})
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read()
            digest = response.headers["Docker-Content-Digest"]
        if digest != "sha256:" + hashlib.sha256(body).hexdigest():
            raise RuntimeError("registry manifest digest mismatch")
        manifest = json.loads(body)
        if not any(m.get("platform", {}).get("os") == "linux" and
                   m.get("platform", {}).get("architecture") == "amd64"
                   for m in manifest.get("manifests", [])):
            raise RuntimeError("required linux/amd64 official image is unavailable")
        (evidence() / (key + "-manifest.json")).write_bytes(body)
        result[key] = {"repository": "library/" + repository, "tag": tag,
                       "digest": digest, "image": repository + "@" + digest}
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"{key}={repository}@{digest}\n")
    write_json("registry.json", result)
    return True


def restore():
    prepared = Path(os.environ["RUNNER_TEMP"]) / "p1-prepare"
    identity = json.loads((prepared / "identity.json").read_text())
    for key, env in (("sha", "GITHUB_SHA"), ("run_id", "GITHUB_RUN_ID"), ("attempt", "GITHUB_RUN_ATTEMPT")):
        if identity[key] != os.environ[env]:
            raise RuntimeError("artifact identity mismatch")
    source = prepared / "Cargo.lock"
    checksum_line = next(line for line in (prepared / "SHA256SUMS").read_text().splitlines()
                         if line.endswith("  Cargo.lock"))
    if hashlib.sha256(source.read_bytes()).hexdigest() != checksum_line.split()[0]:
        raise RuntimeError("artifact lock checksum mismatch")
    status = json.loads((prepared / "lock-status.json").read_text())
    if bool(status.get("refreshed")) != refresh_requested():
        raise RuntimeError("artifact refresh authorization mismatch")
    if (ROOT / "Cargo.lock").exists() and source.read_bytes() != (ROOT / "Cargo.lock").read_bytes():
        if not refresh_requested() or not status.get("requires_recovery_and_locked_rerun"):
            raise RuntimeError("prepared lock differs from committed lock")
        if status.get("previous_sha256") != hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest():
            raise RuntimeError("refresh artifact does not match original committed lock")
    shutil.copyfile(source, ROOT / "Cargo.lock")
    shutil.copyfile(prepared / "lock-status.json", evidence() / "lock-status.json")
    return True


UPSTREAM_SHA = "ec542e7050932b82a2c087004ce54131ea67a836"


def p2_oracle():
    reference = ROOT / "upstream-reference"
    actual = subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip()
    if actual != UPSTREAM_SHA:
        raise RuntimeError("upstream SHA mismatch")
    source = Path(os.environ["RUNNER_TEMP"]) / "p2-oracle-source"
    shutil.copytree(reference, source)
    module = source / "apps/api"
    (module / "web/dist").mkdir(parents=True, exist_ok=True)
    (module / "web/dist/index.html").touch()
    success = True
    for kind, package in (("crypto", "identity"), ("origin", "security"), ("session-key", "identity")):
        template = ROOT / f"scripts/ci/p2-{kind}-oracle_test.go.txt"
        text = template.read_text()
        if not re.search(r"(?m)^package\s+" + package + r"\s*$", text):
            raise RuntimeError("oracle template package mismatch")
        names = re.findall(r"(?m)^func\s+(TestP2\w*Oracle\w*)\s*\(t\s+\*testing.T\)", text)
        if len(names) != 1:
            raise RuntimeError("oracle requires exactly one P2 oracle entry test")
        test = names[0]
        shutil.copyfile(template, module / f"internal/{package}/p2_{kind}_oracle_test.go")
        shutil.copyfile(template, evidence() / template.name)
        destination = evidence() / f"p2-{kind}-oracle.jsonl"
        env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="-mod=readonly",
                   UPSTREAM_SHA=UPSTREAM_SHA)
        env[f"P2_{kind.upper().replace('-', '_')}_ORACLE_PATH"] = str(destination)
        command = ["go", "test", "-json", "-count=1", "-tags", "with_gvisor,with_wireguard,with_utls",
                   f"./internal/{package}", "-run", "^" + test + "$"]
        result = subprocess.run(command, cwd=module, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, check=False)
        (evidence() / f"p2-{kind}-go.log").write_text(redact(result.stdout))
        events = []
        for line in result.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        counts = {action: sum(event.get("Action") == action and "Test" in event for event in events)
                  for action in ("pass", "fail", "skip")}
        root_pass = any(event.get("Action") == "pass" and event.get("Test") == test for event in events)
        # The actual Origin template exports t.Logf records. Preserve actual values.
        marker = f"P2_{kind.upper().replace('-', '_')}_ORACLE "
        records = []
        for event in events:
            output = event.get("Output", "")
            if marker in output:
                records.append(json.loads(output.split(marker, 1)[1].strip()))
        if records:
            if destination.exists():
                raise RuntimeError("ambiguous oracle output: both file and markers")
            destination.write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records))
        valid = destination.exists() and bool(destination.read_text().strip())
        if valid:
            raw = destination.read_text()
            try:
                valid = bool(json.loads(raw))
            except json.JSONDecodeError:
                valid = bool([json.loads(line) for line in raw.splitlines() if line.strip()])
        ok = result.returncode == 0 and root_pass and counts["fail"] == 0 and counts["skip"] == 0 and valid
        write_json(f"p2-{kind}-oracle-command.json", {
            "upstream_sha": actual, "package": package, "test": test, "command": command,
            "exit_code": result.returncode, "tests": counts, "fixture_valid": valid,
            "marker_records": len(records), "policy_ok": ok,
        })
        success = ok and success
    write_json("p2-oracle-source.json", {"upstream_sha": actual, "policy_ok": success})
    return success


def p2_restore_oracle():
    prepared = Path(os.environ["RUNNER_TEMP"]) / "p2-oracle"
    identity = json.loads((prepared / "identity.json").read_text())
    for key, env in (("sha", "GITHUB_SHA"), ("run_id", "GITHUB_RUN_ID"), ("attempt", "GITHUB_RUN_ATTEMPT")):
        if identity[key] != os.environ[env]:
            raise RuntimeError("oracle artifact identity mismatch")
    source = json.loads((prepared / "p2-oracle-source.json").read_text())
    if source != {"upstream_sha": UPSTREAM_SHA, "policy_ok": True}:
        raise RuntimeError("oracle source or execution failed")
    checksums = dict(line.split("  ", 1)[::-1] for line in (prepared / "SHA256SUMS").read_text().splitlines())
    for kind in ("crypto", "origin", "session-key"):
        name = f"p2-{kind}-oracle.jsonl"
        path = prepared / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != checksums[name] or not path.stat().st_size:
            raise RuntimeError("oracle checksum mismatch or empty fixture")
        shutil.copyfile(path, evidence() / name)
        with open(os.environ["GITHUB_ENV"], "a") as output:
            output.write(f"P2_{kind.upper().replace('-', '_')}_ORACLE_PATH={path}\n")
    shutil.copyfile(prepared / "p2-oracle-source.json", evidence() / "p2-oracle-source.json")
    write_json("p2-oracle-restore.json", {"exit_code": 0, "identity": identity, "upstream_sha": UPSTREAM_SHA})
    return True


def redis_version_matches(text):
    return re.search(r"(?m)^redis_version:7\.2\.17\r?$", text) is not None


def verify():
    if not os.environ.get("TEST_REDIS_URL"):
        raise RuntimeError("Redis fixture URL is mandatory, not a skip condition")
    print("::add-mask::" + os.environ["TEST_REDIS_URL"], flush=True)
    for kind in ("CRYPTO", "ORIGIN", "SESSION_KEY"):
        path = os.environ.get(f"P2_{kind}_ORACLE_PATH")
        if not path or not Path(path).is_file() or not Path(path).stat().st_size:
            raise RuntimeError("verified P2 oracle fixture is mandatory")
    if not os.environ.get("TEST_POSTGRES_DSN"):
        raise RuntimeError("PostgreSQL fixture DSN is mandatory, not a skip condition")
    print("::add-mask::" + os.environ["TEST_POSTGRES_DSN"], flush=True)
    ok = run("postgres-version", ["docker", "exec", os.environ["P1_POSTGRES_CONTAINER"],
             "psql", "-U", "p1_test", "-d", "p1_test", "-Atc", "SHOW server_version"])
    version = (evidence() / "postgres-version.log").read_text().strip()
    expected = os.environ["P1_POSTGRES_MAJOR"]
    version_ok = version.startswith(expected + ".") or version.startswith(expected + " ")
    write_json("postgres-version-policy.json", {"expected": expected, "actual": version, "policy_ok": version_ok})
    ok = version_ok and ok
    redis_ok = run("redis-version", ["docker", "exec", os.environ["P2_REDIS_CONTAINER"],
                   "redis-cli", "--raw", "INFO", "server"])
    redis_version_ok = redis_version_matches((evidence() / "redis-version.log").read_text())
    write_json("redis-version-policy.json", {
        "expected": "7.2.17", "policy_ok": redis_ok and redis_version_ok,
        "image": os.environ["P2_REDIS_IMAGE"],
    })
    ok = redis_ok and redis_version_ok and ok
    ok = run("driver-tests", ["python3", "scripts/ci/p1-ci-test.py"]) and ok
    for label, command in (
        ("rustc", ["rustc", "+" + TOOLCHAIN, "--version", "--verbose"]),
        ("check", cargo("check", "--locked", "--workspace")),
        ("fmt", cargo("fmt", "--all", "--check")),
        ("clippy", cargo("clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings")),
        ("metadata", cargo("metadata", "--locked", "--format-version", "1")),
        ("features", cargo("tree", "--locked", "--edges", "features")),
    ):
        ok = run(label, command) and ok
    ok = run("workspace-tests", cargo("test", "--locked", "--workspace"), True) and ok
    ok = run("origin-oracle-tests", cargo("test", "--locked", "-p", "newapi-security",
             "--test", "origin_oracle", "origin_matches_go_oracle", "--", "--exact"), True) and ok
    ok = run("session-cache-tests", cargo("test", "--locked", "-p", "newapi-identity",
             "--test", "session_cache", "--", "--test-threads=1"), True) and ok
    # Positive counts per backend AND owning module prevent all-filtered false greens.
    for package in ("newapi-storage", "newapi-catalog", "newapi-identity"):
        for backend in ("sqlite", "postgres"):
            ok = run(f"{package}-{backend}", cargo("test", "--locked", "-p", package,
                     backend + "_", "--", "--test-threads=1"), True) and ok
    return ok


def finalize():
    write_json("steps.json", json.loads(os.environ.get("STEPS_JSON", "{}")))
    write_json("job-status.json", {"status": os.environ.get("JOB_STATUS", "unknown")})
    if (ROOT / "Cargo.lock").exists():
        shutil.copyfile(ROOT / "Cargo.lock", evidence() / "Cargo.lock")
    expected = ["generate-lockfile", "update", "metadata", "tree", "features"] if os.environ["GITHUB_JOB"] == "prepare" else [
        "postgres-version", "driver-tests", "rustc", "check", "fmt", "clippy", "metadata", "features", "workspace-tests",
        "newapi-storage-sqlite", "newapi-storage-postgres", "newapi-catalog-sqlite", "newapi-catalog-postgres",
        "newapi-identity-sqlite", "newapi-identity-postgres"]
    if os.environ["GITHUB_JOB"] == "process":
        expected = ["go-oracle", "server-build", "process-tests"]
    elif os.environ["GITHUB_JOB"] == "oracle":
        expected = ["p2-crypto-oracle-command", "p2-origin-oracle-command"]
    elif os.environ["GITHUB_JOB"] == "verify":
        expected.extend(["p2-oracle-restore", "origin-oracle-tests", "redis-version", "session-cache-tests"])
    write_json("command-status.json", {name: "recorded" if (evidence() / (name + ".json")).exists()
                                      else "not-executed (see steps/lock-status)" for name in expected})
    lines = []
    for path in sorted(evidence().rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(evidence())))
    (evidence() / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return True


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("P1 driver is restricted to GitHub-hosted Actions; no local execution")
    handlers = {"init": init, "prepare": prepare, "images": images,
                "restore": restore, "verify": verify, "finalize": finalize,
                "p2-oracle": p2_oracle, "p2-restore-oracle": p2_restore_oracle}
    try:
        result = handlers[sys.argv[1]]()
    except Exception as error:
        # Do not stringify exceptions: subprocess/database/network errors can contain credentials.
        write_json("driver-error.json", {"mode": sys.argv[1], "type": type(error).__name__, "exit_code": 1})
        raise SystemExit(1) from None
    raise SystemExit(1 if result is False else 0)


if __name__ == "__main__":
    main()
