#!/usr/bin/env python3
"""Driver regression tests; invoked by p1-rust.yml only."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
    raise SystemExit("Tests are restricted to GitHub-hosted Actions")

spec = importlib.util.spec_from_file_location("p1_ci", Path(__file__).with_name("p1-ci.py"))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class EvidenceTests(unittest.TestCase):
    def test_aggregate_all_test_binaries(self):
        text = "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out\n"
        text += "test result: FAILED. 2 passed; 1 failed; 3 ignored; 0 measured; 0 filtered out\n"
        self.assertEqual(ci.test_counts(text), {
            "passed": 6, "failed": 1, "ignored": 3, "measured": 0, "filtered": 2,
        })

    def test_zero_tests_is_not_positive_evidence(self):
        self.assertEqual(ci.test_counts("compilation failed")["passed"], 0)
        self.assertEqual(ci.test_counts(
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out"
        )["passed"], 0)

    def test_redact_dsn_and_environment_secret(self):
        with patch.dict(os.environ, {"TEST_POSTGRES_DSN": "postgres://user:password@host/db",
                                     "PGPASSWORD": "fixture-password"}):
            text = ci.redact("postgres://user:password@host/db fixture-password")
        self.assertNotIn("password", text)
        self.assertNotIn("host", text)

    def test_redact_unexpected_postgres_url(self):
        self.assertEqual(ci.redact('error: "postgresql://other:secret@host/db"'),
                         'error: "postgresql://[REDACTED]"')

    def test_redis_url_redaction(self):
        with patch.dict(os.environ, {"TEST_REDIS_URL": "redis://127.0.0.1:12345/0"}):
            self.assertEqual(ci.redact(os.environ["TEST_REDIS_URL"]), "[REDACTED]")
        self.assertEqual(ci.redact('"rediss://user:secret@remote/0"'),
                         '"rediss://[REDACTED]"')

    def test_exact_redis_server_version(self):
        self.assertTrue(ci.redis_version_matches("# Server\r\nredis_version:7.2.17\r\n"))
        self.assertFalse(ci.redis_version_matches("redis_version:7.2.170\n"))
        self.assertFalse(ci.redis_version_matches("redis_version:7.4.12\n"))
        self.assertFalse(ci.redis_version_matches("ERR connection refused"))

    def test_session_cache_uses_real_binary_without_name_filter(self):
        self.assertEqual(ci.cargo("test", "--locked", "-p", "newapi-identity",
                                  "--test", "session_cache", "--", "--test-threads=1"),
                         ["cargo", "+1.99.1", "test", "--locked", "-p", "newapi-identity",
                          "--test", "session_cache", "--", "--test-threads=1"])

    def test_push_cannot_refresh_even_with_environment_flag(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "push", "P1_REFRESH_LOCK": "true"}):
            self.assertFalse(ci.refresh_requested())
            self.assertIsNone(ci.lock_command(True))
            with self.assertRaises(RuntimeError):
                ci.lock_command(False)

    def test_dispatch_default_is_locked(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "P1_REFRESH_LOCK": "false"}):
            self.assertIsNone(ci.lock_command(True))
            with self.assertRaises(RuntimeError):
                ci.lock_command(False)

    def test_explicit_dispatch_updates_existing_or_generates_missing(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "P1_REFRESH_LOCK": "true"}):
            self.assertTrue(ci.refresh_requested())
            self.assertEqual(ci.lock_command(True), "update")
            self.assertEqual(ci.lock_command(False), "generate-lockfile")

    def test_fixed_toolchain_and_locked_command(self):
        self.assertEqual(ci.cargo("test", "--locked", "--workspace"),
                         ["cargo", "+1.99.1", "test", "--locked", "--workspace"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
