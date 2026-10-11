#!/usr/bin/env python3
"""Isolated PITR readiness and recovery-plan unit tests (no live database)."""
from __future__ import annotations

import contextlib
from datetime import datetime, timezone, timedelta
from io import StringIO
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pitr-readiness.py"
spec = importlib.util.spec_from_file_location("securevault_pitr_readiness", SCRIPT)
assert spec and spec.loader
pitr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pitr)


class ReadinessTests(unittest.TestCase):
    def test_postgres_good_preconditions_still_not_offsite_verified(self):
        state = {
            "wal_level": "replica", "archive_mode": "on",
            "archive_target_configured": True, "full_page_writes": "on",
            "archived_count": 12, "failed_count": 0,
        }
        with patch.object(pitr, "tool_exists", return_value=True):
            result = pitr.report_postgresql(state)
        self.assertTrue(result["local_prerequisites_met"])
        self.assertFalse(result["offsite_recovery_verified"])
        self.assertEqual(result["issues"], [])

    def test_postgres_unsafe_wal_settings_are_rejected(self):
        state = {
            "wal_level": "minimal", "archive_mode": "off",
            "archive_target_configured": False, "full_page_writes": "off",
            "archived_count": 0, "failed_count": 3,
        }
        with patch.object(pitr, "tool_exists", return_value=False):
            result = pitr.report_postgresql(state)
        self.assertFalse(result["local_prerequisites_met"])
        self.assertGreaterEqual(len(result["issues"]), 4)
        self.assertTrue(result["warnings"])

    def test_mariadb_enabled_and_tools_present_never_prove_offhost(self):
        state = {
            "log_bin": "ON", "binlog_format": "ROW", "server_id": "1",
            "binlog_expire_logs_seconds": "604800",
        }
        with patch.object(pitr, "tool_exists", return_value=True):
            result = pitr.report_mariadb(state)
        self.assertTrue(result["local_prerequisites_met"])
        self.assertFalse(result["offsite_recovery_verified"])

    def test_mariadb_missing_binlogs_and_tools_is_rejected(self):
        state = {"log_bin": "OFF", "binlog_format": "STATEMENT", "server_id": "0"}
        with patch.object(pitr, "tool_exists", return_value=False):
            result = pitr.report_mariadb(state)
        self.assertFalse(result["local_prerequisites_met"])
        self.assertGreaterEqual(len(result["issues"]), 3)
        self.assertTrue(any("ROW" in warning for warning in result["warnings"]))

    def test_probe_postgres_invokes_read_only_select_only(self):
        def mock_run(command, timeout=20):
            self.assertIn("-c", command)
            sql = command[command.index("-c") + 1]
            self.assertTrue(sql.lstrip().startswith("SELECT json_build_object"))
            self.assertNotIn("ALTER SYSTEM", sql)
            self.assertNotIn("pg_switch_wal", sql)
            return '{"wal_level":"replica","archive_mode":"on"}'
        with patch.object(pitr, "run_readonly", side_effect=mock_run):
            with patch.object(pitr, "tool_exists", return_value=False):
                with patch.object(pitr.os, "geteuid", return_value=1000):
                    self.assertEqual(pitr.probe_postgresql()["wal_level"], "replica")

    def test_probe_mariadb_only_reads_global_variables(self):
        def mock_run(command, timeout=20):
            sql = command[command.index("--execute") + 1]
            self.assertIn("SHOW GLOBAL VARIABLES", sql)
            self.assertNotIn("SET GLOBAL", sql)
            return "log_bin\tON\nbinlog_format\tROW\nserver_id\t1\n"
        with patch.object(pitr, "run_readonly", side_effect=mock_run):
            result = pitr.probe_mariadb()
        self.assertEqual(result["log_bin"], "ON")

    def test_no_probe_access_does_not_claim_readiness(self):
        with patch.object(pitr, "probe_postgresql", side_effect=RuntimeError()):
            with patch.object(pitr, "probe_mariadb", side_effect=RuntimeError()):
                report, code = pitr.audit()
        self.assertEqual(code, 2)
        self.assertFalse(report["postgresql"]["checked"])
        self.assertFalse(report["mariadb"]["checked"])
        self.assertEqual(set(report["probe_errors"]), {"postgresql", "mariadb"})

    def test_recovery_time_must_be_timezone_aware_and_in_past(self):
        with self.assertRaises(ValueError):
            pitr.parse_target_time("2026-01-01T12:00:00")
        with self.assertRaises(ValueError):
            pitr.parse_target_time("2999-01-01T12:00:00+00:00")
        self.assertEqual(
            pitr.parse_target_time("2024-02-10T13:00:00+03:30"),
            "2024-02-10 09:30:00+00",
        )

    def test_stanza_injection_is_rejected(self):
        with patch.object(pitr, "check_new_target", return_value="/isolated/fresh"):
            with self.assertRaises(ValueError):
                pitr.postgres_plan("test;rm -rf /", "2024-01-01T00:00:00Z", "/tmp/x")

    def test_postgres_plan_is_only_a_reviewed_argv(self):
        with patch.object(pitr, "check_new_target", return_value="/srv/securevault-recovery/db1"):
            result = pitr.postgres_plan(
                "main", "2024-01-01T09:00:00Z", "/srv/securevault-recovery/db1"
            )
        self.assertTrue(result["plan_only"])
        self.assertFalse(result["executed"])
        self.assertIn("--type=time", result["review_only_command_argv"])

    def test_mariadb_plan_is_not_an_automatic_binlog_replay(self):
        with patch.object(pitr, "check_new_target", return_value="/srv/securevault-recovery/maria1"):
            result = pitr.mariadb_plan(
                "2024-01-01T09:00:00Z", "/srv/securevault-recovery/maria1"
            )
        self.assertTrue(result["plan_only"])
        self.assertFalse(result["executed"])
        self.assertTrue(any("contiguous" in step for step in result["required_manual_steps"]))

    def test_restore_path_rejects_live_paths_and_existing_directory(self):
        for raw in ("/", "/etc", "/var/lib/mysql", "/var/lib/postgresql",
                    "/srv/securevault-recovery/../other"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                pitr.check_new_target(raw)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                pitr.check_new_target(tmp)
            with self.assertRaises(ValueError):
                pitr.check_new_target(tmp + "/new")

    def test_probe_error_does_not_expose_command_stderr(self):
        fail = subprocess.CompletedProcess(
            args=["psql"], returncode=1, stdout="",
            stderr="password=my-secret-token"
        )
        with patch.object(pitr.subprocess, "run", return_value=fail):
            with self.assertRaises(RuntimeError) as raised:
                pitr.run_readonly(["psql"])
        self.assertNotIn("my-secret-token", str(raised.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
