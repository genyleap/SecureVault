#!/usr/bin/env python3
"""Hermetic SecureVault integration tests. Never connect to live databases."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

BINARY = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else "backup"
sys.argv = [sys.argv[0]]


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="securevault-integration-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "hello.txt").write_text("critical backup data\n")
        os.chmod(self.source / "hello.txt", 0o640)
        (self.source / "empty-directory").mkdir()
        if os.name != "nt":
            (self.source / "relative-link").symlink_to("hello.txt")
        self.destination = self.root / "backups"
        self.config = self.root / "config.json"

    def configure(self, *, remote=False, databases=None, source=None):
        cfg = {
            "backup_base": str(self.destination) + "/",
            "backup_dirs": [str(source or self.source)],
            "exclude_extensions": [],
            "retention_days": 30,
            "databases": databases if databases is not None else [],
            "require_remote": remote,
            "schedule": {"type": "daily", "time": "03:00:00"},
        }
        self.config.write_text(json.dumps(cfg))

    def run_backup(self, *args, env=None):
        return subprocess.run(
            [BINARY, "--config", str(self.config), *args],
            text=True, capture_output=True, timeout=60,
            cwd=self.root, env=env,
        )

    def test_full_snapshot_preserves_paths_modes_and_links(self):
        self.configure()
        result = self.run_backup("daily")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        archives = list((self.destination / "sys").glob("*.tar.gz"))
        self.assertEqual(len(archives), 1)
        relative = self.source.relative_to("/")
        with tarfile.open(archives[0], "r:gz") as tar:
            names = set(tar.getnames())
            self.assertIn(str(relative / "hello.txt"), names)
            self.assertIn(str(relative / "empty-directory"), names)
            entry = tar.getmember(str(relative / "hello.txt"))
            self.assertEqual(entry.mode & 0o777, 0o640)
            self.assertEqual(tar.extractfile(entry).read(), b"critical backup data\n")
            if os.name != "nt":
                link = tar.getmember(str(relative / "relative-link"))
                self.assertTrue(link.issym())
                self.assertEqual(link.linkname, "hello.txt")

    def test_remote_requirement_fails_closed(self):
        self.configure(remote=True)
        result = self.run_backup("daily")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Remote backup required", result.stderr)
        self.assertFalse(list(self.destination.glob("sys/*.tar.gz")))

    def test_database_dump_failure_is_fatal(self):
        fakebin = self.root / "fakebin"
        fakebin.mkdir()
        binary = fakebin / ("mysqldump.exe" if os.name == "nt" else "mysqldump")
        binary.write_text("#!/bin/sh\nexit 23\n")
        os.chmod(binary, 0o755)
        self.configure(databases=[{"type": "mysql", "user": "test", "password": "", "host": "localhost", "port": 3306}])
        env = dict(os.environ)
        env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
        result = self.run_backup("daily", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Database backup failed", result.stderr)
        self.assertNotIn("Backup completed successfully", result.stdout)
        self.assertFalse(list(self.destination.glob("sys/*.tar.gz")))

    def test_file_only_cleanup_without_database_directory(self):
        """Missing db/ is normal when the backup profile has no databases."""
        self.configure(databases=[])
        result = self.run_backup("daily")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Backup completed successfully", result.stdout)
        self.assertFalse((self.destination / "db").exists())
        self.assertEqual(len(list((self.destination / "sys").glob("*.tar.gz"))), 1)

    def test_missing_source_is_fatal(self):
        self.configure(source=self.root / "does-not-exist")
        result = self.run_backup("daily")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Backup completed successfully", result.stdout)

    def test_unsafe_incremental_refused(self):
        self.configure()
        result = self.run_backup("--incremental", "daily")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incremental backups are disabled", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
