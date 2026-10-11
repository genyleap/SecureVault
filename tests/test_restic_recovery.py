#!/usr/bin/env python3
"""Hermetic mock-Restic recovery tests; no real repository or database."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

RECOVERY = Path(__file__).resolve().parents[1] / "scripts" / "restic-recovery.py"
FILES_ID = "a" * 64
PG_ID = "b" * 64
MARIA_ID = "c" * 64

MOCK_RESTIC = """#!PYTHON
import json
import os
from pathlib import Path
import sys

kind_ids = {"files": "a" * 64, "postgresql": "b" * 64, "mariadb": "c" * 64}
snapshots = [
    {"id": value, "tags": ["securevault", kind, "20261011T090000Z"],
     "time": "2026-10-11T09:00:00Z"}
    for kind, value in kind_ids.items()
]
snapshots.append({"id": "d" * 64, "tags": ["irrelevant"]})
if os.environ.get("SV_MOCK_DROP_KIND"):
    snapshots = [s for s in snapshots if os.environ["SV_MOCK_DROP_KIND"] not in s["tags"]]
args = sys.argv[1:]
if args[:1] == ["snapshots"]:
    print(json.dumps(snapshots))
elif args[:1] == ["restore"]:
    stage = Path(args[args.index("--target") + 1])
    snapshot_id = args[1]
    if snapshot_id == kind_ids["files"]:
        location = stage / "var" / "www" / "example"
        location.mkdir(parents=True)
        (location / "index.txt").write_text("safe restoration")
    elif snapshot_id == kind_ids["postgresql"]:
        (stage / "postgresql-all.sql").write_text("SELECT 1;")
    elif snapshot_id == kind_ids["mariadb"]:
        (stage / "mariadb-all.sql").write_text("SELECT 2;")
    else:
        sys.exit(22)
    if os.environ.get("SV_MOCK_EXTRA_SQL"):
        (stage / "unexpected.txt").write_text("not part of a trusted SQL export")
    if os.environ.get("SV_MOCK_BAD_LINK"):
        (stage / "unsafe-link").symlink_to("/etc/passwd")
    if os.environ.get("SV_MOCK_RACE_DEST"):
        raced = Path(os.environ["SV_MOCK_RACE_DEST"])
        raced.mkdir()
        (raced / "sentinel").write_text("do not overwrite")
    if os.environ.get("SV_MOCK_FAIL_RESTORE"):
        sys.exit(19)
elif args[:1] == ["check"]:
    if os.environ.get("SV_MOCK_FAIL_CHECK"):
        sys.exit(20)
else:
    sys.exit(21)
""".replace("#!PYTHON", f"#!{sys.executable}")


class ResticRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="securevault-restic-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        restic = bin_dir / "restic"
        restic.write_text(MOCK_RESTIC)
        restic.chmod(0o700)
        password_file = self.base / "password"
        password_file.write_text("dummy-test-password")
        password_file.chmod(0o600)
        self.env = dict(os.environ)
        self.env.update({
            "PATH": str(bin_dir) + os.pathsep + self.env.get("PATH", ""),
            "RESTIC_REPOSITORY": "s3:fake-bucket-for-tests",
            "RESTIC_PASSWORD_FILE": str(password_file),
        })

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, str(RECOVERY), *map(str, arguments)],
            capture_output=True, text=True, timeout=30,
            cwd=self.base, env=self.env,
        )

    def test_list_contains_only_securevault_types(self):
        result = self.run_cli("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(FILES_ID, result.stdout)
        self.assertIn(PG_ID, result.stdout)
        self.assertIn(MARIA_ID, result.stdout)
        self.assertNotIn("d" * 64, result.stdout)

    def test_file_restore_stages_and_publishes(self):
        target = self.base / "new-recovery"
        result = self.run_cli("restore", "--snapshot", FILES_ID,
                              "--kind", "files", "--target", target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target / "var/www/example/index.txt").read_text(), "safe restoration")
        self.assertFalse(list(self.base.glob(".securevault-restic-*")))

    def test_existing_destination_is_never_replaced(self):
        target = self.base / "existing"
        target.mkdir()
        (target / "critical").write_text("keep me")
        result = self.run_cli("restore", "--snapshot", FILES_ID,
                              "--kind", "files", "--target", target)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((target / "critical").read_text(), "keep me")
        self.assertFalse(list(self.base.glob(".securevault-restic-*")))

    def test_database_restore_requires_explicit_plaintext_opt_in(self):
        target = self.base / "db-export"
        options = ("restore", "--snapshot", PG_ID, "--kind", "postgresql", "--target", target)
        denied = self.run_cli(*options)
        self.assertNotEqual(denied.returncode, 0)
        self.assertFalse(target.exists())
        allowed = self.run_cli(*options, "--allow-plaintext-export")
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        sql = target / "postgresql-all.sql"
        self.assertEqual(sql.read_text(), "SELECT 1;")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(sql.stat().st_mode), 0o600)

    def test_database_export_refuses_unexpected_files(self):
        self.env["SV_MOCK_EXTRA_SQL"] = "1"
        target = self.base / "unexpected-db-files"
        result = self.run_cli("restore", "--snapshot", PG_ID,
                              "--kind", "postgresql", "--target", target,
                              "--allow-plaintext-export")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SQL snapshot contents differ", result.stderr)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.base.glob(".securevault-restic-*")))

    def test_wrong_type_and_short_snapshot_id_are_rejected(self):
        for snapshot_id, kind in ((FILES_ID, "mariadb"), ("aaaa", "files")):
            with self.subTest(kind=kind, snapshot_id=snapshot_id):
                target = self.base / "uncreated"
                result = self.run_cli("restore", "--snapshot", snapshot_id,
                                      "--kind", kind, "--target", target)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(target.exists())

    def test_partial_restic_failure_leaves_no_destination(self):
        self.env["SV_MOCK_FAIL_RESTORE"] = "1"
        target = self.base / "absent"
        result = self.run_cli("restore", "--snapshot", FILES_ID,
                              "--kind", "files", "--target", target)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.base.glob(".securevault-restic-*")))

    def test_generation_completeness(self):
        good = self.run_cli("generations")
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertIn("20261011T090000Z  COMPLETE", good.stdout)
        self.env["SV_MOCK_DROP_KIND"] = "mariadb"
        partial = self.run_cli("generations")
        self.assertEqual(partial.returncode, 0, partial.stderr)
        self.assertIn("20261011T090000Z  INCOMPLETE", partial.stdout)

    def test_atomic_publish_refuses_racing_destination(self):
        target = self.base / "racing-target"
        self.env["SV_MOCK_RACE_DEST"] = str(target)
        result = self.run_cli("restore", "--snapshot", FILES_ID,
                              "--kind", "files", "--target", target)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((target / "sentinel").read_text(), "do not overwrite")
        self.assertFalse(list(self.base.glob(".securevault-restic-*")))

    def test_restore_rejects_absolute_symlink(self):
        if os.name == "nt":
            self.skipTest("Symlink creation is not available on this Windows runner")
        self.env["SV_MOCK_BAD_LINK"] = "1"
        target = self.base / "invalid-symlinks"
        result = self.run_cli("restore", "--snapshot", FILES_ID,
                              "--kind", "files", "--target", target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Symlink escapes", result.stderr)
        self.assertFalse(target.exists())

    def test_repository_check_failure_propagates(self):
        self.env["SV_MOCK_FAIL_CHECK"] = "1"
        result = self.run_cli("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("restic check failed", result.stderr)

    def test_secret_file_is_required_and_private(self):
        self.env.pop("RESTIC_PASSWORD_FILE")
        denied = self.run_cli("list")
        self.assertNotEqual(denied.returncode, 0)
        file = self.base / "insecure-password"
        file.write_text("test-only")
        file.chmod(0o644)
        self.env["RESTIC_PASSWORD_FILE"] = str(file)
        denied = self.run_cli("list")
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("group/world accessible", denied.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
