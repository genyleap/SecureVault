#!/usr/bin/env python3
"""Read-only PostgreSQL/MariaDB PITR preflight and isolated recovery planner.

Never modifies database settings, runs a backup, starts a restore, or
connects to a production database for any write. Intended for operators to
run explicitly; not activated as a service.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

POSTGRES_QUERY = """
SELECT json_build_object(
  'wal_level', current_setting('wal_level'),
  'archive_mode', current_setting('archive_mode'),
  'archive_target_configured',
    (current_setting('archive_command') <> '' OR
     current_setting('archive_library') <> ''),
  'full_page_writes', current_setting('full_page_writes'),
  'archived_count', (SELECT archived_count FROM pg_stat_archiver),
  'failed_count', (SELECT failed_count FROM pg_stat_archiver)
)::text;
""".strip()

MARIADB_QUERY = """
SHOW GLOBAL VARIABLES
WHERE Variable_name IN (
  'log_bin', 'binlog_format', 'server_id',
  'expire_logs_days', 'binlog_expire_logs_seconds'
);
""".strip()

STANZA_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
BLOCKED_ROOTS = (
    Path("/"), Path("/var/lib/mysql"), Path("/var/lib/postgresql"),
    Path("/etc"), Path("/boot"), Path("/opt"), Path("/var/www"),
)


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_readonly(command: list[str], timeout: int = 20) -> str:
    try:
        finished = subprocess.run(
            command, check=False, capture_output=True, text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        raise RuntimeError("Read-only probe could not be executed") from err
    if finished.returncode:
        # Suppress stderr; it may contain hostnames/usernames or passwords.
        raise RuntimeError("Read-only probe exited unsuccessfully")
    return finished.stdout.strip()


def probe_postgresql() -> dict[str, Any]:
    command = ["psql", "--no-psqlrc", "-X", "-A", "-t",
               "-v", "ON_ERROR_STOP=1", "-d", "postgres",
               "-c", POSTGRES_QUERY]
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0 and tool_exists("runuser"):
        command = ["runuser", "-u", "postgres", "--", *command]
    raw = run_readonly(command)
    try:
        values = json.loads(raw)
        if not isinstance(values, dict):
            raise ValueError()
        return values
    except ValueError as err:
        raise RuntimeError("PostgreSQL returned unexpected results") from err


def probe_mariadb() -> dict[str, str]:
    raw = run_readonly([
        "mariadb", "--batch", "--skip-column-names",
        "--execute", MARIADB_QUERY,
    ])
    values = {}
    for line in raw.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            raise RuntimeError("MariaDB returned unexpected results")
        values[parts[0].lower()] = parts[1]
    if not values:
        raise RuntimeError("MariaDB returned no server variables")
    return values


def report_postgresql(values: dict[str, Any] | None) -> dict[str, Any]:
    issues: list[str] = []
    warnings: list[str] = []
    if values is None:
        issues.append("Could not inspect PostgreSQL; no readiness conclusion possible")
        return {"checked": False, "issues": issues, "warnings": warnings}
    if str(values.get("wal_level", "")).lower() not in {"replica", "logical"}:
        issues.append("wal_level must be replica or logical for WAL-based recovery")
    if str(values.get("archive_mode", "")).lower() not in {"on", "always"}:
        issues.append("WAL archive_mode is not enabled")
    if values.get("archive_target_configured") is not True:
        issues.append("No PostgreSQL archive_command or archive_library is configured")
    if str(values.get("full_page_writes", "")).lower() != "on":
        issues.append("full_page_writes must be enabled for reliable WAL recovery")
    if not tool_exists("pgbackrest"):
        issues.append("pgBackRest executable was not found on this machine")
    if not values.get("archived_count"):
        warnings.append("No WAL archive success is visible in pg_stat_archiver")
    if values.get("failed_count"):
        warnings.append("pg_stat_archiver records WAL archive failures; investigate")
    warnings.append("Local checks cannot establish off-host WAL retention or PITR restorability")
    return {
        "checked": True, "local_prerequisites_met": not issues,
        "offsite_recovery_verified": False, "issues": issues, "warnings": warnings,
        "observed": {
            key: values.get(key) for key in
            ("wal_level", "archive_mode", "archive_target_configured",
             "full_page_writes", "archived_count", "failed_count")
        },
    }


def report_mariadb(values: dict[str, str] | None) -> dict[str, Any]:
    issues: list[str] = []
    warnings: list[str] = []
    if values is None:
        issues.append("Could not inspect MariaDB; no readiness conclusion possible")
        return {"checked": False, "issues": issues, "warnings": warnings}
    if str(values.get("log_bin", "")).upper() not in {"ON", "1"}:
        issues.append("MariaDB binary logging is disabled")
    if str(values.get("binlog_format", "")).upper() != "ROW":
        warnings.append("ROW binlog format is preferred for predictable PITR replay")
    try:
        if int(values.get("server_id", "0")) < 1:
            issues.append("MariaDB server_id is not configured")
    except ValueError:
        issues.append("MariaDB server_id is invalid")
    if not tool_exists("mariadb-backup"):
        issues.append("mariadb-backup executable was not found on this machine")
    if not (tool_exists("mariadb-binlog") or tool_exists("mysqlbinlog")):
        issues.append("mariadb-binlog/mysqlbinlog executable was not found")
    raw_retention = values.get("binlog_expire_logs_seconds")
    if raw_retention is not None:
        try:
            if int(raw_retention) < 86400 and int(raw_retention) != 0:
                warnings.append("Binlog retention is under one day; WAL/binlog shipping must keep up")
        except ValueError:
            warnings.append("Binlog retention could not be parsed")
    elif "expire_logs_days" in values:
        try:
            if float(values["expire_logs_days"]) < 1 and float(values["expire_logs_days"]) != 0:
                warnings.append("Binlog retention is under one day")
        except ValueError:
            warnings.append("Binlog retention could not be parsed")
    warnings.append("Local binlog settings do not prove off-host binlog archive continuity")
    return {
        "checked": True, "local_prerequisites_met": not issues,
        "offsite_recovery_verified": False, "issues": issues, "warnings": warnings,
        "observed": {
            key: values.get(key) for key in
            ("log_bin", "binlog_format", "server_id",
             "expire_logs_days", "binlog_expire_logs_seconds")
        },
    }


def audit() -> tuple[dict[str, Any], int]:
    errors: dict[str, str] = {}
    pg = None
    maria = None
    try:
        pg = probe_postgresql()
    except RuntimeError:
        errors["postgresql"] = "Read-only probe unavailable or permissions insufficient"
    try:
        maria = probe_mariadb()
    except RuntimeError:
        errors["mariadb"] = "Read-only probe unavailable or permissions insufficient"
    result = {
        "schema": "securevault.pitr.readiness.v1",
        "read_only": True,
        "changes_applied": False,
        "postgresql": report_postgresql(pg),
        "mariadb": report_mariadb(maria),
        "probe_errors": errors,
    }
    ok = (
        result["postgresql"].get("local_prerequisites_met") is True
        and result["mariadb"].get("local_prerequisites_met") is True
    )
    return result, 0 if ok else 2


def parse_target_time(raw: str) -> str:
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as err:
        raise ValueError("Recovery time must be ISO 8601 with a timezone") from err
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Recovery time must include an explicit timezone offset")
    parsed = parsed.astimezone(timezone.utc)
    if parsed >= datetime.now(timezone.utc):
        raise ValueError("Recovery target must be in the past")
    return parsed.strftime("%Y-%m-%d %H:%M:%S+00")


def check_new_target(raw: str) -> str:
    destination = Path(raw)
    if not destination.is_absolute():
        raise ValueError("Isolated restore directory must be an absolute path")
    if ".." in destination.parts:
        raise ValueError("Traversal is forbidden in restore path")
    resolved = destination.resolve(strict=False)
    if resolved in BLOCKED_ROOTS:
        raise ValueError("Cannot target a live production or system directory")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Restore destination must not exist")
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise ValueError("Restore parent must be an existing real directory")
    # A plan cannot guarantee the mount is independent from production.
    # Explicitly require a dedicated isolated staging root.
    if not str(resolved).startswith("/srv/securevault-recovery/"):
        raise ValueError("Use an isolated new directory below /srv/securevault-recovery/")
    return str(resolved)


def postgres_plan(stanza: str, target_time: str, destination: str) -> dict[str, Any]:
    if not STANZA_PATTERN.fullmatch(stanza):
        raise ValueError("Stanza must contain only letters, numbers, hyphens or underscores")
    time_utc = parse_target_time(target_time)
    restore_path = check_new_target(destination)
    return {
        "engine": "postgresql", "plan_only": True, "executed": False,
        "restore_target_utc": time_utc,
        "isolated_data_directory": restore_path,
        "preconditions": [
            "Use a fresh dedicated recovery host; PostgreSQL must be stopped there",
            "Validate pgBackRest repository backups and all archived WAL up to target time",
            "Use a dedicated pgBackRest configuration, stanza and repository credentials",
            "Never run this restore on a production PostgreSQL cluster",
            "Only after isolated restore, start it on an isolated socket/port and validate queries",
        ],
        "review_only_command_argv": [
            "pgbackrest", f"--stanza={stanza}", f"--pg1-path={restore_path}",
            "--type=time", f"--target={time_utc}", "--target-action=promote", "restore",
        ],
    }


def mariadb_plan(target_time: str, destination: str) -> dict[str, Any]:
    time_utc = parse_target_time(target_time)
    restore_path = check_new_target(destination)
    return {
        "engine": "mariadb", "plan_only": True, "executed": False,
        "restore_target_utc": time_utc,
        "isolated_data_directory": restore_path,
        "required_manual_steps": [
            "Select a compatible complete mariadb-backup physical base backup prior to target",
            "Verify its backup metadata, binlog filename/position or GTID and checksums",
            "Ensure a contiguous, independently retained set of binlogs covers the target",
            "Prepare the base backup in an isolated writable copy; never prepare the only backup",
            "Restore to a NEW isolated MariaDB data directory, with the service stopped",
            "Start isolated MariaDB, replay the verified binlog range only to the target time",
            "Validate data and application consistency; never overwrite production automatically",
        ],
        "note": "MariaDB time-based binlog replay is not universally transaction-exact; "
                "GTID/position and event boundaries must be checked by an operator.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("audit", help="Read-only server prerequisite checks")
    pg = commands.add_parser("plan-postgresql", help="Generate an isolated PG restore plan, do not execute")
    pg.add_argument("--stanza", required=True)
    pg.add_argument("--target-time", required=True)
    pg.add_argument("--dest", required=True)
    maria = commands.add_parser("plan-mariadb", help="Generate isolated MariaDB restore checklist")
    maria.add_argument("--target-time", required=True)
    maria.add_argument("--dest", required=True)
    args = parser.parse_args()
    try:
        if args.action == "audit":
            result, status = audit()
        elif args.action == "plan-postgresql":
            result, status = postgres_plan(args.stanza, args.target_time, args.dest), 0
        else:
            result, status = mariadb_plan(args.target_time, args.dest), 0
        print(json.dumps(result, indent=2, sort_keys=True))
        return status
    except (ValueError, OSError) as err:
        print(f"SecureVault PITR: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
