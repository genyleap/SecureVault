#!/usr/bin/env python3
"""Read-only Restic inventory/check and isolated SecureVault recovery.

Does not initialize, forget, prune, unlock or modify a Restic repository.
Does not import SQL into a database and never restores over an existing path.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

KINDS = ("files", "postgresql", "mariadb")
ID_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")


class RecoveryError(Exception):
    pass


def repository_preflight() -> None:
    if not os.environ.get("RESTIC_REPOSITORY"):
        raise RecoveryError("RESTIC_REPOSITORY must identify an existing repository")
    secret_path = os.environ.get("RESTIC_PASSWORD_FILE")
    if not secret_path:
        raise RecoveryError("RESTIC_PASSWORD_FILE is required (do not pass passwords on CLI)")
    secret = Path(secret_path)
    if not secret.is_file() or not os.access(secret, os.R_OK):
        raise RecoveryError("RESTIC_PASSWORD_FILE is not a readable regular file")
    if os.name == "posix" and (secret.stat().st_mode & 0o077):
        raise RecoveryError("RESTIC_PASSWORD_FILE must not be group/world accessible")
    if shutil.which("restic") is None:
        raise RecoveryError("restic executable is unavailable")


def restic(*args: str, capture: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["restic", *args],
        text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        # Do not accidentally echo a storage token embedded in a URL or error.
        raise RecoveryError(f"restic {args[0]} failed (exit {result.returncode})")
    return result


def securevault_snapshots() -> list[dict[str, Any]]:
    result = restic("snapshots", "--json", "--tag", "securevault")
    try:
        entries = json.loads(result.stdout)
    except (ValueError, TypeError) as error:
        raise RecoveryError("Restic returned invalid snapshots JSON") from error
    if not isinstance(entries, list):
        raise RecoveryError("Unexpected Restic snapshots result")
    safe: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        tags = entry.get("tags") or []
        snapshot_id = entry.get("id")
        if (
            isinstance(tags, list)
            and all(isinstance(tag, str) for tag in tags)
            and "securevault" in tags
            and isinstance(snapshot_id, str)
            and ID_PATTERN.fullmatch(snapshot_id)
            and sum(kind in tags for kind in KINDS) == 1
        ):
            safe.append(entry)
    return safe


def list_generations() -> None:
    """Show whether each tagged run contains all three expected snapshots.

    Completeness is only about the three uploaded snapshots; it does not
    make independently captured databases/files transactionally atomic.
    """
    groups: dict[str, set[str]] = {}
    for snapshot in securevault_snapshots():
        stamp = next(
            (tag for tag in snapshot["tags"] if re.fullmatch(r"\d{8}T\d{6}Z", tag)),
            None,
        )
        if stamp:
            groups.setdefault(stamp, set()).update(
                kind for kind in KINDS if kind in snapshot["tags"]
            )
    for stamp, present in sorted(groups.items(), reverse=True):
        status = "COMPLETE" if set(KINDS) == present else "INCOMPLETE"
        print(f"{stamp}  {status}  {','.join(sorted(present))}")


def find_snapshot(snapshot_id: str, kind: str) -> dict[str, Any]:
    if not ID_PATTERN.fullmatch(snapshot_id):
        raise RecoveryError("Use the complete 64-character snapshot ID")
    matches = [s for s in securevault_snapshots() if s["id"].lower() == snapshot_id.lower()]
    if len(matches) != 1 or kind not in matches[0]["tags"]:
        raise RecoveryError("Snapshot not found, not a SecureVault snapshot or kind mismatched")
    return matches[0]


def publish_exclusive(stage: Path, target: Path) -> None:
    """Publish a directory atomically, never replacing an existing target.

    POSIX os.rename() may replace an existing empty directory, so use
    RENAME_NOREPLACE on Linux and RENAME_EXCL on macOS instead.
    """
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise RecoveryError("Atomic no-overwrite directory rename is unavailable")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p,
                           ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        code = rename(-100, os.fsencode(stage), -100, os.fsencode(target), 1)
    elif sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renamex_np", None)
        if rename is None:
            raise RecoveryError("Atomic exclusive rename is unavailable on this macOS")
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        code = rename(os.fsencode(stage), os.fsencode(target), 0x00000004)
    elif os.name == "nt":
        os.rename(stage, target)  # Windows rename fails when destination exists.
        return
    else:
        raise RecoveryError("Atomic no-overwrite directory publish unavailable")
    if code != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), str(target))


def validate_restored_links(stage: Path) -> None:
    """Disallow restored symlinks that can escape the private recovery root."""
    entries = list(stage.rglob("*"))
    links = set()
    absolute_stage = os.path.abspath(stage)
    for entry in entries:
        if not entry.is_symlink():
            continue
        links.add(entry)
        link_target = os.readlink(entry)
        resolved = os.path.abspath(os.path.join(entry.parent, link_target))
        if os.path.commonpath([absolute_stage, resolved]) != absolute_stage:
            raise RecoveryError(f"Symlink escapes restore directory: {entry.relative_to(stage)}")
    for entry in entries:
        ancestor = entry.parent
        while ancestor != stage and stage in ancestor.parents:
            if ancestor in links:
                raise RecoveryError(f"Entry beneath a symlink: {entry.relative_to(stage)}")
            ancestor = ancestor.parent


def restore_to_new_directory(snapshot_id: str, kind: str, requested: str, plaintext_ok: bool) -> None:
    if kind != "files" and not plaintext_ok:
        raise RecoveryError("Database export needs --allow-plaintext-export (never import into live DB)")
    find_snapshot(snapshot_id, kind)
    target = Path(os.path.abspath(requested))
    if target == Path(target.anchor) or target.name in ("", ".", ".."):
        raise RecoveryError("Restore target must be a new non-root directory")
    parent = target.parent
    if not parent.is_dir() or parent.is_symlink():
        raise RecoveryError("Restore parent must be a real existing directory")
    if os.path.lexists(target):
        raise RecoveryError("Restore target already exists; refusing any overwrite")
    stage = Path(tempfile.mkdtemp(prefix=".securevault-restic-", dir=str(parent)))
    try:
        os.chmod(stage, 0o700)
        restic("restore", snapshot_id, "--target", str(stage), capture=False)
        if kind != "files":
            expected = "postgresql-all.sql" if kind == "postgresql" else "mariadb-all.sql"
            # Do not silently export unexpected files or follow an injected link.
            actual = list(stage.rglob("*"))
            if len(actual) != 1 or actual[0] != stage / expected or actual[0].is_symlink() or not actual[0].is_file():
                raise RecoveryError("SQL snapshot contents differ from the expected single dump")
            os.chmod(actual[0], 0o600)
        if not any(stage.iterdir()):
            raise RecoveryError("Restic restored no files; refusing empty recovery")
        validate_restored_links(stage)
        # Stage and target are siblings: atomic, exclusive publish on the
        # same filesystem. Even an attacker racing to create the target
        # cannot cause an existing directory to be overwritten.
        publish_exclusive(stage, target)
        print(f"Restored {kind} snapshot {snapshot_id} into {target}")
        if kind != "files":
            print("WARNING: Exported SQL is plaintext. Keep it private and delete when no longer needed.")
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("list", help="List only tagged SecureVault snapshots")
    commands.add_parser("generations", help="Show complete/incomplete three-part backup generations")
    commands.add_parser("check", help="Read and verify all repository data (potentially expensive)")
    restore = commands.add_parser("restore", help="Restore a verified snapshot into a NEW directory")
    restore.add_argument("--snapshot", required=True, help="Full 64-character Restic snapshot ID")
    restore.add_argument("--kind", required=True, choices=KINDS)
    restore.add_argument("--target", required=True, help="Nonexistent restoration directory")
    restore.add_argument("--allow-plaintext-export", action="store_true",
                         help="Explicitly permit plaintext SQL export in a private directory")
    args = parser.parse_args()
    try:
        repository_preflight()
        if args.action == "list":
            for snapshot in securevault_snapshots():
                kinds = [kind for kind in KINDS if kind in snapshot["tags"]]
                generation = next((tag for tag in snapshot["tags"] if re.fullmatch(r"\d{8}T\d{6}Z", tag)), "unknown")
                print(f"{snapshot['id']}  {kinds[0]}  {generation}  {snapshot.get('time', '')}")
        elif args.action == "generations":
            list_generations()
        elif args.action == "check":
            restic("check", "--read-data", capture=False)
            print("Restic repository data check passed")
        else:
            restore_to_new_directory(args.snapshot, args.kind, args.target,
                                     args.allow_plaintext_export)
    except (RecoveryError, OSError, ValueError) as error:
        print(f"Recovery failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
