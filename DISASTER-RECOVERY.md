# SecureVault disaster-recovery roadmap (v2)

## Safety first

This branch is a hardening worktree, **not yet a production backup solution**.
Do not configure a production backup service until an independent, encrypted
off-server backup has been taken and restored successfully in a disposable VM.

**No single tool or VPS snapshot can guarantee zero data loss.**

For Genyleap's Ubuntu/XFS VPS, use separate protection layers:

1. **Files/configuration**: encrypted, deduplicated Restic snapshots to a
   storage provider independent of the main VPS; keep credentials separately.
   Include /var/www, /opt project data (excluding rebuildable caches),
   /etc, /boot, service units, certificates and Docker volumes/bind mounts.
2. **PostgreSQL**: use pgBackRest or equivalent base backups plus continuous
   WAL archive; test point-in-time recovery of a disposable database.
3. **MariaDB**: use mariadb-backup with binary logs; test restoration of a
   physical backup and binlog replay.
4. **Machine/boot**: provider snapshots can speed recovery but must not be the
   only backup. Record partition table, bootloader mode, XFS UUIDs and fstab,
   systemd and Nginx configuration; test a fresh host rebuild.
5. **Site availability**: maintain optional warm-standby machine, promote
   databases only with a controlled failover procedure; ensure backup archives
   are immutable/off-provider so replication cannot propagate accidental deletes.

## Suggested recovery objectives

- File snapshots every 15 minutes (15-minute file RPO target, not a guarantee).
- Database PITR with WAL/binlog shipment continuously (minutes or less, if
  measured and monitored).
- Weekly full-machine snapshot outside the primary failure domain if supported.
- Encrypted version retention policy: daily for 30 days, weekly for 12 weeks,
  monthly for 12 months, subject to budget and compliance.
- Monthly full test restore. A backup that has not passed restoration tests
  does not meet the project's reliability requirements.

## Hardening branch currently implemented

- Database backup failure and SFTP failure abort the run.
- `require_remote: true` refuses to claim success without off-server delivery.
- POSIX credential temp files use exclusive creation.
- Strict tar stream verification, no silent missing-folder success.
- File metadata (mode, symlinks and directories) preserved for *full* tar runs.
- `--config` works for manual invocations.
- Legacy timestamp-based incremental backup is disabled; full is the safe default.
- SFTP uploads staged to a remote `.partial-*` path then published.

## Important limitations

- Tar/gzip and SQL dumps **are not encrypted at rest** by this C++ engine.
- Neither mysqldump nor pg_dumpall implements continuous WAL/binlog PITR.
- Snapshot files are not immutable. The SFTP destination must enforce
  off-host retention and least privilege.
- File archives alone do not make consistent running database or Docker
  volume backups. Use application-aware backup strategies.
- Restoring with tar must validate path traversal and symlink targets and be
  performed in an isolated restoration root, never extracted directly over
  a running production host.
- Explicit `require_remote: false` is for local-only development or a second
  layer with independently configured backup transfer.
- Remote timestamps, host-key rotation, ACL/xattr/SELinux metadata, file
  changes during streaming, disaster recovery of boot sectors, authenticated
  hash manifests, and restore verification require further work.
- Old success logs are not evidence of complete backups: earlier code
  continued after individual database/remote transfer errors.

## Production deployment acceptance checklist

- [ ] Dedicated backup identity and least-privilege destination
- [ ] Encrypted repository and keys stored outside the VPS
- [ ] At least one immutable retention copy
- [ ] Restore from independent provider to empty machine
- [ ] PostgreSQL WAL archive and verified PITR test
- [ ] MariaDB binlog archive and verified PITR test
- [ ] Docker data and configuration included; volumes enumerated
- [ ] Monitor backup age, transfer failure and retention drift
- [ ] No secrets in logs, JSON source control, or archive filenames
- [ ] Full software test suite passes on a separate build runner
- [ ] Confirm all files (including symlinks, modes) restored


## Safe file restore (development feature)

The C++ CLI now supports `backup verify <archive>` and
`backup restore <archive> <new-destination-directory>`. This operation
verifies archive payloads, rejects unsafe paths/symlinks and performs a
two-phase staging restore before publishing the result. The destination
must be non-existent. The original tar.gz format remains supported.

This is a **file restore only**: database point-in-time recovery, database
import, ownership/xattrs, full disk images and full machine boot recovery
are still outside this operation's scope. Run any actual data recovery
on a disposable host, and compare recovered data before promotion.

## Development and tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSECUREVAULT_REQUIRE_SFTP=ON
cmake --build build --parallel 2
python3 tests/test_securevault.py build/backup
```

The tests use disposable directories and a fake mysqldump executable.
They must not connect to live databases. Run the test suite manually on a
separate development machine before any production deployment.

Development checkout is not configured to start a service or scheduled backup.

## Point-in-time database recovery readiness

See [PITR-READINESS.md](PITR-READINESS.md). The new
`scripts/pitr-readiness.py audit` command inspects PostgreSQL WAL archive
and MariaDB binlog settings using **read-only queries**. It reports
missing tools and prerequisites but does not alter settings or contact a
backup destination. `plan-postgresql` and `plan-mariadb` generate
review-only instructions for fresh isolated recovery instances.

**This is not an automated PITR implementation.** Actual base backup,
continuous remote WAL/binlog capture, retention validation, and an
isolated successful end-to-end restore are still release blockers.
Run `python3 tests/test_pitr_readiness.py` for mocked tests only.

## Encrypted off-site recovery commands

The optional `scripts/restic-recovery.py` utility is independent of
the C++ tar restore. It requires an existing Restic repository and a
private `RESTIC_PASSWORD_FILE`. Commands:

- `list`: list SecureVault-tagged Restic snapshot IDs and their types
- `generations`: report matching-tag three-part backup generations as
  COMPLETE or INCOMPLETE; a complete tag does not guarantee atomicity
- `check`: verify all repository data with `restic check --read-data`
- `restore --snapshot <64-hex-id> --kind files --target <new-dir>`:
  restore files to a previously nonexistent directory via private staging
- For PostgreSQL/MariaDB, use `--kind postgresql` or `--kind mariadb`
  with `--allow-plaintext-export`. This creates only a private SQL export;
  no database import or destructive restore is performed.

Restoring from a real off-site repository must be tested on a disposable
machine before marking the system production-ready. Automated tests mock
the Restic CLI and check refusal of overwrite, racing destination
creation, failed recovery cleanup, SQL privacy gating, and generation
completeness. Do not confuse these tests with a real end-to-end recovery
drill.

## Optional encrypted Restic coordinator (development preview)

`scripts/backup-restic.sh` is a separate, Linux-only encrypted off-site
path. It streams `pg_dumpall` and `mariadb-dump` directly into distinct
Restic snapshots (no intermediate plaintext SQL files on the host), then
snapshots `/var/www /opt /etc /boot`. A shared UTC generation tag associates
the snapshots. It reports success only if all three off-site stages return
success. It does **not** configure the production server when cloned.

The deployment templates under `deploy/systemd/` define a low-priority
15-minute schedule. **Do not activate these templates without an independent
repository, secret management, initial load test and test restore.**

Illustrative deployment after operator review (not executed by this branch):

1. Install a compatible Restic version and database client tools.
2. Set up an independent encrypted off-site repository and object-store
   credentials. Initialize the repository separately using `restic init`.
3. Store `RESTIC_REPOSITORY` and `RESTIC_PASSWORD_FILE` in
   `/etc/securevault/restic.env` (owner root, mode 0600). Store the
   repository password in another root-only file **outside Git**.
4. Install the script at
   `/usr/local/libexec/securevault/backup-restic.sh` and install the
   systemd unit templates under `/etc/systemd/system/`.
5. Run a **manual** job first, inspect `journalctl`, and perform a restore
   on an empty disposable server. Only then enable the timer.
6. Set external monitoring on
   `/var/lib/securevault/last_success`; alert if stale or failures occur.

**Not yet production-ready**: This script has not been run on the target
server. It requires PostgreSQL local superuser access and MariaDB dump
permissions. `pg_dumpall` / `mariadb-dump` offer logical snapshots, not
continuous point-in-time recovery. Database WAL/binlog archival, physical
database backup, consistent Docker-volume snapshots, immutable retention,
network-capacity testing and successful disaster-recovery drills must still
be implemented/verified. Avoid simultaneous cron, manual and systemd runs;
the script uses `flock` for single-instance execution.

Do not add automatic `restic forget --prune` to an object-locked bucket without
designing retention and lock periods; storage immutability policies must
be compatible with repository maintenance.
