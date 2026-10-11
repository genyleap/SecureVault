# PostgreSQL and MariaDB PITR: audit and isolated recovery planning

> **Development feature, not an active backup or disaster-recovery system.**
> These commands neither change live database settings nor execute a restore.
> All destructive database restore operations require separate, human-reviewed
> runbooks and an independently tested off-host backup.

## Inspect local prerequisites (read-only)

```bash
python3 scripts/pitr-readiness.py audit
```

This prints a machine-readable JSON report and exits with 0 only if both
engines' **local prerequisites** pass. Exit 2 means failed or unavailable
local checks. Neither exit status verifies recovery from a real independent
backup location.

The PostgreSQL query is a read-only `SELECT` over `current_setting` and
`pg_stat_archiver`. It reports:

- `wal_level`, `archive_mode`, `full_page_writes`
- Whether an archive command or library is configured (the actual command
  is **not printed**, as it may embed a secret)
- Archiver success/failure counters
- Presence of the local `pgbackrest` executable

When invoked as root on Linux, it uses `runuser -u postgres -- psql` for
the read-only probe. Otherwise the caller must supply adequate PostgreSQL
connection credentials without embedding secrets in the command line.

The MariaDB query uses `SHOW GLOBAL VARIABLES` and reports:

- Whether binary logging is active and its format
- `server_id` and binlog retention settings (when supported)
- Presence of `mariadb-backup` and `mariadb-binlog`/`mysqlbinlog`

The tool does **not** enable WAL archiving or binary logging, install
packages, rotate logs, call `pg_switch_wal`, or read any application data.
It does not validate the real database backup repository or its encryption.

## Prepare isolated recovery plans (never executed)

First provision an **isolated recovery machine** and explicitly create
`/srv/securevault-recovery` there. The planned target must be a new
nonexistent subdirectory under that path. Examples:

```bash
python3 scripts/pitr-readiness.py plan-postgresql \
  --stanza genyleap \
  --target-time '2026-10-10T02:00:00+00:00' \
  --dest /srv/securevault-recovery/postgres-incident-1

python3 scripts/pitr-readiness.py plan-mariadb \
  --target-time '2026-10-10T02:00:00+00:00' \
  --dest /srv/securevault-recovery/mariadb-incident-1
```

Output includes `plan_only: true` and `executed: false`. For PostgreSQL it
contains a **review-only argument vector** for pgBackRest to restore to a
separate data directory, assuming the operator has already configured a
valid stanza, archive retention, permissions, matching database version and
repository on the recovery host. It never invokes pgBackRest.

For MariaDB it emits a **manual, non-executable checklist** because
point-in-time recovery requires selecting a consistent base physical backup,
confirming start binlog coordinates/GTID, ensuring binlog continuity and
replaying events up to a verified boundary in a separate server. Generating
blind binlog replay commands would risk data corruption.

## What is required before calling this PITR-ready

1. An independently stored, recoverable base backup (pgBackRest stanza for
   PostgreSQL; mariadb-backup for MariaDB).
2. Continuous off-host shipping and retention of **all** PostgreSQL WAL /
   MariaDB binary logs needed since the selected base backup.
3. Permission-limited archive repository, encryption and immutable retention
   independent of the primary VPS.
4. Monitoring that detects delayed or missing WAL/binlog segments and failures
   in storage upload, not just local `archive_mode=on`.
5. Restoration of both databases in a disposable machine, with deliberate
   validation of data and application integrity.
6. Measured RPO/RTO from a simulated failure. This cannot be inferred from
   successful local configuration checks alone.

### Safety constraints

- Never point the recovery plan at `/var/lib/postgresql`,
  `/var/lib/mysql` or other live data paths.
- Never turn on a new binlog/WAL feature in production without a verified
  restore path and capacity plan. MariaDB binary logging changes might
  require a database restart; do not perform this during these audits.
- PostgreSQL `pg_stat_archiver` counters provide evidence of activity,
  **not** an assurance of remote durability or complete WAL chains.
- A database logical dump via `pg_dumpall` or `mariadb-dump` alone
  is not a continuous point-in-time backup.
- Never perform automatic failover on this project based solely on the
  report from this script.

## Offline automated tests

```bash
python3 tests/test_pitr_readiness.py
```

The tests stub all database clients. They validate safe read-only queries,
secret-safe failure handling, unsafe configuration reporting, target-time
validation, path restrictions and generation of review-only plans. They do
not contact the production VPS or establish actual recoverability.
